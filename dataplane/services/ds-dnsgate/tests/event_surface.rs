//! §5.5 LOG-1 `DnsEvent` surface tests (doc 11 §5.5 / §6.7, D75; D71 authored SOA).
//!
//! These drive the `StubRequestHandler` DIRECTLY (not over a bound socket) so the
//! service-internal [`CapturingSink`](ds_dnsgate::CapturingSink) — injected through the
//! `with_forwarder_boundary_zone_and_sink` constructor — can observe the events the
//! handler emits on EVERY query path. A request is authored as wire bytes with
//! `hickory-proto` (the same wire the listener decodes), decoded with the public
//! `Request::from_bytes`, and the authored response is drained back through the same
//! `BufDnsStreamHandle` / `ResponseHandle` seam `server.rs` uses — so the events AND
//! the wire response are both observable, with NO bound port and NO network.
//!
//! The forwarded-answer path is exercised against the same network-free loopback mock
//! upstream pattern `suppression_shapes.rs` uses (a UDP+TCP DNS responder on a
//! `127.0.0.1` ephemeral port, injected via `ForwarderConfig`).
//!
//! What is proven here:
//!   * An AAAA fast-NODATA emits a `FastNodata` event with `aaaa_stripped = 1` and the
//!     RECORDED-DEFERRAL `aaaa_only` (the path never forwards AAAA upstream — the
//!     parallel A-probe was rejected; see the `AaaaOnly` design decision).
//!   * A scrubbed bundled answer (A + AAAA) emits a `ForwardedAnswer` event whose
//!     `aaaa_stripped` counts the removed AAAA RRs (and `aaaa_only == Determined(false)`,
//!     since an A survived).
//!   * An A query over a pure v6-only origin returns NoData and RECORDS THE DEFERRAL of
//!     `aaaa_only` — MEASURED: a type-filtered A-lookup hides the upstream AAAA, so the
//!     genuine v6-only trigger is phase-B work, never a silent `false` here.
//!   * EVERY event carries POL-3 provenance (§6.7, CI-fatal if missing).
//!   * The configured boundary zone flows into the authored-SOA MNAME (the D71 VALUE
//!     derivation point), default == the working name `denied.policy.boundary.`.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use std::path::PathBuf;

use ds_dnsgate::event::{AaaaOnly, CapturingSink, DeferralReason, DnsEvent, EventPath};
use ds_dnsgate::handler::{ForwarderConfig, StubRequestHandler, SOA_SIGNATURE_MNAME};
use ds_dnsgate::policy::{FixedStubPolicy, PolicyCorePolicy};

use ds_contracts::pol1::{parse_layer, PolicyLayer};
use policy_core::pol1_eval::{compose, ComposedPolicy};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::svcb::{Alpn, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, HTTPS, SVCB};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::{Protocol, StreamReceiver};
use hickory_server::net::BufDnsStreamHandle;
use hickory_server::server::{Request, RequestHandler, ResponseHandle};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Query construction (wire bytes) + the direct-drive harness.
// ---------------------------------------------------------------------------

fn query_bytes(id: u16, name: &str, qtype: RecordType) -> Vec<u8> {
    let mut msg = Message::query();
    msg.metadata.id = id;
    msg.metadata.message_type = MessageType::Query;
    msg.metadata.op_code = OpCode::Query;
    msg.metadata.recursion_desired = true;
    msg.add_query(hickory_proto::op::Query::query(
        Name::from_ascii(name).unwrap(),
        qtype,
    ));
    msg.to_vec().unwrap()
}

/// A fixed loopback client address for the synthetic `Request`. Never dialed — the
/// handler is driven in-process, so this is only the request's recorded source.
fn client_src() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 9))
}

/// Drive the handler with a single query and return the authored wire response (parsed)
/// together with the events the `CapturingSink` recorded. NO bound socket, NO network
/// (the forwarder, if reached, dials whatever `forwarder` points at — a loopback mock
/// or a dead port). Mirrors the `server.rs` TCP serve seam: author into a
/// `BufDnsStreamHandle`, run `handle_request`, drain the serialized response.
async fn drive(
    forwarder: ForwarderConfig,
    boundary_zone: &str,
    query: &[u8],
) -> (Message, Vec<DnsEvent>) {
    let sink = CapturingSink::new();
    let handler = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        FixedStubPolicy::new(),
        forwarder,
        boundary_zone,
        Arc::new(sink.clone()),
    );

    let src = client_src();
    let request = Request::from_bytes(query.to_vec(), src, Protocol::Tcp).unwrap();
    let (stream_handle, mut receiver) = BufDnsStreamHandle::new(src);
    let response_handle = ResponseHandle::new(src, stream_handle, Protocol::Tcp);

    let _ =
        <StubRequestHandler<FixedStubPolicy> as RequestHandler>::handle_request::<_, TokioTime>(
            &handler,
            &request,
            response_handle,
        )
        .await;

    let response = next_response(&mut receiver)
        .await
        .expect("the handler authored a response");
    (response, sink.events())
}

/// Drain the next serialized response the handler pushed into the per-request sink, if
/// any. The handler pushes synchronously inside `handle_request`, so by the time it
/// returns the message is queued; a short timeout guards the no-response case.
async fn next_response(receiver: &mut StreamReceiver) -> Option<Message> {
    use futures_util::StreamExt;
    let serial = tokio::time::timeout(Duration::from_millis(200), receiver.next())
        .await
        .ok()??;
    let (bytes, _addr) = serial.into_parts();
    Message::from_vec(&bytes).ok()
}

/// Assert every event carries non-empty POL-3 provenance (doc 11 §6.7, CI-fatal if
/// missing). Called on every path's events.
fn assert_provenance_present(events: &[DnsEvent]) {
    assert!(
        !events.is_empty(),
        "§6.7: a DnsEvent is emitted on every path"
    );
    for e in events {
        assert!(
            !e.provenance.rule_id.is_empty()
                && !e.provenance.policy_layer.is_empty()
                && !e.provenance.policy_version.is_empty(),
            "§6.7: every DnsEvent carries POL-3 provenance (rule_id/layer/version)"
        );
    }
}

// ===========================================================================
// The in-process MOCK UPSTREAM (network-free forwarder fixture, doc 11 §2).
// A trimmed copy of the suppression_shapes fixture — a UDP+TCP DNS responder on a
// shared 127.0.0.1 ephemeral port that serves a programmed answer set, so a test can
// make the UPSTREAM carry AAAA records the gate must scrub and signal on.
// ===========================================================================

mod mock_up {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A per-query-type counter the counting mock increments on every request it serves —
    /// used to prove the bounded AAAA probe rides the single forwarder with no fan-out.
    pub type QueryCounts = Arc<Mutex<HashMap<u16, u32>>>;

    #[derive(Default, Clone)]
    pub struct Zone {
        answers: HashMap<(String, u16), Vec<Record>>,
    }

    impl Zone {
        pub fn new() -> Self {
            Self::default()
        }

        fn key(name: &str, qtype: RecordType) -> (String, u16) {
            (
                Name::from_ascii(name).unwrap().to_lowercase().to_ascii(),
                u16::from(qtype),
            )
        }

        pub fn set(mut self, name: &str, qtype: RecordType, records: Vec<Record>) -> Self {
            self.answers.insert(Self::key(name, qtype), records);
            self
        }

        fn respond(&self, request: &Message) -> Message {
            let mut resp = Message::response(request.metadata.id, OpCode::Query);
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::NoError;
            if let Some(q) = request.queries.first() {
                resp.add_query(q.clone());
                let key = (
                    q.name().to_lowercase().to_ascii(),
                    u16::from(q.query_type()),
                );
                if let Some(records) = self.answers.get(&key) {
                    resp.add_answers(records.iter().cloned());
                }
            }
            resp
        }
    }

    pub struct MockUpstream {
        pub addr: SocketAddr,
        shutdown: Arc<tokio::sync::Notify>,
        counts: QueryCounts,
    }

    impl MockUpstream {
        pub fn forwarder(&self, timeout: Duration) -> ForwarderConfig {
            ForwarderConfig {
                upstreams: vec![self.addr],
                timeout,
            }
        }

        /// A snapshot of how many queries of each qtype this single mock upstream served
        /// — the proof the bounded AAAA probe rode THIS one forwarder (no second resolver)
        /// and added no per-query fan-out.
        pub fn queries_by_type(&self) -> HashMap<u16, u32> {
            self.counts
                .lock()
                .expect("query-count mutex poisoned")
                .clone()
        }
    }

    impl Drop for MockUpstream {
        fn drop(&mut self) {
            self.shutdown.notify_waiters();
        }
    }

    /// Increment the per-qtype counter for the request's question (if any). A no-op for
    /// the non-counting mock (an empty shared map nobody reads).
    fn count_query(counts: &QueryCounts, request: &Message) {
        if let Some(q) = request.queries.first() {
            let mut guard = counts.lock().expect("query-count mutex poisoned");
            *guard.entry(u16::from(q.query_type())).or_insert(0) += 1;
        }
    }

    async fn bind_shared_port() -> (UdpSocket, tokio::net::TcpListener) {
        for _ in 0..64 {
            let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let udp = UdpSocket::bind(loopback).await.unwrap();
            let port = udp.local_addr().unwrap().port();
            let want = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            match tokio::net::TcpListener::bind(want).await {
                Ok(tcp) => return (udp, tcp),
                Err(_) => continue,
            }
        }
        panic!("could not find a loopback port free in both UDP and TCP namespaces");
    }

    pub async fn spawn(zone: Zone) -> MockUpstream {
        spawn_inner(zone).await
    }

    /// Spawn a mock upstream that ALSO counts the queries it serves by qtype — used to
    /// prove the bounded AAAA probe rides the single forwarder with no per-query fan-out.
    pub async fn spawn_counting(zone: Zone) -> MockUpstream {
        spawn_inner(zone).await
    }

    async fn spawn_inner(zone: Zone) -> MockUpstream {
        let (udp, tcp) = bind_shared_port().await;
        let addr = udp.local_addr().unwrap();
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let zone = Arc::new(zone);
        let counts: QueryCounts = Arc::new(Mutex::new(HashMap::new()));

        {
            let zone = zone.clone();
            let shutdown = shutdown.clone();
            let counts = counts.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let recv = tokio::select! {
                        r = udp.recv_from(&mut buf) => r,
                        _ = shutdown.notified() => break,
                    };
                    let Ok((n, peer)) = recv else { break };
                    let Ok(request) = Message::from_vec(&buf[..n]) else {
                        continue;
                    };
                    count_query(&counts, &request);
                    let resp = zone.respond(&request);
                    if let Ok(bytes) = resp.to_vec() {
                        let _ = udp.send_to(&bytes, peer).await;
                    }
                }
            });
        }

        {
            let zone = zone.clone();
            let shutdown = shutdown.clone();
            let counts = counts.clone();
            tokio::spawn(async move {
                loop {
                    let accepted = tokio::select! {
                        a = tcp.accept() => a,
                        _ = shutdown.notified() => break,
                    };
                    let Ok((mut stream, _peer)) = accepted else {
                        break;
                    };
                    let zone = zone.clone();
                    let counts = counts.clone();
                    tokio::spawn(async move {
                        loop {
                            let mut len_buf = [0u8; 2];
                            if stream.read_exact(&mut len_buf).await.is_err() {
                                return;
                            }
                            let len = u16::from_be_bytes(len_buf) as usize;
                            let mut msg = vec![0u8; len];
                            if stream.read_exact(&mut msg).await.is_err() {
                                return;
                            }
                            let Ok(request) = Message::from_vec(&msg) else {
                                return;
                            };
                            count_query(&counts, &request);
                            let resp = zone.respond(&request);
                            let Ok(bytes) = resp.to_vec() else { return };
                            let Ok(rlen) = u16::try_from(bytes.len()) else {
                                return;
                            };
                            if stream.write_all(&rlen.to_be_bytes()).await.is_err()
                                || stream.write_all(&bytes).await.is_err()
                                || stream.flush().await.is_err()
                            {
                                return;
                            }
                        }
                    });
                }
            });
        }

        MockUpstream {
            addr,
            shutdown,
            counts,
        }
    }
}

// ---------------------------------------------------------------------------
// Record builders (the malicious/steering classes the scrub + signals cover).
// ---------------------------------------------------------------------------

fn a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::A(A(ip)))
}

fn aaaa_record(name: &str, ip: Ipv6Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::AAAA(AAAA(ip)))
}

fn https_record(name: &str, ttl: u32) -> Record {
    let svcb = SVCB::new(
        1,
        Name::from_ascii(".").unwrap(),
        vec![(
            SvcParamKey::Alpn,
            SvcParamValue::Alpn(Alpn(vec!["h3".to_string()])),
        )],
    );
    Record::from_rdata(
        Name::from_ascii(name).unwrap(),
        ttl,
        RData::HTTPS(HTTPS(svcb)),
    )
}

/// The single event the handler emitted (these tests drive one query at a time).
fn only_event(events: &[DnsEvent]) -> &DnsEvent {
    assert_eq!(
        events.len(),
        1,
        "one query emits exactly one event on its path (§6.7)"
    );
    &events[0]
}

// ===========================================================================
// 1. An AAAA fast-NODATA emits `aaaa_stripped` and the recorded-deferral `aaaa_only`.
// ===========================================================================

#[tokio::test]
async fn aaaa_fast_nodata_emits_aaaa_stripped_and_deferred_aaaa_only() {
    // A dead upstream with a long timeout: if the AAAA path forwarded, the test would
    // hang on the timeout. The fast-NODATA authors without any forward, so the event
    // and response are immediate (this also re-proves the no-forward property from the
    // EVENT side).
    let forwarder = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_secs(30),
    };
    let query = query_bytes(0xa6a6, "v6.example.test.", RecordType::AAAA);
    let (resp, events) = tokio::time::timeout(
        Duration::from_secs(3),
        drive(forwarder, "boundary.", &query),
    )
    .await
    .expect("AAAA fast-NODATA must not wait on the upstream (no forward)");

    // The wire shape is the §3.3 fast NODATA (NOERROR, empty answer).
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 0);

    // The event: FastNodata path, exactly one AAAA stripped, and the RECORDED-DEFERRAL
    // aaaa_only (this path never forwards AAAA upstream; the parallel A-probe was
    // rejected, so it does NOT claim a v6-only determination here).
    let event = only_event(&events);
    assert_eq!(event.path, EventPath::FastNodata);
    assert_eq!(event.qtype, u16::from(RecordType::AAAA));
    assert_eq!(
        event.aaaa_stripped, 1,
        "an AAAA query strips exactly the one AAAA the guest asked for"
    );
    assert_eq!(
        event.aaaa_only,
        AaaaOnly::Deferred(DeferralReason::FastNodataNoForward),
        "the fast-NODATA path defers aaaa_only — never a parallel A-probe (D75 design decision)"
    );
    assert!(
        !event.is_aaaa_only_trigger(),
        "a deferral is never the T-C3 trigger"
    );
    assert_provenance_present(&events);
}

// ===========================================================================
// 2. An HTTPS(65) fast-NODATA emits a FastNodata event that strips no AAAA.
// ===========================================================================

#[tokio::test]
async fn https_fast_nodata_emits_event_with_zero_aaaa_stripped() {
    let forwarder = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_secs(30),
    };
    let query = query_bytes(0x6565, "ech.example.test.", RecordType::HTTPS);
    let (resp, events) = tokio::time::timeout(
        Duration::from_secs(3),
        drive(forwarder, "boundary.", &query),
    )
    .await
    .expect("HTTPS suppression is also forward-free");

    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    let event = only_event(&events);
    assert_eq!(event.path, EventPath::FastNodata);
    assert_eq!(
        event.aaaa_stripped, 0,
        "an HTTPS query strips no AAAA — the signal is AAAA-specific"
    );
    assert_eq!(
        event.aaaa_only,
        AaaaOnly::Deferred(DeferralReason::FastNodataNoForward)
    );
    assert_provenance_present(&events);
}

// ===========================================================================
// 3. A scrubbed bundled answer (A + AAAA) emits ForwardedAnswer with the AAAA counted.
// ===========================================================================

#[tokio::test]
async fn forwarded_answer_with_bundled_aaaa_emits_aaaa_stripped_count() {
    // Upstream returns an A bundled with two AAAA RRs for the same name. The gate
    // forwards the A; the event counts the two stripped AAAA. aaaa_only is FALSE
    // (an A survived — v4 can reach the name).
    let v6a = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1);
    let v6b = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x2);
    let answer = vec![
        a_record("dual.example.test.", Ipv4Addr::new(198, 51, 100, 4), 90),
        aaaa_record("dual.example.test.", v6a, 90),
        aaaa_record("dual.example.test.", v6b, 90),
    ];
    let zone = mock_up::Zone::new().set("dual.example.test.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;

    let query = query_bytes(0x0a28, "dual.example.test.", RecordType::A);
    let (resp, events) = drive(mock.forwarder(Duration::from_secs(2)), "boundary.", &query).await;

    // The A survives; no AAAA reaches the VM.
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert!(resp
        .answers
        .iter()
        .all(|r| r.record_type() != RecordType::AAAA));

    let event = only_event(&events);
    assert_eq!(event.path, EventPath::ForwardedAnswer);
    assert_eq!(
        event.aaaa_stripped, 2,
        "both bundled AAAA RRs are counted in aaaa_stripped"
    );
    assert_eq!(
        event.aaaa_only,
        AaaaOnly::Determined(false),
        "an A survived — v4 can reach the name, so not aaaa_only"
    );
    assert_provenance_present(&events);
}

// ===========================================================================
// 4. An A query over a pure v6-only origin (AAAA-only, no A) -> NoData on the wire, but
//    the bounded explicit AAAA probe (doc 11 §3.5 phase-B pre-step) SETTLES the genuine
//    aaaa_only trigger: Determined(true), NOT a deferral.
//
// MEASURED (this very test): hickory-resolver's type-filtered `lookup(name, A)` over an
// AAAA-only origin returns NoData and does NOT surface the AAAA RRs — so the A-path
// alone cannot observe "upstream had AAAA but zero A". The bounded AAAA probe on the
// SAME forwarder resolves the AAAA leg, sees the records, and settles the trigger. The
// VM still gets the v4-only NOERROR/NODATA (the guest stays v4-only; the probe is a
// telemetry settlement, not an answer the guest sees).
// ===========================================================================

#[tokio::test]
async fn forwarded_v6_only_origin_is_settled_by_the_bounded_aaaa_probe() {
    // The A query's upstream answer carries ONLY AAAA records (a v6-only origin): the
    // mock serves AAAA for this name but no A, so the A-lookup is NoData and the bounded
    // AAAA probe finds the AAAA on the same forwarder.
    let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0, 0, 0, 0, 0x10);
    let answer = vec![aaaa_record("v6only.example.test.", v6, 120)];
    let zone = mock_up::Zone::new().set("v6only.example.test.", RecordType::AAAA, answer);
    let mock = mock_up::spawn(zone).await;

    let query = query_bytes(0x0a06, "v6only.example.test.", RecordType::A);
    let (resp, events) = drive(mock.forwarder(Duration::from_secs(2)), "boundary.", &query).await;

    // The VM still gets NOERROR with no records (no A existed; the guest stays v4-only —
    // the probe never injects the v6 address into the guest answer).
    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 0);

    let event = only_event(&events);
    assert_eq!(event.path, EventPath::NoData);
    assert_eq!(
        event.aaaa_only,
        AaaaOnly::Determined(true),
        "the bounded AAAA probe settled the genuine pure-v6-only origin (doc 11 §3.5), not a deferral"
    );
    assert!(
        event.is_aaaa_only_trigger() && !event.aaaa_only.is_deferred(),
        "a settled pure-v6-only origin IS the T-C3 trigger (no longer phase-B-deferred)"
    );
    assert_provenance_present(&events);
}

// ===========================================================================
// 4b. The same forwarded-NoData path over a genuinely-empty origin (no A AND no AAAA)
//     resolves to Determined(false): the probe ran, found no AAAA either, so the name is
//     genuinely empty — NOT v6-only, and NOT a silent deferral.
// ===========================================================================

#[tokio::test]
async fn forwarded_empty_origin_is_settled_false_by_the_bounded_aaaa_probe() {
    // The origin has NO records of any type (the mock serves an empty answer for every
    // qtype): the A-lookup is NoData and the bounded AAAA probe is ALSO NoData.
    let zone = mock_up::Zone::new();
    let mock = mock_up::spawn(zone).await;

    let query = query_bytes(0x0a07, "empty.example.test.", RecordType::A);
    let (resp, events) = drive(mock.forwarder(Duration::from_secs(2)), "boundary.", &query).await;

    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 0);

    let event = only_event(&events);
    assert_eq!(event.path, EventPath::NoData);
    assert_eq!(
        event.aaaa_only,
        AaaaOnly::Determined(false),
        "an origin with neither A nor AAAA is genuinely empty — Determined(false), not v6-only"
    );
    assert!(!event.is_aaaa_only_trigger());
    assert_provenance_present(&events);
}

// ===========================================================================
// 4c. The bounded AAAA probe rides the SINGLE upstream forwarder — there is no second
//     resolver and no per-query fan-out (doc 11 §1). A query-counting mock (the ONLY
//     upstream the gate is configured with) proves the AAAA probe arrives at that one
//     forwarder, and that at most ONE bounded AAAA probe is issued per query.
// ===========================================================================

#[tokio::test]
async fn bounded_aaaa_probe_rides_the_single_forwarder_with_no_fan_out() {
    // A v6-only origin served by ONE counting mock upstream — the gate's forwarder is
    // configured with exactly this single address (mock.forwarder == vec![addr]).
    let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0, 0, 0, 0, 0x20);
    let answer = vec![aaaa_record("v6only2.example.test.", v6, 120)];
    let zone = mock_up::Zone::new().set("v6only2.example.test.", RecordType::AAAA, answer);
    let mock = mock_up::spawn_counting(zone).await;

    let forwarder = mock.forwarder(Duration::from_secs(2));
    let query = query_bytes(0x0a08, "v6only2.example.test.", RecordType::A);
    let (_resp, events) = drive(forwarder, "boundary.", &query).await;

    // The probe fired and settled the trigger — proving it reached the SINGLE configured
    // upstream (the gate has no other resolver to reach).
    let event = only_event(&events);
    assert_eq!(
        event.aaaa_only,
        AaaaOnly::Determined(true),
        "the bounded probe settled the v6-only trigger via the single forwarder"
    );

    // The bounded probe added at most ONE AAAA leg on top of the A-lookup chase — no
    // per-query fan-out of N probes (doc 11 §1: single resolver / DoS chokepoint). All
    // of it landed on the ONE counting mock (the only upstream the gate was given).
    let by_type = mock.queries_by_type();
    let aaaa_probes = by_type
        .get(&u16::from(RecordType::AAAA))
        .copied()
        .unwrap_or(0);
    assert!(
        (1..=2).contains(&aaaa_probes),
        "exactly the bounded AAAA probe reached the single forwarder (allowing one A→TCP \
         retry of the same single probe); no fan-out (got {aaaa_probes})"
    );
}

// ===========================================================================
// 5. A plain A answer (no v6 at all) emits ForwardedAnswer with zero strip, not a
//    trigger — the common case carries the signals at their no-op values.
// ===========================================================================

#[tokio::test]
async fn plain_a_answer_emits_event_with_no_signals_set() {
    let answer = vec![a_record(
        "a.example.test.",
        Ipv4Addr::new(203, 0, 113, 7),
        60,
    )];
    let zone = mock_up::Zone::new().set("a.example.test.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;

    let query = query_bytes(0x0a01, "a.example.test.", RecordType::A);
    let (resp, events) = drive(mock.forwarder(Duration::from_secs(2)), "boundary.", &query).await;

    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    assert_eq!(resp.answers.len(), 1);
    let event = only_event(&events);
    assert_eq!(event.path, EventPath::ForwardedAnswer);
    assert_eq!(event.aaaa_stripped, 0);
    assert_eq!(event.aaaa_only, AaaaOnly::Determined(false));
    assert!(!event.is_aaaa_only_trigger());
    assert_provenance_present(&events);
}

// ===========================================================================
// 6. The forwarded answer bundling HTTPS still strips it (event path proven) — the
//    HTTPS strip is signalled as a ForwardedAnswer event (no aaaa_stripped).
// ===========================================================================

#[tokio::test]
async fn forwarded_a_answer_with_bundled_https_emits_forwarded_event() {
    let answer = vec![
        a_record("cdn.example.test.", Ipv4Addr::new(203, 0, 113, 9), 120),
        https_record("cdn.example.test.", 120),
    ];
    let zone = mock_up::Zone::new().set("cdn.example.test.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;

    let query = query_bytes(0x0a65, "cdn.example.test.", RecordType::A);
    let (resp, events) = drive(mock.forwarder(Duration::from_secs(2)), "boundary.", &query).await;

    assert!(resp
        .answers
        .iter()
        .all(|r| r.record_type() != RecordType::HTTPS));
    let event = only_event(&events);
    assert_eq!(event.path, EventPath::ForwardedAnswer);
    // The HTTPS strip does not move the AAAA-specific signal.
    assert_eq!(event.aaaa_stripped, 0);
    assert_eq!(
        event.aaaa_only,
        AaaaOnly::Determined(false),
        "the A survived — not aaaa_only"
    );
    assert_provenance_present(&events);
}

// ===========================================================================
// 7. The configured boundary zone flows into the authored-SOA MNAME (D71 VALUE
//    derivation point), and the default is the working name.
// ===========================================================================

#[tokio::test]
async fn configured_boundary_zone_drives_the_authored_soa_mname() {
    // A non-default boundary zone: the authored SOA MNAME must reflect it.
    let forwarder = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_secs(2),
    };
    let query = query_bytes(0xb000, "v6.example.test.", RecordType::AAAA);
    let (resp, _events) = drive(forwarder.clone(), "ds.internal", &query).await;

    let soa = resp
        .authorities
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(soa) => Some(soa),
            _ => None,
        })
        .expect("the §3.3 fast-NODATA authors an SOA in the authority section");
    assert_eq!(
        soa.mname.to_ascii(),
        "denied.policy.ds.internal.",
        "the authored SOA MNAME is derived from the configured boundary zone (D71 VALUE change)"
    );

    // The default working name reproduces the frozen pre-stage constant exactly.
    let (resp_default, _) = drive(forwarder, "boundary.", &query).await;
    let soa_default = resp_default
        .authorities
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(soa) => Some(soa),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        soa_default.mname.to_ascii(),
        SOA_SIGNATURE_MNAME,
        "the default boundary zone reproduces the frozen working-name MNAME"
    );
}

// ===========================================================================
// 8. The boundary-zone constructor normalizes a missing trailing dot (the derivation
//    point is exercised for both dotted and undotted inputs).
// ===========================================================================

#[tokio::test]
async fn boundary_zone_without_trailing_dot_is_normalized() {
    let handler_dotted = StubRequestHandler::with_forwarder_and_boundary_zone(
        FixedStubPolicy::new(),
        ForwarderConfig::default(),
        "corp.example.",
    );
    let handler_bare = StubRequestHandler::with_forwarder_and_boundary_zone(
        FixedStubPolicy::new(),
        ForwarderConfig::default(),
        "corp.example",
    );
    assert_eq!(handler_dotted.soa_mname(), "denied.policy.corp.example.");
    assert_eq!(
        handler_dotted.soa_mname(),
        handler_bare.soa_mname(),
        "a missing trailing dot is normalized to the same FQDN MNAME"
    );
}

// ===========================================================================
// 9. The no-answer-set ERROR paths emit the dedicated `ErrorPathNoAnswerSet` deferral —
//    NOT the forwarded-NoData label (label precision: these carry NO answer set at all
//    and never forwarded, so a consumer reading only the reason is no longer misled).
//    The genuine forwarded-NoData emission (test 4 above) keeps ForwardedNoDataV6Invisible.
// ===========================================================================

/// A query-less wire message: a valid DNS header with ZERO questions. The handler's
/// `request_info()` errors on "not exactly one query", so this drives the FORMERR path.
fn query_less_bytes(id: u16) -> Vec<u8> {
    let mut msg = Message::query();
    msg.metadata.id = id;
    msg.metadata.message_type = MessageType::Query;
    msg.metadata.op_code = OpCode::Query;
    // No add_query — the request carries no question section.
    msg.to_vec().unwrap()
}

#[tokio::test]
async fn formerr_path_emits_error_path_no_answer_set_deferral() {
    // A dead upstream with a long timeout would hang the test IF this path forwarded;
    // the FORMERR path authors immediately with no forward.
    let forwarder = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_secs(30),
    };
    let query = query_less_bytes(0xf00d);
    let (resp, events) = tokio::time::timeout(
        Duration::from_secs(3),
        drive(forwarder, "boundary.", &query),
    )
    .await
    .expect("the FORMERR path must not wait on the upstream (no forward)");

    // The wire shape is FORMERR.
    assert_eq!(resp.metadata.response_code, ResponseCode::FormErr);

    // The event: FormErr path, and the dedicated no-answer-set deferral (NOT the
    // forwarded-NoData label — this request carried no question and never forwarded).
    let event = only_event(&events);
    assert_eq!(event.path, EventPath::FormErr);
    assert_eq!(
        event.aaaa_only,
        AaaaOnly::Deferred(DeferralReason::ErrorPathNoAnswerSet),
        "the FORMERR no-answer-set path uses the dedicated deferral, never ForwardedNoDataV6Invisible"
    );
    assert!(
        !event.is_aaaa_only_trigger() && event.aaaa_only.is_deferred(),
        "an error-path deferral is never the T-C3 trigger"
    );
    assert_provenance_present(&events);
}

#[tokio::test]
async fn servfail_error_path_emits_error_path_no_answer_set_deferral() {
    // A genuine upstream failure (a dead loopback port the forwarder cannot reach) is a
    // SERVFAIL with NO answer set — never a forwarded NoData. A short timeout keeps the
    // test fast; the upstream is unreachable, so the forward fails (SERVFAIL, §8.5).
    let forwarder = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_millis(300),
    };
    let query = query_bytes(0x5fa1, "unreachable.example.test.", RecordType::A);
    let (resp, events) = tokio::time::timeout(
        Duration::from_secs(3),
        drive(forwarder, "boundary.", &query),
    )
    .await
    .expect("a dead-upstream forward resolves to SERVFAIL within the timeout");

    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::ServFail,
        "an unreachable upstream is a genuine failure → SERVFAIL (doc 11 §8.5)"
    );

    let event = only_event(&events);
    assert_eq!(event.path, EventPath::ServFail);
    assert_eq!(
        event.aaaa_only,
        AaaaOnly::Deferred(DeferralReason::ErrorPathNoAnswerSet),
        "the SERVFAIL no-answer-set error path uses the dedicated deferral, never ForwardedNoDataV6Invisible"
    );
    assert!(
        event.aaaa_only.is_deferred(),
        "a genuine-failure error path carries no answer set to settle the trigger from"
    );
    assert_provenance_present(&events);
}

// ===========================================================================
// 10. PART A — the DnsEvent carries the LIVE verdict's POL-3 provenance: the shipped
//     POL-2 baseline pack's real rule_id / policy_layer / policy_version, NOT the
//     retired fixed "stub" triple. Driven through the pack-backed `PolicyCorePolicy`
//     (the production evaluator), so an allowed AND a denied name both name their matched
//     pack rule on the emitted event (doc 11 §5.5 LOG-1 / §6.7; POL-3 schema doc 13).
// ===========================================================================

/// The repo-relative path to the SHIPPED POL-2 baseline pack (read-only). The ds-dnsgate
/// `CARGO_MANIFEST_DIR` is `.../dataplane/services/ds-dnsgate`; the pack lives under
/// `.../dataplane/artifacts/policy-packs/`.
fn shipped_pack_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // ds-dnsgate
    p.pop(); // services
    p.push("artifacts");
    p.push("policy-packs");
    p.push("pol2-system-baseline.pol1.yaml");
    p
}

/// Parse the shipped pack with ZERO PolicyErrors and compose the host's ONE document
/// (fresh install, no capabilities present — the `requires` entries are INERT).
fn pack_policy() -> PolicyCorePolicy {
    let text = std::fs::read_to_string(shipped_pack_path()).expect("reading shipped pack");
    let layer: PolicyLayer = parse_layer(&text)
        .unwrap_or_else(|errs| panic!("the SHIPPED POL-2 baseline pack must parse: {errs}"));
    let composed: ComposedPolicy = compose(&[layer], &[]);
    PolicyCorePolicy::new(composed)
}

/// Drive the PACK-BACKED handler with one query and return the (response, events). Same
/// network-free in-process seam as [`drive`], but with the real `policy-core` evaluator so
/// the emitted event carries the matched pack rule's POL-3 triple.
async fn drive_pack(forwarder: ForwarderConfig, query: &[u8]) -> (Message, Vec<DnsEvent>) {
    let sink = CapturingSink::new();
    let handler = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        pack_policy(),
        forwarder,
        "boundary.",
        Arc::new(sink.clone()),
    );

    let src = client_src();
    let request = Request::from_bytes(query.to_vec(), src, Protocol::Tcp).unwrap();
    let (stream_handle, mut receiver) = BufDnsStreamHandle::new(src);
    let response_handle = ResponseHandle::new(src, stream_handle, Protocol::Tcp);

    let _ =
        <StubRequestHandler<PolicyCorePolicy> as RequestHandler>::handle_request::<_, TokioTime>(
            &handler,
            &request,
            response_handle,
        )
        .await;

    let response = next_response(&mut receiver)
        .await
        .expect("the handler authored a response");
    (response, sink.events())
}

#[tokio::test]
async fn allowed_name_event_carries_the_real_pack_provenance_not_the_stub() {
    // api.anthropic.com is an enabled `core` family endpoint in the shipped pack. The
    // gate forwards + scrubs; the emitted ForwardedAnswer event must name the matched
    // pack rule, never the retired fixed stub triple.
    let answer = vec![a_record(
        "api.anthropic.com.",
        Ipv4Addr::new(203, 0, 113, 5),
        120,
    )];
    let zone = mock_up::Zone::new().set("api.anthropic.com.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;

    let query = query_bytes(0x0aa1, "api.anthropic.com.", RecordType::A);
    let (resp, events) = drive_pack(mock.forwarder(Duration::from_secs(2)), &query).await;

    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    let event = only_event(&events);
    assert_eq!(event.path, EventPath::ForwardedAnswer);

    // The LIVE pack provenance, NOT the retired stub triple.
    assert_ne!(
        event.provenance.rule_id, "stub",
        "the event carries the LIVE verdict provenance, not the retired fixed stub rule id"
    );
    assert_ne!(event.provenance.policy_version, "pre-stage");
    assert!(
        event.provenance.rule_id.contains("api.anthropic.com"),
        "the event names the matched pack rule (got rule_id={:?})",
        event.provenance.rule_id
    );
    assert!(
        !event.provenance.policy_layer.is_empty() && !event.provenance.policy_version.is_empty(),
        "POL-3: layer and version are present (§6.7)"
    );
}

#[tokio::test]
async fn denied_name_event_carries_the_real_pack_provenance_not_the_stub() {
    // dns.google is on the shipped pack's blocklist (the resolver-lock; blocklists win).
    // A dead upstream with a long timeout: the Deny arm never forwards, so the test does
    // not hang.
    let forwarder = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_secs(30),
    };
    let query = query_bytes(0x0aa2, "dns.google.", RecordType::A);
    let (resp, events) =
        tokio::time::timeout(Duration::from_secs(3), drive_pack(forwarder, &query))
            .await
            .expect("the Deny arm must not wait on the upstream (no forward)");

    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::NXDomain,
        "a blocklisted DoH resolver is the §3.2 hard deny → NXDOMAIN"
    );

    let event = only_event(&events);
    assert_eq!(event.path, EventPath::Denied);
    assert_ne!(
        event.provenance.rule_id, "stub",
        "the deny event carries the LIVE blocklist-rule provenance, not the retired stub"
    );
    assert_ne!(event.provenance.policy_version, "pre-stage");
    assert!(
        event.provenance.rule_id.contains("dns.google"),
        "the deny event names the matched blocklist rule (got rule_id={:?})",
        event.provenance.rule_id
    );
    assert_provenance_present(&events);
}

// ===========================================================================
// 11. The spool-wired gate: a DnsEvent driven through the PRODUCTION path
//     (DnsEvent -> to_envelope -> TelemetrySink -> SpoolSink -> disk segment)
//     lands as a flushed record on the disk segment (doc 11 §5.5, D116).
//
//     Binds 127.0.0.1:0 (OS-assigned loopback port). No live resolver — the gate
//     is configured with a dead upstream (loopback port 1 that never answers) for
//     the fast-NODATA paths that do not forward. One AAAA query drives the
//     `FastNodata` path (no upstream contact needed); the event is encoded by
//     `TelemetrySink` into an `EventEnvelope`, handed to the `SpoolSink`, flushed
//     to the segment file, and verified by reading the raw bytes back out.
//
//     On-disk record format (ds_telemetry::spool free encoding):
//       - 1-byte kind tag: 0x02 == DnsEvent (kind_tag(EventKind::DnsEvent))
//       - 4-byte big-endian length of the body
//       - body: `rule_id|policy_layer|policy_version||<render_payload bytes>`
//         where render_payload encodes `qname=... qtype=... path=... aaaa_stripped=...`
// ===========================================================================

/// Decode the raw on-disk segment bytes and return all DnsEvent payload bodies
/// (kind tag == 0x02). The framing mirrors `append_batch`: per record:
///   byte 0  : 1-byte kind tag
///   bytes 1-4: 4-byte big-endian body length
///   bytes 5..: body
fn decode_dns_event_bodies(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        let tag = bytes[i];
        let len =
            u32::from_be_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]) as usize;
        let body_start = i + 5;
        let body_end = body_start + len;
        if body_end > bytes.len() {
            break;
        }
        // kind tag 0x02 == EventKind::DnsEvent (ds_telemetry::spool::kind_tag)
        if tag == 0x02 {
            out.push(bytes[body_start..body_end].to_vec());
        }
        i = body_end;
    }
    out
}

/// Return true if any record in the on-disk segment has the 0xFF overflow-marker tag.
fn segment_contains_overflow_marker(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        let tag = bytes[i];
        let len =
            u32::from_be_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]) as usize;
        let body_end = i + 5 + len;
        if body_end > bytes.len() {
            break;
        }
        if tag == 0xFF {
            return true;
        }
        i = body_end;
    }
    false
}

// ---------------------------------------------------------------------------
// Off-tmpfs scratch dir: prefer DS_WT_ROOT (btrfs-backed ~/tmp), then TMPDIR,
// then fall back to std::env::temp_dir(). Tests MUST NOT write spool segments
// to tmpfs (/tmp) because that eats RAM; btrfs-backed paths support CoW and
// keep spool I/O off the memory-backed tmpfs mount (repo convention: scratch
// under ~/tmp, never /tmp). DS_WT_ROOT points at the wave worktree root which
// lives on the same btrfs device as the repo; TMPDIR is the next-best override.
// ---------------------------------------------------------------------------

/// Return a btrfs-backed scratch root for spool segment files.
///
/// Resolution order (first set env var wins):
///   1. `DS_WT_ROOT` — the wave worktree root (btrfs, same device as repo).
///   2. `TMPDIR`     — caller-controlled override (CI may point this at btrfs).
///   3. `std::env::temp_dir()` — last resort (may be tmpfs; tests still pass).
fn spool_scratch_root() -> std::path::PathBuf {
    if let Ok(v) = std::env::var("DS_WT_ROOT") {
        if !v.is_empty() {
            return std::path::PathBuf::from(v);
        }
    }
    if let Ok(v) = std::env::var("TMPDIR") {
        if !v.is_empty() {
            return std::path::PathBuf::from(v);
        }
    }
    std::env::temp_dir()
}

/// Send a length-framed DNS query over TCP to `addr` and return the response bytes.
/// Loopback only; no live resolver is dialed.
async fn tcp_query(addr: SocketAddr, query: &[u8]) -> Vec<u8> {
    use tokio::net::TcpStream;
    let mut stream = TcpStream::connect(addr).await.expect("tcp connect to gate");
    let len = u16::try_from(query.len()).unwrap();
    stream.write_all(&len.to_be_bytes()).await.unwrap();
    stream.write_all(query).await.unwrap();
    stream.flush().await.unwrap();

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .expect("tcp len read timed out")
        .unwrap();
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await.unwrap();
    resp
}

/// Send a DNS query as a single UDP datagram to `addr` and return the response bytes.
/// DNS over UDP uses raw datagrams with no length prefix. Loopback only; no live
/// resolver is dialed. The response is bounded by the UDP receive buffer (65 535 bytes),
/// which is always sufficient for the synthetic loopback queries in these tests.
async fn udp_query(addr: SocketAddr, query: &[u8]) -> Vec<u8> {
    let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let sock = UdpSocket::bind(local)
        .await
        .expect("bind udp client socket");
    sock.send_to(query, addr).await.expect("udp send to gate");
    let mut buf = vec![0u8; 65535];
    let (n, _) = tokio::time::timeout(Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("udp recv timed out")
        .expect("udp recv error");
    buf.truncate(n);
    buf
}

#[tokio::test]
async fn spool_wired_gate_flushes_dns_event_to_disk() {
    // A dead upstream — the AAAA fast-NODATA path never contacts it, so the gate
    // responds immediately without waiting for any upstream round-trip.
    let forwarder = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_secs(2),
    };
    let config = ds_dnsgate::GateConfig {
        forwarder,
        ..ds_dnsgate::GateConfig::default()
    };

    // Open a real ds_telemetry Spool (the production LOG-3 disk-bounded spool).
    // A generous bound so no overflow fires here — this test proves the NORMAL path.
    // Spool segment scratch is routed off tmpfs: DS_WT_ROOT (btrfs-backed ~/tmp) is
    // preferred, then TMPDIR, then temp_dir() as last resort (repo convention).
    let dir = spool_scratch_root().join(format!(
        "ds-dnsgate-spooltest-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seg_path = dir.join("dns.spool");

    let bounds = ds_telemetry::SpoolBounds {
        max_records: 64,
        batch_size: 8,
        channel_depth: 64,
        flush_interval: Duration::from_millis(10),
    };
    let spool = ds_telemetry::Spool::open(&seg_path, bounds)
        .await
        .expect("open spool segment");
    let spool_sink = spool.sink();

    // Wire the SpoolSink through TelemetrySink to adapt it to the gate's EventSink
    // (DnsEvent -> to_envelope -> EventEnvelope -> SpoolSink). This is the exact
    // PRODUCTION wiring doc 11 §5.5 describes: replace the sink, not the emission sites.
    let event_sink: Arc<dyn ds_dnsgate::EventSink> =
        Arc::new(ds_dnsgate::TelemetrySink::new(spool_sink));

    // Bind the gate on loopback:0 — OS assigns the port; no network.
    let gate = ds_dnsgate::spawn_gate_with_sink(FixedStubPolicy::new(), config, event_sink)
        .await
        .expect("spawn gate");

    // Drive one AAAA query over TCP — the fast-NODATA path: no upstream contact,
    // immediate response. The handler emits one DnsEvent; TelemetrySink encodes it and
    // the SpoolSink channels it to the flush task.
    let query = query_bytes(0x5011, "v6.example.test.", RecordType::AAAA);
    let _resp_bytes = tokio::time::timeout(
        Duration::from_secs(5),
        tcp_query(gate.tcp_local_addr(), &query),
    )
    .await
    .expect("TCP round-trip timed out");

    // UDP-TRANSPORT PARITY (doc 11 §3.4): the gate's UDP and TCP handlers share the
    // same StubRequestHandler, the same EventSink, and the same spool — so a UDP-driven
    // query MUST land a DnsEvent on the SAME real spool the TCP query writes to. Drive an
    // identical AAAA fast-NODATA query over UDP (a distinct wire id, same qname, so the
    // emitted DnsEvent is byte-identical in shape to the TCP arm's) and prove the §3.4
    // byte-identical-across-transports guarantee at the DISK-PERSISTENCE layer — not just
    // the in-memory event path the sibling event tests cover. The fast-NODATA arm never
    // contacts the upstream, so the UDP round-trip is immediate.
    let udp_query_bytes = query_bytes(0x5012, "v6.example.test.", RecordType::AAAA);
    let _udp_resp_bytes = tokio::time::timeout(
        Duration::from_secs(5),
        udp_query(gate.udp_local_addr(), &udp_query_bytes),
    )
    .await
    .expect("UDP round-trip timed out");

    // Graceful shutdown: the gate stops accepting; the TelemetrySink arc inside the
    // gate is released. Then shut down the spool so the flush task drains everything
    // to disk before we inspect the segment.
    gate.shutdown().await.expect("gate shutdown");
    spool.shutdown().await.expect("spool shutdown");

    // Verify: the segment contains DnsEvent records (tag 0x02) whose decoded bodies
    // carry the qname the handler emitted. Both the TCP arm and the UDP arm above drove
    // an identical fast-NODATA query through the SAME gate / EventSink / spool, so the
    // segment must hold at LEAST TWO DnsEvent records — cross-transport parity at the
    // disk-persistence layer (doc 11 §3.4): UDP-driven and TCP-driven queries both land a
    // DnsEvent on the real spool, not just on the in-memory event path.
    let contents = std::fs::read(&seg_path).expect("reading spool segment");
    let dns_bodies = decode_dns_event_bodies(&contents);
    assert!(
        !dns_bodies.is_empty(),
        "at least one DnsEvent record (tag 0x02) must land on the spool segment after \
         driving a query through the gate; segment size = {} bytes",
        contents.len()
    );
    assert!(
        dns_bodies.len() >= 2,
        "§3.4 cross-transport parity at the disk layer: BOTH the TCP-driven and the \
         UDP-driven fast-NODATA query must land a DnsEvent on the real spool (expected \
         >= 2 DnsEvent records, got {}); segment size = {} bytes",
        dns_bodies.len(),
        contents.len()
    );

    // The on-disk body is: `rule_id|policy_layer|policy_version||<render_payload>`.
    // `render_payload` encodes the full doc 11 §5.5 D75 signal set for the FastNodata
    // arm driven above: qname=v6.example.test. qtype=28 path=FastNodata
    // aaaa_stripped=1 aaaa_only=Deferred(FastNodataNoForward)
    //
    // Decode the FIRST body and assert the complete §5.5 / D75 trigger signal set:
    //   * qname    — the queried name (the LOG-1 identity field)
    //   * qtype    — IANA numeric type 28 (AAAA)
    //   * path     — FastNodata (the §3.3 forward-free AAAA suppression arm)
    //   * aaaa_stripped — 1 (the one AAAA the guest asked for was stripped)
    //   * aaaa_only     — Deferred(FastNodataNoForward) (no parallel A-probe fired;
    //                     the §3.3 freeze keeps this arm forward-free, D75)
    let all_bodies_text: String = dns_bodies
        .iter()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect::<Vec<_>>()
        .join("\n");

    // qname: identity field — the query name the handler stamped on the DnsEvent.
    assert!(
        all_bodies_text.contains("qname=v6.example.test."),
        "§5.5 D75: DnsEvent body must carry qname=v6.example.test. (got {all_bodies_text:?})"
    );
    // qtype: 28 == AAAA (IANA numeric; the pre-freeze rendering uses the u16 code).
    assert!(
        all_bodies_text.contains("qtype=28"),
        "§5.5 D75: DnsEvent body must carry qtype=28 (AAAA) (got {all_bodies_text:?})"
    );
    // path: FastNodata — the §3.3 AAAA suppression path, no upstream forward.
    assert!(
        all_bodies_text.contains("path=FastNodata"),
        "§5.5 D75: DnsEvent body must carry path=FastNodata (got {all_bodies_text:?})"
    );
    // aaaa_stripped: 1 — the one AAAA RR the guest asked for was stripped by §3.3.
    assert!(
        all_bodies_text.contains("aaaa_stripped=1"),
        "§5.5 D75: DnsEvent body must carry aaaa_stripped=1 (got {all_bodies_text:?})"
    );
    // aaaa_only: Deferred(FastNodataNoForward) — the §3.3 recorded-deferral; no
    // parallel A-probe is fired on the forward-free AAAA fast-NODATA arm (D75 design
    // decision). The Debug rendering of DeferralReason::FastNodataNoForward is exact.
    assert!(
        all_bodies_text.contains("aaaa_only=Deferred(FastNodataNoForward)"),
        "§5.5 D75: DnsEvent body must carry aaaa_only=Deferred(FastNodataNoForward) \
         (got {all_bodies_text:?})"
    );

    // PROVENANCE PREFIX (doc 11 §6.7 provenance-on-every-event, at the DISK layer).
    // The on-disk body is `rule_id|policy_layer|policy_version|fp||<render_payload>`
    // (ds_telemetry::spool::render_payload): the four `|`-joined provenance/fingerprint
    // fields, then the payload. For a DnsEvent the credential fingerprint `fp` is empty
    // (DnsEvent envelopes carry no secret), so the empty `fp` field collapses the last two
    // joiners into the `||` separator that fronts the payload — i.e. the body opens with
    //   harness/allow-all|harness|<policy_version>||qname=...
    // The expected provenance triple is the harness allow-all policy (src/policy.rs
    // FixedStubPolicy / harness_default_provenance): rule_id='harness/allow-all',
    // policy_layer='harness', policy_version=<non-empty> ('allow-all' today; asserted
    // non-empty so a future version bump does not falsely fail this disk-layer guarantee).
    //
    // Assert the prefix on EVERY decoded DnsEvent body (both the TCP and UDP arms), so the
    // §6.7 guarantee is proven to ride EVERY transport's record on the real spool, not just
    // the in-memory event path the sibling tests cover.
    for body in &dns_bodies {
        let text = String::from_utf8_lossy(body);
        let (prefix, _payload) = text.split_once("||").unwrap_or_else(|| {
            panic!("§6.7: the on-disk DnsEvent body has a `||` provenance/payload separator (got {text:?})")
        });
        // The empty `fp` field's surrounding pipes ARE the `||` we split on, so the prefix
        // before it is exactly `rule_id|policy_layer|policy_version` (the trailing
        // empty-fp slot was consumed into the separator). Splitting on `|` yields the
        // three provenance fields: [rule_id, policy_layer, policy_version].
        let fields: Vec<&str> = prefix.split('|').collect();
        assert!(
            fields.len() >= 3,
            "§6.7: the provenance prefix carries rule_id|policy_layer|policy_version \
             before the `||` payload separator (got prefix {prefix:?})"
        );
        assert_eq!(
            fields[0], "harness/allow-all",
            "§6.7: the on-disk DnsEvent provenance prefix names the FixedStubPolicy harness \
             rule_id (got {prefix:?})"
        );
        assert_eq!(
            fields[1], "harness",
            "§6.7: the on-disk DnsEvent provenance prefix carries policy_layer=harness \
             (got {prefix:?})"
        );
        // The frozen `FixedStubPolicy` literal: `harness_default_provenance()` (src/policy.rs)
        // stamps `policy_version: "allow-all"`. The sibling in-memory provenance tests already
        // pin the exact triple; tighten this DISK-layer check from merely-non-empty to the EXACT
        // frozen literal so the on-disk provenance is asserted byte-for-byte against the harness
        // source of truth — a regression that silently re-stamped the harness version would now
        // break here, closing the gap with the in-memory provenance tests. (When a real shipped
        // policy version later replaces the harness literal, this assert is the single place the
        // disk-layer expectation is updated, in lockstep with src/policy.rs.)
        assert_eq!(
            fields[2], "allow-all",
            "§6.7: the on-disk DnsEvent provenance prefix carries the FROZEN FixedStubPolicy \
             policy_version literal 'allow-all' (harness_default_provenance, src/policy.rs) \
             (got {prefix:?})"
        );
    }

    assert!(
        !segment_contains_overflow_marker(&contents),
        "no SpoolOverflow marker expected on the normal path (got one in segment)"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// 12. Under a forced disk bound, a SpoolOverflow marker rides the surviving
//     stream (D116 visible-loss guarantee). A tiny-bound spool (max_records = 1,
//     batch_size = 100, flush_interval = 60s) is wired to the gate so events
//     accumulate in the ring between round-trips before any auto-drain fires.
//     Four queries are driven — three over TCP and one over UDP (§3.4 parity):
//     the UDP arm proves a UDP-driven query ALSO lands a DnsEvent on the SAME
//     spool as the TCP queries (closing the telemetry surface parity gap).
//     After the first event fills the ring, each subsequent event overflows it,
//     minting a DiskDrop 0xFF marker on the priority lane. The explicit spool
//     shutdown drains them all to disk (markers-first per D116).
//
//     Timing discipline: `batch_size: 100` prevents auto-drain after each event
//     (the ring only self-drains when it holds >= 100 records, which never
//     happens); `flush_interval: 60s` means the ticker fires only at startup
//     (the initial immediate tokio::time::interval tick, which hits an empty ring
//     and no-ops) and then not again before the explicit shutdown — so the ring
//     accumulates without the tick racing the overflow.
// ===========================================================================

#[tokio::test]
async fn spool_wired_gate_emits_overflow_marker_under_forced_bound() {
    // A live mock upstream so the A-query forwarded-answer path runs end-to-end
    // (the fast-NODATA path still fires for AAAA; both contribute DnsEvents).
    let v4 = Ipv4Addr::new(203, 0, 113, 11);
    let answer = vec![a_record("a.example.test.", v4, 60)];
    let zone = mock_up::Zone::new().set("a.example.test.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;

    let config = ds_dnsgate::GateConfig {
        forwarder: mock.forwarder(Duration::from_secs(2)),
        ..ds_dnsgate::GateConfig::default()
    };

    // Tiny-bound spool: max_records = 1 forces drop-oldest overflow after the
    // first payload record arrives in the ring.
    //   - batch_size = 100: the flush task does NOT auto-drain until 100 records
    //     accumulate (never reached with 3 events), so each event stays in the
    //     ring long enough for the next to trigger overflow.
    //   - flush_interval = 60s: the tick won't fire during the test window; the
    //     initial immediate tokio::time::interval tick hits an empty ring (no-op)
    //     before any events are sent.
    //   - channel_depth = 64: large enough that try_send always succeeds (the
    //     disk ring is the sole loss point; channel shed is not exercised here).
    // Spool segment scratch is routed off tmpfs via spool_scratch_root() (btrfs-backed
    // ~/tmp preferred; see the helper's doc comment for the resolution order).
    let dir = spool_scratch_root().join(format!(
        "ds-dnsgate-overflow-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seg_path = dir.join("dns.spool");

    let bounds = ds_telemetry::SpoolBounds {
        max_records: 1,
        batch_size: 100,
        channel_depth: 64,
        flush_interval: Duration::from_secs(60),
    };
    let spool = ds_telemetry::Spool::open(&seg_path, bounds)
        .await
        .expect("open tiny-bound spool");
    let spool_sink = spool.sink();

    let event_sink: Arc<dyn ds_dnsgate::EventSink> =
        Arc::new(ds_dnsgate::TelemetrySink::new(spool_sink));

    let gate = ds_dnsgate::spawn_gate_with_sink(FixedStubPolicy::new(), config, event_sink)
        .await
        .expect("spawn gate");

    let tcp_addr = gate.tcp_local_addr();
    // UDP-TRANSPORT PARITY (doc 11 §3.4): the gate's UDP and TCP handlers share the
    // same StubRequestHandler, the same EventSink, and the same spool — so a UDP-driven
    // query MUST land a DnsEvent on the SAME spool the TCP queries write to. This arm
    // proves the §3.4 byte-identical-across-transports guarantee on the TELEMETRY
    // surface, closing the parity gap: both transports drive DnsEvents into the spool.
    let udp_addr = gate.udp_local_addr();

    // Drive four queries: TCP × 3 + UDP × 1; each emits one DnsEvent via
    // TelemetrySink → SpoolSink. The flush task receives them and pushes each to the
    // ring:
    //   event 1 (TCP): ring 0 → 1 (no overflow; batch 1 < 100, no auto-drain)
    //   event 2 (TCP): ring full (1 >= max_records=1) → drop-oldest, push, mint
    //                  DiskDrop SpoolOverflow marker onto the priority lane
    //   event 3 (TCP): same as event 2 — a second overflow marker minted
    //   event 4 (UDP): same — a third overflow marker (the UDP arm)
    // The explicit spool shutdown drains all pending records (markers first per
    // D116's priority-lane invariant), writing the 0xFF receipts to the segment.

    // Query 1 (TCP): AAAA fast-NODATA (no upstream round-trip; immediate response).
    let q1 = query_bytes(0x6001, "v6.example.test.", RecordType::AAAA);
    tokio::time::timeout(Duration::from_secs(5), tcp_query(tcp_addr, &q1))
        .await
        .expect("query 1 timed out");

    // Query 2 (TCP): A forwarded-answer (via the mock upstream).
    let q2 = query_bytes(0x6002, "a.example.test.", RecordType::A);
    tokio::time::timeout(Duration::from_secs(5), tcp_query(tcp_addr, &q2))
        .await
        .expect("query 2 timed out");

    // Query 3 (TCP): another AAAA fast-NODATA (no upstream round-trip).
    let q3 = query_bytes(0x6003, "v6.example.test.", RecordType::AAAA);
    tokio::time::timeout(Duration::from_secs(5), tcp_query(tcp_addr, &q3))
        .await
        .expect("query 3 timed out");

    // Query 4 (UDP): AAAA fast-NODATA over UDP — proving the UDP transport ALSO
    // drives a DnsEvent onto the SAME spool (doc 11 §3.4 UDP/TCP parity on the
    // telemetry surface). The fast-NODATA path never contacts the upstream so the
    // round-trip is immediate. The gate's UDP handler is the same StubRequestHandler
    // that TCP uses (server.rs wires both with the same events Arc), so the event
    // lands on the spool via the same TelemetrySink path.
    let q4 = query_bytes(0x6004, "v6.example.test.", RecordType::AAAA);
    tokio::time::timeout(Duration::from_secs(5), udp_query(udp_addr, &q4))
        .await
        .expect("query 4 (UDP) timed out");

    // Shutdown the gate first (releases the event_sink Arc inside the gate), then
    // shut down the spool so the flush task's explicit-shutdown path drains the
    // pending ring contents (markers-first) to the segment file.
    gate.shutdown().await.expect("gate shutdown");
    spool.shutdown().await.expect("spool shutdown");

    // The segment must contain at least one SpoolOverflow marker (0xFF tag):
    // D116 mandates visible loss, never silent loss.
    let contents = std::fs::read(&seg_path).expect("reading overflow segment");
    assert!(
        segment_contains_overflow_marker(&contents),
        "a SpoolOverflow marker (0xFF tag) must appear on the segment when the tiny-bound \
         spool overflows under a driven DnsEvent flood (D116 visible-loss invariant); \
         segment size = {} bytes",
        contents.len()
    );

    // The segment must also carry surviving DnsEvent payload records (tag 0x02):
    // the overflow marker rides the surviving stream, never replaces it.
    let dns_bodies = decode_dns_event_bodies(&contents);
    assert!(
        !dns_bodies.is_empty(),
        "at least one DnsEvent payload record must survive the overflow flush alongside \
         the SpoolOverflow marker"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// 12b. The spool SEGMENT round-trip for the reload-boundary + warm-restart
//      PolicyDecision envelopes (doc 11 §5.3 / §5.5 / §8.4, D116). Test 11 above
//      proves a query-path `DnsEvent` lands on a real on-disk segment; THIS leg
//      proves the OTHER two production envelopes the `DS_DNSGATE_DROP_SPOOL_LIVE`
//      route wires (`main.rs`: `SpoolDropSink::observe_drop` for reload-boundary
//      drops + the warm-restart completion emit) ALSO round-trip through a REAL
//      `ds_telemetry::Spool` opened against a tmpdir root — no gate, no kernel, no
//      network (D50 loopback/synthetic).
//
//      Both `SnapshotDropEvent::to_envelope()` and
//      `WarmRestartCompletionEvent::to_envelope()` encode an
//      `EventKind::PolicyDecision` envelope, which lands under kind tag 0x04 on
//      disk (`ds_telemetry::spool::kind_tag`) — DISTINCT from a `DnsEvent`'s 0x02 —
//      so the two lifecycle envelopes share the PolicyDecision lane on the segment.
//      The test opens the spool, emits all THREE reload-boundary drop reasons plus
//      one completion event onto the SAME `SpoolSink` the production route hands
//      them to (`to_envelope()` → fire-and-forget `EventSink::emit`, exactly as
//      `SpoolDropSink` does), flushes, `shutdown().await`s — the drain barrier, NO
//      fixed sleep — reads the raw segment back, and asserts:
//        * the three drop reason tokens (stale_fan_out / content_hash_mismatch /
//          schema_failure) round-trip DISTINCT on readback, and
//        * `distinct_ips_substantiated` round-trips in the completion payload.
//
//      On-disk PolicyDecision record body (ds_telemetry::spool::render_payload):
//        `rule_id|policy_layer|policy_version|fp|<payload>` — for these envelopes
//        the credential fingerprint `fp` is empty (no secret crosses), so the last
//        two joiners collapse into `||` that fronts the free `render_payload()` text.
// ===========================================================================

/// Decode the raw on-disk segment bytes and return all PolicyDecision payload
/// bodies (kind tag == 0x04). Framing mirrors [`decode_dns_event_bodies`] /
/// `append_batch`: per record a 1-byte kind tag, a 4-byte big-endian body length,
/// then the body.
fn decode_policy_decision_bodies(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        let tag = bytes[i];
        let len =
            u32::from_be_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]) as usize;
        let body_start = i + 5;
        let body_end = body_start + len;
        if body_end > bytes.len() {
            break;
        }
        // kind tag 0x04 == EventKind::PolicyDecision (ds_telemetry::spool::kind_tag)
        if tag == 0x04 {
            out.push(bytes[body_start..body_end].to_vec());
        }
        i = body_end;
    }
    out
}

#[tokio::test]
async fn spool_segment_round_trips_reload_and_warm_restart_envelopes() {
    use ds_dnsgate::event::{
        EventProvenance, SnapshotDropEvent, SnapshotDropReason, WarmRestartCompletionEvent,
    };
    // The SpoolSink `emit` inherent-vs-trait method comes from ds_telemetry's EventSink —
    // brought into scope exactly as the production `SpoolDropSink` (main.rs) does.
    use ds_telemetry::event::EventSink as _;

    // A non-empty POL-3 triple (§6.7: provenance on EVERY event) — the live committed
    // version's triple the production subscriber / rebuild paths stamp on these envelopes.
    let provenance = || EventProvenance {
        rule_id: "rule-allow".into(),
        policy_layer: "system-baseline".into(),
        policy_version: "pol1/v-loose".into(),
    };

    // Open a REAL ds_telemetry Spool against a tmpdir root routed OFF tmpfs (btrfs-backed
    // ~/tmp via DS_WT_ROOT, then TMPDIR, then temp_dir() — repo convention; test 11's helper).
    let dir = spool_scratch_root().join(format!(
        "ds-dnsgate-spoolrt-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let seg_path = dir.join("reload.spool");

    // Generous bounds so no overflow fires — this proves the NORMAL round-trip path. The
    // flush_interval is irrelevant to correctness here: `shutdown().await` drains the flush
    // task fully before we read (the synchronization barrier — no sleep).
    let bounds = ds_telemetry::SpoolBounds {
        max_records: 64,
        batch_size: 8,
        channel_depth: 64,
        flush_interval: Duration::from_millis(10),
    };
    let spool = ds_telemetry::Spool::open(&seg_path, bounds)
        .await
        .expect("open spool segment");
    let sink = spool.sink();

    // The THREE DISTINCT reload-boundary drop reasons the production `SpoolDropSink`
    // (main.rs, DS_DNSGATE_DROP_SPOOL_LIVE) routes onto this spool: the benign
    // forward-only-seq dedup (StaleFanOut) plus the two integrity rejections
    // (ContentHashMismatch / SchemaFailure). Each is encoded via `to_envelope()` and
    // handed to the SpoolSink exactly as `SpoolDropSink::observe_drop` does.
    let stale = SnapshotDropEvent::stale_fan_out(4, 7, provenance());
    let hash_mismatch = SnapshotDropEvent {
        reason: SnapshotDropReason::ContentHashMismatch,
        dropped_seq: 9,
        committed_seq: 8,
        provenance: provenance(),
    };
    let schema_fail = SnapshotDropEvent {
        reason: SnapshotDropReason::SchemaFailure,
        dropped_seq: 11,
        committed_seq: 10,
        provenance: provenance(),
    };
    for drop in [&stale, &hash_mismatch, &schema_fail] {
        let envelope = drop.to_envelope().expect("a live POL-3 triple encodes");
        sink.emit(envelope);
    }

    // The warm-restart COMPLETION envelope the SAME route emits once a rebuild reconciles
    // (main.rs warm-restart leg). `distinct_ips_substantiated` is the substantiation-coverage
    // scalar the §5.5 telemetry join reconciles against the kernel dump — the value under test.
    const SUBSTANTIATED: usize = 42;
    let completion = WarmRestartCompletionEvent::new(
        SUBSTANTIATED,
        3,    // provenance_gaps
        45,   // entries_rebuilt
        true, // reconciles
        provenance(),
    );
    let completion_envelope = completion
        .to_envelope()
        .expect("a live POL-3 triple encodes");
    sink.emit(completion_envelope);

    // Drain barrier: `shutdown().await` flushes the channel + flush task fully to disk before
    // returning (NO fixed sleep — the shutdown IS the synchronization point).
    spool.shutdown().await.expect("spool shutdown");

    // Read the raw segment back and pull every PolicyDecision body (tag 0x04) — the lane BOTH
    // lifecycle envelopes land on, distinct from a DnsEvent's 0x02.
    let contents = std::fs::read(&seg_path).expect("reading spool segment");
    let bodies = decode_policy_decision_bodies(&contents);
    assert!(
        bodies.len() >= 4,
        "all three drop envelopes + the completion envelope must land as PolicyDecision \
         records (tag 0x04) on the real on-disk segment (expected >= 4, got {}); segment size \
         = {} bytes",
        bodies.len(),
        contents.len()
    );

    let all_text: String = bodies
        .iter()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect::<Vec<_>>()
        .join("\n");

    // THE THREE DROP REASON TOKENS ARE DISTINCT ON READBACK (doc 11 §5.3): a benign
    // stale-fan-out dedup is separable ON DISK from either integrity NACK. Recover the
    // `reason=<token>` from each drop body and assert the set is EXACTLY the three expected,
    // distinct tokens — never one token silently standing in for another.
    let reasons: std::collections::BTreeSet<String> = bodies
        .iter()
        .filter_map(|b| {
            let text = String::from_utf8_lossy(b);
            let (_, after) = text.split_once("snapshot_drop reason=")?;
            Some(after.split_whitespace().next().unwrap_or("").to_string())
        })
        .collect();
    let expected: std::collections::BTreeSet<String> =
        ["stale_fan_out", "content_hash_mismatch", "schema_failure"]
            .into_iter()
            .map(String::from)
            .collect();
    assert_eq!(
        reasons, expected,
        "the three reload-boundary drop reason tokens must round-trip DISTINCT off the real \
         segment (got {reasons:?})"
    );
    assert_eq!(
        reasons.len(),
        3,
        "exactly three distinct drop reason tokens on readback (no collision, no substitution)"
    );

    // distinct_ips_substantiated ROUND-TRIPS in the completion payload (doc 11 §5.5 / §8.4):
    // the substantiation-coverage scalar an operator's rebuild dashboard joins on is recoverable
    // byte-for-byte off the segment.
    assert!(
        all_text.contains(&format!(
            "warm_restart_complete distinct_ips_substantiated={SUBSTANTIATED}"
        )),
        "the warm-restart completion payload must round-trip distinct_ips_substantiated=\
         {SUBSTANTIATED} off the real segment (got {all_text:?})"
    );

    // No SpoolOverflow marker on the generous-bound normal path (D116 visible-loss is the
    // overflow leg's concern — test 12 above).
    assert!(
        !segment_contains_overflow_marker(&contents),
        "no SpoolOverflow marker expected on the normal-bound reload/warm-restart round-trip \
         (got one in segment)"
    );

    std::fs::remove_dir_all(&dir).ok();
}

// ===========================================================================
// SPLIT-OUT submodules (test-only reorg; behavior-preserving). The snapshot /
// reload-boundary / D72 forward-only / D53 revocation-sweep / D120 verify-only
// machinery — sections 13-18 below — was extracted from this once-oversized file
// into cohesive sibling files under `tests/event_surface/` to keep the DnsEvent
// query-path surface (sections 1-12, above) reviewable. Each is `#[path]`-included
// as a submodule of THIS integration-test binary, so the shared root helpers
// (`query_bytes`, `tcp_query`, `udp_query`) resolve via `crate::` and all tests
// still compile + run in the SAME `event_surface` test target (one binary).
// ===========================================================================

#[path = "event_surface/snapshot_reload_wiring.rs"]
mod snapshot_reload_wiring;

#[path = "event_surface/forward_only_drop.rs"]
mod forward_only_drop;

#[path = "event_surface/revocation_sweep.rs"]
mod revocation_sweep;

#[path = "event_surface/verify_only_nack.rs"]
mod verify_only_nack;

// ===========================================================================
// SHARED TEST-SUPPORT: the release-barrier `SnapshotSink` decorator (doc 11 §5.3 / §5.5,
// D72). Single-sourced here at the `event_surface` test-binary CRATE ROOT so every submodule
// of THIS integration test reaches ONE copy via `crate::gated_snapshot_sink::GatedCommitSink`
// (the §18b D53 refcount witnesses drive it; the `snapshot_reload_wiring` back-pressure
// witnesses grow the SAME barrier around a `BoundaryZoneSink`). It wraps a PRODUCTION
// `SnapshotSink` and gates its FIRST `commit_snapshot` on a one-shot release barrier so a
// back-pressure wedge is driven with NO fixed sleep, while EVERY commit AND EVERY drop
// delegate to the inner sink (the decorator FORWARD RULE: `observe_snapshot_drop` is a
// DEFAULTED no-op, so a wrapper that forgets to delegate silently SHADOWS the inner sink's
// production drop routing — this decorator forwards it, and the `forward_rule` module below
// pins BOTH forwards as an executable assertion).
// ===========================================================================
mod gated_snapshot_sink {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use ds_dnsgate::event::SnapshotDropEvent;
    use ds_dnsgate::server::{BoundarySnapshot, SnapshotSink};

    /// A decorator [`SnapshotSink`] that wraps a PRODUCTION inner sink (e.g. the
    /// `SnapshotCommitSink`) and gates its FIRST `commit_snapshot` on a one-shot release barrier
    /// — so the back-pressure wedge is driven with NO fixed sleep. The first commit:
    ///   * fires `entered` (so the test learns, via a happens-before signal rather than a timed
    ///     poll, that the subscriber has STOPPED draining and the bounded feed is now filling
    ///     behind it — the deterministic wedge trigger), then
    ///   * parks on `release.recv()` until the test sends the token,
    /// while EVERY commit and EVERY drop delegates to the wrapped inner sink — so the real
    /// evaluator re-source + §5.4 revocation sweep + reportable enforcer run byte-unchanged, and
    /// the stale-fan-out drop signal is never shadowed (the [`SnapshotSink`] decorator FORWARD
    /// RULE: delegate every defaulted method, not just the one wrapped). The barrier blocks only
    /// the subscriber's own worker (both callers run on a multi-thread runtime), never the burst
    /// publisher, so the feed provably back-pressures WITHOUT any `tokio::time::sleep`.
    pub(crate) struct GatedCommitSink<S: SnapshotSink> {
        inner: S,
        commits_started: AtomicUsize,
        /// Fired once, as the subscriber ENTERS its first commit (before it parks) — the test
        /// awaits this instead of polling a counter behind a sleep.
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        /// The release barrier: the FIRST commit blocks on `recv()` until the test sends.
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl<S: SnapshotSink> GatedCommitSink<S> {
        pub(crate) fn new(
            inner: S,
            entered: tokio::sync::oneshot::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        ) -> Self {
            Self {
                inner,
                commits_started: AtomicUsize::new(0),
                entered: Mutex::new(Some(entered)),
                release: Mutex::new(Some(release)),
            }
        }
    }

    impl<S: SnapshotSink> SnapshotSink for GatedCommitSink<S> {
        fn commit_snapshot(&self, snapshot: &BoundarySnapshot) {
            let nth = self.commits_started.fetch_add(1, Ordering::SeqCst);
            if nth == 0 {
                // Signal the test that the subscriber has entered its first commit — it will now
                // park here, so the bounded feed fills behind it (a deterministic barrier the
                // test awaits, replacing any fixed-sleep wedge observation).
                if let Some(tx) = self.entered.lock().expect("entered mutex").take() {
                    let _ = tx.send(());
                }
                // Park THIS subscriber worker until the test releases it (one-shot). Blocks only
                // this worker (multi-thread runtime), never the burst publisher.
                if let Some(rx) = self.release.lock().expect("release mutex").take() {
                    let _ = rx.recv();
                }
            }
            self.inner.commit_snapshot(snapshot);
        }

        fn observe_snapshot_drop(&self, drop: SnapshotDropEvent) {
            // DELEGATE — never shadow the inner sink's production drop routing (the decorator
            // FORWARD RULE). Forward-only-seq bursts commit every snapshot, so this leg does not
            // fire in those witnesses, but the decorator stays transparent to the drop signal
            // regardless (the `forward_rule` assertion below pins it).
            self.inner.observe_snapshot_drop(drop);
        }
    }

    // -----------------------------------------------------------------------
    // FORWARD-RULE assertion: the shared helper forwards BOTH `commit_snapshot` AND
    // `observe_snapshot_drop` to the wrapped inner `SnapshotSink` (never the trait's defaulted
    // no-op), driven with NO fixed sleep — the release token is pre-buffered so the barriered
    // first commit's `recv()` returns at once, no second thread and no timing. Loopback /
    // synthetic only (D50): no gate, no network, no kernel — only the public `SnapshotSink`
    // seam and an in-memory recording inner sink.
    // -----------------------------------------------------------------------
    mod forward_rule {
        use super::*;
        use std::sync::Arc;

        use ds_dnsgate::event::EventProvenance;

        /// A recording inner `SnapshotSink`: counts commits and captures forwarded drops so the
        /// test reads back exactly what the decorator delegated (clones share one backing).
        #[derive(Clone, Default)]
        struct RecordingInnerSink {
            commits: Arc<AtomicUsize>,
            drops: Arc<Mutex<Vec<SnapshotDropEvent>>>,
        }

        impl RecordingInnerSink {
            fn commits(&self) -> usize {
                self.commits.load(Ordering::SeqCst)
            }
            fn drops(&self) -> Vec<SnapshotDropEvent> {
                self.drops.lock().expect("drops mutex").clone()
            }
        }

        impl SnapshotSink for RecordingInnerSink {
            fn commit_snapshot(&self, _snapshot: &BoundarySnapshot) {
                self.commits.fetch_add(1, Ordering::SeqCst);
            }
            fn observe_snapshot_drop(&self, drop: SnapshotDropEvent) {
                self.drops.lock().expect("drops mutex").push(drop);
            }
        }

        /// A non-empty POL-3 triple for the synthetic drop event (§6.7: provenance on every event).
        fn provenance() -> EventProvenance {
            EventProvenance {
                rule_id: "rule-allow".into(),
                policy_layer: "system-baseline".into(),
                policy_version: "pol1/v-loose".into(),
            }
        }

        #[test]
        fn gated_commit_sink_forwards_both_commit_and_drop_to_the_inner_sink() {
            let inner = RecordingInnerSink::default();
            let (entered_tx, mut entered_rx) = tokio::sync::oneshot::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            // Pre-buffer the release token so the FIRST commit's `recv()` returns at once — the
            // barrier is preserved (a real one-shot park), but this assertion needs no second
            // thread and NO fixed sleep.
            release_tx.send(()).expect("buffer the release token");

            let gated = GatedCommitSink::new(inner.clone(), entered_tx, release_rx);

            // commit_snapshot FORWARDS to the inner sink (the first commit consumes the token).
            gated.commit_snapshot(&BoundarySnapshot::new(1, "fwd.example."));
            assert_eq!(
                inner.commits(),
                1,
                "the decorator forwards commit_snapshot to the wrapped inner SnapshotSink"
            );
            assert!(
                entered_rx.try_recv().is_ok(),
                "the first commit fired the `entered` barrier signal as it entered"
            );

            // observe_snapshot_drop FORWARDS to the inner sink — the decorator FORWARD RULE, not
            // the trait's defaulted no-op that would silently shadow the drop signal.
            gated.observe_snapshot_drop(SnapshotDropEvent::stale_fan_out(4, 7, provenance()));
            let forwarded = inner.drops();
            assert_eq!(
                forwarded.len(),
                1,
                "the decorator forwards observe_snapshot_drop to the inner sink (the forward rule)"
            );
            assert!(
                forwarded[0].is_stale_fan_out(),
                "the forwarded drop kept its benign forward-only-seq reason"
            );
            assert_eq!(forwarded[0].dropped_seq, 4);
            assert_eq!(forwarded[0].committed_seq, 7);
        }

        #[test]
        fn gated_commit_sink_forwards_every_post_barrier_commit() {
            // Only the FIRST commit is barriered; the helper must forward EVERY later commit with
            // no gating (the burst witnesses depend on this). Pre-buffer the token for commit #1.
            let inner = RecordingInnerSink::default();
            let (entered_tx, _entered_rx) = tokio::sync::oneshot::channel::<()>();
            let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
            release_tx.send(()).expect("buffer the release token");
            let gated = GatedCommitSink::new(inner.clone(), entered_tx, release_rx);

            for seq in 1..=3 {
                gated.commit_snapshot(&BoundarySnapshot::new(seq, "fwd.example."));
            }
            assert_eq!(
                inner.commits(),
                3,
                "every commit — barriered first and unbarriered rest — reaches the inner sink"
            );
        }
    }
}

// ===========================================================================
// 18b. §5.4 / D53 REVOCATION-SWEEP REFCOUNT-CORRECTNESS WITNESSES (additive, test-only;
//      the sweep / refcount src behavior is UNCHANGED). The module-18 witness
//      (`event_surface/revocation_sweep.rs`) drives a SEVERING-rung reload all the way to
//      the reportable enforcer, but only over SOLE-reference IPs in ONE session. Two
//      refcount-correctness edges the reverse-index discipline (doc 11 §5.4 / D53/W4
//      under-delete bias, the `(session, ip)` distinct-name count in
//      `txn::InMemoryReverseIndex`) must hold ACROSS THE SAME PRODUCTION WIRE-RELOAD COMMIT
//      PATH (`SnapshotCommitSink::with_revocation_sweep_enforced` → `route_sweep_outcome` →
//      reportable `RecordingSweepEnforcer`) are not yet witnessed out-of-crate:
//
//        (1) SHARED-CDN: a single IP held by BOTH a revoked name and a SURVIVING sibling
//            must NOT be withdrawn / flushed across a wire reload — only the revoked name's
//            SOLE-reference IP is. The under-delete bias must survive the commit path, not
//            just the in-crate sweep core.
//        (2) CROSS-SESSION: two DISTINCT sessions admit the SAME IP; denying ONLY session A
//            frees A's element ((A,ip) → 0) while B's element is NEVER withdrawn ((B,ip) ≥ 1).
//            The over-delete guard is the `(session, ip)` key in the shared reverse index —
//            a per-session count, never a flat per-IP one — so A's decref can never touch B's
//            still-live element.
//
//      Both run against the PRODUCTION combined-commit wiring exactly as the module-18 witness
//      does (a real loopback gate, the host-LOCAL `boundary_snapshot_feed` →
//      `watch_snapshots` → `SnapshotCommitSink::with_revocation_sweep_enforced`), and observe
//      the routed sever through a `RecordingSweepEnforcer` we own and read back. The
//      cross-session leg additionally binds the W1/W2 transaction's shared DNS-2b reverse
//      index by sweeping the SAME `LiveAdmissions` an `AdmissionStores` minted into (so the
//      `(session, ip)` count the sweep reads is the one the admit incref'd — one refcount, no
//      drift), so the over-delete guard is exercised on the REAL shared index, not the
//      survivor-derived fallback. Loopback / synthetic only (§5.3): no live kernel, no
//      network, the reportable in-memory enforcer. No new D-number; the FROZEN
//      `DnsVerdict::Deny` keeps its three fields {rcode_policy, rung, provenance}.
// ===========================================================================
mod d53_sweep_refcount_correctness {
    use std::net::IpAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use ds_contracts::dns_admission::{
        AddressFamily, AdmissionType, AdmittedAddr, Instant, Provenance,
    };
    use ds_contracts::flush::DstKey;
    use ds_dnsgate::policy::{PolicyCorePolicy, TtlClamp};
    use ds_dnsgate::server::{
        boundary_snapshot_feed, spawn_gate, watch_snapshots, BoundarySnapshot, GateConfig,
        LiveAdmission, LiveAdmissions, LiveAskGrant, RecordingSweepEnforcer, SnapshotCommitSink,
        SweepEnforcer,
    };
    use ds_dnsgate::txn::{AdmissionInputs, AdmissionOutcome, AdmissionStores};

    // The release-barrier `SnapshotSink` decorator is now a single-sourced crate-root helper.
    use crate::gated_snapshot_sink::GatedCommitSink;
    use policy_core::pol1_eval::{compose, ComposedPolicy};

    use ds_contracts::pol1::parse_layer;

    // ── Severing-rung POL-1 layer fixtures, mirroring the module-18 witness shape (doc 11
    //    §5.4 / D53). LOOSE admits the witness names; the TIGHT variants below each flip ONE
    //    name to a SEVERING (`kill+snapshot`, block-or-higher → §5.4 flush) Deny while the
    //    sibling / the other session's name stays allowlisted — so the sweep revokes exactly
    //    the one name and the reverse-index refcount decides which element is freed. ──

    /// LOOSE: allowlists every name the two witnesses admit under — all ADMIT. The startup
    /// version each synthetic admission is minted under.
    const SWEEP_LAYER_LOOSE: &str = r#"
schema_version: pol1/v-loose
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: tighten.example
  - domain: kept.example
  - domain: a.example
  - domain: b.example
  - domain: grant-a.example
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// TIGHT (shared-CDN leg): `tighten.example` is BLOCKED at a SEVERING rung; `kept.example`
    /// stays allowlisted (the survivor that co-references the shared-CDN IP). Re-sourcing
    /// LOOSE → this flips ONLY `tighten.example` Allow → severing Deny.
    const SWEEP_LAYER_TIGHT_TIGHTEN: &str = r#"
schema_version: pol1/v-tight
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: kept.example
  - domain: a.example
  - domain: b.example
blocklist:
  - domain: tighten.example
    reason: tightened-policy-push
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// TIGHT (cross-session leg): `a.example` (session A's name) is BLOCKED at a SEVERING rung;
    /// `b.example` (session B's name) stays allowlisted. Both names resolve to the SAME shared
    /// IP, but the verdict is name-scoped — so re-sourcing LOOSE → this revokes ONLY session A's
    /// admission. The shared IP frees for `(A, ip)` but `(B, ip)` keeps its non-zero count.
    const SWEEP_LAYER_TIGHT_DENY_A: &str = r#"
schema_version: pol1/v-tight-a
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: tighten.example
  - domain: kept.example
  - domain: b.example
blocklist:
  - domain: a.example
    reason: tightened-policy-push
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// TIGHT (cross-session ASK-GRANT leg): `grant-a.example` (session A's PARKED ask-grant name)
    /// is BLOCKED at a SEVERING rung; `b.example` (session B's surviving ADMISSION name) stays
    /// allowlisted. The grant and the admission share ONE CDN IP. Re-sourcing LOOSE → this EVICTS
    /// session A's ask-grant (a `vN+1` deny outranks the user approval, fail-closed) while session
    /// B's admission survives — so the shared IP frees for `(A, ip)` but `(B, ip)` keeps its
    /// non-zero count: the ask-grant decref keys on `(session, ip)` and never over-deletes the
    /// shared IP a surviving sibling holds (the unified under-delete refcount reads BOTH legs, W4).
    const SWEEP_LAYER_TIGHT_DENY_GRANT_A: &str = r#"
schema_version: pol1/v-tight-grant-a
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: tighten.example
  - domain: kept.example
  - domain: a.example
  - domain: b.example
blocklist:
  - domain: grant-a.example
    reason: tightened-policy-push
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// Compose one synthetic POL-1 layer into the deny-wins document the running
    /// `PolicyCorePolicy` decides against — the SAME `parse_layer` → `compose` lift the
    /// module-18 witness (and `main`'s startup + reload paths) use (POL-3: no rule reimplemented).
    fn composed(layer_yaml: &str) -> ComposedPolicy {
        let layer = parse_layer(layer_yaml).expect("the witness POL-1 layer parses");
        compose(&[layer], &[])
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("the witness IP parses")
    }

    /// The canonical `AdmittedAddr::to_dst_key` form for an IP — built through the SAME frozen
    /// projection the §5.4 routing (and the admission insert) uses, so the witness asserts
    /// byte-exact key agreement without re-deriving the hex (matching the module-18 witness).
    fn dst_key_of(addr: IpAddr) -> DstKey {
        admitted_addr(addr).to_dst_key()
    }

    /// Project a `std::net::IpAddr` onto the frozen family-agnostic `AdmittedAddr` — the SAME
    /// projection `txn::to_admitted_addr` / `server::admitted_addr` do, so the reverse-index
    /// refcount read (`AdmissionStores::reverse_refcount`) keys on the byte-exact octets the
    /// admit insert + the sweep delete agree on.
    fn admitted_addr(addr: IpAddr) -> AdmittedAddr {
        match addr {
            IpAddr::V4(v4) => AdmittedAddr {
                family: AddressFamily::V4,
                octets: v4.octets().to_vec(),
            },
            IpAddr::V6(v6) => AdmittedAddr {
                family: AddressFamily::V6,
                octets: v6.octets().to_vec(),
            },
        }
    }

    /// Build the `AdmissionInputs` the W1/W2 transaction runs for a name resolving to one or
    /// more IPs under a CHOSEN session — so two DISTINCT sessions can admit the SAME shared IP
    /// and the `(session, ip)` reverse index keeps a per-session count. Mirrors the server.rs
    /// `sweep_inputs_multi` shape but with a caller-chosen `session_uuid` + `session_index` (the
    /// cross-session leg needs distinct sessions; the in-crate helper is fixed to one session).
    fn admission_inputs(
        session: &str,
        session_index: u32,
        fqdn: &str,
        addrs: Vec<IpAddr>,
    ) -> AdmissionInputs {
        AdmissionInputs {
            session_uuid: session.into(),
            session_index,
            original_query_fqdn: fqdn.into(),
            terminal_addrs: addrs,
            chain_min_ttl: 300,
            ttl_floor: 60,
            ttl_ceil: 900,
            grace: 60,
            provenance: Provenance {
                rule_id: "rule-allow".into(),
                policy_layer: "system-baseline".into(),
                policy_version: "pol1/v-loose".into(),
            },
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
        }
    }

    #[tokio::test]
    async fn shared_cdn_ip_survives_a_wire_reload_while_the_sole_ref_ip_is_withdrawn_and_flushed() {
        // (1) SHARED-CDN, across the PRODUCTION WIRE-RELOAD COMMIT PATH. The module-18 witness
        // only severs SOLE-reference IPs; this proves the D53/W4 under-delete bias survives the
        // full `SnapshotCommitSink::with_revocation_sweep_enforced` → `route_sweep_outcome` path
        // when an IP is SHARED between a revoked name and a survivor. Admit (under LOOSE) the
        // name the tightened version severs at TWO IPs — a SOLE-reference IP it alone holds AND a
        // SHARED-CDN IP a still-allowed sibling also references — plus the sibling at that SAME
        // shared IP. Reload a committed snapshot that DENIES the severed name at a SEVERING rung.
        // The admitter-LAST commit re-sources the evaluator FIRST, THEN sweeps → ONLY the
        // sole-reference IP is withdrawn + flushed; the shared IP is NEITHER (the survivor still
        // references it; the reverse-index refcount stays non-zero — bias to under-delete).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v-loose");

        // ── ADMIT under LOOSE. The bare synthetic registry (no bound map) exercises the
        //    survivor-derived refcount — an IP frees iff no SURVIVOR (any session) still holds
        //    it — which is exactly the under-delete bias this leg witnesses across the wire. ──
        let admissions = LiveAdmissions::new();
        let sole_ip = ip("203.0.113.7"); // tighten.example's SOLE-reference IP
        let shared_ip = ip("198.51.100.9"); // shared between tighten.example + kept.example
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", sole_ip));
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", shared_ip));
        admissions.admit(LiveAdmission::new("sess-b", "kept.example", shared_ip));
        assert_eq!(admissions.len(), 3, "three live admissions under LOOSE");

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let enforcer_dyn: Arc<dyn SweepEnforcer> = enforcer.clone();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer_dyn,
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // RELOAD the SEVERING-rung version that denies ONLY tighten.example.
        feed.publish(BoundarySnapshot::with_policy(
            7,
            "pushed.example.",
            composed(SWEEP_LAYER_TIGHT_TIGHTEN),
            TtlClamp::DEFAULT,
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(
            commits, 1,
            "the severing-rung snapshot re-sourced + swept once"
        );
        assert_eq!(
            gate.policy_version(),
            "pol1/v-tight",
            "the running evaluator re-sourced its composed document admitter-LAST"
        );

        // The DNS-2b registry: BOTH tighten.example records were revoked; kept.example survived.
        let survivors = admissions.snapshot();
        assert_eq!(survivors.len(), 1, "only the still-allowed sibling remains");
        assert_eq!(survivors[0].fqdn, "kept.example.");
        assert_eq!(survivors[0].ip, shared_ip);

        // The REPORTABLE allow-set delete: EXACTLY the sole-reference IP is withdrawn — the
        // shared IP is NOT (kept.example still references it; the under-delete bias survives the
        // commit path, D53/W4).
        let withdrawn = enforcer.withdrawn();
        assert_eq!(
            withdrawn.len(),
            1,
            "exactly the freed sole-reference IP is withdrawn across the wire reload"
        );
        assert_eq!(withdrawn[0].dst_key, dst_key_of(sole_ip));
        assert!(
            !withdrawn.iter().any(|w| w.dst_key == dst_key_of(shared_ip)),
            "the shared-CDN IP is NEVER withdrawn — a survivor still references it (under-delete bias)"
        );

        // The REPORTABLE conntrack flush (the D53 sever): narrowed to EXACTLY the freed
        // sole-reference IP; the shared IP is NOT flushed.
        let flushed = enforcer.flushed();
        assert_eq!(
            flushed.len(),
            1,
            "a severing-rung reload fired the rung-conditional conntrack flush (D53)"
        );
        assert_eq!(
            flushed[0].dst_keys,
            vec![dst_key_of(sole_ip)],
            "the flush narrows to EXACTLY the freed sole-reference IP"
        );
        assert!(
            !flushed[0].dst_keys.contains(&dst_key_of(shared_ip)),
            "the shared-CDN IP is NEVER flushed — the under-delete bias survives the commit path"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn cross_session_deny_frees_only_the_denied_sessions_element_off_the_shared_index() {
        // (2) CROSS-SESSION over-delete guard, across the PRODUCTION WIRE-RELOAD COMMIT PATH and
        // the REAL shared `(session, ip)` reverse index. Two DISTINCT sessions admit the SAME
        // shared IP through the W1/W2 transaction (`AdmissionStores::run_admission`), so the
        // shared reverse index holds `(A, ip) = 1` AND `(B, ip) = 1` — two independent per-session
        // counts, NEVER one flat per-IP count. Reload a version that denies ONLY session A's name
        // (`a.example`) at a SEVERING rung while session B's name (`b.example`) stays allowed. The
        // sweep — driven over the SAME `LiveAdmissions` the transaction minted into, so it revokes
        // THROUGH the bound map (one refcount, no drift) — must decref ONLY `(A, ip)` to 0
        // (freeing A's element) and leave `(B, ip) ≥ 1` (B's element NEVER withdrawn). The
        // `(session, ip)` key in `txn::InMemoryReverseIndex` IS the over-delete guard.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        // ── ADMIT the SAME shared IP under TWO distinct sessions through the W1/W2 transaction.
        //    `AdmissionStores` binds its DNS-2b map into its live registry, so the §5.4 sweep
        //    revokes THROUGH the same shared reverse index the admit increfs — the bound-map
        //    path, NOT the survivor-derived fallback. ──
        let stores = AdmissionStores::new();
        let shared_ip = ip("198.51.100.9"); // the SAME IP both sessions admit
        let shared_addr = admitted_addr(shared_ip);
        let t0 = Instant::from_unix_nanos(1_000_000_000_000);

        assert!(
            matches!(
                stores.run_admission(
                    &admission_inputs("sess-a", 11, "a.example.", vec![shared_ip]),
                    t0
                ),
                AdmissionOutcome::Admitted { .. }
            ),
            "session A admits a.example → shared_ip"
        );
        assert!(
            matches!(
                stores.run_admission(
                    &admission_inputs("sess-b", 22, "b.example.", vec![shared_ip]),
                    t0
                ),
                AdmissionOutcome::Admitted { .. }
            ),
            "session B admits b.example → the SAME shared_ip"
        );
        // The shared reverse index: TWO independent per-session counts on the SAME IP.
        assert_eq!(
            stores.reverse_refcount("sess-a", &shared_addr),
            1,
            "session A holds one reference to the shared IP"
        );
        assert_eq!(
            stores.reverse_refcount("sess-b", &shared_addr),
            1,
            "session B independently holds one reference to the SAME IP — distinct (session,ip) keys"
        );

        let admissions = stores.live().clone();
        assert_eq!(admissions.len(), 2, "two cross-session admissions are live");

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let enforcer_dyn: Arc<dyn SweepEnforcer> = enforcer.clone();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        // Sweep the SAME registry the transaction minted into (the bound-map path), so the
        // commit's `route_sweep_outcome` records exactly the elements the shared index frees.
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer_dyn,
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // RELOAD the version that denies ONLY session A's name at a SEVERING rung.
        feed.publish(BoundarySnapshot::with_policy(
            9,
            "pushed-a.example.",
            composed(SWEEP_LAYER_TIGHT_DENY_A),
            TtlClamp::DEFAULT,
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1, "the deny-A snapshot re-sourced + swept once");
        assert_eq!(gate.policy_version(), "pol1/v-tight-a");

        // Session A's admission was revoked; session B's survives.
        let survivors = admissions.snapshot();
        assert_eq!(survivors.len(), 1, "only session B's admission survives");
        assert_eq!(survivors[0].session, "sess-b");
        assert_eq!(survivors[0].fqdn, "b.example.");
        assert_eq!(survivors[0].ip, shared_ip);

        // The shared `(session, ip)` reverse index: (A, ip) decref'd to 0 (A's element freed),
        // (B, ip) UNTOUCHED at ≥ 1 (the over-delete guard — A's decref keys on (A, ip), never
        // (B, ip), so it can NEVER drive B's still-live element to zero).
        assert_eq!(
            stores.reverse_refcount("sess-a", &shared_addr),
            0,
            "the denied session A's (A, ip) count reached zero — A's element is freed"
        );
        assert_eq!(
            stores.reverse_refcount("sess-b", &shared_addr),
            1,
            "session B's (B, ip) count is UNTOUCHED — no cross-session decref (over-delete guard)"
        );

        // The REPORTABLE allow-set delete: EXACTLY one element (session A's shared IP) was
        // withdrawn, on session A's PER-SESSION set (`allow4_<A-idx>`), NEVER session B's. B's
        // element is ABSENT from the deletions entirely.
        let withdrawn = enforcer.withdrawn();
        assert_eq!(
            withdrawn.len(),
            1,
            "exactly session A's freed element is withdrawn — never session B's still-live one"
        );
        assert_eq!(withdrawn[0].dst_key, dst_key_of(shared_ip));
        assert_eq!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, 11),
            "the withdraw names session A's OWN per-session set (allow4_11), keyed on A's index"
        );
        assert_ne!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, 22),
            "session B's per-session set (allow4_22) is NEVER named in the deletion"
        );

        // No conntrack flush leaks onto session B either — the single flush narrows to A's freed
        // IP and is keyed on A's session + index (the sever pair over A's flows only).
        let flushed = enforcer.flushed();
        assert_eq!(
            flushed.len(),
            1,
            "exactly session A's severing revoke fired one flush"
        );
        assert_eq!(
            flushed[0].session, "sess-a",
            "the flush is keyed on the DENIED session only"
        );
        assert_eq!(
            flushed[0].host_session_index, 11,
            "and on session A's OWN index"
        );
        assert_eq!(flushed[0].dst_keys, vec![dst_key_of(shared_ip)]);

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn cross_session_ask_grant_eviction_frees_only_its_sole_ref_ip_never_the_survivors_shared_one(
    ) {
        // (3) CROSS-SESSION ASK-GRANT over-delete guard, across the PRODUCTION WIRE-RELOAD COMMIT
        // PATH. The §5.4 sweep folds PARKED ask-grants (doc 09 §4 DNS-3 / POL-5) through the SAME
        // reverse-index discipline it sweeps DNS-2b admissions with — but the existing wire
        // witnesses (the two above) only exercise the ADMISSION leg. This is the missing
        // integration-surface ask-grant twin of the in-crate
        // `sweep::shared_ip_held_by_a_surviving_admission_survives_an_ask_grant_eviction`: it drives
        // the eviction all the way through `SnapshotCommitSink::with_revocation_sweep_enforced` →
        // `route_sweep_outcome` → the reportable `RecordingSweepEnforcer`, NOT just the in-crate
        // sweep core.
        //
        // Session A PARKS an ask-grant on `grant-a.example` resolving to TWO IPs — a SOLE-reference
        // IP it alone holds AND a SHARED-CDN IP a surviving SESSION-B admission (`b.example`) also
        // holds. Re-source LOOSE → a version that DENIES `grant-a.example` at a SEVERING rung while
        // `b.example` stays allowed. The grant is evicted (a `vN+1` deny outranks the user
        // approval, fail-closed); the over-delete guard frees EXACTLY the grant's sole-reference IP
        // and NEVER the shared IP session B still holds, AND the routed allow-set delete + conntrack
        // flush are keyed on session A's OWN host_session_index (never session B's set/flows).
        //
        // The bare synthetic registry (no bound DNS-2b map) exercises the UNIFIED survivor-derived
        // refcount: an IP frees iff NO survivor — admission OR ask-grant, any session — still
        // references it. A parked ask-grant is not a DNS-2b map entry, so the bound-map revoke
        // cannot decref it; this leg is precisely where the unified survivor refcount (reading BOTH
        // legs, W4) — not the per-`(session, ip)` bound-map reverse index — carries the under-delete
        // guard. The two agree by construction (the shared index's post-revoke count for an IP
        // equals the surviving distinct names holding it), and the cross-session ADMISSION witness
        // above proves the bound-map `(session, ip)` decref directly. Loopback / synthetic (§5.3).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v-loose");

        // ── ADMIT under LOOSE. Session B holds a surviving admission on the shared IP; session A
        //    parks an ask-grant resolving to BOTH the shared IP and a sole-reference IP. ──
        let admissions = LiveAdmissions::new();
        let sole_ip = ip("203.0.113.21"); // grant-a.example's SOLE-reference IP (session A only)
        let shared_ip = ip("198.51.100.9"); // shared between grant-a.example (A) + b.example (B)
                                            // Session B's SURVIVING admission references the shared IP (it stays allowlisted).
        admissions.admit(
            LiveAdmission::new("sess-b", "b.example", shared_ip).with_host_session_index(22),
        );
        // Session A's PARKED ask-grant references BOTH IPs (its retry already resolved them).
        admissions.park_ask_grant(
            LiveAskGrant::new("sess-a", "grant-a.example", vec![sole_ip, shared_ip])
                .with_host_session_index(11),
        );
        assert_eq!(admissions.len(), 1, "one surviving admission under LOOSE");
        assert_eq!(
            admissions.ask_grant_len(),
            1,
            "one parked ask-grant under LOOSE"
        );

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let enforcer_dyn: Arc<dyn SweepEnforcer> = enforcer.clone();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer_dyn,
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // RELOAD the SEVERING-rung version that denies ONLY session A's ask-grant name.
        feed.publish(BoundarySnapshot::with_policy(
            8,
            "pushed-grant-a.example.",
            composed(SWEEP_LAYER_TIGHT_DENY_GRANT_A),
            TtlClamp::DEFAULT,
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(
            commits, 1,
            "the deny-grant-A snapshot re-sourced + swept once"
        );
        assert_eq!(gate.policy_version(), "pol1/v-tight-grant-a");

        // Session A's ask-grant was evicted; session B's admission survives, still holding the
        // shared IP.
        assert_eq!(
            admissions.ask_grant_len(),
            0,
            "the denied session A ask-grant was evicted"
        );
        let survivors = admissions.snapshot();
        assert_eq!(
            survivors.len(),
            1,
            "session B's admission survives the sweep"
        );
        assert_eq!(survivors[0].session, "sess-b");
        assert_eq!(survivors[0].fqdn, "b.example.");
        assert_eq!(survivors[0].ip, shared_ip);

        // The REPORTABLE allow-set delete: EXACTLY the grant's SOLE-reference IP is withdrawn — the
        // SHARED IP is NOT (session B's admission still references it). The unified refcount reads
        // BOTH legs (admission AND ask-grant), so the grant's eviction frees only an IP NO survivor
        // holds; the shared IP a session-B survivor keeps stays live — the over-delete guard, W4.
        let withdrawn = enforcer.withdrawn();
        assert_eq!(
            withdrawn.len(),
            1,
            "exactly the grant's freed sole-reference IP is withdrawn across the wire reload"
        );
        assert_eq!(withdrawn[0].dst_key, dst_key_of(sole_ip));
        assert!(
            !withdrawn.iter().any(|w| w.dst_key == dst_key_of(shared_ip)),
            "the shared-CDN IP is NEVER withdrawn — a surviving session-B admission still \
             references it (the grant eviction never over-deletes a survivor-held IP)"
        );
        // And the one withdrawal is keyed on session A's OWN per-session set (allow4_11), never B's
        // (allow4_22) — the routed delete is session-scoped to the evicted grant's index.
        assert_eq!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, 11),
            "the withdraw names session A's OWN per-session set (allow4_11), keyed on the grant's index"
        );
        assert_ne!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, 22),
            "session B's per-session set (allow4_22) is NEVER named in the grant eviction's deletion"
        );

        // The REPORTABLE conntrack flush (the D53 sever): a SEVERING-rung grant eviction fires the
        // rung-conditional flush, narrowed to EXACTLY the grant's freed sole-reference IP and keyed
        // on session A's own session + index — the shared IP is NEVER flushed.
        let flushed = enforcer.flushed();
        assert_eq!(
            flushed.len(),
            1,
            "a severing-rung ask-grant eviction fired exactly one rung-conditional flush (D53)"
        );
        assert_eq!(
            flushed[0].session, "sess-a",
            "the flush is keyed on the DENIED ask-grant's session only"
        );
        assert_eq!(
            flushed[0].host_session_index, 11,
            "and on the grant's OWN host_session_index"
        );
        assert_eq!(
            flushed[0].dst_keys,
            vec![dst_key_of(sole_ip)],
            "the flush narrows to EXACTLY the grant's freed sole-reference IP"
        );
        assert!(
            !flushed[0].dst_keys.contains(&dst_key_of(shared_ip)),
            "the shared-CDN IP is NEVER flushed — the under-delete bias survives the commit path"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn grant_derived_admission_decrefs_only_its_own_session_off_the_shared_bound_index() {
        // (4) GRANT-DERIVED-ADMISSION bound-map decref twin, across the PRODUCTION WIRE-RELOAD
        // COMMIT PATH and the REAL shared `(session, ip)` reverse index. This is the BOUND-MAP
        // twin of the bare-registry PARKED-grant witness (3) above: an APPROVED ask-grant whose
        // retry ALREADY RESOLVED an address is NOT a parked grant — server.rs documents
        // (`LiveAdmissions::ask_grants`, ~L527-528) that such a grant "is a plain `LiveAdmission`
        // (it admitted a flow) and rides the `inner` leg". So a resolved grant promotes into the
        // SAME W1/W2 transaction (`AdmissionStores::run_admission`) any DNS-2b admission runs
        // through, and is decref'd off the SAME bound `(session, ip)` reverse index — it is NOT
        // special-cased.
        //
        // The two existing bound-map / survivor witnesses leave this provenance lineage
        // unwitnessed: witness (2) decrefs two GENERIC admissions off the bound index, and witness
        // (3) evicts a PARKED grant through the survivor-derived fallback (no bound map). Neither
        // proves that a grant PROMOTED into the bound-map admission path decrefs correctly off the
        // shared reverse index with no over-delete. This twin pins exactly that: a grant-derived
        // admission's revoke keys on the grant session's OWN `(session, ip)`, frees its element,
        // and NEVER touches a sibling session's still-live count on a shared CDN IP.
        //
        // Session A admits `grant-a.example` (a grant-derived admission, promoted from an approved
        // already-resolved ask-grant) sharing ONE CDN IP with session B's sibling admission
        // `b.example`. Re-source LOOSE → `SWEEP_LAYER_TIGHT_DENY_GRANT_A` denies `grant-a.example`
        // at a SEVERING rung while `b.example` stays allowed. The bound-map sweep decrefs ONLY
        // `(A, ip)` to 0 (freeing A's element) and leaves `(B, ip) ≥ 1` (B's element NEVER
        // withdrawn), with the routed delete keyed on session A's OWN host_session_index — no
        // over-delete. Loopback / synthetic (§5.3).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v-loose");

        // ── ADMIT through the W1/W2 transaction so both legs incref the SAME bound `(session, ip)`
        //    reverse index. The grant-derived admission (session A) is admitted EXACTLY like any
        //    DNS-2b admission — a resolved grant is a plain `LiveAdmission` (server.rs ~L527-528),
        //    so it rides `run_admission`, not the parked-ask-grant leg. ──
        let stores = AdmissionStores::new();
        let shared_ip = ip("198.51.100.9"); // shared between grant-a.example (A) + b.example (B)
        let shared_addr = admitted_addr(shared_ip);
        let t0 = Instant::from_unix_nanos(1_000_000_000_000);

        assert!(
            matches!(
                stores.run_admission(
                    // Session A's grant-derived admission: an approved, already-resolved ask-grant
                    // promoted into the bound-map admission path (index 11 = session A's allow set).
                    &admission_inputs("sess-a", 11, "grant-a.example.", vec![shared_ip]),
                    t0
                ),
                AdmissionOutcome::Admitted { .. }
            ),
            "session A's grant-derived admission admits grant-a.example → shared_ip"
        );
        assert!(
            matches!(
                stores.run_admission(
                    &admission_inputs("sess-b", 22, "b.example.", vec![shared_ip]),
                    t0
                ),
                AdmissionOutcome::Admitted { .. }
            ),
            "session B's sibling admission admits b.example → the SAME shared_ip"
        );
        // The shared reverse index: TWO independent per-session counts on the SAME IP — the
        // grant-derived admission is NOT distinguished from a normal one at the index level.
        assert_eq!(
            stores.reverse_refcount("sess-a", &shared_addr),
            1,
            "session A's grant-derived admission holds one reference to the shared IP"
        );
        assert_eq!(
            stores.reverse_refcount("sess-b", &shared_addr),
            1,
            "session B's sibling admission independently holds one reference to the SAME IP"
        );

        let admissions = stores.live().clone();
        assert_eq!(admissions.len(), 2, "two cross-session admissions are live");

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let enforcer_dyn: Arc<dyn SweepEnforcer> = enforcer.clone();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        // Sweep the SAME registry the transaction minted into (the bound-map path), so the
        // commit's `route_sweep_outcome` records exactly the elements the shared index frees.
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer_dyn,
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // RELOAD the SEVERING-rung version that denies ONLY session A's grant-derived name.
        feed.publish(BoundarySnapshot::with_policy(
            10,
            "pushed-grant-a.example.",
            composed(SWEEP_LAYER_TIGHT_DENY_GRANT_A),
            TtlClamp::DEFAULT,
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(
            commits, 1,
            "the deny-grant-A snapshot re-sourced + swept once"
        );
        assert_eq!(gate.policy_version(), "pol1/v-tight-grant-a");

        // Session A's grant-derived admission was revoked; session B's sibling survives.
        let survivors = admissions.snapshot();
        assert_eq!(
            survivors.len(),
            1,
            "only session B's sibling admission survives"
        );
        assert_eq!(survivors[0].session, "sess-b");
        assert_eq!(survivors[0].fqdn, "b.example.");
        assert_eq!(survivors[0].ip, shared_ip);

        // The shared `(session, ip)` reverse index: (A, ip) decref'd to 0 (the grant-derived
        // admission's element freed), (B, ip) UNTOUCHED at ≥ 1. The grant-derived admission's
        // decref keys on (A, ip), NEVER (B, ip), so it can never drive B's still-live element to
        // zero — the over-delete guard holds identically for a grant-derived admission.
        assert_eq!(
            stores.reverse_refcount("sess-a", &shared_addr),
            0,
            "the denied grant-derived admission's (A, ip) count reached zero — A's element is freed"
        );
        assert_eq!(
            stores.reverse_refcount("sess-b", &shared_addr),
            1,
            "session B's (B, ip) count is UNTOUCHED — no cross-session decref (over-delete guard)"
        );

        // The REPORTABLE allow-set delete: EXACTLY one element (the grant-derived admission's
        // shared IP) was withdrawn, on session A's PER-SESSION set (`allow4_11`), keyed on the
        // grant session's OWN host_session_index — NEVER session B's (`allow4_22`).
        let withdrawn = enforcer.withdrawn();
        assert_eq!(
            withdrawn.len(),
            1,
            "exactly the grant-derived admission's freed element is withdrawn — never session B's"
        );
        assert_eq!(withdrawn[0].dst_key, dst_key_of(shared_ip));
        assert_eq!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, 11),
            "the withdraw names session A's OWN per-session set (allow4_11), keyed on the grant's index"
        );
        assert_ne!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, 22),
            "session B's per-session set (allow4_22) is NEVER named in the deletion"
        );

        // The REPORTABLE conntrack flush (the D53 sever): the severing-rung grant-derived revoke
        // fires exactly one rung-conditional flush, narrowed to the freed shared IP and keyed on
        // session A's OWN session + host_session_index — never session B's.
        let flushed = enforcer.flushed();
        assert_eq!(
            flushed.len(),
            1,
            "exactly the grant-derived admission's severing revoke fired one flush"
        );
        assert_eq!(
            flushed[0].session, "sess-a",
            "the flush is keyed on the DENIED grant session only"
        );
        assert_eq!(
            flushed[0].host_session_index, 11,
            "and on session A's OWN host_session_index"
        );
        assert_eq!(flushed[0].dst_keys, vec![dst_key_of(shared_ip)]);

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shared_cdn_ip_survives_a_revoked_siblings_sweep_under_burst_back_pressure() {
        // (5) SURVIVOR-UNDER-BURST. The shared-CDN under-delete bias of witness (1) must hold
        // even when the SEVERING policy version arrives at the TAIL of a publisher BURST that
        // EXCEEDS the bounded host-local feed capacity (doc 11 §1 bounded-mpsc back-pressure).
        // The §14 `subscriber_backpressure` witness proves the feed back-pressures + preserves
        // D72 forward-only ordering, but only over boundary-zone-ONLY commits with NO admission
        // registry — it never drives the §5.4 revocation sweep, so it cannot witness that a
        // SURVIVOR's shared-CDN IP is preserved when the burst's tail commit severs a
        // co-referencing sibling. This pins exactly that: a burst of forward-seq re-sources
        // (both names live, every intermediate sweep a no-op) that back-pressures `publish()`
        // on a SMALL bounded feed, capped by a SEVERING tail commit — the survivor's
        // `(session, ip)` reverse refcount stays >= 1 and ONLY the revoked name's
        // sole-reference IP is withdrawn + flushed, across the PRODUCTION wire-reload commit
        // path (`SnapshotCommitSink::with_revocation_sweep_enforced` → `route_sweep_outcome` →
        // the reportable `RecordingSweepEnforcer`). Bare synthetic `LiveAdmissions` (no W1/W2
        // `AdmissionStores` bind): the survivor-derived refcount — an IP frees iff NO survivor
        // (any session) still holds it (the under-delete bias, D53/W4). Loopback / synthetic
        // only (§5.3): no live kernel, no network. No new D-number; `DnsVerdict::Deny` unchanged.
        //
        // The back-pressure wedge is driven by the `GatedCommitSink` release barrier — NOT a
        // fixed sleep: the subscriber parks on its first commit, the test awaits that `entered`
        // signal, and the bounded feed's capacity makes `completed < BURST` a HARD invariant
        // while the subscriber holds. Fully deterministic (no `tokio::time::sleep`).

        const CAPACITY: usize = 2;
        const BURST: u64 = 10; // >> CAPACITY + 1 — surplus publishes MUST block on the bound.

        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v-loose");

        // ── ADMIT under LOOSE: the to-be-revoked name at a SOLE-reference IP + a SHARED-CDN IP,
        //    and the surviving sibling at that SAME shared IP. The bare registry exercises the
        //    survivor-derived refcount this leg witnesses across the wire. ──
        let admissions = LiveAdmissions::new();
        let sole_ip = ip("203.0.113.7"); // tighten.example's SOLE-reference IP
        let shared_ip = ip("198.51.100.9"); // shared between tighten.example + kept.example
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", sole_ip));
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", shared_ip));
        admissions.admit(LiveAdmission::new("sess-b", "kept.example", shared_ip));
        assert_eq!(admissions.len(), 3, "three live admissions under LOOSE");

        // The survivor-derived `(session, ip)` reverse refcount: the count of live admissions a
        // session holds on an IP — the under-delete guard reads this (an IP frees iff it drops
        // to zero across ALL survivors). Recomputed from the live registry snapshot each call.
        let survivor_refcount = |session: &str, target: IpAddr| -> usize {
            admissions
                .snapshot()
                .iter()
                .filter(|a| a.session == session && a.ip == target)
                .count()
        };
        assert_eq!(
            survivor_refcount("sess-b", shared_ip),
            1,
            "the surviving sibling holds one reference to the shared-CDN IP under LOOSE"
        );

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let enforcer_dyn: Arc<dyn SweepEnforcer> = enforcer.clone();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(CAPACITY);

        // ── The real survivor-enforcer commit sink, WRAPPED in a `GatedCommitSink` that parks
        //    the subscriber on its FIRST commit (the release-barrier pattern). Spawned FIRST: it
        //    pulls snapshot #1, enters commit #1, signals `entered`, and parks — so it stops
        //    draining and the bounded feed fills behind it, forcing `publish()` to back-pressure.
        //    Its inner sink runs the §5.4 revocation sweep over the SAME bare `LiveAdmissions` on
        //    every (post-release) commit. ──
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer_dyn,
        );
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let gated_sink = GatedCommitSink::new(commit_sink, entered_tx, release_rx);
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &gated_sink).await });

        // ── The BURST publisher: forward-seq snapshots 1..=BURST. seq < BURST re-source LOOSE
        //    (both names stay live — every intermediate sweep is a no-op); seq == BURST severs
        //    `tighten.example` at a SEVERING rung. A completed-publish counter lets the test
        //    observe the wedge; the publisher drops the feed after the burst so the subscriber
        //    loop returns. ──
        let completed = Arc::new(AtomicUsize::new(0));
        let pub_completed = completed.clone();
        let publisher = tokio::spawn(async move {
            for seq in 1..=BURST {
                let layer = if seq < BURST {
                    SWEEP_LAYER_LOOSE
                } else {
                    SWEEP_LAYER_TIGHT_TIGHTEN
                };
                feed.publish(BoundarySnapshot::with_policy(
                    seq,
                    "pushed.example.",
                    composed(layer),
                    TtlClamp::DEFAULT,
                ))
                .await
                .expect("the subscriber drains the whole burst");
                pub_completed.fetch_add(1, Ordering::SeqCst);
            }
            // Drop the feed (last sender) so the subscriber loop returns after drain.
            drop(feed);
        });

        // ── Prove BACK-PRESSURE, DETERMINISTICALLY (no sleep): await the `entered` barrier — the
        //    subscriber has now stopped draining, parked inside commit #1 having consumed EXACTLY
        //    one snapshot. With the bounded feed (CAPACITY buffered + the one consumed) far
        //    smaller than BURST, the publisher PHYSICALLY cannot have completed the whole burst
        //    while the subscriber holds — `completed < BURST` is a HARD invariant here, not a
        //    timing race — and it is still wedged on `send().await`. A bounded mpsc pins it at
        //    the wall; an unbounded buffer (or a drop) would let it race to BURST (doc 11 §1). ──
        entered_rx
            .await
            .expect("the subscriber entered its gated first commit");
        let wedged = completed.load(Ordering::SeqCst);
        assert!(
            wedged < BURST as usize,
            "a bounded feed must back-pressure the publisher, not buffer the whole burst \
             (got {wedged} of {BURST} published with the subscriber parked — unbounded buffer or drop)"
        );
        assert!(
            !publisher.is_finished(),
            "the back-pressured publisher is still wedged on `send().await` while the subscriber \
             is parked — it cannot complete the burst until a slot drains"
        );

        // ── Release the back-pressure: the parked first commit returns, the subscriber drains
        //    the buffered burst (freeing slots so each wedged `publish()` completes) and runs the
        //    §5.4 sweep on every commit — admitter-LAST, the severing tail last. ──
        release_tx
            .send(())
            .expect("subscriber parked on the release gate");

        publisher.await.expect("publisher task");
        // Every burst publish completed once back-pressure released — NONE was dropped.
        assert_eq!(
            completed.load(Ordering::SeqCst),
            BURST as usize,
            "every back-pressured publish completed once the subscriber drained — none dropped"
        );

        // The publisher dropped the feed after its burst, so the subscriber loop now returns.
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(
            commits, BURST,
            "every forward-seq snapshot in the burst committed — the bounded feed back-pressures, \
             it does not silently drop the back-pressured snapshots (D72)"
        );
        assert_eq!(
            gate.policy_version(),
            "pol1/v-tight",
            "the burst's severing tail re-sourced the running evaluator admitter-LAST"
        );

        // The DNS-2b registry: BOTH tighten.example records were revoked by the tail sweep;
        // kept.example survived — the shared-CDN IP survives the revoked sibling's sweep.
        let survivors = admissions.snapshot();
        assert_eq!(
            survivors.len(),
            1,
            "only the still-allowed sibling remains after the burst"
        );
        assert_eq!(survivors[0].fqdn, "kept.example.");
        assert_eq!(survivors[0].ip, shared_ip);

        // The survivor's `(session, ip)` reverse refcount stays >= 1 across the whole burst —
        // the shared-CDN IP is NOT over-deleted (bias to under-delete, D53/W4).
        assert!(
            survivor_refcount("sess-b", shared_ip) >= 1,
            "the survivor's (sess-b, shared_ip) reverse refcount stays >= 1 through the burst"
        );
        assert_eq!(
            survivor_refcount("sess-b", shared_ip),
            1,
            "exactly the one surviving sibling reference remains on the shared-CDN IP"
        );
        assert_eq!(
            survivor_refcount("sess-a", shared_ip),
            0,
            "the revoked name no longer references the shared IP (its records were swept)"
        );

        // The REPORTABLE allow-set delete: EXACTLY the revoked name's sole-reference IP is
        // withdrawn — the shared IP is NEVER withdrawn (kept.example still references it; the
        // under-delete bias survives the bursting wire-reload commit path, D53/W4).
        let withdrawn = enforcer.withdrawn();
        assert_eq!(
            withdrawn.len(),
            1,
            "exactly the freed sole-reference IP is withdrawn across the bursting wire reload"
        );
        assert_eq!(withdrawn[0].dst_key, dst_key_of(sole_ip));
        assert!(
            !withdrawn.iter().any(|w| w.dst_key == dst_key_of(shared_ip)),
            "the shared-CDN IP is NEVER withdrawn — a survivor still references it (under-delete bias)"
        );

        // The REPORTABLE conntrack flush (the D53 sever): the SEVERING tail commit fired exactly
        // one rung-conditional flush, narrowed to the freed sole-reference IP; the intermediate
        // LOOSE re-sources swept nothing, and the shared IP is NEVER flushed.
        let flushed = enforcer.flushed();
        assert_eq!(
            flushed.len(),
            1,
            "only the severing tail commit fired the rung-conditional conntrack flush (D53)"
        );
        assert_eq!(
            flushed[0].dst_keys,
            vec![dst_key_of(sole_ip)],
            "the flush narrows to EXACTLY the freed sole-reference IP"
        );
        assert!(
            !flushed[0].dst_keys.contains(&dst_key_of(shared_ip)),
            "the shared-CDN IP is NEVER flushed — the under-delete bias survives the burst"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cross_session_deny_frees_only_its_element_off_the_bound_index_under_burst_back_pressure(
    ) {
        // (6) CROSS-SESSION OVER-DELETE GUARD UNDER BURST — the BOUND-MAP twin of witness (5).
        // Witness (5) proves the SURVIVOR-DERIVED under-delete bias (bare `LiveAdmissions`, no
        // W1/W2 bind) holds when the severing version arrives at the TAIL of a capacity-exceeding
        // publisher burst. Witness (2) proves the REAL W1/W2-bound `(session, ip)` reverse index
        // (`AdmissionStores::run_admission`) enforces the CROSS-SESSION over-delete guard — but
        // only under a SINGLE non-bursting reload. Neither pins the two together: that the shared
        // BOUND reverse index's per-`(session, ip)` decref survives feed back-pressure, i.e. the
        // over-delete guard is NOT a quiescent-reload artifact but holds when the severing tail
        // commit is drained out of a wedged bounded feed. This does exactly that: two DISTINCT
        // sessions admit the SAME shared IP through the W1/W2 transaction (so the bound index
        // holds `(A, ip) = 1` AND `(B, ip) = 1`), then a forward-seq burst that back-pressures
        // `publish()` on a SMALL bounded feed is capped by a SEVERING tail that denies ONLY
        // session A's name. Swept THROUGH the SAME bound map the admit increfs (one refcount, no
        // drift), the tail decrefs ONLY `(A, ip)` to 0 and leaves `(B, ip)` UNTOUCHED — the
        // over-delete guard, across the PRODUCTION wire-reload commit path
        // (`SnapshotCommitSink::with_revocation_sweep_enforced` → `route_sweep_outcome` → the
        // reportable `RecordingSweepEnforcer`). The back-pressure wedge is driven by the
        // `GatedCommitSink` release barrier, fully deterministic (NO sleep). Loopback / synthetic
        // only (§5.3): no live kernel, no network. No new D-number; `DnsVerdict::Deny` unchanged.

        const CAPACITY: usize = 2;
        const BURST: u64 = 10; // >> CAPACITY + 1 — surplus publishes MUST block on the bound.

        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v-loose");

        // ── ADMIT the SAME shared IP under TWO distinct sessions through the W1/W2 transaction,
        //    so the REAL bound `(session, ip)` reverse index holds two independent per-session
        //    counts (NEVER one flat per-IP count) — the bound-map path, not the survivor-derived
        //    fallback. ──
        let stores = AdmissionStores::new();
        let shared_ip = ip("198.51.100.9"); // the SAME IP both sessions admit
        let shared_addr = admitted_addr(shared_ip);
        let t0 = Instant::from_unix_nanos(1_000_000_000_000);
        assert!(
            matches!(
                stores.run_admission(
                    &admission_inputs("sess-a", 11, "a.example.", vec![shared_ip]),
                    t0
                ),
                AdmissionOutcome::Admitted { .. }
            ),
            "session A admits a.example → shared_ip"
        );
        assert!(
            matches!(
                stores.run_admission(
                    &admission_inputs("sess-b", 22, "b.example.", vec![shared_ip]),
                    t0
                ),
                AdmissionOutcome::Admitted { .. }
            ),
            "session B admits b.example → the SAME shared_ip"
        );
        assert_eq!(
            stores.reverse_refcount("sess-a", &shared_addr),
            1,
            "session A holds one reference to the shared IP on the bound index"
        );
        assert_eq!(
            stores.reverse_refcount("sess-b", &shared_addr),
            1,
            "session B independently holds one reference to the SAME IP — distinct (session,ip) keys"
        );

        let admissions = stores.live().clone();
        assert_eq!(admissions.len(), 2, "two cross-session admissions are live");

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let enforcer_dyn: Arc<dyn SweepEnforcer> = enforcer.clone();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(CAPACITY);

        // ── The real sweep-enforced commit sink over the SAME bound registry the transaction
        //    minted into (so the sweep revokes THROUGH the shared index the admit increfs),
        //    WRAPPED in a `GatedCommitSink` that parks the subscriber on its first commit. Spawned
        //    FIRST so the bounded feed fills behind the parked subscriber and `publish()`
        //    back-pressures. ──
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer_dyn,
        );
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let gated_sink = GatedCommitSink::new(commit_sink, entered_tx, release_rx);
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &gated_sink).await });

        // ── The BURST publisher: forward-seq snapshots 1..=BURST. seq < BURST re-source LOOSE
        //    (both names stay live — every intermediate sweep a no-op); seq == BURST denies ONLY
        //    session A's name at a SEVERING rung. The publisher drops the feed after the burst so
        //    the subscriber loop returns. ──
        let completed = Arc::new(AtomicUsize::new(0));
        let pub_completed = completed.clone();
        let publisher = tokio::spawn(async move {
            for seq in 1..=BURST {
                let layer = if seq < BURST {
                    SWEEP_LAYER_LOOSE
                } else {
                    SWEEP_LAYER_TIGHT_DENY_A
                };
                feed.publish(BoundarySnapshot::with_policy(
                    seq,
                    "pushed-a.example.",
                    composed(layer),
                    TtlClamp::DEFAULT,
                ))
                .await
                .expect("the subscriber drains the whole burst");
                pub_completed.fetch_add(1, Ordering::SeqCst);
            }
            drop(feed);
        });

        // ── Prove BACK-PRESSURE, DETERMINISTICALLY (no sleep): await the `entered` barrier — the
        //    subscriber has parked inside commit #1 having consumed EXACTLY one snapshot. With the
        //    bounded feed (CAPACITY buffered + the one consumed) far smaller than BURST, the
        //    publisher PHYSICALLY cannot have completed the whole burst while the subscriber holds
        //    — `completed < BURST` is a HARD invariant, not a timing race — and it is still wedged
        //    on `send().await`. ──
        entered_rx
            .await
            .expect("the subscriber entered its gated first commit");
        let wedged = completed.load(Ordering::SeqCst);
        assert!(
            wedged < BURST as usize,
            "a bounded feed must back-pressure the publisher, not buffer the whole burst \
             (got {wedged} of {BURST} published with the subscriber parked — unbounded buffer or drop)"
        );
        assert!(
            !publisher.is_finished(),
            "the back-pressured publisher is still wedged on `send().await` while the subscriber \
             is parked — it cannot complete the burst until a slot drains"
        );

        // ── Release the back-pressure: the subscriber drains the buffered burst (freeing slots so
        //    each wedged `publish()` completes) and runs the §5.4 sweep on every commit —
        //    admitter-LAST, the severing tail last. ──
        release_tx
            .send(())
            .expect("subscriber parked on the release gate");

        publisher.await.expect("publisher task");
        assert_eq!(
            completed.load(Ordering::SeqCst),
            BURST as usize,
            "every back-pressured publish completed once the subscriber drained — none dropped"
        );

        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(
            commits, BURST,
            "every forward-seq snapshot in the burst committed — the bounded feed back-pressures, \
             it does not silently drop the back-pressured snapshots (D72)"
        );
        assert_eq!(
            gate.policy_version(),
            "pol1/v-tight-a",
            "the burst's severing tail re-sourced the running evaluator admitter-LAST"
        );

        // Session A's admission was revoked by the tail sweep; session B's survives.
        let survivors = admissions.snapshot();
        assert_eq!(
            survivors.len(),
            1,
            "only session B's admission survives the burst"
        );
        assert_eq!(survivors[0].session, "sess-b");
        assert_eq!(survivors[0].fqdn, "b.example.");
        assert_eq!(survivors[0].ip, shared_ip);

        // The shared BOUND `(session, ip)` reverse index: (A, ip) decref'd to 0 (A's element
        // freed), (B, ip) UNTOUCHED at >= 1 — the over-delete guard survives the bursting
        // wire-reload commit path: A's decref keys on (A, ip), NEVER (B, ip), so it can never
        // drive B's still-live element to zero (bias to under-delete, D53/W4).
        assert_eq!(
            stores.reverse_refcount("sess-a", &shared_addr),
            0,
            "the denied session A's (A, ip) count reached zero — A's element is freed"
        );
        assert_eq!(
            stores.reverse_refcount("sess-b", &shared_addr),
            1,
            "session B's (B, ip) count is UNTOUCHED — no cross-session decref (over-delete guard)"
        );

        // The REPORTABLE allow-set delete: EXACTLY one element (session A's shared IP) was
        // withdrawn; session B's still-live element is ABSENT from the deletions entirely.
        let withdrawn = enforcer.withdrawn();
        assert_eq!(
            withdrawn.len(),
            1,
            "exactly session A's freed element is withdrawn across the burst — never session B's"
        );
        assert_eq!(withdrawn[0].dst_key, dst_key_of(shared_ip));

        // The REPORTABLE conntrack flush (the D53 sever): the SEVERING tail fired exactly one
        // rung-conditional flush, narrowed to session A's freed element; the intermediate LOOSE
        // re-sources swept nothing.
        let flushed = enforcer.flushed();
        assert_eq!(
            flushed.len(),
            1,
            "only the severing tail commit fired the rung-conditional conntrack flush (D53)"
        );
        assert_eq!(flushed[0].dst_keys, vec![dst_key_of(shared_ip)]);

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }
}

// ===========================================================================
// 19. The `SnapshotSink` decorator FORWARD RULE, made EXECUTABLE out-of-crate (doc 11
//     §5.3 / §5.5, D72). `SnapshotSink::observe_snapshot_drop` is DEFAULTED to a no-op so
//     the two production impls (`SnapshotCommitSink`, `BoundaryZoneOnly`) need no change;
//     the hazard the default creates is that a WRAPPER/decorator `SnapshotSink` — one that
//     intercepts `commit_snapshot` around an INNER `SnapshotSink` — silently INHERITS that
//     no-op and SHADOWS the inner sink's production drop routing, swallowing the
//     stale-fan-out DROP signal §5.3's single-monotonic-version story relies on for
//     observability. server.rs carries only the PROSE forward rule (and the `BoundaryZoneOnly`
//     audit note that it wraps a `BoundaryZoneSink`, not a `SnapshotSink`, so it has no inner
//     override to shadow). This module makes the rule EXECUTABLE from OUTSIDE the crate, over
//     the public `SnapshotSink` seam:
//
//       * POSITIVE: a decorator that DELEGATES `observe_snapshot_drop` to its inner sink
//         forwards a `SnapshotDropEvent::stale_fan_out` all the way through to the inner
//         sink's wired `CapturingDropSink` (`count_with_reason(StaleFanOut) == 1`). A future
//         decorator that FORGETS to delegate — inheriting the default — regresses THIS assert
//         instead of silently dropping the signal.
//       * NEGATIVE PIN: a decorator that OMITS `observe_snapshot_drop` (inherits the no-op
//         default) forwards NOTHING — the inner `CapturingDropSink` stays empty. This DOCUMENTS
//         the exact shadow the forward rule forbids, so the positive assert's value is legible.
//
//     Pure in-process, loopback/synthetic (D50): no gate, no network, no kernel — only the
//     public `SnapshotSink` / `SnapshotDropSink` seams and the in-memory `CapturingDropSink`.
//     Drop BEHAVIOR is unchanged; this is an OBSERVABILITY witness only.
// ===========================================================================
mod snapshotsink_forward_rule {
    use ds_dnsgate::event::{
        CapturingDropSink, EventProvenance, SnapshotDropEvent, SnapshotDropReason, SnapshotDropSink,
    };
    use ds_dnsgate::server::{BoundarySnapshot, SnapshotSink};

    /// The INNER `SnapshotSink`, shaped like the production `SnapshotCommitSink`: it OVERRIDES
    /// `observe_snapshot_drop` to ROUTE every reload-boundary drop to a wired `CapturingDropSink`
    /// (the terminal recorder an operator's dashboard joins on). `commit_snapshot` is inert — the
    /// witness exercises only the drop-forwarding seam, never the commit path.
    struct RoutingInnerSink {
        drop_sink: CapturingDropSink,
    }

    impl SnapshotSink for RoutingInnerSink {
        fn commit_snapshot(&self, _snapshot: &BoundarySnapshot) {}

        fn observe_snapshot_drop(&self, drop: SnapshotDropEvent) {
            // The production override shape: route the drop to the wired sink (never the default).
            self.drop_sink.observe_drop(drop);
        }
    }

    /// A CONFORMING decorator: wraps an inner `SnapshotSink` and DELEGATES `observe_snapshot_drop`
    /// to it — the forward rule satisfied. A decorator delegates EVERY defaulted method, not just
    /// the `commit_snapshot` it set out to wrap.
    struct DelegatingDecorator<S: SnapshotSink> {
        inner: S,
    }

    impl<S: SnapshotSink> SnapshotSink for DelegatingDecorator<S> {
        fn commit_snapshot(&self, snapshot: &BoundarySnapshot) {
            self.inner.commit_snapshot(snapshot);
        }

        fn observe_snapshot_drop(&self, drop: SnapshotDropEvent) {
            // DELEGATE — the forward rule. Without this line the decorator would inherit the no-op
            // default and shadow `RoutingInnerSink`'s routing (the exact regression the positive
            // test below fails on).
            self.inner.observe_snapshot_drop(drop);
        }
    }

    /// The FORBIDDEN shape (negative pin): a decorator that wraps an inner `SnapshotSink` but OMITS
    /// `observe_snapshot_drop`, silently inheriting the trait's no-op default. It still type-checks
    /// and still commits snapshots correctly — yet swallows the drop signal. This exists only to
    /// DOCUMENT the shadow the forward rule forbids.
    struct ShadowingDecorator<S: SnapshotSink> {
        inner: S,
    }

    impl<S: SnapshotSink> SnapshotSink for ShadowingDecorator<S> {
        fn commit_snapshot(&self, snapshot: &BoundarySnapshot) {
            self.inner.commit_snapshot(snapshot);
        }
        // observe_snapshot_drop is INTENTIONALLY OMITTED: it inherits the no-op default, so the
        // drop never reaches the inner sink — the shadow the FORWARD RULE forbids.
    }

    /// A non-empty POL-3 triple for the synthetic drop event (§6.7: provenance on every event).
    fn provenance() -> EventProvenance {
        EventProvenance {
            rule_id: "rule-allow".into(),
            policy_layer: "system-baseline".into(),
            policy_version: "pol1/v-loose".into(),
        }
    }

    #[test]
    fn delegating_decorator_forwards_stale_fan_out_to_the_inner_capturing_sink() {
        // The inner sink routes drops to a CapturingDropSink we hold a clone of (clones share one
        // backing buffer), so we read back exactly what the decorator forwarded.
        let capturing = CapturingDropSink::new();
        let inner = RoutingInnerSink {
            drop_sink: capturing.clone(),
        };
        let decorator = DelegatingDecorator { inner };

        // A benign forward-only-seq stale fan-out: seq 4 re-delivered while the admitter is at 7.
        let event = SnapshotDropEvent::stale_fan_out(4, 7, provenance());
        decorator.observe_snapshot_drop(event);

        // The decorator DELEGATED — the inner CapturingDropSink observed exactly the one
        // stale-fan-out drop (the signal was NOT shadowed by the defaulted method).
        assert_eq!(
            capturing.count_with_reason(SnapshotDropReason::StaleFanOut),
            1,
            "the delegating decorator forwards the stale_fan_out drop to the inner sink"
        );
        assert_eq!(
            capturing.len(),
            1,
            "exactly one drop was forwarded through — no duplication, no loss"
        );
        let forwarded = capturing.drops();
        assert_eq!(forwarded[0].dropped_seq, 4);
        assert_eq!(forwarded[0].committed_seq, 7);
        assert!(
            forwarded[0].is_stale_fan_out(),
            "the forwarded event kept its benign forward-only-seq reason"
        );
    }

    #[test]
    fn non_delegating_decorator_inherits_the_default_and_shadows_the_drop() {
        // The negative pin: a decorator that OMITS observe_snapshot_drop inherits the no-op default
        // and drops NOTHING to the inner sink — documenting the shadow the forward rule forbids.
        let capturing = CapturingDropSink::new();
        let inner = RoutingInnerSink {
            drop_sink: capturing.clone(),
        };
        let decorator = ShadowingDecorator { inner };

        decorator.observe_snapshot_drop(SnapshotDropEvent::stale_fan_out(4, 7, provenance()));

        assert!(
            capturing.is_empty(),
            "the inherited no-op default swallows the drop — the inner sink observes nothing (the \
             forbidden shadow the forward rule guards against)"
        );
        assert_eq!(
            capturing.count_with_reason(SnapshotDropReason::StaleFanOut),
            0,
            "a non-delegating decorator forwards zero stale_fan_out drops"
        );
    }
}
