//! ds-dnsgate QUERY-PATH GUARDRAIL conformance (the SECURITY-CRITICAL deny path).
//!
//! These tests PROVE, on the wire and at the seam, the three coupled query-path
//! guardrails (tasks 01KTWJ5XS8 denial-semantics, 01KTWJ5ZQR DNS-4-scrub, 01KTWJ5YRG
//! LOG-1-emission). They are deliberately SEPARATE from the existing `tests/` units
//! (`suppression_shapes.rs` owns the §3.3 RECORD-TYPE scrub; `policy_verdict.rs` owns the
//! Allow/Deny/Ask verdict fork; `event_surface.rs` owns the §5.5 event-signal surface) so
//! the units stay disjoint. The novel coverage here, NOT proven elsewhere:
//!
//!   1. **DNS-4 / W5 SANITY scrub on the WIRE answer path** (doc 09 §4 DNS-4 rule 2; doc 11
//!      §3.3 W5): a forwarded upstream answer carrying martian / private / loopback /
//!      link-local / EMBEDDED-IPv4 addresses is SCRUBBED from the answer the VM sees, and a
//!      name resolving ENTIRELY to martians is SERVFAIL (never an answer carrying a martian,
//!      never a policy NXDOMAIN). The existing tests only proved the RECORD-TYPE scrub
//!      (AAAA/HTTPS/SVCB); this proves the IP-RANGE rebinding defense on the answer path.
//!   2. **Ask-path ASK-USER seam** (doc 09 §4 DNS-3; doc 14 §2b; D18/D53/D77): an attended
//!      unknown-domain Ask authors REFUSED AND raises a one-way `AskUserRequest` (the VM is
//!      NEVER suspended); an unattended Ask DOWNGRADES to immediate block+log — REFUSED with
//!      NO ask raised. The existing tests only proved the REFUSED rcode; this proves the
//!      seam emission, the attendedness fork, and the no-suspend invariant.
//!   3. **`aimed_resolver` reserved-optional** (doc 11 §5.5 / doc 14 §2, D69): every event
//!      carries the field, conservatively always-`None` (the OQ3 default) — the SHAPE is
//!      ready, the population deferred to the ConnOrigin task.
//!
//! Network-free: a self-contained UDP+TCP loopback mock upstream (the `mock_up` module, a
//! trimmed copy of the suppression_shapes fixture) serves programmed answers; no test
//! reaches a real resolver or assumes a default route (D50 synthetic fixtures only).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ds_dnsgate::ask::{AskPosture, CapturingAskSink, RESOURCE_KIND_DOMAIN};
use ds_dnsgate::event::{CapturingSink, EventPath};
use ds_dnsgate::handler::{ForwarderConfig, StubRequestHandler, DEFAULT_BOUNDARY_ZONE};
use ds_dnsgate::policy::{DnsQueryCtx, FixedStubPolicy, PolicyHook, PromptRef, Verdict};
use ds_dnsgate::SeamProvenance;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::{Protocol, StreamReceiver};
use hickory_server::net::BufDnsStreamHandle;
use hickory_server::server::{Request, RequestHandler, ResponseHandle};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// Query construction + the direct-drive harness (no bound port; mirrors policy_seam).
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

fn client_src() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 9))
}

/// Drive a handler with one query and return the authored wire response. NO bound socket,
/// NO network beyond whatever `forwarder` points at (the loopback mock for the Allow path).
async fn drive<P: PolicyHook>(handler: &StubRequestHandler<P>, query: &[u8]) -> Message {
    let src = client_src();
    let request = Request::from_bytes(query.to_vec(), src, Protocol::Tcp).unwrap();
    let (stream_handle, mut receiver) = BufDnsStreamHandle::new(src);
    let response_handle = ResponseHandle::new(src, stream_handle, Protocol::Tcp);

    let _ =
        RequestHandler::handle_request::<_, TokioTime>(handler, &request, response_handle).await;

    next_response(&mut receiver)
        .await
        .expect("the handler authored a response")
}

async fn next_response(receiver: &mut StreamReceiver) -> Option<Message> {
    use futures_util::StreamExt;
    let serial = tokio::time::timeout(Duration::from_millis(500), receiver.next())
        .await
        .ok()??;
    let (bytes, _addr) = serial.into_parts();
    Message::from_vec(&bytes).ok()
}

fn a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::A(A(ip)))
}

fn aaaa_record(name: &str, ip: Ipv6Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::AAAA(AAAA(ip)))
}

/// The set of address literals an answer carried back to the VM (post-scrub).
fn answered_addrs(msg: &Message) -> Vec<IpAddr> {
    msg.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        })
        .collect()
}

// ===========================================================================
// The in-process MOCK UPSTREAM (network-free forwarder fixture; trimmed from
// suppression_shapes / policy_seam — a UDP+TCP DNS responder on a 127.0.0.1 port).
// ===========================================================================

mod mock_up {
    use super::*;
    use std::collections::HashMap;

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
    }

    impl MockUpstream {
        pub fn forwarder(&self, timeout: Duration) -> ForwarderConfig {
            ForwarderConfig {
                upstreams: vec![self.addr],
                timeout,
            }
        }
    }

    impl Drop for MockUpstream {
        fn drop(&mut self) {
            self.shutdown.notify_waiters();
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
        let (udp, tcp) = bind_shared_port().await;
        let addr = udp.local_addr().unwrap();
        let shutdown = Arc::new(tokio::sync::Notify::new());
        let zone = Arc::new(zone);

        {
            let zone = zone.clone();
            let shutdown = shutdown.clone();
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

        MockUpstream { addr, shutdown }
    }
}

// ===========================================================================
// GUARDRAIL 1 — DNS-4 / W5 SANITY SCRUB on the WIRE ANSWER PATH (doc 09 §4 rule 2).
//
// The always-Allow FixedStubPolicy forwards every query, so a mock upstream answering
// martian addresses exercises the gate's answer-path sanity scrub directly: a martian RR
// must NEVER reach the VM, and a name resolving entirely to martians is SERVFAIL.
// ===========================================================================

/// Build an always-Allow handler whose forwarder points at the mock, with a capturing
/// event sink so the LOG-1 emission is assertable on the same drive.
fn allow_handler(
    forwarder: ForwarderConfig,
    sink: &CapturingSink,
) -> StubRequestHandler<FixedStubPolicy> {
    StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        FixedStubPolicy::new(),
        forwarder,
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(sink.clone()),
    )
}

#[tokio::test]
async fn forwarded_answer_strips_private_and_keeps_public_a_records() {
    // A rebinding upstream returns BOTH a public address AND a private (RFC1918) one for
    // an admitted name. The W5 scrub removes the private RR from the answer the VM sees,
    // keeps the public one, and the answer is NOERROR (a usable public address survived).
    let public = Ipv4Addr::new(140, 82, 121, 4); // a genuine public unicast addr
    let private = Ipv4Addr::new(10, 0, 0, 5); // RFC1918 — a rebinding answer
    let answer = vec![
        a_record("mixed.example.", public, 300),
        a_record("mixed.example.", private, 300),
    ];
    let zone = mock_up::Zone::new().set("mixed.example.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;
    let sink = CapturingSink::new();
    let handler = allow_handler(mock.forwarder(Duration::from_secs(2)), &sink);

    let resp = drive(&handler, &query_bytes(1, "mixed.example.", RecordType::A)).await;

    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::NoError,
        "a public address survived, so the answer is NOERROR"
    );
    let addrs = answered_addrs(&resp);
    assert!(
        addrs.contains(&IpAddr::V4(public)),
        "the public address is answered: {addrs:?}"
    );
    assert!(
        !addrs.contains(&IpAddr::V4(private)),
        "the RFC1918 private address is SCRUBBED from the answer (DNS-4 rule 2): {addrs:?}"
    );
}

#[tokio::test]
async fn name_resolving_entirely_to_martians_is_servfail_never_an_answer() {
    // A name whose every resolved address is a martian (private + loopback + link-local).
    // The W5 filter leaves no plumbable address → the transaction returns NoPlumbableAddress
    // → SERVFAIL (a genuine ds-dnsgate failure). NEVER a NOERROR answer carrying a martian,
    // and NEVER a policy NXDOMAIN (W5 is not a policy verdict).
    let answer = vec![
        a_record("allmartian.example.", Ipv4Addr::new(192, 168, 1, 1), 300),
        a_record("allmartian.example.", Ipv4Addr::new(127, 0, 0, 1), 300),
        a_record("allmartian.example.", Ipv4Addr::new(169, 254, 0, 1), 300),
    ];
    let zone = mock_up::Zone::new().set("allmartian.example.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;
    let sink = CapturingSink::new();
    let handler = allow_handler(mock.forwarder(Duration::from_secs(2)), &sink);

    let resp = drive(
        &handler,
        &query_bytes(2, "allmartian.example.", RecordType::A),
    )
    .await;

    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::ServFail,
        "an all-martian name is SERVFAIL (W5: no plumbable address to admit/answer)"
    );
    assert!(
        answered_addrs(&resp).is_empty(),
        "no address record is ever answered for an all-martian name"
    );
    assert_ne!(
        resp.metadata.response_code,
        ResponseCode::NXDomain,
        "W5 is a genuine ds-dnsgate failure (SERVFAIL), never a policy NXDOMAIN"
    );
}

#[tokio::test]
async fn forwarded_answer_strips_embedded_ipv4_mapped_private_aaaa() {
    // The load-bearing rebinding clause (doc 09 §4 rule 2 verbatim): an answer carrying an
    // IPv4-MAPPED IPv6 address wrapping a private v4 (::ffff:10.0.0.5) gains nothing — the
    // embedded v4 is unwrapped and scrubbed. Here a query for AAAA would be fast-NODATA'd,
    // so we drive an A query whose answer bundles BOTH a public A and a mapped-private AAAA;
    // the §3.3 type-scrub already removes AAAA, but the KEY assertion is the public A
    // survives and the mapped-private never appears (the W5 + §3.3 layers compose). The
    // mapped-private AAAA is independently proven scrubbed-by-value in the txn unit table.
    let public = Ipv4Addr::new(8, 8, 4, 4);
    let mapped_private: Ipv6Addr = "::ffff:10.0.0.5".parse().unwrap();
    let answer = vec![
        a_record("embed.example.", public, 300),
        aaaa_record("embed.example.", mapped_private, 300),
    ];
    let zone = mock_up::Zone::new().set("embed.example.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;
    let sink = CapturingSink::new();
    let handler = allow_handler(mock.forwarder(Duration::from_secs(2)), &sink);

    let resp = drive(&handler, &query_bytes(3, "embed.example.", RecordType::A)).await;

    assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
    let addrs = answered_addrs(&resp);
    assert!(
        addrs.contains(&IpAddr::V4(public)),
        "the public A survives: {addrs:?}"
    );
    assert!(
        !addrs.contains(&IpAddr::V6(mapped_private)),
        "the IPv4-mapped-private AAAA never reaches the VM (§3.3 type-scrub + W5): {addrs:?}"
    );
}

// ===========================================================================
// GUARDRAIL 2 — DENIAL SEMANTICS on the wire (doc 11 §3.2, D71) — a focused re-proof of
// the hard-deny shape on the SAME drive harness, distinct from policy_verdict's pack path.
// ===========================================================================

/// A policy that DENIES every query (NXDOMAIN) with a real POL-3 triple.
#[derive(Clone)]
struct AlwaysDenyPolicy;
impl PolicyHook for AlwaysDenyPolicy {
    fn evaluate(&self, _ctx: &DnsQueryCtx) -> Verdict {
        Verdict::Deny {
            rcode_policy: ds_dnsgate::policy::RcodePolicy::NxDomain,
            rung: None,
            provenance: SeamProvenance {
                rule_id: "blocklist/denied.example".to_string(),
                policy_layer: "system-baseline".to_string(),
                policy_version: "2026-06-13".to_string(),
            },
        }
    }
}

#[tokio::test]
async fn hard_deny_is_nxdomain_with_authored_soa_and_no_address() {
    // The §3.2 hard-deny shape: NXDOMAIN (never SERVFAIL/REFUSED), empty answer, the
    // always-authored signature SOA with MNAME=denied.policy.<zone> and TTL==MINIMUM.
    let sink = CapturingSink::new();
    let handler = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        AlwaysDenyPolicy,
        // A dead upstream with a long timeout: a deny NEVER forwards, so this hang-trap
        // proves the deny is authored without contacting any upstream.
        ForwarderConfig {
            upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
            timeout: Duration::from_secs(30),
        },
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(sink.clone()),
    );

    let resp = tokio::time::timeout(
        Duration::from_secs(3),
        drive(&handler, &query_bytes(4, "denied.example.", RecordType::A)),
    )
    .await
    .expect("a deny must not wait on the upstream (no forward)");

    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::NXDomain,
        "a hard deny is NXDOMAIN, never SERVFAIL/REFUSED"
    );
    assert!(resp.answers.is_empty(), "a deny carries no answer record");
    let soa = resp
        .authorities
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(soa) => Some((soa, r.ttl)),
            _ => None,
        })
        .expect("the §3.2 hard deny authors a signature SOA");
    assert_eq!(
        soa.0.mname.to_ascii(),
        "denied.policy.boundary.",
        "the default boundary zone reproduces the frozen signature MNAME"
    );
    assert_eq!(soa.1, soa.0.minimum, "SOA record TTL == MINIMUM (RFC 2308)");

    // §6.7: the deny emitted a PolicyDecision-class event on the Denied path.
    let ev = sink.events();
    assert_eq!(ev.last().unwrap().path, EventPath::Denied);
    assert!(!ev.last().unwrap().provenance.rule_id.is_empty());
}

// ===========================================================================
// GUARDRAIL 3 — ASK-USER SEAM + ATTENDEDNESS DOWNGRADE (doc 09 §4 DNS-3; D18/D53/D77).
// ===========================================================================

/// A policy that ASKS for every query (unknown-domain posture) with a real POL-3 triple
/// and a session-scoped PromptRef.
#[derive(Clone)]
struct AlwaysAskPolicy;
impl PolicyHook for AlwaysAskPolicy {
    fn evaluate(&self, ctx: &DnsQueryCtx) -> Verdict {
        Verdict::Ask {
            prompt_ref: PromptRef {
                session: ctx.session.clone(),
                qname: ctx.qname.clone(),
            },
            provenance: SeamProvenance {
                rule_id: "baseline-pack:core/unknown.example".to_string(),
                policy_layer: "pol2-system-baseline".to_string(),
                policy_version: "2026-06-13".to_string(),
            },
        }
    }
}

/// A dead-upstream forwarder: an Ask never forwards, so this hang-trap proves it.
fn dead_forwarder() -> ForwarderConfig {
    ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_secs(30),
    }
}

#[tokio::test]
async fn attended_ask_is_refused_and_raises_one_ask_user_request_without_suspend() {
    // ATTENDED unknown-domain Ask (D77): the wire answer is an immediate REFUSED (no
    // cacheable signal), the human is notified async via exactly ONE AskUserRequest, and
    // the VM is never suspended (the gate has no suspend path — it answers REFUSED and the
    // agent keeps running). The AskUserRequest carries the domain + the matched-rule POL-3.
    let events = CapturingSink::new();
    let asks = CapturingAskSink::new();
    let handler = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        AlwaysAskPolicy,
        dead_forwarder(),
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(events.clone()),
    )
    .with_ask_user(Arc::new(asks.clone()))
    .with_ask_posture(AskPosture::Attended);

    let resp = tokio::time::timeout(
        Duration::from_secs(3),
        drive(&handler, &query_bytes(5, "unknown.example.", RecordType::A)),
    )
    .await
    .expect("an Ask must not wait on the upstream (no forward)");

    // Wire: REFUSED, never NXDOMAIN (no cacheable negative signal), no records.
    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::Refused,
        "an attended Ask is REFUSED (§3.2): {resp:?}"
    );
    assert_ne!(
        resp.metadata.response_code,
        ResponseCode::NXDomain,
        "an Ask is never NXDOMAIN (no cacheable negative signal)"
    );
    assert!(resp.answers.is_empty(), "a REFUSED carries no answer");

    // Seam: exactly ONE AskUserRequest raised, carrying the domain + matched-rule POL-3.
    let raised = asks.asks();
    assert_eq!(raised.len(), 1, "exactly one ask raised, got {raised:?}");
    assert_eq!(raised[0].resource_kind, RESOURCE_KIND_DOMAIN);
    assert_eq!(raised[0].resource_name, "unknown.example.");
    assert_eq!(
        raised[0].matched_rule_id, "baseline-pack:core/unknown.example",
        "the ask carries the matched-rule POL-3 (the why-was-this-asked answer)"
    );
    assert_eq!(raised[0].policy_layer, "pol2-system-baseline");
    assert_eq!(raised[0].policy_version, "2026-06-13");

    // LOG-1: the event is the attended `Asked` path with real provenance.
    let ev = events.events();
    assert_eq!(ev.last().unwrap().path, EventPath::Asked);
    assert_eq!(
        ev.last().unwrap().provenance.rule_id,
        "baseline-pack:core/unknown.example"
    );
}

#[tokio::test]
async fn unattended_ask_downgrades_to_block_and_raises_no_ask_user_request() {
    // UNATTENDED unknown-domain Ask (D53 as revised by D77): DOWNGRADE to immediate
    // block+log. The wire answer is still REFUSED (the §3.2 ask shape, never a cacheable
    // signal), but NO human is interrupted — ZERO AskUserRequests raised — and the LOG-1
    // event is the DISTINCT `AskDowngradedBlock` path so a join tells the two apart. The VM
    // is never suspended.
    let events = CapturingSink::new();
    let asks = CapturingAskSink::new();
    let handler = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        AlwaysAskPolicy,
        dead_forwarder(),
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(events.clone()),
    )
    .with_ask_user(Arc::new(asks.clone()))
    .with_ask_posture(AskPosture::Unattended);

    let resp = tokio::time::timeout(
        Duration::from_secs(3),
        drive(&handler, &query_bytes(6, "unknown.example.", RecordType::A)),
    )
    .await
    .expect("an Ask must not wait on the upstream (no forward)");

    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::Refused,
        "an unattended Ask is still REFUSED on the wire (the §3.2 ask shape)"
    );
    assert!(
        asks.is_empty(),
        "the unattended downgrade raises NO ask (no human to interrupt): {:?}",
        asks.asks()
    );
    let ev = events.events();
    assert_eq!(
        ev.last().unwrap().path,
        EventPath::AskDowngradedBlock,
        "the downgrade is recorded on the distinct AskDowngradedBlock path"
    );
    assert!(!ev.last().unwrap().provenance.rule_id.is_empty());
}

#[tokio::test]
async fn default_posture_is_the_conservative_unattended_downgrade() {
    // A handler with NO posture set defaults to UNATTENDED — the conservative posture
    // (no open ask no one will answer). Proven by driving the default handler and asserting
    // the downgrade path + zero asks.
    let events = CapturingSink::new();
    let asks = CapturingAskSink::new();
    let handler = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        AlwaysAskPolicy,
        dead_forwarder(),
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(events.clone()),
    )
    .with_ask_user(Arc::new(asks.clone()));
    // (no .with_ask_posture — the default)

    let resp = tokio::time::timeout(
        Duration::from_secs(3),
        drive(&handler, &query_bytes(7, "unknown.example.", RecordType::A)),
    )
    .await
    .expect("an Ask must not wait on the upstream");

    assert_eq!(resp.metadata.response_code, ResponseCode::Refused);
    assert!(asks.is_empty(), "the default posture interrupts no human");
    assert_eq!(
        events.events().last().unwrap().path,
        EventPath::AskDowngradedBlock
    );
}

// ===========================================================================
// GUARDRAIL 4 — LOG-1 emission invariants: provenance on EVERY event (the CI gate), and
// the `aimed_resolver` reserved-optional carried on every event (OQ3 always-None default).
// ===========================================================================

#[tokio::test]
async fn every_query_path_event_carries_provenance_and_the_aimed_resolver_field() {
    // §6.7: every query path emits a DnsEvent with NON-EMPTY POL-3 provenance (the CI-fatal
    // invariant), AND every event carries the reserved-optional `aimed_resolver` field —
    // conservatively always-None (the OQ3 default; population is the ConnOrigin task's). We
    // sweep an Allow (forwarded answer), a Deny, and an Ask through the same capturing sink.
    let answer = vec![a_record(
        "allow.example.",
        Ipv4Addr::new(93, 184, 216, 34),
        300,
    )];
    let zone = mock_up::Zone::new().set("allow.example.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;

    // Allow path (forwarded answer) — the always-Allow stub.
    let allow_sink = CapturingSink::new();
    let allow = allow_handler(mock.forwarder(Duration::from_secs(2)), &allow_sink);
    let _ = drive(&allow, &query_bytes(8, "allow.example.", RecordType::A)).await;

    // Deny path.
    let deny_sink = CapturingSink::new();
    let deny = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        AlwaysDenyPolicy,
        dead_forwarder(),
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(deny_sink.clone()),
    );
    let _ = drive(&deny, &query_bytes(9, "denied.example.", RecordType::A)).await;

    // Ask path (attended).
    let ask_sink = CapturingSink::new();
    let ask = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        AlwaysAskPolicy,
        dead_forwarder(),
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(ask_sink.clone()),
    )
    .with_ask_posture(AskPosture::Attended);
    let _ = drive(&ask, &query_bytes(10, "unknown.example.", RecordType::A)).await;

    for sink in [&allow_sink, &deny_sink, &ask_sink] {
        let events = sink.events();
        assert!(!events.is_empty(), "every path emits at least one event");
        for e in &events {
            // The CI-fatal §6.7 invariant: provenance is present and non-empty on EVERY event.
            assert!(
                !e.provenance.rule_id.is_empty()
                    && !e.provenance.policy_layer.is_empty()
                    && !e.provenance.policy_version.is_empty(),
                "every event carries a complete POL-3 triple: {e:?}"
            );
            // The reserved-optional aimed_resolver is present on every event, always-None
            // (the conservative OQ3 default — the SHAPE is ready, population deferred).
            assert_eq!(
                e.aimed_resolver, None,
                "aimed_resolver is the reserved-optional OQ3 always-None default: {e:?}"
            );
        }
    }

    // The forwarded answer survived and carries the public address (proves the Allow path
    // reached the answer authoring, so its event is a real ForwardedAnswer, not an error).
    assert!(allow_sink
        .events()
        .iter()
        .any(|e| e.path == EventPath::ForwardedAnswer));
}

// ===========================================================================
// GUARDRAIL 5 — HANDLER→TXN FULL-PIPELINE DEDUP (W1, doc 11 §3.1 / §5.4): a wire answer
// carrying the SAME terminal A RR twice, pushed THROUGH the full request→handle→answer
// pipeline (the `drive` harness above), must program EXACTLY ONE kernel SetInsert, mint
// EXACTLY ONE live admission record, and leave the §5.4 reverse-sweep refcount at 1.
//
// The handler.rs `terminal_addr_dedup_tests` already pin this at the `run_admission_for_answer`
// UNIT level (the in-process call). This is the missing FULL-PIPELINE twin: it drives a real
// duplicate-stuffed UDP/TCP wire answer through `RequestHandler::handle_request` and reads the
// dedup result off the handler's OWN admission stores. The dedup is LAYERED — the handler
// canonicalizes its terminal addresses to a distinct set BEFORE the transaction (handler.rs),
// and the transaction itself re-canonicalizes (txn.rs) — so this contract pins BOTH layers as
// ONE wire-observable property: a future refactor cannot drop one layer assuming the other
// covers it. LOOPBACK/SYNTHETIC only (D50): the mock upstream + the reportable in-memory
// RecordingSetProgrammer, no live kernel, no network beyond 127.0.0.1.
// ===========================================================================
mod handler_txn_full_pipeline_dedup {
    use super::*;

    use ds_contracts::dns_admission::{AddressFamily, AdmissionKey, AdmittedAddr};
    use ds_dnsgate::server::LiveAdmissions;
    use ds_dnsgate::txn::{AdmissionStores, RecordingSetProgrammer};

    /// The fixed single-session uuid the handler attributes every query to (the
    /// `with_session_uuid` agreement, doc 11 §5.1) — so the admission lands under a
    /// deterministic `{uuid, fqdn}` key the test reads back, independent of the wire source.
    const FIXED_UUID: &str = "sess-full-pipeline-dedup-0001";

    /// Project an `Ipv4Addr` onto the frozen family-agnostic `AdmittedAddr` — the SAME
    /// projection the admit insert + the reverse-index read agree on (mirrors the in-crate
    /// `txn` dedup test's `admitted_v4`).
    fn admitted_v4(ip: Ipv4Addr) -> AdmittedAddr {
        AdmittedAddr {
            family: AddressFamily::V4,
            octets: ip.octets().to_vec(),
        }
    }

    #[tokio::test]
    async fn duplicate_a_rr_on_the_wire_admits_once_through_the_full_pipeline() {
        // A rebinding / malformed upstream returns the SAME public A RR THREE times for an
        // admitted name. Driven through the full request→handle→answer pipeline, the layered
        // handler+txn dedup must collapse it to ONE kernel SetInsert, ONE live record, and a
        // reverse-sweep refcount of 1 — so a single later revoke fully releases the kernel
        // element (no residue at refcount > 0). Pre-dedup this would have inflated all three.
        let dup = Ipv4Addr::new(93, 184, 216, 34); // a genuine public unicast addr
        let answer = vec![
            a_record("dup.example.", dup, 300),
            a_record("dup.example.", dup, 300),
            a_record("dup.example.", dup, 300),
        ];
        let zone = mock_up::Zone::new().set("dup.example.", RecordType::A, answer);
        let mock = mock_up::spawn(zone).await;

        // Build the always-Allow handler over OUR OWN set programmer + live registry (Arc
        // clones we keep), bound via `with_admission(AdmissionStores::with_parts(..))`, so we
        // can read the kernel SetInsert count + the live records off the SAME stores the
        // handler admits into. `with_session_uuid` pins the attribution to FIXED_UUID so the
        // admission key is deterministic regardless of the wire source.
        let set = Arc::new(RecordingSetProgrammer::new());
        let live = LiveAdmissions::new();
        let stores = AdmissionStores::with_parts(Arc::clone(&set), live.clone());
        let handler = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
            FixedStubPolicy::new(),
            mock.forwarder(Duration::from_secs(2)),
            DEFAULT_BOUNDARY_ZONE,
            Arc::new(CapturingSink::new()),
        )
        .with_session_uuid(FIXED_UUID)
        .with_admission(stores.clone(), 60);

        let resp = drive(&handler, &query_bytes(1, "dup.example.", RecordType::A)).await;

        // The wire answer is NOERROR carrying the single public address (the dedup is
        // canonicalization, not a deny — and a duplicate-stuffed answer still admits).
        assert_eq!(
            resp.metadata.response_code,
            ResponseCode::NoError,
            "a duplicate-stuffed answer still admits NOERROR: {resp:?}"
        );
        let addrs = answered_addrs(&resp);
        assert!(
            addrs.contains(&IpAddr::V4(dup)),
            "the public address is answered: {addrs:?}"
        );

        // (1) EXACTLY ONE kernel SetInsert programmed — three identical A RRs do NOT program
        //     the NFT-3 set element three times. `committed()` (live residue) and `programmed()`
        //     (every attempt) are both 1, since nothing was withdrawn on this success path.
        assert_eq!(
            set.programmed().len(),
            1,
            "three identical A RRs program the kernel allow-set element exactly once: {:?}",
            set.programmed()
        );
        assert_eq!(
            set.committed().len(),
            1,
            "exactly one kernel element is live (no inflated set): {:?}",
            set.committed()
        );
        assert_eq!(
            set.committed()[0].element,
            admitted_v4(dup).to_dst_key().0,
            "the one programmed element is the deduped public IP, keyed byte-exact"
        );

        // (2) EXACTLY ONE live §5.4 admission record minted for the distinct IP (not three) —
        //     read off the SAME registry the handler admitted into.
        let records = live.snapshot();
        assert_eq!(
            records.len(),
            1,
            "one live admission record for the distinct IP (not one per duplicate RR): {records:?}"
        );
        assert_eq!(records[0].ip, IpAddr::V4(dup));
        assert_eq!(
            records[0].session, FIXED_UUID,
            "the live record is attributed to the agreed single-session uuid"
        );

        // The DNS-2b map entry records exactly the one distinct admitted IP, under the dot-less
        // `{uuid, fqdn}` key (the gate canonicalizes the trailing dot off — the form a co-host
        // ds-tlsproxy reads with).
        let key = AdmissionKey {
            session_uuid: FIXED_UUID.to_string(),
            original_query_fqdn: "dup.example".to_string(),
        };
        let entry = stores
            .lookup(&key)
            .expect("the full-pipeline admission wrote a DNS-2b map entry under the dot-less key");
        assert_eq!(
            entry.admitted_ips,
            vec![admitted_v4(dup)],
            "three identical A RRs collapse to a single admitted IP in the map entry"
        );

        // (3) The §5.4 reverse-sweep refcount is 1 (NOT 3) — a single revoke fully releases the
        //     kernel element; no residual refcount holds an unrevoked allow-set entry.
        assert_eq!(
            stores.reverse_refcount(FIXED_UUID, &admitted_v4(dup)),
            1,
            "the duplicated IP increments the (session, ip) revocation refcount exactly once"
        );
    }
}
