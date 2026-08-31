//! §3.3 record-scrubbing wire tests (doc 11 §3.3, D70/D75; D71 authored SOA).
//!
//! These drive the gate over the wire through a NETWORK-FREE loopback mock upstream
//! (the `mock_up` module below — a self-contained UDP+TCP DNS responder on a
//! `127.0.0.1` ephemeral port, injected into the gate's forwarder pool via
//! `ForwarderConfig`). No test reaches a real resolver or assumes a default route.
//! They are kept SEPARATE from `framework_validation.rs` so the fuzz-corpus unit
//! stays the sole owner of that file (per the taskdb collision note).
//!
//! What is proven here (each over BOTH UDP and TCP/53 — the same handler serves both
//! transports, so the scrub is transport-invariant, doc 11 §3.4):
//!   * AAAA query -> fast NOERROR/NODATA with the D71 ds-dnsgate-authored SOA in the
//!     authority section; the AAAA never reaches the VM; never drop/SERVFAIL/REFUSED.
//!   * A query whose mock upstream answer carries HTTPS(65)/SVCB(64) records arrives
//!     at the client WITHOUT them (suppressed entirely on the forwarded answer path).
//!   * An explicit type-65 (HTTPS) / type-64 (SVCB) query -> NODATA with an authored
//!     SOA — never forwarded.
//!   * An A answer that carries a bundled AAAA RR has the AAAA stripped too.
//!
//! The §3.3 suppression is the steering control for COOPERATIVE clients; the NFT-4
//! udp/443 reject is the sole control for non-cooperative clients — a separate,
//! independent control tested elsewhere, never merged with these (doc 11 §3.3).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ds_dnsgate::handler::{
    ForwarderConfig, StubRequestHandler, DEFAULT_BOUNDARY_ZONE, NEGATIVE_TTL_SECS,
    SOA_SIGNATURE_MNAME,
};
use ds_dnsgate::policy::FixedStubPolicy;
use ds_dnsgate::{spawn_gate, GateConfig, RunningGate};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::svcb::{Alpn, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, HTTPS, SVCB};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

// ---------------------------------------------------------------------------
// Query construction + UDP/TCP round-trips (loopback only).
// ---------------------------------------------------------------------------

fn query_of(id: u16, name: &str, qtype: RecordType) -> Vec<u8> {
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

async fn udp_round_trip(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    sock.connect(server).await.unwrap();
    sock.send(query).await.unwrap();
    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .expect("udp recv timed out")
        .unwrap();
    buf.truncate(n);
    buf
}

async fn tcp_round_trip(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let mut stream = TcpStream::connect(server).await.unwrap();
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

/// Run `query` over UDP and over TCP/53 against the gate and parse both responses,
/// so every §3.3 invariant is asserted IDENTICALLY across the two transports (doc 11
/// §3.4: every wire invariant holds for TCP-transported queries too, including the
/// TC-bit retry path the client would take after a truncated UDP answer).
async fn both_transports<P: ds_dnsgate::policy::PolicyHook + Clone>(
    gate: &RunningGate<P>,
    query: &[u8],
) -> (Message, Message) {
    let udp = Message::from_vec(&udp_round_trip(gate.udp_local_addr(), query).await).unwrap();
    let tcp = Message::from_vec(&tcp_round_trip(gate.tcp_local_addr(), query).await).unwrap();
    (udp, tcp)
}

// ===========================================================================
// The in-process MOCK UPSTREAM (network-free forwarder fixture, doc 11 §2).
//
// A tiny UDP+TCP DNS responder on 127.0.0.1:0, injected into the gate's forwarder
// pool. It serves a programmed zone of arbitrary record sets so a test can make the
// UPSTREAM answer carry HTTPS/SVCB/AAAA records — the seam the §3.3 forwarded-answer
// scrub must strip before the answer reaches the VM. Built from hickory-proto wire
// types only (the same wire the real upstream speaks), never the resolver internals.
// ===========================================================================

mod mock_up {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

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

        /// Program one or more answer records for `(name, qtype)`. The mock authors
        /// exactly these records into the answer section of the response — so a test
        /// can have the UPSTREAM return AAAA / HTTPS / SVCB records the gate must scrub.
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

    /// Bind a UDP socket and a TCP listener that share one loopback ephemeral port
    /// (the forwarder dials one SocketAddr for both transports). Bounded retries —
    /// real exhaustion surfaces as a panic, never a hang. Network-free.
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

    /// Spawn the mock upstream serving `zone` over UDP and TCP. Network-free.
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

/// A gate whose forwarder points at the given mock upstream.
async fn gate_with_mock(mock: &mock_up::MockUpstream) -> RunningGate<FixedStubPolicy> {
    let config = GateConfig {
        forwarder: mock.forwarder(Duration::from_secs(2)),
        ..GateConfig::default()
    };
    spawn_gate(FixedStubPolicy::new(), config).await.unwrap()
}

// ---------------------------------------------------------------------------
// Record builders for the malicious/steering record classes.
// ---------------------------------------------------------------------------

fn a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::A(A(ip)))
}

fn aaaa_record(name: &str, ip: Ipv6Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::AAAA(AAAA(ip)))
}

/// A realistic HTTPS (type-65) record advertising `alpn=h3` — the D70 steering shape
/// (and the ECH carrier) the §3.3 scrub must remove from any answer reaching a VM.
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

/// A SVCB (type-64) record — the generic sibling of HTTPS, same suppression class.
fn svcb_record(name: &str, ttl: u32) -> Record {
    let svcb = SVCB::new(1, Name::from_ascii("target.example.test.").unwrap(), vec![]);
    Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::SVCB(svcb))
}

/// Assert a parsed response is the §3.3 fast NOERROR/NODATA shape with the D71
/// authored SOA in the authority section: NOERROR rcode, empty answer section, and an
/// authority SOA whose MNAME is the frozen signature name and whose TTL/MINIMUM equal
/// the negative-TTL. NEVER NXDOMAIN/SERVFAIL/REFUSED, and never any answer record of
/// the scrubbed type.
fn assert_authored_nodata(msg: &Message, transport: &str) {
    assert_eq!(
        msg.metadata.response_code,
        ResponseCode::NoError,
        "{transport}: §3.3 scrub is NOERROR/NODATA — never NXDOMAIN/SERVFAIL/REFUSED (RFC 4074 stall)"
    );
    assert_eq!(
        msg.answers.len(),
        0,
        "{transport}: NODATA has an empty answer section — the scrubbed record never reaches the VM"
    );

    // The D71 authored SOA rides the authority section (the encoder chains the `soa`
    // build slot into NSCOUNT).
    let (soa_rec, soa) = msg
        .authorities
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(soa) => Some((r, soa)),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!("{transport}: an authored SOA must be present in the authority section (§3.2)")
        });
    assert_eq!(
        soa.mname.to_ascii(),
        SOA_SIGNATURE_MNAME,
        "{transport}: the SOA MNAME is the frozen ds-dnsgate signature name (D71), not an upstream relay"
    );
    assert_eq!(
        soa.minimum, NEGATIVE_TTL_SECS,
        "{transport}: SOA MINIMUM == the policy negative-TTL (RFC 2308 cache control)"
    );
    assert_eq!(
        soa_rec.ttl, NEGATIVE_TTL_SECS,
        "{transport}: SOA record TTL == MINIMUM == the negative-TTL (RFC 2308)"
    );
}

// ===========================================================================
// 1. AAAA query -> fast NOERROR/NODATA + D71 authored SOA, over UDP and TCP/53.
// ===========================================================================

#[tokio::test]
async fn aaaa_query_is_fast_nodata_with_authored_soa() {
    // Program the mock upstream WITH a real AAAA for the name. The gate must NOT
    // forward the AAAA query at all (fast NODATA) — so even though the upstream would
    // happily answer with the v6 address, it never reaches the VM.
    let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0, 0, 0, 0, 0x10);
    let zone = mock_up::Zone::new().set(
        "v6.example.test.",
        RecordType::AAAA,
        vec![aaaa_record("v6.example.test.", v6, 300)],
    );
    let mock = mock_up::spawn(zone).await;
    let gate = gate_with_mock(&mock).await;

    let query = query_of(0xa6a6, "v6.example.test.", RecordType::AAAA);
    let (udp, tcp) = both_transports(&gate, &query).await;

    assert_authored_nodata(&udp, "UDP");
    assert_authored_nodata(&tcp, "TCP");
    // No AAAA RR anywhere in the response reaching the VM.
    for (msg, t) in [(&udp, "UDP"), (&tcp, "TCP")] {
        assert!(
            msg.answers
                .iter()
                .all(|r| r.record_type() != RecordType::AAAA),
            "{t}: the AAAA never reaches the VM"
        );
    }
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 2. Explicit HTTPS(65) / SVCB(64) query -> NODATA + authored SOA (never forwarded).
// ===========================================================================

#[tokio::test]
async fn explicit_https_query_is_nodata_with_authored_soa() {
    // Program the upstream with an HTTPS record for the name; the gate must suppress
    // it entirely — an explicit type-65 query returns NODATA with the authored SOA,
    // never forwarded.
    let zone = mock_up::Zone::new().set(
        "ech.example.test.",
        RecordType::HTTPS,
        vec![https_record("ech.example.test.", 300)],
    );
    let mock = mock_up::spawn(zone).await;
    let gate = gate_with_mock(&mock).await;

    let query = query_of(0x6565, "ech.example.test.", RecordType::HTTPS);
    let (udp, tcp) = both_transports(&gate, &query).await;
    assert_authored_nodata(&udp, "UDP");
    assert_authored_nodata(&tcp, "TCP");
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn explicit_svcb_query_is_nodata_with_authored_soa() {
    let zone = mock_up::Zone::new().set(
        "svc.example.test.",
        RecordType::SVCB,
        vec![svcb_record("svc.example.test.", 300)],
    );
    let mock = mock_up::spawn(zone).await;
    let gate = gate_with_mock(&mock).await;

    let query = query_of(0x6464, "svc.example.test.", RecordType::SVCB);
    let (udp, tcp) = both_transports(&gate, &query).await;
    assert_authored_nodata(&udp, "UDP");
    assert_authored_nodata(&tcp, "TCP");
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 3. A query whose upstream answer carries HTTPS/SVCB records -> stripped.
//
// The ECH-can't-hide-a-non-admitted-domain assertion (doc 11 §6): no HTTPS/SVCB
// answer reaches a VM, even when the answer's PRIMARY record (the A) is legitimately
// forwarded. The suppression is authored on the gate's answer path, not via hickory.
// ===========================================================================

#[tokio::test]
async fn forwarded_a_answer_has_https_and_svcb_stripped() {
    // The upstream returns an A record bundled with an HTTPS and a SVCB record for the
    // same name (a real CDN frequently bundles HTTPS hints in the A response's answer
    // or additional section; here in the answer section so the gate's answer-path
    // scrub is the unit under test). The gate forwards the A; the HTTPS/SVCB are gone.
    let answer = vec![
        a_record("cdn.example.test.", Ipv4Addr::new(203, 0, 113, 9), 120),
        https_record("cdn.example.test.", 120),
        svcb_record("cdn.example.test.", 120),
    ];
    let zone = mock_up::Zone::new().set("cdn.example.test.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;
    let gate = gate_with_mock(&mock).await;

    let query = query_of(0x0a65, "cdn.example.test.", RecordType::A);
    let (udp, tcp) = both_transports(&gate, &query).await;

    for (msg, t) in [(&udp, "UDP"), (&tcp, "TCP")] {
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::NoError,
            "{t}: a forwarded A answer is NOERROR"
        );
        // The legitimate A survives.
        assert!(
            msg.answers
                .iter()
                .any(|r| r.data.ip_addr()
                    == Some(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)))),
            "{t}: the legitimate A record is forwarded to the VM"
        );
        // No HTTPS/SVCB record reaches the VM (§3.3 ECH/QUIC steering suppression).
        assert!(
            msg.answers
                .iter()
                .all(|r| r.record_type() != RecordType::HTTPS),
            "{t}: no HTTPS(65) record reaches the VM — ECH config suppressed"
        );
        assert!(
            msg.answers
                .iter()
                .all(|r| r.record_type() != RecordType::SVCB),
            "{t}: no SVCB(64) record reaches the VM — alpn=h3 steering suppressed"
        );
    }
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 4. An A answer that bundles a stray AAAA -> AAAA stripped from the answer path.
//
// §3.3: AAAA RRs are stripped before the VM. Even when an A query's upstream answer
// carries an AAAA RR (a misbehaving or dual-stack-bundling upstream), the AAAA never
// reaches the v4-only guest.
// ===========================================================================

#[tokio::test]
async fn forwarded_a_answer_has_bundled_aaaa_stripped() {
    let v6 = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1);
    let answer = vec![
        a_record("dual.example.test.", Ipv4Addr::new(198, 51, 100, 4), 90),
        aaaa_record("dual.example.test.", v6, 90),
    ];
    let zone = mock_up::Zone::new().set("dual.example.test.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;
    let gate = gate_with_mock(&mock).await;

    let query = query_of(0x0a28, "dual.example.test.", RecordType::A);
    let (udp, tcp) = both_transports(&gate, &query).await;

    for (msg, t) in [(&udp, "UDP"), (&tcp, "TCP")] {
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(
            msg.answers
                .iter()
                .any(|r| r.data.ip_addr()
                    == Some(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 4)))),
            "{t}: the A is forwarded"
        );
        assert!(
            msg.answers
                .iter()
                .all(|r| r.record_type() != RecordType::AAAA),
            "{t}: the bundled AAAA is stripped before the v4-only guest sees it"
        );
    }
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 5. AAAA fast-NODATA is genuinely FAST — it is never forwarded upstream.
//
// Point the gate at a BLACKHOLE upstream (no mock at all -> the address is dead) but
// give it a long upstream timeout. An A query would stall the whole timeout; the AAAA
// fast-NODATA must return immediately because it is authored without any forward.
// ===========================================================================

#[tokio::test]
async fn aaaa_nodata_does_not_wait_on_upstream() {
    // A forwarder pointed at a closed loopback port with a LONG timeout. If the AAAA
    // path forwarded, it would stall the full timeout; the fast-NODATA returns at once.
    let dead = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
    let config = GateConfig {
        forwarder: ForwarderConfig {
            upstreams: vec![dead],
            timeout: Duration::from_secs(30),
        },
        ..GateConfig::default()
    };
    let gate = spawn_gate(FixedStubPolicy::new(), config).await.unwrap();

    let query = query_of(0xfa57, "fast.example.test.", RecordType::AAAA);
    let started = std::time::Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(3),
        udp_round_trip(gate.udp_local_addr(), &query),
    )
    .await
    .expect("AAAA fast-NODATA must NOT wait on the upstream — no forward at all");
    let elapsed = started.elapsed();
    let msg = Message::from_vec(&resp).unwrap();
    assert_authored_nodata(&msg, "UDP");
    assert!(
        elapsed < Duration::from_secs(2),
        "AAAA NODATA returned in {elapsed:?} — fast, no upstream round-trip (the 30s timeout never ran)"
    );
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 6. UDP/TCP shape parity for the scrubbed answer (the §3.4 frozen row).
// ===========================================================================

#[tokio::test]
async fn udp_and_tcp_agree_on_scrubbed_answer() {
    let answer = vec![
        a_record("parity.example.test.", Ipv4Addr::new(192, 0, 2, 50), 60),
        https_record("parity.example.test.", 60),
    ];
    let zone = mock_up::Zone::new().set("parity.example.test.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;
    let gate = gate_with_mock(&mock).await;

    let query = query_of(0x0aaa, "parity.example.test.", RecordType::A);
    let (udp, tcp) = both_transports(&gate, &query).await;

    assert_eq!(
        udp.metadata.response_code, tcp.metadata.response_code,
        "UDP and TCP agree on rcode for a scrubbed answer"
    );
    assert_eq!(
        udp.answers.len(),
        tcp.answers.len(),
        "UDP and TCP agree on answer count after the scrub"
    );
    assert_eq!(udp.answers.len(), 1, "only the A survives — HTTPS stripped");
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 7. SOA MNAME boundary-zone derivation (D71 — the VALUE change, not a SHAPE change).
//
// The authored-SOA MNAME is `denied.policy.<boundary-zone>.`. D71 freezes the
// `denied.policy.` prefix and the always-authored-SOA / TTL==MINIMUM==negative-TTL
// shape; only the `<boundary-zone>` suffix is a policy-push VALUE. `ds-policy-snapshot`
// carries no boundary-zone field yet (verified), so the gate threads a handler-local
// configured value via a constructor parameter that DEFAULTS to the working name. These
// assertions exercise that derivation point directly (no wire needed — the MNAME is a
// pure function of the configured zone), proving the default reproduces the frozen
// working-name MNAME and a configured zone flows through.
// ===========================================================================

#[test]
fn default_boundary_zone_reproduces_frozen_working_name_mname() {
    // The default constructor (and `spawn_gate`, which calls it) uses the working name.
    let handler =
        StubRequestHandler::with_forwarder(FixedStubPolicy::new(), ForwarderConfig::default());
    assert_eq!(
        handler.soa_mname(),
        SOA_SIGNATURE_MNAME,
        "the default boundary zone authors the frozen working-name MNAME (D71 working shape)"
    );
    // And the working name itself is the documented `boundary.` value.
    assert_eq!(DEFAULT_BOUNDARY_ZONE, "boundary.");
}

#[test]
fn configured_boundary_zone_derives_the_mname_value() {
    // A pushed boundary zone changes the VALUE (the suffix), never the SHAPE (the
    // `denied.policy.` prefix and trailing dot are constant).
    let handler = StubRequestHandler::with_forwarder_and_boundary_zone(
        FixedStubPolicy::new(),
        ForwarderConfig::default(),
        "ds.example.",
    );
    assert_eq!(handler.soa_mname(), "denied.policy.ds.example.");
    assert!(
        handler.soa_mname().starts_with("denied.policy."),
        "the D71 `denied.policy.` prefix is frozen — only the suffix is a value"
    );
    assert!(
        handler.soa_mname().ends_with('.'),
        "the authored MNAME is always a trailing-dot FQDN"
    );
}
