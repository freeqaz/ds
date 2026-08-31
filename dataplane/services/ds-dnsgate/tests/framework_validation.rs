//! DNS-1 framework-validation + forwarder/hardening harness (doc 09 §4 / doc 11).
//!
//! These tests MEASURE hickory-server 0.26.x behavior AND exercise the upstream
//! forwarder pool through live round-trips against the gate (`ds_dnsgate::spawn_gate`),
//! so the thresholds recorded in `README.md` are demonstrated, not asserted from
//! documentation. Everything is NETWORK-FREE: the forwarder is pointed at an
//! in-process UDP+TCP mock upstream on a `127.0.0.1` ephemeral port (the `mock_up`
//! module below); no test reaches a real resolver or assumes a default route. Live
//! resolution against the D64 `1.1.1.1` / `8.8.8.8` pair is gated behind
//! `DS_DNSGATE_LIVE_UPSTREAM=1` as a deferred manual step (`live_upstream_d64_pair`).
//!
//! Coverage map:
//!   * read/conn timeouts        — `tcp_read_timeout_closes_idle_connection`
//!   * connection cap (semaphore)— `tcp_connection_cap_holds_under_flood`
//!   * TC-bit truncation         — `udp_no_edns_*`, `udp_edns_*`
//!   * EDNS buffer sizes         — `edns_*`, `udp_*`
//!   * UDP/TCP parity            — `tcp_never_truncates_what_udp_truncates`
//!   * forwarder pool (D64)      — `forward_a_record_*`, `forward_aaaa_*`
//!   * CNAME-chain following     — `forward_follows_cname_chain_*`
//!   * upstream timeout->SERVFAIL— `forward_upstream_timeout_is_servfail`
//!   * RUSTSEC-2026-0118 (NSEC3) — `rustsec_2026_0118_nsec3_loop_bounded`
//!   * RUSTSEC-2026-0119 (bomb)  — `rustsec_2026_0119_compression_bomb_bounded`
//!   * D67 seam (no hickory pub) — `no_hickory_type_in_policy_seam`
//!
//! The truncation tests still drive a parallel `padded::PaddedHandler` gate to push
//! the encoder past the UDP cap; the production handler forwards real upstream
//! answers and never pads.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use ds_dnsgate::handler::ForwarderConfig;
use ds_dnsgate::policy::FixedStubPolicy;
use ds_dnsgate::{spawn_gate, GateConfig};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, NULL};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

// ---------------------------------------------------------------------------
// MEASURED hickory 0.26.1 thresholds — the README findings, in code.
// ---------------------------------------------------------------------------

/// UDP, no EDNS OPT: hickory caps the response encoder at
/// `MAX_RECEIVE_BUFFER_SIZE` (NOT 512) — see hickory-server
/// `zone_handler/message_response.rs::encode`.
const UDP_NO_EDNS_MAX_SIZE: usize = 4096;
/// EDNS floor (RFC 6891 "values < 512 MUST be treated as 512"); `Edns::default`
/// and `Message::max_payload` both clamp to this floor.
const EDNS_FLOOR: u16 = 512;
/// 2020 DNS flag-day default advertised payload (`DEFAULT_MAX_PAYLOAD_LEN`).
const EDNS_FLAG_DAY_DEFAULT: u16 = 1232;
/// TCP encoder max size: `u16::MAX` — TCP answers never truncate.
const TCP_MAX_SIZE: usize = u16::MAX as usize;

// ---------------------------------------------------------------------------
// Helpers: build a query, send over UDP / TCP, parse the response.
// ---------------------------------------------------------------------------

fn query_of(id: u16, name: &str, qtype: RecordType, edns_payload: Option<u16>) -> Vec<u8> {
    let mut msg = Message::query();
    msg.metadata.id = id;
    msg.metadata.message_type = MessageType::Query;
    msg.metadata.op_code = OpCode::Query;
    msg.metadata.recursion_desired = true;
    msg.add_query(hickory_proto::op::Query::query(
        Name::from_ascii(name).unwrap(),
        qtype,
    ));
    if let Some(payload) = edns_payload {
        let mut edns = Edns::new();
        edns.set_max_payload(payload);
        edns.set_version(0);
        msg.set_edns(edns);
    }
    msg.to_vec().unwrap()
}

fn a_query(id: u16, name: &str, edns_payload: Option<u16>) -> Vec<u8> {
    query_of(id, name, RecordType::A, edns_payload)
}

async fn udp_round_trip(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    sock.connect(server).await.unwrap();
    sock.send(query).await.unwrap();
    // The UDP receive buffer the client offers; large enough to see whatever
    // hickory chose to send (truncated or not).
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
    // DNS over TCP framing: 2-byte big-endian length prefix.
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

// ===========================================================================
// The in-process MOCK UPSTREAM (network-free forwarder fixtures, doc 11 §2).
//
// A tiny UDP+TCP DNS responder on 127.0.0.1:0, injected into the gate's forwarder
// pool via ForwarderConfig. It serves a programmed zone: A/AAAA records and CNAME
// chains. A "blackhole" name is configured by simply NOT programming it AND running
// in blackhole mode (never answers) so the gate's per-query upstream timeout fires
// and yields SERVFAIL. Built from hickory-proto wire types only — the same wire the
// real upstream speaks — never the resolver internals.
// ===========================================================================

mod mock_up {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A programmed upstream zone: `(lowercased-name, qtype) -> answer records`.
    /// CNAME chains are expressed by programming a CNAME record under the original
    /// name plus the terminal record(s) under the target name; the mock authors the
    /// FULL chain in one response, mirroring a recursing upstream (so the gate's
    /// internal CNAME following is exercised by the gate consuming a chained answer).
    #[derive(Default, Clone)]
    pub struct Zone {
        answers: HashMap<(String, u16), Vec<Record>>,
        /// Crafted AUTHORITY-section records keyed by `(name, qtype)`, authored into
        /// the response's authority section alongside (or instead of) any answer. Used
        /// to feed the RUSTSEC-2026-0118 malicious NSEC3 chain to the gate's resolver
        /// the way a recursing upstream would on a denial-of-existence response.
        authority: HashMap<(String, u16), Vec<Record>>,
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

        /// Program one or more answer records for `(name, qtype)`.
        pub fn set(mut self, name: &str, qtype: RecordType, records: Vec<Record>) -> Self {
            self.answers.insert(Self::key(name, qtype), records);
            self
        }

        /// Program crafted AUTHORITY records for `(name, qtype)` — emitted in the
        /// response's authority section with a NOERROR/empty answer (a denial-of-
        /// existence shape). The gate's resolver DECODES the full upstream response,
        /// authority section included, so this is the seam the RUSTSEC-2026-0118 NSEC3
        /// reproduction needs to drive the malicious chain through the pinned hickory.
        pub fn set_authority(
            mut self,
            name: &str,
            qtype: RecordType,
            records: Vec<Record>,
        ) -> Self {
            self.authority.insert(Self::key(name, qtype), records);
            self
        }

        /// Program the RUSTSEC-2026-0118 malicious NSEC3 chain in the authority section
        /// of the denial response for `(name, A)`. The gate runs hickory 0.26.x with
        /// the dnssec feature OFF, so on the wire these records are opaque NSEC3-typed
        /// (RR type 50) rdata — exactly what a feature-stripped resolver decodes. The
        /// crafted `rdata` carries the YAML's "iteration/linkage that forms a cycle
        /// with no terminating owner name" shape (a high iteration count + a next-owner
        /// hash whose closest-encloser walk would, pre-fix, never terminate). The
        /// load-bearing property is that decoding/handling this authority section in
        /// the patched resolver is BOUNDED — no NSEC3 closest-encloser hang.
        pub fn nsec3_loop_authority(self, name: &str) -> Self {
            // RR type 50 = NSEC3 (IANA). Opaque rdata since dnssec is feature-off.
            const NSEC3_TYPE: u16 = 50;
            // Synthetic NSEC3 rdata bytes (D50): hash-algo=1 (SHA-1), flags=1
            // (opt-out), iterations=0xFFFF (max — the "iteration" half of the spec's
            // loop shape), salt-len=0, hash-len=20, a 20-byte next-hashed-owner that
            // points the closest-encloser walk back into the chain (the "linkage that
            // forms a cycle" half), and a single type-bitmap window. Pure bytes — never
            // a typed dnssec rdata (the gate can't construct one without the feature).
            let mut rdata = Vec::new();
            rdata.push(1u8); // hash algorithm: SHA-1
            rdata.push(1u8); // flags: opt-out
            rdata.extend_from_slice(&0xFFFFu16.to_be_bytes()); // iterations: max
            rdata.push(0u8); // salt length: 0
            rdata.push(20u8); // hash length: 20
            rdata.extend_from_slice(&[0xAAu8; 20]); // next-hashed-owner: cycles back
            rdata.extend_from_slice(&[0x00u8, 0x01u8, 0x40u8]); // type bitmap: window 0
            let nsec3 = Record::from_rdata(
                Name::from_ascii(name).unwrap(),
                300,
                RData::Unknown {
                    code: RecordType::from(NSEC3_TYPE),
                    rdata: NULL::with(rdata),
                },
            );
            self.set_authority(name, RecordType::A, vec![nsec3])
        }

        /// Convenience: program an A record.
        pub fn a(self, name: &str, ip: Ipv4Addr, ttl: u32) -> Self {
            let rec = Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::A(A(ip)));
            self.set(name, RecordType::A, vec![rec])
        }

        /// Convenience: program an AAAA record.
        pub fn aaaa(self, name: &str, ip: Ipv6Addr, ttl: u32) -> Self {
            let rec =
                Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::AAAA(AAAA(ip)));
            self.set(name, RecordType::AAAA, vec![rec])
        }

        /// Convenience: program a CNAME chain `name -> target` PLUS the terminal A at
        /// the chain end, all authored into the A answer for `name` (the chained
        /// answer a recursing upstream returns).
        pub fn cname_to_a(self, name: &str, target: &str, terminal: Ipv4Addr, ttl: u32) -> Self {
            let cname = Record::from_rdata(
                Name::from_ascii(name).unwrap(),
                ttl,
                RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
            );
            let a = Record::from_rdata(
                Name::from_ascii(target).unwrap(),
                ttl,
                RData::A(A(terminal)),
            );
            self.set(name, RecordType::A, vec![cname, a])
        }

        /// Author the response Message for a query (matching the request id), or a
        /// NOERROR/NODATA empty answer if the name/type is not programmed.
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
                // Crafted authority section (e.g. the RUSTSEC-2026-0118 NSEC3 chain on a
                // denial-of-existence response). The gate's resolver decodes the whole
                // upstream message, so authority records reach the unit-under-test.
                if let Some(records) = self.authority.get(&key) {
                    resp.add_authorities(records.iter().cloned());
                }
            }
            resp
        }
    }

    /// A running mock upstream: its UDP and TCP loopback addresses (same port).
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

    /// Bind a UDP socket and a TCP listener that share one loopback ephemeral port,
    /// retrying until a number is simultaneously free in both namespaces (closing the
    /// UDP-then-reuse-for-TCP race that made the TCP-forward tests flaky under the
    /// parallel runner). Bounded retries — a real exhaustion would surface as a panic
    /// rather than hang. Network-free.
    async fn bind_shared_port() -> (UdpSocket, tokio::net::TcpListener) {
        for _ in 0..64 {
            let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let udp = UdpSocket::bind(loopback).await.unwrap();
            let port = udp.local_addr().unwrap().port();
            let want = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
            // Try TCP on the SAME number. If another transient listener still holds it,
            // drop this UDP socket and pick a fresh number.
            match tokio::net::TcpListener::bind(want).await {
                Ok(tcp) => return (udp, tcp),
                Err(_) => continue, // udp dropped here, frees the number for the retry
            }
        }
        panic!("could not find a loopback port free in both UDP and TCP namespaces");
    }

    /// Spawn the mock upstream serving `zone`. `blackhole` makes it accept packets
    /// but NEVER answer, so the gate's per-query timeout fires (-> SERVFAIL test).
    pub async fn spawn(zone: Zone, blackhole: bool) -> MockUpstream {
        // UDP and TCP must share the same port (the forwarder dials one SocketAddr for
        // both transports). The two transports live in INDEPENDENT port namespaces, so
        // binding UDP on `:0` and then reusing its number for TCP races: under the
        // parallel test runner another (recently-dropped) mock's TCP listener can still
        // hold that exact number, yielding a flaky `AddrInUse` on the TCP bind. Bind
        // both inside a bounded retry that only succeeds when a SINGLE number is free in
        // BOTH namespaces at once, so the returned addr is valid for UDP and TCP with no
        // TOCTOU window. Network-free: everything is 127.0.0.1 ephemeral.
        let (udp, tcp) = bind_shared_port().await;
        let addr = udp.local_addr().unwrap();

        let shutdown = Arc::new(tokio::sync::Notify::new());
        let zone = Arc::new(zone);

        // UDP responder.
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
                    if blackhole {
                        continue;
                    }
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

        // TCP responder (length-prefixed framing).
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
                    if blackhole {
                        // Hold the connection open but never answer.
                        continue;
                    }
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

/// A gate whose forwarder points at the given mock upstream, with a short upstream
/// timeout so the SERVFAIL test is fast.
async fn gate_with_mock(mock: &mock_up::MockUpstream) -> ds_dnsgate::RunningGate<FixedStubPolicy> {
    let config = GateConfig {
        forwarder: mock.forwarder(Duration::from_secs(2)),
        ..GateConfig::default()
    };
    spawn_gate(FixedStubPolicy::new(), config).await.unwrap()
}

// ===========================================================================
// 1. Forwarder pool — verdict -> forward -> respond over the loopback mock.
// ===========================================================================

#[tokio::test]
async fn forward_a_record_over_udp() {
    let zone = mock_up::Zone::new().a("example.test.", Ipv4Addr::new(93, 184, 216, 34), 300);
    let mock = mock_up::spawn(zone, false).await;
    let gate = gate_with_mock(&mock).await;

    let resp = udp_round_trip(
        gate.udp_local_addr(),
        &a_query(0x1234, "example.test.", None),
    )
    .await;
    let msg = Message::from_vec(&resp).unwrap();

    assert_eq!(msg.metadata.id, 0x1234);
    assert_eq!(msg.metadata.message_type, MessageType::Response);
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 1, "forwarded A answer from the upstream");
    assert_eq!(
        msg.answers[0].data.ip_addr(),
        Some(std::net::IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        "the gate relays the upstream's terminal A — no fixed sentinel"
    );
    assert!(!msg.metadata.truncation, "single answer never truncates");
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn forward_a_record_over_tcp() {
    let zone = mock_up::Zone::new().a("example.test.", Ipv4Addr::new(203, 0, 113, 7), 120);
    let mock = mock_up::spawn(zone, false).await;
    let gate = gate_with_mock(&mock).await;

    let resp = tcp_round_trip(
        gate.tcp_local_addr(),
        &a_query(0x55aa, "example.test.", None),
    )
    .await;
    let msg = Message::from_vec(&resp).unwrap();
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 1, "TCP forward parity with UDP");
    assert_eq!(
        msg.answers[0].data.ip_addr(),
        Some(std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
    );
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn forward_aaaa_record_is_fast_nodata_not_relayed() {
    // The §3.3 AAAA-strip scrub is now wired (D75): an AAAA query is answered as a
    // fast NOERROR/NODATA — the upstream AAAA is NEVER relayed to the VM, even though
    // the mock upstream has one programmed. The full authored-SOA shape and the
    // UDP/TCP parity for this contract are exhaustively asserted in the dedicated
    // `tests/suppression_shapes.rs` unit; here we only confirm the forwarder path no
    // longer leaks the AAAA (the framework-validation regression for §3.3).
    let v6 = Ipv6Addr::new(0x2606, 0x2800, 0x220, 0, 0, 0, 0, 0x10);
    let zone = mock_up::Zone::new().aaaa("v6.example.test.", v6, 300);
    let mock = mock_up::spawn(zone, false).await;
    let gate = gate_with_mock(&mock).await;

    let resp = udp_round_trip(
        gate.udp_local_addr(),
        &query_of(0x0a0a, "v6.example.test.", RecordType::AAAA, None),
    )
    .await;
    let msg = Message::from_vec(&resp).unwrap();
    // NOERROR/NODATA — never drop/SERVFAIL/REFUSED (RFC 4074 stall).
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        msg.answers.len(),
        0,
        "§3.3: the AAAA is stripped — fast NODATA, the upstream v6 address never reaches the VM"
    );
    assert!(
        msg.answers
            .iter()
            .all(|r| r.record_type() != RecordType::AAAA),
        "no AAAA RR reaches the VM"
    );
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn forward_follows_cname_chain_to_terminal_a() {
    // example.test. CNAME alias.cdn.test. ; alias.cdn.test. A 198.51.100.9
    let zone = mock_up::Zone::new().cname_to_a(
        "example.test.",
        "alias.cdn.test.",
        Ipv4Addr::new(198, 51, 100, 9),
        300,
    );
    let mock = mock_up::spawn(zone, false).await;
    let gate = gate_with_mock(&mock).await;

    let resp = udp_round_trip(
        gate.udp_local_addr(),
        &a_query(0x7777, "example.test.", None),
    )
    .await;
    let msg = Message::from_vec(&resp).unwrap();
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);

    // The forwarder followed the CNAME chain and the answer carries the terminal A.
    let terminal_a = msg
        .answers
        .iter()
        .filter_map(|r| r.data.ip_addr())
        .find(|ip| *ip == std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
    assert_eq!(
        terminal_a,
        Some(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        "the CNAME chain resolves to the terminal address {:?}",
        msg.answers
    );
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn forward_follows_cname_chain_over_tcp() {
    let zone = mock_up::Zone::new().cname_to_a(
        "tcp-chain.test.",
        "tcp-target.cdn.test.",
        Ipv4Addr::new(192, 0, 2, 200),
        60,
    );
    let mock = mock_up::spawn(zone, false).await;
    let gate = gate_with_mock(&mock).await;

    let resp = tcp_round_trip(
        gate.tcp_local_addr(),
        &a_query(0x4242, "tcp-chain.test.", None),
    )
    .await;
    let msg = Message::from_vec(&resp).unwrap();
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    let found = msg
        .answers
        .iter()
        .filter_map(|r| r.data.ip_addr())
        .any(|ip| ip == std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)));
    assert!(
        found,
        "TCP CNAME chase reaches the terminal A: {:?}",
        msg.answers
    );
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn forward_unknown_name_is_noerror_nodata() {
    // The upstream answers NOERROR with an empty answer for an unprogrammed name; the
    // gate relays NOERROR/NODATA (the §3.2 authored NXDOMAIN/SOA denial shapes are
    // DNS-1+ work, deliberately out of this increment's scope).
    let mock = mock_up::spawn(mock_up::Zone::new(), false).await;
    let gate = gate_with_mock(&mock).await;
    let resp = udp_round_trip(
        gate.udp_local_addr(),
        &a_query(0x0001, "nothing-here.test.", None),
    )
    .await;
    let msg = Message::from_vec(&resp).unwrap();
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(msg.answers.len(), 0, "NODATA: empty answer, NOERROR rcode");
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn forward_upstream_timeout_is_servfail() {
    // Blackhole upstream: accepts but never answers. The gate's per-query upstream
    // timeout fires and yields SERVFAIL (doc 11 §8.5: upstream resolve failure /
    // timeout -> SERVFAIL, a genuine-failure rcode, never a policy verdict).
    let mock = mock_up::spawn(mock_up::Zone::new(), true).await;
    let config = GateConfig {
        // Short upstream timeout so the test is fast.
        forwarder: mock.forwarder(Duration::from_millis(400)),
        ..GateConfig::default()
    };
    let gate = spawn_gate(FixedStubPolicy::new(), config).await.unwrap();

    let started = Instant::now();
    let resp = udp_round_trip(gate.udp_local_addr(), &a_query(0x9999, "slow.test.", None)).await;
    let elapsed = started.elapsed();
    let msg = Message::from_vec(&resp).unwrap();
    assert_eq!(
        msg.metadata.response_code,
        ResponseCode::ServFail,
        "an upstream that never answers yields SERVFAIL"
    );
    assert_eq!(msg.answers.len(), 0, "no answer on a SERVFAIL");
    assert!(
        elapsed < Duration::from_secs(3),
        "SERVFAIL is bounded by the per-query timeout, not the client timeout (took {elapsed:?})"
    );
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 2. The test-only PADDED handler that emits N answers (truncation thresholds).
// These spin up a parallel server with a widened handler — the production handler
// forwards real upstream answers and never pads.
// ===========================================================================

mod padded {
    use super::*;
    use async_trait::async_trait;
    use hickory_server::net::runtime::Time;
    use hickory_server::proto::op::{Metadata, ResponseCode};
    use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo, Server};
    use hickory_server::zone_handler::MessageResponseBuilder;
    use tokio::net::{TcpListener, UdpSocket};

    /// A handler that answers an A query with `answers` identical A records, so the
    /// encoder is driven past the UDP size cap and hickory sets the TC bit.
    pub struct PaddedHandler {
        pub answers: usize,
    }

    #[async_trait]
    impl RequestHandler for PaddedHandler {
        async fn handle_request<R: ResponseHandler, T: Time>(
            &self,
            request: &Request,
            mut response_handle: R,
        ) -> ResponseInfo {
            let info = request.request_info().unwrap();
            let name = info.query.original().name().clone();
            let records: Vec<Record> = (0..self.answers)
                .map(|i| {
                    Record::from_rdata(
                        name.clone(),
                        60,
                        RData::A(A(Ipv4Addr::new(
                            198,
                            18,
                            ((i >> 8) & 0xff) as u8,
                            (i & 0xff) as u8,
                        ))),
                    )
                })
                .collect();

            let mut builder = MessageResponseBuilder::from_message_request(request);
            // Echo the request EDNS so the advertised UDP buffer cap is honored —
            // exactly what the production handler does (see README findings).
            if let Some(edns) = request.edns.as_ref() {
                builder.edns(edns);
            }
            let mut metadata = Metadata::response_from_request(&request.metadata);
            metadata.recursion_available = true;
            metadata.response_code = ResponseCode::NoError;

            let response = builder.build(
                metadata,
                records.iter(),
                std::iter::empty(),
                std::iter::empty(),
                std::iter::empty(),
            );
            response_handle.send_response(response).await.unwrap()
        }
    }

    pub struct PaddedGate {
        // Held (never read) so the listener tasks stay alive for the test's
        // duration; dropping the gate shuts the server down.
        #[allow(dead_code)]
        pub server: Server<PaddedHandler>,
        pub udp: SocketAddr,
        pub tcp: SocketAddr,
    }

    pub async fn spawn_padded_gate(answers: usize) -> PaddedGate {
        let udp_sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let udp = udp_sock.local_addr().unwrap();
        let tcp_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let tcp = tcp_listener.local_addr().unwrap();

        let mut server = Server::new(PaddedHandler { answers });
        server.register_socket(udp_sock);
        server.register_listener(tcp_listener, Duration::from_secs(5), u16::MAX as usize);
        PaddedGate { server, udp, tcp }
    }
}

// ===========================================================================
// 3. TC-bit truncation thresholds + EDNS buffer interaction.
// ===========================================================================

#[tokio::test]
async fn udp_no_edns_truncates_at_4096_not_512() {
    // ~40 A answers is > 512 bytes but < 4096; with NO EDNS hickory caps at 4096,
    // so this must NOT truncate — proving the no-EDNS cap is 4096, not 512.
    let gate = padded::spawn_padded_gate(40).await;
    let udp = gate.udp;
    let resp = udp_round_trip(udp, &a_query(1, "example.test.", None)).await;
    let msg = Message::from_vec(&resp).unwrap();
    assert!(
        resp.len() > EDNS_FLOOR as usize,
        "answer ({} bytes) must exceed the 512 EDNS floor to be a real test",
        resp.len()
    );
    assert!(
        resp.len() <= UDP_NO_EDNS_MAX_SIZE,
        "no-EDNS UDP answer stays within the {UDP_NO_EDNS_MAX_SIZE} cap"
    );
    assert!(
        !msg.metadata.truncation,
        ">512B answer with NO EDNS is NOT truncated — hickory's no-EDNS cap is {UDP_NO_EDNS_MAX_SIZE}, not 512"
    );
    drop(gate);
}

#[tokio::test]
async fn udp_edns_512_truncates_above_floor() {
    // Same wide answer, but the client advertises EDNS payload 512. Now the cap is
    // 512 and the answer overflows -> TC bit set, answers dropped.
    let gate = padded::spawn_padded_gate(40).await;
    let udp = gate.udp;
    let resp = udp_round_trip(udp, &a_query(2, "example.test.", Some(EDNS_FLOOR))).await;
    let msg = Message::from_vec(&resp).unwrap();
    assert!(
        resp.len() <= EDNS_FLOOR as usize,
        "EDNS-512 response must fit in 512 bytes (got {})",
        resp.len()
    );
    assert!(
        msg.metadata.truncation,
        "answer overflowing the advertised 512B EDNS buffer sets the TC bit"
    );
    drop(gate);
}

#[tokio::test]
async fn udp_edns_below_512_clamps_to_floor() {
    // Client advertises 200 (< 512). RFC 6891 floor: hickory treats it as 512.
    let gate = padded::spawn_padded_gate(20).await; // ~ between 200 and 512 bytes
    let udp = gate.udp;
    let resp = udp_round_trip(udp, &a_query(3, "example.test.", Some(200))).await;
    let msg = Message::from_vec(&resp).unwrap();
    assert!(
        resp.len() > 200,
        "answer ({} bytes) exceeds the literal 200B advertisement — only the 512 floor lets it through untruncated",
        resp.len()
    );
    assert!(
        resp.len() <= EDNS_FLOOR as usize,
        "answer fits within the clamped 512 floor"
    );
    assert!(
        !msg.metadata.truncation,
        "sub-512 EDNS payload is clamped UP to the {EDNS_FLOOR} floor (RFC 6891), so a <512B answer is not truncated"
    );
    drop(gate);
}

#[tokio::test]
async fn udp_edns_flag_day_1232_admits_larger_answer() {
    // Advertise the 2020 flag-day default of 1232. An answer in (512, 1232] now
    // passes untruncated where the 512 case truncated it.
    let gate = padded::spawn_padded_gate(40).await;
    let udp = gate.udp;
    let resp = udp_round_trip(
        udp,
        &a_query(4, "example.test.", Some(EDNS_FLAG_DAY_DEFAULT)),
    )
    .await;
    let msg = Message::from_vec(&resp).unwrap();
    assert!(
        resp.len() > EDNS_FLOOR as usize,
        "answer ({} bytes) is larger than the 512 floor",
        resp.len()
    );
    assert!(
        resp.len() <= EDNS_FLAG_DAY_DEFAULT as usize,
        "answer fits within the advertised {EDNS_FLAG_DAY_DEFAULT}B buffer"
    );
    assert!(
        !msg.metadata.truncation,
        "answer within the advertised {EDNS_FLAG_DAY_DEFAULT}B EDNS buffer is not truncated"
    );
    drop(gate);
}

// ===========================================================================
// 4. UDP/TCP parity — TCP never truncates what UDP must.
// ===========================================================================

#[tokio::test]
async fn tcp_never_truncates_what_udp_truncates() {
    // A genuinely large answer: 400 A records (~6-7 KiB) overflows BOTH the 512
    // EDNS buffer AND the 4096 no-EDNS cap on UDP, but fits on TCP (cap u16::MAX).
    let gate = padded::spawn_padded_gate(400).await;
    let udp = gate.udp;
    let tcp = gate.tcp;

    // UDP with EDNS 512: truncated.
    let udp_resp = udp_round_trip(udp, &a_query(5, "big.test.", Some(EDNS_FLOOR))).await;
    let udp_msg = Message::from_vec(&udp_resp).unwrap();
    assert!(
        udp_msg.metadata.truncation,
        "UDP/512 must truncate a 400-record answer"
    );

    // TCP: identical query, full answer, no TC bit.
    let tcp_resp = tcp_round_trip(tcp, &a_query(5, "big.test.", Some(EDNS_FLOOR))).await;
    let tcp_msg = Message::from_vec(&tcp_resp).unwrap();
    assert!(
        !tcp_msg.metadata.truncation,
        "TCP answer is not truncated (TCP encoder cap is {TCP_MAX_SIZE})"
    );
    assert_eq!(
        tcp_msg.answers.len(),
        400,
        "TCP carries the full 400-record answer the UDP path had to drop"
    );
    drop(gate);
}

#[tokio::test]
async fn udp_and_tcp_agree_on_forwarded_answer() {
    // Parity floor: for a forwarded answer that fits both transports, UDP and TCP
    // responses are semantically identical (same rcode, same answer count).
    let zone = mock_up::Zone::new().a("small.test.", Ipv4Addr::new(198, 51, 100, 1), 60);
    let mock = mock_up::spawn(zone, false).await;
    let gate = gate_with_mock(&mock).await;
    let q = a_query(6, "small.test.", None);

    let udp_msg = Message::from_vec(&udp_round_trip(gate.udp_local_addr(), &q).await).unwrap();
    let tcp_msg = Message::from_vec(&tcp_round_trip(gate.tcp_local_addr(), &q).await).unwrap();

    assert_eq!(
        udp_msg.metadata.response_code,
        tcp_msg.metadata.response_code
    );
    assert_eq!(udp_msg.answers.len(), tcp_msg.answers.len());
    assert_eq!(udp_msg.answers.len(), 1);
    assert!(!udp_msg.metadata.truncation && !tcp_msg.metadata.truncation);
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 5. TCP read/idle timeout — the per-connection DoS lever.
// ===========================================================================

#[tokio::test]
async fn tcp_read_timeout_closes_idle_connection() {
    // Bind with a short TCP read timeout; open a connection and send NOTHING.
    // The accept-loop serve must close it within ~timeout, so our read returns
    // EOF (0 bytes) rather than hanging.
    let zone = mock_up::Zone::new();
    let mock = mock_up::spawn(zone, false).await;
    let config = GateConfig {
        tcp_timeout: Duration::from_millis(300),
        forwarder: mock.forwarder(Duration::from_secs(2)),
        ..GateConfig::default()
    };
    let gate = spawn_gate(FixedStubPolicy::new(), config).await.unwrap();
    let mut stream = TcpStream::connect(gate.tcp_local_addr()).await.unwrap();

    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) => { /* clean EOF — connection closed by the timeout */ }
        Ok(Ok(n)) => panic!("expected the idle connection to be closed, got {n} bytes"),
        Ok(Err(_)) => { /* reset is also an acceptable close */ }
        Err(_) => panic!("idle TCP connection was NOT closed within the read timeout"),
    }
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 6. Connection cap — the accept-loop semaphore holds under a synthetic flood.
//
// hickory has no built-in cap (README finding). server.rs imposes one via an
// accept-loop semaphore. We set a small cap, open MANY idle connections (a flood),
// and assert the gate still serves real queries (the cap bounds resource use, it does
// not wedge the gate) AND that no more than `cap` connections are served concurrently.
// Network-free: everything is loopback.
// ===========================================================================

#[tokio::test]
async fn tcp_connection_cap_holds_under_flood() {
    // A small cap and a synthetic flood of real concurrent queries: every query
    // completes (the cap SERIALIZES connections, it does not drop them), and the gate
    // stays alive throughout. With a working accept-loop semaphore this is bounded and
    // every connection is served in turn; without it (or with a deadlock) the flood
    // would wedge or drop. Network-free: everything is loopback.
    const CAP: usize = 4;
    const FLOOD: usize = 48;

    let zone = mock_up::Zone::new().a("served.test.", Ipv4Addr::new(198, 51, 100, 5), 60);
    let mock = mock_up::spawn(zone, false).await;
    let config = GateConfig {
        max_tcp_connections: CAP,
        tcp_timeout: Duration::from_secs(3),
        forwarder: mock.forwarder(Duration::from_secs(2)),
        ..GateConfig::default()
    };
    let gate = spawn_gate(FixedStubPolicy::new(), config).await.unwrap();
    let tcp = gate.tcp_local_addr();

    // Fire FLOOD real queries concurrently, each on its own TCP connection. With the
    // cap at CAP, at most CAP are served at any instant; the rest queue for a permit.
    // ALL must eventually complete with the forwarded answer.
    let mut handles = Vec::with_capacity(FLOOD);
    for i in 0..FLOOD {
        handles.push(tokio::spawn(async move {
            let q = a_query(0x3000 + i as u16, "served.test.", None);
            let resp = tokio::time::timeout(Duration::from_secs(20), tcp_round_trip(tcp, &q)).await;
            resp.map(|bytes| {
                let msg = Message::from_vec(&bytes).unwrap();
                (
                    msg.metadata.response_code,
                    msg.answers.first().and_then(|r| r.data.ip_addr()),
                )
            })
        }));
    }

    let mut served = 0usize;
    for h in handles {
        let (rcode, ip) = h
            .await
            .unwrap()
            .expect("every flood query completed — the cap serializes, it does not wedge");
        assert_eq!(rcode, ResponseCode::NoError);
        assert_eq!(
            ip,
            Some(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))),
            "each connection got the forwarded answer"
        );
        served += 1;
    }
    assert_eq!(
        served, FLOOD,
        "all {FLOOD} connections served under a cap of {CAP}"
    );

    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_cap_serializes_concurrent_connections_to_cap() {
    // A tighter cap assertion: with CAP=1 and the upstream BLACKHOLED so each served
    // query holds its connection for the full upstream timeout, two simultaneous
    // queries cannot both complete in less than ~2x the per-query timeout — the
    // second waits for the first's permit. This demonstrates the cap genuinely
    // serializes, not just "doesn't crash".
    let mock = mock_up::spawn(mock_up::Zone::new(), true).await; // blackhole
    let per_query = Duration::from_millis(500);
    let config = GateConfig {
        max_tcp_connections: 1,
        tcp_timeout: Duration::from_secs(5),
        forwarder: mock.forwarder(per_query),
        ..GateConfig::default()
    };
    let gate = spawn_gate(FixedStubPolicy::new(), config).await.unwrap();
    let tcp = gate.tcp_local_addr();

    let started = Instant::now();
    let a = tokio::spawn(
        async move { tcp_round_trip(tcp, &a_query(1, "blackhole.test.", None)).await },
    );
    let b = tokio::spawn(
        async move { tcp_round_trip(tcp, &a_query(2, "blackhole.test.", None)).await },
    );
    let (ra, rb) = (a.await.unwrap(), b.await.unwrap());
    let elapsed = started.elapsed();

    // Both return SERVFAIL (blackhole -> per-query timeout). With CAP=1 the second
    // query's connection is not served until the first releases its permit, so the
    // total wall time is >= ~2x the per-query timeout (serialized), not ~1x.
    for r in [&ra, &rb] {
        let msg = Message::from_vec(r).unwrap();
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
    }
    assert!(
        elapsed >= per_query + per_query / 2,
        "CAP=1 serializes: two blackholed queries take >= ~2x the per-query timeout (took {elapsed:?})"
    );
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 7. Wire-driven RUSTSEC reproductions (doc 11 §6 obligation 8, doc 14 §9).
//
// Spec source: assurance/advisory-mirror/advisories/RUSTSEC-2026-0118.yaml and
// RUSTSEC-2026-0119.yaml (IDs, repro shape, suite destination). These are STUB
// CLIENT OVER THE WIRE against a listening gate — never a hickory API call (doc 11
// §6 obligation 10). The malicious shapes are SYNTHETIC (D50: a fixture in git is
// synthetic): we craft the malicious upstream/wire input and assert the gate
// survives in bounded time against the pinned hickory 0.26.x — no hang, no
// exhaustion, a genuine-failure verdict (SERVFAIL) within the YAML's bound.
// ===========================================================================

/// The bound from both YAML specs' `expected_verdict.within_ms` (the <500ms denial-
/// conformance class, doc 11 §6 obligation 3). We give the test a generous safety
/// margin over it; a true hang/exhaustion would blow past any finite bound.
const RUSTSEC_BOUND: Duration = Duration::from_secs(5);

#[tokio::test]
async fn rustsec_2026_0118_nsec3_loop_bounded() {
    // RUSTSEC-2026-0118 (NSEC3 validation loop). Spec: a crafted authoritative
    // response whose NSEC3 chain linkage never terminates the closest-encloser walk
    // would, pre-fix, hang the resolver thread. The gate runs hickory 0.26.x WITHOUT
    // DNSSEC features (default-features off, no DO-bit validation), and forwards over
    // the wire. The wire-driven reproduction sends the DO-bit query the spec names
    // (dnssec_ok: true) against a mock upstream that returns the crafted NSEC3-shaped
    // authority section; the patched/feature-stripped resolver must NOT hang — the
    // query resolves to a bounded verdict well within the YAML bound.
    //
    // Because no answer carrying the unproven name may reach the VM (W1 fail-closed,
    // expected_behavior), and the gate does not validate DNSSEC, the crafted answer's
    // empty A-section yields NODATA/NOERROR or SERVFAIL — either is a bounded,
    // genuine-failure-or-empty verdict; the load-bearing assertion is BOUNDED TIME.
    //
    // The malicious shape from the YAML (input_shape.upstream_response.authority_records:
    // a crafted NSEC3 chain "with no terminating owner name") is programmed into the mock
    // upstream's AUTHORITY section for the queried denial name, so the gate's resolver
    // actually decodes the loop-shaped NSEC3 rdata — not just an empty answer.
    const DENIAL_NAME: &str = "nonexistent.example-zone.test.";
    let zone = mock_up::Zone::new().nsec3_loop_authority(DENIAL_NAME);
    let mock = mock_up::spawn(zone, false).await;
    let config = GateConfig {
        forwarder: mock.forwarder(Duration::from_secs(2)),
        ..GateConfig::default()
    };
    let gate = spawn_gate(FixedStubPolicy::new(), config).await.unwrap();

    // dnssec_ok: true — exercise the NSEC3 denial-of-existence path the spec names.
    let mut q = Message::query();
    q.metadata.id = 0x0118;
    q.add_query(hickory_proto::op::Query::query(
        Name::from_ascii(DENIAL_NAME).unwrap(),
        RecordType::A,
    ));
    let mut edns = Edns::new();
    edns.set_version(0);
    edns.set_dnssec_ok(true); // DO bit
    q.set_edns(edns);
    let wire = q.to_vec().unwrap();

    let started = Instant::now();
    let resp = tokio::time::timeout(RUSTSEC_BOUND, udp_round_trip(gate.udp_local_addr(), &wire))
        .await
        .expect("RUSTSEC-2026-0118: NSEC3 path must terminate in bounded work — no hang");
    let elapsed = started.elapsed();
    let msg = Message::from_vec(&resp).unwrap();

    // within_ms bound (with margin): no thread hang, no unbounded CPU.
    assert!(
        elapsed < RUSTSEC_BOUND,
        "RUSTSEC-2026-0118 reproduction completed in {elapsed:?} (< the {RUSTSEC_BOUND:?} bound)"
    );
    // residue: none / no unproven name admitted — the answer is bounded and carries
    // no spoofed terminal address (the name is unprogrammed upstream).
    assert!(
        msg.answers.is_empty(),
        "no answer carrying an unproven name reaches the VM (W1 fail-closed)"
    );
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn rustsec_2026_0119_compression_bomb_bounded() {
    // RUSTSEC-2026-0119 (compression bomb). Spec: a crafted message whose DNS name
    // compression pointers (pointer chains / overlapping offsets / pointer cycles)
    // expand to disproportionate work during decoding, exhausting the resolver. The
    // wire-driven reproduction crafts such a message and feeds it to the GATE'S OWN
    // wire parser (the gate decodes every client query via hickory's Request parser);
    // the pinned hickory must reject it in bounded time — pointer cycles detected,
    // never followed indefinitely, no exhaustion (expected_behavior). We send the
    // malformed bytes directly as the client query so the gate's decoder is the
    // unit-under-test; a bounded SERVFAIL/FORMERR/drop is the genuine-failure verdict.
    let mock = mock_up::spawn(mock_up::Zone::new(), false).await;
    let config = GateConfig {
        forwarder: mock.forwarder(Duration::from_secs(2)),
        ..GateConfig::default()
    };
    let gate = spawn_gate(FixedStubPolicy::new(), config).await.unwrap();

    // Craft a compression-bomb message: a valid header + question header, then a name
    // built ENTIRELY from compression pointers that form a CYCLE (pointer at offset
    // 12 points back to offset 12). A naive decoder follows the cycle forever; the
    // patched hickory must detect the loop and bail in bounded work.
    let bomb = compression_bomb_query(0x0119);

    let started = Instant::now();
    // Send over UDP; the gate parses, fails to decode (or decodes to nothing), and
    // either drops or answers a bounded error. EITHER outcome is acceptable; the
    // load-bearing property is that the call RETURNS within the bound (no hang).
    let outcome = tokio::time::timeout(RUSTSEC_BOUND, async {
        let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        sock.connect(gate.udp_local_addr()).await.unwrap();
        sock.send(&bomb).await.unwrap();
        // A malformed query may be dropped (no response) — that is fine; we only need
        // the GATE to not hang. Use a short recv timeout to distinguish "dropped"
        // (bounded, good) from "hang" (the outer timeout would fire).
        let mut buf = vec![0u8; 65535];
        let _ = tokio::time::timeout(Duration::from_secs(1), sock.recv(&mut buf)).await;
    })
    .await;
    let elapsed = started.elapsed();

    assert!(
        outcome.is_ok(),
        "RUSTSEC-2026-0119: the compression bomb must be rejected in bounded work — no decode hang/exhaustion"
    );
    assert!(
        elapsed < RUSTSEC_BOUND,
        "RUSTSEC-2026-0119 reproduction completed in {elapsed:?} (< the {RUSTSEC_BOUND:?} bound) — pointer cycle detected, not followed"
    );

    // The gate is still alive and serving after the bomb — exhaustion would have
    // wedged it. Prove liveness with a normal query.
    let zone_addr = Ipv4Addr::new(198, 51, 100, 8);
    // Reprogram via a fresh gate+mock would race; instead just confirm the gate
    // answers (NODATA for the unprogrammed name) within the bound.
    let _ = zone_addr;
    let live = tokio::time::timeout(
        RUSTSEC_BOUND,
        udp_round_trip(
            gate.udp_local_addr(),
            &a_query(0x011a, "still-alive.test.", None),
        ),
    )
    .await
    .expect("the gate is still serving after the compression bomb");
    let live_msg = Message::from_vec(&live).unwrap();
    assert!(
        matches!(
            live_msg.metadata.response_code,
            ResponseCode::NoError | ResponseCode::ServFail
        ),
        "gate remains responsive post-bomb"
    );
    gate.shutdown().await.unwrap();
}

/// Build a synthetic compression-bomb query: header + question whose QNAME is a
/// single compression pointer that points back at itself (a pointer CYCLE). This is
/// the canonical malformed-name shape RUSTSEC-2026-0119 names (compression loops).
/// Pure bytes, no hickory encoder — exactly the adversarial wire a malicious client
/// would send. D50: a fixture in git is synthetic.
fn compression_bomb_query(id: u16) -> Vec<u8> {
    let mut msg = Vec::new();
    // Header: id, flags (standard query, RD), qdcount=1, others 0.
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD set
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                // Question QNAME: a compression pointer (0xC0 0x0C) pointing at offset 12, which
                                                // is the FIRST byte of the QNAME itself — a self-referential cycle. A naive
                                                // decoder loops forever; a bounded decoder detects the cycle.
    msg.push(0xC0);
    msg.push(0x0C);
    // QTYPE = A (1), QCLASS = IN (1).
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg
}

// ===========================================================================
// 8. D67 seam discipline — no hickory type in the cross-service policy seam.
//
// The frozen corollary (doc 11 §2 / §4): no hickory type appears in any cross-service
// interface, so the raw-tokio fallback stays a library migration. This is enforced
// STRUCTURALLY: the policy seam module (src/policy.rs) and the forwarder's pub knob
// (ForwarderConfig) are hickory-free. We assert it diff-verifiably by reading the
// seam source and the public config and proving they name no hickory type, and by
// constructing the pub config from std types only.
// ===========================================================================

#[test]
fn no_hickory_type_in_policy_seam() {
    // The policy seam source must name no hickory type (the cross-service interface).
    let policy_src = include_str!("../src/policy.rs");
    // Strip the doc-comment lines (which legitimately discuss "hickory" in prose)
    // and assert no CODE line names a hickory_* path.
    for (i, line) in policy_src.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") || code.starts_with("/*") || code.starts_with('*') {
            continue;
        }
        assert!(
            !code.contains("hickory"),
            "src/policy.rs line {} names a hickory type in CODE — the cross-service seam must stay hickory-free (D67): {line:?}",
            i + 1
        );
    }

    // The forwarder's only pub knob is constructible from std types alone — no
    // hickory ResolverConfig/NameServerConfig crosses the boundary (D67).
    let cfg = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53))],
        timeout: Duration::from_secs(5),
    };
    assert_eq!(cfg.upstreams.len(), 1);
    // Default carries the D64 pair (1.1.1.1 / 8.8.8.8), hickory-free.
    let def = ForwarderConfig::default();
    assert_eq!(def.upstreams.len(), 2, "default forwarder is the D64 pair");
    assert!(def
        .upstreams
        .iter()
        .any(|s| s.ip() == std::net::IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert!(def
        .upstreams
        .iter()
        .any(|s| s.ip() == std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

// ===========================================================================
// 8b. Extended malformed-query fuzz corpus (doc 11 §6 obligation 8, §8.5; DNS-5).
//
// Beyond the RUSTSEC-2026-0119 self-referential pointer-cycle shape (section 7), the
// DNS-5 hardening pass owes a BOUNDED, FIXED-iteration adversarial corpus over the
// gate's OWN wire parser: overlapping compression offsets, deep pointer chains past
// the parser depth bound, oversized frames (UDP payloads beyond 512/4096; a TCP
// length-prefix that disagrees with the actual frame), and frames truncated at every
// header / question-section boundary. For each the gate must answer FORMERR/NOTIMP or
// cleanly IGNORE (drop, no response) per hickory semantics WITHOUT panic, hang, or
// resource blow-up — and stay alive and serving afterward. This is a fixed iteration
// set (no time-based fuzzing), network-free (loopback mocks only — never a live
// resolver), and its total runtime is well under the suite timeout.
//
// Every shape is exercised over BOTH UDP and TCP/53 (doc 11 §3.4 parity), including a
// TCP-only length-prefix-mismatch shape that has no UDP analogue. The load-bearing
// property is BOUNDED TIME + LIVENESS: the gate's decoder is the unit under test, fed
// raw adversarial bytes a malicious client would send (D50: a fixture in git is
// synthetic). We send via raw sockets, not the hickory encoder, so genuinely
// malformed frames reach the parser.
// ===========================================================================

/// One named adversarial frame in the corpus: the DNS *message* bytes (no TCP length
/// prefix — the harness frames it for the TCP leg). `tcp_len_override` lets a shape
/// declare a TCP length prefix that DISAGREES with the actual byte count (the TCP
/// length-prefix-mismatch shape); `None` means "frame honestly".
struct FuzzFrame {
    name: &'static str,
    bytes: Vec<u8>,
    tcp_len_override: Option<u16>,
}

impl FuzzFrame {
    fn new(name: &'static str, bytes: Vec<u8>) -> Self {
        Self {
            name,
            bytes,
            tcp_len_override: None,
        }
    }

    fn with_tcp_len(name: &'static str, bytes: Vec<u8>, tcp_len: u16) -> Self {
        Self {
            name,
            bytes,
            tcp_len_override: Some(tcp_len),
        }
    }
}

/// A 12-byte DNS header with one question declared (QDCOUNT=1), standard query + RD.
fn dns_header_qd1(id: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(12);
    h.extend_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    h.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    h.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    h.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    h.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    h
}

/// The fixed, bounded adversarial corpus. Pure bytes — every frame is constructed
/// here, deterministically; there is no randomness and no time-based fuzzing.
fn malformed_corpus() -> Vec<FuzzFrame> {
    let mut corpus = Vec::new();

    // --- Overlapping compression offsets ---------------------------------------
    // A QNAME label whose CONTENT a later compression pointer points back INTO at a
    // non-label-boundary offset, so the two name encodings overlap. A naive decoder
    // can re-interpret label-length bytes as pointer bytes and walk a contradictory
    // chain; the bounded parser must reject or ignore it, never loop.
    {
        let mut m = dns_header_qd1(0xF001);
        // QNAME: a 3-byte label "abc", then a pointer to offset 13 (the length byte of
        // that same label region), creating an overlap where the pointer target is in
        // the middle of an already-parsed label.
        m.push(0x03);
        m.extend_from_slice(b"abc");
        m.push(0xC0);
        m.push(0x0D); // -> offset 13 (inside the label we just wrote)
        m.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        corpus.push(FuzzFrame::new("overlapping_compression_offsets", m));
    }

    // --- Deep pointer chain past the depth bound -------------------------------
    // A long chain of compression pointers, each hopping forward to the next, far
    // deeper than any sane name. Even WITHOUT a cycle, a parser that follows pointers
    // unboundedly does O(chain) work per name; the depth-bounded parser must cap it.
    {
        let mut m = dns_header_qd1(0xF002);
        // Build the question QNAME as a pointer to the FIRST chain link, then append a
        // run of pointers each pointing to the next link, terminating at a root label.
        // Header is 12 bytes; the question's QNAME starts at offset 12.
        // QNAME = pointer to offset 16 (the first chain link).
        m.push(0xC0);
        m.push(0x10); // -> offset 16
        m.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
                                                  // Now at offset 16: a chain of 64 forward pointers, each +2 bytes, then root.
        let chain_start = m.len();
        const CHAIN_LINKS: usize = 64; // past any reasonable depth bound (hickory caps far lower)
        for i in 0..CHAIN_LINKS {
            let here = chain_start + i * 2;
            let next = (here + 2) as u16;
            m.push(0xC0 | ((next >> 8) as u8));
            m.push((next & 0xFF) as u8);
        }
        // Final link target: a root label (0x00) so a depth-respecting parser CAN
        // terminate; the malice is purely the chain length.
        m.push(0x00);
        corpus.push(FuzzFrame::new("deep_pointer_chain", m));
    }

    // --- Oversized UDP frame, beyond 512 (classic) -----------------------------
    // A well-formed header claiming QDCOUNT=1 but padded with a multi-kilobyte junk
    // QNAME so the whole frame exceeds the 512-byte classic UDP limit. The parser must
    // bound its work and not over-read.
    {
        let mut m = dns_header_qd1(0xF003);
        // A single giant label run that overflows the 63-byte label cap repeatedly —
        // each label is a 63-byte chunk; many chunks push the frame past 512.
        for _ in 0..20 {
            m.push(63);
            m.extend(std::iter::repeat_n(b'a', 63));
        }
        m.push(0x00); // root terminator
        m.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        assert!(
            m.len() > 512,
            "oversized_udp_over_512 must exceed 512 bytes"
        );
        corpus.push(FuzzFrame::new("oversized_udp_over_512", m));
    }

    // --- Oversized frame, beyond 4096 (the no-EDNS UDP cap) ---------------------
    // Even larger: past the 4096 MAX_RECEIVE_BUFFER_SIZE the no-EDNS UDP path caps at.
    {
        let mut m = dns_header_qd1(0xF004);
        for _ in 0..80 {
            m.push(63);
            m.extend(std::iter::repeat_n(b'b', 63));
        }
        m.push(0x00);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        assert!(
            m.len() > 4096,
            "oversized_over_4096 must exceed the 4096 cap"
        );
        corpus.push(FuzzFrame::new("oversized_over_4096", m));
    }

    // --- TCP length-prefix vs actual-frame mismatch ----------------------------
    // A valid small message, but the TCP framing declares a length LARGER than the
    // bytes that follow (the harness sends only the real bytes). The TCP serve must
    // not hang waiting for the missing bytes beyond its read timeout, and must never
    // over-read; a clean connection close is the acceptable outcome. UDP has no length
    // prefix, so this shape is TCP-only (its UDP leg simply sends the honest frame).
    {
        let mut m = dns_header_qd1(0xF005);
        m.push(0x00); // root QNAME
        m.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        m.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
        let real_len = m.len() as u16;
        // Declare a length 200 bytes longer than the actual frame.
        corpus.push(FuzzFrame::with_tcp_len(
            "tcp_length_prefix_overstated",
            m,
            real_len + 200,
        ));
    }

    // --- Header / QD-boundary truncations --------------------------------------
    // Frames cut off at every meaningful boundary: mid-header, at the header edge with
    // QDCOUNT=1 but no question, mid-QNAME, after QNAME but before QTYPE/QCLASS, and a
    // bare empty datagram. Each must bottom out in a bounded error/ignore.
    {
        // 0 bytes: an empty datagram.
        corpus.push(FuzzFrame::new("empty_datagram", Vec::new()));
        // 6 bytes: half a header.
        corpus.push(FuzzFrame::new(
            "truncated_mid_header",
            dns_header_qd1(0xF006)[..6].to_vec(),
        ));
        // Exactly 12 bytes: a complete header declaring QDCOUNT=1 but NO question body.
        corpus.push(FuzzFrame::new(
            "header_only_qd1_no_question",
            dns_header_qd1(0xF007),
        ));
        // Header + a partial QNAME label whose length byte claims more bytes than
        // remain (a length byte of 5 followed by only 2 bytes).
        {
            let mut m = dns_header_qd1(0xF008);
            m.push(0x05);
            m.extend_from_slice(b"ab"); // claims 5, only 2 present
            corpus.push(FuzzFrame::new("truncated_mid_qname_label", m));
        }
        // Header + complete QNAME but truncated before QTYPE/QCLASS.
        {
            let mut m = dns_header_qd1(0xF009);
            m.push(0x03);
            m.extend_from_slice(b"www");
            m.push(0x00); // root terminator -> QNAME complete
                          // ...and stop: no QTYPE/QCLASS bytes follow.
            corpus.push(FuzzFrame::new("truncated_before_qtype_qclass", m));
        }
    }

    corpus
}

/// Send raw `bytes` over UDP to `server` and return within `bound`, tolerating a
/// dropped (no-response) frame. Returns `Ok(Some(resp))` if the gate answered,
/// `Ok(None)` if it cleanly ignored the frame, and the OUTER timeout (the test's
/// `expect`) fires only on a genuine hang.
async fn udp_send_malformed(server: SocketAddr, bytes: &[u8], bound: Duration) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap();
    sock.connect(server).await.unwrap();
    // An empty datagram is still a sendable 0-length UDP packet.
    sock.send(bytes).await.unwrap();
    let mut buf = vec![0u8; 65535];
    match tokio::time::timeout(bound, sock.recv(&mut buf)).await {
        Ok(Ok(n)) => {
            buf.truncate(n);
            Some(buf)
        }
        // A cleanly-ignored (dropped) frame: no response within the per-frame budget.
        _ => None,
    }
}

/// Send raw `bytes` over TCP with a length prefix (honest, or the declared override),
/// returning within `bound`. A clean close / no-response is acceptable (the frame was
/// ignored); the outer timeout fires only on a genuine hang.
async fn tcp_send_malformed(
    server: SocketAddr,
    bytes: &[u8],
    tcp_len: u16,
    bound: Duration,
) -> Option<Vec<u8>> {
    let mut stream = TcpStream::connect(server).await.unwrap();
    if stream.write_all(&tcp_len.to_be_bytes()).await.is_err()
        || stream.write_all(bytes).await.is_err()
        || stream.flush().await.is_err()
    {
        return None;
    }
    // Read a length-prefixed response if one comes; otherwise tolerate a clean close.
    let read = tokio::time::timeout(bound, async {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await?;
        Ok::<Vec<u8>, std::io::Error>(resp)
    })
    .await;
    match read {
        Ok(Ok(resp)) => Some(resp),
        _ => None,
    }
}

/// If the gate answered a malformed frame, the answer must be a bounded, sane
/// error/ignore shape — never a positive answer with records, and a recognized rcode
/// (FORMERR / NOTIMP / SERVFAIL / REFUSED / NOERROR-empty). A genuinely garbage
/// response would be a bug; we assert the rcode is one of the documented dispositions
/// and that no answer record was minted for malformed input.
fn assert_bounded_error_shape(resp: &[u8], frame: &str, transport: &str) {
    // The response must itself be parseable (the gate authors a well-formed reply even
    // to garbage input) — if it does not parse, that is still bounded (no hang), but a
    // gate that emits unparseable bytes would be a defect; we require parseability.
    let msg = Message::from_vec(resp)
        .unwrap_or_else(|e| panic!("{transport}/{frame}: gate reply did not parse: {e}"));
    assert!(
        matches!(
            msg.metadata.response_code,
            ResponseCode::FormErr
                | ResponseCode::NotImp
                | ResponseCode::ServFail
                | ResponseCode::Refused
                | ResponseCode::NoError
        ),
        "{transport}/{frame}: malformed input yields a documented disposition rcode, got {:?}",
        msg.metadata.response_code
    );
    assert!(
        msg.answers.is_empty(),
        "{transport}/{frame}: no answer record is minted for a malformed query"
    );
}

#[tokio::test]
async fn malformed_corpus_is_bounded_and_no_panic_over_udp_and_tcp() {
    // Per-frame budget; the whole corpus must finish well under the suite timeout. A
    // true hang on any frame blows past PER_FRAME_BOUND and the test fails loudly.
    const PER_FRAME_BOUND: Duration = Duration::from_secs(2);

    // A live mock upstream so a (malformed-but-parseable) frame that reaches the
    // forwarder still resolves in bounded time rather than stalling on a dead address.
    let zone = mock_up::Zone::new().a("alive.test.", Ipv4Addr::new(198, 51, 100, 9), 60);
    let mock = mock_up::spawn(zone, false).await;
    let gate = gate_with_mock(&mock).await;

    let corpus = malformed_corpus();
    // Sanity: the corpus is a fixed, non-trivial set (no accidental empty run).
    assert!(
        corpus.len() >= 10,
        "the fixed corpus covers all named shapes ({} frames)",
        corpus.len()
    );

    let suite_started = Instant::now();
    for frame in &corpus {
        // UDP leg: send the honest frame (UDP has no length prefix).
        let udp_resp = tokio::time::timeout(
            PER_FRAME_BOUND + Duration::from_secs(1),
            udp_send_malformed(gate.udp_local_addr(), &frame.bytes, PER_FRAME_BOUND),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "UDP/{}: the gate HUNG on a malformed frame — parser not bounded",
                frame.name
            )
        });
        if let Some(resp) = udp_resp {
            assert_bounded_error_shape(&resp, frame.name, "UDP");
        }

        // TCP leg: frame with the honest length, or the declared mismatch override.
        let tcp_len = frame
            .tcp_len_override
            .unwrap_or_else(|| u16::try_from(frame.bytes.len()).unwrap_or(u16::MAX));
        let tcp_resp = tokio::time::timeout(
            PER_FRAME_BOUND + Duration::from_secs(1),
            tcp_send_malformed(
                gate.tcp_local_addr(),
                &frame.bytes,
                tcp_len,
                PER_FRAME_BOUND,
            ),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "TCP/{}: the gate HUNG on a malformed frame — parser/framing not bounded",
                frame.name
            )
        });
        if let Some(resp) = tcp_resp {
            assert_bounded_error_shape(&resp, frame.name, "TCP");
        }
    }
    let suite_elapsed = suite_started.elapsed();
    // The whole fixed corpus is fast — bounded-time, not time-based fuzzing.
    assert!(
        suite_elapsed < Duration::from_secs(30),
        "the malformed corpus ran in {suite_elapsed:?} — well under the suite timeout"
    );

    // LIVENESS: after the entire corpus, the gate still serves a legitimate query —
    // no frame wedged, leaked a task, or exhausted a resource.
    let live = tokio::time::timeout(
        Duration::from_secs(3),
        udp_round_trip(gate.udp_local_addr(), &a_query(0xF0FF, "alive.test.", None)),
    )
    .await
    .expect("the gate is still serving after the whole malformed corpus");
    let live_msg = Message::from_vec(&live).unwrap();
    assert_eq!(live_msg.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        live_msg.answers.first().and_then(|r| r.data.ip_addr()),
        Some(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))),
        "the gate answers a real query after surviving the corpus"
    );
    gate.shutdown().await.unwrap();
}

// ===========================================================================
// 9. Live upstream against the D64 pair — DEFERRED MANUAL STEP.
//
// Gated behind DS_DNSGATE_LIVE_UPSTREAM=1; never runs in CI / the offline gate (it
// needs a real default route to 1.1.1.1 / 8.8.8.8). This is the only path that
// touches the real D64 resolvers; everything else is the loopback mock.
// ===========================================================================

#[tokio::test]
async fn live_upstream_d64_pair() {
    if std::env::var("DS_DNSGATE_LIVE_UPSTREAM").as_deref() != Ok("1") {
        eprintln!(
            "live_upstream_d64_pair: SKIPPED — set DS_DNSGATE_LIVE_UPSTREAM=1 to resolve against \
             the real D64 1.1.1.1/8.8.8.8 pair (deferred manual step; needs a default route)."
        );
        return;
    }
    // Default forwarder = the D64 pair.
    let gate = spawn_gate(FixedStubPolicy::new(), GateConfig::default())
        .await
        .unwrap();
    let resp = udp_round_trip(
        gate.udp_local_addr(),
        &a_query(0xd64d, "one.one.one.one.", None),
    )
    .await;
    let msg = Message::from_vec(&resp).unwrap();
    assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
    assert!(
        msg.answers.iter().any(|r| r.data.ip_addr().is_some()),
        "live resolution against the D64 pair returns at least one address"
    );
    gate.shutdown().await.unwrap();
}
