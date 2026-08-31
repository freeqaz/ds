//! The frozen admission-seam tests (doc 11 §4): `evaluate(DnsQueryCtx) -> Verdict ∈
//! {Allow{admit, ttl_clamp}, Deny{rcode_policy}, Ask{prompt_ref}}`, all three arms
//! reachable, wired through `policy-core`'s PUBLIC consumer surface
//! (`consumer::dns_admission_decision`) — the SAME evaluator ds-tlsproxy and the NFT
//! programming path embed (POL-3: no rule is reimplemented here).
//!
//! Kept SEPARATE from `framework_validation.rs` (the listener / forwarder / scrub
//! harness, which runs the always-`Allow` [`FixedStubPolicy`]) and from
//! `suppression_shapes.rs` / `event_surface.rs` so the units stay disjoint. These tests
//! drive the handler against the SHIPPED POL-2 baseline pack
//! (`dataplane/artifacts/policy-packs/pol2-system-baseline.pol1.yaml`, read-only),
//! parsed by the `ds-contracts` reader and composed by `policy-core`, with a network-free
//! loopback mock upstream for the Allow arm (the Deny / Ask arms never forward).
//!
//! What is proven:
//!   * **Allow** — an enabled-family domain (`api.anthropic.com`) is admitted and the
//!     gate forwards + answers the (scrubbed) upstream A record.
//!   * **Ask** — an arbitrary UNLISTED domain is REFUSED (the §3.2 ask-posture shape:
//!     RCODE REFUSED, no cacheable negative signal, no forward).
//!   * **Deny** — a known public DoH/DoT resolver domain (blocklisted in the pack) is
//!     authored as the §3.2 hard-deny NXDOMAIN + the D71 signature SOA (no forward).
//!   * The evaluator carries POL-3 provenance through to the verdict (the seam never
//!     yields a verdict without a rule id / layer / version).
//!   * Two `policy-core` arms project correctly into the seam `Verdict`: a unit check of
//!     [`PolicyCorePolicy::evaluate`] directly, independent of the wire path.
//!
//! D67: no hickory type is named in `src/policy.rs` (asserted by
//! `framework_validation::no_hickory_type_in_policy_seam`); this test exercises the seam
//! through the public `ds_dnsgate` surface, which is hickory-free.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ds_dnsgate::handler::{ForwarderConfig, StubRequestHandler};
use ds_dnsgate::policy::{DnsQueryCtx, PolicyCorePolicy, PolicyHook, RcodePolicy, Verdict};

use ds_contracts::pol1::{parse_layer, PolicyLayer};
use policy_core::pol1_eval::{compose, ComposedPolicy};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::{Protocol, StreamReceiver};
use hickory_server::net::BufDnsStreamHandle;
use hickory_server::server::{Request, RequestHandler, ResponseHandle};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

// ---------------------------------------------------------------------------
// The shipped POL-2 baseline pack (read-only) → composed host document.
// ---------------------------------------------------------------------------

/// The repo-relative path from this crate to the SHIPPED baseline pack. The ds-dnsgate
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

/// Read + parse the shipped pack with ZERO PolicyErrors (the same bar the
/// policy-core `pol2_baseline` integration test holds).
fn parse_shipped_pack() -> PolicyLayer {
    let path = shipped_pack_path();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading shipped pack {}: {e}", path.display()));
    parse_layer(&text).unwrap_or_else(|errs| {
        panic!("the SHIPPED POL-2 baseline pack must parse with zero PolicyErrors, got:\n{errs}")
    })
}

/// Compose the shipped baseline into the host's ONE composed document — fresh install,
/// no capabilities present (the `requires: http-policy` entries are INERT, exactly the
/// state the seam evaluates in pre-TLS-6).
fn composed_fresh_install() -> ComposedPolicy {
    compose(&[parse_shipped_pack()], &[])
}

/// The pack-backed evaluator the seam tests drive (POL-3: it routes the public
/// `dns_admission_decision`).
fn pack_policy() -> PolicyCorePolicy {
    PolicyCorePolicy::new(composed_fresh_install())
}

// ---------------------------------------------------------------------------
// Wire-level query construction + the direct-drive harness (no bound port).
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

/// Drive the pack-backed handler with one query and return the authored wire response.
/// NO bound socket, NO network beyond whatever `forwarder` points at (a loopback mock
/// for the Allow arm; a dead port for the Deny/Ask arms, which never forward).
async fn drive(forwarder: ForwarderConfig, query: &[u8]) -> Message {
    let handler = StubRequestHandler::with_forwarder(pack_policy(), forwarder);

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

// ===========================================================================
// The in-process MOCK UPSTREAM (network-free forwarder fixture, doc 11 §2) — a
// UDP+TCP DNS responder on a 127.0.0.1 ephemeral port serving a programmed answer set.
// (A trimmed copy of the suppression_shapes / event_surface fixture, kept local so this
// test file stays self-contained and disjoint.)
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

fn a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::A(A(ip)))
}

fn ctx(qname: &str, qtype: RecordType) -> DnsQueryCtx {
    DnsQueryCtx {
        session: "seam-test".to_string(),
        qname: qname.to_string(),
        qtype: u16::from(qtype),
        source: client_src(),
    }
}

// ===========================================================================
// 1. ALLOW arm — an enabled-family domain is admitted and the (scrubbed) upstream A is
//    forwarded back to the VM.
// ===========================================================================

#[tokio::test]
async fn allowed_family_domain_resolves_and_is_forwarded() {
    // api.anthropic.com is an enabled `core` family endpoint in the shipped pack.
    let answer = vec![a_record(
        "api.anthropic.com.",
        Ipv4Addr::new(203, 0, 113, 5),
        120,
    )];
    let zone = mock_up::Zone::new().set("api.anthropic.com.", RecordType::A, answer);
    let mock = mock_up::spawn(zone).await;

    let query = query_bytes(0x0a01, "api.anthropic.com.", RecordType::A);
    let resp = drive(mock.forwarder(Duration::from_secs(2)), &query).await;

    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::NoError,
        "an admitted enabled-family domain resolves (NOERROR)"
    );
    assert_eq!(
        resp.answers.len(),
        1,
        "the admitted A record is forwarded to the VM"
    );
    assert_eq!(resp.answers[0].record_type(), RecordType::A);
}

// ===========================================================================
// 2. ASK arm — an arbitrary UNLISTED domain is REFUSED (the §3.2 ask-posture shape: no
//    forward, no cacheable negative signal).
// ===========================================================================

#[tokio::test]
async fn unlisted_domain_is_refused() {
    // A dead upstream with a long timeout: if the Ask arm forwarded, the test would hang.
    // The §3.2 ask shape authors REFUSED immediately, without any forward.
    let forwarder = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_secs(30),
    };
    let query = query_bytes(0x0a02, "totally-unlisted.invalid.", RecordType::A);
    let resp = tokio::time::timeout(Duration::from_secs(3), drive(forwarder, &query))
        .await
        .expect("the Ask arm must NOT wait on the upstream (no forward)");

    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::Refused,
        "an unlisted domain is the Ask posture → REFUSED (doc 11 §3.2)"
    );
    assert_eq!(resp.answers.len(), 0, "a REFUSED carries no answer record");
}

// ===========================================================================
// 3. DENY arm — a blocklisted public DoH/DoT resolver domain is the §3.2 hard deny:
//    NXDOMAIN + the D71 authored signature SOA (no forward).
// ===========================================================================

#[tokio::test]
async fn blocklisted_doh_resolver_is_nxdomain_with_signature_soa() {
    // dns.google is on the shipped pack's blocklist (the resolver-lock; blocklists win).
    let forwarder = ForwarderConfig {
        upstreams: vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 1))],
        timeout: Duration::from_secs(30),
    };
    let query = query_bytes(0x0a03, "dns.google.", RecordType::A);
    let resp = tokio::time::timeout(Duration::from_secs(3), drive(forwarder, &query))
        .await
        .expect("the Deny arm must NOT wait on the upstream (no forward)");

    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::NXDomain,
        "a blocklisted DoH resolver is the §3.2 hard deny → NXDOMAIN (D71)"
    );
    assert_eq!(
        resp.answers.len(),
        0,
        "a hard deny never carries an address record"
    );

    // The always-present D71 authored signature SOA rides the authority section.
    let soa = resp
        .authorities
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(soa) => Some(soa),
            _ => None,
        })
        .expect("the §3.2 hard deny authors a signature SOA in the authority section");
    assert_eq!(
        soa.mname.to_ascii(),
        "denied.policy.boundary.",
        "the default boundary zone reproduces the frozen working-name signature MNAME"
    );
}

// ===========================================================================
// 4. Unit: the seam projects all three policy-core arms into the frozen Verdict, each
//    carrying POL-3 provenance (independent of the wire path).
// ===========================================================================

#[test]
fn evaluate_projects_all_three_arms_with_provenance() {
    let policy = pack_policy();

    // Allow — an enabled-family endpoint.
    let allow = policy.evaluate(&ctx("api.anthropic.com.", RecordType::A));
    assert!(
        matches!(allow, Verdict::Allow { .. }),
        "an enabled-family endpoint is Allow, got {allow:?}"
    );
    assert!(allow.admits());

    // Deny — a blocklisted resolver; the rcode policy is the §3.2 NXDOMAIN shape.
    let deny = policy.evaluate(&ctx("dns.google.", RecordType::A));
    match &deny {
        Verdict::Deny { rcode_policy, .. } => {
            assert_eq!(*rcode_policy, RcodePolicy::NxDomain);
        }
        other => panic!("a blocklisted resolver is Deny, got {other:?}"),
    }
    assert!(!deny.admits());

    // Ask — an unlisted domain (the unknown-domain posture path).
    let ask = policy.evaluate(&ctx("totally-unlisted.invalid.", RecordType::A));
    assert!(
        matches!(ask, Verdict::Ask { .. }),
        "an unlisted domain is Ask, got {ask:?}"
    );
    assert!(!ask.admits());

    // §6.7: every verdict carries non-empty POL-3 provenance (rule id / layer / version).
    for v in [&allow, &deny, &ask] {
        let p = v.provenance();
        assert!(
            !p.rule_id.is_empty() && !p.policy_layer.is_empty() && !p.policy_version.is_empty(),
            "every verdict carries POL-3 provenance, got {p:?}"
        );
    }
    // The Deny/Allow provenance names the matched rule (the pack entry / blocklist domain).
    assert!(deny.provenance().rule_id.contains("dns.google"));
    assert!(allow.provenance().rule_id.contains("api.anthropic.com"));
}
