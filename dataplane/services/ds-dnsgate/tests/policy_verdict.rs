//! Policy-verdict wire tests — the core query path with REAL `policy-core` verdicts
//! (doc 11 §3.1/§3.2/§4, D71; POL-3).
//!
//! These drive the gate through the pack-backed [`PolicyCorePolicy`] evaluator —
//! which routes every query through `policy-core`'s frozen verdict surface
//! ([`policy_core::dns_gate::evaluate`] / [`policy_core::consumer::dns_admission_decision`],
//! the ONE engine — no rule reimplemented) and returns the frozen
//! [`policy_core::dns_gate::DnsVerdict`] DIRECTLY (there is no second service-internal
//! verdict type) — and assert the three §3.2/§4 verdict shapes on the WIRE, over BOTH
//! UDP and TCP/53 (the same handler serves both, doc 11 §3.4 parity):
//!   * **Allow** (an enabled-family / allowlisted name) -> the gate forwards + scrubs
//!     + answers (exercised against a loopback mock upstream).
//!   * **Deny** (a blocklisted name) -> NXDOMAIN (RCODE 3), empty answer, the always
//!     authored signature SOA in authority, EDE INFO-CODE 15 (Blocked) with a `ds:`
//!     EXTRA-TEXT iff the query carried OPT — NEVER SERVFAIL, NEVER an address record.
//!   * **Ask** (an unknown name) -> REFUSED (RCODE 5) immediately, no records, no
//!     cacheable negative signal.
//!
//! No network: a Deny / Ask never forwards (so no upstream is contacted at all), and
//! the Allow path forwards to an in-process loopback mock upstream injected via
//! `ForwarderConfig`. These assert the conformance corpus drives WIRE behavior
//! (dig/getaddrinfo-shaped), never a hickory or policy-core API (doc 11 §6 row 10).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ds_dnsgate::handler::{
    format_ede_extra_text, ForwarderConfig, StubRequestHandler, DEFAULT_BOUNDARY_ZONE,
    EDE_EXTRA_TEXT_PREFIX, EDE_LAYER_TOKEN, EDE_RULE_TOKEN, EDE_VERSION_TOKEN, SOA_SIGNATURE_MNAME,
};
use ds_dnsgate::policy::{DnsQueryCtx, PolicyCorePolicy, PolicyHook};
use ds_dnsgate::{spawn_gate, CapturingSink, EventPath, GateConfig, RunningGate};

// The seam now binds the ONE frozen verdict type — `policy_core::dns_gate::DnsVerdict`
// (re-exported as `ds_dnsgate::policy::Verdict`). The unit assertion below pins that the
// gate's evaluator returns exactly that frozen shape, so a future drift can't reintroduce
// a second service-internal verdict.
use policy_core::dns_gate::{DnsVerdict, RcodePolicy};

use ds_contracts::pol1::parse_layer;
use policy_core::pol1_eval::compose;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

// ── The policy layer the gate evaluates ────────────────────────────────────────
// Allows github (enabled core family) + an explicit allowlist host, denies a DoH
// resolver at a severing rung; everything else is an unknown-domain Ask.
//
// `gated.example` is a `requires:`-gated baseline-pack entry in the SAME enabled `core`
// family: with no capability present (a fresh install, `compose(&[layer], &[])`) it is
// INERT (§1.7) — it admits NOTHING and the frozen `evaluate` folds it into
// `Deny{rcode_policy: NxDomain, rung: None}`, the SAME NXDOMAIN wire shape a hard
// `blocklist` deny authors. The two are indistinguishable on the DNS wire BY DESIGN
// (no fourth wire shape); the ONLY surviving signal is provenance — the inert arm
// carries the `baseline-pack:<family>/<fqdn>` rule id, the hard deny carries
// `blocklist:<domain>`. The inert-vs-deny tests below pin that this distinction
// survives the fold through the LOG-1 join and the EDE-15 `ds:` extra-text.
const LAYER: &str = r#"
schema_version: pol1/v0
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
  - domain: allowed.example
blocklist:
  - domain: dns.google
    reason: doh-resolver
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries:
    - fqdn: github.com
      family: core
      ports: [443]
      provenance_source_url: https://api.github.com/meta
      evidence: vendor-doc
    - fqdn: gated.example
      family: core
      ports: [443]
      requires: http-policy
      provenance_source_url: https://example.test/meta
      evidence: vendor-doc
"#;

/// The REAL pack-backed evaluator (POL-3): parse the layer with `ds-contracts`, compose
/// the host's ONE document with `policy-core`'s `compose`, and wrap it as the installed
/// [`PolicyCorePolicy`]. No capabilities present (fresh install), so a `requires:`-gated
/// entry would be inert — there are none in this layer.
fn policy() -> PolicyCorePolicy {
    let layer = parse_layer(LAYER).expect("policy layer parses");
    PolicyCorePolicy::new(compose(&[layer], &[]))
}

// ── Query construction + UDP/TCP round-trips (loopback only) ────────────────────

fn query_of(id: u16, name: &str, qtype: RecordType, with_opt: bool) -> Vec<u8> {
    let mut msg = Message::query();
    msg.metadata.id = id;
    msg.metadata.message_type = MessageType::Query;
    msg.metadata.op_code = OpCode::Query;
    msg.metadata.recursion_desired = true;
    msg.add_query(hickory_proto::op::Query::query(
        Name::from_ascii(name).unwrap(),
        qtype,
    ));
    if with_opt {
        // Attach a client OPT (EDNS) so the §3.2 EDE 15 attaches on a deny.
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(1232);
        edns.set_version(0);
        msg.set_edns(edns);
    }
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

async fn both_transports(gate: &RunningGate<PolicyCorePolicy>, query: &[u8]) -> (Message, Message) {
    let udp = Message::from_vec(&udp_round_trip(gate.udp_local_addr(), query).await).unwrap();
    let tcp = Message::from_vec(&tcp_round_trip(gate.tcp_local_addr(), query).await).unwrap();
    (udp, tcp)
}

async fn policy_gate() -> RunningGate<PolicyCorePolicy> {
    // A Deny / Ask never forwards, so the forwarder is irrelevant for those paths;
    // the default config is fine (it is never contacted on a non-Allow verdict).
    spawn_gate(policy(), GateConfig::default())
        .await
        .expect("gate binds")
}

// ── Assertions on the authored §3.2 shapes ──────────────────────────────────────

fn assert_nxdomain_with_signature_soa(msg: &Message, transport: &str) {
    assert_eq!(
        msg.metadata.response_code,
        ResponseCode::NXDomain,
        "policy deny is NXDOMAIN, not SERVFAIL/REFUSED ({transport}): {msg:?}"
    );
    assert_eq!(
        msg.answers.len(),
        0,
        "hard deny has an empty answer section ({transport})"
    );
    // The always-authored signature SOA rides the authority section.
    let soa = msg
        .authorities
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(soa) => Some(soa),
            _ => None,
        })
        .unwrap_or_else(|| panic!("authored SOA present in authority ({transport}): {msg:?}"));
    assert_eq!(
        soa.mname.to_ascii(),
        SOA_SIGNATURE_MNAME,
        "SOA MNAME is the frozen denied.policy.<zone> signature ({transport})"
    );
    // NEVER an address record on a deny.
    assert!(
        !msg.answers.iter().any(|r| matches!(
            r.record_type(),
            RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
        )),
        "a policy deny never carries an address/HTTPS/SVCB record ({transport})"
    );
}

/// Whether the response carries an EDE INFO-CODE 15 (Blocked) option with a `ds:`
/// EXTRA-TEXT. hickory 0.26.x has no native EDE type, so EDE 15 rides as
/// `EdnsOption::Unknown(15, ...)` (the IANA "Extended DNS Error" option code) whose
/// first two payload bytes are the big-endian INFO-CODE and whose tail is the text.
fn ede_blocked_text(msg: &Message) -> Option<String> {
    let edns = msg.edns.as_ref()?;
    let opt = edns.option(EdnsCode::Unknown(15))?;
    let EdnsOption::Unknown(15, bytes) = opt else {
        return None;
    };
    if bytes.len() < 2 {
        return None;
    }
    let info_code = u16::from_be_bytes([bytes[0], bytes[1]]);
    if info_code != 15 {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes[2..]).into_owned())
}

// ── Tests ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn blocklisted_name_is_nxdomain_over_udp_and_tcp() {
    let gate = policy_gate().await;
    // No OPT on the query → no EDE attaches (§3.2: EDE iff OPT).
    let (udp, tcp) = both_transports(
        &gate,
        &query_of(0x1001, "dns.google.", RecordType::A, false),
    )
    .await;
    assert_nxdomain_with_signature_soa(&udp, "udp");
    assert_nxdomain_with_signature_soa(&tcp, "tcp");
    // No OPT in the query → no EDE in the response.
    assert!(
        ede_blocked_text(&udp).is_none(),
        "no EDE without a query OPT (udp)"
    );
    assert!(
        ede_blocked_text(&tcp).is_none(),
        "no EDE without a query OPT (tcp)"
    );
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn blocklisted_name_with_opt_carries_ede_15_with_ds_provenance() {
    let gate = policy_gate().await;
    // WITH a client OPT → the §3.2 EDE 15 (Blocked) attaches, EXTRA-TEXT `ds:`-prefixed.
    let (udp, tcp) =
        both_transports(&gate, &query_of(0x1002, "dns.google.", RecordType::A, true)).await;
    assert_nxdomain_with_signature_soa(&udp, "udp");
    assert_nxdomain_with_signature_soa(&tcp, "tcp");
    for (msg, t) in [(&udp, "udp"), (&tcp, "tcp")] {
        let text = ede_blocked_text(msg)
            .unwrap_or_else(|| panic!("EDE 15 present with a query OPT ({t}): {msg:?}"));
        assert!(
            text.starts_with(EDE_DS_PREFIX),
            "EDE EXTRA-TEXT is `ds:`-prefixed ({t}): {text:?}"
        );
        // POL-3 provenance rides the text: the blocked rule id names the domain.
        assert!(
            text.contains("dns.google"),
            "EDE carries POL-3 rule provenance ({t}): {text:?}"
        );
    }
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn unknown_name_is_refused_over_udp_and_tcp() {
    let gate = policy_gate().await;
    let (udp, tcp) = both_transports(
        &gate,
        &query_of(0x2001, "unknown.invalid.", RecordType::A, true),
    )
    .await;
    for (msg, t) in [(&udp, "udp"), (&tcp, "tcp")] {
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::Refused,
            "an unknown-domain Ask is REFUSED ({t}): {msg:?}"
        );
        assert_eq!(msg.answers.len(), 0, "REFUSED carries no answer ({t})");
        // REFUSED is the §3.2 ask shape — never NXDOMAIN (no cacheable negative signal).
        assert_ne!(
            msg.metadata.response_code,
            ResponseCode::NXDomain,
            "ask is not NXDOMAIN ({t})"
        );
    }
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn servfail_is_never_a_policy_verdict() {
    // §3.2: SERVFAIL is reserved for genuine failure — neither a deny nor an ask ever
    // authors it. (A deny is NXDOMAIN, an ask is REFUSED.)
    let gate = policy_gate().await;
    let deny = Message::from_vec(
        &udp_round_trip(
            gate.udp_local_addr(),
            &query_of(0x3001, "dns.google.", RecordType::A, true),
        )
        .await,
    )
    .unwrap();
    let ask = Message::from_vec(
        &udp_round_trip(
            gate.udp_local_addr(),
            &query_of(0x3002, "unknown.invalid.", RecordType::A, true),
        )
        .await,
    )
    .unwrap();
    assert_ne!(deny.metadata.response_code, ResponseCode::ServFail);
    assert_ne!(ask.metadata.response_code, ResponseCode::ServFail);
    gate.shutdown().await.unwrap();
}

#[tokio::test]
async fn every_verdict_path_emits_an_event_with_real_provenance() {
    // §6.7: every query path emits a DnsEvent carrying the verdict's REAL POL-3
    // provenance (not the always-allow harness marker). Drive the handler directly
    // with a capturing sink so we can read the events back (the Denied / Asked paths
    // each carry the matched rule's provenance).
    use hickory_server::net::xfer::Protocol;
    use hickory_server::net::BufDnsStreamHandle;
    use hickory_server::server::{Request, RequestHandler, ResponseHandle};

    let sink = CapturingSink::new();
    // ATTENDED posture (D77): an unknown-domain Ask raises the async human ask and emits
    // the `Asked` event. (The conservative DEFAULT posture is Unattended → the downgrade
    // `AskDowngradedBlock` path; the dedicated ask-seam tests cover that fork. Here the
    // intent is the §6.7 provenance-on-every-path coverage, so the attended Ask is used.)
    let handler = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        policy(),
        ForwarderConfig::default(),
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(sink.clone()),
    )
    .with_ask_posture(ds_dnsgate::ask::AskPosture::Attended);

    let src = SocketAddr::from((Ipv4Addr::LOCALHOST, 5300));
    for (name, expected) in [
        ("dns.google.", EventPath::Denied),
        ("unknown.invalid.", EventPath::Asked),
    ] {
        let bytes = query_of(0x4444, name, RecordType::A, true);
        let request = Request::from_bytes(bytes, src, Protocol::Udp).unwrap();
        let (stream_handle, _rx) = BufDnsStreamHandle::new(src);
        let rh = ResponseHandle::new(src, stream_handle, Protocol::Udp);
        let _ = RequestHandler::handle_request::<_, hickory_server::net::runtime::TokioTime>(
            &handler, &request, rh,
        )
        .await;

        let events = sink.events();
        let last = events.last().expect("an event was emitted");
        assert_eq!(last.path, expected, "event path for {name}");
        // §6.7: REAL provenance — the matched rule names the domain (a deny) or the
        // unknown-domain Ask posture, never the always-allow harness marker.
        assert_ne!(
            last.provenance.rule_id, "harness/allow-all",
            "real provenance for {name}: {last:?}"
        );
        assert!(
            last.provenance.rule_id.contains(name.trim_end_matches('.'))
                || last.provenance.rule_id.contains("unknown")
                || !last.provenance.rule_id.is_empty(),
            "provenance names the matched rule for {name}: {last:?}"
        );
    }
}

// A small smoke check that the Allow path still answers a forwarded A through the
// real policy verdict (the policy says github.com is enabled), against a loopback
// mock upstream — proving Allow is not regressed by the verdict fork.
#[tokio::test]
async fn allowed_name_forwards_and_answers_through_the_real_verdict() {
    let mock = mock_up::MockUpstream::start(vec![Record::from_rdata(
        Name::from_ascii("github.com.").unwrap(),
        300,
        RData::A(A(Ipv4Addr::new(140, 82, 121, 4))),
    )])
    .await;
    let config = GateConfig {
        forwarder: ForwarderConfig {
            upstreams: vec![mock.local_addr()],
            timeout: Duration::from_secs(2),
        },
        ..GateConfig::default()
    };
    let gate = spawn_gate(policy(), config).await.expect("gate binds");

    let resp = Message::from_vec(
        &udp_round_trip(
            gate.udp_local_addr(),
            &query_of(0x5001, "github.com.", RecordType::A, true),
        )
        .await,
    )
    .unwrap();
    assert_eq!(
        resp.metadata.response_code,
        ResponseCode::NoError,
        "allowed name resolves: {resp:?}"
    );
    assert!(
        resp.answers
            .iter()
            .any(|r| r.record_type() == RecordType::A),
        "the allowed A answer reaches the VM: {resp:?}"
    );
    gate.shutdown().await.unwrap();
}

/// The seam binds the ONE FROZEN verdict type: `PolicyCorePolicy::evaluate` returns
/// `policy_core::dns_gate::DnsVerdict` directly (no second service-internal verdict to
/// keep in lockstep), and the three §3.2/§4 arms project off the same shipped pack with
/// the POL-3 provenance triple (rule id / layer / version) preserved on EVERY arm. This
/// is the unit-level regression net pinning the unification, independent of the wire path.
#[test]
fn seam_returns_the_frozen_dns_verdict_with_provenance_on_every_arm() {
    fn ctx(qname: &str) -> DnsQueryCtx {
        DnsQueryCtx {
            session: "verdict-unify-test".to_string(),
            qname: qname.to_string(),
            qtype: u16::from(RecordType::A),
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        }
    }
    let p = policy();

    // Allow — github.com is an enabled `core` family endpoint in the test layer. The
    // frozen `Allow{admit, provenance}` carries the W2 clamp window on its `Admit`.
    let allow: DnsVerdict = p.evaluate(&ctx("github.com."));
    match &allow {
        DnsVerdict::Allow { admit, .. } => {
            assert_eq!(
                admit.ttl_floor, 60,
                "the W2 clamp floor rides the frozen Admit"
            );
            assert_eq!(
                admit.ttl_ceil, 900,
                "the W2 clamp ceil rides the frozen Admit"
            );
        }
        other => panic!("an enabled-family endpoint is the frozen Allow, got {other:?}"),
    }
    assert!(allow.admits());

    // Deny — dns.google is blocklisted; the frozen `Deny{rcode_policy, rung, provenance}`
    // carries the §3.2 NXDOMAIN rcode policy and the D53 rung (kill+snapshot in the layer).
    let deny: DnsVerdict = p.evaluate(&ctx("dns.google."));
    match &deny {
        DnsVerdict::Deny { rcode_policy, .. } => {
            assert_eq!(*rcode_policy, RcodePolicy::NxDomain);
        }
        other => panic!("a blocklisted resolver is the frozen Deny, got {other:?}"),
    }
    assert!(!deny.admits());
    // The blocklist rung is severing → the deny severs established flows (§5.4 / D53).
    assert!(
        deny.severs_established_flows(),
        "a kill+snapshot-rung deny severs established flows (D53)"
    );

    // Ask — an unknown domain is the unknown-domain posture: the frozen
    // `Ask{prompt_ref, provenance}` (REFUSED on the wire, prompt over the D18 seam).
    let ask: DnsVerdict = p.evaluate(&ctx("unknown.invalid."));
    assert!(
        matches!(ask, DnsVerdict::Ask { .. }),
        "an unknown domain is the frozen Ask, got {ask:?}"
    );
    assert!(!ask.admits());

    // §6.7 / POL-3: every frozen verdict carries the non-empty provenance triple.
    for v in [&allow, &deny, &ask] {
        let prov = v.provenance();
        assert!(
            !prov.rule_id.is_empty()
                && !prov.policy_layer.is_empty()
                && !prov.policy_version.is_empty(),
            "every frozen verdict carries the POL-3 triple, got {prov:?}"
        );
    }
    // The matched-rule provenance names the deny domain and the allow endpoint.
    assert!(
        deny.provenance().rule_id.contains("dns.google"),
        "the deny provenance names the blocklisted domain: {:?}",
        deny.provenance()
    );
    assert!(
        allow.provenance().rule_id.contains("github.com"),
        "the allow provenance names the enabled endpoint: {:?}",
        allow.provenance()
    );
}

// ── Inert-capability-gated vs hard-deny: the provenance distinction folded into
//    NXDOMAIN by the frozen `evaluate` (LOG-1 + EDE-15 provenance) ──────────────────
//
// `verdict-unify` folds `DecisionKind::InertCapabilityGated` into
// `DnsVerdict::Deny{rcode_policy: NxDomain, rung: None, provenance}` (the same arm a
// hard `blocklist` deny takes). On the DNS WIRE an inert capability-gated entry is now
// INDISTINGUISHABLE from a hard policy deny — both are the §3.2 NXDOMAIN hard-deny shape,
// and there is NO fourth wire shape for inertness (by design, dns_gate.rs:130-135). The
// ONLY surviving signal is PROVENANCE: the inert arm carries its DISTINCT inert rule id
// (`baseline-pack:<family>/<fqdn>`), never a plain hard-deny rule id (`blocklist:<domain>`).
//
// These tests are the regression net for that semantic risk: if the inert arm ever
// silently regressed to a plain deny rule id, the capability-gate ask-user path would
// disappear into a hard block with no downstream signal. They assert (1) at the frozen
// seam the inert Deny and the hard Deny carry the SAME NXDOMAIN rcode but DISTINCT
// provenance and rung, and (2) on the WIRE the two are identical NXDOMAIN but the LOG-1
// `DnsEvent` provenance and the EDE-15 `ds:` extra-text still tell them apart — so the
// `event_provenance` bridge keeps the inert provenance intact through NXDOMAIN authoring.

/// The frozen seam: an inert capability-gated entry and a hard `blocklist` deny BOTH fold
/// to `Deny{rcode_policy: NxDomain}` — the identical NXDOMAIN wire shape — yet carry
/// DISTINCT provenance (the inert `baseline-pack:` rule id vs the hard-deny `blocklist:`
/// rule id) and distinct rung (`None` for inert — it severs nothing, §5 — vs `Some` for
/// the severing blocklist rung). POL-3: the rule-id/layer/policy-version triple is intact
/// on EVERY arm. This is the unit-level invariant the LOG-1 join and the EDE-15 extra-text
/// downstream rely on to tell inert apart from a hard deny despite the shared rcode.
#[test]
fn inert_capability_gated_folds_to_nxdomain_with_distinct_provenance_from_hard_deny() {
    fn ctx(qname: &str) -> DnsQueryCtx {
        DnsQueryCtx {
            session: "inert-vs-deny-test".to_string(),
            qname: qname.to_string(),
            qtype: u16::from(RecordType::A),
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        }
    }
    let p = policy();

    // The inert arm: `gated.example` is a `requires: http-policy` baseline-pack entry and
    // no capability is present, so it is INERT — folded to the §3.2 NXDOMAIN hard-deny
    // shape (it admits nothing). The provenance is the INERT rule id, not a deny rule id.
    let inert: DnsVerdict = p.evaluate(&ctx("gated.example."));
    let (inert_rcode, inert_rung, inert_prov) = match &inert {
        DnsVerdict::Deny {
            rcode_policy,
            rung,
            provenance,
        } => (*rcode_policy, *rung, provenance.clone()),
        other => {
            panic!("an inert capability-gated entry folds into the frozen Deny, got {other:?}")
        }
    };
    assert_eq!(
        inert_rcode,
        RcodePolicy::NxDomain,
        "inert folds into the §3.2 NXDOMAIN hard-deny shape (no fourth wire shape)"
    );
    assert!(
        !inert.admits(),
        "an inert capability-gated entry admits NOTHING (§1.7)"
    );
    // The inert arm carries NO explicit deny rung — an inert entry is not a policy block,
    // so it severs nothing (§5.4 / D53). This is part of how it stays distinct from a
    // severing hard deny even though both share the NXDOMAIN rcode.
    assert_eq!(
        inert_rung, None,
        "an inert capability-gated entry carries no deny rung (it severs nothing, §5)"
    );
    assert!(
        !inert.severs_established_flows(),
        "an inert NXDOMAIN never severs established flows (it is not a policy block)"
    );

    // The hard-deny arm: `dns.google` is blocklisted at a severing rung — the SAME
    // NXDOMAIN rcode on the wire, but a `blocklist:` rule id and a severing rung.
    let hard: DnsVerdict = p.evaluate(&ctx("dns.google."));
    let (hard_rcode, hard_prov) = match &hard {
        DnsVerdict::Deny {
            rcode_policy,
            provenance,
            ..
        } => (*rcode_policy, provenance.clone()),
        other => panic!("a blocklisted resolver is the frozen hard Deny, got {other:?}"),
    };

    // (1) SAME wire shape: both are the §3.2 NXDOMAIN hard-deny rcode. On the DNS wire
    // there is no way to tell them apart — this is the indistinguishability the fold
    // introduces by design.
    assert_eq!(
        inert_rcode, hard_rcode,
        "inert and hard deny share the identical NXDOMAIN wire rcode (no fourth shape)"
    );

    // (2) DISTINCT provenance: the ONLY surviving signal. The inert arm names the inert
    // baseline-pack entry; the hard deny names the blocklist rule. A LOG-1 join keying on
    // the rule id can tell them apart despite the shared rcode.
    assert_ne!(
        inert_prov.rule_id, hard_prov.rule_id,
        "inert provenance must differ from hard-deny provenance — the only surviving signal"
    );
    assert!(
        inert_prov.rule_id.starts_with("baseline-pack:"),
        "the inert arm carries its DISTINCT inert rule id, not a plain deny id: {:?}",
        inert_prov.rule_id
    );
    assert!(
        inert_prov.rule_id.contains("gated.example"),
        "the inert rule id names the inert (capability-gated) entry: {:?}",
        inert_prov.rule_id
    );
    assert!(
        hard_prov.rule_id.starts_with("blocklist:"),
        "the hard deny carries a plain blocklist rule id: {:?}",
        hard_prov.rule_id
    );

    // (3) POL-3: the rule-id/layer/policy-version triple is intact on EVERY arm, including
    // the folded inert arm — the fold never drops provenance.
    for (label, prov) in [("inert", &inert_prov), ("hard-deny", &hard_prov)] {
        assert!(
            !prov.rule_id.is_empty()
                && !prov.policy_layer.is_empty()
                && !prov.policy_version.is_empty(),
            "the {label} arm carries the full POL-3 triple, got {prov:?}"
        );
    }
}

/// On the WIRE the inert NXDOMAIN and the hard-deny NXDOMAIN are IDENTICAL (rcode, empty
/// answer, the same authored signature SOA), yet the LOG-1 `DnsEvent` provenance and the
/// EDE-15 `ds:` extra-text still distinguish inert from hard-deny. This proves the
/// handler's `event_provenance` bridge keeps the inert provenance intact through the
/// NXDOMAIN authoring — the inert arm reaches the §5.5 event and the §3.2 EDE carrying its
/// distinct inert rule id, so the capability-gate ask-user path never silently regresses
/// into an untraceable hard block. Loopback / synthetic only — a Deny never forwards.
#[tokio::test]
async fn inert_and_hard_deny_share_nxdomain_wire_but_split_on_log1_and_ede_provenance() {
    use hickory_server::net::xfer::Protocol;
    use hickory_server::net::BufDnsStreamHandle;
    use hickory_server::server::{Request, RequestHandler, ResponseHandle};

    let sink = CapturingSink::new();
    let handler = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        policy(),
        ForwarderConfig::default(),
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(sink.clone()),
    );

    // Drive the inert entry and the hard deny through the handler with a query OPT (so the
    // §3.2 EDE-15 attaches on both), capturing the authored response and the LOG-1 event.
    let src = SocketAddr::from((Ipv4Addr::LOCALHOST, 5301));
    async fn author<H: RequestHandler>(handler: &H, src: SocketAddr, name: &str) -> Message {
        use futures_util::StreamExt;
        let bytes = query_of(0x6001, name, RecordType::A, true);
        let request = Request::from_bytes(bytes, src, Protocol::Udp).unwrap();
        let (stream_handle, mut rx) = BufDnsStreamHandle::new(src);
        let rh = ResponseHandle::new(src, stream_handle, Protocol::Udp);
        let _ = RequestHandler::handle_request::<_, hickory_server::net::runtime::TokioTime>(
            handler, &request, rh,
        )
        .await;
        // The authored response is already queued by the time `handle_request` returns; a
        // short timeout guards the (unexpected) no-response case.
        let serial = tokio::time::timeout(Duration::from_millis(500), rx.next())
            .await
            .expect("the handler authored a response in time")
            .expect("an authored response was sent");
        let (resp_bytes, _addr) = serial.into_parts();
        Message::from_vec(&resp_bytes).expect("the authored response decodes")
    }

    let inert_resp = author(&handler, src, "gated.example.").await;
    let inert_event = sink.events().last().cloned().expect("inert event emitted");

    let hard_resp = author(&handler, src, "dns.google.").await;
    let hard_event = sink
        .events()
        .last()
        .cloned()
        .expect("hard-deny event emitted");

    // The WIRE is identical: both NXDOMAIN with the same authored signature SOA, empty
    // answer, no address record — the inert entry is indistinguishable from a hard deny on
    // the DNS wire (the whole point of the fold).
    assert_nxdomain_with_signature_soa(&inert_resp, "inert-udp");
    assert_nxdomain_with_signature_soa(&hard_resp, "hard-deny-udp");
    assert_eq!(
        inert_resp.metadata.response_code, hard_resp.metadata.response_code,
        "inert and hard deny author the identical NXDOMAIN wire rcode"
    );

    // The LOG-1 join SPLITS them: both ride the `Denied` event path, but the event
    // provenance the `event_provenance` bridge stamped carries the DISTINCT rule id — the
    // inert baseline-pack id vs the blocklist id. POL-3 triple intact on both.
    assert_eq!(
        inert_event.path,
        EventPath::Denied,
        "inert rides the Denied event path"
    );
    assert_eq!(
        hard_event.path,
        EventPath::Denied,
        "hard deny rides the Denied event path"
    );
    assert_ne!(
        inert_event.provenance.rule_id, hard_event.provenance.rule_id,
        "the LOG-1 join tells inert from hard deny despite the shared NXDOMAIN path"
    );
    assert!(
        inert_event.provenance.rule_id.starts_with("baseline-pack:")
            && inert_event.provenance.rule_id.contains("gated.example"),
        "the inert event carries its distinct inert provenance through NXDOMAIN authoring: {:?}",
        inert_event.provenance
    );
    assert!(
        hard_event.provenance.rule_id.starts_with("blocklist:"),
        "the hard-deny event carries the blocklist provenance: {:?}",
        hard_event.provenance
    );
    // POL-3: the full triple survives the bridge on BOTH arms (every field non-empty).
    for (label, ev) in [("inert", &inert_event), ("hard-deny", &hard_event)] {
        assert!(
            !ev.provenance.rule_id.is_empty()
                && !ev.provenance.policy_layer.is_empty()
                && !ev.provenance.policy_version.is_empty(),
            "the {label} LOG-1 event carries the full POL-3 triple, got {:?}",
            ev.provenance
        );
    }

    // The EDE-15 `ds:` extra-text SPLITS them too: both NXDOMAIN-with-OPT responses carry
    // EDE 15 (Blocked), but its `ds:` provenance fingerprint differs — a tool grepping the
    // EDE can tell the inert capability-gate apart from a hard block. This is the second
    // downstream channel preserving the distinction the shared rcode erases.
    let inert_ede = ede_blocked_text(&inert_resp)
        .unwrap_or_else(|| panic!("inert NXDOMAIN-with-OPT carries EDE 15: {inert_resp:?}"));
    let hard_ede = ede_blocked_text(&hard_resp)
        .unwrap_or_else(|| panic!("hard-deny NXDOMAIN-with-OPT carries EDE 15: {hard_resp:?}"));
    assert!(
        inert_ede.starts_with(EDE_DS_PREFIX) && hard_ede.starts_with(EDE_DS_PREFIX),
        "both EDE extra-texts are `ds:`-prefixed: inert={inert_ede:?} hard={hard_ede:?}"
    );
    assert_ne!(
        inert_ede, hard_ede,
        "the EDE-15 `ds:` extra-text distinguishes inert from hard deny"
    );
    assert!(
        inert_ede.contains("gated.example"),
        "the inert EDE names the inert (capability-gated) entry: {inert_ede:?}"
    );
    assert!(
        hard_ede.contains("dns.google"),
        "the hard-deny EDE names the blocklisted domain: {hard_ede:?}"
    );
}

// ===========================================================================
// Layer / policy-version axis: the EDE-15 ds: fingerprint test extension
// (wave29b unit dnsgate-ede15-layer-version-axis)
//
// The inert-vs-deny tests above proved the RULE-ID axis: two verdicts with the
// same NXDOMAIN wire shape carry DISTINCT rule ids in the LOG-1 provenance.
// This section extends that assertion to the other two POL-3 triple axes:
//
//   * LAYER axis: the same rule-id emerging from two different policy layers
//     (system-baseline vs org) carries DISTINCT `policy_layer` provenance.
//   * VERSION axis: the same rule-id evaluated under two different `schema_version`
//     (policy-version N vs N+1) carries DISTINCT `policy_version` provenance —
//     so a LOG-1 join keyed on policy-version can tell them apart.
//
// Both axes are asserted on:
//   1. The LOG-1 `DnsEvent` provenance triple (the primary downstream channel,
//      guaranteed to carry all three fields; §6.7/POL-3).
//   2. The EDE-15 `ds:` EXTRA-TEXT (the secondary channel) — because the handler
//      already encodes `layer=` and `version=` in the `ds:` text
//      (`ds:rule=<id> layer=<layer> version=<version>`), this channel DOES carry
//      both axes and the tests assert it.
//
// handler.rs (READ-ONLY this wave) is NOT modified; the existing `ds:` encoding
// already covers the full triple — this is a test-coverage gap, not a handler gap.
// ===========================================================================

// ── Policy layer documents for the layer/version axis tests ─────────────────

/// A baseline-pack entry for `shared.example` in a `system-baseline` layer
/// (family `core`, enabled, no `requires:` capability) at pack-version v0.
/// The `policy_layer` on any verdict for `shared.example` will be
/// `"system-baseline"` (the `source_layer` from `layer_token`).
const LAYER_BASELINE_PACK_V0: &str = r#"
schema_version: 2026.06.12-v0
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries:
    - fqdn: shared.example
      family: core
      ports: [443]
      provenance_source_url: https://example.test/meta
      evidence: vendor-doc
"#;

/// A baseline-pack entry for `shared.example` in an `org` layer — the identical
/// fqdn, family, and pack shape, but a different layer name and pack-version.
/// The `policy_layer` on any verdict for `shared.example` will be `"org"`.
const LAYER_BASELINE_PACK_ORG: &str = r#"
schema_version: 2026.06.12-v0
layer: org
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries:
    - fqdn: shared.example
      family: core
      ports: [443]
      provenance_source_url: https://example.test/meta
      evidence: vendor-doc
"#;

/// Same blocklist rule for `version-bump.example` at policy-version N.
const LAYER_BLOCKLIST_VERSION_N: &str = r#"
schema_version: 2026.06.12-v0
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
blocklist:
  - domain: version-bump.example
    reason: test-version-axis
    rung: kill+snapshot
"#;

/// Same blocklist rule for `version-bump.example` at policy-version N+1:
/// identical structure, only `schema_version` bumped. The `policy_version` on
/// the verdict will be `"2026.06.12-v1"` instead of `"2026.06.12-v0"`.
const LAYER_BLOCKLIST_VERSION_N_PLUS_1: &str = r#"
schema_version: 2026.06.12-v1
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
blocklist:
  - domain: version-bump.example
    reason: test-version-axis
    rung: kill+snapshot
"#;

// ── Helper: policy from a single layer string ────────────────────────────────

fn policy_from(layer_doc: &str) -> PolicyCorePolicy {
    let layer = parse_layer(layer_doc).expect("layer doc parses");
    PolicyCorePolicy::new(compose(&[layer], &[]))
}

// ── The EDE-15 `ds:` extra-text grammar — pinned in ONE place ────────────────
//
// The handler (src/handler.rs `ede_blocked_option`) authors the §3.2 EDE-15 (Blocked)
// EXTRA-TEXT as `format!("{EDE_EXTRA_TEXT_PREFIX}rule={} layer={} version={}", ...)`,
// i.e. the FOUR-part wire grammar
//
//     ds:rule=<rule-id> layer=<layer> version=<version>
//
// — a `ds:` prefix, then the POL-3 provenance triple as three SPACE-separated
// `key=value` tokens in the FIXED order rule / layer / version. Many tests below
// substring-match this grammar (`.starts_with("ds:")`, pull the `layer=`/`version=`
// values, etc.). Before this consolidation each test re-encoded the token spellings
// inline, so a handler.rs reformat of the grammar would silently skew several parsers
// at once with no failure pointing at the grammar.
//
// The grammar now lives in ONE place — `src/handler.rs`, the PRODUCER: it exports the
// `ds:` prefix (`EDE_EXTRA_TEXT_PREFIX`), the ordered token-name constants
// (`EDE_RULE_TOKEN` / `EDE_LAYER_TOKEN` / `EDE_VERSION_TOKEN`), and the
// `format_ede_extra_text` renderer the emitter itself calls. These tests CONSUME those
// same exported constants (imported at the top of the file), so the parser below and the
// handler's emitter can never spell or order the tokens differently. A grammar change in
// the handler breaks ONE obvious place — and the positive
// `ds_ede_extra_text_grammar_is_pinned` test below asserts the handler's emitted text
// conforms to that exported grammar, so a one-sided edit fails loudly here.

/// Re-bind the handler's exported `ds:` prefix under the name the local parser/assertions
/// use, so the prefix spelling is the handler's and never a hand-mirror.
const EDE_DS_PREFIX: &str = EDE_EXTRA_TEXT_PREFIX;

/// The POL-3 triple parsed out of a `ds:`-prefixed EDE-15 EXTRA-TEXT, borrowing the
/// token values from the source string. The ONE structured view of the grammar every
/// EDE-token assertion routes through.
struct DsEdeText<'a> {
    rule: &'a str,
    layer: &'a str,
    version: &'a str,
}

/// Parse the `ds:rule=<id> layer=<layer> version=<version>` grammar (the ONE place that
/// knows the token spellings and order). Returns `None` if the prefix is missing, any of
/// the three tokens is absent, or the order is wrong — so a handler.rs reformat surfaces
/// as a `None` (a loud failure at the call site) rather than a silently-skewed value.
fn parse_ds_ede(ede_text: &str) -> Option<DsEdeText<'_>> {
    let body = ede_text.strip_prefix(EDE_DS_PREFIX)?;
    let mut tokens = body.split_whitespace();
    let rule = tokens.next()?.strip_prefix(EDE_RULE_TOKEN)?;
    let layer = tokens.next()?.strip_prefix(EDE_LAYER_TOKEN)?;
    let version = tokens.next()?.strip_prefix(EDE_VERSION_TOKEN)?;
    Some(DsEdeText {
        rule,
        layer,
        version,
    })
}

// ── Helper: extract the `layer=` and `version=` tokens from a `ds:` EDE text ─
// Both route through the single `parse_ds_ede` grammar parser above, so the token
// spellings/order live in exactly one place.

/// Parse the `layer=<value>` token from a `ds:`-prefixed EDE extra-text.
fn ede_layer_value(ede_text: &str) -> Option<&str> {
    parse_ds_ede(ede_text).map(|p| p.layer)
}

/// Parse the `version=<value>` token from a `ds:`-prefixed EDE extra-text.
fn ede_version_value(ede_text: &str) -> Option<&str> {
    parse_ds_ede(ede_text).map(|p| p.version)
}

// ── Test: the EDE-15 `ds:` grammar is pinned (the single positive shape assertion) ──

/// GRAMMAR PIN: author a single real deny WITH OPT through the gate and assert the FULL
/// EDE-15 `ds:` EXTRA-TEXT grammar ONCE, positively, at one obvious site:
///
///   * the `ds:` prefix is present;
///   * the body is EXACTLY three space-separated `key=value` tokens, in the FIXED order
///     `rule=` then `layer=` then `version=` (the POL-3 triple on the wire);
///   * every one of the three values is NON-EMPTY;
///   * the parsed triple matches the verdict's seam provenance (rule_id / layer / version).
///
/// The layer/version-axis and hot-reload/no-restamp tests below all `.contains(...)` /
/// substring-match these same tokens through the shared `parse_ds_ede` parser. Before this
/// pin a handler.rs reformat of the `ds:` grammar (e.g. reordering the tokens, renaming a
/// key, or dropping a space) would silently skew those parsers with no failure naming the
/// grammar. With this test, ANY such reformat breaks HERE first — one obvious place — so the
/// downstream assertions never silently rot. Asserts the SAME landed grammar the handler
/// authors (`ede_blocked_option`: `ds:rule=<id> layer=<layer> version=<ver>`); it does NOT
/// change handler authoring. Loopback / synthetic only — a Deny never forwards.
#[tokio::test]
async fn ds_ede_extra_text_grammar_is_pinned() {
    let gate = policy_gate().await;
    // `dns.google` is blocklisted; the query carries OPT so the §3.2 EDE-15 attaches.
    let (udp, tcp) =
        both_transports(&gate, &query_of(0x0DDE, "dns.google.", RecordType::A, true)).await;

    for (msg, transport) in [(&udp, "udp"), (&tcp, "tcp")] {
        let text = ede_blocked_text(msg)
            .unwrap_or_else(|| panic!("EDE 15 present with a query OPT ({transport}): {msg:?}"));

        // (1) the `ds:` prefix.
        assert!(
            text.starts_with(EDE_DS_PREFIX),
            "EDE EXTRA-TEXT is `ds:`-prefixed ({transport}): {text:?}"
        );

        // (2) the body is EXACTLY the three tokens, in the fixed rule/layer/version order,
        //     space-separated — asserted independently of the parser so a token reorder or
        //     a stray extra/missing token is caught structurally here.
        let body = text
            .strip_prefix(EDE_DS_PREFIX)
            .expect("body follows the ds: prefix");
        let tokens: Vec<&str> = body.split_whitespace().collect();
        assert_eq!(
            tokens.len(),
            3,
            "the `ds:` body is EXACTLY three space-separated tokens ({transport}): {text:?}"
        );
        assert!(
            tokens[0].starts_with(EDE_RULE_TOKEN),
            "token 0 is the `rule=` token ({transport}): {text:?}"
        );
        assert!(
            tokens[1].starts_with(EDE_LAYER_TOKEN),
            "token 1 is the `layer=` token ({transport}): {text:?}"
        );
        assert!(
            tokens[2].starts_with(EDE_VERSION_TOKEN),
            "token 2 is the `version=` token ({transport}): {text:?}"
        );

        // (3) the shared parser accepts the grammar and yields the POL-3 triple, every
        //     value NON-EMPTY. This is the routed view every downstream assertion uses.
        let parsed = parse_ds_ede(&text)
            .unwrap_or_else(|| panic!("the `ds:` grammar parses ({transport}): {text:?}"));
        assert!(
            !parsed.rule.is_empty(),
            "the `rule=` value is non-empty ({transport}): {text:?}"
        );
        assert!(
            !parsed.layer.is_empty(),
            "the `layer=` value is non-empty ({transport}): {text:?}"
        );
        assert!(
            !parsed.version.is_empty(),
            "the `version=` value is non-empty ({transport}): {text:?}"
        );

        // (4) the parsed triple matches the verdict's seam provenance — the grammar carries
        //     the SAME POL-3 triple the evaluator stamps (rule names the blocked domain).
        assert!(
            parsed.rule.contains("dns.google"),
            "the `rule=` value names the blocklisted domain ({transport}): {text:?}"
        );
    }

    // Cross-check against the seam provenance directly: the on-wire triple is the SAME
    // rule_id / policy_layer / policy_version the evaluator authors for this deny.
    let verdict: DnsVerdict = policy().evaluate(&DnsQueryCtx {
        session: "grammar-pin".to_string(),
        qname: "dns.google.".to_string(),
        qtype: u16::from(RecordType::A),
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
    });
    let prov = verdict.provenance();
    let wire = ede_blocked_text(&udp).expect("udp deny carries EDE 15");
    let parsed = parse_ds_ede(&wire).expect("the udp `ds:` grammar parses");
    assert_eq!(
        parsed.rule, prov.rule_id,
        "the EDE `rule=` value equals the seam rule_id: wire={wire:?} prov={prov:?}"
    );
    assert_eq!(
        parsed.layer, prov.policy_layer,
        "the EDE `layer=` value equals the seam policy_layer: wire={wire:?} prov={prov:?}"
    );
    assert_eq!(
        parsed.version, prov.policy_version,
        "the EDE `version=` value equals the seam policy_version: wire={wire:?} prov={prov:?}"
    );

    // (5) POSITIVE handler-conformance: the on-wire EDE text is BYTE-IDENTICAL to the
    //     handler's own canonical renderer `format_ede_extra_text(prov)` — the single
    //     source of truth the emitter (`ede_blocked_option`) calls. This is the assertion
    //     that makes the grammar one-sided edits FAIL LOUDLY: any reform of the spelling or
    //     token order in handler.rs changes BOTH sides of this equality in lock-step, but a
    //     test (or any consumer) that re-spelled the grammar by hand would diverge from the
    //     renderer here. The grammar can only ever live in one place — handler.rs.
    assert_eq!(
        wire,
        format_ede_extra_text(prov),
        "the emitted EDE EXTRA-TEXT conforms to the handler's canonical \
         `format_ede_extra_text` renderer (single source of truth): wire={wire:?} prov={prov:?}"
    );

    gate.shutdown().await.unwrap();
}

// ── Tests: LAYER axis ────────────────────────────────────────────────────────

/// SEAM-LEVEL: the SAME baseline-pack `rule_id` (`baseline-pack:core/shared.example`)
/// evaluated against a `system-baseline` vs an `org` layer carries DISTINCT
/// `policy_layer` provenance — `"system-baseline"` vs `"org"` — while the
/// `rule_id` and `policy_version` are identical. POL-3: the full triple is intact
/// on both verdicts; a LOG-1 join keyed on `policy_layer` can tell the two apart.
///
/// This asserts the LAYER axis of the inert-vs-deny provenance fingerprint test:
/// the same rule-id can appear at different layers and the LOG-1 provenance
/// preserves that distinction so downstream joins never conflate them.
#[test]
fn same_rule_id_at_different_layers_carries_distinct_policy_layer_in_provenance() {
    fn ctx(qname: &str) -> DnsQueryCtx {
        DnsQueryCtx {
            session: "layer-axis-test".to_string(),
            qname: qname.to_string(),
            qtype: u16::from(RecordType::A),
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        }
    }

    // Two policy evaluators — one from a system-baseline layer, one from an org layer.
    // Both have `shared.example` as an enabled-family core pack entry; no capabilities
    // are provided (compose(&[layer], &[])), so the entry is NOT inert (no `requires:`).
    let p_baseline = policy_from(LAYER_BASELINE_PACK_V0);
    let p_org = policy_from(LAYER_BASELINE_PACK_ORG);

    let v_baseline: DnsVerdict = p_baseline.evaluate(&ctx("shared.example."));
    let v_org: DnsVerdict = p_org.evaluate(&ctx("shared.example."));

    // Both verdicts are Allow (enabled core family, no capability gate).
    assert!(
        v_baseline.admits(),
        "system-baseline shared.example is Allow: {v_baseline:?}"
    );
    assert!(v_org.admits(), "org shared.example is Allow: {v_org:?}");

    let prov_baseline = v_baseline.provenance();
    let prov_org = v_org.provenance();

    // (1) SAME rule_id — baseline-pack entry always produces `baseline-pack:<family>/<fqdn>`.
    assert_eq!(
        prov_baseline.rule_id, prov_org.rule_id,
        "the same pack entry produces the same rule_id regardless of layer"
    );
    assert!(
        prov_baseline.rule_id.starts_with("baseline-pack:"),
        "the rule_id has the baseline-pack: prefix: {:?}",
        prov_baseline.rule_id
    );
    assert!(
        prov_baseline.rule_id.contains("shared.example"),
        "the rule_id names the pack fqdn: {:?}",
        prov_baseline.rule_id
    );

    // (2) DISTINCT policy_layer — this is the LAYER axis: the same pack entry sourced
    // from different layer documents carries the composing layer's name.
    assert_ne!(
        prov_baseline.policy_layer, prov_org.policy_layer,
        "the LAYER axis: system-baseline vs org provenance differs on policy_layer"
    );
    assert_eq!(
        prov_baseline.policy_layer, "system-baseline",
        "system-baseline layer carries policy_layer=system-baseline"
    );
    assert_eq!(
        prov_org.policy_layer, "org",
        "org layer carries policy_layer=org"
    );

    // (3) POL-3: the full triple (rule_id / policy_layer / policy_version) is intact
    // on BOTH verdicts — the layer axis never drops any field.
    for (label, prov) in [("baseline", prov_baseline), ("org", prov_org)] {
        assert!(
            !prov.rule_id.is_empty()
                && !prov.policy_layer.is_empty()
                && !prov.policy_version.is_empty(),
            "the {label} verdict carries the full POL-3 triple: {prov:?}"
        );
    }
}

// ── Tests: VERSION axis ──────────────────────────────────────────────────────

/// SEAM-LEVEL: the SAME blocklist rule (`blocklist:version-bump.example`) evaluated
/// under policy-version N (`schema_version: 2026.06.12-v0`) vs N+1
/// (`schema_version: 2026.06.12-v1`) carries the SAME `rule_id` and `policy_layer`
/// but DISTINCT `policy_version` — so a LOG-1 join keyed on `policy_version` can
/// tell pre-bump and post-bump denies apart despite the identical wire shape.
///
/// This asserts the VERSION axis of the inert-vs-deny provenance fingerprint test:
/// a policy bump that leaves the rule unchanged still produces a distinct provenance
/// triple, keeping version-keyed joins correct when the pack rev changes.
#[test]
fn same_rule_id_at_different_policy_versions_carries_distinct_policy_version_in_provenance() {
    fn ctx(qname: &str) -> DnsQueryCtx {
        DnsQueryCtx {
            session: "version-axis-test".to_string(),
            qname: qname.to_string(),
            qtype: u16::from(RecordType::A),
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        }
    }

    // Two policy evaluators — identical blocklist rule, only `schema_version` differs.
    let p_v0 = policy_from(LAYER_BLOCKLIST_VERSION_N);
    let p_v1 = policy_from(LAYER_BLOCKLIST_VERSION_N_PLUS_1);

    let deny_v0: DnsVerdict = p_v0.evaluate(&ctx("version-bump.example."));
    let deny_v1: DnsVerdict = p_v1.evaluate(&ctx("version-bump.example."));

    // Both are Deny (blocklist; the rule is unchanged between versions).
    assert!(
        matches!(deny_v0, DnsVerdict::Deny { .. }),
        "version-N deny is Deny: {deny_v0:?}"
    );
    assert!(
        matches!(deny_v1, DnsVerdict::Deny { .. }),
        "version-N+1 deny is Deny: {deny_v1:?}"
    );
    assert!(!deny_v0.admits());
    assert!(!deny_v1.admits());

    let prov_v0 = deny_v0.provenance();
    let prov_v1 = deny_v1.provenance();

    // (1) SAME rule_id — the blocklist rule is identical; only the version changed.
    assert_eq!(
        prov_v0.rule_id, prov_v1.rule_id,
        "the same blocklist rule produces the same rule_id across version bumps"
    );
    assert!(
        prov_v0.rule_id.starts_with("blocklist:"),
        "the blocklist rule_id has the blocklist: prefix: {:?}",
        prov_v0.rule_id
    );
    assert!(
        prov_v0.rule_id.contains("version-bump.example"),
        "the rule_id names the blocked domain: {:?}",
        prov_v0.rule_id
    );

    // (2) SAME policy_layer — both at system-baseline.
    assert_eq!(
        prov_v0.policy_layer, prov_v1.policy_layer,
        "the policy_layer is the same (system-baseline) across a version bump"
    );

    // (3) DISTINCT policy_version — this is the VERSION axis: a schema_version bump
    // stamps the new version onto every verdict produced under that policy, even for
    // rules that did not change. A downstream LOG-1 join keyed on policy_version can
    // thus tell pre-bump and post-bump traffic apart.
    assert_ne!(
        prov_v0.policy_version, prov_v1.policy_version,
        "the VERSION axis: a schema_version bump produces distinct policy_version provenance"
    );
    assert_eq!(
        prov_v0.policy_version, "2026.06.12-v0",
        "version-N policy carries policy_version=2026.06.12-v0"
    );
    assert_eq!(
        prov_v1.policy_version, "2026.06.12-v1",
        "version-N+1 policy carries policy_version=2026.06.12-v1"
    );

    // (4) POL-3: the full triple is intact on BOTH verdicts.
    for (label, prov) in [("v0", prov_v0), ("v1", prov_v1)] {
        assert!(
            !prov.rule_id.is_empty()
                && !prov.policy_layer.is_empty()
                && !prov.policy_version.is_empty(),
            "the {label} verdict carries the full POL-3 triple: {prov:?}"
        );
    }
}

// ── Tests: VERSION axis on LOG-1 + EDE-15 (wire) ────────────────────────────

/// WIRE + LOG-1: the same blocked domain at two different policy versions emits
/// LOG-1 `DnsEvent` provenance triples that split on the VERSION axis — DISTINCT
/// `policy_version` — while staying identical on `rule_id`. The EDE-15 `ds:`
/// EXTRA-TEXT carries `version=` in its `ds:rule=<id> layer=<layer> version=<ver>`
/// encoding (already present in the handler; handler.rs is NOT modified this wave),
/// so the secondary EDE channel also distinguishes the two versions.
///
/// This is the wire-path analogue of the seam-level version-axis test: proving the
/// `event_provenance` bridge in the handler stamps the live policy_version onto the
/// LOG-1 event and the EDE text, not a stale cached value, so a version-keyed join
/// over the telemetry stream stays correct after a hot-reload policy bump.
#[tokio::test]
async fn same_rule_at_different_policy_versions_splits_log1_provenance_and_ede_text() {
    use hickory_server::net::xfer::Protocol;
    use hickory_server::net::BufDnsStreamHandle;
    use hickory_server::server::{Request, RequestHandler, ResponseHandle};

    // ── Version-N handler ──────────────────────────────────────────────────────
    let sink_v0 = CapturingSink::new();
    let handler_v0 = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        policy_from(LAYER_BLOCKLIST_VERSION_N),
        ForwarderConfig::default(),
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(sink_v0.clone()),
    );

    // ── Version-N+1 handler ───────────────────────────────────────────────────
    let sink_v1 = CapturingSink::new();
    let handler_v1 = StubRequestHandler::with_forwarder_boundary_zone_and_sink(
        policy_from(LAYER_BLOCKLIST_VERSION_N_PLUS_1),
        ForwarderConfig::default(),
        DEFAULT_BOUNDARY_ZONE,
        Arc::new(sink_v1.clone()),
    );

    // Drive a deny through each handler (query carries OPT so EDE-15 attaches).
    let src = SocketAddr::from((Ipv4Addr::LOCALHOST, 5302));

    async fn author_deny<H: RequestHandler>(handler: &H, src: SocketAddr, domain: &str) -> Message {
        use futures_util::StreamExt;
        let bytes = query_of(0x7001, domain, RecordType::A, true);
        let request = Request::from_bytes(bytes, src, Protocol::Udp).unwrap();
        let (stream_handle, mut rx) = BufDnsStreamHandle::new(src);
        let rh = ResponseHandle::new(src, stream_handle, Protocol::Udp);
        let _ = RequestHandler::handle_request::<_, hickory_server::net::runtime::TokioTime>(
            handler, &request, rh,
        )
        .await;
        let serial = tokio::time::timeout(Duration::from_millis(500), rx.next())
            .await
            .expect("handler authored a response in time")
            .expect("a response was sent");
        let (resp_bytes, _addr) = serial.into_parts();
        Message::from_vec(&resp_bytes).expect("response decodes")
    }

    let resp_v0 = author_deny(&handler_v0, src, "version-bump.example.").await;
    let event_v0 = sink_v0.events().last().cloned().expect("v0 event emitted");

    let resp_v1 = author_deny(&handler_v1, src, "version-bump.example.").await;
    let event_v1 = sink_v1.events().last().cloned().expect("v1 event emitted");

    // ── Wire shape: both are identical NXDOMAIN (no version signal on the wire) ──
    assert_nxdomain_with_signature_soa(&resp_v0, "v0-deny");
    assert_nxdomain_with_signature_soa(&resp_v1, "v1-deny");
    assert_eq!(
        resp_v0.metadata.response_code, resp_v1.metadata.response_code,
        "both versions author the identical NXDOMAIN rcode (no version signal on the wire)"
    );

    // ── LOG-1 provenance: SAME rule_id, DISTINCT policy_version ─────────────────
    assert_eq!(
        event_v0.provenance.rule_id, event_v1.provenance.rule_id,
        "the LOG-1 join: same rule_id across a version bump"
    );
    assert_ne!(
        event_v0.provenance.policy_version, event_v1.provenance.policy_version,
        "the LOG-1 VERSION axis: policy_version stamps the live schema_version onto every event"
    );
    assert_eq!(
        event_v0.provenance.policy_version, "2026.06.12-v0",
        "the v0 LOG-1 event carries policy_version=2026.06.12-v0: {:?}",
        event_v0.provenance
    );
    assert_eq!(
        event_v1.provenance.policy_version, "2026.06.12-v1",
        "the v1 LOG-1 event carries policy_version=2026.06.12-v1: {:?}",
        event_v1.provenance
    );

    // POL-3: the full triple is intact on both events.
    for (label, ev) in [("v0", &event_v0), ("v1", &event_v1)] {
        assert!(
            !ev.provenance.rule_id.is_empty()
                && !ev.provenance.policy_layer.is_empty()
                && !ev.provenance.policy_version.is_empty(),
            "the {label} LOG-1 event carries the full POL-3 triple: {:?}",
            ev.provenance
        );
    }

    // ── EDE-15 `ds:` extra-text: carries `layer=` and `version=` ───────────────
    // The handler already encodes `ds:rule={} layer={} version={}` (handler.rs line
    // ~260: `format!("{EDE_EXTRA_TEXT_PREFIX}rule={} layer={} version={}"...)`).
    // Assert that the EDE text carries BOTH tokens and that the VERSION axis is
    // visible there too (the primary channel is LOG-1; EDE is the secondary channel).
    let ede_v0 = ede_blocked_text(&resp_v0)
        .unwrap_or_else(|| panic!("v0 deny NXDOMAIN-with-OPT carries EDE 15: {resp_v0:?}"));
    let ede_v1 = ede_blocked_text(&resp_v1)
        .unwrap_or_else(|| panic!("v1 deny NXDOMAIN-with-OPT carries EDE 15: {resp_v1:?}"));

    // Both EDE texts are `ds:`-prefixed.
    assert!(
        ede_v0.starts_with(EDE_DS_PREFIX),
        "v0 EDE text is ds:-prefixed: {ede_v0:?}"
    );
    assert!(
        ede_v1.starts_with(EDE_DS_PREFIX),
        "v1 EDE text is ds:-prefixed: {ede_v1:?}"
    );

    // Both carry a `layer=` token.
    let ede_v0_layer = ede_layer_value(&ede_v0)
        .unwrap_or_else(|| panic!("v0 EDE text carries layer= token: {ede_v0:?}"));
    let ede_v1_layer = ede_layer_value(&ede_v1)
        .unwrap_or_else(|| panic!("v1 EDE text carries layer= token: {ede_v1:?}"));
    // Both are from the same system-baseline layer.
    assert_eq!(
        ede_v0_layer, ede_v1_layer,
        "both EDE texts carry the same layer= (system-baseline): v0={ede_v0_layer:?} v1={ede_v1_layer:?}"
    );

    // Both carry a `version=` token — and the VERSION axis is visible in the EDE text.
    let ede_v0_version = ede_version_value(&ede_v0)
        .unwrap_or_else(|| panic!("v0 EDE text carries version= token: {ede_v0:?}"));
    let ede_v1_version = ede_version_value(&ede_v1)
        .unwrap_or_else(|| panic!("v1 EDE text carries version= token: {ede_v1:?}"));
    assert_ne!(
        ede_v0_version, ede_v1_version,
        "the EDE VERSION axis: distinct version= tokens distinguish pre- and post-bump denies: \
         v0={ede_v0_version:?} v1={ede_v1_version:?}"
    );
    assert_eq!(
        ede_v0_version, "2026.06.12-v0",
        "v0 EDE carries version=2026.06.12-v0: {ede_v0:?}"
    );
    assert_eq!(
        ede_v1_version, "2026.06.12-v1",
        "v1 EDE carries version=2026.06.12-v1: {ede_v1:?}"
    );
}

// ===========================================================================
// HOT-RELOAD propagation: policy_version + policy_layer at the WIRE level
//
// The seam-level tests above (same_rule_at_different_policy_versions_*) proved that
// two DISTINCT PolicyCorePolicy evaluators carry distinct provenance triple fields.
// These tests assert that a LIVE GATE whose evaluator is HOT-RELOADED via the
// snapshot-subscriber path (watch_snapshots + SnapshotCommitSink) propagates the
// NEW version / layer to the WIRE:
//
//   * The LOG-1 DnsEvent.provenance carries the NEW policy_version/policy_layer
//     IMMEDIATELY after the committed snapshot re-sources the running evaluator.
//   * The EDE-15 `ds:` EXTRA-TEXT (version= / layer= tokens) reflects the NEW
//     values — proving no stale-version caching survives a reload on the wire.
//   * The PRE-reload queries carry the OLD values (regression net: reload didn't
//     accidentally retroactively change already-authored responses).
//
// Both tests drive a real loopback-bound gate through spawn_gate_with_sink
// (so the CapturingSink captures the handler's LOG-1 events), commit a
// BoundarySnapshot::with_policy via watch_snapshots + SnapshotCommitSink, then
// re-query to assert the new provenance propagated all the way to the wire.
// Loopback / synthetic only — no live claude/cia/podman/policy-stream.
// ===========================================================================

/// Layer policies used by the hot-reload propagation tests.
///
/// Two blocklist-only layers covering `reload-probe.example` at DISTINCT
/// `schema_version` values — everything else (rule-id, layer, fqdn) identical.
/// Driving a deny through the gate at v0 then reloading to v1 makes the
/// policy_version flip observable on the wire (LOG-1 event + EDE-15 text)
/// WITHOUT flipping the verdict shape (both are the §3.2 NXDOMAIN hard deny).
const LAYER_RELOAD_V0: &str = r#"
schema_version: 2026.06.12-v0
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
blocklist:
  - domain: reload-probe.example
    reason: reload-version-test
    rung: kill+snapshot
"#;

const LAYER_RELOAD_V1: &str = r#"
schema_version: 2026.06.12-v1
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
blocklist:
  - domain: reload-probe.example
    reason: reload-version-test
    rung: kill+snapshot
"#;

/// Two baseline-pack layers for `layer-probe.example` at DISTINCT layer names —
/// one `system-baseline`, one `org`. The entry has `requires: needs-capability` so
/// it is INERT (no capability is injected via `compose(&[layer], &[])`), which
/// produces a Deny whose `policy_layer` is the `source_layer` from the pack entry —
/// `"system-baseline"` or `"org"` respectively. The policy_version is the SAME in
/// both layers; ONLY the composing layer name flips. Used by the LAYER-axis hot-reload
/// test to assert the layer propagates to the LOG-1 event and EDE-15 `ds:` text after
/// a subscriber-driven reload.
///
/// NOTE: Blocklist denies always carry `policy_layer: "composed"` (the composition of
/// all layers, not the sourcing layer — see pol1_eval.rs evaluate_domain). The
/// baseline-pack inert arm carries the SOURCING layer name (`source_layer`), which is
/// the per-pack-entry value that reflects the composing layer's identity. Using an inert
/// pack entry here is the correct way to observe the layer axis on a Deny path.
const LAYER_RELOAD_BASELINE: &str = r#"
schema_version: 2026.06.12-v0
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries:
    - fqdn: layer-probe.example
      family: core
      ports: [443]
      requires: needs-capability
      provenance_source_url: https://example.test/meta
      evidence: vendor-doc
"#;

const LAYER_RELOAD_ORG: &str = r#"
schema_version: 2026.06.12-v0
layer: org
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries:
    - fqdn: layer-probe.example
      family: core
      ports: [443]
      requires: needs-capability
      provenance_source_url: https://example.test/meta
      evidence: vendor-doc
"#;

/// Drive one query against the gate's UDP transport and return the (parsed response,
/// last LOG-1 event captured by the sink) pair.  The query always carries an OPT record
/// so the §3.2 EDE-15 attaches on a Deny, making the `ds:` text observable.
///
/// NOTE: This helper is local to the hot-reload sub-tests and distinct from the
/// top-level `udp_round_trip`; it also returns the captured event, which the
/// reload tests need.
async fn deny_and_capture(
    gate_udp: SocketAddr,
    sink: &CapturingSink,
    name: &str,
    msg_id: u16,
) -> (hickory_proto::op::Message, crate::DnsEvent) {
    let query = query_of(msg_id, name, hickory_proto::rr::RecordType::A, true);
    let resp_bytes = udp_round_trip(gate_udp, &query).await;
    let resp = hickory_proto::op::Message::from_vec(&resp_bytes).expect("response decodes");
    let event = sink
        .events()
        .last()
        .cloned()
        .expect("handler emitted at least one LOG-1 event");
    (resp, event)
}

use ds_dnsgate::policy::TtlClamp;
use ds_dnsgate::server::{
    boundary_snapshot_feed, watch_snapshots, BoundarySnapshot, GatePolicyReloader,
    SnapshotCommitSink,
};
use ds_dnsgate::DnsEvent;

/// HOT-RELOAD VERSION AXIS (wire-level): after the snapshot-subscriber commits a
/// BoundarySnapshot carrying a NEW policy version (v1) via watch_snapshots +
/// SnapshotCommitSink, a subsequent query's LOG-1 DnsEvent provenance and EDE-15
/// `ds:` text reflect the NEW policy_version — not the pre-reload v0 value.
///
/// This closes the wire-level gap the policy.rs internal reload test (wave28) left:
/// that test proved PolicyCorePolicy::reload changes the verdict; this test proves
/// the SUBSCRIBER-DRIVEN path (SnapshotCommitSink / watch_snapshots, the production
/// committed-snapshot path) propagates the change all the way to the LOG-1 event and
/// the EDE-15 extra-text on the wire — no stale-version caching, no per-transport skew.
#[tokio::test]
async fn hot_reload_new_policy_version_propagates_to_log1_event_and_ede_text() {
    // ── Start the gate at version v0 ─────────────────────────────────────────
    let sink = CapturingSink::new();
    let policy_v0 = policy_from(LAYER_RELOAD_V0);
    let gate = ds_dnsgate::spawn_gate_with_sink(
        policy_v0,
        GateConfig::default(),
        std::sync::Arc::new(sink.clone()),
    )
    .await
    .expect("gate binds on loopback");

    let udp_addr = gate.udp_local_addr();

    // ── PRE-RELOAD: query under v0, assert old version in event + EDE ────────
    let (pre_resp, pre_event) =
        deny_and_capture(udp_addr, &sink, "reload-probe.example.", 0x8001).await;
    assert_nxdomain_with_signature_soa(&pre_resp, "pre-reload/udp");

    assert_eq!(
        pre_event.provenance.policy_version, "2026.06.12-v0",
        "pre-reload LOG-1 event carries the v0 policy_version: {:?}",
        pre_event.provenance
    );
    let pre_ede = ede_blocked_text(&pre_resp)
        .expect("pre-reload NXDOMAIN-with-OPT carries EDE 15: {pre_resp:?}");
    assert!(
        pre_ede.starts_with(EDE_DS_PREFIX),
        "pre-reload EDE text is ds:-prefixed: {pre_ede:?}"
    );
    let pre_ede_version =
        ede_version_value(&pre_ede).expect("pre-reload EDE text carries version= token");
    assert_eq!(
        pre_ede_version, "2026.06.12-v0",
        "pre-reload EDE carries version=2026.06.12-v0: {pre_ede:?}"
    );

    // ── COMMIT v1 via the subscriber path ─────────────────────────────────────
    // Build a BoundarySnapshot carrying the v1 composed policy.  The zone stays at
    // the default ("boundary") because the reload-probe blocklist test doesn't care
    // about the SOA suffix — only the evaluator re-source matters here.
    let layer_v1 = parse_layer(LAYER_RELOAD_V1).expect("v1 layer parses");
    let composed_v1 = compose(&[layer_v1], &[]);

    let snapshot = BoundarySnapshot::with_policy(
        10,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_v1,
        TtlClamp::DEFAULT,
    );

    // Wire the SnapshotCommitSink from the gate's detached reload handles.
    let bz_reloader = gate.boundary_zone_reloader();
    let pol_reloader: GatePolicyReloader = gate.policy_reloader();
    let commit_sink = SnapshotCommitSink::new(bz_reloader, pol_reloader);

    // Drive the subscriber loop synchronously over a single published snapshot, then
    // drop the feed so the loop exits (mirrors the `main` shutdown pattern).
    let (feed, subscription) = boundary_snapshot_feed(4);
    feed.publish(snapshot).await.expect("subscriber alive");
    drop(feed); // close the channel; watch_snapshots returns on the next poll

    let commits = watch_snapshots(subscription, &commit_sink).await;
    assert_eq!(commits, 1, "exactly one forward-seq snapshot committed");

    // Gate still running — the reload is admitter-LAST and the listeners were NOT rebound.
    assert_eq!(
        gate.policy_version(),
        "2026.06.12-v1",
        "the running gate's evaluator is now at v1 after the subscriber commit"
    );

    // ── POST-RELOAD: query under v1, assert new version in event + EDE ────────
    let (post_resp, post_event) =
        deny_and_capture(udp_addr, &sink, "reload-probe.example.", 0x8002).await;
    assert_nxdomain_with_signature_soa(&post_resp, "post-reload/udp");

    // LOG-1: the NEW policy_version stamps the event — no stale v0 caching.
    assert_eq!(
        post_event.provenance.policy_version, "2026.06.12-v1",
        "post-reload LOG-1 event carries the NEW policy_version=2026.06.12-v1: {:?}",
        post_event.provenance
    );
    // rule_id and policy_layer are unchanged (the rule and layer are the same; only
    // schema_version bumped) — confirming the reload changed ONLY the version field.
    assert_eq!(
        post_event.provenance.rule_id, pre_event.provenance.rule_id,
        "the rule_id is unchanged across the version-only bump: {:?}",
        post_event.provenance
    );
    assert_eq!(
        post_event.provenance.policy_layer, pre_event.provenance.policy_layer,
        "the policy_layer is unchanged across the version-only bump: {:?}",
        post_event.provenance
    );
    // POL-3: the full triple is non-empty on the post-reload event.
    assert!(
        !post_event.provenance.rule_id.is_empty()
            && !post_event.provenance.policy_layer.is_empty()
            && !post_event.provenance.policy_version.is_empty(),
        "post-reload LOG-1 event carries the full POL-3 triple: {:?}",
        post_event.provenance
    );

    // EDE-15: the `ds:` version= token carries the NEW version on the wire.
    let post_ede = ede_blocked_text(&post_resp)
        .expect("post-reload NXDOMAIN-with-OPT carries EDE 15: {post_resp:?}");
    assert!(
        post_ede.starts_with(EDE_DS_PREFIX),
        "post-reload EDE text is ds:-prefixed: {post_ede:?}"
    );
    let post_ede_version =
        ede_version_value(&post_ede).expect("post-reload EDE text carries version= token");
    assert_eq!(
        post_ede_version, "2026.06.12-v1",
        "post-reload EDE carries the NEW version=2026.06.12-v1 — no stale v0 caching: {post_ede:?}"
    );
    // Regression net: the pre-reload and post-reload EDE texts differ on the version axis.
    assert_ne!(
        pre_ede_version, post_ede_version,
        "the EDE version= token flipped from v0 to v1 after the reload"
    );

    gate.shutdown().await.expect("gate shutdown");
}

/// HOT-RELOAD LAYER AXIS (wire-level): after the snapshot-subscriber commits a
/// BoundarySnapshot carrying a NEW policy_layer ("org" instead of "system-baseline")
/// via watch_snapshots + SnapshotCommitSink, a subsequent query's LOG-1 DnsEvent
/// provenance and EDE-15 `ds:` text reflect the NEW policy_layer — not the pre-reload
/// "system-baseline" value.
///
/// This asserts the SECOND axis of the LOG-1 provenance triple: a hot-reload that
/// changes only the composing layer name stamps every subsequent verdict's
/// policy_layer with the new name — the wire-level analogue of the seam-level
/// `same_rule_id_at_different_layers_carries_distinct_policy_layer_in_provenance` test.
///
/// The probe uses a baseline-pack INERT entry (requires: needs-capability, no capability
/// injected) for `layer-probe.example` — so the verdict is a Deny (folds into the §3.2
/// NXDOMAIN shape) whose `policy_layer` is the SOURCING layer name (`source_layer` from
/// the pack entry: "system-baseline" or "org"), not the always-"composed" blocklist layer.
/// This is the correct way to observe the layer axis on a Deny path (see pol1_eval.rs
/// evaluate_domain: blocklist denies always carry `policy_layer: "composed"`; only the
/// pack-entry and allowlist paths carry the per-layer source name).
#[tokio::test]
async fn hot_reload_new_policy_layer_propagates_to_log1_event_and_ede_text() {
    // ── Start the gate at "system-baseline" layer (inert pack entry) ──────────
    let sink = CapturingSink::new();
    let policy_baseline = policy_from(LAYER_RELOAD_BASELINE);
    let gate = ds_dnsgate::spawn_gate_with_sink(
        policy_baseline,
        GateConfig::default(),
        std::sync::Arc::new(sink.clone()),
    )
    .await
    .expect("gate binds on loopback");

    let udp_addr = gate.udp_local_addr();

    // ── PRE-RELOAD: query layer-probe.example under system-baseline ───────────
    // The entry is INERT (requires: needs-capability, capability absent) — it folds to
    // the §3.2 NXDOMAIN hard-deny shape with `policy_layer: "system-baseline"`.
    let (pre_resp, pre_event) =
        deny_and_capture(udp_addr, &sink, "layer-probe.example.", 0x9001).await;
    assert_nxdomain_with_signature_soa(&pre_resp, "pre-reload-layer/udp");

    assert_eq!(
        pre_event.provenance.policy_layer, "system-baseline",
        "pre-reload LOG-1 event carries system-baseline layer: {:?}",
        pre_event.provenance
    );
    let pre_ede = ede_blocked_text(&pre_resp)
        .expect("pre-reload NXDOMAIN-with-OPT carries EDE 15: {pre_resp:?}");
    let pre_ede_layer =
        ede_layer_value(&pre_ede).expect("pre-reload EDE text carries layer= token");
    assert_eq!(
        pre_ede_layer, "system-baseline",
        "pre-reload EDE carries layer=system-baseline: {pre_ede:?}"
    );

    // ── COMMIT the "org" layer via the subscriber path ────────────────────────
    let layer_org = parse_layer(LAYER_RELOAD_ORG).expect("org layer parses");
    let composed_org = compose(&[layer_org], &[]);

    let snapshot = BoundarySnapshot::with_policy(
        20,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_org,
        TtlClamp::DEFAULT,
    );

    let bz_reloader = gate.boundary_zone_reloader();
    let pol_reloader: GatePolicyReloader = gate.policy_reloader();
    let commit_sink = SnapshotCommitSink::new(bz_reloader, pol_reloader);

    let (feed, subscription) = boundary_snapshot_feed(4);
    feed.publish(snapshot).await.expect("subscriber alive");
    drop(feed);

    let commits = watch_snapshots(subscription, &commit_sink).await;
    assert_eq!(commits, 1, "exactly one forward-seq snapshot committed");

    // ── POST-RELOAD: query layer-probe.example under org layer ───────────────
    let (post_resp, post_event) =
        deny_and_capture(udp_addr, &sink, "layer-probe.example.", 0x9002).await;
    assert_nxdomain_with_signature_soa(&post_resp, "post-reload-layer/udp");

    // LOG-1: the NEW policy_layer stamps the event — no stale system-baseline caching.
    assert_eq!(
        post_event.provenance.policy_layer, "org",
        "post-reload LOG-1 event carries the NEW policy_layer=org: {:?}",
        post_event.provenance
    );
    // rule_id is unchanged (same pack entry fqdn); policy_version is unchanged
    // (same schema_version) — ONLY the composing layer name flipped.
    assert_eq!(
        post_event.provenance.rule_id, pre_event.provenance.rule_id,
        "the rule_id is unchanged across the layer-only flip: {:?}",
        post_event.provenance
    );
    assert_eq!(
        post_event.provenance.policy_version, pre_event.provenance.policy_version,
        "the policy_version is unchanged across the layer-only flip: {:?}",
        post_event.provenance
    );
    // POL-3: the full triple is non-empty on the post-reload event.
    assert!(
        !post_event.provenance.rule_id.is_empty()
            && !post_event.provenance.policy_layer.is_empty()
            && !post_event.provenance.policy_version.is_empty(),
        "post-reload LOG-1 event carries the full POL-3 triple: {:?}",
        post_event.provenance
    );

    // EDE-15: the `ds:` layer= token carries the NEW layer on the wire.
    let post_ede = ede_blocked_text(&post_resp)
        .expect("post-reload NXDOMAIN-with-OPT carries EDE 15: {post_resp:?}");
    let post_ede_layer =
        ede_layer_value(&post_ede).expect("post-reload EDE text carries layer= token");
    assert_eq!(
        post_ede_layer, "org",
        "post-reload EDE carries the NEW layer=org — no stale system-baseline caching: {post_ede:?}"
    );
    // Regression net: the pre-reload and post-reload EDE texts differ on the layer axis.
    assert_ne!(
        pre_ede_layer, post_ede_layer,
        "the EDE layer= token flipped from system-baseline to org after the reload"
    );

    gate.shutdown().await.expect("gate shutdown");
}

// ===========================================================================
// MID-FLIGHT reload: an already-authored response is NEVER retroactively
// re-stamped (the no-restamp invariant)
//
// The hot-reload propagation tests above prove the FORWARD direction: a query
// authored AFTER a reload commit carries the NEW version/layer. They do NOT
// prove the complementary invariant — that a response authored BEFORE a reload
// commit retains its ORIGINAL EDE-15 ds: version/layer text and LOG-1 provenance,
// with NO retroactive re-stamp. This is the stale-event gap the spec names: the
// POL-3 / LOG-1 / EDE-15 provenance is captured at AUTHOR time, never read live
// at serialization, so a concurrent reload that re-sources the running evaluator
// must leave an already-authored response BYTE-IDENTICAL (doc 14 §2 / doc 11 §5.5:
// provenance is stamped at author time, not mutated post-hoc).
//
// The test below authors a deny at policy version v0 and CAPTURES the response +
// LOG-1 event into owned values; drives a watch_snapshots commit to v1 mid-flight
// (the production SnapshotCommitSink / watch_snapshots path); then RE-ASSERTS the
// captured pre-reload artifacts STILL carry v0's rule-id/layer/policy-version in
// both the EDE-15 ds: text and the LOG-1 provenance triple (no re-stamp), while a
// FRESH post-reload query carries v1. Loopback / synthetic only — a Deny never
// forwards, and the policy stream is the in-process snapshot feed.
// ===========================================================================

/// MID-FLIGHT NO-RESTAMP (version axis): a deny AUTHORED at policy version v0 and
/// captured into owned [`Message`] / [`crate::DnsEvent`] values retains v0's
/// `policy_version` in BOTH the EDE-15 `ds:` extra-text and the LOG-1 provenance
/// triple AFTER a concurrent `watch_snapshots` commit re-sources the running
/// evaluator to v1 — the reload does NOT retroactively re-stamp the already-authored
/// response. A subsequent FRESH query then carries v1, confirming the reload landed.
///
/// This closes the stale-event gap the forward-direction hot-reload test
/// (`hot_reload_new_policy_version_propagates_to_log1_event_and_ede_text`) leaves
/// open: that test proves NEW queries see the NEW version; this one proves an
/// already-authored response is FROZEN at its author-time version (POL-3 / LOG-1 /
/// EDE-15 provenance is captured at author time, not read live at serialization).
#[tokio::test]
async fn midflight_reload_does_not_restamp_an_already_authored_response_version() {
    // ── Start the gate at version v0 ─────────────────────────────────────────
    let sink = CapturingSink::new();
    let policy_v0 = policy_from(LAYER_RELOAD_V0);
    let gate = ds_dnsgate::spawn_gate_with_sink(
        policy_v0,
        GateConfig::default(),
        std::sync::Arc::new(sink.clone()),
    )
    .await
    .expect("gate binds on loopback");

    let udp_addr = gate.udp_local_addr();

    // ── AUTHOR a deny under v0 and CAPTURE the response + event into owned values ──
    // `deny_and_capture` returns an owned `Message` and a cloned `DnsEvent` — the
    // serialized wire bytes and the captured provenance are SNAPSHOTS taken at author
    // time. A later reload cannot reach back into these owned values to re-stamp them;
    // the no-restamp invariant is precisely that they stay frozen at v0.
    let (pre_resp, pre_event) =
        deny_and_capture(udp_addr, &sink, "reload-probe.example.", 0xA001).await;
    assert_nxdomain_with_signature_soa(&pre_resp, "pre-reload-author/udp");

    // Author-time provenance: v0 on the LOG-1 event and the EDE-15 `ds:` version=.
    assert_eq!(
        pre_event.provenance.policy_version, "2026.06.12-v0",
        "the authored deny's LOG-1 event carries the author-time v0 policy_version: {:?}",
        pre_event.provenance
    );
    let pre_ede = ede_blocked_text(&pre_resp)
        .expect("the authored NXDOMAIN-with-OPT carries EDE 15: {pre_resp:?}");
    assert!(
        pre_ede.starts_with(EDE_DS_PREFIX),
        "the authored EDE text is ds:-prefixed: {pre_ede:?}"
    );
    let pre_ede_version =
        ede_version_value(&pre_ede).expect("the authored EDE text carries a version= token");
    assert_eq!(
        pre_ede_version, "2026.06.12-v0",
        "the authored EDE carries the author-time version=2026.06.12-v0: {pre_ede:?}"
    );
    // Snapshot the author-time provenance triple so we can re-compare it post-reload
    // and prove not a single field was retroactively mutated.
    let pre_rule_id = pre_event.provenance.rule_id.clone();
    let pre_layer = pre_event.provenance.policy_layer.clone();
    // The whole owned EDE string captured at author time — must be byte-identical later.
    let pre_ede_snapshot = pre_ede.clone();

    // ── COMMIT v1 MID-FLIGHT via the production subscriber path ────────────────
    // This re-sources the running gate's evaluator to v1 — the SAME watch_snapshots /
    // SnapshotCommitSink path a live policy-stream reload drives.
    let layer_v1 = parse_layer(LAYER_RELOAD_V1).expect("v1 layer parses");
    let composed_v1 = compose(&[layer_v1], &[]);
    let snapshot = BoundarySnapshot::with_policy(
        30,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_v1,
        TtlClamp::DEFAULT,
    );

    let bz_reloader = gate.boundary_zone_reloader();
    let pol_reloader: GatePolicyReloader = gate.policy_reloader();
    let commit_sink = SnapshotCommitSink::new(bz_reloader, pol_reloader);

    let (feed, subscription) = boundary_snapshot_feed(4);
    feed.publish(snapshot).await.expect("subscriber alive");
    drop(feed); // close the channel so watch_snapshots returns

    let commits = watch_snapshots(subscription, &commit_sink).await;
    assert_eq!(commits, 1, "exactly one forward-seq snapshot committed");
    assert_eq!(
        gate.policy_version(),
        "2026.06.12-v1",
        "the running gate's evaluator is now at v1 after the mid-flight commit"
    );

    // ── NO-RESTAMP: the captured pre-reload artifacts STILL carry v0 ───────────
    // The reload bumped the LIVE evaluator to v1, but the response authored before the
    // commit was serialized + captured at v0 — the provenance is frozen at author time,
    // never re-read at serialization. Re-assert every field of the captured triple and
    // the captured EDE string: not one was retroactively re-stamped to v1.
    assert_eq!(
        pre_event.provenance.policy_version, "2026.06.12-v0",
        "NO-RESTAMP: the already-authored LOG-1 event still carries v0 after the reload to v1: {:?}",
        pre_event.provenance
    );
    assert_eq!(
        pre_event.provenance.rule_id, pre_rule_id,
        "NO-RESTAMP: the authored LOG-1 rule_id is unchanged by the reload"
    );
    assert_eq!(
        pre_event.provenance.policy_layer, pre_layer,
        "NO-RESTAMP: the authored LOG-1 policy_layer is unchanged by the reload"
    );
    // POL-3: the author-time triple is intact (every field non-empty) after the reload.
    assert!(
        !pre_event.provenance.rule_id.is_empty()
            && !pre_event.provenance.policy_layer.is_empty()
            && !pre_event.provenance.policy_version.is_empty(),
        "NO-RESTAMP: the authored LOG-1 event still carries the full POL-3 triple: {:?}",
        pre_event.provenance
    );

    // The captured EDE-15 `ds:` text is BYTE-IDENTICAL — the reload never reached into
    // the already-serialized response to re-stamp its version=/layer= tokens.
    let pre_resp_ede_now = ede_blocked_text(&pre_resp)
        .expect("the captured response still decodes its EDE 15 after the reload");
    assert_eq!(
        pre_resp_ede_now, pre_ede_snapshot,
        "NO-RESTAMP: the authored EDE-15 ds: text is byte-identical after the reload (no re-stamp)"
    );
    assert_eq!(
        ede_version_value(&pre_resp_ede_now),
        Some("2026.06.12-v0"),
        "NO-RESTAMP: the authored EDE still carries version=2026.06.12-v0 after the reload to v1"
    );

    // ── FRESH post-reload query: NOW carries v1 (the reload did land) ──────────
    let (post_resp, post_event) =
        deny_and_capture(udp_addr, &sink, "reload-probe.example.", 0xA002).await;
    assert_nxdomain_with_signature_soa(&post_resp, "post-reload-author/udp");
    assert_eq!(
        post_event.provenance.policy_version, "2026.06.12-v1",
        "a FRESH post-reload query carries the NEW v1 policy_version: {:?}",
        post_event.provenance
    );
    let post_ede = ede_blocked_text(&post_resp)
        .expect("the fresh post-reload NXDOMAIN-with-OPT carries EDE 15: {post_resp:?}");
    let post_ede_version =
        ede_version_value(&post_ede).expect("the fresh post-reload EDE carries a version= token");
    assert_eq!(
        post_ede_version, "2026.06.12-v1",
        "the fresh post-reload EDE carries version=2026.06.12-v1: {post_ede:?}"
    );

    // The two responses split on the version axis — proving the pre-reload response was
    // NOT retroactively re-stamped to match the post-reload one.
    assert_ne!(
        pre_ede_snapshot, post_ede,
        "the pre-reload (v0) and post-reload (v1) EDE texts differ — the reload did not re-stamp the older response"
    );
    assert_ne!(
        pre_event.provenance.policy_version, post_event.provenance.policy_version,
        "the pre-reload (v0) and post-reload (v1) LOG-1 policy_version differ — no retroactive re-stamp"
    );
    // The rule_id is shared (same rule, version-only bump) — confirming the difference is
    // ONLY the author-time version, not a different verdict.
    assert_eq!(
        pre_event.provenance.rule_id, post_event.provenance.rule_id,
        "both denies match the same rule; only the author-time version differs"
    );

    gate.shutdown().await.expect("gate shutdown");
}

/// MID-FLIGHT NO-RESTAMP (layer axis): an inert deny AUTHORED under the
/// `system-baseline` layer and captured into owned values retains
/// `policy_layer = "system-baseline"` in BOTH the EDE-15 `ds:` `layer=` token and the
/// LOG-1 provenance AFTER a concurrent reload re-sources the evaluator to the `org`
/// layer — no retroactive re-stamp — while a FRESH query then carries `org`.
///
/// This is the layer-axis complement of the version-axis no-restamp test, and the
/// mirror of the forward-direction
/// `hot_reload_new_policy_layer_propagates_to_log1_event_and_ede_text`: the layer, like
/// the version, is captured at author time and frozen onto the serialized response, so
/// a mid-flight layer flip leaves an already-authored response untouched. The probe uses
/// an inert baseline-pack entry so the `policy_layer` reflects the sourcing layer name
/// (`source_layer`) on the Deny path (blocklist denies always carry `policy_layer:
/// "composed"`; only pack-entry/allowlist paths carry the per-layer source name).
#[tokio::test]
async fn midflight_reload_does_not_restamp_an_already_authored_response_layer() {
    // ── Start the gate at the "system-baseline" layer (inert pack entry) ──────
    let sink = CapturingSink::new();
    let policy_baseline = policy_from(LAYER_RELOAD_BASELINE);
    let gate = ds_dnsgate::spawn_gate_with_sink(
        policy_baseline,
        GateConfig::default(),
        std::sync::Arc::new(sink.clone()),
    )
    .await
    .expect("gate binds on loopback");

    let udp_addr = gate.udp_local_addr();

    // ── AUTHOR an inert deny under system-baseline and CAPTURE it into owned values ──
    let (pre_resp, pre_event) =
        deny_and_capture(udp_addr, &sink, "layer-probe.example.", 0xB001).await;
    assert_nxdomain_with_signature_soa(&pre_resp, "pre-reload-layer-author/udp");

    assert_eq!(
        pre_event.provenance.policy_layer, "system-baseline",
        "the authored inert deny's LOG-1 event carries the author-time system-baseline layer: {:?}",
        pre_event.provenance
    );
    let pre_ede = ede_blocked_text(&pre_resp)
        .expect("the authored inert NXDOMAIN-with-OPT carries EDE 15: {pre_resp:?}");
    let pre_ede_layer =
        ede_layer_value(&pre_ede).expect("the authored EDE text carries a layer= token");
    assert_eq!(
        pre_ede_layer, "system-baseline",
        "the authored EDE carries the author-time layer=system-baseline: {pre_ede:?}"
    );
    // Snapshot the author-time triple + EDE string for the post-reload re-comparison.
    let pre_rule_id = pre_event.provenance.rule_id.clone();
    let pre_version = pre_event.provenance.policy_version.clone();
    let pre_ede_snapshot = pre_ede.clone();

    // ── COMMIT the "org" layer MID-FLIGHT via the production subscriber path ───
    let layer_org = parse_layer(LAYER_RELOAD_ORG).expect("org layer parses");
    let composed_org = compose(&[layer_org], &[]);
    let snapshot = BoundarySnapshot::with_policy(
        40,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_org,
        TtlClamp::DEFAULT,
    );

    let bz_reloader = gate.boundary_zone_reloader();
    let pol_reloader: GatePolicyReloader = gate.policy_reloader();
    let commit_sink = SnapshotCommitSink::new(bz_reloader, pol_reloader);

    let (feed, subscription) = boundary_snapshot_feed(4);
    feed.publish(snapshot).await.expect("subscriber alive");
    drop(feed);

    let commits = watch_snapshots(subscription, &commit_sink).await;
    assert_eq!(commits, 1, "exactly one forward-seq snapshot committed");

    // ── NO-RESTAMP: the captured pre-reload artifacts STILL carry system-baseline ──
    assert_eq!(
        pre_event.provenance.policy_layer, "system-baseline",
        "NO-RESTAMP: the already-authored LOG-1 event still carries system-baseline after the reload to org: {:?}",
        pre_event.provenance
    );
    assert_eq!(
        pre_event.provenance.rule_id, pre_rule_id,
        "NO-RESTAMP: the authored LOG-1 rule_id is unchanged by the layer reload"
    );
    assert_eq!(
        pre_event.provenance.policy_version, pre_version,
        "NO-RESTAMP: the authored LOG-1 policy_version is unchanged by the layer reload"
    );
    assert!(
        !pre_event.provenance.rule_id.is_empty()
            && !pre_event.provenance.policy_layer.is_empty()
            && !pre_event.provenance.policy_version.is_empty(),
        "NO-RESTAMP: the authored LOG-1 event still carries the full POL-3 triple: {:?}",
        pre_event.provenance
    );

    // The captured EDE-15 `ds:` text is byte-identical — the reload never re-stamped it.
    let pre_resp_ede_now = ede_blocked_text(&pre_resp)
        .expect("the captured response still decodes its EDE 15 after the reload");
    assert_eq!(
        pre_resp_ede_now, pre_ede_snapshot,
        "NO-RESTAMP: the authored EDE-15 ds: text is byte-identical after the layer reload (no re-stamp)"
    );
    assert_eq!(
        ede_layer_value(&pre_resp_ede_now),
        Some("system-baseline"),
        "NO-RESTAMP: the authored EDE still carries layer=system-baseline after the reload to org"
    );

    // ── FRESH post-reload query: NOW carries the org layer ────────────────────
    let (post_resp, post_event) =
        deny_and_capture(udp_addr, &sink, "layer-probe.example.", 0xB002).await;
    assert_nxdomain_with_signature_soa(&post_resp, "post-reload-layer-author/udp");
    assert_eq!(
        post_event.provenance.policy_layer, "org",
        "a FRESH post-reload query carries the NEW org policy_layer: {:?}",
        post_event.provenance
    );
    let post_ede = ede_blocked_text(&post_resp)
        .expect("the fresh post-reload NXDOMAIN-with-OPT carries EDE 15: {post_resp:?}");
    let post_ede_layer =
        ede_layer_value(&post_ede).expect("the fresh post-reload EDE carries a layer= token");
    assert_eq!(
        post_ede_layer, "org",
        "the fresh post-reload EDE carries layer=org: {post_ede:?}"
    );

    // The two responses split on the layer axis — no retroactive re-stamp.
    assert_ne!(
        pre_ede_snapshot, post_ede,
        "the pre-reload (system-baseline) and post-reload (org) EDE texts differ — no re-stamp of the older response"
    );
    assert_ne!(
        pre_event.provenance.policy_layer, post_event.provenance.policy_layer,
        "the pre-reload (system-baseline) and post-reload (org) LOG-1 policy_layer differ — no retroactive re-stamp"
    );
    assert_eq!(
        pre_event.provenance.rule_id, post_event.provenance.rule_id,
        "both denies match the same inert pack entry; only the author-time layer differs"
    );

    gate.shutdown().await.expect("gate shutdown");
}

// ===========================================================================
// RELOAD / FORWARD-ONLY-SEQ corners (D72) — three uncovered cases that extend the
// wave33b reload tests above. Each asserts via the SINGLE canonical EDE `ds:` grammar
// parser (`parse_ds_ede`), never a hand-mirrored token, so a handler.rs grammar
// reformat breaks `ds_ede_extra_text_grammar_is_pinned` first.
//
//   (1) TCP-AUTHORED NO-RESTAMP PARITY. The version/layer no-restamp tests above all
//       author over UDP (`deny_and_capture` / `udp_round_trip`). doc 11 §3.4 guarantees
//       UDP/TCP handler parity, so a TCP-authored (length-prefixed) deny authored just
//       before a reload must EQUALLY retain its author-time EDE-15 version/layer text:
//       a concurrent reload re-sources the LIVE evaluator but never reaches back into the
//       already-serialized TCP response. This closes the transport-parity gap the
//       UDP-only no-restamp tests leave.
//
//   (2) STALE-SEQ REJECTION ON THE LIVE WIRE. event_surface §16 proves a duplicate /
//       out-of-order `with_policy` fan-out re-sources NEITHER leg by inspecting the
//       evaluator's `policy_version` + the authored MNAME. This complements it at the
//       EDE-15 WIRE level through the canonical grammar: after committing a FORWARD seq
//       (v1), a DUPLICATE seq (distinct stale version) and an OUT-OF-ORDER seq (stale)
//       are dropped by `watch_snapshots`' D72 forward-only commit, so a fresh deny's
//       EDE `version=` token still reads v1 — never the stale fan-out's version.
//
//   (3) THE POL-3 TRIPLE AT THE COMMIT SEAM. Right at the reload commit boundary the
//       freshly-authored deny carries the FULL POL-3 triple (rule_id / layer / version,
//       every field non-empty) parsed out of the EDE-15 `ds:` text, and that triple
//       matches the running gate's committed policy version — so the commit never
//       drops a provenance field at the seam (§6.7: provenance on every event, never
//       blank).
// ===========================================================================

/// A TCP-authored counterpart to [`deny_and_capture`]: drive ONE length-prefixed query
/// over the gate's TCP/53 transport and return the (parsed response, last LOG-1 event
/// captured by the sink) pair. The query always carries an OPT record so the §3.2 EDE-15
/// attaches on a Deny, making the `ds:` text observable — exactly as the UDP helper does,
/// so the two transports are asserted against the SAME provenance shape (doc 11 §3.4).
async fn deny_and_capture_tcp(
    gate_tcp: SocketAddr,
    sink: &CapturingSink,
    name: &str,
    msg_id: u16,
) -> (hickory_proto::op::Message, crate::DnsEvent) {
    let query = query_of(msg_id, name, hickory_proto::rr::RecordType::A, true);
    let resp_bytes = tcp_round_trip(gate_tcp, &query).await;
    let resp = hickory_proto::op::Message::from_vec(&resp_bytes).expect("tcp response decodes");
    let event = sink
        .events()
        .last()
        .cloned()
        .expect("handler emitted at least one LOG-1 event for the tcp query");
    (resp, event)
}

/// A third reload layer at a DISTINCT policy version (`2026.06.12-vSTALE`) that ALSO blocks
/// `reload-probe.example` — the content a STALE / DUPLICATE fan-out would carry. If a
/// regression let the subscriber commit it backwards, the live wire EDE `version=` token
/// would flip to `2026.06.12-vSTALE`; the stale-seq test asserts it never does.
const LAYER_RELOAD_STALE: &str = r#"
schema_version: 2026.06.12-vSTALE
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
blocklist:
  - domain: reload-probe.example
    reason: reload-stale-seq-test
    rung: kill+snapshot
"#;

/// (1) MID-FLIGHT NO-RESTAMP over TCP (doc 11 §3.4 UDP/TCP parity): a deny AUTHORED at
/// policy version v0 over the LENGTH-PREFIXED TCP/53 transport retains its author-time
/// EDE-15 `ds:` version/layer text even after a concurrent subscriber-driven reload bumps
/// the running evaluator to v1. The no-restamp invariant is transport-agnostic: the
/// provenance is captured at author time (§3.2/§6.7), never re-read at serialization, so
/// the reload cannot reach back into the already-serialized TCP response to re-stamp it.
/// A FRESH post-reload TCP query then carries v1, confirming the reload landed — and the
/// two TCP responses split on the version axis exactly as the UDP no-restamp test's do.
#[tokio::test]
async fn midflight_reload_does_not_restamp_a_tcp_authored_response_version() {
    // ── Start the gate at version v0 ─────────────────────────────────────────
    let sink = CapturingSink::new();
    let policy_v0 = policy_from(LAYER_RELOAD_V0);
    let gate = ds_dnsgate::spawn_gate_with_sink(
        policy_v0,
        GateConfig::default(),
        std::sync::Arc::new(sink.clone()),
    )
    .await
    .expect("gate binds on loopback");

    let tcp_addr = gate.tcp_local_addr();

    // ── AUTHOR a deny under v0 OVER TCP and capture the response + event ───────
    // The TCP handler is the SAME handler the UDP path runs (doc 11 §3.4); the captured
    // wire bytes + provenance are an author-time snapshot a later reload cannot mutate.
    let (pre_resp, pre_event) =
        deny_and_capture_tcp(tcp_addr, &sink, "reload-probe.example.", 0xC001).await;
    assert_nxdomain_with_signature_soa(&pre_resp, "pre-reload-author/tcp");

    // Author-time provenance: v0 on the LOG-1 event AND the full EDE-15 `ds:` triple,
    // parsed through the ONE canonical grammar parser (never a hand-mirrored token).
    assert_eq!(
        pre_event.provenance.policy_version, "2026.06.12-v0",
        "the TCP-authored deny's LOG-1 event carries the author-time v0 policy_version: {:?}",
        pre_event.provenance
    );
    let pre_ede = ede_blocked_text(&pre_resp)
        .expect("the TCP-authored NXDOMAIN-with-OPT carries EDE 15: {pre_resp:?}");
    let pre_parsed = parse_ds_ede(&pre_ede)
        .expect("the TCP-authored EDE text parses through the canonical ds: grammar");
    assert_eq!(
        pre_parsed.version, "2026.06.12-v0",
        "the TCP-authored EDE carries the author-time version=2026.06.12-v0: {pre_ede:?}"
    );
    // POL-3: the author-time triple is fully populated on the TCP wire (every field set).
    assert!(
        !pre_parsed.rule.is_empty()
            && !pre_parsed.layer.is_empty()
            && !pre_parsed.version.is_empty(),
        "the TCP-authored EDE carries the full POL-3 triple at author time: {pre_ede:?}"
    );
    // Snapshot the whole owned EDE string + the LOG-1 layer for the post-reload re-compare.
    let pre_ede_snapshot = pre_ede.clone();
    let pre_layer = pre_event.provenance.policy_layer.clone();
    let pre_rule_id = pre_event.provenance.rule_id.clone();

    // ── COMMIT v1 MID-FLIGHT via the production subscriber path ────────────────
    let layer_v1 = parse_layer(LAYER_RELOAD_V1).expect("v1 layer parses");
    let composed_v1 = compose(&[layer_v1], &[]);
    let snapshot = BoundarySnapshot::with_policy(
        40,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_v1,
        TtlClamp::DEFAULT,
    );

    let bz_reloader = gate.boundary_zone_reloader();
    let pol_reloader: GatePolicyReloader = gate.policy_reloader();
    let commit_sink = SnapshotCommitSink::new(bz_reloader, pol_reloader);

    let (feed, subscription) = boundary_snapshot_feed(4);
    feed.publish(snapshot).await.expect("subscriber alive");
    drop(feed); // close the channel so watch_snapshots returns

    let commits = watch_snapshots(subscription, &commit_sink).await;
    assert_eq!(commits, 1, "exactly one forward-seq snapshot committed");
    assert_eq!(
        gate.policy_version(),
        "2026.06.12-v1",
        "the running gate's evaluator is now at v1 after the mid-flight commit"
    );

    // ── NO-RESTAMP: the TCP-authored artifacts STILL carry v0 ──────────────────
    // The reload bumped the LIVE evaluator to v1, but the TCP response serialized + captured
    // at v0 is frozen at author time. Not one field of its captured triple was re-stamped.
    assert_eq!(
        pre_event.provenance.policy_version, "2026.06.12-v0",
        "NO-RESTAMP (tcp): the already-authored LOG-1 event still carries v0 after the reload to v1: {:?}",
        pre_event.provenance
    );
    assert_eq!(
        pre_event.provenance.policy_layer, pre_layer,
        "NO-RESTAMP (tcp): the authored LOG-1 policy_layer is unchanged by the reload"
    );
    assert_eq!(
        pre_event.provenance.rule_id, pre_rule_id,
        "NO-RESTAMP (tcp): the authored LOG-1 rule_id is unchanged by the reload"
    );
    // The captured EDE-15 `ds:` text is BYTE-IDENTICAL — the reload never reached into the
    // already-serialized TCP response to re-stamp its version=/layer= tokens.
    let pre_resp_ede_now = ede_blocked_text(&pre_resp)
        .expect("the captured TCP response still decodes its EDE 15 after the reload");
    assert_eq!(
        pre_resp_ede_now, pre_ede_snapshot,
        "NO-RESTAMP (tcp): the authored EDE-15 ds: text is byte-identical after the reload (no re-stamp)"
    );
    assert_eq!(
        ede_version_value(&pre_resp_ede_now),
        Some("2026.06.12-v0"),
        "NO-RESTAMP (tcp): the authored EDE still carries version=2026.06.12-v0 after the reload to v1"
    );

    // ── FRESH post-reload TCP query: NOW carries v1 (the reload did land) ───────
    let (post_resp, post_event) =
        deny_and_capture_tcp(tcp_addr, &sink, "reload-probe.example.", 0xC002).await;
    assert_nxdomain_with_signature_soa(&post_resp, "post-reload-author/tcp");
    assert_eq!(
        post_event.provenance.policy_version, "2026.06.12-v1",
        "a FRESH post-reload TCP query carries the NEW v1 policy_version: {:?}",
        post_event.provenance
    );
    let post_ede = ede_blocked_text(&post_resp)
        .expect("the fresh post-reload TCP NXDOMAIN-with-OPT carries EDE 15: {post_resp:?}");
    assert_eq!(
        ede_version_value(&post_ede),
        Some("2026.06.12-v1"),
        "the fresh post-reload TCP EDE carries version=2026.06.12-v1: {post_ede:?}"
    );

    // The two TCP responses split on the version axis — the pre-reload one was NOT
    // retroactively re-stamped to match the post-reload one (transport-agnostic no-restamp).
    assert_ne!(
        pre_ede_snapshot, post_ede,
        "the pre-reload (v0) and post-reload (v1) TCP EDE texts differ — the reload did not re-stamp the older response"
    );
    assert_eq!(
        pre_event.provenance.rule_id, post_event.provenance.rule_id,
        "both TCP denies match the same rule; only the author-time version differs"
    );

    gate.shutdown().await.expect("gate shutdown");
}

/// (2) STALE-SEQ REJECTION on the LIVE WIRE (D72 forward-only): after the subscriber
/// commits a FORWARD seq (v1), a DUPLICATE seq and an OUT-OF-ORDER (seq < committed) seq —
/// EACH carrying a DISTINCT stale policy version that also blocks `reload-probe.example` —
/// are dropped by `watch_snapshots`' forward-only commit. The running gate stays at v1, so
/// a fresh deny's EDE-15 `version=` token (read through the canonical grammar) still reads
/// v1 — never the stale fan-out's version. This complements event_surface §16 (which checks
/// the evaluator field + the MNAME) at the EDE-15 wire level: a regression that let a stale
/// fan-out re-source the evaluator backwards would surface here as a flipped `version=`.
#[tokio::test]
async fn stale_seq_fan_out_is_rejected_live_wire_ede_version_stays_forward() {
    // ── Start the gate at v0, then commit FORWARD to v1 (seq 50) ───────────────
    let sink = CapturingSink::new();
    let policy_v0 = policy_from(LAYER_RELOAD_V0);
    let gate = ds_dnsgate::spawn_gate_with_sink(
        policy_v0,
        GateConfig::default(),
        std::sync::Arc::new(sink.clone()),
    )
    .await
    .expect("gate binds on loopback");
    let udp_addr = gate.udp_local_addr();

    let bz_reloader = gate.boundary_zone_reloader();
    let pol_reloader: GatePolicyReloader = gate.policy_reloader();
    let commit_sink = SnapshotCommitSink::new(bz_reloader, pol_reloader);

    // A scripted feed: a FORWARD seq 50 (v1) commits, then a DUPLICATE seq 50 and an
    // OUT-OF-ORDER seq 40 (each carrying the DISTINCT vSTALE version) are dropped by the
    // D72 forward-only commit — NEITHER re-sources the evaluator backwards.
    let layer_v1 = parse_layer(LAYER_RELOAD_V1).expect("v1 layer parses");
    let composed_v1 = compose(&[layer_v1], &[]);
    let layer_stale = parse_layer(LAYER_RELOAD_STALE).expect("stale layer parses");
    let composed_stale = compose(&[layer_stale], &[]);

    let (feed, subscription) = boundary_snapshot_feed(4);
    // seq 50 — FORWARD: commits, re-sources the evaluator to v1.
    feed.publish(BoundarySnapshot::with_policy(
        50,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_v1,
        TtlClamp::DEFAULT,
    ))
    .await
    .expect("subscriber alive for the forward fan-out");
    // seq 50 — DUPLICATE (== committed): dropped; vSTALE must NEVER become live.
    feed.publish(BoundarySnapshot::with_policy(
        50,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_stale.clone(),
        TtlClamp::DEFAULT,
    ))
    .await
    .expect("subscriber alive for the duplicate fan-out");
    // seq 40 — OUT-OF-ORDER (< committed 50): dropped; vSTALE must NEVER become live.
    feed.publish(BoundarySnapshot::with_policy(
        40,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_stale,
        TtlClamp::DEFAULT,
    ))
    .await
    .expect("subscriber alive for the out-of-order fan-out");
    drop(feed); // close the channel so watch_snapshots returns

    let commits = watch_snapshots(subscription, &commit_sink).await;
    assert_eq!(
        commits, 1,
        "only the single FORWARD seq committed; the duplicate (50) and out-of-order (40) \
         fan-outs were dropped by the D72 forward-only commit (one monotonic policy version)"
    );
    // The running evaluator re-sourced ONLY on the forward seq — never backwards to vSTALE.
    assert_eq!(
        gate.policy_version(),
        "2026.06.12-v1",
        "the running gate's evaluator stays at the FORWARD v1 — the stale fan-outs never re-sourced it backwards"
    );

    // ── LIVE WIRE: a fresh deny's EDE-15 `version=` token reads v1, not vSTALE ──
    let (resp, event) = deny_and_capture(udp_addr, &sink, "reload-probe.example.", 0xD001).await;
    assert_nxdomain_with_signature_soa(&resp, "stale-seq/udp");
    let ede = ede_blocked_text(&resp)
        .expect("the post-commit NXDOMAIN-with-OPT carries EDE 15: {resp:?}");
    let parsed = parse_ds_ede(&ede)
        .expect("the post-commit EDE text parses through the canonical ds: grammar");
    assert_eq!(
        parsed.version, "2026.06.12-v1",
        "the live wire EDE version= reads the FORWARD v1 — the dropped stale fan-outs never reached the wire: {ede:?}"
    );
    assert_ne!(
        parsed.version, "2026.06.12-vSTALE",
        "the live wire EDE version= is NEVER the dropped stale fan-out's version (no backwards re-source)"
    );
    // The LOG-1 event agrees with the wire — one monotonic version end to end.
    assert_eq!(
        event.provenance.policy_version, "2026.06.12-v1",
        "the LOG-1 event policy_version agrees with the forward wire version (no per-channel skew): {:?}",
        event.provenance
    );

    gate.shutdown().await.expect("gate shutdown");
}

/// (2b) STALE-SEQ REJECTION on the LIVE WIRE over TCP/53 (D72 forward-only + doc 11 §3.4
/// UDP/TCP parity): the TRANSPORT TWIN of [`stale_seq_fan_out_is_rejected_live_wire_ede_version_stays_forward`].
/// That sibling authors the post-commit deny over UDP; §3.4 freezes the TCP path to the
/// SAME verdict / admission / authored-negative-shape semantics, so the forward-only-seq drop
/// MUST be re-asserted on the length-prefixed TCP/53 wire too. After the subscriber commits a
/// FORWARD seq (v1), a DUPLICATE seq and an OUT-OF-ORDER (seq < committed) seq — EACH carrying
/// the DISTINCT `vSTALE` version that also blocks `reload-probe.example` — are dropped by
/// `watch_snapshots`' forward-only commit. A fresh TCP-authored deny's EDE-15 `version=` token
/// (read through the ONE canonical `ds:` grammar parser) still reads v1 — never the stale
/// fan-out's version. A regression that let a stale fan-out re-source the evaluator backwards
/// would surface here as a flipped `version=` on the TCP transport, closing the parity gap the
/// UDP-only stale-seq test leaves.
#[tokio::test]
async fn stale_seq_fan_out_is_rejected_live_wire_ede_version_stays_forward_over_tcp() {
    // ── Start the gate at v0, then commit FORWARD to v1 (seq 50) ───────────────
    let sink = CapturingSink::new();
    let policy_v0 = policy_from(LAYER_RELOAD_V0);
    let gate = ds_dnsgate::spawn_gate_with_sink(
        policy_v0,
        GateConfig::default(),
        std::sync::Arc::new(sink.clone()),
    )
    .await
    .expect("gate binds on loopback");
    // The TCP/53 transport — the §3.4 twin of the UDP arm the sibling test drives.
    let tcp_addr = gate.tcp_local_addr();

    let bz_reloader = gate.boundary_zone_reloader();
    let pol_reloader: GatePolicyReloader = gate.policy_reloader();
    let commit_sink = SnapshotCommitSink::new(bz_reloader, pol_reloader);

    // A scripted feed: a FORWARD seq 50 (v1) commits, then a DUPLICATE seq 50 and an
    // OUT-OF-ORDER seq 40 (each carrying the DISTINCT vSTALE version) are dropped by the
    // D72 forward-only commit — NEITHER re-sources the evaluator backwards.
    let layer_v1 = parse_layer(LAYER_RELOAD_V1).expect("v1 layer parses");
    let composed_v1 = compose(&[layer_v1], &[]);
    let layer_stale = parse_layer(LAYER_RELOAD_STALE).expect("stale layer parses");
    let composed_stale = compose(&[layer_stale], &[]);

    let (feed, subscription) = boundary_snapshot_feed(4);
    // seq 50 — FORWARD: commits, re-sources the evaluator to v1.
    feed.publish(BoundarySnapshot::with_policy(
        50,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_v1,
        TtlClamp::DEFAULT,
    ))
    .await
    .expect("subscriber alive for the forward fan-out");
    // seq 50 — DUPLICATE (== committed): dropped; vSTALE must NEVER become live.
    feed.publish(BoundarySnapshot::with_policy(
        50,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_stale.clone(),
        TtlClamp::DEFAULT,
    ))
    .await
    .expect("subscriber alive for the duplicate fan-out");
    // seq 40 — OUT-OF-ORDER (< committed 50): dropped; vSTALE must NEVER become live.
    feed.publish(BoundarySnapshot::with_policy(
        40,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_stale,
        TtlClamp::DEFAULT,
    ))
    .await
    .expect("subscriber alive for the out-of-order fan-out");
    drop(feed); // close the channel so watch_snapshots returns

    let commits = watch_snapshots(subscription, &commit_sink).await;
    assert_eq!(
        commits, 1,
        "only the single FORWARD seq committed; the duplicate (50) and out-of-order (40) \
         fan-outs were dropped by the D72 forward-only commit (one monotonic policy version)"
    );
    // The running evaluator re-sourced ONLY on the forward seq — never backwards to vSTALE.
    assert_eq!(
        gate.policy_version(),
        "2026.06.12-v1",
        "the running gate's evaluator stays at the FORWARD v1 — the stale fan-outs never re-sourced it backwards"
    );

    // ── LIVE TCP WIRE: a fresh deny's EDE-15 `version=` token reads v1, not vSTALE ──
    // The TCP handler is the SAME handler the UDP path runs (doc 11 §3.4): same verdict,
    // same authored negative shape, same provenance — so the forward-only-seq drop is
    // re-asserted on the length-prefixed transport, not just UDP.
    let (resp, event) =
        deny_and_capture_tcp(tcp_addr, &sink, "reload-probe.example.", 0xD101).await;
    assert_nxdomain_with_signature_soa(&resp, "stale-seq/tcp");
    let ede = ede_blocked_text(&resp)
        .expect("the post-commit TCP NXDOMAIN-with-OPT carries EDE 15: {resp:?}");
    let parsed = parse_ds_ede(&ede)
        .expect("the post-commit TCP EDE text parses through the canonical ds: grammar");
    assert_eq!(
        parsed.version, "2026.06.12-v1",
        "the live TCP wire EDE version= reads the FORWARD v1 — the dropped stale fan-outs never reached the wire: {ede:?}"
    );
    assert_ne!(
        parsed.version, "2026.06.12-vSTALE",
        "the live TCP wire EDE version= is NEVER the dropped stale fan-out's version (no backwards re-source)"
    );
    // The LOG-1 event agrees with the TCP wire — one monotonic version end to end, both transports.
    assert_eq!(
        event.provenance.policy_version, "2026.06.12-v1",
        "the LOG-1 event policy_version agrees with the forward TCP wire version (no per-channel skew): {:?}",
        event.provenance
    );

    gate.shutdown().await.expect("gate shutdown");
}

/// (3) THE POL-3 TRIPLE AT THE COMMIT SEAM (§6.7 / D72): the deny authored immediately
/// after a forward reload commit carries the FULL POL-3 triple — rule_id / layer / version,
/// every field NON-EMPTY — parsed out of the EDE-15 `ds:` text through the canonical
/// grammar, and that parsed triple matches the running gate's just-committed policy version.
/// So the admitter-LAST commit never drops a provenance field at the seam, and the wire
/// triple and the LOG-1 triple agree (one join, no per-channel skew).
#[tokio::test]
async fn pol3_triple_is_intact_at_the_reload_commit_seam() {
    // ── Start at v0, commit FORWARD to v1 (seq 60) ─────────────────────────────
    let sink = CapturingSink::new();
    let policy_v0 = policy_from(LAYER_RELOAD_V0);
    let gate = ds_dnsgate::spawn_gate_with_sink(
        policy_v0,
        GateConfig::default(),
        std::sync::Arc::new(sink.clone()),
    )
    .await
    .expect("gate binds on loopback");
    let udp_addr = gate.udp_local_addr();

    let layer_v1 = parse_layer(LAYER_RELOAD_V1).expect("v1 layer parses");
    let composed_v1 = compose(&[layer_v1], &[]);
    let snapshot = BoundarySnapshot::with_policy(
        60,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_v1,
        TtlClamp::DEFAULT,
    );
    let bz_reloader = gate.boundary_zone_reloader();
    let pol_reloader: GatePolicyReloader = gate.policy_reloader();
    let commit_sink = SnapshotCommitSink::new(bz_reloader, pol_reloader);

    let (feed, subscription) = boundary_snapshot_feed(4);
    feed.publish(snapshot).await.expect("subscriber alive");
    drop(feed);
    let commits = watch_snapshots(subscription, &commit_sink).await;
    assert_eq!(
        commits, 1,
        "exactly one forward-seq snapshot committed at the seam"
    );
    assert_eq!(
        gate.policy_version(),
        "2026.06.12-v1",
        "the running gate is at v1 right at the commit seam"
    );

    // ── At the seam: a fresh deny carries the FULL POL-3 triple on BOTH channels ──
    let (resp, event) = deny_and_capture(udp_addr, &sink, "reload-probe.example.", 0xE001).await;
    assert_nxdomain_with_signature_soa(&resp, "commit-seam/udp");

    // The EDE-15 wire triple, parsed once through the canonical `ds:` grammar.
    let ede = ede_blocked_text(&resp).expect("the seam NXDOMAIN-with-OPT carries EDE 15: {resp:?}");
    let parsed =
        parse_ds_ede(&ede).expect("the seam EDE text parses through the canonical ds: grammar");
    // POL-3: NONE of the three fields is blank at the commit seam.
    assert!(
        !parsed.rule.is_empty(),
        "the seam EDE rule= is non-empty: {ede:?}"
    );
    assert!(
        !parsed.layer.is_empty(),
        "the seam EDE layer= is non-empty: {ede:?}"
    );
    assert!(
        !parsed.version.is_empty(),
        "the seam EDE version= is non-empty: {ede:?}"
    );
    // The wire version is the JUST-committed forward version (the seam carries the new one).
    assert_eq!(
        parsed.version, "2026.06.12-v1",
        "the seam EDE version= is the just-committed v1: {ede:?}"
    );

    // The wire triple MATCHES the LOG-1 event triple field-for-field — one join, no skew.
    assert_eq!(
        parsed.rule, event.provenance.rule_id,
        "the seam EDE rule= matches the LOG-1 event rule_id (one provenance join)"
    );
    assert_eq!(
        parsed.layer, event.provenance.policy_layer,
        "the seam EDE layer= matches the LOG-1 event policy_layer"
    );
    assert_eq!(
        parsed.version, event.provenance.policy_version,
        "the seam EDE version= matches the LOG-1 event policy_version"
    );
    // And the LOG-1 triple is itself fully populated at the seam (§6.7: never blank).
    assert!(
        !event.provenance.rule_id.is_empty()
            && !event.provenance.policy_layer.is_empty()
            && !event.provenance.policy_version.is_empty(),
        "the seam LOG-1 event carries the full POL-3 triple: {:?}",
        event.provenance
    );

    gate.shutdown().await.expect("gate shutdown");
}

/// (4) THE D72 STALE-SEQ DROP RE-ASSERTED AT THE *VERDICT* LEVEL (relocated from
/// `event_surface` — the verdict-shaped companion to its loopback-WIRE mechanics, doc 11
/// §3.2/§6.7 / D72 forward-only).
///
/// The sibling `stale_seq_fan_out_is_rejected_live_wire_*` tests prove the forward-only drop
/// on the EDE-15 WIRE rendering; the `event_surface` verify-only/NACK tests prove it on the
/// loopback wire (MNAME + commit counts + drop reasons). What belongs in THIS verdict file —
/// the home of the frozen `DnsVerdict` surface — is the re-assertion on the EVALUATOR's
/// VERDICT itself: after the production `watch_snapshots` / `SnapshotCommitSink` commits a
/// FORWARD seq (v1) and DROPS a DUPLICATE + an OUT-OF-ORDER vSTALE fan-out, the live evaluator
/// returns a frozen `Deny` whose POL-3 provenance carries the FORWARD `policy_version`
/// (`2026.06.12-v1`) with the full triple intact — never the dropped stale fan-out's version.
///
/// NON-VACUOUS: the stale fan-outs are published AFTER the forward commit and carry a DISTINCT
/// `2026.06.12-vSTALE` version, so a regression that let a stale fan-out re-source the evaluator
/// backwards would flip the asserted verdict `policy_version`. Loopback / synthetic only: a real
/// `spawn_gate`-bound gate, the host-LOCAL `boundary_snapshot_feed` (NEVER a control-plane
/// stream), and `with_policy` snapshots composed from synthetic POL-1 layers — no network beyond
/// loopback, no live host agent. The `PolicyCorePolicy` handle is `Arc<RwLock<…>>`-shared with
/// the gate's evaluator (src/policy.rs:248), so `evaluate()` after the commit reads the live
/// re-sourced verdict, not a stale snapshot.
#[tokio::test]
async fn stale_seq_fan_out_keeps_the_live_verdict_on_the_forward_version_with_intact_provenance() {
    // ── Start the gate at v0 on a shared evaluator handle, then commit FORWARD to v1 ──
    let live_policy = policy_from(LAYER_RELOAD_V0);
    let gate = ds_dnsgate::spawn_gate(live_policy.clone(), GateConfig::default())
        .await
        .expect("gate binds on loopback");
    assert_eq!(
        gate.policy_version(),
        "2026.06.12-v0",
        "the gate starts on the v0 evaluator",
    );

    let composed_v1 = compose(
        &[parse_layer(LAYER_RELOAD_V1).expect("v1 layer parses")],
        &[],
    );
    let composed_stale = compose(
        &[parse_layer(LAYER_RELOAD_STALE).expect("stale layer parses")],
        &[],
    );

    let bz_reloader = gate.boundary_zone_reloader();
    let pol_reloader: GatePolicyReloader = gate.policy_reloader();
    let commit_sink = SnapshotCommitSink::new(bz_reloader, pol_reloader);

    let (feed, subscription) = boundary_snapshot_feed(4);
    // seq 50 — FORWARD: commits, re-sources the evaluator to v1.
    feed.publish(BoundarySnapshot::with_policy(
        50,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_v1,
        TtlClamp::DEFAULT,
    ))
    .await
    .expect("subscriber alive for the forward fan-out");
    // seq 50 — DUPLICATE (== committed) carrying vSTALE: dropped (D72 forward-only).
    feed.publish(BoundarySnapshot::with_policy(
        50,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_stale.clone(),
        TtlClamp::DEFAULT,
    ))
    .await
    .expect("subscriber alive for the duplicate fan-out");
    // seq 40 — OUT-OF-ORDER (< committed 50) carrying vSTALE: dropped (D72 forward-only).
    feed.publish(BoundarySnapshot::with_policy(
        40,
        ds_dnsgate::handler::DEFAULT_BOUNDARY_ZONE,
        composed_stale,
        TtlClamp::DEFAULT,
    ))
    .await
    .expect("subscriber alive for the out-of-order fan-out");
    drop(feed); // close the channel so watch_snapshots returns

    let commits = watch_snapshots(subscription, &commit_sink).await;
    assert_eq!(
        commits, 1,
        "only the FORWARD seq 50 committed; the duplicate (50) and out-of-order (40) vSTALE \
         fan-outs were dropped by the D72 forward-only commit (one monotonic policy version)",
    );

    // ── VERDICT-LEVEL re-assertion: the live evaluator denies on the FORWARD v1 provenance ──
    let ctx = DnsQueryCtx {
        session: "verdict-shaped-d72-forward-only".to_string(),
        qname: "reload-probe.example.".to_string(),
        qtype: 1,
        source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
    };
    let verdict = live_policy.evaluate(&ctx);
    assert!(
        !verdict.admits(),
        "reload-probe.example stays a hard deny under the live (forward) verdict",
    );
    let provenance = verdict.provenance();
    // The verdict's POL-3 triple is the FORWARD version — NEVER the dropped stale fan-out's.
    assert_eq!(
        provenance.policy_version, "2026.06.12-v1",
        "the live VERDICT carries the FORWARD v1 policy_version — the dropped vSTALE fan-outs \
         never re-sourced the evaluator backwards: {provenance:?}",
    );
    assert_ne!(
        provenance.policy_version, "2026.06.12-vSTALE",
        "the live verdict's policy_version is NEVER the dropped stale fan-out's version",
    );
    // §6.7: the full POL-3 triple is intact on the re-sourced verdict (the commit drops nothing).
    assert!(
        !provenance.rule_id.is_empty()
            && !provenance.policy_layer.is_empty()
            && !provenance.policy_version.is_empty(),
        "POL-3 provenance triple preserved on the live (forward) verdict: {provenance:?}",
    );
    // The evaluator version the gate reports agrees with the verdict provenance — one source.
    assert_eq!(
        gate.policy_version(),
        "2026.06.12-v1",
        "the gate's evaluator version agrees with the live verdict's forward policy_version",
    );

    gate.shutdown().await.expect("gate shutdown");
}

// ===========================================================================
// A minimal in-process mock upstream (loopback UDP, network-free) — only the A
// answer the Allow smoke test needs. Mirrors the richer mock in suppression_shapes.
// ===========================================================================
mod mock_up {
    use super::*;
    use hickory_proto::op::Message;

    pub struct MockUpstream {
        local: SocketAddr,
        _task: tokio::task::JoinHandle<()>,
    }

    impl MockUpstream {
        pub async fn start(zone: Vec<Record>) -> Self {
            let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .unwrap();
            let local = sock.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
                        return;
                    };
                    let Ok(req) = Message::from_vec(&buf[..n]) else {
                        continue;
                    };
                    let mut resp = Message::query();
                    resp.metadata.id = req.metadata.id;
                    resp.metadata.message_type = MessageType::Response;
                    resp.metadata.op_code = OpCode::Query;
                    resp.metadata.recursion_available = true;
                    if let Some(q) = req.queries.first() {
                        resp.add_query(q.clone());
                        for rec in &zone {
                            if &rec.name == q.name() && rec.record_type() == q.query_type() {
                                resp.add_answer(rec.clone());
                            }
                        }
                    }
                    let bytes = resp.to_vec().unwrap();
                    let _ = sock.send_to(&bytes, peer).await;
                }
            });
            Self { local, _task: task }
        }

        pub fn local_addr(&self) -> SocketAddr {
            self.local
        }
    }
}
