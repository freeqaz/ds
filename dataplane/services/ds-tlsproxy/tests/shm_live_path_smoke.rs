//! D131 shm-rollout T1 — the PORTABLE end-to-end LIVE-PATH smoke for the production
//! rollout. It drives the FULL ds-tlsproxy READER gate selection over a UNIQUE named
//! POSIX-shm segment and asserts a real FORWARD **Proceed** (`Tls1Decision::Tunnel`):
//!
//!   1. a WRITER (`ds_admission_shm::ShmAdmissionMap`, the same crate ds-dnsgate's
//!      `with_shm_writer` backs the W1/W2 transaction with) admits a `(session, fqdn)
//!      → ip` entry onto a unique named segment;
//!   2. an INDEPENDENT read-only `ds_admission_shm::ShmAdmissionReader` attaches to the
//!      SAME name — exactly what `ds-tlsproxy`'s `acquire_admission_map` does behind
//!      `DS_TLS1_LIVE` (this test re-creates the in-binary `ShmReaderAdapter`, which is
//!      private to `main.rs`, as a thin local adapter over the SAME frozen
//!      `ds_contracts::dns_admission::AdmissionMap` trait — no rule reimplemented);
//!   3. the SAME `ds_tlsproxy::tls1_admission::decide` the listener calls runs over the
//!      live reader + a real allowing `PolicyCoreOracle`, and a policy-allowed SNI whose
//!      kernel `original_dst` is in the admitted set yields `Tunnel` (FORWARD Proceed).
//!
//! It also pins the FAIL-CLOSED edges on the SAME live reader (an un-admitted dst is an
//! SNI-dst mismatch refusal; a never-admitted SNI re-admits, which refuses fail-closed
//! once the not-wired re-resolve seam declines). Hermetic: a UNIQUE per-test segment
//! name (PID + counter) + `ShmAdmissionMap::unlink` teardown; runs in-sandbox on
//! `/dev/shm`. This is the cargo half of the rollout verification; the optional
//! two-binary boot smoke is `dataplane/scripts/shm-rollout-smoke.sh` (operator-gated).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use ds_admission_shm::{ShmAdmissionMap, ShmAdmissionReader};
use ds_contracts::dns_admission::{
    AddressFamily, AdmissionEntry, AdmissionError, AdmissionKey, AdmissionType, AdmittedAddr,
    Instant, Provenance, ReverseIndex,
};
use ds_contracts::session::SessionRef;
use ds_tlsproxy::tls1_admission::{decide, PolicyCoreOracle, Tls1Decision};
use ds_tlsproxy::transparent::ConnOrigin;

/// A unique-per-invocation POSIX shm name (PID + a process-local counter): hermetic
/// across parallel test threads, never reusing a stale leftover. POSIX shm names begin
/// with `/` and carry no further `/`.
fn unique_segment_name(tag: &str) -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("/ds-admission-smoke-{tag}-{}-{n}", std::process::id())
}

const NANOS_PER_SEC: u64 = 1_000_000_000;
const SESSION_UUID: &str = "smoke-session-uuid";

fn v4(a: u8, b: u8, c: u8, d: u8) -> AdmittedAddr {
    AdmittedAddr {
        family: AddressFamily::V4,
        octets: vec![a, b, c, d],
    }
}

/// A live (far-future deadline) NORMAL admission entry over one admitted IP.
fn live_entry(ip: AdmittedAddr) -> AdmissionEntry {
    AdmissionEntry {
        admitted_ips: vec![ip],
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
        // Far future, so it is unexpired at the test clock below.
        expires_at: Instant::from_unix_nanos(10_000 * NANOS_PER_SEC),
        admitted_at: Instant::from_unix_nanos(1_000 * NANOS_PER_SEC),
        provenance: Provenance {
            rule_id: "allowlist:cdn.smoke.test".into(),
            policy_layer: "org".into(),
            policy_version: "2026-06-17".into(),
        },
    }
}

fn now() -> Instant {
    Instant::from_unix_nanos(2_000 * NANOS_PER_SEC)
}

// ── synthetic ClientHello builder (a minimal-but-well-formed TLS 1.2 ClientHello
//    carrying one host_name SNI, so the production parser is exercised on real wire
//    bytes with no TLS stack). Mirrors the tls1_admission unit-test fixtures. ──────────

const RECORD_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const EXT_SERVER_NAME: u16 = 0;
const SNI_NAME_TYPE_HOST: u8 = 0;

fn ext(ext_type: u16, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ext_type.to_be_bytes());
    v.extend_from_slice(&(body.len() as u16).to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn server_name_body(host: &str) -> Vec<u8> {
    let mut name = Vec::new();
    name.push(SNI_NAME_TYPE_HOST);
    name.extend_from_slice(&(host.len() as u16).to_be_bytes());
    name.extend_from_slice(host.as_bytes());
    let mut body = Vec::new();
    body.extend_from_slice(&(name.len() as u16).to_be_bytes()); // list length
    body.extend_from_slice(&name);
    body
}

fn client_hello_with_sni(host: &str) -> Vec<u8> {
    let extensions = ext(EXT_SERVER_NAME, &server_name_body(host));
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    body.extend_from_slice(&[0u8; 32]); // random
    body.push(0); // session_id length 0
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites
    body.push(1); // compression_methods length
    body.push(0); // null compression
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut hs = Vec::new();
    hs.push(HANDSHAKE_TYPE_CLIENT_HELLO);
    let len = body.len() as u32;
    hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    hs.extend_from_slice(&body);

    let mut rec = Vec::new();
    rec.push(RECORD_TYPE_HANDSHAKE);
    rec.extend_from_slice(&[0x03, 0x01]); // legacy record version
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn origin_to(dst: &str) -> ConnOrigin {
    let original_dst: SocketAddr = dst.parse().expect("dst parses");
    ConnOrigin {
        original_dst,
        session: SessionRef::new(SESSION_UUID.into(), "host-a".into(), 7, "dstap-7".into()),
    }
}

/// An allowing `ComposedPolicy` over a POL-1 allowlist — the SAME parse → compose path
/// the proxy boots with, wrapped by the PRODUCTION `PolicyCoreOracle` (POL-3: the same
/// engine verdict DNS admission used). A `domain` on the allowlist gets `Admit`.
fn allowing_policy(domain: &str) -> policy_core::pol1_eval::ComposedPolicy {
    let doc = format!(
        "schema_version: pol1/v0\nlayer: session\nposture: standard\nallowlist:\n  - domain: {domain}\n"
    );
    let layer = ds_contracts::pol1::parse_layer(&doc).expect("the allowlist POL-1 layer parses");
    policy_core::pol1_eval::compose(&[layer], &[])
}

// ── A local adapter wrapping the read-only `ShmAdmissionReader` as the frozen
//    `AdmissionMap` (the SAME shape `main.rs`'s private `ShmReaderAdapter` has): the
//    reader only `lookup`s; the writer methods are inert (ds-dnsgate is the sole
//    writer). This lets the test drive the PRODUCTION `decide` over the live reader. ──

#[derive(Default)]
struct InertReverse;
impl ReverseIndex for InertReverse {
    fn incref(&mut self, _s: &str, _ip: &AdmittedAddr, _d: &str) -> u32 {
        0
    }
    fn decref(&mut self, _s: &str, _ip: &AdmittedAddr, _d: &str) -> u32 {
        0
    }
    fn refcount(&self, _s: &str, _ip: &AdmittedAddr) -> u32 {
        0
    }
}

struct ReaderMap {
    reader: ShmAdmissionReader,
    reverse: InertReverse,
}

impl ds_contracts::dns_admission::AdmissionMap for ReaderMap {
    type Reverse = InertReverse;
    fn admit(&mut self, _key: AdmissionKey, _entry: AdmissionEntry) -> Result<(), AdmissionError> {
        // Reader side: never writes (the mapping is PROT_READ). Inert success to keep
        // the trait total; `decide` only ever reads through `lookup`.
        Ok(())
    }
    fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
        self.reader.lookup(key)
    }
    fn revoke(&mut self, _key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
        Ok(vec![])
    }
    fn reverse_index(&self) -> &Self::Reverse {
        &self.reverse
    }
}

/// THE live-path smoke: a writer admits over a unique named segment; an independent
/// reader (the ds-tlsproxy read shape) attaches by name; the PRODUCTION `decide` runs
/// over the live reader + a real allowing policy and a policy-allowed SNI whose kernel
/// `original_dst` is admitted yields a FORWARD **Proceed** (`Tunnel`).
#[test]
fn live_shm_reader_drives_a_forward_proceed_through_the_production_decide() {
    let name = unique_segment_name("proceed");
    let sni = "cdn.smoke.test";
    let admitted_ip = v4(203, 0, 113, 42);

    // ── WRITER: create the named segment + admit (the ds-dnsgate write shape) ─────
    let mut writer =
        ShmAdmissionMap::create_named(&name, 64, 64).expect("create the named shm segment");
    let key = AdmissionKey {
        session_uuid: SESSION_UUID.to_string(),
        original_query_fqdn: sni.to_string(),
    };
    ds_contracts::dns_admission::AdmissionMap::admit(
        &mut writer,
        key.clone(),
        live_entry(admitted_ip.clone()),
    )
    .expect("the writer admits the entry onto the shm segment");

    // ── READER: attach an INDEPENDENT read-only handle by name (the ds-tlsproxy
    //    `acquire_admission_map` shape) and adapt it as the frozen AdmissionMap. ──
    let reader = ReaderMap {
        reader: ShmAdmissionReader::attach_named(&name).expect("attach the read-only reader"),
        reverse: InertReverse,
    };

    // Sanity: the live reader sees the writer's admission cross-handle (the raw
    // reader's seqlock read, the same one the adapter's `lookup` delegates to).
    assert_eq!(
        reader
            .reader
            .lookup(&key)
            .expect("reader sees the admission")
            .admitted_ips,
        vec![admitted_ip.clone()],
        "the live reader reads the writer's admission back over the named segment"
    );

    // ── DECIDE: the PRODUCTION FORWARD decision over the LIVE reader. A policy-allowed
    //    SNI whose kernel original_dst IS the admitted IP yields a FORWARD Proceed. ──
    let policy = allowing_policy(sni);
    let oracle = PolicyCoreOracle::new(&policy);
    let hello = client_hello_with_sni(sni);
    let origin = origin_to("203.0.113.42:443"); // == the admitted IP

    let decision = decide(&hello, &origin, &reader, &oracle, now());
    assert_eq!(
        decision,
        Tls1Decision::Tunnel,
        "a policy-allowed SNI with a LIVE shm admission for its kernel dst is a FORWARD Proceed \
         (opaque tunnel) — the end-to-end writer→reader→decide live path"
    );

    ShmAdmissionMap::unlink(&name).expect("unlink the test segment");
}

/// FAIL-CLOSED on the SAME live reader: a policy-allowed SNI whose kernel `original_dst`
/// is NOT in the admitted set is the CDN SNI-dst mismatch — Refuse, never substitute.
#[test]
fn live_shm_reader_refuses_a_dst_outside_the_admitted_set() {
    let name = unique_segment_name("mismatch");
    let sni = "cdn.smoke.test";

    let mut writer =
        ShmAdmissionMap::create_named(&name, 64, 64).expect("create the named shm segment");
    let key = AdmissionKey {
        session_uuid: SESSION_UUID.to_string(),
        original_query_fqdn: sni.to_string(),
    };
    ds_contracts::dns_admission::AdmissionMap::admit(
        &mut writer,
        key,
        live_entry(v4(203, 0, 113, 42)),
    )
    .expect("admit 203.0.113.42 only");

    let reader = ReaderMap {
        reader: ShmAdmissionReader::attach_named(&name).expect("attach reader"),
        reverse: InertReverse,
    };
    let policy = allowing_policy(sni);
    let oracle = PolicyCoreOracle::new(&policy);
    let hello = client_hello_with_sni(sni);
    // A DIFFERENT kernel dst than the admitted IP: the CDN hole — must refuse.
    let origin = origin_to("198.51.100.9:443");

    assert!(
        matches!(
            decide(&hello, &origin, &reader, &oracle, now()),
            Tls1Decision::Refuse(_)
        ),
        "an admitted SNI but a non-admitted kernel dst is the CDN SNI-dst mismatch (fail-closed)"
    );

    ShmAdmissionMap::unlink(&name).expect("unlink the test segment");
}

/// FAIL-CLOSED on the SAME live reader: a policy-allowed SNI with NO live admission is a
/// D68 ReAdmit (re-admit, not refuse). The decision itself is ReAdmit; the listener then
/// drives the re-resolve seam — which, not wired, refuses fail-closed. Here we assert the
/// decision is the D68 ReAdmit (the gate never fabricates an admission off an empty map).
#[test]
fn live_shm_reader_re_admits_a_policy_allowed_sni_with_no_admission() {
    let name = unique_segment_name("readmit");
    let sni = "cdn.smoke.test";

    // Create an EMPTY segment (no admission written), attach the reader.
    let _writer =
        ShmAdmissionMap::create_named(&name, 64, 64).expect("create the empty named shm segment");
    let reader = ReaderMap {
        reader: ShmAdmissionReader::attach_named(&name).expect("attach reader"),
        reverse: InertReverse,
    };
    let policy = allowing_policy(sni);
    let oracle = PolicyCoreOracle::new(&policy);
    let hello = client_hello_with_sni(sni);
    let origin = origin_to("203.0.113.42:443");

    // No live admission for the SNI → D68 ReAdmit (the gate signals re-resolve, never
    // an outright admit off the empty map). The not-wired re-resolve then refuses
    // fail-closed at the listener — the boundary is never weakened by an empty map.
    assert!(
        matches!(
            decide(&hello, &origin, &reader, &oracle, now()),
            Tls1Decision::ReAdmit { .. }
        ),
        "a policy-allowed SNI with no live admission re-admits (D68 re-admit-not-refuse); the \
         empty map never fabricates a Proceed"
    );

    ShmAdmissionMap::unlink(&name).expect("unlink the test segment");
}
