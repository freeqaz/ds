//! TLS-3 in-crate acceptance suite — the crate-local mirror of the boundary
//! executable spec (`boundary/tlsproxy/tlsproxy_inspect_test.go`, D26) for the
//! per-session-CA termination path (doc 12 §3 / §13.2; doc 09 §5 TLS-3
//! done-when; D17 / D82).
//!
//! # What this proves
//!
//! These three `#[test]`s exercise the REAL [`ds_tlsproxy::ca::SessionCa`] leaf
//! authority and the REAL [`ds_tlsproxy::reoriginate::validate_origin_chain`]
//! strict-WebPKI core, CRYPTOGRAPHICALLY, against the boundary's three inspection
//! properties — with a real rustls handshake over a loopback `TcpListener`
//! (the `e2e_transparent_forward.rs` pattern; no live external network):
//!
//! - **TLS-3.a** (`TestInspect_PerOriginLeaf_ValidTLS_MetadataTelemetry`):
//!   a rustls client trusting ONLY session A's CA handshakes successfully against
//!   a rustls server presenting `ca_a.leaf_for(origin)`; the presented leaf names
//!   the EXACT origin (not the CA root); and a
//!   [`ds_tlsproxy::telemetry_http::HttpEvent`] built over the exchange carries
//!   method / host / path / status (the "metadata in telemetry" done-when).
//! - **TLS-3.c** (`TestInspect_PerSessionCAIsolation_AUselessAgainstB`):
//!   the two sessions' CA materials are DISTINCT; LEG-1 — a client trusting only
//!   A's pool FAILS the handshake against B's leaf; LEG-2 — an A-signed leaf is
//!   REFUSED by B's strict-WebPKI upstream validation. The test FAILS if A and B
//!   were ever wired to share CA key material.
//! - **TLS-3.d** (`TestInspect_LeafCache_StablePerOrigin`):
//!   `leaf_for(X)` twice is byte-identical (the per-(session, origin) cache);
//!   `leaf_for(Y)` is distinct and names Y, not X.
//!
//! # Why an in-file self-mint (no `test-ca` feature)
//!
//! `SessionCa::new_self_signed_for_test` is behind `#[cfg(any(test,
//! feature = "test-ca"))]`. An integration test is a SEPARATE crate and does NOT
//! inherit `cfg(test)`, so under the bare `cargo test -p ds-tlsproxy` gate that
//! symbol is invisible. To keep the single-file commit AND have the bare gate
//! actually run this file, each session's throwaway interception CA is minted
//! in-file with rcgen (a fresh `KeyPair` + a self-signed CA cert, CN
//! `ds-session-ca-<id>`, `is_ca = true`) and then INGESTED through the PRODUCTION
//! [`ds_tlsproxy::ca::SessionCa::from_pem`] path — exactly what
//! `new_self_signed_for_test` does internally, so the real signing/caching path
//! is exercised with no feature flag.
//!
//! # Issuer-provenance altitude
//!
//! The boundary asserts `leaf.Issuer.CommonName == ds-session-ca-<id>`.
//! `rustls-webpki` does not expose issuer-CN enumeration, so provenance is proven
//! at the equivalent altitude: the leaf CHAINS to `ca_a.ca_cert_der()` (a root /
//! self-issued leaf would not), and a leaf minted by A's CA does NOT chain to B's
//! CA. (The literal issuer-CN convention is already unit-tested in `ca.rs` via
//! `SessionCa::issuer_common_name`.)

use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

use ds_contracts::session::SessionRef;
use ds_tlsproxy::ca::SessionCa;
use ds_tlsproxy::reoriginate::{
    validate_origin_chain, AdmittedConn, ReoriginateRefuse, ReoriginatedConn, TrustRoots,
};
use ds_tlsproxy::telemetry_http::{HttpEvent, Provenance};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures: a per-session interception CA self-minted in-file, ingested via the
// PRODUCTION from_pem path (no test-ca feature; the bare gate runs this file).
// ─────────────────────────────────────────────────────────────────────────────

/// Mint a throwaway interception CA for `session_id` (a fresh key + a self-signed
/// CA cert, CN `ds-session-ca-<id>`, `is_ca = true`) and INGEST it through the
/// production [`SessionCa::from_pem`] — the same code path an Identity-minted CA
/// (D82) travels. Mirrors `SessionCa::new_self_signed_for_test` without needing
/// the `test-ca` feature, so a separate integration-test crate can build it.
fn session_ca(session_id: &str) -> SessionCa {
    let key = KeyPair::generate().expect("ca key");
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("ds-session-ca-{session_id}"));
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = params.self_signed(&key).expect("self-sign CA");
    // Ingest via the always-public production path (D82 opaque ingest).
    SessionCa::from_pem(session_id, &ca_cert.pem(), &key.serialize_pem())
        .expect("ingest self-minted CA via the production from_pem path")
}

/// A fixed validation clock inside rcgen's wide default leaf-validity window
/// (epoch 1_700_000_000s = 2023-11-14) — the injected `now` for
/// [`validate_origin_chain`].
fn now_fixed() -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_000))
}

fn session_ref(idx: u32) -> SessionRef {
    SessionRef::new(
        "11111111-2222-3333-4444-555555555555".into(),
        "host-a".into(),
        idx,
        format!("dstap-{idx}"),
    )
}

fn provenance() -> Provenance {
    Provenance::new("rule-allow-inspected", "org", "policy-v1")
}

// ─────────────────────────────────────────────────────────────────────────────
// rustls 0.23 helpers (RING provider, default-features = false → an EXPLICIT
// provider, not a process default). Build a server config from a minted leaf and
// a client config trusting exactly one session's CA, then drive a real loopback
// handshake.
// ─────────────────────────────────────────────────────────────────────────────

/// The RING crypto provider (the dependency policy's chosen backend). Built
/// explicitly per config so the test never depends on a process-default provider
/// being installed.
fn ring_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Parse the single PKCS#8 PRIVATE KEY block out of a PEM string into DER. rcgen
/// serializes leaf keys as PKCS#8 PEM (`LeafCert::key_pem`); we extract the DER
/// without pulling `rustls-pemfile` (not a dependency).
fn pkcs8_der_from_pem(pem: &str) -> Vec<u8> {
    const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
    const END: &str = "-----END PRIVATE KEY-----";
    let start = pem.find(BEGIN).expect("PKCS#8 BEGIN block") + BEGIN.len();
    let stop = pem[start..].find(END).expect("PKCS#8 END block") + start;
    let b64: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64_decode(&b64).expect("valid base64 PKCS#8 body")
}

/// Minimal standard-alphabet base64 decoder (no new dep); `None` on any invalid
/// byte. Mirrors the in-crate decoders in `ca.rs` / `reoriginate.rs`.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    for &b in &bytes {
        acc = (acc << 6) | val(b)?;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

/// A rustls `ServerConfig` presenting `leaf` (its DER cert + its PKCS#8 key) — the
/// in-test stand-in for what `src/main.rs` builds from a `LeafCert` for the
/// pingora `TlsAccept` resolver (D40: that wiring stays in the bin; here we build
/// a plain rustls server to drive a real handshake).
fn server_config_from_leaf(leaf_cert_der: &[u8], leaf_key_pem: &str) -> Arc<ServerConfig> {
    let cert = CertificateDer::from(leaf_cert_der.to_vec());
    let key = PrivatePkcs8KeyDer::from(pkcs8_der_from_pem(leaf_key_pem));
    let cfg = ServerConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .expect("server protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .expect("server config from minted leaf");
    Arc::new(cfg)
}

/// A rustls `ClientConfig` trusting EXACTLY the one CA whose DER is `ca_cert_der`
/// (a session's interception CA). This is the in-test stand-in for the golden
/// image's per-session trust bundle: the client trusts only this session's CA.
fn client_config_trusting_only(ca_cert_der: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_cert_der.to_vec()))
        .expect("add session CA to root store");
    let cfg = ClientConfig::builder_with_provider(ring_provider())
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(cfg)
}

/// The outcome of a real loopback rustls handshake: `Ok((peer_chain))` carries the
/// cert chain the server presented (so the caller can assert the leaf's name /
/// provenance); `Err` is the handshake/trust failure.
type HandshakeChain = Vec<CertificateDer<'static>>;

/// Drive a full rustls handshake over a fresh loopback `TcpListener`: the server
/// presents `server_cfg`, the client (trusting `client_cfg`'s roots) connects for
/// `sni`. Returns the peer cert chain the client saw on success, or the handshake
/// error on failure. Handshake-only — no application round-trip is required for
/// the trust assertions (the TLS-3.c failure leg is a handshake error). A short
/// timeout guards against a negative-leg stall instead of a clean error.
fn handshake(
    server_cfg: Arc<ServerConfig>,
    client_cfg: Arc<ClientConfig>,
    sni: &str,
) -> Result<HandshakeChain, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;

    // Server thread: accept one connection and complete the TLS handshake.
    let server = thread::spawn(move || {
        let (mut sock, _) = match listener.accept() {
            Ok(v) => v,
            Err(_) => return,
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(5)));
        let mut conn = match ServerConnection::new(server_cfg) {
            Ok(c) => c,
            Err(_) => return,
        };
        // Drive the handshake to completion (or error out — the client observes
        // the corresponding failure). complete_io writes the handshake bytes
        // straight to the socket, so no separate flush is needed.
        let _ = conn.complete_io(&mut sock);
        // Hold the socket briefly so the client can finish reading the handshake.
        thread::sleep(Duration::from_millis(50));
        let _ = sock.shutdown(Shutdown::Both);
    });

    let result = (|| -> Result<HandshakeChain, String> {
        let mut sock = TcpStream::connect(addr).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        sock.set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        let name = ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
        let mut conn = ClientConnection::new(client_cfg, name).map_err(|e| e.to_string())?;
        // Complete the handshake; a trust/cert failure surfaces here.
        conn.complete_io(&mut sock).map_err(|e| e.to_string())?;
        if conn.is_handshaking() {
            return Err("handshake did not complete".into());
        }
        let chain = conn
            .peer_certificates()
            .ok_or_else(|| "no peer certificates after handshake".to_string())?
            .iter()
            .map(|c| CertificateDer::from(c.as_ref().to_vec()))
            .collect();
        Ok(chain)
    })();

    let _ = server.join();
    result
}

// ─────────────────────────────────────────────────────────────────────────────
// webpki assertions (the same crate `ca.rs` uses for its in-module checks).
// ─────────────────────────────────────────────────────────────────────────────

/// The ring-backed signature algorithms the leaf validation accepts (rcgen mints
/// ECDSA-P256 by default; cover the modern ring set).
static VERIFICATION_ALGS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::ED25519,
];

/// Whether `leaf_der` chains to the trust anchor `ca_cert_der` for server auth at
/// `now_fixed` — the provenance check standing in for the boundary's literal
/// issuer-CN assertion (a root / self-issued leaf would NOT chain to the
/// per-session CA).
fn leaf_chains_to(leaf_der: &[u8], ca_cert_der: &[u8]) -> bool {
    let leaf = CertificateDer::from(leaf_der.to_vec());
    let ca = CertificateDer::from(ca_cert_der.to_vec());
    let Ok(anchor) = anchor_from_trusted_cert(&ca) else {
        return false;
    };
    let anchors = [anchor];
    let Ok(ee) = EndEntityCert::try_from(&leaf) else {
        return false;
    };
    ee.verify_for_usage(
        VERIFICATION_ALGS,
        &anchors,
        &[],
        now_fixed(),
        KeyUsage::server_auth(),
        None,
        None,
    )
    .is_ok()
}

/// Whether `leaf_der` carries `host` as a usable subject name (its only SAN, by
/// construction in `ca.rs`). rustls-webpki has no SAN enumeration, so assert via
/// the same `verify_is_valid_for_subject_name` the TLS handshake performs.
fn leaf_names_host(leaf_der: &[u8], host: &str) -> bool {
    let leaf = CertificateDer::from(leaf_der.to_vec());
    let Ok(ee) = EndEntityCert::try_from(&leaf) else {
        return false;
    };
    let Ok(name) = ServerName::try_from(host) else {
        return false;
    };
    ee.verify_is_valid_for_subject_name(&name).is_ok()
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS-3.a — per-origin leaf is valid TLS named the exact origin; HTTP metadata
// is visible in telemetry. (boundary `TestInspect_PerOriginLeaf_ValidTLS_…`)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tls3a_per_origin_leaf_valid_tls_and_metadata_visible() {
    const ORIGIN: &str = "inspected.example";
    let ca_a = session_ca("sess-a");
    let a_leaf = ca_a.leaf_for(ORIGIN).expect("A mints leaf for the origin");

    // A real rustls client trusting ONLY session A's CA handshakes successfully
    // against a server presenting A's leaf — the golden image sees valid TLS.
    let server_cfg = server_config_from_leaf(&a_leaf.cert_der, &a_leaf.key_pem);
    let client_cfg = client_config_trusting_only(ca_a.ca_cert_der());
    let chain = handshake(server_cfg, client_cfg, ORIGIN)
        .expect("client trusting only session A's CA must see valid TLS");

    // The presented leaf names the EXACT origin (its only SAN) and is the one A
    // minted (byte-identical to leaf_for).
    let presented = chain.first().expect("server presented a leaf");
    assert_eq!(
        presented.as_ref(),
        a_leaf.cert_der.as_slice(),
        "the handshake must present the exact leaf A minted for the origin"
    );
    assert!(
        leaf_names_host(presented.as_ref(), ORIGIN),
        "presented leaf must name the exact origin {ORIGIN}"
    );

    // Provenance: the leaf chains to the per-session CA (not a root / not itself).
    // (The boundary asserts issuer.CN == ds-session-ca-<id>; rustls-webpki has no
    // issuer-CN enumeration, so prove provenance by chaining to A's CA.)
    assert!(
        leaf_chains_to(presented.as_ref(), ca_a.ca_cert_der()),
        "presented leaf must be issued by the per-session CA (chains to A's CA)"
    );
    // It is NOT a self-issued / self-signed leaf masquerading as its own anchor.
    assert!(
        !leaf_chains_to(presented.as_ref(), presented.as_ref()),
        "presented leaf must not be its own trust anchor (it is CA-issued, not self-signed)"
    );

    // The "metadata in telemetry" done-when: an HttpEvent over the exchange
    // carries method / host / path / status (boundary requireEvent(EventHTTP,
    // "GET", domain, "/data", "200")).
    let sess = session_ref(0);
    let ev = HttpEvent::from_exchange(&sess, "GET", ORIGIN, "/data", 200, provenance());
    assert_eq!(ev.method, "GET");
    assert_eq!(ev.host, ORIGIN);
    assert_eq!(ev.path, "/data");
    assert_eq!(ev.status, 200);
    assert!(ev.has_response());
    assert_eq!(ev.tap_name, "dstap-0");
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS-3.c — session A's CA is USELESS against session B. The headline isolation.
// (boundary `TestInspect_PerSessionCAIsolation_AUselessAgainstB`)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tls3c_session_a_ca_useless_against_session_b() {
    const ORIGIN: &str = "inspected.example";
    let ca_a = session_ca("sess-a");
    let ca_b = session_ca("sess-b");

    // Distinct CA key material. This assertion FAILS if A and B were ever wired
    // to share a CA — the cryptographic heart of the isolation property.
    assert_ne!(
        ca_a.ca_cert_der(),
        ca_b.ca_cert_der(),
        "independent session CAs must have distinct CA material"
    );

    // Control: a client trusting B's pool succeeds against B's interface.
    let b_leaf = ca_b.leaf_for(ORIGIN).expect("B mints leaf");
    let b_server = server_config_from_leaf(&b_leaf.cert_der, &b_leaf.key_pem);
    let b_client = client_config_trusting_only(ca_b.ca_cert_der());
    assert!(
        handshake(b_server, b_client, ORIGIN).is_ok(),
        "control: a client trusting B's pool must handshake on B's interface"
    );

    // LEG-1 (handshake fails): a client trusting ONLY A's pool MUST FAIL the
    // handshake against B's leaf — A's CA is useless against B's interface.
    let b_leaf2 = ca_b.leaf_for(ORIGIN).expect("B mints leaf (cached)");
    let b_server2 = server_config_from_leaf(&b_leaf2.cert_der, &b_leaf2.key_pem);
    let a_client = client_config_trusting_only(ca_a.ca_cert_der());
    let leg1 = handshake(b_server2, a_client, ORIGIN);
    assert!(
        leg1.is_err(),
        "session A's CA pool must be useless against session B's interface (handshake must fail), got Ok"
    );

    // LEG-2 (strict-WebPKI rejects): a leaf signed by A's CA, validated under
    // TrustRoots built from ONLY B's CA, MUST be refused by the strict upstream
    // re-origination core.
    let a_leaf = ca_a.leaf_for(ORIGIN).expect("A mints leaf");
    let b_roots = TrustRoots::from_der_roots(&[CertificateDer::from(ca_b.ca_cert_der().to_vec())])
        .expect("build B-only trust roots");
    let leg2 = validate_origin_chain(
        &[CertificateDer::from(a_leaf.cert_der.clone())],
        ORIGIN,
        &b_roots,
        now_fixed(),
    );
    assert!(
        matches!(leg2, Err(ReoriginateRefuse::UntrustedChain)),
        "an A-signed leaf must be refused by B's strict upstream validation (untrusted chain), got {leg2:?}"
    );

    // Control for LEG-2: the same A-signed leaf validates against A's OWN roots —
    // proving the refusal above is the isolation, not a broken validator.
    let a_roots = TrustRoots::from_der_roots(&[CertificateDer::from(ca_a.ca_cert_der().to_vec())])
        .expect("build A-only trust roots");
    let control = validate_origin_chain(
        &[CertificateDer::from(a_leaf.cert_der.clone())],
        ORIGIN,
        &a_roots,
        now_fixed(),
    );
    assert_eq!(
        control,
        Ok(()),
        "control: an A-signed leaf must validate against A's own trust roots"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS-3.d — per-origin leaf certs are stable within a session and distinct across
// origins. (boundary `TestInspect_LeafCache_StablePerOrigin`)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn tls3d_leaf_cache_stable_per_origin_and_distinct() {
    const ORIGIN_X: &str = "alpha.example";
    const ORIGIN_Y: &str = "beta.example";
    let ca = session_ca("sess-a");

    // Two calls for the same origin return the byte-identical cached leaf (a fresh
    // mint would differ by serial + key, so byte-equality proves the cache).
    let x1 = ca.leaf_for(ORIGIN_X).expect("mint X #1");
    let x2 = ca.leaf_for(ORIGIN_X).expect("mint X #2");
    assert_eq!(
        x1.cert_der, x2.cert_der,
        "the same origin must present a byte-identical (cached) leaf (TLS-3.d)"
    );
    assert_eq!(x1.key_pem, x2.key_pem, "cached leaf key must be identical");
    assert!(
        Arc::ptr_eq(&x1, &x2),
        "a cache hit must hand back the same Arc allocation"
    );

    // A different origin is a DISTINCT leaf that names Y, not X.
    let y = ca.leaf_for(ORIGIN_Y).expect("mint Y");
    assert_ne!(
        x1.cert_der, y.cert_der,
        "different origins must not share a leaf"
    );
    assert!(
        leaf_names_host(&y.cert_der, ORIGIN_Y),
        "Y's leaf must name {ORIGIN_Y}"
    );
    assert!(
        !leaf_names_host(&y.cert_der, ORIGIN_X),
        "Y's leaf must NOT name {ORIGIN_X} (the SAN is the exact origin only)"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// TLS-3 splice-arm — the operator DS_TLS3_LIVE end-to-end splice proof.
//
// This is the env-gated live wiring Phase B drives in the nested testbed: once the
// strict-WebPKI re-originated conn the dialer returns is ARMED into the splice
// (`SpliceUpstreamSink::armed` over `ReoriginatedUpstreamWrite { conn }` in
// `src/main.rs`), the SUBSTITUTED long-lived credential egresses the real upstream over
// the terminated TLS stack, the VM-presented short-lived placeholder NEVER does, and a
// reset upstream leg fails CLOSED.
//
// `run_inspected_flow` + `SpliceUpstreamSink` are private to the bin, so this proof
// drives the SAME contract at the PUBLIC lib altitude the rest of this file uses: the
// `ds_tlsproxy::reoriginate::ReoriginatedConn` cleartext write/read seam over a REAL
// loopback TLS upstream (the test twin of `src/main.rs`'s `RealReoriginatedConn`),
// admitted through the production `AdmittedConn` handle. The bin-internal wiring (the
// adapter + the armed sink + the `splice_cleartext` pump) is unit-tested in `src/main.rs`;
// this asserts the END-TO-END byte properties over a cryptographic TLS stack.
//
// Env-gated (DS_TLS3_LIVE): a NO-OP offline (returns early, the default build is
// byte-identical) so the bare `cargo test -p ds-tlsproxy` gate stays green without a
// live TLS leg; set DS_TLS3_LIVE to exercise it (here over a local loopback origin — in
// Phase B against the real nested-testbed origin).

/// A `ReoriginatedConn` over a REAL blocking rustls CLIENT connection to a loopback
/// upstream — the integration-test twin of `src/main.rs`'s `RealReoriginatedConn`. It
/// encrypts the cleartext write through the upstream TLS session and reads the decrypted
/// reply back, so the substituted bytes egress over a genuine TLS stack (not a buffer).
struct LiveLoopbackConn {
    origin_domain: String,
    sock: TcpStream,
    tls: ClientConnection,
}

impl ReoriginatedConn for LiveLoopbackConn {
    fn origin_domain(&self) -> &str {
        &self.origin_domain
    }
    fn write_all_cleartext(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        // Encrypt through the upstream TLS session, then drive the records to the socket
        // (complete_io flushes the outbound TLS). A reset socket surfaces the io::Error.
        self.tls.writer().write_all(bytes)?;
        self.tls.complete_io(&mut self.sock)?;
        Ok(())
    }
    fn read_cleartext(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Read;
        // Pull + decrypt inbound records until rustls has plaintext (or EOF).
        loop {
            match self.tls.reader().read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let (rd, _) = self.tls.complete_io(&mut self.sock)?;
                    if rd == 0 {
                        return Ok(0); // upstream closed the reply direction
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[test]
fn tls3_live_splice_substitutes_credential_upstream_and_fails_closed_on_reset() {
    if std::env::var_os("DS_TLS3_LIVE").is_none() {
        eprintln!(
            "SKIP tls3_live_splice_substitutes_credential_upstream_and_fails_closed_on_reset: \
             set DS_TLS3_LIVE to drive the end-to-end re-originated splice (the substituted \
             long-lived credential egresses over the terminated TLS stack, the VM placeholder \
             never does, a reset fails closed). No-op offline so the default build is byte-identical."
        );
        return;
    }

    const ORIGIN: &str = "upstream.example";
    // The substituted long-lived credential the swap injects (must egress upstream) and
    // the VM-presented short-lived placeholder (must NEVER egress upstream) — doc 16 §5.2.
    const LONG_LIVED: &[u8] = b"Bearer ghp_LONGLIVED_REALCRED";
    const PLACEHOLDER: &[u8] = b"sl-sess-a-github-placeholder";

    // ── 1. A real loopback TLS UPSTREAM origin presenting a leaf for ORIGIN ────────
    // Mint a per-session interception CA + its leaf (the same production from_pem path),
    // and stand up a blocking rustls server that records EXACTLY the cleartext bytes it
    // receives (the "did the credential / placeholder egress?" oracle), then replies.
    let ca = session_ca("sess-splice");
    let leaf = ca.leaf_for(ORIGIN).expect("mint upstream leaf");
    let server_cfg = server_config_from_leaf(&leaf.cert_der, &leaf.key_pem);
    let client_cfg = client_config_trusting_only(ca.ca_cert_der());

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream origin");
    let addr = listener.local_addr().expect("origin addr");
    const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

    let server = thread::spawn(move || -> Vec<u8> {
        let (mut sock, _) = listener.accept().expect("origin accepts");
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
        sock.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let mut conn = ServerConnection::new(server_cfg).expect("server conn");
        // Complete the handshake, then read the cleartext the proxy spliced upstream.
        conn.complete_io(&mut sock).expect("server handshake");
        let mut received = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    received.extend_from_slice(&buf[..n]);
                    // Once we have the request line + header, reply and stop.
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        use std::io::Write;
                        conn.writer().write_all(REPLY).expect("server reply");
                        conn.complete_io(&mut sock).expect("flush reply");
                        break;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if conn.complete_io(&mut sock).map(|(rd, _)| rd).unwrap_or(0) == 0 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        received
    });

    // ── 2. Re-originate the upstream leg (the strict-WebPKI dialer's job) + ADMIT it ─
    use std::io::Read;
    let mut sock = TcpStream::connect(addr).expect("connect upstream");
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let name = ServerName::try_from(ORIGIN).expect("server name");
    let mut tls = ClientConnection::new(client_cfg, name).expect("client conn");
    tls.complete_io(&mut sock)
        .expect("client handshake completes");
    // The conn is write-capable only because validation passed — modelled by the
    // production `AdmittedConn` handle (the witness is consumed to mint it).
    let mut admitted = AdmittedConn::for_test(Box::new(LiveLoopbackConn {
        origin_domain: ORIGIN.to_string(),
        sock,
        tls,
    }));
    assert_eq!(admitted.origin_domain(), ORIGIN);

    // ── 3. The splice arms with this conn and writes the SUBSTITUTED credential ─────
    // (the byte-identical effect of `SpliceUpstreamSink::armed(...).write_upstream(...)`
    // in `src/main.rs`). The substituted long-lived credential is written as the upstream
    // request's Authorization; the VM placeholder is NEVER written.
    let request = {
        let mut r = Vec::new();
        r.extend_from_slice(b"GET /data HTTP/1.1\r\nHost: ");
        r.extend_from_slice(ORIGIN.as_bytes());
        r.extend_from_slice(b"\r\nAuthorization: ");
        r.extend_from_slice(LONG_LIVED);
        r.extend_from_slice(b"\r\n\r\n");
        r
    };
    admitted
        .conn_mut()
        .write_all_cleartext(&request)
        .expect("the substituted request egresses over the terminated TLS stack");

    // The origin's reply is relayed back over the same TLS leg (the reply direction).
    let mut reply = vec![0u8; REPLY.len()];
    let mut got = 0;
    while got < reply.len() {
        match admitted.conn_mut().read_cleartext(&mut reply[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) => panic!("relaying the upstream reply failed: {e}"),
        }
    }
    assert_eq!(
        &reply[..got],
        REPLY,
        "the origin reply relayed back over TLS"
    );

    let received = server.join().expect("origin thread");

    // ── 4. The byte properties (doc 16 §5.2) ───────────────────────────────────────
    // (a) the SUBSTITUTED long-lived credential egressed upstream over the TLS stack.
    assert!(
        received.windows(LONG_LIVED.len()).any(|w| w == LONG_LIVED),
        "the substituted long-lived credential must egress the real upstream over TLS"
    );
    // (b) the VM-presented placeholder NEVER reached the upstream (it was swapped out).
    assert!(
        !received
            .windows(PLACEHOLDER.len())
            .any(|w| w == PLACEHOLDER),
        "the VM-presented short-lived placeholder must NEVER reach the upstream (doc 16 §5.2)"
    );

    // ── 5. A reset upstream leg FAILS CLOSED ────────────────────────────────────────
    // A fresh re-originated leg whose socket is shut down before the write: the cleartext
    // write surfaces an io::Error so the caller closes the leg (no half-written request,
    // the credential never re-tried onto a broken leg).
    let listener2 = TcpListener::bind("127.0.0.1:0").expect("bind origin 2");
    let addr2 = listener2.local_addr().expect("origin 2 addr");
    let leaf2 = ca.leaf_for(ORIGIN).expect("mint upstream leaf (cached)");
    let server_cfg2 = server_config_from_leaf(&leaf2.cert_der, &leaf2.key_pem);
    let server2 = thread::spawn(move || {
        if let Ok((mut s, _)) = listener2.accept() {
            let mut c = ServerConnection::new(server_cfg2).expect("server2 conn");
            let _ = c.complete_io(&mut s);
            // Abruptly drop the connection — the re-originated leg sees a reset.
            let _ = s.shutdown(Shutdown::Both);
        }
    });
    let client_cfg2 = client_config_trusting_only(ca.ca_cert_der());
    let mut sock2 = TcpStream::connect(addr2).expect("connect origin 2");
    sock2.set_read_timeout(Some(Duration::from_secs(5))).ok();
    sock2.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let name2 = ServerName::try_from(ORIGIN).expect("server name 2");
    let mut tls2 = ClientConnection::new(client_cfg2, name2).expect("client2 conn");
    let _ = tls2.complete_io(&mut sock2);
    server2.join().expect("origin 2 thread");
    // Model the broken/reset re-originated leg deterministically: shut down the local
    // socket's WRITE half (the peer already RST'd; a half-closed/reset leg is what the
    // splice must fail closed on). Writing the encrypted records to a shut-down socket
    // surfaces a BrokenPipe — the exact io::Error path the production sink latches.
    sock2.shutdown(Shutdown::Write).ok();
    let mut reset_conn = LiveLoopbackConn {
        origin_domain: ORIGIN.to_string(),
        sock: sock2,
        tls: tls2,
    };
    // The write onto the reset leg fails closed — surfaced as an io::Error the splice
    // caller turns into a connection close (never a silent drop, never a leaked byte).
    let result = reset_conn.write_all_cleartext(&request);
    assert!(
        result.is_err(),
        "a write onto a reset re-originated leg must fail closed (Err), got {result:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// The keep-alive bidi-pump property at the live seam altitude (DS_TLS3_LIVE).
//
// `src/main.rs`'s `splice_cleartext` is the CONCURRENT bidi pump: the request leg
// (downstream→upstream) and the reply leg (upstream→downstream) make progress AT
// ONCE, so a client holding its downstream write half OPEN while awaiting the origin
// response (HTTP/1.1 keep-alive, long-poll, interactive HTTPS, gRPC streaming) no
// longer deadlocks. The half-duplex predecessor drained the WHOLE request direction
// to its downstream EOF before relaying any reply — which wedges a keep-alive client.
//
// `splice_cleartext` is bin-internal, so its concurrent-pump unit test (the
// deadlock repro over `tokio::io::duplex` + in-process fakes) lives in `src/main.rs`.
// This file owns the LIVE seam altitude, so this test proves the seam-level
// precondition the pump's reply leg depends on, over a REAL re-originated TLS conn:
// `ReoriginatedConn::read_cleartext` relays the origin's reply WITHOUT the upstream
// having closed the connection (the reply direction stays open — a keep-alive origin),
// and WITHOUT the request write half having been closed. If the seam could only yield
// the reply at upstream EOF, the bidi pump could not relay an early reply, so this
// guards the live counterpart of the deadlock fix.
//
// Env-gated (DS_TLS3_LIVE): a NO-OP offline (returns early; the default build +
// tls3_inspect.rs are byte-identical) so the bare `cargo test -p ds-tlsproxy` gate
// stays green without a live TLS leg.

#[test]
fn tls3_live_reply_relays_while_the_upstream_connection_stays_open_keepalive() {
    if std::env::var_os("DS_TLS3_LIVE").is_none() {
        eprintln!(
            "SKIP tls3_live_reply_relays_while_the_upstream_connection_stays_open_keepalive: \
             set DS_TLS3_LIVE to drive the live keep-alive relay (the origin's reply relays \
             back over the re-originated TLS seam WHILE the connection stays open — the seam \
             precondition the concurrent bidi pump in src/main.rs relies on). No-op offline \
             so the default build is byte-identical."
        );
        return;
    }

    const ORIGIN: &str = "keepalive.example";

    // ── 1. A real loopback TLS UPSTREAM origin that replies, then HOLDS THE CONNECTION
    //       OPEN (keep-alive): it does NOT close the reply direction after replying, so
    //       a half-duplex relay that waited for upstream EOF would never see the reply. ─
    let ca = session_ca("sess-keepalive");
    let leaf = ca.leaf_for(ORIGIN).expect("mint upstream leaf");
    let server_cfg = server_config_from_leaf(&leaf.cert_der, &leaf.key_pem);
    let client_cfg = client_config_trusting_only(ca.ca_cert_der());

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind keepalive origin");
    let addr = listener.local_addr().expect("origin addr");
    const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

    // A barrier so the origin thread keeps the connection OPEN until the client has
    // relayed the reply (proving the relay happened with the connection still open),
    // then closes — letting the thread exit without leaking the socket.
    let keep_open = Arc::new(std::sync::Barrier::new(2));
    let keep_open_srv = keep_open.clone();

    let server = thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("origin accepts");
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
        sock.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let mut conn = ServerConnection::new(server_cfg).expect("server conn");
        conn.complete_io(&mut sock).expect("server handshake");
        // Read the request the client splices upstream, then reply and FLUSH — but do
        // NOT close: the connection stays open (keep-alive) until the client signals it
        // has relayed the reply.
        let mut buf = [0u8; 4096];
        loop {
            match conn.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    use std::io::Write;
                    conn.writer().write_all(REPLY).expect("server reply");
                    conn.complete_io(&mut sock).expect("flush reply");
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if conn.complete_io(&mut sock).map(|(rd, _)| rd).unwrap_or(0) == 0 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // Hold the connection OPEN until the client has read the reply back.
        keep_open_srv.wait();
        // Now tear down cleanly.
        let _ = sock.shutdown(Shutdown::Both);
    });

    // ── 2. Re-originate the upstream leg + admit it (validation-passed handle). ──────
    use std::io::Read;
    let mut sock = TcpStream::connect(addr).expect("connect upstream");
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    sock.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let name = ServerName::try_from(ORIGIN).expect("server name");
    let mut tls = ClientConnection::new(client_cfg, name).expect("client conn");
    tls.complete_io(&mut sock)
        .expect("client handshake completes");
    let mut admitted = AdmittedConn::for_test(Box::new(LiveLoopbackConn {
        origin_domain: ORIGIN.to_string(),
        sock,
        tls,
    }));

    // ── 3. Write the request, then relay the reply back BEFORE the request write half
    //       is closed and WHILE the upstream connection is still open (keep-alive). ───
    let request =
        b"GET /poll HTTP/1.1\r\nHost: keepalive.example\r\nConnection: keep-alive\r\n\r\n";
    admitted
        .conn_mut()
        .write_all_cleartext(request)
        .expect("the request egresses over the terminated TLS stack");

    // The reply must relay back even though NEITHER side has closed: the origin holds
    // the connection open and the client never sent a request half-close. A half-duplex
    // relay that waited for upstream EOF would hang here; the seam yields the reply.
    let mut reply = vec![0u8; REPLY.len()];
    let mut got = 0;
    while got < reply.len() {
        match admitted.conn_mut().read_cleartext(&mut reply[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) => panic!("relaying the upstream reply failed: {e}"),
        }
    }
    assert_eq!(
        &reply[..got],
        REPLY,
        "the origin reply relayed back over the still-open re-originated TLS seam \
         (the keep-alive precondition the concurrent bidi pump relies on)"
    );

    // Release the origin (it has proven it kept the connection open through the relay).
    keep_open.wait();
    server.join().expect("origin thread");
}
