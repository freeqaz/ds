//! TLS-3 per-session interception CA + per-origin leaf authority (doc 12 §3 /
//! §13.2; doc 16 §4; D17 / D82). **Pingora-free** by construction — this module
//! is the lib-side crypto foundation the TLS-3 termination path stacks on, and a
//! review that finds any pingora-* type here FAILS (D40 / doc 12 §13.1).
//!
//! # What this is
//!
//! When a flow is *inspected* (TLS-3, doc 09 §5), the proxy terminates the VM's
//! TLS with a **per-session interception CA** and presents a leaf cert it minted
//! for the exact origin SNI. The golden image trusts this session's CA, so
//! `curl`/`npm`/`git` see valid TLS while the proxy gets cleartext for
//! HTTP-level policy + telemetry. This module owns the crypto half of that:
//!
//! - [`SessionCa`] holds **one** session's interception CA cert + private key as
//!   **opaque ingested material** (D82: the CA is minted by Identity (D22) and
//!   ingested here — it is NOT minted in-process in production). The private key
//!   never leaves this struct.
//! - [`SessionCa::leaf_for`] mints a leaf signed by the session CA whose only SAN
//!   is the **exact** origin host (doc 12 §3 / §13.2), cached per origin host.
//!
//! # Cache (doc 12 §13.2)
//!
//! The leaf cache is keyed on **origin-host only**: the *session* is the
//! partition (it is the [`SessionCa`] instance), the host is the key. The cache
//! lives for the `SessionCa` and is dropped whole when the `SessionCa` drops at
//! session teardown — option (c), unbounded-per-session-then-drop: no
//! cross-session reasoning, no eviction logic. `leaf_for` is **cache-first**, so
//! a second call for the same host returns the byte-identical cached leaf (the
//! TLS-3.d stability property the boundary spec asserts).
//!
//! # Isolation (D17, doc 09 §5 done-when)
//!
//! Each `SessionCa` is an independent key pair, so a leaf minted by session A's
//! CA fails chain validation against a trust pool built from only session B's CA
//! (the TLS-3.c "A's CA is useless against B" property). The interception CA's
//! subject CN follows the boundary fixture convention `ds-session-ca-<id>` so
//! downstream telemetry/conformance can assert provenance; the session id is
//! supplied at construction, never hardcoded.
//!
//! # Pingora confinement (D40 / doc 12 §13.1)
//!
//! This module returns a plain [`LeafCert`] (DER + PEM + key PEM). The bin target
//! (`src/main.rs`) is the ONLY place that turns it into a pingora `TlsAccept`
//! resolver / rustls server config — no rustls **server** type or pingora type
//! leaks here. (`rustls-webpki` is used in tests only, for verification.)

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
// `BasicConstraints` is only referenced by `ca_params` (test/self-mint CA params);
// the production ingest path now reconstructs the issuer from the ingested CA cert
// (`Issuer::from_ca_cert_der`) and never builds synthetic CA params. Gate the import
// to the same cfg so the default build carries no unused-import warning (clippy -D).
#[cfg(any(test, feature = "test-ca"))]
use rcgen::BasicConstraints;

/// The boundary fixture convention for the interception CA's subject/issuer
/// common name: `ds-session-ca-<session-id>` (mirrors
/// `boundary/tlsproxy/tlsproxy_inspect_test.go` `TestNonListedDomain_AlwaysInspected`,
/// which asserts the presented leaf's issuer CN equals this). Downstream
/// telemetry/conformance assert provenance against it. The session id is the
/// argument — never hardcoded.
pub fn session_ca_common_name(session_id: &str) -> String {
    format!("ds-session-ca-{session_id}")
}

/// The error surface for CA ingest + leaf minting. Construction parses the
/// ingested opaque key/cert material; minting signs a leaf — both can fail on
/// malformed input, surfaced as [`CaError`] rather than panicking, so the
/// listener layer can map an ingest/mint failure onto the doc 12 §13.5 error
/// table (REFUSE) rather than crash.
#[derive(Debug)]
pub enum CaError {
    /// The ingested CA private key material (PEM/DER) could not be parsed.
    KeyParse(String),
    /// The ingested CA certificate material (PEM) could not be parsed.
    CertParse(String),
    /// Building the issuer / signing a leaf failed.
    Sign(String),
}

impl std::fmt::Display for CaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaError::KeyParse(e) => write!(f, "ds-tlsproxy CA: key parse: {e}"),
            CaError::CertParse(e) => write!(f, "ds-tlsproxy CA: cert parse: {e}"),
            CaError::Sign(e) => write!(f, "ds-tlsproxy CA: leaf sign: {e}"),
        }
    }
}

impl std::error::Error for CaError {}

/// A minted per-origin leaf: the cert (DER + PEM) and its private key (PEM). The
/// bin target (`src/main.rs`) builds the pingora/rustls server resolver from
/// these bytes — no server-side TLS type lives here (D40). Cloneable and shared
/// behind an `Arc` in the cache so a cache hit hands back the byte-identical
/// material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafCert {
    /// The exact origin host this leaf was minted for (its only SAN DNS name).
    pub origin_host: String,
    /// The leaf certificate, DER-encoded.
    pub cert_der: Vec<u8>,
    /// The leaf certificate, PEM-encoded.
    pub cert_pem: String,
    /// The leaf's private key, PEM-encoded (PKCS#8).
    pub key_pem: String,
}

/// One session's interception CA: the opaque, ingested CA cert + private key
/// (D82) plus the per-origin leaf cache (doc 12 §13.2). The CA private key never
/// leaves this struct; `leaf_for` mints + caches leaves on `&self`.
pub struct SessionCa {
    /// The session id this CA belongs to (drives the `ds-session-ca-<id>` issuer
    /// CN and provenance).
    session_id: String,
    /// The ingested CA certificate, DER-encoded. This is the trust anchor a
    /// golden image / test pool is built from, and (its subject) the issuer DN
    /// every leaf this CA mints carries.
    ca_cert_der: Vec<u8>,
    /// The ingested CA certificate, PEM-encoded (the `CertPool` export shape).
    ca_cert_pem: String,
    /// The reconstructed signing issuer: the ingested CA key bound to the CA
    /// params. The leaf's issuer field is set to this issuer's subject DN (which
    /// equals the ingested CA cert's subject by construction), so a leaf chains
    /// to `ca_cert_der`. Owns its params (`Issuer<'static, _>`).
    issuer: Issuer<'static, KeyPair>,
    /// The per-origin leaf cache: host -> cached leaf. Interior-mutable so
    /// minting is shareable on `&self` (mirrors the `SeveringRegistry` Mutex
    /// pattern in `lib.rs`). Dropped whole with the `SessionCa` at teardown.
    leaves: Mutex<BTreeMap<String, Arc<LeafCert>>>,
}

impl SessionCa {
    /// Ingest a session's interception CA from PEM material (D82: the CA is
    /// minted by Identity and ingested here as opaque bytes — NOT minted
    /// in-process).
    ///
    /// `ca_cert_pem` is the CA certificate (the trust anchor + the leaf's issuer
    /// identity); `ca_key_pem` is the CA's PKCS#8 private key. The CA cert's
    /// subject is expected to be `ds-session-ca-<session_id>` per the D82 / doc 16
    /// §4 convention — the reconstructed issuer uses that CN so the leaves this CA
    /// mints carry an issuer DN matching the ingested CA cert's subject (required
    /// for the leaf to chain to `ca_cert_pem`). The private key never leaves the
    /// returned struct.
    pub fn from_pem(
        session_id: impl Into<String>,
        ca_cert_pem: &str,
        ca_key_pem: &str,
    ) -> Result<SessionCa, CaError> {
        let session_id = session_id.into();
        let key = KeyPair::from_pem(ca_key_pem).map_err(|e| CaError::KeyParse(e.to_string()))?;
        let ca_cert_der = pem_block_to_der(ca_cert_pem, "CERTIFICATE")
            .ok_or_else(|| CaError::CertParse("no CERTIFICATE block in CA cert PEM".into()))?;
        Self::assemble(session_id, ca_cert_der, ca_cert_pem.to_string(), key)
    }

    /// Ingest a session's interception CA from DER cert + PEM key. The DER cert is
    /// the opaque trust-anchor material; the key is the opaque PKCS#8 PEM. See
    /// [`SessionCa::from_pem`] for the issuer-DN / D82 semantics.
    pub fn from_der_cert_pem_key(
        session_id: impl Into<String>,
        ca_cert_der: &[u8],
        ca_key_pem: &str,
    ) -> Result<SessionCa, CaError> {
        let session_id = session_id.into();
        let key = KeyPair::from_pem(ca_key_pem).map_err(|e| CaError::KeyParse(e.to_string()))?;
        let ca_cert_pem = der_to_pem_block(ca_cert_der, "CERTIFICATE");
        Self::assemble(session_id, ca_cert_der.to_vec(), ca_cert_pem, key)
    }

    /// Shared construction tail: reconstruct the signing issuer from the ingested
    /// key + the ingested CA **cert** (not a fabricated DN) and stash the opaque
    /// cert material.
    ///
    /// The signing [`Issuer`]'s subject DN MUST equal the ingested CA cert's
    /// **actual** subject, because `signed_by` copies the issuer's DN into each
    /// leaf's `issuer` field and a client builds the chain by matching that field
    /// to the trust-anchor's subject DN. Deriving the issuer DN from
    /// `ca_params(session_id)` (CN `ds-session-ca-<session_id>`) only chains when
    /// the operator happened to name the CA exactly that; an Identity- or
    /// operator-minted CA with any other subject (e.g. a testbed CA named
    /// `ds-session-ca-l1-testbed` under a different `DS_SESSION_UUID`) yields leaves
    /// whose `issuer` field does not match the CA's `subject` → every *validating*
    /// client fails path-building ("unable to get local issuer certificate") and
    /// aborts the connection (observed live as the VM-side TLS RST that fails-closed
    /// the swap; `curl -k` masked it by skipping verification). So parse the real
    /// subject out of the ingested cert and reconstruct the issuer from it
    /// (`Issuer::from_ca_cert_der`), making the chain valid for ANY ingested CA.
    fn assemble(
        session_id: String,
        ca_cert_der: Vec<u8>,
        ca_cert_pem: String,
        key: KeyPair,
    ) -> Result<SessionCa, CaError> {
        let cert_der = rustls_pki_types::CertificateDer::from(ca_cert_der.clone());
        let issuer = Issuer::from_ca_cert_der(&cert_der, key)
            .map_err(|e| CaError::CertParse(format!("issuer from ingested CA cert: {e}")))?;
        Ok(SessionCa {
            session_id,
            ca_cert_der,
            ca_cert_pem,
            issuer,
            leaves: Mutex::new(BTreeMap::new()),
        })
    }

    /// The session id this CA belongs to.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The interception CA's subject/issuer common name (`ds-session-ca-<id>`).
    pub fn issuer_common_name(&self) -> String {
        session_ca_common_name(&self.session_id)
    }

    /// The ingested CA certificate, DER-encoded — the trust anchor a golden image
    /// (or a test pool) is built from. Mirrors the boundary `SessionCA.CertPool`
    /// export seam.
    pub fn ca_cert_der(&self) -> &[u8] {
        &self.ca_cert_der
    }

    /// The ingested CA certificate, PEM-encoded — the `CertPool` export shape for
    /// the golden image trust bundle (mirrors boundary `SessionCA.CertPool`).
    pub fn cert_pool_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Mint (or return the cached) leaf for `origin_host`, signed by this
    /// session's CA, with the exact origin as its only SAN DNS name (doc 12 §3 /
    /// §13.2; mirrors the boundary `LeafFor` seam + the TLS-3.a DNSNames
    /// assertion).
    ///
    /// **Cache-first**: a repeat call for the same host returns the
    /// byte-identical cached leaf (the TLS-3.d stability property) — a fresh mint
    /// would differ by serial/key, so byte-equality proves the cache. The cache
    /// is keyed on host only; the session is the partition (this instance).
    pub fn leaf_for(&self, origin_host: &str) -> Result<Arc<LeafCert>, CaError> {
        // Cache-first: hand back the byte-identical cached leaf for a known host.
        {
            let cache = self.leaves.lock().expect("leaf cache mutex");
            if let Some(hit) = cache.get(origin_host) {
                return Ok(Arc::clone(hit));
            }
        }

        // Miss: mint a fresh leaf signed by the session CA, SAN = the exact host.
        let leaf = Arc::new(self.mint_leaf(origin_host)?);

        // Insert-or-keep: if a concurrent caller minted the same host between the
        // lookup and here, keep the first one so the cached leaf stays stable.
        let mut cache = self.leaves.lock().expect("leaf cache mutex");
        let entry = cache
            .entry(origin_host.to_string())
            .or_insert_with(|| Arc::clone(&leaf));
        Ok(Arc::clone(entry))
    }

    /// Mint a fresh leaf for `origin_host` (no cache interaction). Each leaf has a
    /// fresh key pair and the exact origin host as its only SAN DNS name.
    fn mint_leaf(&self, origin_host: &str) -> Result<LeafCert, CaError> {
        let leaf_key = KeyPair::generate().map_err(|e| CaError::Sign(e.to_string()))?;

        let mut params = CertificateParams::new(vec![origin_host.to_string()])
            .map_err(|e| CaError::Sign(e.to_string()))?;
        // SAN = the exact origin host only (no wildcard, no extra names).
        params.subject_alt_names = vec![SanType::DnsName(
            origin_host
                .to_string()
                .try_into()
                .map_err(|e: rcgen::Error| CaError::Sign(e.to_string()))?,
        )];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, origin_host);
        params.distinguished_name = dn;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        // signed_by sets the leaf's issuer field to the issuer's subject DN
        // (= ds-session-ca-<id>, matching the ingested CA cert's subject) and
        // signs with the ingested CA key — so the leaf chains to ca_cert_der.
        let cert = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| CaError::Sign(e.to_string()))?;

        Ok(LeafCert {
            origin_host: origin_host.to_string(),
            cert_der: cert.der().to_vec(),
            cert_pem: cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        })
    }
}

/// Build the per-session interception-CA parameters: subject CN
/// `ds-session-ca-<id>`, `is_ca = true`, cert-signing key usage. Used to
/// SELF-MINT a throwaway CA in tests / the `test-ca` harness. The production
/// ingest path no longer derives the signing issuer's DN from these synthetic
/// params (it parses the real subject out of the ingested CA cert via
/// `Issuer::from_ca_cert_der` in `assemble`), so this is test/self-mint-only.
#[cfg(any(test, feature = "test-ca"))]
fn ca_params(session_id: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, session_ca_common_name(session_id));
    params.distinguished_name = dn;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params
}

/// Extract the first DER block of `label` from PEM text. Tiny, dependency-free
/// (the `pem`-feature parser is internal to rcgen) so ingest does not pull a new
/// crate; returns `None` if the labelled block is absent or not valid base64.
fn pem_block_to_der(pem_text: &str, label: &str) -> Option<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem_text.find(&begin)? + begin.len();
    let stop = pem_text[start..].find(&end)? + start;
    let b64: String = pem_text[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    base64_decode(&b64)
}

/// Render DER bytes as a PEM block with the given label (64-char wrapped, the
/// conventional width).
fn der_to_pem_block(der: &[u8], label: &str) -> String {
    let b64 = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Minimal standard-alphabet base64 encoder (no padding-omission games) — kept
/// in-crate so PEM<->DER round-tripping for ingest pulls no new dependency.
fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Minimal standard-alphabet base64 decoder; `None` on any invalid byte.
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
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        let mut have = 0;
        for &b in chunk {
            n = (n << 6) | val(b)?;
            have += 1;
        }
        // left-align the bits we actually decoded.
        n <<= 6 * (4 - have);
        if have >= 2 {
            out.push((n >> 16) as u8);
        }
        if have >= 3 {
            out.push((n >> 8) as u8);
        }
        if have >= 4 {
            out.push(n as u8);
        }
    }
    Some(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Test-CA harness (the dependency-inversion seam mirroring boundary `CAMinter`)
//
// Behind `#[cfg(any(test, feature = "test-ca"))]` so:
//   - ca.rs's own #[cfg(test)] tests exercise the REAL leaf_for code path; and
//   - with `--features test-ca`, LATER TLS-3 units in OTHER modules of this crate
//     (and integration tests) can construct a throwaway per-session interception
//     CA WITHOUT the orchestrator/Identity.
// The self-mint path wraps the SAME `assemble`/`leaf_for` code the production
// ingest uses, so it tests the real signing path — it just supplies a fresh
// rcgen-minted CA instead of an Identity-minted one.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(any(test, feature = "test-ca"))]
impl SessionCa {
    /// Self-mint a throwaway interception CA for `session_id` (TEST/`test-ca`
    /// ONLY — production ingests an Identity-minted CA via [`SessionCa::from_pem`],
    /// D82). Mints a fresh CA key + a self-signed CA cert (`is_ca = true`, subject
    /// `ds-session-ca-<id>`) and wraps them through the SAME ingest path the
    /// production CA uses, so leaf minting/caching is exercised end to end.
    pub fn new_self_signed_for_test(session_id: impl Into<String>) -> Result<SessionCa, CaError> {
        let session_id = session_id.into();
        let key = KeyPair::generate().map_err(|e| CaError::KeyParse(e.to_string()))?;
        let params = ca_params(&session_id);
        let ca_cert = params
            .self_signed(&key)
            .map_err(|e| CaError::Sign(e.to_string()))?;
        let ca_cert_der = ca_cert.der().to_vec();
        let ca_cert_pem = ca_cert.pem();
        // Re-ingest the freshly minted CA key via the production from_pem ingest so
        // the throwaway CA travels the exact code path Identity-ingested CAs do.
        Self::from_der_cert_pem_key(session_id, &ca_cert_der, &key.serialize_pem()).map(|mut ca| {
            // self_signed used the PEM-rendered DER above; keep the byte-exact
            // PEM rcgen produced for the pool export.
            ca.ca_cert_pem = ca_cert_pem;
            ca
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{CertificateDer, UnixTime};
    use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

    // The ring-backed signature algorithms the upstream WebPKI validation uses
    // (doc 12 §3 strict re-origination). ca.rs mints ECDSA-P256 leaves by default
    // (rcgen's default sig algo on ring), so P-256/P-384 SHA-256/384 cover it.
    static VERIFICATION_ALGS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
        webpki::ring::ECDSA_P256_SHA256,
        webpki::ring::ECDSA_P256_SHA384,
        webpki::ring::ECDSA_P384_SHA256,
        webpki::ring::ECDSA_P384_SHA384,
        webpki::ring::ED25519,
    ];

    /// Verify `leaf` (DER) chains to the trust anchor `ca_cert_der` (DER) for
    /// server auth at `now`. The in-crate analogue of the boundary spec's
    /// "validates against the session's pool" assertion.
    fn leaf_chains_to(leaf_der: &[u8], ca_cert_der: &[u8]) -> Result<(), webpki::Error> {
        let leaf = CertificateDer::from(leaf_der.to_vec());
        let ca = CertificateDer::from(ca_cert_der.to_vec());
        let anchor = anchor_from_trusted_cert(&ca)?;
        let anchors = [anchor];
        let ee = EndEntityCert::try_from(&leaf)?;
        ee.verify_for_usage(
            VERIFICATION_ALGS,
            &anchors,
            &[],
            // The leaf's validity window is rcgen's wide default (1975..4096), so
            // any current time validates; use a fixed epoch-relative instant.
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_700_000_000)),
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_path| ())
    }

    /// Whether `leaf_der` carries `host` as a SAN. rustls-webpki does not expose
    /// SAN enumeration, so assert membership via the same subject-name check the
    /// TLS handshake performs (`verify_is_valid_for_subject_name`).
    fn leaf_names_host(leaf_der: &[u8], host: &str) -> bool {
        use rustls_pki_types::ServerName;
        let leaf = CertificateDer::from(leaf_der.to_vec());
        let Ok(ee) = EndEntityCert::try_from(&leaf) else {
            return false;
        };
        let Ok(name) = ServerName::try_from(host) else {
            return false;
        };
        ee.verify_is_valid_for_subject_name(&name).is_ok()
    }

    // ── TLS-3.d: per-origin leaf cache stability + distinctness ────────────────
    //
    // (mirrors boundary `TestInspect_LeafCache_StablePerOrigin`): two leaf_for(X)
    // calls on one session return BYTE-IDENTICAL leaves (proves the cache, since a
    // fresh mint differs by serial/key); leaf_for(Y) is a DISTINCT leaf naming Y.
    #[test]
    fn leaf_cache_is_stable_per_origin_and_distinct_across_origins() {
        let ca = SessionCa::new_self_signed_for_test("sess-a").expect("self-mint CA");

        let x1 = ca.leaf_for("alpha.example").expect("mint alpha #1");
        let x2 = ca.leaf_for("alpha.example").expect("mint alpha #2");
        let y = ca.leaf_for("beta.example").expect("mint beta");

        // Cache-first: the repeat call returns the byte-identical leaf.
        assert_eq!(
            x1.cert_der, x2.cert_der,
            "same origin must present a byte-identical cached leaf (TLS-3.d)"
        );
        assert_eq!(x1.key_pem, x2.key_pem, "cached leaf key must be identical");
        // The Arc itself is shared (same allocation) on a cache hit.
        assert!(
            Arc::ptr_eq(&x1, &x2),
            "cache hit must hand back the same Arc"
        );

        // Distinct origins must not share a leaf.
        assert_ne!(
            x1.cert_der, y.cert_der,
            "different origins must not share a leaf"
        );

        // Each leaf names exactly its own origin host (the only SAN, TLS-3.a).
        assert!(
            leaf_names_host(&x1.cert_der, "alpha.example"),
            "X leaf must name alpha.example"
        );
        assert!(
            leaf_names_host(&y.cert_der, "beta.example"),
            "Y leaf must name beta.example"
        );
        // ...and NOT the other origin (the SAN is the exact host only).
        assert!(
            !leaf_names_host(&y.cert_der, "alpha.example"),
            "Y leaf must NOT name alpha.example (exact-origin SAN)"
        );
    }

    // ── TLS-3.c: per-session CA isolation ("A's CA useless against B") ─────────
    //
    // (mirrors boundary `TestInspect_PerSessionCAIsolation_AUselessAgainstB`):
    // two independent test CAs have distinct CA certs; a leaf minted by A's CA
    // FAILS chain validation against a pool of ONLY B's CA, and SUCCEEDS against
    // A's own pool.
    #[test]
    fn session_a_ca_is_useless_against_session_b() {
        let ca_a = SessionCa::new_self_signed_for_test("sess-a").expect("CA A");
        let ca_b = SessionCa::new_self_signed_for_test("sess-b").expect("CA B");

        // The two CAs are distinct key pairs → distinct CA certs.
        assert_ne!(
            ca_a.ca_cert_der(),
            ca_b.ca_cert_der(),
            "independent session CAs must be distinct"
        );

        const ORIGIN: &str = "inspected.example";
        let a_leaf = ca_a.leaf_for(ORIGIN).expect("A mints leaf");

        // SUCCEEDS against A's own pool.
        assert!(
            leaf_chains_to(&a_leaf.cert_der, ca_a.ca_cert_der()).is_ok(),
            "A's leaf must validate against A's own CA pool"
        );

        // FAILS against a pool of ONLY B's CA (A's CA is useless against B).
        assert!(
            leaf_chains_to(&a_leaf.cert_der, ca_b.ca_cert_der()).is_err(),
            "A's leaf must FAIL validation against B's CA pool (A useless against B)"
        );
    }

    // ── provenance: the issuer CN follows the ds-session-ca-<id> convention ────
    #[test]
    fn issuer_common_name_threads_the_session_id() {
        let ca = SessionCa::new_self_signed_for_test("sess-xyz").expect("CA");
        assert_eq!(ca.issuer_common_name(), "ds-session-ca-sess-xyz");
        assert_eq!(ca.session_id(), "sess-xyz");
        // session id is threaded, never hardcoded.
        let ca2 = SessionCa::new_self_signed_for_test("other").expect("CA2");
        assert_eq!(ca2.issuer_common_name(), "ds-session-ca-other");
    }

    // ── production ingest path round-trips (from_pem) ──────────────────────────
    //
    // Self-mint a CA, export its cert+key PEM, then re-ingest via the PRODUCTION
    // from_pem path (D82 opaque ingest) and prove the re-ingested CA mints a leaf
    // that chains to the original CA cert — i.e. from_pem reconstructs the signing
    // issuer correctly from opaque material.
    #[test]
    fn from_pem_ingest_mints_leaves_that_chain_to_the_ingested_ca() {
        // Mint a throwaway CA and grab its opaque material.
        let key = KeyPair::generate().expect("ca key");
        let params = ca_params("sess-ingest");
        let ca_cert = params.self_signed(&key).expect("self-sign CA");
        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = key.serialize_pem();
        let ca_cert_der = ca_cert.der().to_vec();

        // Ingest via the production opaque path.
        let ca = SessionCa::from_pem("sess-ingest", &ca_cert_pem, &ca_key_pem)
            .expect("ingest CA from PEM");

        let leaf = ca.leaf_for("ingested.example").expect("mint leaf");
        assert!(
            leaf_chains_to(&leaf.cert_der, &ca_cert_der).is_ok(),
            "from_pem-ingested CA must mint leaves chaining to the ingested CA cert"
        );
        assert!(leaf_names_host(&leaf.cert_der, "ingested.example"));
        // The CertPool export is the ingested CA cert PEM.
        assert_eq!(ca.cert_pool_pem(), ca_cert_pem);
    }

    // Regression (live cred-swap RST root cause): an ingested CA whose subject CN
    // does NOT follow the `ds-session-ca-<session_id>` convention — e.g. an
    // operator/Identity-minted CA named `ds-session-ca-l1-testbed` ingested under
    // `DS_SESSION_UUID = sess-nested-testbed-0001`, OR any other subject — must
    // STILL mint leaves that chain to it. Before the fix, `assemble` reconstructed
    // the signing issuer's DN from `ca_params(session_id)` (CN
    // `ds-session-ca-sess-nested-testbed-0001`), so the leaf's `issuer` field did
    // not match the CA cert's actual `subject` (`ds-session-ca-l1-testbed`) → path
    // validation failed ("unable to get local issuer certificate") and the in-VM
    // (validating) client RST the terminated connection. The fix derives the issuer
    // DN from the ingested CA cert itself (`Issuer::from_ca_cert_der`).
    #[test]
    fn ingested_ca_with_nonconventional_subject_still_mints_chaining_leaves() {
        // Build a CA whose subject CN is deliberately UNRELATED to the session id.
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "ds-session-ca-l1-testbed");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca_cert = params.self_signed(&key).expect("self-sign CA");
        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = ca_cert.der().to_vec();

        // Ingest under a DIFFERENT session id (the testbed mismatch shape).
        let ca = SessionCa::from_pem(
            "sess-nested-testbed-0001",
            &ca_cert_pem,
            &key.serialize_pem(),
        )
        .expect("ingest non-conventional CA");

        let leaf = ca.leaf_for("api.anthropic.com").expect("mint leaf");
        assert!(
            leaf_chains_to(&leaf.cert_der, &ca_cert_der).is_ok(),
            "a leaf must chain to its ingested CA even when the CA's subject CN does \
             not match ds-session-ca-<session_id> (the live RST root cause)"
        );
        assert!(leaf_names_host(&leaf.cert_der, "api.anthropic.com"));
    }

    // ── base64 round-trip (the in-crate PEM<->DER helper) ──────────────────────
    #[test]
    fn base64_round_trips_arbitrary_bytes() {
        for n in [0usize, 1, 2, 3, 4, 5, 31, 32, 33, 255] {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            let enc = base64_encode(&data);
            let dec = base64_decode(&enc).expect("decode");
            assert_eq!(dec, data, "base64 round-trip for {n} bytes");
        }
    }

    // ── DER->PEM->DER round-trip via the in-crate helpers ──────────────────────
    #[test]
    fn pem_block_round_trips_der() {
        let der: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
        let pem = der_to_pem_block(&der, "CERTIFICATE");
        let back = pem_block_to_der(&pem, "CERTIFICATE").expect("extract DER");
        assert_eq!(back, der);
        // a missing label yields None.
        assert!(pem_block_to_der(&pem, "PRIVATE KEY").is_none());
    }
}
