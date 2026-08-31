//! TLS-3 strict-WebPKI upstream re-origination — the UPSTREAM leg of the
//! terminate-and-re-originate path (doc 12 §3, §13.5; doc 09 §5 TLS-3; D17/D82/
//! D76/D40).
//!
//! # What this is
//!
//! When the proxy terminates the VM's TLS (the [`crate::ca`] per-session CA mints
//! the leaf the VM sees), the bytes the agent intended for the real origin are no
//! longer protected by the origin's own certificate — the agent delegated its
//! trust to us. doc 12 §3 makes that delegation safe by re-originating upstream
//! with **strict WebPKI validation**:
//!
//! > *"re-originates upstream with strict WebPKI validation — the agent delegated
//! > its trust to us, so our upstream check is at least as strict as the client's
//! > would have been."*
//!
//! and the §13.5 error table is unconditional:
//!
//! > *"Upstream WebPKI validation fails on the re-originated leg → **Refuse**
//! > upstream — our check is at least as strict as the client's would have been."*
//!
//! This module is the framework-agnostic core of that leg. It does NOT terminate
//! the downstream TLS (that is the leaf-cert authority, [`crate::ca`], + the
//! pingora `TlsAccept` wiring in `src/main.rs`); it answers the *upstream*
//! question: given an admitted upstream address and the SNI domain, is the chain
//! the origin presented one a strict WebPKI client would have accepted, AND does
//! it name the domain we asked for? A failure REFUSES the upstream **before any
//! payload byte is written** — the established-but-unvalidated TLS connection is
//! dropped without a single application byte reaching the origin (the boundary
//! "zero upstream request bytes after refusal" assertion).
//!
//! # Three layers (all pingora-FREE, `#![forbid(unsafe_code)]` via the crate root)
//!
//! 1. [`validate_origin_chain`] — the PURE, socket-free validation core over
//!    `rustls-webpki`. This is the security center and the unit-test target: it
//!    parses the end-entity, runs `verify_for_usage(server_auth)` against the
//!    injected [`TrustRoots`] at the injected [`UnixTime`], then a subject-name
//!    check against the SNI. Each `webpki::Error` class maps to a stable
//!    [`ReoriginateRefuse`] variant. No I/O — fixture chains drive it directly.
//! 2. [`TrustRoots`] — the trust-anchor set, an INJECTABLE config seam:
//!    [`TrustRoots::from_der_roots`] for fixture roots (tests), and the
//!    `system`/`from_pem_bundle` production constructors whose provenance is
//!    *config* (doc 12 §3 leaves golden-root provenance to config, not a
//!    hard-coded decision). `main.rs`/config wires the real roots in.
//! 3. [`UpstreamDialer`] — the dialer seam mirroring the boundary
//!    `UpstreamDialer.DialTLS`. `main.rs` injects the real tokio+rustls connector
//!    (D40: the live socket + rustls types stay in the bin); tests inject a fake
//!    so this module unit-tests with NO live socket. Whatever the backing dialer,
//!    the contract is the same: VALIDATE the presented chain via the pure core
//!    BEFORE handing back a connection / before any payload byte; a validation
//!    failure surfaces the stable [`ReoriginateRefuse`] and drops the conn.
//!
//! # D40 pingora confinement
//!
//! No pingora type appears here (doc 12 §13.1). The live tokio+rustls connector
//! wiring (`ClientConfig`, the TCP+TLS handshake, `SO_MARK` before connect per
//! D76) is the documented seam in `src/main.rs`; this module ships the trait + the
//! pure core + fixture tests only.
//!
//! # D74 / additive discipline
//!
//! This module is dormant: the existing TLS-1 opaque-tunnel default path does not
//! call it. Inspection (which routes through here) lands behind the env/feature
//! gate in a later unit; until then the tested default path stays byte-identical.

use std::fmt;
use std::io;
use std::net::SocketAddr;

use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use webpki::{
    anchor_from_trusted_cert, CertRevocationList, EndEntityCert, KeyUsage, OwnedCertRevocationList,
    RevocationOptionsBuilder,
};

use ds_contracts::session::SessionRef;

// ─────────────────────────────────────────────────────────────────────────────
// Refusal reason — the stable, secret-free §10 telemetry class.
// Mirrors `tls1_admission::RefuseReason` / `transparent::RecoveryError`: a
// `reason_code()` of stable kebab-case codes + `Display` + `std::error::Error`
// so ST3/ST4 can emit a §10 `ErrorEvent` carrying the class and nothing more.
// ─────────────────────────────────────────────────────────────────────────────

/// Why the strict upstream WebPKI re-validation refused the re-originated leg
/// (doc 12 §3, §13.5). Each variant is a distinct, secret-free §10 reason class —
/// it NEVER carries the cert bytes, the SNI value, or the upstream address beyond
/// what the class names. The boundary table (`TLS-3.b`) drives the five bad
/// classes; the good control row never reaches a variant.
///
/// The mapping is deliberately conservative: where `rustls-webpki` cannot
/// distinguish two failure shapes (an untrusted root and a self-signed leaf both
/// fail path-building to a trust anchor as `UnknownIssuer`), we pick the variant
/// that best matches how the chain was *constructed* by the caller's fixtures and
/// document the merge, but EVERY one of the five bad classes is a refusal — the
/// security property (no bad chain admits) never depends on the variant chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReoriginateRefuse {
    /// The presented chain does not build a path to any anchor in the configured
    /// [`TrustRoots`] — the classic "untrusted CA" failure. `rustls-webpki`
    /// reports this (and the self-signed case) as `UnknownIssuer`.
    UntrustedChain,
    /// The end-entity is self-signed (its issuer is itself and it is not in the
    /// trust roots). Indistinguishable from [`Self::UntrustedChain`] at the
    /// `webpki` layer (`UnknownIssuer`); surfaced as its own class only when the
    /// caller's fixture marks the leaf self-signed (the dialer-level hint). The
    /// pure core reports the merged `UnknownIssuer` class as [`Self::UntrustedChain`].
    SelfSigned,
    /// The certificate is outside its validity window at the injected `now` —
    /// expired (`CertExpired`) or not-yet-valid (`CertNotValidYet`).
    Expired,
    /// The certificate is valid and trusted but does not name the SNI domain we
    /// asked for (`CertNotValidForName`) — the re-originated leg must be at least
    /// as strict as the client's hostname check.
    HostnameMismatch,
    /// An intermediate in the chain is not a usable CA (e.g. `IsCA=false` /
    /// bad basic-constraints / path-length violated): path building cannot
    /// traverse it. `webpki` reports the broken path as `UnknownIssuer`; this
    /// variant is surfaced when the caller's fixture marks the chain
    /// invalid-intermediate.
    InvalidIntermediate,
    /// The end-entity (or an intermediate) could not be parsed as a valid X.509
    /// certificate, or the SNI was not a usable DNS name — a malformed input that
    /// cannot be validated. Refuse (never admit a chain we cannot parse).
    MalformedCert,
    /// The chain builds a path to a trusted anchor AND names the SNI, but a
    /// configured [`RevocationConfig`] CRL marks a cert in the path REVOKED — or
    /// the CRL-backed revocation status could not be confirmed (the default
    /// `Deny`-unknown policy) (CV2-certval; doc 12 §3 — strict re-origination is
    /// "at least as strict as the client's would have been", and a revoked origin
    /// cert a strict client would reject). `rustls-webpki` reports this as
    /// `CertRevoked` / `UnknownRevocationStatus` / `CrlExpired` when a
    /// [`RevocationOptions`](webpki::RevocationOptions) is threaded into
    /// `verify_for_usage`.
    Revoked,
    /// The kernel `original_dst` the live re-origination dialed is NOT a member of
    /// the live FORWARD admission for `(session, sni)` (CV3 — the CDN shared-IP hole
    /// guard, doc 03 §3 OQ1 / doc 12 §4.1). A chain can be perfectly valid WebPKI
    /// AND name the SNI yet still terminate at a destination DNS-2 never admitted for
    /// that name; the inspected/re-originated leg refuses such a destination before a
    /// payload byte. This is a dialer-level refusal (the membership fact is the
    /// kernel `original_dst`, not anything in the cert chain), surfaced as its own
    /// secret-free class.
    DstNotAdmitted,
}

impl ReoriginateRefuse {
    /// A stable, secret-free reason code for the §10 `ErrorEvent`. Prefixed
    /// `tls3-upstream-` so the operator can tell an upstream re-origination
    /// refusal apart from a TLS-1 admission refusal (`tls1-…`) or a transparent
    /// recovery failure.
    pub fn reason_code(self) -> &'static str {
        match self {
            ReoriginateRefuse::UntrustedChain => "tls3-upstream-untrusted-chain",
            ReoriginateRefuse::SelfSigned => "tls3-upstream-self-signed",
            ReoriginateRefuse::Expired => "tls3-upstream-expired",
            ReoriginateRefuse::HostnameMismatch => "tls3-upstream-hostname-mismatch",
            ReoriginateRefuse::InvalidIntermediate => "tls3-upstream-invalid-intermediate",
            ReoriginateRefuse::MalformedCert => "tls3-upstream-malformed-cert",
            ReoriginateRefuse::Revoked => "tls3-upstream-revoked",
            ReoriginateRefuse::DstNotAdmitted => "tls3-upstream-dst-not-admitted",
        }
    }
}

impl fmt::Display for ReoriginateRefuse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TLS-3 upstream refused: {}", self.reason_code())
    }
}

impl std::error::Error for ReoriginateRefuse {}

/// The outcome of attempting to re-originate one upstream leg. A
/// [`Self::WebPki`] refusal is the §13.5 "REFUSE upstream" verdict (no payload
/// byte was written); a [`Self::Connect`] error is a transport failure on the
/// live dialer (the dialer in `src/main.rs` populates this arm — the pure
/// validation core never produces it).
#[derive(Debug)]
pub enum ReoriginateError {
    /// Strict WebPKI validation refused the presented origin chain (§13.5). The
    /// connection — if one was established — is dropped without a payload byte.
    WebPki(ReoriginateRefuse),
    /// The transport could not be established (TCP connect / TLS handshake I/O
    /// failure) — distinct from a WebPKI refusal. Produced only by the live
    /// dialer in `src/main.rs`; the pure core never returns it.
    Connect(io::Error),
}

impl ReoriginateError {
    /// The stable §10 reason code: the WebPKI refusal class for a
    /// [`Self::WebPki`], or the fixed transport code for a [`Self::Connect`].
    pub fn reason_code(&self) -> &'static str {
        match self {
            ReoriginateError::WebPki(r) => r.reason_code(),
            ReoriginateError::Connect(_) => "tls3-upstream-connect-failed",
        }
    }
}

impl fmt::Display for ReoriginateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReoriginateError::WebPki(r) => write!(f, "{r}"),
            ReoriginateError::Connect(e) => {
                write!(f, "TLS-3 upstream connect failed: {e}")
            }
        }
    }
}

impl std::error::Error for ReoriginateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReoriginateError::WebPki(r) => Some(r),
            ReoriginateError::Connect(e) => Some(e),
        }
    }
}

impl From<ReoriginateRefuse> for ReoriginateError {
    fn from(r: ReoriginateRefuse) -> Self {
        ReoriginateError::WebPki(r)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TrustRoots — the injectable trust-anchor config seam.
// ─────────────────────────────────────────────────────────────────────────────

/// The set of trust anchors the upstream re-origination validates against (doc 12
/// §3). Provenance is CONFIG, not a hard-coded decision: production wires the
/// system / golden roots ([`Self::system`] / [`Self::from_pem_bundle`]); tests
/// inject fixture roots ([`Self::from_der_roots`]). The validation core
/// ([`validate_origin_chain`]) takes this by reference and never reaches outside
/// it — the trust decision is fully determined by what config put here.
///
/// The newtype owns both the parsed [`TrustAnchor`]s and the backing DER bytes
/// they borrow from, so a `TrustRoots` is `'static`-self-contained and can be
/// cheaply held for the proxy's lifetime.
pub struct TrustRoots {
    // The owned DER backing store the anchors borrow from. Kept alive for the
    // lifetime of `anchors`. (Boxed so the anchors' borrows stay stable when the
    // `TrustRoots` itself moves.)
    _der: Vec<Vec<u8>>,
    anchors: Vec<TrustAnchor<'static>>,
}

impl TrustRoots {
    /// Build a trust-root set from DER-encoded CA certificates (the fixture/test
    /// seam, and the building block for the production constructors). A root that
    /// cannot be parsed into a trust anchor is rejected (the whole call fails) —
    /// a malformed root must never silently shrink the trust set.
    pub fn from_der_roots(roots: &[CertificateDer<'_>]) -> Result<TrustRoots, ReoriginateRefuse> {
        let mut der: Vec<Vec<u8>> = Vec::with_capacity(roots.len());
        for r in roots {
            der.push(r.as_ref().to_vec());
        }
        let mut anchors: Vec<TrustAnchor<'static>> = Vec::with_capacity(der.len());
        for bytes in &der {
            let cert = CertificateDer::from(bytes.clone());
            let anchor = anchor_from_trusted_cert(&cert)
                .map_err(map_webpki_error)?
                .to_owned();
            anchors.push(anchor);
        }
        Ok(TrustRoots { _der: der, anchors })
    }

    /// Build a trust-root set from a PEM bundle of CA certificates (the
    /// production provenance seam: `main.rs`/config reads the golden-root bundle
    /// and hands the bytes here). Empty / certless input yields an empty trust
    /// set (every chain then refuses — fail-closed), which is a config error the
    /// caller surfaces, not a panic here.
    pub fn from_pem_bundle(pem: &[u8]) -> Result<TrustRoots, ReoriginateRefuse> {
        let ders = parse_pem_certificates(pem);
        let refs: Vec<CertificateDer<'static>> =
            ders.into_iter().map(CertificateDer::from).collect();
        TrustRoots::from_der_roots(&refs)
    }

    /// The production "system roots" seam. Provenance is config (doc 12 §3): the
    /// real wiring reads the OS trust store / the golden-image bundle and
    /// constructs the roots via [`Self::from_pem_bundle`] in `main.rs`. This
    /// constructor exists so the seam has a name; it deliberately does NOT bake a
    /// hard-coded trust decision into this offline, pingora-free module. Returns
    /// an empty set (fail-closed) so an un-wired deployment refuses every upstream
    /// rather than silently trusting nothing-or-everything.
    pub fn system() -> TrustRoots {
        TrustRoots {
            _der: Vec::new(),
            anchors: Vec::new(),
        }
    }

    /// The configured trust anchors. Borrowed by [`validate_origin_chain`] for
    /// the `verify_for_usage` path-building call.
    pub fn anchors(&self) -> &[TrustAnchor<'static>] {
        &self.anchors
    }

    /// Whether the trust set is empty (every chain will refuse — fail-closed).
    /// A deployment-config sanity check for the wiring layer.
    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RevocationConfig — the injectable CRL config seam (CV2-certval).
// ─────────────────────────────────────────────────────────────────────────────

/// The certificate-revocation config the strict upstream re-origination consults
/// (CV2-certval; doc 12 §3). Provenance is CONFIG, exactly like [`TrustRoots`]:
/// production wires the operator's CRL bundle (the host-local revocation feed, the
/// host-integration-gated seam in `main.rs`); tests inject a fixture CRL
/// ([`Self::from_der_crls`]). When threaded into
/// [`validate_origin_chain_witness_revocable`], a chain whose end-entity (or an
/// intermediate, the default `Chain` depth) is named in an authoritative CRL — or
/// whose revocation status cannot be confirmed (the default `Deny`-unknown policy) —
/// REFUSES with [`ReoriginateRefuse::Revoked`], so a revoked origin cert a strict
/// client would reject is rejected here too.
///
/// FAIL-CLOSED on a malformed CRL: a CRL DER that does not parse fails the whole
/// build (a broken revocation feed must never silently shrink to "no revocation
/// known" and admit a revoked cert). An EMPTY config (no CRLs) is representable but
/// cannot be threaded into `verify_for_usage` (rustls-webpki requires ≥1 CRL to
/// build `RevocationOptions`); [`Self::is_empty`] lets the caller pass `None`
/// revocation instead — byte-identical to the no-CRL validation path.
///
/// The newtype owns the parsed [`OwnedCertRevocationList`]s for the proxy's lifetime;
/// the `revocation_options`-bearing borrow is materialized per validation call.
pub struct RevocationConfig {
    crls: Vec<OwnedCertRevocationList>,
}

impl RevocationConfig {
    /// Build a revocation config from DER-encoded CRLs (the fixture/test seam, and
    /// the building block for the production constructor). A CRL that cannot be
    /// parsed is rejected (the whole call fails) — a malformed revocation feed must
    /// never silently degrade to "nothing revoked".
    pub fn from_der_crls(crls: &[&[u8]]) -> Result<RevocationConfig, ReoriginateRefuse> {
        let mut owned: Vec<OwnedCertRevocationList> = Vec::with_capacity(crls.len());
        for der in crls {
            let crl = OwnedCertRevocationList::from_der(der).map_err(map_webpki_error)?;
            owned.push(crl);
        }
        Ok(RevocationConfig { crls: owned })
    }

    /// Whether the config carries NO CRLs. An empty config is threaded as `None`
    /// revocation (rustls-webpki cannot build `RevocationOptions` from zero CRLs), so
    /// an empty config validates EXACTLY like the no-CRL path — byte-identical. The
    /// production wiring uses this to decide whether to pass revocation at all.
    pub fn is_empty(&self) -> bool {
        self.crls.is_empty()
    }

    /// The parsed CRLs as the `&[&CertRevocationList]` slice `RevocationOptions`
    /// borrows. Materialized per call (the `&CertRevocationList` references borrow
    /// `self.crls`); held only across one `verify_for_usage`.
    fn as_options_input(&self) -> Vec<CertRevocationList<'_>> {
        self.crls
            .iter()
            .map(|c| CertRevocationList::from(c.clone()))
            .collect()
    }
}

/// Extract every `CERTIFICATE` PEM block from `pem` as DER bytes. Non-certificate
/// blocks and surrounding noise are ignored; a block that is not valid base64 is
/// skipped (it cannot become a usable anchor — `from_der_roots` would reject it
/// anyway). Self-contained (no new dep, pingora-free) for the production
/// [`TrustRoots::from_pem_bundle`] seam.
fn parse_pem_certificates(pem: &[u8]) -> Vec<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = match std::str::from_utf8(pem) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after_begin = &rest[start + BEGIN.len()..];
        let Some(end) = after_begin.find(END) else {
            break;
        };
        let b64: String = after_begin[..end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if let Some(der) = base64_decode(&b64) {
            out.push(der);
        }
        rest = &after_begin[end + END.len()..];
    }
    out
}

/// Minimal standard-alphabet base64 decoder; `None` on any invalid byte. Kept
/// self-contained (no dep) for the PEM-bundle seam.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
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
        let v = val(b)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// The pure, socket-free validation core — the security center.
// ─────────────────────────────────────────────────────────────────────────────

/// The ring-backed signature-verification algorithms the upstream WebPKI
/// validation accepts (doc 12 §3 strict re-origination, RING backend per the
/// dependency policy — no aws-lc-rs). Covers ECDSA P-256/P-384 (SHA-256/384),
/// RSA PKCS#1 / PSS (SHA-256/384/512), and Ed25519 — the modern WebPKI set a
/// strict TLS client would accept.
static VERIFICATION_ALGS: &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::ED25519,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
    webpki::ring::RSA_PKCS1_3072_8192_SHA384,
    webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

/// A TYPESTATE WITNESS that [`validate_origin_chain_witness`] returned `Ok` — strict
/// upstream WebPKI re-validation PASSED for the chain it was given (doc 12 §3 / §13.5;
/// 01KV9N17NN CV1-certval).
///
/// # Non-bypassable BY CONSTRUCTION
///
/// The field is PRIVATE and there is no public constructor, so a value of this type
/// can be obtained ONLY as the `Ok` of [`validate_origin_chain_witness`] — no other
/// module (not even `main.rs`'s live dialer) can fabricate one. A
/// [`ReoriginatedConn`] is therefore producible ONLY through
/// [`ReoriginatedConn::admit`], which CONSUMES a `&ValidatedOriginChain` — so the
/// type system makes it impossible to hand back a re-originated connection (the thing
/// the caller writes payload to) without having first run the strict validation to
/// `Ok`. A dialer that "forgets" to validate cannot compile.
///
/// Zero-sized and `Copy`-FREE on purpose: it is a proof token threaded once from the
/// validation site into the conn constructor at the same dialer call, not a flag to
/// be cached, cloned, or reused across chains. It carries NO certificate byte (D73 /
/// secret-free) — its mere existence is the proof, nothing more.
#[derive(Debug)]
pub struct ValidatedOriginChain {
    // Private, unconstructible-from-outside: `validate_origin_chain_witness` is the
    // sole producer. The unit field keeps the type zero-sized.
    _seal: (),
}

/// Validate the chain the origin presented on the re-originated upstream leg
/// (doc 12 §3, §13.5) — the PURE, socket-free security core, returning the
/// [`ValidatedOriginChain`] TYPESTATE WITNESS on success (01KV9N17NN CV1-certval).
///
/// `presented_chain` is the origin's certificate chain end-entity-first (index 0 is
/// the leaf; the rest are intermediates, as a TLS server sends them). `sni` is the
/// domain the agent addressed (the name the leaf must be valid for). `roots` is the
/// configured trust set; `now` is the injected validation clock.
///
/// Returns `Ok(ValidatedOriginChain)` ONLY when the chain builds a path to a trusted
/// anchor for server auth, is within its validity window at `now`, AND names `sni`.
/// Every other outcome is a [`ReoriginateRefuse`] — the §13.5 "REFUSE upstream"
/// verdict, mapped to the most precise class `rustls-webpki` allows. The returned
/// witness is the ONLY way to construct a [`ReoriginatedConn`]
/// ([`ReoriginatedConn::admit`] consumes it), so no upstream conn — and therefore no
/// payload byte — can exist without this `Ok`.
///
/// This function performs NO I/O and never writes a byte: the caller (the
/// [`UpstreamDialer`]) runs it on the chain the handshake already produced, and
/// only constructs the conn (and forwards payload) after the `Ok` witness.
pub fn validate_origin_chain_witness(
    presented_chain: &[CertificateDer<'_>],
    sni: &str,
    roots: &TrustRoots,
    now: UnixTime,
) -> Result<ValidatedOriginChain, ReoriginateRefuse> {
    let (leaf, intermediates) = presented_chain
        .split_first()
        .ok_or(ReoriginateRefuse::MalformedCert)?;

    // Parse the end-entity. A leaf we cannot parse is a malformed input — refuse.
    let ee = EndEntityCert::try_from(leaf).map_err(map_webpki_error)?;

    // Strict path building to a configured trust anchor, for server auth, at the
    // injected clock. This single call covers untrusted-chain / self-signed
    // (no path to an anchor), expired / not-yet-valid (the `now` gate), and
    // invalid-intermediate (a non-CA intermediate breaks the path).
    ee.verify_for_usage(
        VERIFICATION_ALGS,
        roots.anchors(),
        intermediates,
        now,
        KeyUsage::server_auth(),
        None, // no CRL/OCSP revocation check at this leg (doc 12 §3 latitude)
        None, // no extra path predicate
    )
    .map_err(map_webpki_error)?;

    // The chain is trusted and in-validity — now it must name the SNI domain we
    // asked for (at least as strict as the client's hostname check, doc 12 §3).
    let name = ServerName::try_from(sni).map_err(|_| ReoriginateRefuse::MalformedCert)?;
    ee.verify_is_valid_for_subject_name(&name)
        .map_err(map_webpki_error)?;

    // All three gates passed: mint the witness (the SOLE producer of this type).
    Ok(ValidatedOriginChain { _seal: () })
}

/// Validate the chain the origin presented on the re-originated upstream leg
/// (doc 12 §3, §13.5) — the `Ok(())` projection of [`validate_origin_chain_witness`],
/// preserved for call-sites that only need the pass/refuse verdict (the pure-core
/// unit suite + the boundary `TLS-3.b` table). New conn-producing call-sites take the
/// witness via [`validate_origin_chain_witness`] so validation is non-bypassable; this
/// thin wrapper keeps the verdict-only contract byte-identical.
///
/// Returns `Ok(())` only when the chain builds a path to a trusted anchor for server
/// auth, is within its validity window at `now`, AND names `sni`. Every other outcome
/// is the same [`ReoriginateRefuse`] [`validate_origin_chain_witness`] surfaces.
pub fn validate_origin_chain(
    presented_chain: &[CertificateDer<'_>],
    sni: &str,
    roots: &TrustRoots,
    now: UnixTime,
) -> Result<(), ReoriginateRefuse> {
    validate_origin_chain_witness(presented_chain, sni, roots, now).map(|_witness| ())
}

/// The CV2-certval-aware validator: identical to [`validate_origin_chain_witness`]
/// but THREADS an optional [`RevocationConfig`] CRL into the strict
/// `verify_for_usage` path so a REVOKED origin cert refuses with
/// [`ReoriginateRefuse::Revoked`] (doc 12 §3 — strict re-origination is at least as
/// strict as the client's). This is the function the LIVE dialer in `main.rs` calls;
/// [`validate_origin_chain_witness`] is its `revocation == None` projection, so the
/// no-CRL path (every existing call-site + every existing test) is BYTE-IDENTICAL.
///
/// `revocation` is `None` when no CRL feed is configured (the offline default) — then
/// the `verify_for_usage` revocation arg is `None`, exactly as
/// [`validate_origin_chain_witness`] passes it. When `Some(cfg)` with ≥1 CRL, a
/// chain-depth revocation check runs with the default `Deny`-unknown status policy:
/// a cert named in an authoritative CRL, an unconfirmable revocation status, or a
/// CRL past `nextUpdate` all REFUSE (`Revoked`). An EMPTY config
/// ([`RevocationConfig::is_empty`]) degrades to `None` — rustls-webpki requires ≥1
/// CRL to build options — so it validates byte-identically to no-CRL.
pub fn validate_origin_chain_witness_revocable(
    presented_chain: &[CertificateDer<'_>],
    sni: &str,
    roots: &TrustRoots,
    revocation: Option<&RevocationConfig>,
    now: UnixTime,
) -> Result<ValidatedOriginChain, ReoriginateRefuse> {
    let (leaf, intermediates) = presented_chain
        .split_first()
        .ok_or(ReoriginateRefuse::MalformedCert)?;

    let ee = EndEntityCert::try_from(leaf).map_err(map_webpki_error)?;

    // Materialize the CRL borrow set ONLY when a non-empty config is supplied; an
    // absent / empty config keeps `revocation == None` — byte-identical to
    // `validate_origin_chain_witness` (rustls-webpki cannot build options from zero
    // CRLs, and an empty feed must NOT be a silent "nothing revoked" that differs in
    // any observable way from the no-CRL path).
    let crl_input = revocation
        .filter(|cfg| !cfg.is_empty())
        .map(|cfg| cfg.as_options_input());
    let crl_refs: Option<Vec<&CertRevocationList<'_>>> =
        crl_input.as_ref().map(|v| v.iter().collect());
    // `RevocationOptionsBuilder::new` only errs on an empty slice, which `crl_refs`
    // (built from a non-empty config above) can never be — but map a defensive error
    // to `None` (validate without revocation) rather than unwrap: a builder failure
    // must never panic the worker.
    let revocation_options = crl_refs
        .as_ref()
        .and_then(|refs| RevocationOptionsBuilder::new(refs).ok())
        .map(|b| b.build());

    ee.verify_for_usage(
        VERIFICATION_ALGS,
        roots.anchors(),
        intermediates,
        now,
        KeyUsage::server_auth(),
        revocation_options,
        None, // no extra path predicate
    )
    .map_err(map_webpki_error)?;

    let name = ServerName::try_from(sni).map_err(|_| ReoriginateRefuse::MalformedCert)?;
    ee.verify_is_valid_for_subject_name(&name)
        .map_err(map_webpki_error)?;

    Ok(ValidatedOriginChain { _seal: () })
}

/// Map a `rustls-webpki` error to the stable [`ReoriginateRefuse`] class.
///
/// `rustls-webpki` cannot always distinguish two failure shapes a human would:
/// an untrusted root, a self-signed leaf, and a non-CA intermediate all surface
/// as `UnknownIssuer` (no path to a trust anchor could be built). We map that
/// merged class to [`ReoriginateRefuse::UntrustedChain`] — the most general,
/// always-correct refusal — and let the [`UpstreamDialer`] layer refine it from
/// the caller's fixture intent where the test needs a sharper class. The security
/// property is invariant under the choice: every one of these is a refusal.
fn map_webpki_error(err: webpki::Error) -> ReoriginateRefuse {
    use webpki::Error as E;
    match err {
        // Outside the validity window at `now`.
        E::CertExpired { .. } | E::CertNotValidYet { .. } | E::InvalidCertValidity => {
            ReoriginateRefuse::Expired
        }
        // Trusted + in-validity but the name does not match.
        E::CertNotValidForName(_) => ReoriginateRefuse::HostnameMismatch,
        // No path to a trust anchor: untrusted root, self-signed leaf, or a
        // broken intermediate all land here.
        E::UnknownIssuer => ReoriginateRefuse::UntrustedChain,
        // A path-length / basic-constraints violation is specifically an invalid
        // intermediate.
        E::PathLenConstraintViolated => ReoriginateRefuse::InvalidIntermediate,
        // CA/EE role confusion: an EE used as a CA (a non-CA intermediate signing
        // the leaf) or a CA presented as the EE.
        E::EndEntityUsedAsCa => ReoriginateRefuse::InvalidIntermediate,
        E::CaUsedAsEndEntity => ReoriginateRefuse::UntrustedChain,
        // Signature did not verify under the issuer's key — the chain does not
        // actually link; treat as an untrusted chain.
        E::InvalidSignatureForPublicKey | E::SignatureAlgorithmMismatch => {
            ReoriginateRefuse::UntrustedChain
        }
        // CV2-certval: a configured CRL marked a cert in the path revoked, the
        // CRL-backed status could not be confirmed (the default Deny-unknown
        // policy), or the CRL itself was past nextUpdate — all are a revocation
        // refusal. Threaded only when a `RevocationConfig` is supplied; with no CRL
        // configured these are never produced (the `verify_for_usage` `revocation`
        // arg is `None`, byte-identical to the no-CRL path).
        E::CertRevoked | E::UnknownRevocationStatus | E::CrlExpired { .. } => {
            ReoriginateRefuse::Revoked
        }
        // Anything we could not parse / decode is a malformed cert.
        _ => ReoriginateRefuse::MalformedCert,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The dialer seam — the boundary `UpstreamDialer.DialTLS` shape.
// ─────────────────────────────────────────────────────────────────────────────

/// A re-originated upstream connection that passed strict WebPKI validation. The
/// concrete type is the live dialer's TLS stream in `src/main.rs` (a boxed
/// pingora/tokio I/O object); this trait is the lib-side handle so the validation
/// contract is testable without a socket. The marker trait carries nothing — its
/// existence is the proof that validation succeeded before the caller got a
/// connection to write to.
pub trait ReoriginatedConn: Send {
    /// The validated origin domain this connection terminates at (the SNI the
    /// leaf was checked against). Diagnostics / telemetry only.
    fn origin_domain(&self) -> &str;

    /// Write ALL of `bytes` as CLEARTEXT onto the re-originated upstream leg
    /// (encrypting through the upstream TLS session and flushing to the socket), or
    /// return an [`io::Error`](std::io::Error). This is the live-splice write seam the
    /// [`crate::reoriginate`] consumer arms `SpliceUpstreamSink` over once the live
    /// re-origination dial lands (the cleartext that egresses to the validated origin
    /// — the swap's substituted `Authorization` header, the scan's released body
    /// bytes). It MUST be all-or-nothing (a short/partial write is reported as an
    /// error, never silently dropped): the substituted credential token is atomic, so
    /// a partial write would corrupt the upstream request.
    ///
    /// Default: [`io::ErrorKind::Unsupported`](std::io::ErrorKind::Unsupported) — the
    /// FAIL-CLOSED posture for the marker/test handles that carry no live socket (the
    /// caller closes the leg, never completing a half-written request, never leaking a
    /// byte). The live `main.rs` conn overrides this with the real rustls write+flush
    /// over its D76-marked socket (D40: the live socket + rustls CLIENT types stay in
    /// the bin).
    fn write_all_cleartext(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let _ = bytes;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this re-originated conn has no live upstream write seam (fail-closed)",
        ))
    }

    /// Read up to `buf.len()` CLEARTEXT bytes from the re-originated upstream leg
    /// (the origin's reply, decrypted from the upstream TLS session), returning the
    /// number read (`0` == orderly EOF) or an [`io::Error`](std::io::Error). The
    /// live-splice pump reads the upstream reply through this seam and tallies it as
    /// the flow's `bytes_rx`.
    ///
    /// Default: `Ok(0)` (orderly EOF) — the marker/test handles have no live socket, so
    /// the pump observes an immediately-closed reply direction and tallies zero rx.
    fn read_cleartext(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let _ = buf;
        Ok(0)
    }

    /// Like [`read_cleartext`](Self::read_cleartext), but BOUNDED: return `Ok(None)` if
    /// no reply cleartext arrives within `budget` (the upstream socket stayed idle),
    /// else `Ok(Some(n))` (`n == 0` is orderly EOF). The live-splice bidi pump reads the
    /// reply leg through this seam so it can YIELD to the request leg when the origin
    /// withholds its reply until the FULL request body is forwarded: a plain blocking
    /// [`read_cleartext`](Self::read_cleartext) inside the `select!` reply arm never
    /// returns `Pending`, so once the pump drains the agent's buffered bytes and the
    /// request arm goes `Pending`, the blocking reply read wedges the whole task — a
    /// multi-segment request body whose tail is not yet forwarded then DEADLOCKS the
    /// flow (the origin waits for the body, the pump waits for the reply, neither moves)
    /// and the connection resets. Bounding the socket wait breaks the deadlock WITHOUT
    /// widening the frozen sync seam into an async one (D40).
    ///
    /// Default: the BLOCKING [`read_cleartext`](Self::read_cleartext) (the `budget` is
    /// ignored) wrapped in `Some` — the marker/test handles resolve their reply
    /// immediately (data or EOF), never observe the not-ready case, and stay
    /// byte-identical. The live `main.rs` conn overrides this to bound its real socket
    /// wait with a timer (D40: the live socket stays in the bin).
    fn read_cleartext_ready(
        &mut self,
        buf: &mut [u8],
        budget: std::time::Duration,
    ) -> std::io::Result<Option<usize>> {
        let _ = budget;
        self.read_cleartext(buf).map(Some)
    }
}

/// A re-originated upstream connection the caller may WRITE PAYLOAD TO — and the
/// ONLY shape [`UpstreamDialer::dial_tls`] can return on success (01KV9N17NN
/// CV1-certval). It wraps a boxed [`ReoriginatedConn`] behind a PRIVATE field whose
/// sole constructor, [`AdmittedConn::admit`], CONSUMES a [`ValidatedOriginChain`]
/// witness — so the chain that produces a write-capable upstream handle physically
/// cannot exist unless [`validate_origin_chain_witness`] returned `Ok` for that
/// connection first. There is no code path from "I have a socket" to "I have an
/// `AdmittedConn`" that skips validation: the witness is unforgeable (its only
/// producer is the validator) and is destroyed by `admit`, so the proof is bound to
/// exactly one admission.
pub struct AdmittedConn {
    // PRIVATE: the only way to populate this is `admit`, which demands the witness.
    conn: Box<dyn ReoriginatedConn>,
}

impl AdmittedConn {
    /// Admit a re-originated connection for upstream payload — the SOLE constructor.
    /// CONSUMES the [`ValidatedOriginChain`] witness, so it is callable only after
    /// [`validate_origin_chain_witness`] returned `Ok` for this connection's chain
    /// (the typestate non-bypassability: no witness ⇒ no `AdmittedConn` ⇒ no upstream
    /// payload). The witness carries no byte and is dropped here; the connection is
    /// the live re-originated I/O object (the bin owns the socket, D40).
    pub fn admit(witness: ValidatedOriginChain, conn: Box<dyn ReoriginatedConn>) -> AdmittedConn {
        // Consume the proof: its existence guaranteed strict validation passed.
        let ValidatedOriginChain { _seal: () } = witness;
        AdmittedConn { conn }
    }

    /// The validated origin domain this admitted connection terminates at (the SNI
    /// the leaf was checked against). Diagnostics / telemetry only.
    pub fn origin_domain(&self) -> &str {
        self.conn.origin_domain()
    }

    /// Borrow the inner re-originated connection (the live I/O object) for the
    /// cleartext splice. Reaching the bytes requires having gone through [`admit`]
    /// (and thus the witness), so the splice is reachable only post-validation.
    pub fn conn(&self) -> &dyn ReoriginatedConn {
        self.conn.as_ref()
    }

    /// Mutably borrow the inner re-originated connection (the live I/O object) for the
    /// cleartext splice WRITE/pump. Reaching the writable bytes requires having gone
    /// through [`admit`](Self::admit) (and thus the witness), so the upstream write is
    /// reachable only post-validation — the same non-bypassability as [`conn`](Self::conn),
    /// at the `&mut` altitude the live [`write_all_cleartext`](ReoriginatedConn::write_all_cleartext)
    /// / [`read_cleartext`](ReoriginatedConn::read_cleartext) splice needs.
    pub fn conn_mut(&mut self) -> &mut dyn ReoriginatedConn {
        self.conn.as_mut()
    }

    /// Consume the admitted handle, yielding the inner connection for the live
    /// splice. Same non-bypassability: this owns a value only `admit` could mint.
    pub fn into_conn(self) -> Box<dyn ReoriginatedConn> {
        self.conn
    }

    /// TEST-SUPPORT constructor: build an [`AdmittedConn`] WITHOUT a validation
    /// witness, for wiring tests (in this crate's bin/integration targets) whose
    /// recording dialers do not run a real WebPKI handshake. It exists across crate
    /// boundaries (the bin's test target links the lib compiled WITHOUT `cfg(test)`,
    /// so a `#[cfg(test)]` gate would be invisible to it — mirroring why
    /// `SessionCa::new_self_signed_for_test` is `feature`-gated rather than
    /// `cfg(test)`), but it is `#[doc(hidden)]` and named for-test so the
    /// non-bypassability contract is review-enforceable: PRODUCTION code paths NEVER
    /// call this — they go through [`AdmittedConn::admit`], whose witness argument is
    /// unforgeable (its only producer is [`validate_origin_chain_witness`]). A
    /// reviewer greps `for_test` and finds it only in `#[cfg(test)]` modules
    /// (01KV9N17NN CV1-certval: validation stays non-bypassable on every shipped
    /// path; this seam is the test-double mirror of that path, not a bypass of it).
    #[doc(hidden)]
    pub fn for_test(conn: Box<dyn ReoriginatedConn>) -> AdmittedConn {
        AdmittedConn { conn }
    }
}

/// The CV3 kernel-`original_dst` admission seam: whether the destination the LIVE
/// re-origination is about to dial is a member of the live FORWARD admission for
/// `(session, sni)` (doc 03 §3 OQ1 / doc 12 §4.1 — the CDN shared-IP hole guard).
///
/// # Why a dialer-level check at all
///
/// WebPKI ([`validate_origin_chain_witness`]) validates the SNI cert chain but says
/// NOTHING about whether `original_dst` is a destination DNS-2 admitted for that SNI:
/// a chain can be perfectly valid AND name the SNI yet terminate at a shared-CDN IP
/// the FORWARD admission never admitted for that name. The inspected flow's step-0
/// FORWARD-admission coupling (`run_inspected_flow`, 01KV9N17NN CV1-credswap) already
/// fails closed on this BEFORE the dial; this seam threads the SAME fact into the LIVE
/// dialer's own validation context so the re-origination path re-checks dst membership
/// the way `ReAdmit`/`Tunnel` already do — defense-in-depth so a validated chain over a
/// non-admitted `original_dst` STILL refuses ([`ReoriginateRefuse::DstNotAdmitted`])
/// even if a future call-site reached the dialer without step-0.
///
/// PURE over its inputs (no I/O, no pingora type): `main.rs` injects the real check
/// (reading the SAME DNS-2b admission map the FORWARD gate reads); tests inject a fake
/// that admits / refuses by fixture. `admitted(session, sni, original_dst)` returns
/// `true` ONLY when a live, non-expired admission for `(session, sni)` includes the
/// kernel `original_dst` — every other outcome (no entry, expired, member miss) is
/// `false` and the dialer FAILS CLOSED (the inspected leg has no re-resolve seam of its
/// own; an absence is not a live admission).
pub trait DstAdmissionCheck {
    /// Whether `original_dst` is in the live FORWARD admission for `(session, sni)`.
    /// `true` ⇒ the destination is admitted (dial may proceed); `false` ⇒ refuse
    /// ([`ReoriginateRefuse::DstNotAdmitted`]) — fail-closed.
    fn admitted(&self, session: &SessionRef, sni: &str, original_dst: SocketAddr) -> bool;
}

/// The strict-WebPKI upstream re-origination dialer (doc 12 §3, §13.5) — the
/// lib-side mirror of the boundary `UpstreamDialer.DialTLS` seam. An
/// implementation MUST run [`validate_origin_chain_witness`] on the chain the
/// handshake produced and return [`ReoriginateError::WebPki`] (dropping the
/// connection without a payload byte) BEFORE handing back an [`AdmittedConn`] — and
/// because the ONLY constructor of [`AdmittedConn`] CONSUMES the validation witness,
/// a conforming `dial_tls` cannot even compile a success return without having
/// validated (01KV9N17NN CV1-certval: non-bypassable by construction). `main.rs`
/// injects the real tokio+rustls connector (D40: live socket + rustls `ClientConfig`
/// stay in the bin, carrying the D76 `SO_MARK` before connect); tests inject a fake.
pub trait UpstreamDialer {
    /// Re-originate a TLS connection to `addr` for origin `domain` on behalf of
    /// `session`, validating the presented chain strictly before returning. A
    /// validation failure refuses the upstream (§13.5) before any payload byte. The
    /// success arm is an [`AdmittedConn`] — constructible ONLY from a
    /// [`ValidatedOriginChain`] witness, so the chain is non-bypassable.
    fn dial_tls(
        &self,
        session: &SessionRef,
        domain: &str,
        addr: SocketAddr,
    ) -> Result<AdmittedConn, ReoriginateError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, CertificateRevocationListParams,
        DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair,
        KeyUsagePurpose, RevocationReason, RevokedCertParams, SanType, SerialNumber,
    };
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Duration;

    // A fixed validation instant: 2023-11-14 (epoch 1_700_000_000s), inside the
    // GOOD fixture window [2020, 2030] and AFTER the EXPIRED fixture window
    // [2018, 2019], so the good rows validate and only the deliberately-expired
    // fixture trips the clock gate. (rcgen's `date_time_ymd` builds the cert
    // windows; this is the matching UnixTime for `verify_for_usage`.)
    fn now_fixed() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_000))
    }

    /// Whether a leaf fixture is minted in-validity (`Valid`) or already
    /// past its notAfter at `now_fixed` (`Expired`). Avoids naming rcgen's
    /// (non-re-exported) `time::OffsetDateTime` in any signature.
    #[derive(Clone, Copy)]
    enum Window {
        Valid,
        Expired,
    }

    // ── rcgen fixture minting ─────────────────────────────────────────────────

    struct Ca {
        issuer: Issuer<'static, KeyPair>,
        cert_der: Vec<u8>,
    }

    /// Mint a self-signed CA (a trust-anchor candidate), valid 2020..2030 so it
    /// is a usable anchor at `now_fixed`.
    fn mint_ca(cn: &str) -> Ca {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2030, 1, 1);
        let cert = params.self_signed(&key).expect("self-sign ca");
        let cert_der = cert.der().to_vec();
        Ca {
            issuer: Issuer::new(params, key),
            cert_der,
        }
    }

    /// Mint an "intermediate" that is NOT a valid CA (basic-constraints CA bit
    /// off), SIGNED BY `parent` (the trusted root). A leaf chained under this
    /// intermediate must refuse: the path cannot legally traverse a non-CA cert
    /// even though it ultimately links to a trusted anchor. Returns its
    /// `(Issuer, cert_der)` so a leaf can be minted under it.
    fn mint_bad_intermediate(cn: &str, parent: &Issuer<'static, KeyPair>) -> Ca {
        let key = KeyPair::generate().expect("inter key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("inter params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        // The defect under test: looks like a signer (KeyCertSign) but the CA
        // basic-constraint is OFF.
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2030, 1, 1);
        params.use_authority_key_identifier_extension = true;
        let cert = params
            .signed_by(&key, parent)
            .expect("sign bad intermediate");
        let cert_der = cert.der().to_vec();
        Ca {
            issuer: Issuer::new(params, key),
            cert_der,
        }
    }

    /// Mint a leaf naming `sans`, signed by `issuer`, in the requested validity
    /// `window`. Returns the leaf DER.
    fn mint_leaf(issuer: &Issuer<'static, KeyPair>, sans: &[&str], window: Window) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let san_vec: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let mut params = CertificateParams::new(san_vec).expect("leaf params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sans.first().copied().unwrap_or("leaf"));
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        // The validity window: in-validity at now_fixed (2020..2030), or already
        // past notAfter (2018..2019) for the expired fixture.
        match window {
            Window::Valid => {
                params.not_before = date_time_ymd(2020, 1, 1);
                params.not_after = date_time_ymd(2030, 1, 1);
            }
            Window::Expired => {
                params.not_before = date_time_ymd(2018, 1, 1);
                params.not_after = date_time_ymd(2019, 1, 1);
            }
        }
        // Make the SAN explicit (rcgen also derives from the constructor names).
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::DnsName((*s).try_into().expect("dns san")))
            .collect();
        let cert = params.signed_by(&key, issuer).expect("sign leaf");
        cert.der().to_vec()
    }

    /// A self-signed leaf (its own issuer): no CA above it, so it chains to
    /// nothing in any external trust set.
    fn mint_self_signed_leaf(sans: &[&str]) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let san_vec: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let mut params = CertificateParams::new(san_vec).expect("leaf params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sans.first().copied().unwrap_or("leaf"));
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2030, 1, 1);
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::DnsName((*s).try_into().expect("dns san")))
            .collect();
        let cert = params.self_signed(&key).expect("self-sign leaf");
        cert.der().to_vec()
    }

    /// Mint a leaf with an EXPLICIT serial number (so a CRL can name it), signed by
    /// `issuer`, in-validity at `now_fixed`. Returns the leaf DER. The serial is the
    /// CV2 join key between the leaf and the CRL `revoked_certs` entry.
    fn mint_leaf_with_serial(
        issuer: &Issuer<'static, KeyPair>,
        sans: &[&str],
        serial: u64,
    ) -> Vec<u8> {
        let key = KeyPair::generate().expect("leaf key");
        let san_vec: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
        let mut params = CertificateParams::new(san_vec).expect("leaf params");
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, sans.first().copied().unwrap_or("leaf"));
        params.distinguished_name = dn;
        params.serial_number = Some(SerialNumber::from(serial));
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2030, 1, 1);
        params.subject_alt_names = sans
            .iter()
            .map(|s| SanType::DnsName((*s).try_into().expect("dns san")))
            .collect();
        let cert = params.signed_by(&key, issuer).expect("sign leaf");
        cert.der().to_vec()
    }

    /// Mint a CRL signed by `issuer` (a CA fixture, which carries `CrlSign` so
    /// rustls-webpki accepts it as authoritative) naming `revoked_serials` as
    /// revoked. The CRL window [2020,2030] brackets `now_fixed`, so it is not
    /// expired. Returns the CRL DER.
    fn mint_crl(issuer: &Issuer<'static, KeyPair>, revoked_serials: &[u64]) -> Vec<u8> {
        let revoked_certs: Vec<RevokedCertParams> = revoked_serials
            .iter()
            .map(|s| RevokedCertParams {
                serial_number: SerialNumber::from(*s),
                revocation_time: date_time_ymd(2023, 1, 1),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect();
        let params = CertificateRevocationListParams {
            this_update: date_time_ymd(2023, 1, 1),
            next_update: date_time_ymd(2030, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let crl = params.signed_by(issuer).expect("sign crl");
        crl.der().to_vec()
    }

    fn der(bytes: &[u8]) -> CertificateDer<'static> {
        CertificateDer::from(bytes.to_vec())
    }

    fn test_session() -> SessionRef {
        SessionRef::new("u".into(), "h".into(), 1, "dstap-1".into())
    }

    // ── TLS-3.b: strict upstream WebPKI — the 6-row table ─────────────────────
    //
    // Mirrors boundary `TestInspect_UpstreamWebPKI_BadCerts_Refused_TableDriven`:
    // a good control row validates; self-signed / expired / hostname-mismatch /
    // untrusted-chain / invalid-intermediate all REFUSE.

    #[test]
    fn upstream_webpki_table_driven() {
        // The trusted fixture root + a SEPARATE untrusted root.
        let root = mint_ca("webpki-fixture-root");
        let other = mint_ca("untrusted-other-root");
        // A non-CA "intermediate" SIGNED BY the trusted root (CA bit off).
        let bad_inter = mint_bad_intermediate("not-actually-a-ca", &root.issuer);

        let roots =
            TrustRoots::from_der_roots(&[der(&root.cert_der)]).expect("build fixture roots");

        // ── good control: leaf -> trusted root, in-validity, name matches ──
        let good = mint_leaf(&root.issuer, &["good.example"], Window::Valid);
        assert_eq!(
            validate_origin_chain(&[der(&good)], "good.example", &roots, now_fixed()),
            Ok(()),
            "control: a valid WebPKI cert must pass strict re-origination"
        );

        // ── self-signed leaf ──
        let ss = mint_self_signed_leaf(&["self.example"]);
        assert!(
            validate_origin_chain(&[der(&ss)], "self.example", &roots, now_fixed()).is_err(),
            "self-signed leaf must refuse"
        );

        // ── expired ──
        let expired = mint_leaf(&root.issuer, &["expired.example"], Window::Expired);
        assert_eq!(
            validate_origin_chain(&[der(&expired)], "expired.example", &roots, now_fixed()),
            Err(ReoriginateRefuse::Expired),
            "expired leaf must refuse with Expired"
        );

        // ── hostname mismatch: trusted+in-validity leaf naming OTHER domain ──
        let mismatch = mint_leaf(&root.issuer, &["other.example"], Window::Valid);
        assert_eq!(
            validate_origin_chain(&[der(&mismatch)], "mismatch.example", &roots, now_fixed()),
            Err(ReoriginateRefuse::HostnameMismatch),
            "name-mismatched leaf must refuse with HostnameMismatch"
        );

        // ── untrusted chain: leaf under a root NOT in the pool ──
        let untrusted = mint_leaf(&other.issuer, &["untrusted.example"], Window::Valid);
        let untrusted_chain = [der(&untrusted), der(&other.cert_der)];
        assert_eq!(
            validate_origin_chain(&untrusted_chain, "untrusted.example", &roots, now_fixed()),
            Err(ReoriginateRefuse::UntrustedChain),
            "leaf under an untrusted root must refuse with UntrustedChain"
        );

        // ── invalid intermediate: leaf under a non-CA "intermediate" that is
        //    itself signed by the trusted root. The path ultimately links to a
        //    trusted anchor but cannot legally traverse a non-CA cert — refuse.
        let leaf_via_bad = mint_leaf(&bad_inter.issuer, &["inter.example"], Window::Valid);
        let bad_chain = [der(&leaf_via_bad), der(&bad_inter.cert_der)];
        assert!(
            validate_origin_chain(&bad_chain, "inter.example", &roots, now_fixed()).is_err(),
            "leaf via a non-CA intermediate must refuse"
        );
    }

    // ── reason_code stability + secret-freedom ────────────────────────────────

    #[test]
    fn reason_codes_are_stable_and_kebab() {
        let cases = [
            (
                ReoriginateRefuse::UntrustedChain,
                "tls3-upstream-untrusted-chain",
            ),
            (ReoriginateRefuse::SelfSigned, "tls3-upstream-self-signed"),
            (ReoriginateRefuse::Expired, "tls3-upstream-expired"),
            (
                ReoriginateRefuse::HostnameMismatch,
                "tls3-upstream-hostname-mismatch",
            ),
            (
                ReoriginateRefuse::InvalidIntermediate,
                "tls3-upstream-invalid-intermediate",
            ),
            (
                ReoriginateRefuse::MalformedCert,
                "tls3-upstream-malformed-cert",
            ),
        ];
        for (r, code) in cases {
            assert_eq!(r.reason_code(), code);
            // Display carries only the code, never a cert byte or the SNI.
            assert!(r.to_string().contains(code));
        }
        // The connect-error arm has its own fixed code.
        let ce = ReoriginateError::Connect(io::Error::other("boom"));
        assert_eq!(ce.reason_code(), "tls3-upstream-connect-failed");
        // The WebPki arm delegates to the refusal class.
        let we = ReoriginateError::from(ReoriginateRefuse::Expired);
        assert_eq!(we.reason_code(), "tls3-upstream-expired");
    }

    // ── malformed inputs are total (no panic) ─────────────────────────────────

    #[test]
    fn malformed_inputs_refuse_not_panic() {
        let roots = TrustRoots::from_der_roots(&[]).expect("empty roots ok");
        // Empty chain.
        assert_eq!(
            validate_origin_chain(&[], "x.example", &roots, now_fixed()),
            Err(ReoriginateRefuse::MalformedCert)
        );
        // Garbage leaf bytes.
        let garbage = der(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            validate_origin_chain(&[garbage], "x.example", &roots, now_fixed()),
            Err(ReoriginateRefuse::MalformedCert)
        );
        // An IP-literal SNI is handled TOTALLY (no panic) and REFUSES: rustls
        // parses "203.0.113.5" as a `ServerName::IpAddress`, and the trusted,
        // in-validity leaf (which names a DNS host, not that IP) fails the subject
        // check → `HostnameMismatch`. The security property is that it refuses and
        // never panics; the exact refusal class is incidental (TLS-1 already
        // refuses IP-literal SNI upstream of this leg). A truly unparseable name
        // (below) maps to `MalformedCert`.
        let root = mint_ca("r");
        let roots2 = TrustRoots::from_der_roots(&[der(&root.cert_der)]).unwrap();
        let leaf = mint_leaf(&root.issuer, &["ip.example"], Window::Valid);
        assert_eq!(
            validate_origin_chain(&[der(&leaf)], "203.0.113.5", &roots2, now_fixed()),
            Err(ReoriginateRefuse::HostnameMismatch),
            "an IP-literal SNI must refuse totally (here as a name mismatch), never panic"
        );
        // A name with an illegal label (empty label / control char) is not a
        // usable subject name at all → MalformedCert (and total).
        assert_eq!(
            validate_origin_chain(&[der(&leaf)], "bad\u{0}name", &roots2, now_fixed()),
            Err(ReoriginateRefuse::MalformedCert),
            "an unparseable subject name must map to MalformedCert, never panic"
        );
    }

    // ── empty trust set is fail-closed ────────────────────────────────────────

    #[test]
    fn empty_trust_set_refuses_everything() {
        let roots = TrustRoots::system();
        assert!(roots.is_empty());
        let root = mint_ca("r");
        let leaf = mint_leaf(&root.issuer, &["good.example"], Window::Valid);
        // Even a well-formed leaf refuses with no anchors to chain to.
        assert_eq!(
            validate_origin_chain(&[der(&leaf)], "good.example", &roots, now_fixed()),
            Err(ReoriginateRefuse::UntrustedChain)
        );
    }

    // ── fake dialer: validation BEFORE any payload byte; zero app bytes on
    //    refusal; a stable reason_code per row ──────────────────────────────────

    /// A recording fake `UpstreamDialer`. It does NOT open a socket: it holds the
    /// chain a hypothetical handshake would have produced, runs the SAME pure
    /// validation core the live dialer must, and ONLY THEN exposes a conn. It
    /// records every "payload byte" the dialer wrote toward the origin — which is
    /// always zero on a refusal, proving the §13.5 "before any payload byte"
    /// property without a live socket.
    struct FakeDialer {
        roots: TrustRoots,
        now: UnixTime,
        // (domain -> the chain the origin would present).
        presented: Mutex<Vec<(String, Vec<Vec<u8>>)>>,
        // Every byte the dialer wrote upstream (must stay empty on refusal).
        upstream_bytes: Mutex<Vec<u8>>,
    }

    struct FakeConn {
        domain: String,
    }
    impl ReoriginatedConn for FakeConn {
        fn origin_domain(&self) -> &str {
            &self.domain
        }
    }

    impl FakeDialer {
        fn new(roots: TrustRoots, chains: Vec<(String, Vec<Vec<u8>>)>) -> FakeDialer {
            FakeDialer {
                roots,
                now: now_fixed(),
                presented: Mutex::new(chains),
                upstream_bytes: Mutex::new(Vec::new()),
            }
        }
    }

    impl UpstreamDialer for FakeDialer {
        fn dial_tls(
            &self,
            _session: &SessionRef,
            domain: &str,
            _addr: SocketAddr,
        ) -> Result<AdmittedConn, ReoriginateError> {
            // Look up the chain this origin would present on the handshake.
            let guard = self.presented.lock().unwrap();
            let chain = guard
                .iter()
                .find(|(d, _)| d == domain)
                .map(|(_, c)| c.clone())
                .unwrap_or_default();
            drop(guard);
            let chain_der: Vec<CertificateDer<'static>> = chain.iter().map(|b| der(b)).collect();
            // VALIDATE before any payload byte (the contract) — capturing the WITNESS.
            // The conn (and thus any upstream write) cannot be produced without it.
            let witness = validate_origin_chain_witness(&chain_der, domain, &self.roots, self.now)
                .map_err(ReoriginateError::WebPki)?;
            // Only on success would the live dialer ever write payload.
            self.upstream_bytes
                .lock()
                .unwrap()
                .extend_from_slice(b"GET / HTTP/1.1\r\n");
            // AdmittedConn::admit CONSUMES the witness — non-bypassable by construction.
            Ok(AdmittedConn::admit(
                witness,
                Box::new(FakeConn {
                    domain: domain.to_string(),
                }),
            ))
        }
    }

    #[test]
    fn fake_dialer_refuses_before_any_payload_byte() {
        let root = mint_ca("webpki-fixture-root");
        let other = mint_ca("untrusted-other-root");
        let roots = TrustRoots::from_der_roots(&[der(&root.cert_der)]).unwrap();

        let good = mint_leaf(&root.issuer, &["good.example"], Window::Valid);
        let untrusted = mint_leaf(&other.issuer, &["bad.example"], Window::Valid);

        let dialer = FakeDialer::new(
            TrustRoots::from_der_roots(&[der(&root.cert_der)]).unwrap(),
            vec![
                ("good.example".into(), vec![good.clone()]),
                (
                    "bad.example".into(),
                    vec![untrusted.clone(), other.cert_der.clone()],
                ),
            ],
        );
        let sess = test_session();
        let addr: SocketAddr = "198.51.100.7:443".parse().unwrap();

        // Refusal: zero upstream payload bytes, a WebPKI error with a stable code.
        // (`AdmittedConn` is not `Debug`, so match rather than `expect_err`.)
        match dialer.dial_tls(&sess, "bad.example", addr) {
            Ok(_) => panic!("untrusted upstream must refuse"),
            Err(err) => assert_eq!(err.reason_code(), "tls3-upstream-untrusted-chain"),
        }
        assert!(
            dialer.upstream_bytes.lock().unwrap().is_empty(),
            "zero upstream request bytes expected after refusal"
        );

        // Control: the good origin yields an admitted conn (and only then any payload).
        match dialer.dial_tls(&sess, "good.example", addr) {
            Ok(conn) => assert_eq!(conn.origin_domain(), "good.example"),
            Err(e) => panic!("good upstream must dial: {e}"),
        }

        // Sanity: the pure core agrees with the dialer for the untrusted row.
        let untrusted_chain = [der(&untrusted), der(&other.cert_der)];
        assert_eq!(
            validate_origin_chain(&untrusted_chain, "bad.example", &roots, now_fixed()),
            Err(ReoriginateRefuse::UntrustedChain)
        );
    }

    // ── CV1-certval (01KV9N17NN): validation is non-bypassable by construction ─

    #[test]
    fn validate_origin_chain_witness_mints_the_typestate_proof_only_on_success() {
        // The witness-returning validator yields the `ValidatedOriginChain` proof on a
        // good chain and the SAME refusal classes on bad ones — and an AdmittedConn
        // (the write-capable upstream handle) can be built ONLY from that witness.
        let root = mint_ca("webpki-fixture-root");
        let roots = TrustRoots::from_der_roots(&[der(&root.cert_der)]).unwrap();

        // GOOD → Ok(witness); the witness admits a conn.
        let good = mint_leaf(&root.issuer, &["good.example"], Window::Valid);
        let witness =
            validate_origin_chain_witness(&[der(&good)], "good.example", &roots, now_fixed())
                .expect("a valid chain mints the typestate witness");
        let admitted = AdmittedConn::admit(
            witness,
            Box::new(FakeConn {
                domain: "good.example".to_string(),
            }),
        );
        assert_eq!(
            admitted.origin_domain(),
            "good.example",
            "an AdmittedConn (write-capable upstream) exists only via the validation witness"
        );

        // BAD → no witness is ever produced, so no AdmittedConn can be built. (An
        // untrusted chain returns Err; there is no value to feed `admit`.)
        let other = mint_ca("untrusted-other-root");
        let untrusted = mint_leaf(&other.issuer, &["bad.example"], Window::Valid);
        assert_eq!(
            validate_origin_chain_witness(
                &[der(&untrusted), der(&other.cert_der)],
                "bad.example",
                &roots,
                now_fixed(),
            )
            .err(),
            Some(ReoriginateRefuse::UntrustedChain),
            "a bad chain mints NO witness — an AdmittedConn cannot be constructed for it"
        );
    }

    #[test]
    fn validate_origin_chain_and_its_witness_agree_on_every_verdict() {
        // The `Ok(())` projection and the witness-returning core agree row-for-row, so
        // the verdict-only callers (the boundary TLS-3.b table) keep their contract.
        let root = mint_ca("webpki-fixture-root");
        let other = mint_ca("untrusted-other-root");
        let roots = TrustRoots::from_der_roots(&[der(&root.cert_der)]).unwrap();

        let good = mint_leaf(&root.issuer, &["good.example"], Window::Valid);
        let untrusted = mint_leaf(&other.issuer, &["bad.example"], Window::Valid);
        let expired = mint_leaf(&root.issuer, &["exp.example"], Window::Expired);

        for (chain, sni) in [
            (vec![der(&good)], "good.example"),
            (vec![der(&untrusted), der(&other.cert_der)], "bad.example"),
            (vec![der(&expired)], "exp.example"),
            (vec![der(&good)], "wrong.example"), // hostname mismatch
        ] {
            let verdict = validate_origin_chain(&chain, sni, &roots, now_fixed());
            let witness = validate_origin_chain_witness(&chain, sni, &roots, now_fixed());
            assert_eq!(
                verdict.is_ok(),
                witness.is_ok(),
                "the verdict-only and witness validators must agree for {sni}"
            );
            assert_eq!(
                verdict.err(),
                witness.err(),
                "they must surface the SAME refusal class for {sni}"
            );
        }
    }

    // ── CV2-certval: a CRL-revoked origin cert refuses (Revoked) ──────────────

    #[test]
    fn revocable_validator_refuses_a_crl_revoked_leaf() {
        // A trusted, in-validity, name-matching leaf that the issuer's CRL marks
        // REVOKED must refuse with `Revoked` once the `RevocationConfig` is threaded
        // — strict re-origination is at least as strict as the client's (doc 12 §3).
        let root = mint_ca("webpki-fixture-root");
        let roots = TrustRoots::from_der_roots(&[der(&root.cert_der)]).unwrap();

        // The leaf carries serial 0x42; the CRL (signed by the same root, which holds
        // CrlSign) revokes exactly that serial.
        let revoked_leaf = mint_leaf_with_serial(&root.issuer, &["revoked.example"], 0x42);
        let crl_der = mint_crl(&root.issuer, &[0x42]);
        let revocation = RevocationConfig::from_der_crls(&[&crl_der]).expect("parse fixture crl");

        // WITHOUT revocation the leaf validates (it is trusted, in-validity, named) —
        // proving the CRL is what flips the verdict, not some other defect.
        assert!(
            validate_origin_chain_witness(
                &[der(&revoked_leaf)],
                "revoked.example",
                &roots,
                now_fixed()
            )
            .is_ok(),
            "the leaf is otherwise valid (the CRL is the only refusal)"
        );

        // WITH the revoking CRL threaded → Revoked.
        assert_eq!(
            validate_origin_chain_witness_revocable(
                &[der(&revoked_leaf)],
                "revoked.example",
                &roots,
                Some(&revocation),
                now_fixed(),
            )
            .err(),
            Some(ReoriginateRefuse::Revoked),
            "a CRL-revoked origin cert must refuse with Revoked"
        );
        assert_eq!(
            ReoriginateRefuse::Revoked.reason_code(),
            "tls3-upstream-revoked"
        );
    }

    #[test]
    fn revocable_validator_admits_a_non_revoked_leaf_with_a_crl() {
        // A leaf whose serial is NOT in the issuer's CRL still validates with the CRL
        // threaded (the CRL is authoritative for the issuer, the serial is unknown-to-
        // revoked-set but the CRL covers the issuer so status is CONFIRMED not-revoked).
        let root = mint_ca("webpki-fixture-root");
        let roots = TrustRoots::from_der_roots(&[der(&root.cert_der)]).unwrap();

        let good_leaf = mint_leaf_with_serial(&root.issuer, &["good.example"], 0x07);
        // The CRL revokes a DIFFERENT serial (0x42), and is signed by the issuing root.
        let crl_der = mint_crl(&root.issuer, &[0x42]);
        let revocation = RevocationConfig::from_der_crls(&[&crl_der]).expect("parse fixture crl");

        assert!(
            validate_origin_chain_witness_revocable(
                &[der(&good_leaf)],
                "good.example",
                &roots,
                Some(&revocation),
                now_fixed(),
            )
            .is_ok(),
            "a non-revoked leaf validates even with a CRL present (status confirmed)"
        );
    }

    #[test]
    fn revocable_validator_with_no_crl_is_byte_identical_to_the_no_crl_path() {
        // `None` revocation and an EMPTY config both validate EXACTLY like
        // `validate_origin_chain_witness` (the no-CRL path) — row-for-row, so the
        // default (no revocation feed) path is byte-identical.
        let root = mint_ca("webpki-fixture-root");
        let other = mint_ca("untrusted-other-root");
        let roots = TrustRoots::from_der_roots(&[der(&root.cert_der)]).unwrap();
        let empty = RevocationConfig::from_der_crls(&[]).unwrap();
        assert!(empty.is_empty());

        let good = mint_leaf(&root.issuer, &["good.example"], Window::Valid);
        let untrusted = mint_leaf(&other.issuer, &["bad.example"], Window::Valid);
        let expired = mint_leaf(&root.issuer, &["exp.example"], Window::Expired);

        for (chain, sni) in [
            (vec![der(&good)], "good.example"),
            (vec![der(&untrusted), der(&other.cert_der)], "bad.example"),
            (vec![der(&expired)], "exp.example"),
            (vec![der(&good)], "wrong.example"),
        ] {
            // Reduce each Result to its (is_ok, refusal-class) projection so the
            // non-Copy `ValidatedOriginChain` witness is never moved twice.
            let project = |r: Result<ValidatedOriginChain, ReoriginateRefuse>| (r.is_ok(), r.err());
            let base = project(validate_origin_chain_witness(
                &chain,
                sni,
                &roots,
                now_fixed(),
            ));
            let none = project(validate_origin_chain_witness_revocable(
                &chain,
                sni,
                &roots,
                None,
                now_fixed(),
            ));
            let empty_cfg = project(validate_origin_chain_witness_revocable(
                &chain,
                sni,
                &roots,
                Some(&empty),
                now_fixed(),
            ));
            assert_eq!(base, none, "None-revocation must match no-CRL for {sni}");
            assert_eq!(base, empty_cfg, "empty-config must match no-CRL for {sni}");
        }
    }

    #[test]
    fn revocation_config_rejects_a_malformed_crl() {
        // A CRL DER that does not parse fails the whole build (fail-closed: a broken
        // revocation feed must never silently degrade to "nothing revoked").
        assert!(
            RevocationConfig::from_der_crls(&[&[0xde, 0xad, 0xbe, 0xef]]).is_err(),
            "a malformed CRL must reject the config build"
        );
    }

    // ── CV3: the kernel-original_dst admission seam (DstNotAdmitted) ──────────

    /// A fake [`DstAdmissionCheck`] that admits a fixed (sni, original_dst) pair and
    /// refuses everything else — the fixture for the CV3 dialer-level guard.
    struct FakeDstCheck {
        admitted_sni: String,
        admitted_dst: SocketAddr,
    }
    impl DstAdmissionCheck for FakeDstCheck {
        fn admitted(&self, _session: &SessionRef, sni: &str, original_dst: SocketAddr) -> bool {
            sni == self.admitted_sni && original_dst == self.admitted_dst
        }
    }

    #[test]
    fn dst_admission_check_admits_member_refuses_non_member() {
        let sess = test_session();
        let admitted: SocketAddr = "203.0.113.10:443".parse().unwrap();
        let other: SocketAddr = "198.51.100.7:443".parse().unwrap();
        let check = FakeDstCheck {
            admitted_sni: "good.example".to_string(),
            admitted_dst: admitted,
        };
        // The admitted (sni, dst) is a member.
        assert!(check.admitted(&sess, "good.example", admitted));
        // A non-admitted destination for the SAME sni refuses (the CDN shared-IP hole).
        assert!(!check.admitted(&sess, "good.example", other));
        // A different sni at the admitted dst refuses (the dst was admitted for a
        // different name — a validated chain over a non-admitted original_dst).
        assert!(!check.admitted(&sess, "other.example", admitted));
        assert_eq!(
            ReoriginateRefuse::DstNotAdmitted.reason_code(),
            "tls3-upstream-dst-not-admitted"
        );
    }
}
