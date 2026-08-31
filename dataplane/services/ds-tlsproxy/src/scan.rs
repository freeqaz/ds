//! TLS-7 in-process secret-scanning gate — the framework-agnostic library core
//! (doc 09 §5 TLS-7; doc 12 §5 / §13.1 / §13.5; D73, the two-plane split;
//! D40 pingora confinement).
//!
//! # What this is
//!
//! D73 ratified the TLS-7 secret-scanning gate as an **in-process module on the
//! inspected (TLS-3-terminated) path**, invoked from the body-filter chain so a
//! secret the agent tries to egress to an allowed domain is caught **at first
//! egress** (the rewritten doc 09 TLS-7 done-when: *"a planted canary credential
//! never egresses"*). This module ships the three frozen pieces D73 §5.1 names —
//! and nothing the §9 "Free" column leaves to the engine:
//!
//! 1. [`SecretMatcher`] — the frozen trait. The matcher is the pluggable engine
//!    (aho-corasick / Vectorscan / RegexSet / exact-set vs Bloom-prefilter — all
//!    §9-Free); it owns its carryover state. Its one method has the frozen
//!    signature D73 §5.1 fixes:
//!
//!    > *"The matcher is a Rust trait (`SecretMatcher`) in or beside `policy-core`:
//!    > `scan(chunk: &[u8], end_of_stream: bool, ctx) -> Verdict`."*
//!
//! 2. [`Verdict`] — the direction-symmetric verdict enum, frozen at Stage-0
//!    beside the D22 seam (doc 14 §7 / doc 16 §9). D73 §5.1:
//!
//!    > *"`Verdict ∈ { Pass(release_n), Hold(await more), Block(abort; matched
//!    > bytes never egress; agent sees an in-band refusal), Flag(pass +
//!    > PolicyDecision event), Redact(reserved — schema slot frozen,
//!    > implementation deferred) }`. Every non-`Pass` verdict carries POL-3
//!    > provenance (rule id, ruleset/digest-set version, policy layer,
//!    > `plane = keyed | generic`)."*
//!
//! 3. [`HoldBackBuffer`] — the **proxy-owned hold-back invariant**. D73 §5.1
//!    splits ownership precisely: the matcher owns carryover state, but
//!
//!    > *"the proxy owns the hold-back invariant: no byte is forwarded upstream
//!    > until the matcher releases it (retain up to max-secret-length−1 trailing
//!    > bytes — a few hundred bytes — so a secret spanning a chunk/TLS-record
//!    > boundary is never detected only after its prefix egressed)."*
//!
//! # Fail-closed-when-keyed (D73, doc 12 §13.5)
//!
//! The §13.5 error table is unconditional for the keyed plane:
//!
//! > *"`SecretMatcher` error/panic while the keyed plane is loaded → **Fail-closed**
//! > (no byte released) — fail-open is permitted only for generic flag-only configs
//! > and must be an explicit policy bit (the Envoy ext_proc `failure_mode_allow`
//! > lesson)."*
//!
//! [`ScanGate::scan_chunk`] encodes that: a matcher `Err(_)` while the keyed plane
//! is loaded collapses to [`Verdict::Hold`] (no byte leaves the hold-back buffer);
//! the explicit fail-open path is gated on a generic-flag-only config bit. The
//! fail-open *policy-bit schema* itself is §9-Free / a later unit — u1 carries the
//! [`FailMode`] placeholder so the fail-closed default is unconditional and the
//! fail-open seam is named, not implemented.
//!
//! # Never-log-the-secret (D73)
//!
//! This module touches the cleartext body chunks but emits **no** event itself —
//! event construction (fingerprint-only [`crate::telemetry_http`]) is the caller's
//! job and is unit-tested there. Nothing here owns a log/event/spool sink; the
//! [`ScanProvenance`] a verdict carries is a fingerprint-free POL-3 triple +
//! plane, never a matched byte. The hold-back buffer holds cleartext only
//! transiently and releases or drops it; it is never serialized.
//!
//! # D40 pingora confinement / integration seam
//!
//! No pingora type appears here (doc 12 §13.1). The body-filter integration
//! ([`crate::transparent`] / `src/main.rs`, gated behind `DS_TLS3_LIVE` exactly as
//! the TLS-3 inspected path is) is the documented seam: `main.rs` reads the
//! cleartext chunk off the terminated stream, drives [`ScanGate::scan_chunk`], and
//! forwards only the bytes the gate returns as released — never weakening the
//! default (`DS_TLS3_LIVE` unset) opaque-tunnel path, which never reaches a
//! scanner (TLS-4 pass-through is a stated non-claim, doc 12 §5.3). That wiring is
//! a deferred unit (this is u1: the lib-side trait + verdict + hold-back core).

#![forbid(unsafe_code)]

use std::error::Error as StdError;
use std::fmt;

/// Which detection plane produced a verdict (D73 two-plane split, doc 12 §5.2).
///
/// The plane is load-bearing for fail-closed semantics: the keyed plane (exact
/// match on creds Identity minted or guards — near-zero false-positive rate)
/// mandates fail-closed on matcher error; the generic plane (pattern rules, 25–75%
/// precision) is capped at block+log and is the only plane an explicit policy bit
/// may run fail-open. Every non-[`Verdict::Pass`] verdict names its plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Plane {
    /// Exact-match against the Identity digest feed (mint-time / fleet-revocation).
    Keyed,
    /// Generic pattern rules from the policy layer (POL-4 push); capped block+log.
    Generic,
}

/// The POL-3 provenance a non-`Pass` verdict carries (D73 §5.1 — "rule id,
/// ruleset/digest-set version, policy layer, `plane = keyed | generic`").
///
/// This mirrors the boundary `Provenance{RuleID, PolicyLayer, PolicyVersion}` (and
/// the [`crate::telemetry_http::Provenance`] the emitted event carries) plus the
/// TLS-7-specific [`Plane`] discriminator D73 adds: `ruleset_version` fills the
/// `PolicyVersion` slot with the ruleset/digest-set version in force. It carries
/// **no** matched bytes and **no** fingerprint — never-log-the-secret is a
/// type-level property here (the only data is rule metadata + plane).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanProvenance {
    /// The matched rule / digest id.
    pub rule_id: String,
    /// The ruleset / digest-set version in force (the `PolicyVersion` slot).
    pub ruleset_version: String,
    /// The composing policy layer.
    pub policy_layer: String,
    /// Which plane produced the match (keyed | generic).
    pub plane: Plane,
}

impl ScanProvenance {
    /// Build a provenance quad from its parts (the values `main.rs` reads off the
    /// matched rule / digest-set the matcher returns).
    pub fn new(
        rule_id: impl Into<String>,
        ruleset_version: impl Into<String>,
        policy_layer: impl Into<String>,
        plane: Plane,
    ) -> ScanProvenance {
        ScanProvenance {
            rule_id: rule_id.into(),
            ruleset_version: ruleset_version.into(),
            policy_layer: policy_layer.into(),
            plane,
        }
    }
}

/// The direction-symmetric TLS-7 verdict (D73 §5.1), frozen at Stage-0 beside the
/// D22 seam (doc 14 §7 / doc 16 §9). Zero-copy in shape: every payload is either a
/// small count or the fingerprint-free [`ScanProvenance`] (no matched bytes ride
/// the verdict). The shape is direction-symmetric — the same verdict set serves
/// egress (request, v0) and ingress (response, the post-MVP follow-on); enabling
/// the second direction is policy, not a verdict-shape change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Release the first `release_n` held bytes upstream — they are clean. The
    /// matcher cleared a prefix; the proxy may forward exactly that many bytes from
    /// the front of the hold-back buffer. `release_n == 0` releases nothing this
    /// call (distinct from [`Verdict::Hold`], which also asks for more input).
    Pass {
        /// Count of leading hold-back bytes the matcher cleared for egress.
        release_n: usize,
    },
    /// Release nothing and await more input — a candidate may be mid-formation at
    /// the tail (a secret may span the chunk/record boundary). The proxy holds the
    /// buffer; the matcher needs the next chunk (or `end_of_stream`) to decide.
    Hold,
    /// Abort: the matched bytes must never egress; the agent sees an in-band
    /// refusal. Carries fingerprint-free POL-3 provenance (the matched value is
    /// never on the verdict — never-log-the-secret).
    Block(ScanProvenance),
    /// Pass the bytes through but emit a `PolicyDecision` event (generic-plane
    /// alert mode / keyed-flag rungs). Carries provenance; the bytes are NOT held.
    Flag(ScanProvenance),
    /// Reserved (D73): the schema slot is frozen, the redaction implementation is
    /// deferred. Carries provenance so the frozen shape is complete; constructing
    /// it is legal, acting on it is a later unit.
    Redact(ScanProvenance),
}

impl Verdict {
    /// `true` for the two terminal-no-release verdicts ([`Verdict::Hold`] and
    /// [`Verdict::Block`]) — the verdicts under which the proxy forwards **zero**
    /// new bytes this call. The fail-closed default collapses to one of these.
    pub fn releases_nothing(&self) -> bool {
        matches!(self, Verdict::Hold | Verdict::Block(_))
    }

    /// The POL-3 provenance a non-`Pass` verdict carries, if any. `Pass`/`Hold`
    /// carry none (a clean release / a request for more input cite no rule).
    pub fn provenance(&self) -> Option<&ScanProvenance> {
        match self {
            Verdict::Block(p) | Verdict::Flag(p) | Verdict::Redact(p) => Some(p),
            Verdict::Pass { .. } | Verdict::Hold => None,
        }
    }
}

/// The opaque per-stream scan context handed to [`SecretMatcher::scan`] (the
/// `ctx` of the frozen `scan(chunk, end_of_stream, ctx)` signature). It names the
/// session and direction so the matcher can scope carryover / digest lookups; it
/// is **read-only** to the matcher and carries no secret material. The rich
/// context (the per-session digest set, the loaded generic pack) is matcher-owned
/// state wired at construction — §9-Free — so `ctx` stays a thin, frozen handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanCtx {
    /// The scan direction. v0 enables [`Direction::Egress`] only; the verdict shape
    /// is direction-symmetric so [`Direction::Ingress`] is policy, not rework.
    pub direction: Direction,
}

impl ScanCtx {
    /// An egress-direction context (the v0 request-direction scan).
    pub fn egress() -> ScanCtx {
        ScanCtx {
            direction: Direction::Egress,
        }
    }

    /// An ingress-direction context (the post-MVP response-direction follow-on).
    pub fn ingress() -> ScanCtx {
        ScanCtx {
            direction: Direction::Ingress,
        }
    }
}

/// Scan direction (D73 — the matcher is direction-symmetric; v0 is egress only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Request direction — bytes the agent is sending to an allowed upstream (the
    /// secret-egress direction; the v0 enabled direction).
    Egress,
    /// Response direction — bytes entering the VM (the post-MVP follow-on).
    Ingress,
}

/// The error a [`SecretMatcher`] surfaces (engine failure, digest-load failure, a
/// caught panic the wiring converts). It is the input to the fail-closed decision:
/// while the keyed plane is loaded, ANY matcher error collapses to
/// [`Verdict::Hold`] (no byte released) — fail-open is generic-flag-only and an
/// explicit policy bit (doc 12 §13.5, D73). It carries a secret-free reason class
/// only (never a matched byte).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MatcherError {
    /// A secret-free reason class for the failure (for the fingerprint-only error
    /// event the caller emits; never a matched byte).
    pub reason: String,
}

impl MatcherError {
    /// Build a matcher error from a secret-free reason class.
    pub fn new(reason: impl Into<String>) -> MatcherError {
        MatcherError {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for MatcherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "secret-matcher error: {}", self.reason)
    }
}

impl StdError for MatcherError {}

/// The frozen TLS-7 matcher trait (D73 §5.1) — the pluggable detection engine.
///
/// The signature is frozen: `scan(chunk, end_of_stream, ctx) -> Verdict` (returned
/// as `Result<Verdict, MatcherError>` so the fail-closed-when-keyed contract has an
/// error channel to act on — a panic-free engine returns `Ok`, a failed engine
/// returns `Err` and [`ScanGate`] applies §13.5). The matcher **owns its carryover
/// state** across calls (`&mut self`); the proxy owns the hold-back invariant
/// ([`HoldBackBuffer`]). The engine choice (aho-corasick / Vectorscan / RegexSet /
/// exact-set vs Bloom-prefilter-plus-confirm), candidate extraction, content-type
/// scoping, and HMAC key rotation are all §9-Free.
pub trait SecretMatcher {
    /// Scan `chunk` (the next slice of cleartext body), with `end_of_stream` set on
    /// the final chunk so a tail candidate can be resolved, in the `ctx` scope.
    /// Returns the [`Verdict`] (release_n / hold / block / flag / redact) or a
    /// [`MatcherError`] the fail-closed gate acts on.
    fn scan(
        &mut self,
        chunk: &[u8],
        end_of_stream: bool,
        ctx: &ScanCtx,
    ) -> Result<Verdict, MatcherError>;
}

/// The fail-open posture (doc 12 §13.5, D73). The default is fail-CLOSED; fail-open
/// is permitted **only** for generic-flag-only configs and **must** be an explicit
/// policy bit (the Envoy ext_proc `failure_mode_allow` lesson).
///
/// u1 carries this as a placeholder so the fail-closed default is unconditional and
/// the fail-open seam is named — the policy-bit *schema* (which validates that a
/// fail-open config is genuinely generic-flag-only) is §9-Free / a later unit
/// (ACCEPTANCE: "schema not implemented in u1, placeholder").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailMode {
    /// Fail-closed (the mandatory default whenever the keyed plane is loaded): a
    /// matcher error releases NO byte (collapses to [`Verdict::Hold`]).
    Closed,
    /// Fail-open (generic-flag-only, explicit policy bit ONLY): a matcher error
    /// passes the chunk. Selecting this with the keyed plane loaded is rejected by
    /// [`ScanGate::new`] — fail-closed-when-keyed is mandatory.
    Open,
}

/// The proxy-owned scan gate: it owns the [`HoldBackBuffer`] (the hold-back
/// invariant) and the fail-closed-when-keyed decision, and drives a
/// [`SecretMatcher`] across a stream. This is the lib-side core `main.rs`/
/// `transparent.rs` wires onto the body-filter seam (deferred unit) — it is
/// itself pingora-free and `#![forbid(unsafe_code)]`-clean via the crate root.
///
/// Invariant: a byte enters [`HoldBackBuffer`] and leaves it ONLY when the matcher
/// returns a [`Verdict::Pass`] releasing it (or `end_of_stream` drains the cleared
/// remainder). On a matcher error under fail-closed, NO held byte is released.
pub struct ScanGate<M: SecretMatcher> {
    matcher: M,
    buffer: HoldBackBuffer,
    /// `true` when the keyed plane is loaded — forces fail-closed regardless of
    /// [`FailMode`] (the load-bearing fail-closed-when-keyed bit, D73).
    keyed_loaded: bool,
    fail_mode: FailMode,
}

impl<M: SecretMatcher> ScanGate<M> {
    /// Build a gate over `matcher` with a hold-back window sized to
    /// `max_secret_length` (the buffer retains up to `max_secret_length - 1`
    /// trailing bytes). `keyed_loaded` records whether the keyed plane is loaded;
    /// `fail_mode` is the configured posture.
    ///
    /// Enforces fail-closed-when-keyed at construction: selecting [`FailMode::Open`]
    /// while `keyed_loaded` is `true` is rejected (`Err`) — fail-open is
    /// generic-flag-only (D73, doc 12 §13.5). The generic-flag-only *schema* that
    /// would further validate an `Open` config is §9-Free (u1 placeholder).
    pub fn new(
        matcher: M,
        max_secret_length: usize,
        keyed_loaded: bool,
        fail_mode: FailMode,
    ) -> Result<ScanGate<M>, MatcherError> {
        if keyed_loaded && fail_mode == FailMode::Open {
            return Err(MatcherError::new(
                "fail-open rejected: keyed plane loaded mandates fail-closed (D73, doc 12 §13.5)",
            ));
        }
        Ok(ScanGate {
            matcher,
            buffer: HoldBackBuffer::new(max_secret_length),
            keyed_loaded,
            fail_mode,
        })
    }

    /// Whether this gate is operating fail-closed for THIS call's error handling.
    /// Always `true` when the keyed plane is loaded; otherwise follows [`FailMode`].
    fn fail_closed(&self) -> bool {
        self.keyed_loaded || self.fail_mode == FailMode::Closed
    }

    /// Feed the next cleartext `chunk` (with `end_of_stream` on the final chunk) and
    /// return the [`Verdict`] for the proxy to act on. The chunk is appended to the
    /// hold-back buffer first, so the matcher always sees the buffered tail joined
    /// to the new bytes — a secret spanning the chunk boundary is one contiguous
    /// view, never two halves scanned in isolation.
    ///
    /// Fail-closed (D73, doc 12 §13.5): a matcher `Err(_)` under [`Self::fail_closed`]
    /// collapses to [`Verdict::Hold`] — NO held byte is released. Under fail-open
    /// (generic-flag-only) a matcher error passes the chunk.
    pub fn scan_chunk(&mut self, chunk: &[u8], end_of_stream: bool, ctx: &ScanCtx) -> Verdict {
        self.buffer.append(chunk);
        match self
            .matcher
            .scan(self.buffer.scannable(), end_of_stream, ctx)
        {
            Ok(verdict) => verdict,
            Err(_err) => {
                if self.fail_closed() {
                    // Fail-closed: release nothing, hold every buffered byte. The
                    // caller emits the fingerprint-only error event off `_err`.
                    Verdict::Hold
                } else {
                    // Fail-open (generic-flag-only, explicit policy bit): pass the
                    // whole buffered remainder through.
                    Verdict::Pass {
                        release_n: self.buffer.len(),
                    }
                }
            }
        }
    }

    /// Release the first `n` held bytes for egress, draining them from the front of
    /// the hold-back buffer. The proxy calls this after a [`Verdict::Pass`] to take
    /// exactly the cleared bytes; the remainder stays held (the unscanned tail).
    /// `n` is clamped to the buffered length.
    pub fn take_released(&mut self, n: usize) -> Vec<u8> {
        self.buffer.drain_front(n)
    }

    /// Borrow the hold-back buffer (its `len` / `scannable` view) — for the proxy's
    /// release bookkeeping and for tests asserting no byte egressed prematurely.
    pub fn buffer(&self) -> &HoldBackBuffer {
        &self.buffer
    }
}

/// The proxy-owned hold-back buffer (D73 §5.1 — the hold-back invariant).
///
/// It retains up to `max_secret_length - 1` trailing bytes of the stream so a
/// secret straddling a chunk / TLS-record boundary is held until the matcher has
/// seen its whole span — never detected only after its prefix already egressed.
/// The buffer is the proxy's, not the matcher's: the matcher owns *candidate*
/// carryover; the buffer owns the *byte* hold-back the forwarding path obeys.
///
/// Holds cleartext transiently only — it is never serialized to any log / event /
/// spool (never-log-the-secret, D73). On drop the `Vec` frees normally; the buffer
/// carries no long-lived secret (a held secret is either blocked-and-dropped or
/// released-after-clearance, both prompt).
pub struct HoldBackBuffer {
    bytes: Vec<u8>,
    /// The hold-back window: retain up to `max_secret_length - 1` trailing bytes.
    /// Stored as the trailing-retain count (`max_secret_length - 1`); a
    /// `max_secret_length` of 0 or 1 retains nothing (no multi-byte secret can
    /// straddle a boundary).
    retain: usize,
}

impl HoldBackBuffer {
    /// A buffer whose hold-back window is `max_secret_length - 1` trailing bytes.
    /// `max_secret_length` of 0 or 1 means a zero-width window (saturating).
    pub fn new(max_secret_length: usize) -> HoldBackBuffer {
        HoldBackBuffer {
            bytes: Vec::new(),
            retain: max_secret_length.saturating_sub(1),
        }
    }

    /// The hold-back window size (`max_secret_length - 1`).
    pub fn retain_window(&self) -> usize {
        self.retain
    }

    /// Append the next cleartext chunk into the buffer (the new bytes join the
    /// retained tail so the matcher sees one contiguous span across the boundary).
    pub fn append(&mut self, chunk: &[u8]) {
        self.bytes.extend_from_slice(chunk);
    }

    /// The full buffered span the matcher scans (the retained tail + the new chunk).
    pub fn scannable(&self) -> &[u8] {
        &self.bytes
    }

    /// How many bytes are currently buffered.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// How many leading bytes are SAFE to release right now WITHOUT the matcher's
    /// verdict — i.e. everything except the trailing hold-back window. This is the
    /// floor the invariant guarantees: a multi-byte secret cannot straddle the
    /// boundary beyond `retain` trailing bytes, so any byte before that floor is
    /// not part of a boundary-straddling candidate. The matcher's [`Verdict::Pass`]
    /// `release_n` may release MORE than this (it cleared the tail too); this is the
    /// no-verdict-needed floor, never an upper bound.
    pub fn releasable_floor(&self) -> usize {
        self.bytes.len().saturating_sub(self.retain)
    }

    /// Drain (release) the first `n` bytes from the front of the buffer, returning
    /// them for egress. `n` is clamped to the buffered length. The retained tail
    /// stays held.
    pub fn drain_front(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.bytes.len());
        self.bytes.drain(..n).collect()
    }

    /// Drain the ENTIRE buffer (end-of-stream, after the final clearing verdict):
    /// the hold-back window no longer matters once the stream is complete and the
    /// matcher has cleared the remainder.
    pub fn drain_all(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

// ===========================================================================
// u2 — Digest-feed consumer: keyed + generic plane ingestion (lib-side)
// ===========================================================================
//
// This is the consumer half of the D73 two-plane split (doc 12 §5.2): the
// framework-agnostic library that ingests the FROZEN digest-feed proto (the
// keyed plane, Identity → Boundary seam — `proto/dreamserpent/identity/v1/
// digest_feed.proto`, doc 14 §7 / doc 16 §6.6) and the POL-4 generic pack (the
// generic plane — doc 16 §7, the gitleaks-compatible content-class ruleset of
// doc 14 §9) and feeds BOTH into a [`SecretMatcher`] the [`ScanGate`] drives.
//
// # The plaintext-never-crosses-the-seam contract is a TYPE-LEVEL property here
//
// The producer computes every digest INSIDE the D39 secret-store trust zone
// (doc 14 §7); only the HMAC key id + the truncated digest bytes + the variant
// tag cross. This consumer therefore ingests [`KeyedDigest`] values that carry
// the DIGEST bytes, never a plaintext — there is no field on [`KeyedDigest`],
// [`KeyedEntry`], or the [`DigestSetMatcher`] state that holds, or can be made
// to hold, a credential plaintext. The matcher confirms a candidate by HASHING
// the candidate (through the §9-Free [`DigestHasher`] seam) and comparing the
// result to the loaded digest set — it NEVER stores the candidate, and a
// [`Verdict`] carries only the fingerprint-free [`ScanProvenance`] (the
// candidate bytes are dropped the instant a window is scanned). This is the
// never-log-the-secret invariant realized as a type property: grep the public
// fields below and no plaintext slot exists.
//
// # Mint-before-attach (doc 14 §7 / doc 16 §6.1, D109)
//
// Session-scoped keyed digests MUST land — and the session be marked
// digests-ready — BEFORE the session's first egress byte. [`DigestSetMatcher`]
// encodes this as a load gate: a matcher whose keyed plane is loaded but for
// which the session has NOT been marked [`DigestSetMatcher::seal_keyed`] (the
// in-process twin of the orchestrator's "session not routable until acked"
// barrier) is in the PRE-SEAL state and `scan` fails closed (returns
// `Err(MatcherError)` → [`ScanGate`] Holds, no byte released). Only after
// `seal_keyed` — the consumer's ack-landed edge — does the keyed plane match.
// This makes attaching traffic to a session whose digests have not landed a
// fail-closed event, not a silent miss (the ordering invariant the proto's
// `DigestPublishResponse.committed` enforces, mirrored in-process).
//
// # Fail-closed-when-keyed propagates to the gate
//
// [`DigestSetMatcher::keyed_loaded`] reports whether the keyed plane is loaded
// so the caller wires it into [`ScanGate::new`] — keeping the load-bearing
// fail-closed-when-keyed bit (D73, doc 12 §13.5) sourced from the SAME state
// that decides whether keyed matching is live, never a second copy that could
// skew.

/// The keyed-hash family + truncation length a digest was computed under
/// (mirrors `digest_feed.proto` `DigestAlgo`). HMAC-SHA-256 is the only Stage-0
/// family; the truncation length is carried so the consumer truncates candidate
/// hashes IDENTICALLY before comparison (producer and matcher must agree, doc 14
/// §7 / doc 16 §6.3). This is metadata, never a key or a plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DigestAlgo {
    /// Keyed-hash family. v0 ships only HMAC-SHA-256; future families are
    /// additive (mirrors the proto enum being additive, never a retype).
    pub family: DigestFamily,
    /// Truncation length in bytes applied to the keyed hash before comparison.
    pub truncation_len_bytes: usize,
}

/// Keyed-hash family (mirrors `digest_feed.proto` `DigestAlgo.Family`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestFamily {
    /// HMAC-SHA-256 — the only Stage-0 family (doc 14 §7).
    HmacSha256,
}

/// The credential class a keyed digest belongs to (mirrors `digest_feed.proto`
/// `DigestCredClass`). `Issued{service_id}` egresses to its intended service
/// without flagging (the swap/scan interlock, doc 16 §10) and is a
/// wrong-destination event elsewhere; `Forbidden` must never egress in any
/// variant — a forbidden-class entry is the doc 06 (c) canary anchor (D73).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum CredClass {
    /// A credential Identity minted, tagged with its intended `service_id`.
    Issued {
        /// The registry `services[]` key this credential is intended for.
        service_id: String,
    },
    /// A credential Identity guards — must never egress (canary class).
    Forbidden,
}

/// Lifecycle scope of a keyed digest (mirrors `digest_feed.proto` `DigestScope`,
/// D72/D73). `Session` digests are session-lifecycle data, D72-exempt, carried
/// on the digest-feed RPC seam (mint-before-attach). `Fleet` digests are a
/// policy artifact under the `policy_log` seq, delivered through the POL-4 /
/// one-per-host subscriber (D72) — they ride the policy-snapshot subscription,
/// not the session seam, but share this entry shape so one matcher serves both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DigestScope {
    /// Session-lifecycle data, D72-exempt; the mint-before-attach path.
    Session,
    /// A policy artifact under `policy_log` seq, via the one-per-host subscriber.
    Fleet,
}

/// The encoding variant a single digest was computed over (mirrors
/// `digest_feed.proto` `DigestVariantTag`). The producer pushes every variant a
/// credential could appear in on the wire so the matcher catches a base64'd or
/// url-encoded secret as readily as the raw bytes (doc 14 §7). The matcher
/// applies the SAME transform to a candidate window before hashing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VariantTag {
    /// The credential's raw bytes.
    Raw,
    /// Standard base64 of the credential.
    Base64,
    /// URL-percent-encoding of the credential.
    UrlEnc,
    /// Lowercase hex of the credential.
    Hex,
}

/// One keyed-plane digest — the frozen `digest_feed.proto` `DigestEntry`'s
/// per-variant unit, lib-side. A credential pushed in N encodings yields N
/// [`KeyedDigest`] values sharing key_id / algo / cred_class / scope / expiry
/// and differing only in [`KeyedDigest::digest`] + [`KeyedDigest::variant_tag`].
///
/// CONTRACT: [`KeyedDigest::digest`] is the truncated HMAC output — a one-way
/// keyed hash — and is the ONLY credential-derived value on this type. There is
/// no plaintext field (plaintext-never-crosses-the-seam, doc 14 §7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyedDigest {
    /// Id of the HMAC key the digest was computed under (per-host per-epoch).
    /// Selects the matching key on the boundary; never the key material.
    pub key_id: String,
    /// Family + truncation length (must match the key the consumer hashes with).
    pub algo: DigestAlgo,
    /// The truncated HMAC digest bytes — the one credential-derived value.
    pub digest: Vec<u8>,
    /// ISSUED{service_id} | FORBIDDEN.
    pub cred_class: CredClass,
    /// SESSION (digest-feed seam) | FLEET (policy stream).
    pub scope: DigestScope,
    /// Absolute expiry as a unix-seconds tick (tracks the cred TTL; the matcher
    /// ages the entry out in lockstep). `None` = no expiry tracked in v0.
    pub expiry_unix_secs: Option<u64>,
    /// Which encoding the `digest` was computed over.
    pub variant_tag: VariantTag,
    /// The producer-assigned rule/digest id surfaced in [`ScanProvenance`] on a
    /// match (POL-3 `rule_id`). Distinct from `key_id` (which selects the HMAC
    /// key); this names the matched digest for provenance, never a secret byte.
    pub rule_id: String,
}

/// A batch of keyed digests for one session (mirrors `digest_feed.proto`
/// `DigestPublishRequest`): the session's full digest set landing in one publish
/// ahead of first egress. The `batch_id` correlates the publish with its ack;
/// `session_uuid` scopes the mint-before-attach ordering (it is NOT an
/// attribution key — the deliberate thin-local `DigestSessionRef`, doc 14 §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyedPublish {
    /// The session these entries are minted for (session scope).
    pub session_uuid: String,
    /// The entries to register.
    pub entries: Vec<KeyedDigest>,
    /// Producer-chosen id correlating this publish with its ack.
    pub batch_id: String,
    /// The digest-set version stamped into verdict provenance for these entries
    /// (the separate non-policy namespace, doc 14 §2 — NOT `policy_log` skew).
    pub digest_set_version: String,
}

/// One generic-plane content-class rule — the lib-side view of a POL-4 generic
/// pack entry (the gitleaks-compatible ruleset of doc 14 §9 / doc 16 §7). The
/// generic plane is pattern rules at 25–75% precision (D73) and is CAPPED at
/// block+log: a generic rule can never drive a suspend/kill rung (doc 14 §8
/// "schema forbids suspend/kill on generic rules"). `entropy` is present in the
/// gitleaks format but UNUSED in v0 (doc 14 §8 "entropy present, unused in v0").
///
/// The matcher applies `keywords` as a cheap prefilter (a chunk with no keyword
/// skips the rule), then the §9-Free regex confirm. v0 ships a literal-substring
/// confirm for `regex` (the real RegexSet/Vectorscan engine is §9-Free behind
/// the trait, doc 12 §13.1 OQ #5); the SHAPE — keyword prefilter then confirm —
/// is what u2 freezes, faithful to the gitleaks-compatible field set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenericRule {
    /// The rule id (gitleaks `id`) — surfaced as `rule_id` in provenance.
    pub id: String,
    /// The detection pattern (gitleaks `regex`). v0 confirms by literal
    /// substring; the real regex engine is §9-Free behind the trait.
    pub regex: String,
    /// Keyword prefilter (gitleaks `keywords`): a chunk lacking ALL keywords
    /// skips this rule entirely (the cheap pre-confirm gate). Empty = no
    /// prefilter (the rule is always confirm-evaluated).
    pub keywords: Vec<String>,
    /// The capture-group index whose match is the secret (gitleaks
    /// `secretGroup`) — carried for the §9-Free confirm engine; unused by the v0
    /// literal confirm but frozen so the format-compatibility pin holds.
    pub secret_group: u32,
    /// Per-rule allowlist substrings (gitleaks `allowlists`): a confirm whose
    /// matched span sits inside an allowlisted span is suppressed (a false
    /// positive the curated ruleset already knows about).
    pub allowlists: Vec<String>,
}

/// The POL-4 generic pack — a versioned set of [`GenericRule`]s delivered on the
/// policy-snapshot subscription (doc 14 §9, D72/D74). The `pack_version` is the
/// digest-set/ruleset version stamped into provenance for generic-plane matches
/// (the same separate non-policy namespace as the keyed `digest_set_version`).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct GenericPack {
    /// The rules in force.
    pub rules: Vec<GenericRule>,
    /// The pack/ruleset version stamped into generic-plane provenance.
    pub pack_version: String,
    /// The composing policy layer (POL-3 `policy_layer` for generic matches).
    pub policy_layer: String,
}

/// The §9-Free keyed-hash seam (doc 12 §13.1 OQ #5 / doc 16 §6.3): given a
/// candidate's bytes, produce the SAME truncated HMAC the producer computed in
/// the D39 trust zone, so a candidate digest is byte-comparable to a loaded
/// [`KeyedDigest::digest`]. The concrete engine (the real `ring::hmac` keyed on
/// the per-host key material, the HMAC key rotation cadence) is Boundary/Identity
/// wiring (doc 16 §6.3) — this trait is the inversion seam so [`DigestSetMatcher`]
/// stays stdlib-only, dependency-free, and `#![forbid(unsafe_code)]`-clean, and
/// so the consumer is unit-testable against a fake hasher that mirrors the fake
/// publisher's computation (u0 dependency). It is handed only candidate bytes and
/// the `key_id` + truncation length to use; it returns digest bytes, never the
/// input — so it cannot become a plaintext sink either.
pub trait DigestHasher {
    /// Compute the truncated keyed hash of `candidate` under the key named
    /// `key_id`, truncated to `truncation_len_bytes`. Returns `None` when the
    /// `key_id` is unknown to this hasher (a key the producer used under a
    /// rotation the consumer has not yet loaded — the caller treats that as
    /// no-match, never a panic).
    fn hash(&self, key_id: &str, candidate: &[u8], truncation_len_bytes: usize) -> Option<Vec<u8>>;
}

/// Apply a [`VariantTag`]'s encoding to `raw` — the canonical, single-source
/// implementation of the variant invariant producer and consumer MUST agree on
/// (doc 14 §7: the producer pushes one digest per encoding a credential could
/// appear in, computed over the ENCODED form; that encoded form is what appears
/// on the wire). A real producer integration / a real [`DigestHasher`] reuses
/// THIS function so the encodings can never skew between the two sides. v0 ships
/// the four Stage-0 variants with stdlib-only encoders (no new dependency). Note
/// the matcher does NOT call this at scan time — the wire already carries the
/// encoded bytes (see [`DigestSetMatcher::match_keyed`]); this is the producer-
/// side / candidate-derivation utility that defines each variant's bytes.
pub fn encode_variant(tag: VariantTag, raw: &[u8]) -> Vec<u8> {
    match tag {
        VariantTag::Raw => raw.to_vec(),
        VariantTag::Base64 => base64_standard(raw).into_bytes(),
        VariantTag::UrlEnc => url_percent_encode(raw).into_bytes(),
        VariantTag::Hex => hex_lower(raw).into_bytes(),
    }
}

/// Standard base64 (RFC 4648, with `=` padding), stdlib-only — the on-wire form
/// of a `Base64` variant. Used to encode a candidate window before hashing so it
/// matches a producer-pushed base64 variant digest.
pub fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// RFC 3986 url percent-encoding (unreserved bytes pass through; everything else
/// is `%XX`), stdlib-only — the on-wire form of a `UrlEnc` variant.
pub fn url_percent_encode(input: &[u8]) -> String {
    fn unreserved(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
    }
    let mut out = String::with_capacity(input.len());
    for &b in input {
        if unreserved(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(
                char::from_digit((b >> 4) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
            out.push(
                char::from_digit((b & 0xf) as u32, 16)
                    .unwrap()
                    .to_ascii_uppercase(),
            );
        }
    }
    out
}

/// Lowercase hex, stdlib-only — the on-wire form of a `Hex` variant.
pub fn hex_lower(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    out
}

/// Whether `hay` contains `needle` as a contiguous sub-slice (the literal-confirm
/// primitive the generic plane uses in v0; the real engine is §9-Free).
fn contains_subslice(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Match a `span` against a [`GenericPack`] (keyword prefilter → literal confirm →
/// allowlist suppression) and, on the first non-suppressed hit, return the
/// fingerprint-free [`ScanProvenance`] (`plane = Generic`, the pack's
/// `pack_version`/`policy_layer`, the matched rule id). `None` on no match.
///
/// This is the SINGLE generic-plane match implementation — both the inline
/// [`DigestSetMatcher::match_generic`] scan path and the u2 hot-reload sweep's
/// re-evaluation of in-flight streams against a NEW pack call it, so a rule that
/// matches in the scan path is exactly the rule the re-evaluation reports (no
/// second, skewable copy of the keyword/confirm/allowlist logic). The generic
/// plane is CAPPED at block+log (doc 14 §8): the caller wraps the provenance in
/// [`Verdict::Block`] (inline) or a policy-decision event (sweep) — never a
/// suspend/kill rung.
#[must_use]
pub fn match_generic_pack(pack: &GenericPack, span: &[u8]) -> Option<ScanProvenance> {
    for rule in &pack.rules {
        // Keyword prefilter: if the rule names keywords and the span contains
        // NONE of them, skip the (expensive) confirm entirely.
        if !rule.keywords.is_empty()
            && !rule
                .keywords
                .iter()
                .any(|k| contains_subslice(span, k.as_bytes()))
        {
            continue;
        }
        // Confirm (v0 literal substring; §9-Free engine swaps in here).
        let pat = rule.regex.as_bytes();
        if pat.is_empty() || !contains_subslice(span, pat) {
            continue;
        }
        // Allowlist suppression: a matched span inside an allowlisted substring is
        // a known false positive (gitleaks `allowlists`).
        let suppressed = rule
            .allowlists
            .iter()
            .any(|a| !a.is_empty() && contains_subslice(span, a.as_bytes()));
        if suppressed {
            continue;
        }
        return Some(ScanProvenance::new(
            rule.id.clone(),
            pack.pack_version.clone(),
            pack.policy_layer.clone(),
            Plane::Generic,
        ));
    }
    None
}

/// The two-plane digest-feed consumer + matcher (D73) — the lib-side engine that
/// ingests the keyed plane (digest-feed proto) and the generic plane (POL-4 pack)
/// and implements [`SecretMatcher`] over both. It carries ONLY fingerprints
/// (digest bytes + rule metadata) and the §9-Free [`DigestHasher`] seam — never a
/// plaintext (the never-log-the-secret type property, doc 14 §7).
///
/// Match precedence on a chunk (egress direction, v0): the KEYED plane is checked
/// first (exact-match, near-zero FP, the only plane inline-block + D53-rung
/// verdicts trust); on a keyed hit it returns the keyed verdict (default
/// [`Verdict::Block`] for the forbidden / wrong-destination case) carrying
/// `plane = keyed`. The generic plane is checked next; a generic hit is CAPPED at
/// block+log and carries `plane = generic`. No match → `Pass` up to the hold-back
/// floor (the trailing window is held for the next chunk so a boundary-straddling
/// secret is never released early — the u1 invariant the gate enforces).
pub struct DigestSetMatcher<H: DigestHasher> {
    hasher: H,
    /// The loaded keyed digests, grouped so a candidate is hashed once per
    /// distinct (key_id, algo, variant) and compared to the matching digests.
    keyed: Vec<KeyedEntry>,
    /// The digest-set version stamped into keyed-plane provenance.
    keyed_set_version: String,
    /// The composing policy layer for keyed-plane provenance.
    keyed_policy_layer: String,
    /// `true` once a keyed publish has been ingested (the keyed plane is loaded).
    keyed_present: bool,
    /// The mint-before-attach barrier: `false` until [`Self::seal_keyed`] marks
    /// the session digests-ready (the in-process ack-landed edge). While the
    /// keyed plane is present but UNSEALED, `scan` fails closed.
    keyed_sealed: bool,
    /// The session this matcher's session-scoped keyed digests belong to, set when
    /// the orchestrator's `hostagent.v1` session-lifecycle channel ingests them at
    /// connection time ([`Self::ingest_session_lifecycle`]). `None` until that
    /// connection-time ingestion runs; it scopes the mint-before-attach ordering
    /// and is the key [`Self::flush_session`] clears at NFT-6 teardown. It is NOT
    /// an attribution key (the deliberate thin-local `DigestSessionRef`, doc 14 §4)
    /// — only a lifecycle scope label, never a secret.
    session_uuid: Option<String>,
    /// The loaded generic pack (POL-4 plane).
    generic: GenericPack,
    /// The hold-back window the matcher releases up to on a clean chunk: retain
    /// `max_candidate_len - 1` trailing bytes so a boundary-straddling candidate
    /// is held for the next chunk (mirrors the [`HoldBackBuffer`] floor; the gate
    /// owns the byte hold-back, the matcher owns the release-point on a Pass).
    retain: usize,
    /// The default verdict an ISSUED wrong-destination / FORBIDDEN keyed hit
    /// produces (D53 rung). v0 default: [`KeyedHitAction::Block`].
    keyed_hit_action: KeyedHitAction,
}

/// What a keyed-plane hit does (the D53 response rung, Identity-assigned). v0
/// defaults to `Block`; `Flag` is the alert-mode rung. Suspend/kill rungs are
/// Identity-owned and out of u2's lib-side scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyedHitAction {
    /// Abort: matched bytes never egress, agent sees an in-band refusal.
    Block,
    /// Pass + PolicyDecision event (alert mode).
    Flag,
}

/// One loaded keyed digest, indexed for matching. Holds the digest bytes (a
/// fingerprint) + the metadata needed to hash a candidate comparably (`key_id` +
/// `truncation_len_bytes`) and to build provenance (`rule_id`) — never a
/// plaintext. The `variant_tag` is NOT retained here: the matcher hashes wire
/// windows AS-IS (the wire already carries the encoded form), so the variant is
/// descriptive metadata on the public [`KeyedDigest`], not match-time state.
struct KeyedEntry {
    key_id: String,
    truncation_len_bytes: usize,
    digest: Vec<u8>,
    rule_id: String,
    #[allow(dead_code)] // carried for the D53 ISSUED-wrong-destination rung wiring (later unit).
    cred_class: CredClass,
}

impl<H: DigestHasher> DigestSetMatcher<H> {
    /// Build an empty matcher over `hasher` with a hold-back release window of
    /// `max_candidate_len - 1` trailing bytes (the same floor the [`HoldBackBuffer`]
    /// retains). No plane is loaded yet — `scan` Passes everything (the gate's
    /// hold-back still applies) until a plane is ingested.
    pub fn new(hasher: H, max_candidate_len: usize) -> DigestSetMatcher<H> {
        DigestSetMatcher {
            hasher,
            keyed: Vec::new(),
            keyed_set_version: String::new(),
            keyed_policy_layer: "identity-keyed".to_string(),
            keyed_present: false,
            keyed_sealed: false,
            session_uuid: None,
            generic: GenericPack::default(),
            retain: max_candidate_len.saturating_sub(1),
            keyed_hit_action: KeyedHitAction::Block,
        }
    }

    /// Set the D53 keyed-hit action (default [`KeyedHitAction::Block`]).
    pub fn with_keyed_hit_action(mut self, action: KeyedHitAction) -> Self {
        self.keyed_hit_action = action;
        self
    }

    /// Ingest a keyed publish (the digest-feed proto `DigestPublishRequest`,
    /// lib-side) — the keyed plane load. This marks the keyed plane PRESENT but
    /// NOT yet sealed: per mint-before-attach, the matcher must not match keyed
    /// digests until [`Self::seal_keyed`] records the ack-landed edge. Calling
    /// this with the keyed plane already sealed re-opens the seal (a re-publish
    /// re-runs the barrier), so a mid-session rotation can never silently match
    /// against a half-loaded set.
    pub fn ingest_keyed(&mut self, publish: &KeyedPublish) {
        for e in &publish.entries {
            self.keyed.push(KeyedEntry {
                key_id: e.key_id.clone(),
                truncation_len_bytes: e.algo.truncation_len_bytes,
                digest: e.digest.clone(),
                rule_id: e.rule_id.clone(),
                cred_class: e.cred_class.clone(),
            });
        }
        if !publish.digest_set_version.is_empty() {
            self.keyed_set_version = publish.digest_set_version.clone();
        }
        self.keyed_present = true;
        // Mint-before-attach: a fresh publish is unsealed until acked.
        self.keyed_sealed = false;
    }

    /// Record the mint-before-attach ack-landed edge: the session's keyed digests
    /// are now host-visible and matchable (the in-process twin of
    /// `DigestPublishResponse.committed == true` → session marked routable, doc 16
    /// §6.1). Until this is called, [`Self::scan`] fails closed on a loaded keyed
    /// plane. No-op (idempotent) if no keyed plane is present.
    pub fn seal_keyed(&mut self) {
        if self.keyed_present {
            self.keyed_sealed = true;
        }
    }

    /// Ingest the session's keyed digests as they arrive on the orchestrator's
    /// `hostagent.v1` SESSION-LIFECYCLE channel at connection time (doc 12 §6;
    /// doc 16 §6.1, D109) — the session-scoped front door distinct from the
    /// generic [`Self::ingest_keyed`] feed-consumer entry.
    ///
    /// Session-scoped digests are session-lifecycle DATA, exempt from the D72
    /// policy distribution topology (doc 12 §6): they ride the per-session
    /// lifecycle channel, not the one-per-host policy-snapshot subscription, and
    /// MUST land before the session's first egress byte (mint-before-attach). This
    /// method binds the matcher to `publish.session_uuid` and ingests ONLY the
    /// [`DigestScope::Session`] entries — a [`DigestScope::Fleet`] entry is a
    /// policy artifact under `policy_log` (doc 12 §5.2) and belongs on the policy
    /// path ([`Self::ingest_keyed`]), so this lifecycle door drops it (a session
    /// channel must not be a back door for fleet/policy digests).
    ///
    /// Like [`Self::ingest_keyed`] this marks the keyed plane PRESENT but UNSEALED:
    /// [`Self::scan`] fails closed until [`Self::seal_keyed`] records the
    /// ack-landed edge (the in-process twin of `DigestPublishResponse.committed`).
    /// Re-ingesting on the SAME bound session is the mid-session rotation case and
    /// re-opens the seal; a DIFFERENT `session_uuid` re-binds the matcher and
    /// drops the prior session's session-scoped entries first (a session's digests
    /// never leak into the next — NFT-6 hygiene applies on re-bind as on teardown).
    pub fn ingest_session_lifecycle(&mut self, publish: &KeyedPublish) {
        // Re-bind: a different session clears the prior session's scoped state so a
        // stale session's digests can never match against the new connection.
        if self.session_uuid.as_deref() != Some(publish.session_uuid.as_str()) {
            self.clear_session_scoped();
        }
        self.session_uuid = Some(publish.session_uuid.clone());

        let mut ingested_any = false;
        for e in &publish.entries {
            // The lifecycle channel carries ONLY session-scoped digests; a
            // fleet/policy entry arriving here is not this door's to load.
            if e.scope != DigestScope::Session {
                continue;
            }
            self.keyed.push(KeyedEntry {
                key_id: e.key_id.clone(),
                truncation_len_bytes: e.algo.truncation_len_bytes,
                digest: e.digest.clone(),
                rule_id: e.rule_id.clone(),
                cred_class: e.cred_class.clone(),
            });
            ingested_any = true;
        }
        if !publish.digest_set_version.is_empty() {
            self.keyed_set_version = publish.digest_set_version.clone();
        }
        // Binding a session and landing its keyed digests marks the keyed plane
        // PRESENT — even if `entries` was empty of session-scoped digests, a bound
        // session enforces mint-before-attach (an attached-but-undigested session
        // fails closed, never a silent miss). The keyed plane is present once a
        // session is bound; it is unsealed until acked.
        let _ = ingested_any;
        self.keyed_present = true;
        // Mint-before-attach: a fresh session publish is unsealed until acked.
        self.keyed_sealed = false;
    }

    /// The session this matcher's session-scoped keyed digests are bound to (set by
    /// [`Self::ingest_session_lifecycle`]), or `None` if no session-lifecycle
    /// ingestion has run. A lifecycle scope label only — never an attribution key,
    /// never a secret (doc 14 §4).
    pub fn bound_session(&self) -> Option<&str> {
        self.session_uuid.as_deref()
    }

    /// Flush all session-scoped state at NFT-6 session-end teardown (doc 12 §6 /
    /// §8) — the session's keyed digests are dropped and the mint-before-attach
    /// barrier resets so the matcher cannot match a torn-down session's digests
    /// against any later byte. After this the keyed plane is no longer present (a
    /// scan Passes through, the gate's hold-back still applying) until a fresh
    /// session's digests are ingested. This is the NFT-6 hygiene the spec freezes:
    /// session-scoped entries are flushed at teardown, leaving no residue.
    pub fn flush_session(&mut self) {
        self.clear_session_scoped();
        self.session_uuid = None;
    }

    /// Drop the session-scoped keyed digests + reset the keyed plane present/seal
    /// bits (the shared body of [`Self::flush_session`] and the re-bind path of
    /// [`Self::ingest_session_lifecycle`]). The generic plane (a policy artifact,
    /// not session-scoped) is untouched.
    fn clear_session_scoped(&mut self) {
        self.keyed.clear();
        self.keyed_present = false;
        self.keyed_sealed = false;
    }

    /// Scan `chunk` returning a [`Verdict`] directly, mapping the mint-before-attach
    /// barrier to [`Verdict::Hold`] at the matcher level: while the keyed plane is
    /// loaded but the session is not yet sealed, EVERY scan returns
    /// [`Verdict::Hold`] (no byte released) rather than surfacing the
    /// [`MatcherError`] [`Self::scan`] raises for the [`ScanGate`] to convert. This
    /// is the convenience the connection-time mint-before-attach gate uses when it
    /// drives the matcher without a [`ScanGate`] in front: a loaded-but-unsealed
    /// session fails closed as a `Hold` on any scan, exactly as the gate would
    /// render it (doc 12 §13.5; the gate-driven path is unchanged — `scan`'s `Err`
    /// channel still feeds [`ScanGate::scan_chunk`]). On a sealed (or no-keyed)
    /// matcher this is identical to `scan(...).unwrap_or(Hold)`.
    pub fn scan_or_hold(&mut self, chunk: &[u8], end_of_stream: bool, ctx: &ScanCtx) -> Verdict {
        match self.scan(chunk, end_of_stream, ctx) {
            Ok(v) => v,
            // The only `Err` this matcher raises is the mint-before-attach
            // fail-closed; render it as the gate would — Hold, no byte released.
            Err(_) => Verdict::Hold,
        }
    }

    /// Ingest the POL-4 generic pack (the generic plane — the policy-snapshot
    /// subscription, doc 14 §9). Replaces the current pack wholesale (a snapshot
    /// is a full document; the two-phase apply is the snapshot loader's job).
    pub fn ingest_generic(&mut self, pack: GenericPack) {
        self.generic = pack;
    }

    /// Whether the keyed plane is loaded (PRESENT — regardless of seal state).
    /// The caller wires this into [`ScanGate::new`] for the fail-closed-when-keyed
    /// bit (D73, doc 12 §13.5), sourced from the SAME state that decides keyed
    /// matching so the two can never skew.
    pub fn keyed_loaded(&self) -> bool {
        self.keyed_present
    }

    /// Whether the keyed plane is loaded AND sealed (mint-before-attach satisfied)
    /// — i.e. keyed matching is live. `false` while pre-seal (the fail-closed
    /// window) or when no keyed plane is loaded.
    pub fn keyed_live(&self) -> bool {
        self.keyed_present && self.keyed_sealed
    }

    /// Whether any generic-plane rule is loaded.
    pub fn generic_loaded(&self) -> bool {
        !self.generic.rules.is_empty()
    }

    /// The longest secret length the loaded planes could match — the basis for
    /// the [`ScanGate`]'s `max_secret_length` hold-back window so a candidate
    /// straddling a chunk boundary is never released early. Keyed entries carry
    /// only digests (the plaintext length is not on the wire), so this reflects
    /// the configured `max_candidate_len` (the `retain + 1` the matcher was built
    /// with); the caller sizes the gate to the larger of this and any generic
    /// regex span it knows.
    pub fn max_candidate_len(&self) -> usize {
        self.retain + 1
    }

    /// Check the keyed plane against the scannable span. Returns the keyed verdict
    /// on the first hit (exact-match over every loaded variant), or `None`.
    /// Pre-seal (mint-before-attach unsatisfied) this is NEVER reached — `scan`
    /// fails closed before consulting it.
    ///
    /// Matching model (the variant invariant, doc 14 §7): the producer computed
    /// each entry's `digest` over the credential ALREADY ENCODED in `variant_tag`
    /// (`hash(encode_variant(secret))`), and that encoded form is exactly what
    /// appears on the wire when the agent egresses the secret in that encoding. So
    /// a wire candidate window is compared by hashing it AS-IS — the matcher does
    /// NOT re-encode (the wire already carries the encoded bytes; re-encoding would
    /// double-apply the transform). `variant_tag` is therefore descriptive
    /// metadata of which encoding an entry's digest covers; the per-variant digests
    /// are what make a base64'd / url-encoded / hex secret match as readily as the
    /// raw bytes, since the producer pushed one entry per variant.
    fn match_keyed(&self, span: &[u8]) -> Option<Verdict> {
        let span_len = span.len();
        // A keyed secret is bounded by the configured candidate window; bound the
        // window scan to that so the cost is linear in the span. The candidate
        // length is the LENGTH OF THE ENCODED form the producer hashed (= the
        // on-wire length), which for non-Raw variants is longer than the raw secret
        // — so the window bound is the on-wire bound the gate's hold-back is sized
        // to (`max_candidate_len`), not a raw-secret bound. Both `max_candidate_len`
        // and `span_len` are loop-invariant across the entries, so compute the
        // window bound ONCE here rather than re-deriving it per keyed entry.
        let max_w = self.max_candidate_len().min(span_len);
        for entry in &self.keyed {
            // Try every window length up to max_w; short-circuit on the first hit.
            for wlen in 1..=max_w {
                for start in 0..=(span_len - wlen) {
                    // Hash the wire window AS-IS — the producer's digest is over the
                    // already-encoded form, which is what is on the wire.
                    let window = &span[start..start + wlen];
                    if let Some(cand) =
                        self.hasher
                            .hash(&entry.key_id, window, entry.truncation_len_bytes)
                    {
                        if cand == entry.digest {
                            let prov = ScanProvenance::new(
                                entry.rule_id.clone(),
                                self.keyed_set_version.clone(),
                                self.keyed_policy_layer.clone(),
                                Plane::Keyed,
                            );
                            return Some(match self.keyed_hit_action {
                                KeyedHitAction::Block => Verdict::Block(prov),
                                KeyedHitAction::Flag => Verdict::Flag(prov),
                            });
                        }
                    }
                }
            }
        }
        None
    }

    /// Check the generic plane against the scannable span: keyword prefilter then
    /// literal confirm (the real regex engine is §9-Free). Generic hits are capped
    /// at block+log; a hit inside an allowlisted span is suppressed. Returns the
    /// first non-suppressed hit's verdict, or `None`. Delegates to the free
    /// [`match_generic_pack`] so the SAME match logic serves the inline scan path
    /// and the u2 hot-reload sweep's in-flight re-evaluation against a NEW pack.
    fn match_generic(&self, span: &[u8]) -> Option<Verdict> {
        match_generic_pack(&self.generic, span).map(Verdict::Block)
    }

    /// How many leading bytes of `span` are safe to release on a clean chunk:
    /// everything except the trailing hold-back window (the matcher's release
    /// point; the gate enforces the byte hold-back). At end-of-stream the whole
    /// span is releasable.
    fn clean_release_n(&self, span_len: usize, end_of_stream: bool) -> usize {
        if end_of_stream {
            span_len
        } else {
            span_len.saturating_sub(self.retain)
        }
    }
}

impl<H: DigestHasher> SecretMatcher for DigestSetMatcher<H> {
    fn scan(
        &mut self,
        chunk: &[u8],
        end_of_stream: bool,
        _ctx: &ScanCtx,
    ) -> Result<Verdict, MatcherError> {
        // Mint-before-attach fail-closed: the keyed plane is loaded but the
        // session has not been sealed (acked) → no byte may match-or-pass against
        // a half-attached set. Surface an error so the gate Holds (fail-closed),
        // never a silent miss.
        if self.keyed_present && !self.keyed_sealed {
            return Err(MatcherError::new(
                "keyed plane loaded but session not sealed (mint-before-attach unsatisfied)",
            ));
        }

        // Keyed plane FIRST (exact-match, the inline-block-trusted plane).
        if self.keyed_live() {
            if let Some(v) = self.match_keyed(chunk) {
                return Ok(v);
            }
        }
        // Generic plane next (capped at block+log).
        if self.generic_loaded() {
            if let Some(v) = self.match_generic(chunk) {
                return Ok(v);
            }
        }
        // Clean: release up to the hold-back floor (hold the trailing window for
        // the next chunk so a boundary-straddling candidate is never released
        // early), or everything at end-of-stream.
        Ok(Verdict::Pass {
            release_n: self.clean_release_n(chunk.len(), end_of_stream),
        })
    }
}

// ===========================================================================
// u2 — generic-pack HOT-RELOAD consumer: the live-swappable pack slot + the
// post-commit in-flight re-evaluation the D72 apply barrier drives (doc 12
// §5.2 / §13.5, D72/D73 — "the generic pack rides the POL-4 live push,
// fleet-wide within seconds, no proxy restart").
// ===========================================================================
//
// D73 gives the generic plane its OWN release-free cadence (doc 12 §108-row):
// a POL-4 generic-pack update lands fleet-wide within seconds, with no
// `ds-tlsproxy` build or restart. The keyed plane is session-lifecycle data
// (mint-before-attach, [`DigestSetMatcher::ingest_session_lifecycle`]); the
// generic plane is a POLICY ARTIFACT under the `policy_log` seq and therefore
// rides the D72 two-phase apply barrier (`crate::apply`). This is the
// pingora-free lib-side substrate that barrier consumes:
//
// - [`SharedGenericPack`] — the ONE live, hot-swappable pack slot every in-flight
//   stream's matcher reads through. The apply barrier's `commit` pointer-swaps a
//   new `Arc<GenericPack>` in atomically; an in-flight scan reads whichever whole
//   pack it observes (never a torn pack), exactly mirroring `apply.rs`'s
//   evaluator pointer-swap for the egress-connect plane.
// - [`InFlightStreams`] — the registry of currently-open inspected streams' tail
//   buffers the sweep re-evaluates against the new ruleset. A stream registers its
//   id + scannable tail; the post-commit sweep re-runs [`match_generic_pack`] over
//   each tail and emits a policy-decision event for any stream a NEWLY-added or
//   NEWLY-changed generic rule now matches (a rule that already matched under the
//   old pack is not re-reported — only the delta).
// - [`GenericReloadEvent`] — the fingerprint-free policy-decision the sweep emits
//   per newly-matched in-flight stream (the stream id + the [`ScanProvenance`]
//   quad). NEVER carries a matched byte (never-log-the-secret, D73): only the
//   stream's lifecycle-scope id + rule metadata + plane cross.
//
// FROZEN here (the spec's "Frozen" column): the generic plane is POL-4
// live-push; every emitted decision names its plane (`Generic`); a generic-plane
// hit defaults to block+log per the D53 schema freeze (no suspend/kill on
// generic — `match_generic_pack` only ever yields a `Plane::Generic` provenance
// the caller caps at block+log). FREE (the spec's "Free" column): whether the
// sweep re-evaluates ALL in-flight or only new-arriving streams — this impl
// re-evaluates every registered in-flight stream's tail (the stronger guarantee:
// an already-open exfil stream is caught by a freshly-pushed rule, not only
// newly-arriving connections); and the generic-rule engine itself (§9-Free, the
// v0 literal-confirm of [`match_generic_pack`]).

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// The ONE live, hot-swappable generic-pack slot the inspected path reads through
/// (doc 12 §5.2, D72/D73). The apply barrier's commit pointer-swaps a new
/// `Arc<GenericPack>` in with a single `RwLock` write; an in-flight scan that
/// already cloned the old `Arc` keeps deciding on the WHOLE old pack, and every
/// scan that begins after the swap reads the WHOLE new pack — never a torn pack
/// (the exact mirror of `apply.rs`'s egress-evaluator pointer-swap, doc 13 §5).
///
/// `Clone` is a cheap `Arc` bump: the proxy hands one handle to each in-flight
/// stream's matcher and keeps one on the apply consumer; all observe the same
/// slot, so a single commit reloads every stream's view at once (fleet-wide-within
/// -a-process; the host fan-out makes it fleet-wide-within-seconds, doc 12 §108).
#[derive(Clone)]
pub struct SharedGenericPack {
    slot: Arc<RwLock<Arc<GenericPack>>>,
}

impl SharedGenericPack {
    /// A shared slot serving an initial pack (the proxy's first composed snapshot's
    /// generic pack, or [`GenericPack::default`] before the first POL-4 push — an
    /// empty pack matches nothing, so the inspected path stays byte-clean).
    #[must_use]
    pub fn new(initial: GenericPack) -> SharedGenericPack {
        SharedGenericPack {
            slot: Arc::new(RwLock::new(Arc::new(initial))),
        }
    }

    /// The pack currently in force — a clone of the `Arc`, so the caller holds the
    /// whole pack without keeping the `RwLock` read guard across a scan (a
    /// concurrent hot-swap cannot tear the pack out from under an in-flight scan).
    #[must_use]
    pub fn current(&self) -> Arc<GenericPack> {
        Arc::clone(&self.slot.read().expect("generic-pack slot lock poisoned"))
    }

    /// Atomically hot-swap the live pack to `pack` (the apply barrier's commit
    /// step). One `RwLock` write swaps the `Arc`; the write guard is dropped before
    /// this returns, so every scan that begins after observes the new pack — the
    /// generic plane is reloaded with no proxy restart (doc 12 §108, D73).
    pub fn hot_swap(&self, pack: GenericPack) {
        *self.slot.write().expect("generic-pack slot lock poisoned") = Arc::new(pack);
    }

    /// The live pack's version (the `pack_version` stamped into generic-plane
    /// provenance) — for the apply barrier's idempotence / audit, never a secret.
    #[must_use]
    pub fn version(&self) -> String {
        self.current().pack_version.clone()
    }
}

/// A fingerprint-free policy-decision the post-commit sweep emits when a freshly
/// hot-swapped generic pack matches an ALREADY-OPEN in-flight stream (doc 12 §5.1
/// `Flag` / `PolicyDecision` event; D73). It names the stream's lifecycle-scope id
/// and the [`ScanProvenance`] quad (rule id, ruleset version, policy layer,
/// `plane = Generic`) — and NOTHING ELSE: never a matched byte, never a buffer
/// slice (never-log-the-secret is a type-level property here, exactly as on
/// [`ScanProvenance`]). The caller ships it through the same telemetry channel a
/// live [`Verdict::Flag`] would, so a rule pushed mid-stream is observable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenericReloadEvent {
    /// The in-flight stream the newly-pushed generic rule matched. A lifecycle
    /// correlation id (the proxy's `dstap-<idx>` / session-scope handle), never an
    /// attribution key and never a secret (doc 14 §4).
    pub stream_id: String,
    /// The fingerprint-free generic-plane provenance (`plane = Generic`, the new
    /// pack's version + layer + the matched rule id).
    pub provenance: ScanProvenance,
}

/// The registry of currently-open inspected streams the post-commit sweep
/// re-evaluates against a freshly hot-swapped generic pack (doc 12 §5.2, D72/D73).
///
/// On a generic-pack hot-reload the D72 sweep (post-commit, BEFORE `applied_seq`
/// advances) re-runs the new ruleset over every open stream's buffered tail so an
/// exfiltration ALREADY IN FLIGHT is caught by a rule pushed seconds ago — not
/// only by the next new connection. Each entry holds the stream's lifecycle id and
/// the LAST scannable tail its matcher saw (the hold-back-bounded window — a few
/// hundred bytes, never the whole body, so the registry is O(streams · max-secret)
/// not O(bytes)). The tail is cleartext held only as transiently as the
/// [`HoldBackBuffer`] holds it; the registry is never serialized (never-log-the-
/// secret, D73).
///
/// "Re-evaluate ALL in-flight" is the §9-Free choice this impl makes (the stronger
/// guarantee). The dedup is keyed on the matched rule id: a stream a rule ALREADY
/// matched under the old pack is not re-reported — only the delta the new pack
/// introduces fires a fresh policy-decision event.
#[derive(Default)]
pub struct InFlightStreams {
    /// stream id → (its current scannable tail, the rule ids it has already been
    /// reported for, so a re-evaluation only fires on the delta).
    streams: BTreeMap<String, InFlightEntry>,
}

/// One registered in-flight stream's re-evaluation state.
struct InFlightEntry {
    /// The stream's last scannable tail (hold-back-bounded; never the whole body).
    tail: Vec<u8>,
    /// Rule ids this stream has already emitted a policy-decision event for, so the
    /// sweep reports only NEWLY-matching rules (the delta), never a re-fire.
    reported_rule_ids: std::collections::BTreeSet<String>,
}

impl InFlightStreams {
    /// An empty registry (no inspected stream open yet).
    #[must_use]
    pub fn new() -> InFlightStreams {
        InFlightStreams::default()
    }

    /// Register (or update) an open stream's current scannable tail. The proxy
    /// calls this as each chunk is scanned so the registry always holds the latest
    /// hold-back-bounded window for a possible mid-stream re-evaluation. Replacing
    /// the tail preserves the stream's already-reported rule-id set (a re-push must
    /// not re-fire a rule that already matched this stream).
    pub fn upsert(&mut self, stream_id: impl Into<String>, tail: &[u8]) {
        let stream_id = stream_id.into();
        match self.streams.get_mut(&stream_id) {
            Some(entry) => {
                entry.tail.clear();
                entry.tail.extend_from_slice(tail);
            }
            None => {
                self.streams.insert(
                    stream_id,
                    InFlightEntry {
                        tail: tail.to_vec(),
                        reported_rule_ids: std::collections::BTreeSet::new(),
                    },
                );
            }
        }
    }

    /// Drop a stream from the registry at its teardown (NFT-6 / flow close) — an
    /// already-closed stream is not re-evaluated, and its transient tail is freed.
    pub fn remove(&mut self, stream_id: &str) {
        self.streams.remove(stream_id);
    }

    /// How many streams are currently registered (open + inspected).
    #[must_use]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    /// Re-evaluate every registered in-flight stream's tail against `pack` (the
    /// just-committed generic pack) and return one [`GenericReloadEvent`] per stream
    /// a NEWLY-matching generic rule now hits — the post-commit sweep step (doc 12
    /// §5.2, D72: runs after `commit`, BEFORE `applied_seq` advances). A stream a
    /// rule already matched under the prior pack is NOT re-reported (the
    /// `reported_rule_ids` dedup) — only the delta the hot-reload introduces fires.
    ///
    /// Generic-plane hits are capped at block+log per the D53 schema freeze; this
    /// sweep emits a policy-decision (the `Flag`/`PolicyDecision` event shape) for
    /// the in-flight catch — it does not retroactively sever the stream (severing
    /// is the rung-conditional revocation sweep's job, `crate::sweep`; a generic
    /// rule never drives suspend/kill). The events are returned for the caller to
    /// ship through the telemetry channel; the registry records each fired rule id
    /// so a subsequent re-evaluation under an unchanged rule does not re-fire.
    #[must_use]
    pub fn reevaluate_against(&mut self, pack: &GenericPack) -> Vec<GenericReloadEvent> {
        let mut events = Vec::new();
        for (stream_id, entry) in self.streams.iter_mut() {
            if let Some(prov) = match_generic_pack(pack, &entry.tail) {
                // Only the DELTA: a rule this stream already fired for is not
                // re-reported (an unchanged rule re-matching is not a new decision).
                if entry.reported_rule_ids.insert(prov.rule_id.clone()) {
                    events.push(GenericReloadEvent {
                        stream_id: stream_id.clone(),
                        provenance: prov,
                    });
                }
            }
        }
        events
    }
}

// ===========================================================================
// u3 — Body-filter hook driver: the per-chunk request-direction (egress)
// state machine `main.rs` wires onto the Pingora body-filter seam.
// ===========================================================================
//
// D73 places the TLS-7 scan as a body-filter on the inspected (TLS-3-terminated)
// path (doc 12 §5.1). The Pingora body-filter is called per cleartext chunk; the
// pingora type stays in `main.rs` (D40 confinement, doc 12 §13.1). This module
// adds the pingora-FREE half of that hook: a [`RequestScanFilter`] that wraps the
// proxy-owned [`ScanGate`] and turns each chunk into a [`BodyFilterAction`] the
// caller acts on — forward N bytes, hold (cease forwarding), block (close; matched
// bytes never egress), or flag (forward + fire a PolicyDecision event). v0 is
// egress-only (doc 12 §10 done-when correction): the response direction has a
// schema slot ([`ScanCtx::ingress`]) but no driver here yet.
//
// The hold-back invariant lives entirely in the gate: this driver NEVER hands the
// caller a byte the matcher did not release. On [`Verdict::Block`] it drops the
// whole buffer (the matched bytes are dropped, never forwarded — never-log-the-
// secret + matched-bytes-never-egress, D73). On [`Verdict::Hold`] it forwards
// nothing (the trailing candidate is mid-formation). On [`Verdict::Pass`] it takes
// exactly the released prefix and resumes forwarding.

/// What the proxy does with a body chunk after the scan gate verdicts it — the
/// per-chunk output of [`RequestScanFilter::on_request_chunk`]. It is the
/// pingora-free instruction `main.rs`'s body-filter hook executes against the
/// terminated downstream / re-originated upstream sockets.
///
/// Never-log-the-secret (D73): `Forward`/`Flag` carry only bytes the matcher
/// RELEASED (cleared as clean); `Block`/`Flag` carry the fingerprint-free
/// [`ScanProvenance`] (rule metadata + plane), never a matched byte. `Block` and
/// `Hold` carry no released bytes (matched bytes never egress; a held candidate
/// stays buffered).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BodyFilterAction {
    /// Forward exactly these released bytes upstream and continue reading the body.
    /// May be empty (a clean chunk whose every byte fell inside the hold-back
    /// window — nothing is releasable yet, but the stream is not blocked).
    Forward(Vec<u8>),
    /// Forward nothing this chunk and continue reading: a candidate may be
    /// mid-formation at the buffered tail (a secret spanning the chunk/record
    /// boundary). The proxy ceases forwarding until a later chunk releases.
    Hold,
    /// Abort the stream: a secret matched. The matched bytes are dropped (never
    /// forwarded); the caller closes the upstream and answers the agent with an
    /// in-band refusal. Carries fingerprint-free provenance for the event.
    Block(ScanProvenance),
    /// Forward the released bytes AND fire a `PolicyDecision` event (alert mode):
    /// the bytes pass, but the match is recorded (fingerprint-only). Carries the
    /// provenance for the event alongside the released bytes.
    Flag {
        /// The released (clean) bytes to forward upstream.
        released: Vec<u8>,
        /// The fingerprint-free provenance for the PolicyDecision event.
        provenance: ScanProvenance,
    },
}

impl BodyFilterAction {
    /// The bytes this action releases upstream (empty for `Hold`/`Block`). The
    /// caller forwards exactly these; a recording test upstream counts exactly
    /// these as delivered.
    pub fn released_bytes(&self) -> &[u8] {
        match self {
            BodyFilterAction::Forward(b) => b,
            BodyFilterAction::Flag { released, .. } => released,
            BodyFilterAction::Hold | BodyFilterAction::Block(_) => &[],
        }
    }

    /// `true` if this action aborts the stream ([`BodyFilterAction::Block`]).
    pub fn is_block(&self) -> bool {
        matches!(self, BodyFilterAction::Block(_))
    }

    /// The provenance this action carries, if any ([`BodyFilterAction::Block`] /
    /// [`BodyFilterAction::Flag`]).
    pub fn provenance(&self) -> Option<&ScanProvenance> {
        match self {
            BodyFilterAction::Block(p) | BodyFilterAction::Flag { provenance: p, .. } => Some(p),
            BodyFilterAction::Forward(_) | BodyFilterAction::Hold => None,
        }
    }
}

/// The request-direction (egress, v0) body-filter hook: it wraps the proxy-owned
/// [`ScanGate`] and drives the hold-back state machine across body chunks, turning
/// each chunk into a [`BodyFilterAction`]. This is the pingora-free core `main.rs`'s
/// body-filter hook calls per chunk on the inspected path (the gate is itself
/// pingora-free; D40 keeps the pingora `Stream` in the bin).
///
/// Lifecycle: [`Self::on_request_chunk`] per chunk (with `end_of_stream` on the
/// final chunk). Once a [`BodyFilterAction::Block`] is returned the filter latches
/// CLOSED — every subsequent call returns `Block` again and never releases a byte
/// (the stream is aborting; a late chunk must not sneak a byte past a fired block).
pub struct RequestScanFilter<M: SecretMatcher> {
    gate: ScanGate<M>,
    /// The scan context (egress in v0). Frozen at construction; the ingress
    /// direction is a later unit (schema slot only).
    ctx: ScanCtx,
    /// Latches `Some(prov)` after the first `Block` so a post-block chunk can never
    /// release a byte (the aborting stream stays aborted).
    blocked: Option<ScanProvenance>,
}

impl<M: SecretMatcher> RequestScanFilter<M> {
    /// Wrap `gate` as the egress (request-direction, v0) body filter.
    pub fn egress(gate: ScanGate<M>) -> RequestScanFilter<M> {
        RequestScanFilter {
            gate,
            ctx: ScanCtx::egress(),
            blocked: None,
        }
    }

    /// Feed the next request body `chunk` (with `end_of_stream` on the final chunk)
    /// and return the [`BodyFilterAction`] for the proxy's body-filter hook to act
    /// on. The chunk is driven through the [`ScanGate`] (append → matcher scan →
    /// verdict); the verdict is translated to the action:
    ///
    /// - [`Verdict::Pass`]`{release_n}` → take exactly `release_n` released bytes
    ///   from the front of the hold-back buffer and [`BodyFilterAction::Forward`]
    ///   them (resume forwarding).
    /// - [`Verdict::Hold`] → [`BodyFilterAction::Hold`]: forward nothing, the tail
    ///   candidate is mid-formation.
    /// - [`Verdict::Block`] → [`BodyFilterAction::Block`]: drop the WHOLE buffer
    ///   (the matched bytes never egress) and latch closed.
    /// - [`Verdict::Flag`] → [`BodyFilterAction::Flag`]: the generic-plane alert
    ///   rung — release the buffered bytes (the match passes) and carry the
    ///   provenance so the caller fires a PolicyDecision event.
    /// - [`Verdict::Redact`] → reserved (D73): the redaction implementation is
    ///   deferred; treated as `Hold` (release nothing) so the schema slot is honored
    ///   without leaking an unredacted byte.
    ///
    /// Once latched closed (a prior `Block`), every call returns `Block` and
    /// releases nothing — the aborting stream stays aborted.
    pub fn on_request_chunk(&mut self, chunk: &[u8], end_of_stream: bool) -> BodyFilterAction {
        // Latched closed: a prior Block aborts the whole stream — no late chunk may
        // release a byte (matched bytes never egress, D73).
        if let Some(prov) = &self.blocked {
            return BodyFilterAction::Block(prov.clone());
        }

        match self.gate.scan_chunk(chunk, end_of_stream, &self.ctx) {
            Verdict::Pass { release_n } => {
                let released = self.gate.take_released(release_n);
                BodyFilterAction::Forward(released)
            }
            Verdict::Hold => BodyFilterAction::Hold,
            Verdict::Block(prov) => {
                // Matched bytes never egress: drop the entire hold-back buffer and
                // latch closed. We do NOT take_released — nothing leaves the gate.
                self.blocked = Some(prov.clone());
                BodyFilterAction::Block(prov)
            }
            Verdict::Flag(prov) => {
                // Alert mode: the bytes pass (generic-plane block+log alert rung is
                // a Block; Flag is the pass+log rung). Release the cleared prefix up
                // to the hold-back floor so the stream keeps moving; carry the
                // provenance so the caller fires the PolicyDecision event.
                let release_n = self.gate.buffer().releasable_floor();
                let released = self.gate.take_released(release_n);
                BodyFilterAction::Flag {
                    released,
                    provenance: prov,
                }
            }
            Verdict::Redact(_prov) => {
                // Reserved (D73): redaction is deferred. Hold (release nothing) so an
                // unredacted byte never egresses while the slot is unimplemented.
                BodyFilterAction::Hold
            }
        }
    }

    /// Whether the filter has latched closed on a fired [`Verdict::Block`].
    pub fn is_blocked(&self) -> bool {
        self.blocked.is_some()
    }

    /// Borrow the underlying gate's hold-back buffer (for the caller's release
    /// bookkeeping and for tests asserting no byte egressed prematurely).
    pub fn buffer(&self) -> &HoldBackBuffer {
        self.gate.buffer()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- A fake matcher driving the gate deterministically -------------------

    /// A scripted matcher: it returns a queue of verdicts (one per `scan` call),
    /// or — if a `needle` is set — Blocks the first time the needle appears in the
    /// scannable span and otherwise releases everything except the hold-back tail.
    /// It owns carryover state ONLY in that it sees the buffer the gate feeds it;
    /// this is enough to prove the hold-back invariant end to end without baking a
    /// real engine into u1 (the engine is §9-Free).
    struct FakeMatcher {
        scripted: Vec<Result<Verdict, MatcherError>>,
        needle: Option<Vec<u8>>,
        prov: ScanProvenance,
        retain: usize,
        calls: usize,
    }

    impl FakeMatcher {
        fn scripted(verdicts: Vec<Result<Verdict, MatcherError>>) -> FakeMatcher {
            FakeMatcher {
                scripted: verdicts,
                needle: None,
                prov: prov_keyed(),
                retain: 0,
                calls: 0,
            }
        }

        /// A matcher that Blocks on `needle` and otherwise releases up to the
        /// hold-back floor (`len - retain`), holding the rest for the next chunk.
        fn needle(needle: &[u8], retain: usize) -> FakeMatcher {
            FakeMatcher {
                scripted: Vec::new(),
                needle: Some(needle.to_vec()),
                prov: prov_keyed(),
                retain,
                calls: 0,
            }
        }
    }

    impl SecretMatcher for FakeMatcher {
        fn scan(
            &mut self,
            chunk: &[u8],
            end_of_stream: bool,
            _ctx: &ScanCtx,
        ) -> Result<Verdict, MatcherError> {
            self.calls += 1;
            if let Some(needle) = &self.needle {
                if windows_contains(chunk, needle) {
                    return Ok(Verdict::Block(self.prov.clone()));
                }
                // No match: release everything except the trailing hold-back window
                // (so a candidate straddling the next boundary is never released
                // early), or the whole thing at end-of-stream.
                let release_n = if end_of_stream {
                    chunk.len()
                } else {
                    chunk.len().saturating_sub(self.retain)
                };
                return Ok(Verdict::Pass { release_n });
            }
            self.scripted.remove(0)
        }
    }

    fn windows_contains(hay: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > hay.len() {
            return needle.is_empty();
        }
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn prov_keyed() -> ScanProvenance {
        ScanProvenance::new(
            "rule-canary-1",
            "digest-set-7",
            "identity-keyed",
            Plane::Keyed,
        )
    }

    // ---- SecretMatcher trait compiles + verdict round-trips ------------------

    #[test]
    fn secret_matcher_trait_object_is_callable() {
        // The frozen trait compiles and is usable as a trait object (object-safe).
        let mut m: Box<dyn SecretMatcher> =
            Box::new(FakeMatcher::scripted(vec![Ok(Verdict::Pass {
                release_n: 3,
            })]));
        let v = m.scan(b"abc", true, &ScanCtx::egress()).unwrap();
        assert_eq!(v, Verdict::Pass { release_n: 3 });
    }

    #[test]
    fn verdict_enum_round_trips_through_clone_and_eq() {
        let prov = prov_keyed();
        let cases = vec![
            Verdict::Pass { release_n: 0 },
            Verdict::Pass { release_n: 42 },
            Verdict::Hold,
            Verdict::Block(prov.clone()),
            Verdict::Flag(prov.clone()),
            Verdict::Redact(prov.clone()),
        ];
        for v in &cases {
            // Clone + Eq round-trip (the frozen shape is value-comparable).
            assert_eq!(v.clone(), *v);
        }
        // Provenance is attached on every non-Pass/Hold verdict and absent on the
        // others (Pass/Hold cite no rule).
        assert!(Verdict::Pass { release_n: 1 }.provenance().is_none());
        assert!(Verdict::Hold.provenance().is_none());
        assert_eq!(Verdict::Block(prov.clone()).provenance(), Some(&prov));
        assert_eq!(Verdict::Flag(prov.clone()).provenance(), Some(&prov));
        assert_eq!(Verdict::Redact(prov.clone()).provenance(), Some(&prov));
        // The plane discriminator round-trips on the provenance.
        assert_eq!(
            Verdict::Block(prov).provenance().unwrap().plane,
            Plane::Keyed
        );
    }

    #[test]
    fn verdict_releases_nothing_classifies_hold_and_block() {
        assert!(Verdict::Hold.releases_nothing());
        assert!(Verdict::Block(prov_keyed()).releases_nothing());
        assert!(!Verdict::Pass { release_n: 0 }.releases_nothing());
        assert!(!Verdict::Pass { release_n: 5 }.releases_nothing());
        assert!(!Verdict::Flag(prov_keyed()).releases_nothing());
    }

    // ---- Hold-back buffer retains max_secret_length-1 trailing bytes ----------

    #[test]
    fn holdback_retain_window_is_max_secret_length_minus_one() {
        assert_eq!(HoldBackBuffer::new(40).retain_window(), 39);
        // Saturating at the small end: 0 and 1 retain nothing.
        assert_eq!(HoldBackBuffer::new(1).retain_window(), 0);
        assert_eq!(HoldBackBuffer::new(0).retain_window(), 0);
    }

    #[test]
    fn holdback_releasable_floor_holds_back_exactly_the_window() {
        let mut buf = HoldBackBuffer::new(8); // retain 7 trailing bytes
        buf.append(b"0123456789"); // 10 bytes buffered
                                   // 10 - 7 = 3 leading bytes are releasable without a verdict.
        assert_eq!(buf.releasable_floor(), 3);
        // Below the window, nothing is releasable without a verdict.
        let mut small = HoldBackBuffer::new(8);
        small.append(b"012"); // 3 < 7
        assert_eq!(small.releasable_floor(), 0);
    }

    #[test]
    fn holdback_drain_front_releases_and_retains_tail() {
        let mut buf = HoldBackBuffer::new(4); // retain 3
        buf.append(b"HELLOWORLD"); // 10 bytes
        let released = buf.drain_front(7);
        assert_eq!(released, b"HELLOWO");
        assert_eq!(buf.scannable(), b"RLD"); // the retained tail stays held
        assert_eq!(buf.len(), 3);
        // Over-draining clamps.
        let rest = buf.drain_front(100);
        assert_eq!(rest, b"RLD");
        assert!(buf.is_empty());
    }

    // ---- Fail-closed trait error returns Hold (keyed plane) -------------------

    #[test]
    fn fail_closed_matcher_error_returns_hold_no_byte_released() {
        // Keyed plane loaded → fail-closed mandatory.
        let m = FakeMatcher::scripted(vec![Err(MatcherError::new("engine-oom"))]);
        let mut gate = ScanGate::new(m, 40, /*keyed_loaded=*/ true, FailMode::Closed).unwrap();
        let v = gate.scan_chunk(b"the secret may span here", false, &ScanCtx::egress());
        assert_eq!(
            v,
            Verdict::Hold,
            "matcher error under keyed plane must Hold"
        );
        // No byte was released: the whole chunk is still held.
        assert_eq!(gate.buffer().len(), b"the secret may span here".len());
        // And the proxy releases nothing on a Hold.
        assert!(v.releases_nothing());
    }

    #[test]
    fn keyed_plane_forces_fail_closed_even_if_failmode_open_requested() {
        // ScanGate::new REJECTS Open while keyed is loaded (fail-closed-when-keyed
        // is mandatory; fail-open is generic-flag-only, D73 / doc 12 §13.5).
        let m = FakeMatcher::scripted(vec![]);
        match ScanGate::new(m, 40, /*keyed_loaded=*/ true, FailMode::Open) {
            Err(err) => assert!(err.reason.contains("fail-open rejected")),
            Ok(_) => panic!("keyed plane + FailMode::Open must be rejected at construction"),
        }
    }

    // ---- Generic flag-only fail-open permitted via explicit policy bit --------
    //      (the policy-bit SCHEMA is a u1 placeholder per ACCEPTANCE).

    #[test]
    fn generic_flag_only_fail_open_passes_on_matcher_error() {
        // Generic plane (keyed NOT loaded) + explicit FailMode::Open → on a matcher
        // error the chunk passes (fail-open). This is the ONLY configuration the
        // §13.5 lesson permits to fail-open.
        let m = FakeMatcher::scripted(vec![Err(MatcherError::new("regex-timeout"))]);
        let mut gate = ScanGate::new(m, 40, /*keyed_loaded=*/ false, FailMode::Open).unwrap();
        let v = gate.scan_chunk(b"near-miss content", false, &ScanCtx::egress());
        assert_eq!(
            v,
            Verdict::Pass {
                release_n: b"near-miss content".len()
            },
            "generic flag-only fail-open passes the chunk on matcher error"
        );
    }

    #[test]
    fn generic_plane_default_is_still_fail_closed_without_the_open_bit() {
        // Generic plane but the explicit fail-open bit was NOT set → default
        // fail-closed (Hold) on a matcher error.
        let m = FakeMatcher::scripted(vec![Err(MatcherError::new("regex-timeout"))]);
        let mut gate = ScanGate::new(m, 40, /*keyed_loaded=*/ false, FailMode::Closed).unwrap();
        let v = gate.scan_chunk(b"near-miss content", false, &ScanCtx::egress());
        assert_eq!(v, Verdict::Hold);
    }

    // ---- Secret spanning two chunks: buffered, NO egress until release --------

    #[test]
    fn secret_spanning_two_chunks_is_buffered_and_blocked_before_any_egress() {
        // The canary, split across a chunk boundary: "CANARY" = "CAN" + "ARY".
        let canary = b"CANARY";
        let retain = canary.len() - 1; // hold back up to max_secret_length-1
        let m = FakeMatcher::needle(canary, retain);
        // max_secret_length = canary length so the window = canary.len()-1.
        let mut gate = ScanGate::new(
            m,
            canary.len(),
            /*keyed_loaded=*/ true,
            FailMode::Closed,
        )
        .unwrap();

        // Chunk 1 ends with the secret's PREFIX "...CAN". With the hold-back
        // window, that prefix stays buffered — it must NOT egress before chunk 2
        // reveals the full secret.
        let chunk1 = b"prefix data CAN";
        let v1 = gate.scan_chunk(chunk1, false, &ScanCtx::egress());
        // The matcher saw no full needle yet, so it Passes up to the floor.
        let release1 = match v1 {
            Verdict::Pass { release_n } => release_n,
            other => panic!("chunk 1 verdict = {other:?}, want Pass"),
        };
        let egress1 = gate.take_released(release1);
        // The "CAN" prefix must be within the still-held tail — zero secret bytes
        // egressed.
        assert!(
            !windows_contains(&egress1, b"CAN"),
            "the secret prefix must NOT egress on chunk 1; egressed = {egress1:?}"
        );
        // The held tail still contains the prefix waiting for the rest.
        assert!(windows_contains(gate.buffer().scannable(), b"CAN"));

        // Chunk 2 supplies "ARY..." completing "CANARY" across the boundary.
        let chunk2 = b"ARY more data";
        let v2 = gate.scan_chunk(chunk2, true, &ScanCtx::egress());
        // Now the full canary is visible in the joined buffer → Block.
        assert!(
            matches!(v2, Verdict::Block(_)),
            "the boundary-spanning secret must Block once joined; got {v2:?}"
        );
        // Block releases nothing.
        assert!(v2.releases_nothing());
        // The full secret is still in the buffer and NEVER egressed: the only bytes
        // that ever left are egress1, which we proved carry no "CAN".
        assert!(windows_contains(gate.buffer().scannable(), canary));
    }

    #[test]
    fn clean_stream_releases_everything_at_end_of_stream() {
        // A clean stream (no needle): bytes flow out, all of them by end-of-stream.
        let m = FakeMatcher::needle(b"CANARY", 5);
        let mut gate = ScanGate::new(m, 6, true, FailMode::Closed).unwrap();
        let mut egressed = Vec::new();

        let v1 = gate.scan_chunk(b"hello ", false, &ScanCtx::egress());
        if let Verdict::Pass { release_n } = v1 {
            egressed.extend(gate.take_released(release_n));
        } else {
            panic!("clean chunk 1 should Pass: {v1:?}");
        }

        let v2 = gate.scan_chunk(b"world", true, &ScanCtx::egress());
        if let Verdict::Pass { release_n } = v2 {
            egressed.extend(gate.take_released(release_n));
        } else {
            panic!("clean final chunk should Pass: {v2:?}");
        }
        // At end-of-stream every clean byte has egressed.
        assert_eq!(egressed, b"hello world");
        assert!(gate.buffer().is_empty());
    }

    // =======================================================================
    // u2 — Digest-feed consumer tests (keyed + generic plane)
    // =======================================================================

    /// The fake digest publisher + hasher (the u0 fake-publisher mirror): a
    /// deterministic keyed hash standing in for the real `ring::hmac` engine the
    /// producer computes in the D39 trust zone. The PRODUCER and the CONSUMER's
    /// [`DigestHasher`] use the SAME function, so a candidate the consumer hashes
    /// matches the digest the producer pushed — exactly the §9-Free seam contract.
    /// It is keyed (the `key_id` mixes into the hash) and truncating, mirroring
    /// HMAC-SHA-256 + truncation without pulling a crypto dependency into the lib.
    struct FakeHasher;

    /// The SHARED keyed-hash both the fake producer and the consumer use. A
    /// deterministic FNV-1a mix over (key_id ++ candidate) — NOT a real MAC (it is
    /// test scaffolding for the §9-Free seam), but it has the one property the
    /// matcher's correctness depends on: EVERY input byte avalanches into EVERY
    /// truncated output byte (so `hash("CANA") != hash("CANARYSPAN")` regardless of
    /// truncation length — a single rolling FNV state, re-mixed per output byte,
    /// never a lane-partition that drops late bytes). Key-dependent + truncating, so
    /// key selection, truncation agreement, and per-variant digests are all
    /// exercised honestly.
    fn fake_keyed_hash(key_id: &str, candidate: &[u8], truncation_len_bytes: usize) -> Vec<u8> {
        // One rolling FNV-1a state over the whole input (every byte mixed in).
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in key_id.as_bytes().iter().chain(candidate.iter()) {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        // Expand to the requested length by re-mixing the final state per byte, so
        // a longer truncation reveals more avalanche of the SAME full-input state
        // (every output byte still depends on every input byte).
        let mut out = Vec::with_capacity(truncation_len_bytes);
        let mut s = h;
        for _ in 0..truncation_len_bytes {
            s ^= s >> 33;
            s = s.wrapping_mul(0xff51afd7ed558ccd);
            s ^= s >> 33;
            out.push((s & 0xff) as u8);
        }
        out
    }

    impl DigestHasher for FakeHasher {
        fn hash(
            &self,
            key_id: &str,
            candidate: &[u8],
            truncation_len_bytes: usize,
        ) -> Option<Vec<u8>> {
            // The fake knows the single test key id; an unknown key → no match.
            if key_id == TEST_KEY_ID {
                Some(fake_keyed_hash(key_id, candidate, truncation_len_bytes))
            } else {
                None
            }
        }
    }

    const TEST_KEY_ID: &str = "host-7-epoch-3";
    const TRUNC: usize = 16;

    /// A fake-publisher: compute the keyed digest of `secret` under `variant` the
    /// SAME way the consumer's hasher will (encode then keyed-hash + truncate),
    /// and wrap it as a [`KeyedDigest`]. This is the u0 fake digest publisher: it
    /// produces ONLY the digest, never the plaintext (mirroring "plaintext never
    /// crosses the seam").
    fn publish_digest(
        secret: &[u8],
        variant: VariantTag,
        cred_class: CredClass,
        rule_id: &str,
    ) -> KeyedDigest {
        let encoded = encode_variant(variant, secret);
        let digest = fake_keyed_hash(TEST_KEY_ID, &encoded, TRUNC);
        KeyedDigest {
            key_id: TEST_KEY_ID.to_string(),
            algo: DigestAlgo {
                family: DigestFamily::HmacSha256,
                truncation_len_bytes: TRUNC,
            },
            digest,
            cred_class,
            scope: DigestScope::Session,
            expiry_unix_secs: Some(1_900_000_000),
            variant_tag: variant,
            rule_id: rule_id.to_string(),
        }
    }

    /// Assert that none of the candidate secret's bytes appear in ANY field of a
    /// verdict / its provenance (the never-log-the-secret type property). We
    /// stringify the whole verdict (Debug) and grep for the secret bytes.
    fn assert_no_secret_in_verdict(v: &Verdict, secret: &[u8]) {
        let dbg = format!("{v:?}");
        assert!(
            !contains_subslice(dbg.as_bytes(), secret),
            "secret bytes leaked into the verdict Debug: {dbg}"
        );
        if let Some(p) = v.provenance() {
            // Every provenance string field is rule metadata, never a secret.
            for field in [&p.rule_id, &p.ruleset_version, &p.policy_layer] {
                assert!(
                    !contains_subslice(field.as_bytes(), secret),
                    "secret bytes leaked into provenance field: {field}"
                );
            }
        }
    }

    // ---- mint-before-attach ordering: pre-seal fails closed ------------------

    #[test]
    fn keyed_plane_pre_seal_fails_closed_then_matches_after_seal() {
        // Ingest a fake keyed set but do NOT seal (the session has not acked).
        let secret = b"ghp_canaryTOKEN0001";
        let entry = publish_digest(secret, VariantTag::Raw, CredClass::Forbidden, "canary-1");
        let publish = KeyedPublish {
            session_uuid: "sess-abc".to_string(),
            entries: vec![entry],
            batch_id: "batch-1".to_string(),
            digest_set_version: "ds-v7".to_string(),
        };
        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        m.ingest_keyed(&publish);
        // Keyed plane is loaded (the gate's fail-closed bit is on)...
        assert!(m.keyed_loaded());
        // ...but NOT live (mint-before-attach unsatisfied).
        assert!(!m.keyed_live());

        // Scanning pre-seal fails CLOSED: the matcher errors, the gate Holds.
        let err = m.scan(secret, true, &ScanCtx::egress());
        assert!(
            err.is_err(),
            "pre-seal scan must fail closed (mint-before-attach), got {err:?}"
        );

        // Now the session acks → seal. Mint-before-attach satisfied.
        m.seal_keyed();
        assert!(m.keyed_live());

        // The same canary now BLOCKS, plane = keyed, rule_id present.
        let v = m.scan(secret, true, &ScanCtx::egress()).unwrap();
        match &v {
            Verdict::Block(p) => {
                assert_eq!(p.plane, Plane::Keyed);
                assert_eq!(p.rule_id, "canary-1");
                assert_eq!(p.ruleset_version, "ds-v7");
            }
            other => panic!("sealed canary must Block(plane=keyed); got {other:?}"),
        }
        // Zero plaintext bytes on the verdict.
        assert_no_secret_in_verdict(&v, secret);
    }

    // ---- session-lifecycle ingestion: mint-before-attach Holds on ANY scan ----
    //      then transitions to normal matching after seal_keyed() (4JY5-u1).

    #[test]
    fn session_lifecycle_ingest_holds_on_any_scan_until_sealed() {
        // The orchestrator's hostagent.v1 session-lifecycle channel lands the
        // session's keyed digests at connection time. Until the ack-landed seal,
        // EVERY scan fails closed — rendered as Verdict::Hold at the matcher level.
        let secret = b"ghp_sessionCANARY007";
        let entry = publish_digest(secret, VariantTag::Raw, CredClass::Forbidden, "sess-canary");
        let publish = KeyedPublish {
            session_uuid: "sess-lifecycle-1".to_string(),
            entries: vec![entry],
            batch_id: "batch-1".to_string(),
            digest_set_version: "ds-sess-v1".to_string(),
        };
        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        m.ingest_session_lifecycle(&publish);

        // The matcher is bound to the session and the keyed plane is loaded...
        assert_eq!(m.bound_session(), Some("sess-lifecycle-1"));
        assert!(m.keyed_loaded(), "session ingestion loads the keyed plane");
        // ...but NOT live (mint-before-attach unsatisfied: no ack/seal yet).
        assert!(!m.keyed_live());

        // ANY scan pre-seal returns Hold (no byte released) — even a clean,
        // non-matching chunk, and even at end-of-stream. Mint-before-attach is
        // unconditional: an attached-but-unsealed session releases nothing.
        assert_eq!(
            m.scan_or_hold(b"perfectly ordinary body", false, &ScanCtx::egress()),
            Verdict::Hold,
            "clean chunk pre-seal still Holds (mint-before-attach)"
        );
        assert_eq!(
            m.scan_or_hold(secret, true, &ScanCtx::egress()),
            Verdict::Hold,
            "the canary pre-seal Holds (no match-or-release against a half-attached set)"
        );
        // The underlying scan() still surfaces the Err for the ScanGate path.
        assert!(m.scan(secret, false, &ScanCtx::egress()).is_err());

        // The session acks → seal. Mint-before-attach satisfied; normal matching.
        m.seal_keyed();
        assert!(m.keyed_live());

        // A clean chunk now Passes (normal matching resumes)...
        assert!(matches!(
            m.scan_or_hold(b"perfectly ordinary body", true, &ScanCtx::egress()),
            Verdict::Pass { .. }
        ));
        // ...and the canary BLOCKS, plane = keyed, correct rule metadata.
        let v = m.scan_or_hold(secret, true, &ScanCtx::egress());
        match &v {
            Verdict::Block(p) => {
                assert_eq!(p.plane, Plane::Keyed, "hit carries plane=Keyed");
                assert_eq!(p.rule_id, "sess-canary", "correct rule id");
                assert_eq!(
                    p.ruleset_version, "ds-sess-v1",
                    "correct digest-set version"
                );
            }
            other => panic!("sealed session canary must Block(plane=keyed); got {other:?}"),
        }
        assert_no_secret_in_verdict(&v, secret);
    }

    #[test]
    fn session_lifecycle_ingest_drops_fleet_scoped_entries() {
        // The session-lifecycle door is for SESSION-scoped digests only; a
        // Fleet-scoped entry is a policy artifact (the one-per-host policy path,
        // ingest_keyed) and must not load through the session channel.
        let sess_secret = b"session-tok-AAA";
        let fleet_secret = b"fleet-tok-BBB";
        let mut sess_entry = publish_digest(
            sess_secret,
            VariantTag::Raw,
            CredClass::Forbidden,
            "sess-rule",
        );
        sess_entry.scope = DigestScope::Session;
        let mut fleet_entry = publish_digest(
            fleet_secret,
            VariantTag::Raw,
            CredClass::Forbidden,
            "fleet-rule",
        );
        fleet_entry.scope = DigestScope::Fleet;

        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        m.ingest_session_lifecycle(&KeyedPublish {
            session_uuid: "s".into(),
            entries: vec![sess_entry, fleet_entry],
            batch_id: "b".into(),
            digest_set_version: "v".into(),
        });
        m.seal_keyed();

        // The session-scoped digest matches...
        assert!(matches!(
            m.scan_or_hold(sess_secret, true, &ScanCtx::egress()),
            Verdict::Block(_)
        ));
        // ...but the fleet-scoped digest did NOT load through the session door, so
        // it is NOT matched here (it belongs on the policy path).
        assert!(matches!(
            m.scan_or_hold(fleet_secret, true, &ScanCtx::egress()),
            Verdict::Pass { .. }
        ));
    }

    #[test]
    fn flush_session_clears_session_scoped_digests_at_teardown() {
        // NFT-6 hygiene: at session-end teardown the session's keyed digests are
        // flushed, leaving no residue that could match a later byte/session.
        let secret = b"teardown-canary-XYZ";
        let entry = publish_digest(secret, VariantTag::Raw, CredClass::Forbidden, "td-rule");
        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        m.ingest_session_lifecycle(&KeyedPublish {
            session_uuid: "sess-td".into(),
            entries: vec![entry],
            batch_id: "b".into(),
            digest_set_version: "v".into(),
        });
        m.seal_keyed();
        assert!(matches!(
            m.scan_or_hold(secret, true, &ScanCtx::egress()),
            Verdict::Block(_)
        ));

        // Teardown: flush the session.
        m.flush_session();
        assert_eq!(m.bound_session(), None, "session unbound at teardown");
        assert!(!m.keyed_loaded(), "keyed plane gone after flush");
        assert!(!m.keyed_live());
        // The same bytes now Pass (the digest is gone — no residue).
        assert!(matches!(
            m.scan_or_hold(secret, true, &ScanCtx::egress()),
            Verdict::Pass { .. }
        ));
    }

    #[test]
    fn rebinding_a_new_session_drops_the_prior_sessions_digests() {
        // A different session_uuid re-binds the matcher and drops the prior
        // session's scoped digests first (a session's digests never leak forward).
        let s1_secret = b"sess1-canary-111";
        let s2_secret = b"sess2-canary-222";
        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        m.ingest_session_lifecycle(&KeyedPublish {
            session_uuid: "sess-1".into(),
            entries: vec![publish_digest(
                s1_secret,
                VariantTag::Raw,
                CredClass::Forbidden,
                "s1-rule",
            )],
            batch_id: "b1".into(),
            digest_set_version: "v1".into(),
        });
        m.seal_keyed();
        assert!(matches!(
            m.scan_or_hold(s1_secret, true, &ScanCtx::egress()),
            Verdict::Block(_)
        ));

        // A new session connects on the same matcher instance.
        m.ingest_session_lifecycle(&KeyedPublish {
            session_uuid: "sess-2".into(),
            entries: vec![publish_digest(
                s2_secret,
                VariantTag::Raw,
                CredClass::Forbidden,
                "s2-rule",
            )],
            batch_id: "b2".into(),
            digest_set_version: "v2".into(),
        });
        assert_eq!(m.bound_session(), Some("sess-2"));
        // The new session is unsealed (mint-before-attach re-runs): any scan Holds.
        assert_eq!(
            m.scan_or_hold(s2_secret, true, &ScanCtx::egress()),
            Verdict::Hold
        );
        m.seal_keyed();
        // Session 2's digest matches...
        assert!(matches!(
            m.scan_or_hold(s2_secret, true, &ScanCtx::egress()),
            Verdict::Block(_)
        ));
        // ...and session 1's digest is GONE (it did not leak into session 2).
        assert!(matches!(
            m.scan_or_hold(s1_secret, true, &ScanCtx::egress()),
            Verdict::Pass { .. }
        ));
    }

    // ---- a matched canary returns non-Pass carrying plane=keyed + rule_id ----

    #[test]
    fn matched_canary_returns_block_plane_keyed_with_rule_id() {
        let secret = b"AKIAFAKECANARYKEY42";
        let entry = publish_digest(secret, VariantTag::Raw, CredClass::Forbidden, "aws-canary");
        let mut m = DigestSetMatcher::new(FakeHasher, 32);
        m.ingest_keyed(&KeyedPublish {
            session_uuid: "s1".into(),
            entries: vec![entry],
            batch_id: "b1".into(),
            digest_set_version: "ds-v1".into(),
        });
        m.seal_keyed();

        // The canary embedded in a larger body (egress request body) is caught.
        let body = b"POST /upload key=AKIAFAKECANARYKEY42 trailing";
        let v = m.scan(body, true, &ScanCtx::egress()).unwrap();
        assert!(
            !matches!(v, Verdict::Pass { .. }),
            "a matched canary is non-Pass"
        );
        let p = v.provenance().expect("non-Pass carries provenance");
        assert_eq!(p.plane, Plane::Keyed, "verdict carries plane=keyed");
        assert_eq!(p.rule_id, "aws-canary", "verdict carries rule_id");
        assert_no_secret_in_verdict(&v, secret);
    }

    // ---- variant matching: a base64'd secret matches the Base64 variant ------

    #[test]
    fn base64_variant_secret_on_the_wire_matches_the_base64_digest() {
        let secret = b"super-secret-pat-value";
        // The producer pushes the BASE64 variant of the secret.
        let entry = publish_digest(secret, VariantTag::Base64, CredClass::Forbidden, "pat-b64");
        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        m.ingest_keyed(&KeyedPublish {
            session_uuid: "s".into(),
            entries: vec![entry],
            batch_id: "b".into(),
            digest_set_version: "v".into(),
        });
        m.seal_keyed();

        // The agent base64-encodes the secret before egress — the on-wire bytes
        // are the base64 form. The matcher encodes candidate windows as Base64
        // before hashing, so the RAW base64 text on the wire matches.
        let on_wire = base64_standard(secret);
        let body = format!("Authorization: Basic {on_wire}");
        let v = m.scan(body.as_bytes(), true, &ScanCtx::egress()).unwrap();
        match &v {
            Verdict::Block(p) => assert_eq!(p.plane, Plane::Keyed),
            other => panic!("base64 variant must Block; got {other:?}"),
        }
        // Neither the raw secret nor the base64 text appears in the verdict.
        assert_no_secret_in_verdict(&v, secret);
        assert_no_secret_in_verdict(&v, on_wire.as_bytes());
    }

    // ---- ISSUED{service} keyed-hit Flag rung carries service provenance -------

    #[test]
    fn issued_credential_keyed_hit_flag_rung() {
        let secret = b"issued-github-token-xyz";
        let entry = publish_digest(
            secret,
            VariantTag::Raw,
            CredClass::Issued {
                service_id: "github".into(),
            },
            "issued-github",
        );
        let mut m =
            DigestSetMatcher::new(FakeHasher, 64).with_keyed_hit_action(KeyedHitAction::Flag);
        m.ingest_keyed(&KeyedPublish {
            session_uuid: "s".into(),
            entries: vec![entry],
            batch_id: "b".into(),
            digest_set_version: "v".into(),
        });
        m.seal_keyed();

        let v = m.scan(secret, true, &ScanCtx::egress()).unwrap();
        match &v {
            Verdict::Flag(p) => assert_eq!(p.plane, Plane::Keyed),
            other => panic!("Flag rung must Flag; got {other:?}"),
        }
        assert_no_secret_in_verdict(&v, secret);
    }

    // ---- generic plane: keyword prefilter then confirm, capped at block ------

    #[test]
    fn generic_pack_from_fake_pol4_snapshot_matches_with_plane_generic() {
        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        // Ingest a generic pack from a fake POL-4 snapshot.
        m.ingest_generic(GenericPack {
            rules: vec![GenericRule {
                id: "generic-aws-akid".into(),
                regex: "AKIA".into(),
                keywords: vec!["AKIA".into()],
                secret_group: 0,
                allowlists: vec![],
            }],
            pack_version: "pack-2026.6".into(),
            policy_layer: "org-generic".into(),
        });
        assert!(m.generic_loaded());

        let v = m
            .scan(b"token=AKIAEXAMPLE1234", true, &ScanCtx::egress())
            .unwrap();
        match &v {
            // Generic plane is capped at block+log.
            Verdict::Block(p) => {
                assert_eq!(
                    p.plane,
                    Plane::Generic,
                    "generic match carries plane=generic"
                );
                assert_eq!(p.rule_id, "generic-aws-akid");
                assert_eq!(p.ruleset_version, "pack-2026.6");
            }
            other => panic!("generic hit must Block (capped); got {other:?}"),
        }
    }

    #[test]
    fn generic_keyword_prefilter_skips_rule_when_no_keyword_present() {
        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        m.ingest_generic(GenericPack {
            rules: vec![GenericRule {
                id: "needs-keyword".into(),
                regex: "SECRET".into(),
                keywords: vec!["SECRET".into()],
                secret_group: 0,
                allowlists: vec![],
            }],
            pack_version: "p".into(),
            policy_layer: "l".into(),
        });
        // No keyword in the chunk → the rule is skipped, the chunk passes.
        let v = m
            .scan(b"ordinary body text", true, &ScanCtx::egress())
            .unwrap();
        assert!(
            matches!(v, Verdict::Pass { .. }),
            "no keyword → Pass; got {v:?}"
        );
    }

    #[test]
    fn generic_allowlist_suppresses_a_known_false_positive() {
        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        m.ingest_generic(GenericPack {
            rules: vec![GenericRule {
                id: "fp-prone".into(),
                regex: "TOKEN".into(),
                keywords: vec!["TOKEN".into()],
                secret_group: 0,
                allowlists: vec!["EXAMPLE_TOKEN".into()],
            }],
            pack_version: "p".into(),
            policy_layer: "l".into(),
        });
        // The matched span sits inside the allowlisted substring → suppressed.
        let v = m
            .scan(b"value=EXAMPLE_TOKEN here", true, &ScanCtx::egress())
            .unwrap();
        assert!(
            matches!(v, Verdict::Pass { .. }),
            "allowlisted → Pass; got {v:?}"
        );
    }

    // ---- keyed precedence over generic --------------------------------------

    #[test]
    fn keyed_plane_takes_precedence_over_generic_on_the_same_chunk() {
        let secret = b"AKIAREALCANARY99";
        let mut m = DigestSetMatcher::new(FakeHasher, 64);
        // Keyed forbidden digest for the exact secret...
        m.ingest_keyed(&KeyedPublish {
            session_uuid: "s".into(),
            entries: vec![publish_digest(
                secret,
                VariantTag::Raw,
                CredClass::Forbidden,
                "keyed-akid",
            )],
            batch_id: "b".into(),
            digest_set_version: "ds-keyed".into(),
        });
        m.seal_keyed();
        // ...and a generic rule that would ALSO match (AKIA prefix).
        m.ingest_generic(GenericPack {
            rules: vec![GenericRule {
                id: "generic-akid".into(),
                regex: "AKIA".into(),
                keywords: vec!["AKIA".into()],
                secret_group: 0,
                allowlists: vec![],
            }],
            pack_version: "pack".into(),
            policy_layer: "org".into(),
        });

        let v = m.scan(secret, true, &ScanCtx::egress()).unwrap();
        // The keyed plane wins: provenance names the keyed rule + plane.
        let p = v.provenance().unwrap();
        assert_eq!(p.plane, Plane::Keyed, "keyed plane takes precedence");
        assert_eq!(p.rule_id, "keyed-akid");
    }

    // ---- hold-back integration: the gate (u1) receives the matcher verdict ---

    #[test]
    fn holdback_module_receives_matcher_verdict_and_release_n_semantics() {
        // The u1 ScanGate drives the u2 DigestSetMatcher: a clean stream releases
        // bytes up to the hold-back floor; a canary across a chunk boundary is
        // buffered and Blocked before any secret byte egresses.
        let secret = b"CANARYSPAN";
        let max_len = secret.len(); // hold-back window = secret.len()-1
        let entry = publish_digest(secret, VariantTag::Raw, CredClass::Forbidden, "span-canary");
        let mut matcher = DigestSetMatcher::new(FakeHasher, max_len);
        matcher.ingest_keyed(&KeyedPublish {
            session_uuid: "s".into(),
            entries: vec![entry],
            batch_id: "b".into(),
            digest_set_version: "v".into(),
        });
        matcher.seal_keyed();
        // The gate sources fail-closed-when-keyed from the matcher's own state.
        let mut gate = ScanGate::new(
            matcher,
            max_len,
            /*keyed_loaded=*/ true,
            FailMode::Closed,
        )
        .unwrap();

        // Chunk 1 ends with the secret's PREFIX "...CANARYSP"; with the hold-back
        // window the prefix stays buffered and must NOT egress.
        let chunk1 = b"clean lead CANARYSP";
        let v1 = gate.scan_chunk(chunk1, false, &ScanCtx::egress());
        let release1 = match v1 {
            Verdict::Pass { release_n } => release_n,
            other => panic!("chunk 1 should Pass up to floor; got {other:?}"),
        };
        let egress1 = gate.take_released(release1);
        // No secret prefix egressed (the hold-back floor kept the tail).
        assert!(
            !contains_subslice(&egress1, b"CANARYSP"),
            "secret prefix must NOT egress on chunk 1; egressed={egress1:?}"
        );

        // Chunk 2 supplies "AN" completing "CANARYSPAN" across the boundary.
        let chunk2 = b"AN tail data";
        let v2 = gate.scan_chunk(chunk2, true, &ScanCtx::egress());
        match &v2 {
            Verdict::Block(p) => {
                assert_eq!(p.plane, Plane::Keyed);
                assert_eq!(p.rule_id, "span-canary");
            }
            other => panic!("the boundary-spanning canary must Block once joined; got {other:?}"),
        }
        assert!(v2.releases_nothing(), "Block releases nothing");
        // The full secret is still buffered and NEVER egressed.
        assert!(contains_subslice(gate.buffer().scannable(), secret));
        assert_no_secret_in_verdict(&v2, secret);
    }

    // ---- no plane loaded: everything passes (gate hold-back still applies) ----

    #[test]
    fn no_plane_loaded_passes_through() {
        let mut m = DigestSetMatcher::new(FakeHasher, 16);
        assert!(!m.keyed_loaded());
        assert!(!m.generic_loaded());
        let v = m
            .scan(b"anything goes here", true, &ScanCtx::egress())
            .unwrap();
        assert!(matches!(v, Verdict::Pass { .. }));
    }

    // ---- variant encoders are byte-correct -----------------------------------

    #[test]
    fn variant_encoders_match_known_vectors() {
        assert_eq!(base64_standard(b""), "");
        assert_eq!(base64_standard(b"f"), "Zg==");
        assert_eq!(base64_standard(b"fo"), "Zm8=");
        assert_eq!(base64_standard(b"foo"), "Zm9v");
        assert_eq!(base64_standard(b"foobar"), "Zm9vYmFy");
        assert_eq!(url_percent_encode(b"a b/c"), "a%20b%2Fc");
        assert_eq!(url_percent_encode(b"safe-_.~"), "safe-_.~");
        assert_eq!(hex_lower(&[0x00, 0x0f, 0xab, 0xff]), "000fabff");
    }

    // ---- unknown key id is a clean no-match (rotation safety) -----------------

    #[test]
    fn unknown_key_id_is_a_clean_no_match() {
        // A digest under a key the hasher does not know (a rotation the consumer
        // has not loaded) must NOT match and must NOT panic — it passes through.
        let secret = b"rotated-secret-001";
        let mut entry = publish_digest(secret, VariantTag::Raw, CredClass::Forbidden, "rot");
        entry.key_id = "unknown-key".to_string();
        let mut m = DigestSetMatcher::new(FakeHasher, 32);
        m.ingest_keyed(&KeyedPublish {
            session_uuid: "s".into(),
            entries: vec![entry],
            batch_id: "b".into(),
            digest_set_version: "v".into(),
        });
        m.seal_keyed();
        let v = m.scan(secret, true, &ScanCtx::egress()).unwrap();
        assert!(
            matches!(v, Verdict::Pass { .. }),
            "unknown key → no match → Pass"
        );
    }

    // =====================================================================
    // u3 — RequestScanFilter body-filter driver (the hold-back state machine
    // `main.rs` wires onto the Pingora body-filter seam, exercised over a
    // recording fake upstream that counts matched bytes never delivered).
    // =====================================================================

    /// A recording fake upstream: the body-filter forwards each
    /// [`BodyFilterAction`]'s released bytes to it; it accumulates EXACTLY the
    /// bytes that egressed. A test then asserts the canary's matched bytes never
    /// reached it (the acceptance: "zero matched bytes observed by recording
    /// upstream"). This is the lib-side twin of the conformance-adapter recording
    /// upstream — it counts delivered bytes, never re-derives a verdict.
    #[derive(Default)]
    struct RecordingUpstream {
        delivered: Vec<u8>,
    }

    impl RecordingUpstream {
        /// Apply one filter action: forward its released bytes (Block/Hold deliver
        /// nothing). Returns `true` if the action aborted the stream (Block) so the
        /// driver loop can stop forwarding.
        fn apply(&mut self, action: &BodyFilterAction) -> bool {
            self.delivered.extend_from_slice(action.released_bytes());
            action.is_block()
        }

        /// How many of `needle`'s bytes ever reached the upstream (0 = the canary's
        /// matched bytes never egressed).
        fn contains(&self, needle: &[u8]) -> bool {
            contains_subslice(&self.delivered, needle)
        }
    }

    /// Build a sealed keyed matcher + an egress filter over a single Forbidden
    /// canary, sized so the canary cannot straddle the hold-back window unnoticed.
    fn canary_filter(
        secret: &[u8],
        rule_id: &str,
    ) -> RequestScanFilter<DigestSetMatcher<FakeHasher>> {
        let max_len = secret.len();
        let entry = publish_digest(secret, VariantTag::Raw, CredClass::Forbidden, rule_id);
        let mut matcher = DigestSetMatcher::new(FakeHasher, max_len);
        matcher.ingest_keyed(&KeyedPublish {
            session_uuid: "sess-u3".into(),
            entries: vec![entry],
            batch_id: "batch-u3".into(),
            digest_set_version: "ds-u3".into(),
        });
        matcher.seal_keyed();
        let keyed_loaded = matcher.keyed_loaded();
        let gate = ScanGate::new(matcher, max_len, keyed_loaded, FailMode::Closed).unwrap();
        RequestScanFilter::egress(gate)
    }

    #[test]
    fn body_filter_blocks_a_single_chunk_canary_zero_matched_bytes_egress() {
        // ACCEPTANCE: a planted GitHub-token canary in a request body → the hook
        // fires Block; the recording upstream observes ZERO matched bytes; the
        // returned action carries the in-band-refusal provenance the agent sees.
        let secret = b"ghp_canaryTOKEN0001CANARY";
        let mut filter = canary_filter(secret, "canary-single");
        let mut upstream = RecordingUpstream::default();

        // A single body chunk carrying clean lead bytes then the canary.
        let body = b"POST /x clean-lead ghp_canaryTOKEN0001CANARY".to_vec();
        let action = filter.on_request_chunk(&body, true);

        match &action {
            BodyFilterAction::Block(p) => {
                assert_eq!(p.plane, Plane::Keyed, "the keyed canary blocks");
                assert_eq!(p.rule_id, "canary-single");
            }
            other => panic!("the canary must Block; got {other:?}"),
        }
        // The provenance is fingerprint-free (never-log-the-secret).
        assert!(
            !contains_subslice(format!("{action:?}").as_bytes(), secret),
            "the action must not carry any matched byte"
        );

        upstream.apply(&action);
        assert!(
            !upstream.contains(b"ghp_canaryTOKEN0001CANARY"),
            "zero matched bytes may reach the upstream; delivered={:?}",
            upstream.delivered
        );
        assert!(
            filter.is_blocked(),
            "the filter latches closed after a Block"
        );
    }

    #[test]
    fn body_filter_holds_a_canary_split_across_two_chunks_until_matcher_releases() {
        // ACCEPTANCE chunk-boundary: a canary split across two read chunks is
        // BUFFERED by the hold-back state machine — the prefix in chunk 1 is NOT
        // forwarded (only released after the matcher decides on the joined span),
        // and chunk 2 completes the canary → Block, zero matched bytes egress.
        let secret = b"CANARYSPLIT01234567";
        let mut filter = canary_filter(secret, "canary-split");
        let mut upstream = RecordingUpstream::default();

        // Chunk 1 ends mid-canary ("...CANARYSPLIT012"). The hold-back window keeps
        // the canary prefix buffered: it is NOT forwarded after only chunk 1.
        let chunk1 = b"lead-clean-bytes CANARYSPLIT012".to_vec();
        let a1 = filter.on_request_chunk(&chunk1, false);
        assert!(
            !a1.is_block(),
            "chunk 1 alone does not complete the canary (no block yet)"
        );
        upstream.apply(&a1);
        // The canary prefix present in chunk 1 must NOT have egressed.
        assert!(
            !upstream.contains(b"CANARYSPLIT012"),
            "the split canary's chunk-1 prefix must stay buffered; delivered={:?}",
            upstream.delivered
        );
        // The clean lead bytes before the hold-back window DID flow (the stream is
        // not stalled on clean data; only the trailing window — up to the secret
        // length − 1 — is held).
        assert!(
            upstream.contains(b"lead-clean"),
            "clean lead bytes before the hold-back window egress normally; \
             delivered={:?}",
            upstream.delivered
        );

        // Chunk 2 supplies "34567" completing "CANARYSPLIT01234567" across the
        // boundary → Block. The completion is only detected AFTER chunk 2, proving
        // the hold-back buffered (did not release after chunk 1).
        let chunk2 = b"34567 trailing-data".to_vec();
        let a2 = filter.on_request_chunk(&chunk2, true);
        assert!(
            a2.is_block(),
            "the boundary-spanning canary blocks once joined"
        );
        upstream.apply(&a2);
        assert!(
            !upstream.contains(secret),
            "the boundary-straddling canary never egresses; delivered={:?}",
            upstream.delivered
        );
    }

    #[test]
    fn body_filter_passes_a_clean_stream_intact() {
        // A clean stream with no canary forwards every byte (across chunks) — the
        // hold-back window holds the trailing bytes per chunk but end_of_stream
        // drains the remainder, so the upstream receives the whole body intact.
        let secret = b"NEVER_PRESENT_CANARY";
        let mut filter = canary_filter(secret, "canary-clean");
        let mut upstream = RecordingUpstream::default();

        let chunk1 = b"clean request body part one ".to_vec();
        let chunk2 = b"and part two with no secret.".to_vec();
        let a1 = filter.on_request_chunk(&chunk1, false);
        assert!(
            matches!(a1, BodyFilterAction::Forward(_)),
            "clean chunk forwards"
        );
        upstream.apply(&a1);
        let a2 = filter.on_request_chunk(&chunk2, true);
        assert!(
            matches!(a2, BodyFilterAction::Forward(_)),
            "clean final chunk forwards"
        );
        upstream.apply(&a2);

        let mut expected = chunk1.clone();
        expected.extend_from_slice(&chunk2);
        assert_eq!(
            upstream.delivered, expected,
            "a clean stream egresses byte-for-byte intact"
        );
    }

    #[test]
    fn body_filter_latches_closed_a_late_chunk_after_block_releases_nothing() {
        // Once Block fires, a LATER chunk (a buggy/racing caller) must never sneak a
        // byte past — the filter latches closed and re-Blocks, releasing nothing.
        let secret = b"ghp_latchCANARY0001x";
        let mut filter = canary_filter(secret, "canary-latch");
        let mut upstream = RecordingUpstream::default();

        let blocked = filter.on_request_chunk(b"x ghp_latchCANARY0001x", true);
        assert!(blocked.is_block());
        upstream.apply(&blocked);

        // A late chunk carrying otherwise-clean bytes must NOT be forwarded.
        let late = filter.on_request_chunk(b"would-be-clean-trailer", true);
        assert!(
            late.is_block(),
            "a post-block chunk re-Blocks (latched closed)"
        );
        upstream.apply(&late);
        assert!(
            !upstream.contains(b"would-be-clean-trailer"),
            "no byte egresses after a fired Block; delivered={:?}",
            upstream.delivered
        );
    }

    #[test]
    fn body_filter_flag_forwards_and_carries_provenance() {
        // The generic-plane Flag (alert) rung: the bytes pass AND the provenance
        // rides the action so the caller fires a PolicyDecision event. We drive a
        // keyed matcher set to the Flag hit-action over a canary so a hit produces
        // Flag (not Block); the bytes forward, provenance present, no secret on it.
        let secret = b"flagCANARY00112233aa";
        let max_len = secret.len();
        let entry = publish_digest(secret, VariantTag::Raw, CredClass::Forbidden, "canary-flag");
        let mut matcher =
            DigestSetMatcher::new(FakeHasher, max_len).with_keyed_hit_action(KeyedHitAction::Flag);
        matcher.ingest_keyed(&KeyedPublish {
            session_uuid: "s".into(),
            entries: vec![entry],
            batch_id: "b".into(),
            digest_set_version: "v".into(),
        });
        matcher.seal_keyed();
        let keyed_loaded = matcher.keyed_loaded();
        let gate = ScanGate::new(matcher, max_len, keyed_loaded, FailMode::Closed).unwrap();
        let mut filter = RequestScanFilter::egress(gate);

        let action = filter.on_request_chunk(&[b"x ".as_slice(), secret].concat(), true);
        match &action {
            BodyFilterAction::Flag { provenance, .. } => {
                assert_eq!(provenance.plane, Plane::Keyed);
                assert_eq!(provenance.rule_id, "canary-flag");
            }
            other => panic!("a Flag hit-action must Flag, not Block; got {other:?}"),
        }
        assert!(
            !filter.is_blocked(),
            "Flag passes the bytes — the filter does NOT latch closed"
        );
        assert!(
            !contains_subslice(format!("{action:?}").as_bytes(), secret),
            "the Flag action must not carry a matched byte"
        );
    }

    #[test]
    fn body_filter_fails_closed_on_unsealed_keyed_plane_releasing_nothing() {
        // Mint-before-attach: the keyed plane is loaded but NOT sealed → the matcher
        // errors → the gate (fail-closed-when-keyed) Holds → the driver forwards
        // nothing. A byte must never egress against a half-attached digest set.
        let secret = b"ghp_unsealedCANARY01";
        let max_len = secret.len();
        let entry = publish_digest(
            secret,
            VariantTag::Raw,
            CredClass::Forbidden,
            "canary-unsealed",
        );
        let mut matcher = DigestSetMatcher::new(FakeHasher, max_len);
        matcher.ingest_keyed(&KeyedPublish {
            session_uuid: "s".into(),
            entries: vec![entry],
            batch_id: "b".into(),
            digest_set_version: "v".into(),
        });
        // NOT sealed (mint-before-attach unsatisfied).
        let keyed_loaded = matcher.keyed_loaded();
        let gate = ScanGate::new(matcher, max_len, keyed_loaded, FailMode::Closed).unwrap();
        let mut filter = RequestScanFilter::egress(gate);
        let mut upstream = RecordingUpstream::default();

        let action = filter.on_request_chunk(b"clean lead bytes here too", true);
        assert!(
            matches!(action, BodyFilterAction::Hold),
            "an unsealed keyed plane fails closed (Hold); got {action:?}"
        );
        upstream.apply(&action);
        assert!(
            upstream.delivered.is_empty(),
            "fail-closed releases NO byte; delivered={:?}",
            upstream.delivered
        );
    }

    // ---- u2: generic-pack hot-reload substrate (shared slot + in-flight sweep) ----

    fn akid_pack(version: &str) -> GenericPack {
        GenericPack {
            rules: vec![GenericRule {
                id: "generic-aws-akid".into(),
                regex: "AKIA".into(),
                keywords: vec!["AKIA".into()],
                secret_group: 0,
                allowlists: vec![],
            }],
            pack_version: version.into(),
            policy_layer: "org-generic".into(),
        }
    }

    #[test]
    fn match_generic_pack_is_the_single_source_for_inline_and_sweep() {
        // The free fn the inline matcher and the sweep BOTH call: a keyword-gated
        // literal confirm yielding a fingerprint-free Generic-plane provenance.
        let pack = akid_pack("pack-1");
        let hit = match_generic_pack(&pack, b"token=AKIAEXAMPLE1234").expect("matches");
        assert_eq!(hit.plane, Plane::Generic);
        assert_eq!(hit.rule_id, "generic-aws-akid");
        assert_eq!(hit.ruleset_version, "pack-1");
        // No keyword → no match (the prefilter short-circuits).
        assert!(match_generic_pack(&pack, b"ordinary body").is_none());
        // The provenance carries no matched byte (never-log-the-secret).
        assert!(!format!("{hit:?}").contains("EXAMPLE1234"));
    }

    #[test]
    fn shared_generic_pack_hot_swaps_atomically_and_in_flight_reads_are_not_torn() {
        let shared = SharedGenericPack::new(GenericPack::default());
        assert_eq!(shared.version(), "");
        // An in-flight scan that cloned the OLD (empty) pack keeps deciding on it.
        let in_flight = shared.current();
        assert!(in_flight.rules.is_empty());

        // Hot-swap a new pack live (the apply barrier's commit step).
        shared.hot_swap(akid_pack("pack-2"));
        assert_eq!(shared.version(), "pack-2");
        // The previously-cloned Arc is the WHOLE old pack — never torn.
        assert!(
            in_flight.rules.is_empty(),
            "the in-flight read sees the whole old pack, never a half-swapped one"
        );
        // A scan that begins after the swap reads the whole new pack.
        let after = shared.current();
        assert_eq!(after.pack_version, "pack-2");
        assert!(match_generic_pack(&after, b"AKIAXXXX").is_some());
    }

    #[test]
    fn inflight_sweep_emits_a_policy_decision_for_a_newly_matched_open_stream() {
        // An open stream whose buffered tail contains a secret that NO rule matched
        // under the old (empty) pack: after a hot-reload to a pack with the matching
        // rule, the sweep emits ONE policy-decision naming the stream + the rule,
        // plane=Generic — the "already-in-flight exfil is caught" guarantee.
        let mut streams = InFlightStreams::new();
        streams.upsert("dstap-1", b"GET /?k=AKIAEXFILNOW");
        streams.upsert("dstap-2", b"ordinary clean body");
        assert_eq!(streams.len(), 2);

        let events = streams.reevaluate_against(&akid_pack("pack-3"));
        assert_eq!(events.len(), 1, "only the matching stream fires");
        assert_eq!(events[0].stream_id, "dstap-1");
        assert_eq!(events[0].provenance.plane, Plane::Generic);
        assert_eq!(events[0].provenance.rule_id, "generic-aws-akid");
        assert_eq!(events[0].provenance.ruleset_version, "pack-3");
        // The event carries no matched byte (never-log-the-secret).
        assert!(!format!("{:?}", events[0]).contains("EXFILNOW"));
    }

    #[test]
    fn inflight_sweep_reports_only_the_delta_not_an_already_matched_rule() {
        // A stream a rule ALREADY fired for is not re-reported on a subsequent
        // re-evaluation under the SAME rule — only the delta a hot-reload introduces.
        let mut streams = InFlightStreams::new();
        streams.upsert("dstap-1", b"k=AKIAFIRSTHIT");
        let first = streams.reevaluate_against(&akid_pack("pack-a"));
        assert_eq!(first.len(), 1, "first match fires");
        // Re-evaluate against a pack still carrying the SAME rule id: no re-fire.
        let again = streams.reevaluate_against(&akid_pack("pack-b"));
        assert!(
            again.is_empty(),
            "an already-reported rule does not re-fire; got {again:?}"
        );
        // A pack adding a DISTINCT new rule that also matches fires for the delta.
        let mut two_rule = akid_pack("pack-c");
        two_rule.rules.push(GenericRule {
            id: "generic-2".into(),
            regex: "AKIA".into(),
            keywords: vec!["AKIA".into()],
            secret_group: 0,
            allowlists: vec![],
        });
        // The first rule still matches first (precedence), so still no NEW event —
        // the delta is keyed on the rule id that actually matches, which is unchanged.
        let third = streams.reevaluate_against(&two_rule);
        assert!(third.is_empty(), "the first rule still wins; no new delta");
    }

    #[test]
    fn inflight_registry_upsert_replaces_tail_and_remove_drops_the_stream() {
        let mut streams = InFlightStreams::new();
        streams.upsert("s", b"clean");
        // Update the tail to one that now contains a secret.
        streams.upsert("s", b"k=AKIANEWTAIL");
        let events = streams.reevaluate_against(&akid_pack("p"));
        assert_eq!(events.len(), 1, "the latest tail is what is re-evaluated");
        // Remove the stream → no longer re-evaluated.
        streams.remove("s");
        assert!(streams.is_empty());
        assert!(streams.reevaluate_against(&akid_pack("p2")).is_empty());
    }
}
