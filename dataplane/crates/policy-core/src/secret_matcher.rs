//! `SecretMatcher` — the frozen TLS-7 secret-scanning trait + verdict semantics
//! (D73, doc 12 §5.1–§5.2, doc 14 §6 crate map).
//!
//! This module freezes the *trait* and the *verdict semantics*, not the engine.
//! The matcher engine (exact digest set vs Bloom-prefilter-plus-confirm,
//! aho-corasick / Vectorscan / RegexSet, candidate extraction) is FREE
//! implementation behind the trait (doc 12 §9 "Inspection hook" row; doc 14 OQ5).
//!
//! What is FROZEN here (changes require a doc 04 §6 decision-log entry):
//!
//! - the [`SecretMatcher`] trait shape and the matcher-owns-carryover /
//!   proxy-owns-hold-back division of responsibility;
//! - the [`Verdict`] set `{Pass, Hold, Block, Flag, Redact}` (direction-symmetric)
//!   and the rule that every non-`Pass`/`Hold` verdict carries POL-3 provenance;
//! - [`VerdictProvenance`] / [`Plane`] and the digest-set-version namespace rule;
//! - the fail-closed-when-keyed-loaded legality predicate ([`FailMode`]);
//! - the confirm-before-verdict rule and the never-log-the-secret invariant.
//!
//! Home note (doc 13 §1 rule 1 / doc 14 §6 "interface homes fixed"): the
//! `SecretMatcher` trait and verdict semantics live IN `policy-core` — the one
//! evaluation engine, embedded (not wired) in both boundary services. This is
//! also the type the Attach & client workstream links for the attach-side
//! consumer (doc 14 §6; policy-core README).
//!
//! Dependency note (doc 14 §6): these types are defined LOCALLY. `policy-core`'s
//! `[dependencies]` stays empty — no `ds-contracts` path dep. The provenance and
//! plane types here deliberately overlap the LOG-1 `PolicyDecision.plane` +
//! digest-set-version fields (doc 14 §2); rehoming the shared shapes into
//! `ds-contracts` later is a REFACTOR (doc 14 §6: "interface homes fixed;
//! renames are refactors"), not a contract change, so it does not gate this
//! freeze and does not pull a framework dependency across the seam.

/// Direction of an inspected byte stream (doc 12 §5.1, direction-symmetric).
///
/// FROZEN — changes require a doc 04 §6 decision-log entry.
///
/// The TLS-7 hook is invoked from the proxy's body-filter chain on **both**
/// directions; the semantics are direction-symmetric. v0 may enable
/// request-direction (egress, the secret-egress direction) only — response
/// (ingress) scanning is an explicit scheduled follow-on (doc 12 §5.1, §10
/// "done-when correction"). The enum carries both arms from day one so enabling
/// the response direction is a config flip, not a type change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Egress: VM → upstream. The secret-egress direction; the only direction
    /// v0 need enable (doc 12 §5.1, §10).
    Request,
    /// Ingress: upstream → VM. Frozen in the type; enablement scheduled as a
    /// follow-on (doc 12 §10).
    Response,
}

/// Minimal per-scan context handed to the matcher (doc 12 §5.1).
///
/// FROZEN (shape) — changes require a doc 04 §6 decision-log entry.
///
/// Kept deliberately lean: the direction-symmetric flag plus an opaque session
/// correlation handle, nothing the matcher does not need. The matcher owns its
/// own carryover state (hence `&mut self` on [`SecretMatcher::scan`]); the
/// context is read-only per-stream metadata, not matcher state.
///
/// Additive-growth latitude: new fields may be appended here without a contract
/// change (the matcher reads what it understands and ignores the rest) — that is
/// why the session handle is an opaque token, not a structured key the matcher
/// is invited to interpret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScanCtx<'a> {
    /// Which direction this stream flows (doc 12 §5.1).
    pub direction: Direction,
    /// Opaque session-correlation handle. The matcher MUST treat this as an
    /// opaque token (for keying its own per-session carryover, for nothing
    /// else); the proxy owns its meaning and may change its internal shape
    /// without a matcher-visible contract change.
    pub session: SessionCorrelation<'a>,
}

/// Opaque session-correlation handle (doc 12 §5.1).
///
/// FROZEN (opacity) — changes require a doc 04 §6 decision-log entry.
///
/// A newtype around a borrowed string the proxy stamps; the matcher keys its
/// carryover on it and never parses it. Wrapping it (rather than exposing a raw
/// `&str`) keeps the "opaque, do not interpret" contract in the type system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionCorrelation<'a>(pub &'a str);

impl<'a> ScanCtx<'a> {
    /// Construct a request-direction (egress) context — the v0-enabled
    /// direction (doc 12 §5.1).
    pub fn request(session: &'a str) -> ScanCtx<'a> {
        ScanCtx {
            direction: Direction::Request,
            session: SessionCorrelation(session),
        }
    }

    /// Construct a response-direction (ingress) context. Frozen in the type;
    /// enablement is a scheduled follow-on (doc 12 §10).
    pub fn response(session: &'a str) -> ScanCtx<'a> {
        ScanCtx {
            direction: Direction::Response,
            session: SessionCorrelation(session),
        }
    }
}

/// Which detection plane produced a verdict (doc 12 §5.1, doc 14 §2 `plane`).
///
/// FROZEN — changes require a doc 04 §6 decision-log entry.
///
/// The two-plane split (D73): the **keyed** plane is the Identity→Boundary
/// exact-match digest feed (near-zero false positives, the only class inline
/// blocking and D53 interrupt rungs may trust); the **generic** plane is the
/// versioned gitleaks-compatible pattern pack (25–75% precision — capped at
/// block+log, never suspend/kill). Carried in [`VerdictProvenance`] and stamped
/// into the LOG-1 `PolicyDecision.plane` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Plane {
    /// Identity→Boundary exact-match digest feed (doc 12 §5.2).
    Keyed,
    /// Versioned generic pattern pack (doc 12 §5.2).
    Generic,
}

/// POL-3 provenance stamped onto every non-`Pass`/`Hold` verdict (doc 12 §5.1).
///
/// FROZEN — changes require a doc 04 §6 decision-log entry.
///
/// **Never-log-the-secret (D73):** this struct is incapable of carrying matched
/// bytes by construction — there is no field that could hold the secret value or
/// a slice of the inspected stream. It carries only fingerprint-class metadata:
/// the rule id, the version of the ruleset OR digest set that fired, the policy
/// layer, and the plane. A test asserts the `Debug` rendering of every verdict
/// built from a synthetic canary contains zero canary bytes.
///
/// **Digest-set-version namespace rule (doc 14 §7):** when [`Self::plane`] is
/// [`Plane::Keyed`], [`Self::ruleset_or_digest_set_version`] is the digest-set
/// version — a SEPARATE, NON-POLICY version namespace. LOG-4's version-chain
/// assertion must NOT read it as `policy_log` skew (doc 14 §6 §7). For
/// [`Plane::Generic`] it is the generic-pack version (a policy artifact under the
/// `policy_log` seq). The field name is deliberately neutral so one type serves
/// both namespaces; the discriminator is [`Self::plane`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct VerdictProvenance {
    /// The matched rule id (POL-3). Fingerprint-class metadata, never the value.
    pub rule_id: String,
    /// Version of the ruleset (generic plane, a `policy_log`-seq policy artifact)
    /// OR of the digest set (keyed plane, a SEPARATE non-policy namespace — see
    /// the struct doc-comment and doc 14 §7). The [`Self::plane`] field is the
    /// discriminator that says which namespace this is in.
    pub ruleset_or_digest_set_version: String,
    /// The composing policy layer (system-baseline → org → repo/session) the rule
    /// came from (POL-3, doc 13 §1.2).
    pub policy_layer: String,
    /// Which plane fired — also the namespace discriminator for
    /// [`Self::ruleset_or_digest_set_version`] (doc 12 §5.1, doc 14 §7).
    pub plane: Plane,
}

/// The frozen TLS-7 verdict set (D73, doc 12 §5.1), direction-symmetric.
///
/// FROZEN — changes require a doc 04 §6 decision-log entry.
///
/// `Verdict ∈ { Pass(release_n), Hold, Block, Flag, Redact }`. Every non-`Pass`,
/// non-`Hold` verdict carries POL-3 [`VerdictProvenance`] (rule id,
/// ruleset/digest-set version, policy layer, plane). The variants are
/// incapable of carrying matched bytes — never-log-the-secret holds by
/// construction (D73): there is no payload field anywhere in this enum that
/// could hold the secret value or any slice of the inspected stream.
///
/// The hold-back invariant (doc 12 §5.1) is the PROXY's contract, expressed
/// through this enum: the proxy forwards bytes upstream ONLY as the matcher
/// releases them via [`Verdict::Pass`]`{ release_n }`, retaining up to
/// `max_secret_len − 1` trailing bytes (see [`SecretMatcher::max_secret_len`])
/// so a secret straddling a chunk / TLS-record boundary is never detected only
/// after its prefix already egressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Release the first `release_n` held bytes upstream; the matcher has
    /// confirmed they cannot be the prefix of any secret. `release_n` is counted
    /// against the proxy's hold-back window: the matcher may release everything
    /// except the up-to-`max_secret_len − 1` trailing bytes that could still be
    /// the start of a boundary-straddling secret (doc 12 §5.1).
    /// `Pass { release_n: 0 }` is a legal "release nothing yet" (equivalent in
    /// effect to a soft hold while awaiting more bytes); `end_of_stream` forces a
    /// final flush.
    Pass {
        /// Number of currently-held leading bytes the matcher authorises for
        /// upstream forwarding.
        release_n: usize,
    },
    /// Await more bytes before deciding; release nothing. The matcher needs more
    /// of the stream (a candidate is in flight and could complete into a secret).
    Hold,
    /// Abort the stream: matched bytes never egress; the agent sees an in-band
    /// refusal (doc 12 §5.1). Carries POL-3 provenance — fingerprint only.
    Block(VerdictProvenance),
    /// Pass the bytes through but emit a `PolicyDecision` event (doc 12 §5.1).
    /// Carries POL-3 provenance — fingerprint only.
    Flag(VerdictProvenance),
    /// FROZEN SCHEMA SLOT, IMPLEMENTATION DEFERRED (doc 12 §5.1; §9 "Redact impl"
    /// is FREE/deferred). The variant exists so the verdict set is complete at
    /// freeze and enabling redaction later is not a breaking enum change; no
    /// matcher returns it in v0. Carries POL-3 provenance — fingerprint only;
    /// like every other variant it cannot carry the matched bytes.
    Redact(VerdictProvenance),
}

impl Verdict {
    /// The POL-3 provenance this verdict carries, if any. `Pass`/`Hold` carry
    /// none (they are not policy decisions); `Block`/`Flag`/`Redact` always do.
    pub fn provenance(&self) -> Option<&VerdictProvenance> {
        match self {
            Verdict::Pass { .. } | Verdict::Hold => None,
            Verdict::Block(p) | Verdict::Flag(p) | Verdict::Redact(p) => Some(p),
        }
    }

    /// Whether this verdict is "block-or-higher" — the severity at which the
    /// confirm-before-verdict rule binds (no Bloom-prefilter hit alone may drive
    /// it) and at which the D53 flow-severing rung fires. `Block` and `Redact`
    /// (a stronger-than-block transform) qualify; `Flag` does not (it passes the
    /// bytes); `Pass`/`Hold` do not.
    pub fn is_block_or_higher(&self) -> bool {
        matches!(self, Verdict::Block(_) | Verdict::Redact(_))
    }
}

/// The frozen TLS-7 secret-scanning trait (D73, doc 12 §5.1).
///
/// FROZEN — changes require a doc 04 §6 decision-log entry.
///
/// **Division of responsibility (doc 12 §5.1):**
/// - the MATCHER owns carryover state (hence `&mut self`): bytes it has seen but
///   not yet released, in-flight candidate state, per-session digest context;
/// - the PROXY owns the hold-back invariant: **no byte is forwarded upstream
///   until the matcher releases it** (via [`Verdict::Pass`]`{ release_n }`),
///   retaining up to [`Self::max_secret_len`]` − 1` trailing bytes — a few
///   hundred bytes — so a secret spanning a chunk / TLS-record boundary is never
///   detected only after its prefix already egressed.
///
/// Quoting doc 12 §5.1 (the frozen invariant): *"The matcher owns carryover
/// state; the proxy owns the hold-back invariant: no byte is forwarded upstream
/// until the matcher releases it (retain up to max-secret-length−1 trailing
/// bytes — a few hundred bytes — so a secret spanning a chunk/TLS-record
/// boundary is never detected only after its prefix egressed). Freeze the trait
/// and the invariant, not the engine."*
///
/// **Confirm-before-verdict (doc 14 OQ5; policy-core README):** no
/// Bloom-prefilter hit may, on its own, drive a ≥block verdict
/// ([`Verdict::is_block_or_higher`]). Engines are free behind the trait
/// (exact digest set vs Bloom-prefilter-plus-confirm, aho-corasick / Vectorscan
/// / RegexSet), but this rule is part of the trait CONTRACT: a prefilter hit must
/// be confirmed against the exact digest/rule before any block-or-higher verdict
/// is returned. A bare prefilter hit may at most produce `Hold` (await
/// confirmation) — never `Block`/`Redact`.
///
/// **Never-log-the-secret (D73):** the trait cannot leak the secret because the
/// only way it reports a finding is a [`Verdict`], and [`Verdict`] /
/// [`VerdictProvenance`] are incapable of carrying matched bytes by construction.
pub trait SecretMatcher {
    /// Scan one chunk of an inspected byte stream and decide what the proxy may
    /// forward (doc 12 §5.1).
    ///
    /// `&mut self`: the matcher accumulates carryover across calls. `chunk` is the
    /// next slice of the stream in `ctx.direction`. `end_of_stream` is the proxy
    /// telling the matcher this is the last chunk — the matcher MUST then make a
    /// terminal decision (a flush `Pass` releasing all remaining held bytes, or a
    /// `Block`); it may not leave the proxy holding bytes forever.
    ///
    /// The returned [`Verdict`] tells the proxy how many held bytes it may release
    /// ([`Verdict::Pass`]`{ release_n }`), to keep holding ([`Verdict::Hold`]), or
    /// to take a policy action ([`Verdict::Block`] / [`Verdict::Flag`] /
    /// [`Verdict::Redact`]). The matcher MUST NOT authorise releasing a byte it
    /// has not confirmed is outside every possible secret prefix.
    fn scan(&mut self, chunk: &[u8], end_of_stream: bool, ctx: &ScanCtx) -> Verdict;

    /// The maximum secret length the matcher can detect, in bytes — the size the
    /// proxy uses to bound its hold-back window (doc 12 §5.1).
    ///
    /// The proxy retains up to `max_secret_len() − 1` trailing un-released bytes
    /// so a secret straddling a chunk boundary is caught. A matcher that reports a
    /// value smaller than its true longest secret breaks the hold-back invariant;
    /// this is part of the trait contract, not an optimisation knob.
    fn max_secret_len(&self) -> usize;
}

/// Fail-mode posture for the inspection hook (doc 12 §5.1, §9 frozen row; D73).
///
/// FROZEN — changes require a doc 04 §6 decision-log entry.
///
/// **The frozen rule (doc 12 §5.1):** *"Fail-closed is mandatory whenever the
/// keyed plane is loaded; fail-open is permitted only for generic flag-only
/// configs and must be an explicit policy bit"* (the Envoy ext_proc
/// `failure_mode_allow` lesson). [`FailMode`] is that explicit policy bit;
/// [`fail_mode_is_legal`] is the legality predicate, and the tests reject the two
/// illegal shapes: fail-open with the keyed plane loaded, and fail-open with a
/// generic config that is not flag-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FailMode {
    /// On matcher error / unavailability, refuse the byte (the mandatory posture
    /// whenever the keyed plane is loaded).
    FailClosed,
    /// On matcher error / unavailability, pass the byte. Legal ONLY for generic
    /// flag-only configs, and only as an explicit policy bit (doc 12 §5.1).
    FailOpen,
}

/// The loaded-plane / config posture the [`FailMode`] legality predicate is
/// evaluated against (doc 12 §5.1, §9).
///
/// FROZEN (shape) — changes require a doc 04 §6 decision-log entry.
///
/// Captures exactly the two facts the legality rule turns on: whether the keyed
/// plane is loaded, and whether the generic config is flag-only (i.e. its
/// strongest configured verdict is `Flag`, with no block-or-higher generic rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlaneConfig {
    /// Whether the keyed (exact-match digest) plane is loaded. If true,
    /// fail-closed is mandatory regardless of the generic config (doc 12 §5.1).
    pub keyed_loaded: bool,
    /// Whether the generic plane is flag-only — its strongest configured generic
    /// verdict is `Flag` (no block-or-higher generic rule). Fail-open is legal
    /// only when this holds AND the keyed plane is not loaded.
    pub generic_flag_only: bool,
}

/// Whether `mode` is a legal posture for `config` (doc 12 §5.1, §9 frozen row).
///
/// FROZEN — changes require a doc 04 §6 decision-log entry.
///
/// `FailClosed` is always legal. `FailOpen` is legal ONLY when the keyed plane is
/// NOT loaded AND the generic config is flag-only. The two rejected shapes:
/// - fail-open with the keyed plane loaded (the keyed plane demands fail-closed);
/// - fail-open with a non-flag-only generic config (a generic block-or-higher
///   rule may not silently fail open).
pub fn fail_mode_is_legal(mode: FailMode, config: PlaneConfig) -> bool {
    match mode {
        FailMode::FailClosed => true,
        FailMode::FailOpen => !config.keyed_loaded && config.generic_flag_only,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Synthetic test fixtures (D50) -----------------------------------
    //
    // All test data here is INLINE and clearly synthetic. There is NO
    // fixtures/ directory (that would trip the D50 CI gate's sidecar
    // requirements) and NO real token shapes (no `sk-ant-…{20,}`, no
    // `Bearer …{40,}` — see scripts/check-fixture-provenance.sh value
    // regexes). The canary is a made-up marker token.

    /// A clearly-synthetic canary token. Deliberately NOT a real provider token
    /// shape: no `sk-ant-<class><dd>-` prefix, no `Bearer ` + long body. This is
    /// the secret a test-local exact-match engine is configured to catch.
    const CANARY: &[u8] = b"ds-test-canary-AAAABBBBCCCC";

    /// A second synthetic canary used to prove `release_n` accounting under the
    /// retention rule without colliding with [`CANARY`].
    const SHORT_CANARY: &[u8] = b"ds-test-canary-XYZ";

    fn keyed_provenance() -> VerdictProvenance {
        VerdictProvenance {
            rule_id: "test-rule-canary".into(),
            ruleset_or_digest_set_version: "digest-set-v1".into(),
            policy_layer: "session".into(),
            plane: Plane::Keyed,
        }
    }

    /// A trivial test-local exact-match engine implementing [`SecretMatcher`]
    /// (D50: a test-local trivial exact-match engine). It looks for ONE
    /// configured needle, streaming across chunk boundaries, and honours the
    /// hold-back invariant: it never authorises releasing a byte that could be
    /// the prefix of the needle, retaining up to `needle.len() − 1` trailing
    /// bytes.
    ///
    /// This is a fixture, not a production engine — production engines are FREE
    /// behind the trait (doc 12 §9). It exists only to exercise the frozen
    /// contract.
    struct ExactMatchEngine {
        needle: Vec<u8>,
        /// Bytes seen but not yet released to the proxy.
        buf: Vec<u8>,
        /// Whether we have already emitted a terminal Block.
        blocked: bool,
    }

    impl ExactMatchEngine {
        fn new(needle: &[u8]) -> ExactMatchEngine {
            ExactMatchEngine {
                needle: needle.to_vec(),
                buf: Vec::new(),
                blocked: false,
            }
        }

        /// How many trailing bytes of `buf` are a proper prefix of `needle` —
        /// the bytes we must keep holding because they could still grow into the
        /// needle. Returns 0 if no suffix of `buf` is a needle-prefix.
        fn pending_prefix_len(&self) -> usize {
            let max = self.needle.len().saturating_sub(1).min(self.buf.len());
            // Longest k (1..=max) such that the last k bytes of buf equal the
            // first k bytes of needle.
            for k in (1..=max).rev() {
                let tail = &self.buf[self.buf.len() - k..];
                if tail == &self.needle[..k] {
                    return k;
                }
            }
            0
        }
    }

    impl SecretMatcher for ExactMatchEngine {
        fn scan(&mut self, chunk: &[u8], end_of_stream: bool, _ctx: &ScanCtx) -> Verdict {
            if self.blocked {
                // Once blocked, the stream is aborted; never release more.
                return Verdict::Block(keyed_provenance());
            }
            self.buf.extend_from_slice(chunk);

            // Full-needle detection: if the needle appears anywhere in the held
            // buffer, the secret's prefix has NOT yet egressed (we held it), so
            // we can block with zero matched bytes released.
            if self
                .buf
                .windows(self.needle.len())
                .any(|w| w == self.needle.as_slice())
            {
                self.blocked = true;
                self.buf.clear();
                return Verdict::Block(keyed_provenance());
            }

            if end_of_stream {
                // Terminal flush: no match, release everything held.
                let n = self.buf.len();
                self.buf.clear();
                return Verdict::Pass { release_n: n };
            }

            // Hold back any trailing bytes that could be a needle prefix;
            // release the rest.
            let pending = self.pending_prefix_len();
            let releasable = self.buf.len() - pending;
            // Keep the pending prefix in buf; drop the released bytes.
            self.buf.drain(..releasable);
            if releasable == 0 {
                Verdict::Hold
            } else {
                Verdict::Pass {
                    release_n: releasable,
                }
            }
        }

        fn max_secret_len(&self) -> usize {
            self.needle.len()
        }
    }

    // ---- Chunk-boundary unit tests (D50) ---------------------------------

    #[test]
    fn chunk_boundary_split_canary_blocks_with_zero_bytes_released() {
        // Split the synthetic canary across two chunks. The prefix must NOT
        // egress before the suffix arrives: the verdict on the first chunk is
        // Hold (or a Pass short of the suffix), then Block on the second — and
        // the engine reports zero bytes released past the split.
        let mut engine = ExactMatchEngine::new(CANARY);
        let ctx = ScanCtx::request("synthetic-session-1");

        let split = CANARY.len() / 2;
        let (head, tail) = CANARY.split_at(split);

        // First chunk: the whole chunk is a prefix of the needle, so nothing is
        // releasable — Hold.
        let v1 = engine.scan(head, false, &ctx);
        assert_eq!(v1, Verdict::Hold, "prefix of a secret must never egress");

        // Second chunk completes the needle: Block, with provenance, no bytes
        // released.
        let v2 = engine.scan(tail, false, &ctx);
        assert!(
            v2.is_block_or_higher(),
            "completed canary must block, got {v2:?}"
        );
        assert!(v2.provenance().is_some(), "block carries POL-3 provenance");
    }

    #[test]
    fn hold_back_retention_releases_all_but_pending_prefix() {
        // Innocuous bytes followed by the START of the canary in one chunk: the
        // innocuous bytes are releasable, but the trailing canary-prefix bytes
        // are held back (≤ max_secret_len − 1 retention rule). Pass(release_n)
        // must equal exactly the innocuous-byte count.
        let mut engine = ExactMatchEngine::new(SHORT_CANARY);
        let ctx = ScanCtx::request("synthetic-session-2");

        let innocuous = b"hello world ";
        // Feed innocuous bytes + the first few canary bytes (a genuine prefix).
        let prefix_len = 6usize; // "ds-tes" — a real prefix of SHORT_CANARY
        assert_eq!(&SHORT_CANARY[..prefix_len], b"ds-tes");
        let mut chunk = Vec::new();
        chunk.extend_from_slice(innocuous);
        chunk.extend_from_slice(&SHORT_CANARY[..prefix_len]);

        let v = engine.scan(&chunk, false, &ctx);
        match v {
            Verdict::Pass { release_n } => {
                // Exactly the innocuous bytes are released; the canary prefix is
                // retained (≤ max_secret_len − 1).
                assert_eq!(release_n, innocuous.len(), "release accounting");
                let retained = chunk.len() - release_n;
                assert!(
                    retained < engine.max_secret_len(),
                    "retention bounded by max_secret_len − 1"
                );
            }
            other => panic!("expected Pass releasing innocuous bytes, got {other:?}"),
        }

        // Now complete the canary: Block, zero further release.
        let v2 = engine.scan(&SHORT_CANARY[prefix_len..], false, &ctx);
        assert!(v2.is_block_or_higher(), "completed canary blocks");
    }

    #[test]
    fn end_of_stream_flushes_held_bytes() {
        // A trailing partial-prefix that never completes must be released on
        // end_of_stream — the matcher may not leave the proxy holding bytes
        // forever (doc 12 §5.1 flush contract).
        let mut engine = ExactMatchEngine::new(CANARY);
        let ctx = ScanCtx::request("synthetic-session-3");

        // A chunk ending in a genuine canary prefix, held back mid-stream.
        let prefix = &CANARY[..8]; // "ds-test-"
        let v1 = engine.scan(prefix, false, &ctx);
        assert_eq!(v1, Verdict::Hold, "pending prefix held mid-stream");

        // end_of_stream with no more bytes: flush the held prefix.
        let v2 = engine.scan(&[], true, &ctx);
        match v2 {
            Verdict::Pass { release_n } => {
                assert_eq!(release_n, prefix.len(), "flush releases all held bytes");
            }
            other => panic!("expected flush Pass at end_of_stream, got {other:?}"),
        }
    }

    #[test]
    fn innocuous_stream_passes_through_without_holding() {
        // A stream with no needle-prefix anywhere releases every byte each call.
        let mut engine = ExactMatchEngine::new(CANARY);
        let ctx = ScanCtx::request("synthetic-session-4");
        let chunk = b"the quick brown fox jumps over the lazy dog";
        let v = engine.scan(chunk, false, &ctx);
        assert_eq!(
            v,
            Verdict::Pass {
                release_n: chunk.len()
            },
            "innocuous bytes pass straight through"
        );
    }

    // ---- Never-log-the-secret (D73) --------------------------------------

    #[test]
    fn debug_never_leaks_the_canary_bytes() {
        // Build every non-Pass/Hold verdict from a provenance whose fields are
        // derived from the synthetic canary's CONTEXT (rule id etc.) — never the
        // canary value itself — and assert the Debug rendering of each verdict,
        // and of the provenance, contains zero canary bytes. The type is
        // fingerprint-only BY CONSTRUCTION; this guards against a future field
        // that could carry the value.
        let canary_str = std::str::from_utf8(CANARY).unwrap();

        let prov = keyed_provenance();
        let verdicts = [
            Verdict::Pass { release_n: 3 },
            Verdict::Hold,
            Verdict::Block(prov.clone()),
            Verdict::Flag(prov.clone()),
            Verdict::Redact(prov.clone()),
        ];
        for v in &verdicts {
            let rendered = format!("{v:?}");
            assert!(
                !rendered.contains(canary_str),
                "verdict Debug leaked canary bytes: {rendered}"
            );
            // Also assert it cannot contain the distinctive canary infix.
            assert!(
                !rendered.contains("AAAABBBBCCCC"),
                "verdict Debug leaked canary infix: {rendered}"
            );
        }

        // The provenance itself, rendered, must not contain the canary either.
        let prov_rendered = format!("{prov:?}");
        assert!(
            !prov_rendered.contains(canary_str),
            "provenance Debug leaked canary bytes: {prov_rendered}"
        );
    }

    #[test]
    fn block_verdict_from_real_match_carries_no_matched_bytes() {
        // Drive a real Block through the engine on the canary, then assert the
        // verdict's Debug carries none of the canary bytes — the engine cannot
        // smuggle the matched value into the verdict because the type has no slot
        // for it.
        let mut engine = ExactMatchEngine::new(CANARY);
        let ctx = ScanCtx::request("synthetic-session-5");
        let v = engine.scan(CANARY, false, &ctx);
        assert!(v.is_block_or_higher(), "canary blocks");
        let rendered = format!("{v:?}");
        let canary_str = std::str::from_utf8(CANARY).unwrap();
        assert!(
            !rendered.contains(canary_str),
            "block verdict leaked the matched canary: {rendered}"
        );
    }

    // ---- Fail-mode legality (doc 12 §5.1, §9) ----------------------------

    #[test]
    fn fail_mode_legality_rejects_fail_open_with_keyed_loaded() {
        // Keyed plane loaded ⇒ fail-closed mandatory; fail-open is illegal even
        // if the generic config happens to be flag-only.
        let cfg = PlaneConfig {
            keyed_loaded: true,
            generic_flag_only: true,
        };
        assert!(!fail_mode_is_legal(FailMode::FailOpen, cfg));
        assert!(fail_mode_is_legal(FailMode::FailClosed, cfg));
    }

    #[test]
    fn fail_mode_legality_rejects_fail_open_with_non_flag_only_generic() {
        // No keyed plane, but the generic config has a block-or-higher rule
        // (not flag-only) ⇒ fail-open is illegal.
        let cfg = PlaneConfig {
            keyed_loaded: false,
            generic_flag_only: false,
        };
        assert!(!fail_mode_is_legal(FailMode::FailOpen, cfg));
        assert!(fail_mode_is_legal(FailMode::FailClosed, cfg));
    }

    #[test]
    fn fail_mode_legality_allows_fail_open_only_for_flag_only_generic_no_keyed() {
        // The single legal fail-open shape: no keyed plane AND flag-only generic.
        let cfg = PlaneConfig {
            keyed_loaded: false,
            generic_flag_only: true,
        };
        assert!(fail_mode_is_legal(FailMode::FailOpen, cfg));
        // Fail-closed is always legal.
        assert!(fail_mode_is_legal(FailMode::FailClosed, cfg));
    }

    // ---- Verdict accessor invariants -------------------------------------

    #[test]
    fn provenance_present_iff_policy_action() {
        assert!(Verdict::Pass { release_n: 0 }.provenance().is_none());
        assert!(Verdict::Hold.provenance().is_none());
        assert!(Verdict::Block(keyed_provenance()).provenance().is_some());
        assert!(Verdict::Flag(keyed_provenance()).provenance().is_some());
        assert!(Verdict::Redact(keyed_provenance()).provenance().is_some());
    }

    #[test]
    fn block_or_higher_classification() {
        assert!(Verdict::Block(keyed_provenance()).is_block_or_higher());
        assert!(Verdict::Redact(keyed_provenance()).is_block_or_higher());
        assert!(!Verdict::Flag(keyed_provenance()).is_block_or_higher());
        assert!(!Verdict::Hold.is_block_or_higher());
        assert!(!Verdict::Pass { release_n: 1 }.is_block_or_higher());
    }

    #[test]
    fn plane_namespace_is_carried_in_provenance() {
        // The plane discriminator distinguishes the keyed digest-set-version
        // namespace from the generic policy-version namespace (doc 14 §7).
        let keyed = keyed_provenance();
        assert_eq!(keyed.plane, Plane::Keyed);
        let generic = VerdictProvenance {
            rule_id: "generic-pattern-1".into(),
            ruleset_or_digest_set_version: "generic-pack-v3".into(),
            policy_layer: "org".into(),
            plane: Plane::Generic,
        };
        assert_eq!(generic.plane, Plane::Generic);
    }
}
