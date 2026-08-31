// SPDX-License-Identifier: Apache-2.0

//! `Consumer` — the frozen D72 two-phase prepare/commit apply seam every
//! host-side policy consumer implements (POL-4 part 2; D72/D36, doc 13 §5,
//! doc 15 §5.2).
//!
//! This is the Rust-side contract the host agent's apply driver invokes and the
//! THREE data-plane consumers implement: ds-dnsgate (the admitter),
//! ds-tlsproxy and the `ds-nft` NFTables programmer (the enforcers). It is the
//! single-source counterpart of the Go `hostagent.ConsumerBarrier` / `Sweeper`
//! seam (`orchestrator/internal/hostagent/apply.go`): the SHAPE is frozen once,
//! here, and the Go driver and the three Rust implementors bind to it rather
//! than re-declaring it per service.
//!
//! # The frozen D72 barrier (do not reopen)
//!
//! The host moves from `vN` to `vN+1` ALL-OR-NONE across the three consumers,
//! in three phases:
//!
//! 1. **PREPARE** — [`Consumer::prepare`] validates the new composed snapshot
//!    via the consumer's embedded `policy-core` and STAGES a new evaluator while
//!    the consumer KEEPS SERVING `vN`. It returns an opaque [`ApplyToken`] on
//!    success, or a [`PrepareError`] naming why the consumer cannot accept the
//!    snapshot. Prepare is the only fallible-by-design step. The host runs
//!    prepare over ALL THREE consumers first; if ANY prepare fails the apply
//!    ABORTS host-wide — NO consumer is committed and the host stays fully on
//!    `vN` (all-or-none, fail-closed).
//! 2. **COMMIT** — [`Consumer::commit`] ATOMICALLY flips the consumer from `vN`
//!    to `vN+1` (a single pointer swap, or one netlink transaction for the NFT
//!    programmer; D72). It is called ONLY with an [`ApplyToken`] this consumer's
//!    own `prepare` returned, and ONLY after EVERY consumer prepared. The host
//!    commits in a FIXED admitter-last order — ds-tlsproxy + the NFT flip BEFORE
//!    ds-dnsgate — so every transient mixed-version window is FAIL-CLOSED
//!    (make-before-break: the enforcers are on the at-least-as-strict `vN+1`
//!    before the admitter starts admitting under it).
//! 3. **SWEEP** — [`Consumer::sweep_and_advance_applied_seq`] runs the
//!    POST-COMMIT revocation sweep: it re-evaluates the consumer's derived state
//!    against `vN+1` (allow4/allow6 entries, the DNS-2b admission map, live
//!    ask-grants), EVICTS everything `vN+1` denies — severing conntrack/tunnels
//!    RUNG-CONDITIONALLY (D53, flush at block-or-higher) through the ONE shared
//!    [`crate::flush::FlushSession`] primitive — and only THEN advances and
//!    returns the consumer's `applied_seq`. `applied_seq` advances ONLY after
//!    the sweep completes (D72); the host heartbeat reports the MIN over the
//!    three consumers (doc 15 §5.2).
//!
//! # Idempotence (frozen)
//!
//! Each method is idempotent ON THE TOKEN: a consumer that has already committed
//! (or already swept) a given [`ApplyToken`] treats a repeated `commit` /
//! `sweep_and_advance_applied_seq` for that same token as a no-op success
//! returning the same result, so a re-driven barrier (a retried apply after a
//! transient host-agent fault) never double-flips or double-evicts. The token
//! carries the snapshot `seq` and the verified `content_hash`, so an
//! implementor can recognise a token it already consumed.
//!
//! # What this module freezes vs. what implementors own
//!
//! This module declares the trait, the token, the version newtype, and the two
//! error surfaces — SHAPES only, no framework types (doc 14 §6, D67/D40): no
//! hickory/pingora/nft/netlink type ever crosses the seam. The per-consumer
//! deep parse, the evaluator staging, the atomic flip mechanism, and the sweep's
//! derived-state walk are all owned by each implementor. The snapshot reaches
//! `prepare` as the already-verified TRANSPORTED BYTES (the host subscriber
//! verified `content_hash` via [`crate::snapshot_verify`] before fan-out, and a
//! consumer re-verifies against the token's hash, never re-serializing); the
//! consumer parses them with `policy-core`, never re-canonicalizing.
//!
//! NEVER-LOG-THE-SECRET: nothing on this seam logs the composed document; it
//! crosses as opaque bytes, and the error surfaces below carry only structural
//! reasons (a seq, a phase, a kind), never document content.

use crate::snapshot_verify::{self, ContentHash};

/// A monotonic policy version — the D36 `policy_log` bigserial `seq`, THE single
/// policy version end to end (D72, doc 13 §1 rule 3). There are no per-service
/// or per-resource-type version namespaces; this newtype just names the one
/// `seq` the snapshot, the token, and `applied_seq` all share.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyVersion(pub u64);

impl PolicyVersion {
    /// The raw `seq`.
    #[must_use]
    pub fn seq(self) -> u64 {
        self.0
    }
}

impl From<u64> for PolicyVersion {
    fn from(seq: u64) -> Self {
        PolicyVersion(seq)
    }
}

/// The opaque handle [`Consumer::prepare`] returns and the same consumer's
/// [`Consumer::commit`] / [`Consumer::sweep_and_advance_applied_seq`] consume —
/// the staged-but-not-yet-flipped evaluator's claim ticket.
///
/// The host driver NEVER inspects a token's meaning; it only routes each token
/// back to the consumer that produced it, preserving the per-consumer
/// atomic-flip contract (D72). The token is deliberately PLAIN DATA (the
/// snapshot identity it stages, `seq` + verified `content_hash`), not a handle
/// onto live evaluator state: the staged evaluator lives inside the implementor,
/// keyed by this identity. That keeps the token `Clone`/`Send`/`Sync` so the
/// host driver can hold and re-present it across a re-driven barrier, and lets
/// an implementor recognise a token it has already consumed (idempotence on the
/// token).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ApplyToken {
    /// The version this token stages — the snapshot `seq` (`vN+1`).
    pub version: PolicyVersion,
    /// The verified `content_hash` of the snapshot this token stages. A consumer
    /// re-checks a presented token's hash against the staged snapshot so a token
    /// can only commit the exact bytes its `prepare` validated (no token reuse
    /// across snapshots).
    pub content_hash: ContentHash,
}

impl ApplyToken {
    /// Construct a token for a staged snapshot identity.
    #[must_use]
    pub fn new(version: PolicyVersion, content_hash: ContentHash) -> ApplyToken {
        ApplyToken {
            version,
            content_hash,
        }
    }

    /// The version (`seq`) this token stages.
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        self.version
    }
}

/// Why a [`Consumer::prepare`] could not accept a snapshot. A prepare error is
/// FATAL to the whole host apply (all-or-none, fail-closed): the host commits no
/// consumer and stays on `vN`.
///
/// The variants are STRUCTURAL reasons only — never document content
/// (NEVER-LOG-THE-SECRET). An implementor maps its internal parse/stage failure
/// onto one of these so the host driver (and the boundary conformance rig) can
/// reason about the abort cause without a framework error type crossing the
/// seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrepareError {
    /// The transported bytes did not hash to the snapshot's claimed
    /// `content_hash` — the consumer re-verified and the bytes are not the ones
    /// the host pinned. NACK host-wide (doc 13 §5.1; the host subscriber should
    /// already have caught this, but the consumer re-checks fail-closed).
    HashMismatch {
        /// The version whose bytes failed to verify.
        version: PolicyVersion,
    },
    /// The bytes verified but `policy-core` rejected the composed document as
    /// structurally invalid (a schema violation, an illegal rung-cap, a missing
    /// mandatory provenance — doc 13 §8.1). The snapshot is unschedulable; the
    /// host stays on `vN`.
    SchemaInvalid {
        /// The version whose document failed validation.
        version: PolicyVersion,
        /// A short, content-free reason (e.g. `"rung-cap exceeded"`), suitable
        /// for a log line — NEVER the document body.
        reason: String,
    },
    /// The document was valid but the consumer could not STAGE a new evaluator
    /// (a resource limit, an internal staging fault). The host stays on `vN`;
    /// the apply is re-driven.
    StageFailed {
        /// The version that could not be staged.
        version: PolicyVersion,
        /// A short, content-free reason.
        reason: String,
    },
}

impl PrepareError {
    /// The version this prepare failure pertains to (the `vN+1` that did not
    /// take effect).
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        match self {
            PrepareError::HashMismatch { version }
            | PrepareError::SchemaInvalid { version, .. }
            | PrepareError::StageFailed { version, .. } => *version,
        }
    }
}

impl core::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PrepareError::HashMismatch { version } => {
                write!(f, "prepare: content_hash mismatch for seq {}", version.0)
            }
            PrepareError::SchemaInvalid { version, reason } => {
                write!(f, "prepare: schema invalid for seq {}: {reason}", version.0)
            }
            PrepareError::StageFailed { version, reason } => {
                write!(f, "prepare: staging failed for seq {}: {reason}", version.0)
            }
        }
    }
}

impl std::error::Error for PrepareError {}

/// Why a [`Consumer::commit`] or [`Consumer::sweep_and_advance_applied_seq`]
/// could not complete. These run AFTER the host has committed to advancing
/// (every consumer already prepared), so the contract differs from prepare:
///
/// - a COMMIT error is a consumer-internal fault during the atomic flip. The
///   already-flipped consumers stay on `vN+1` (at-least-as-strict — fail-closed);
///   the host's recovery policy re-drives. It does NOT retroactively un-prepare
///   the others.
/// - a SWEEP error means the flip happened but the post-commit eviction did not
///   complete; `applied_seq` MUST NOT advance past `vN` for this round (the
///   host withholds the heartbeat min advance until the sweep re-drives, D72).
///
/// Variants are structural only — never document content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyError {
    /// The token presented to `commit` / `sweep` was not produced by this
    /// consumer's own `prepare` for a currently-staged snapshot (an unknown or
    /// already-discarded token). The consumer fails closed and the host
    /// re-drives — never flips an unstaged version.
    UnknownToken {
        /// The version the rejected token claimed.
        version: PolicyVersion,
    },
    /// The atomic flip to `vN+1` failed inside the consumer (a pointer-swap
    /// guard, a netlink transaction that did not apply). Already-committed
    /// enforcers stay on `vN+1`, fail-closed.
    CommitFailed {
        /// The version whose flip failed.
        version: PolicyVersion,
        /// A short, content-free reason.
        reason: String,
    },
    /// The flip succeeded but the post-commit revocation sweep could not
    /// complete (a flush primitive error, a derived-state re-eval fault).
    /// `applied_seq` is HELD at the prior version until the sweep re-drives
    /// (D72).
    SweepFailed {
        /// The version whose sweep did not complete.
        version: PolicyVersion,
        /// A short, content-free reason.
        reason: String,
    },
}

impl ApplyError {
    /// The version this error pertains to.
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        match self {
            ApplyError::UnknownToken { version }
            | ApplyError::CommitFailed { version, .. }
            | ApplyError::SweepFailed { version, .. } => *version,
        }
    }
}

impl core::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ApplyError::UnknownToken { version } => {
                write!(f, "apply: unknown/stale token for seq {}", version.0)
            }
            ApplyError::CommitFailed { version, reason } => {
                write!(
                    f,
                    "apply: commit flip failed for seq {}: {reason}",
                    version.0
                )
            }
            ApplyError::SweepFailed { version, reason } => {
                write!(
                    f,
                    "apply: post-commit sweep failed for seq {}: {reason}",
                    version.0
                )
            }
        }
    }
}

impl std::error::Error for ApplyError {}

/// The frozen D72 two-phase apply seam. The host agent's apply driver invokes
/// it across the three consumers; ds-dnsgate, ds-tlsproxy, and the `ds-nft`
/// programmer implement it.
///
/// Implementors MUST honour (doc 13 §5, D72):
///
/// - **`prepare` serves `vN` throughout.** Staging never disturbs the
///   currently-serving evaluator; the consumer keeps answering on `vN` until its
///   own `commit`.
/// - **`commit` is atomic and admitter-aware.** The flip is a single pointer
///   swap or one netlink transaction — never a torn intermediate. The host
///   sequences commits admitter-last; the consumer itself does not need to know
///   its order, only that its flip is atomic.
/// - **`sweep_and_advance_applied_seq` advances `applied_seq` LAST.** The
///   returned [`PolicyVersion`] is the consumer's NEW `applied_seq`, and it
///   equals the committed version ONLY once the eviction completed. Severing
///   goes through the ONE shared [`crate::flush::FlushSession`] primitive,
///   rung-conditional per D53 — the seam must not fork its own flush path.
/// - **idempotent on the token** (see the module docs): a repeated `commit` /
///   `sweep` for an already-consumed token is a no-op success.
///
/// The trait is `Send + Sync`: the host driver prepares the three consumers in
/// parallel and the consumers run inside async services. It is intentionally NOT
/// object-safe-restricted beyond that — a service holds a concrete implementor;
/// the host driver binds via generics or a thin enum, never needing
/// `dyn Consumer` across the FFI-free Go↔Rust boundary (the Go side has its own
/// `ConsumerBarrier`).
pub trait Consumer: Send + Sync {
    /// Validate `snapshot` via embedded `policy-core` and STAGE a new evaluator
    /// while still serving `vN`. Returns an [`ApplyToken`] for the staged
    /// `vN+1`, or a [`PrepareError`] that aborts the host-wide apply.
    ///
    /// `snapshot` is the transported bytes of the composed document; `version` is
    /// its `seq`. The consumer parses (never re-serializes) and stages. It MUST NOT
    /// flip here. This is the IN-PROCESS entry point for the seam that carries no
    /// separately-transported expected hash (a host-wiring layer that has verified
    /// upstream, the `snapshot_feed.rs` dispatcher which verifies the envelope's
    /// `content_hash` BEFORE this call, or a test that mints well-formed bytes); the
    /// SEPARATELY-transported-hash fail-closed identity gate is
    /// [`Consumer::prepare_verified`].
    fn prepare(&self, snapshot: &[u8], version: PolicyVersion) -> Result<ApplyToken, PrepareError>;

    /// Validate `snapshot` against the TRANSPORTED `expected_hash` and STAGE — the
    /// NON-VACUOUS fail-closed identity gate.
    ///
    /// `expected_hash` is the `content_hash` the PRODUCER pinned over those exact
    /// bytes and TRANSPORTED alongside them (doc 13 §5 identity tuple, the same
    /// `content_hash` [`crate::snapshot_verify`] verifies on the host-local feed).
    /// The default verifies the transported bytes against `expected_hash` via
    /// [`crate::snapshot_verify::verify_snapshot_bytes`] BEFORE parse: a mismatch is
    /// fail-closed [`PrepareError::HashMismatch`] and `prepare` is NEVER entered with
    /// mismatched bytes (parse + stage never run on a hash-failing snapshot). Only
    /// after the bytes verify does it forward to [`Consumer::prepare`] to parse +
    /// stage. It mirrors the `snapshot_feed.rs` envelope path, which verifies the
    /// transported `content_hash` before `prepare`.
    ///
    /// This is the additive seam: the hash is supplied SEPARATELY by the producer,
    /// so the check can actually NACK (unlike re-hashing the bytes and comparing
    /// them to their own hash, which can never NACK). The PRODUCTION feed routes the
    /// transported `content_hash` here so the in-process prepare gets the same real
    /// gate the envelope path applies. An implementor MAY override to fold the verify
    /// into its own parse (both consumers in ds-tlsproxy do), but MUST keep the
    /// verify-before-parse, fail-closed-on-mismatch contract.
    fn prepare_verified(
        &self,
        snapshot: &[u8],
        version: PolicyVersion,
        expected_hash: &ContentHash,
    ) -> Result<ApplyToken, PrepareError> {
        // Verify-only identity gate FIRST — before any parse/stage. A mismatch
        // NACKs host-wide and never reaches `prepare` (no parse/stage residue).
        if !snapshot_verify::verify_snapshot_bytes(snapshot, expected_hash).is_verified() {
            return Err(PrepareError::HashMismatch { version });
        }
        self.prepare(snapshot, version)
    }

    /// Atomically flip from `vN` to the `vN+1` `token` staged. Called only with
    /// a token this consumer's `prepare` returned, and only after all consumers
    /// prepared. Idempotent on `token` (a re-presented already-committed token
    /// is a no-op success). Fail-closed on any error: the consumer does not
    /// half-flip.
    fn commit(&self, token: &ApplyToken) -> Result<(), ApplyError>;

    /// Run the POST-COMMIT revocation sweep for the committed `token`:
    /// re-evaluate derived state against `vN+1`, evict everything `vN+1` denies
    /// (severing conntrack/tunnels rung-conditionally per D53 through the shared
    /// [`crate::flush::FlushSession`] primitive), then advance and return the
    /// consumer's new `applied_seq`. The returned version equals `token.version`
    /// ONLY once the eviction completed (D72). Idempotent on `token`. On an
    /// incomplete sweep returns [`ApplyError::SweepFailed`] and `applied_seq`
    /// stays at the prior version.
    fn sweep_and_advance_applied_seq(
        &self,
        token: &ApplyToken,
    ) -> Result<PolicyVersion, ApplyError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot_verify::sha256;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    fn token_for(seq: u64, bytes: &[u8]) -> ApplyToken {
        ApplyToken::new(PolicyVersion(seq), sha256(bytes))
    }

    #[test]
    fn policy_version_orders_and_unwraps() {
        assert!(PolicyVersion(3) < PolicyVersion(4));
        assert_eq!(PolicyVersion::from(7).seq(), 7);
    }

    #[test]
    fn apply_token_carries_identity() {
        let t = token_for(9, b"{}");
        assert_eq!(t.version(), PolicyVersion(9));
        assert_eq!(t.content_hash, sha256(b"{}"));
        // A token for different bytes differs (no cross-snapshot reuse).
        assert_ne!(t, token_for(9, b"{ }"));
    }

    #[test]
    fn error_versions_and_display_are_content_free() {
        let pe = PrepareError::SchemaInvalid {
            version: PolicyVersion(5),
            reason: "rung-cap exceeded".into(),
        };
        assert_eq!(pe.version(), PolicyVersion(5));
        assert!(pe.to_string().contains("seq 5"));

        let ae = ApplyError::SweepFailed {
            version: PolicyVersion(5),
            reason: "flush_session refused".into(),
        };
        assert_eq!(ae.version(), PolicyVersion(5));
        assert!(ae.to_string().contains("sweep failed"));
    }

    // A minimal in-memory implementor proves the trait is implementable with NO
    // framework types and that the prepare→commit→sweep handshake + token
    // idempotence work as the contract specifies — the whole point of the seam.
    #[derive(Default)]
    struct FakeConsumer {
        staged: Mutex<Option<ApplyToken>>,
        committed: Mutex<Option<ApplyToken>>,
        applied_seq: AtomicU64,
        // counts to prove idempotence is a no-op, not a re-run.
        flips: AtomicU64,
        sweeps: AtomicU64,
        // when set, prepare rejects (schema-invalid) to exercise the abort path.
        reject_prepare: bool,
    }

    impl Consumer for FakeConsumer {
        fn prepare(
            &self,
            snapshot: &[u8],
            version: PolicyVersion,
        ) -> Result<ApplyToken, PrepareError> {
            if self.reject_prepare {
                return Err(PrepareError::SchemaInvalid {
                    version,
                    reason: "fake reject".into(),
                });
            }
            // The token pins the hash of exactly these bytes. The transported-hash
            // identity gate is the provided `prepare_verified` default, which runs
            // BEFORE this and never enters `prepare` on a mismatch.
            let token = ApplyToken::new(version, sha256(snapshot));
            *self.staged.lock().unwrap() = Some(token.clone());
            Ok(token)
        }

        fn commit(&self, token: &ApplyToken) -> Result<(), ApplyError> {
            // Idempotent on token: already committed → no-op success.
            if self.committed.lock().unwrap().as_ref() == Some(token) {
                return Ok(());
            }
            let staged = self.staged.lock().unwrap().clone();
            if staged.as_ref() != Some(token) {
                return Err(ApplyError::UnknownToken {
                    version: token.version(),
                });
            }
            *self.committed.lock().unwrap() = Some(token.clone());
            self.flips.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn sweep_and_advance_applied_seq(
            &self,
            token: &ApplyToken,
        ) -> Result<PolicyVersion, ApplyError> {
            if self.committed.lock().unwrap().as_ref() != Some(token) {
                return Err(ApplyError::UnknownToken {
                    version: token.version(),
                });
            }
            // Idempotent: applied_seq already at this version → no re-sweep.
            if self.applied_seq.load(Ordering::SeqCst) == token.version().seq() {
                return Ok(token.version());
            }
            self.sweeps.fetch_add(1, Ordering::SeqCst);
            self.applied_seq
                .store(token.version().seq(), Ordering::SeqCst);
            Ok(token.version())
        }
    }

    #[test]
    fn prepare_commit_sweep_round_trip_advances_applied_seq() {
        let c = FakeConsumer::default();
        let bytes = b"{\"composed\":true}";
        let token = c.prepare(bytes, PolicyVersion(11)).expect("prepare");
        assert_eq!(token.version(), PolicyVersion(11));
        // applied_seq does NOT advance on commit — only after sweep (D72).
        c.commit(&token).expect("commit");
        assert_eq!(c.applied_seq.load(Ordering::SeqCst), 0);
        let swept = c.sweep_and_advance_applied_seq(&token).expect("sweep");
        assert_eq!(swept, PolicyVersion(11));
        assert_eq!(c.applied_seq.load(Ordering::SeqCst), 11);
    }

    #[test]
    fn commit_and_sweep_are_idempotent_on_token() {
        let c = FakeConsumer::default();
        let token = c.prepare(b"x", PolicyVersion(2)).expect("prepare");
        c.commit(&token).expect("commit 1");
        c.commit(&token).expect("commit 2 (idempotent)");
        assert_eq!(c.flips.load(Ordering::SeqCst), 1, "flip ran exactly once");
        c.sweep_and_advance_applied_seq(&token).expect("sweep 1");
        c.sweep_and_advance_applied_seq(&token)
            .expect("sweep 2 (idempotent)");
        assert_eq!(c.sweeps.load(Ordering::SeqCst), 1, "sweep ran exactly once");
        assert_eq!(c.applied_seq.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn prepare_failure_models_the_host_wide_abort() {
        let c = FakeConsumer {
            reject_prepare: true,
            ..Default::default()
        };
        let err = c.prepare(b"x", PolicyVersion(4)).unwrap_err();
        assert_eq!(err.version(), PolicyVersion(4));
        // Nothing staged → applied_seq untouched (host stays on vN).
        assert_eq!(c.applied_seq.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn prepare_verified_nacks_a_transported_hash_mismatch_before_parse_or_stage() {
        // The NON-VACUOUS gate: a SEPARATELY transported expected hash that does
        // NOT match the bytes is fail-closed HashMismatch — prepare_verified never
        // parses or stages the mismatched snapshot.
        let c = FakeConsumer::default();
        let bytes = b"{\"composed\":true}";
        let mut wrong = sha256(bytes);
        wrong[0] ^= 0x01; // a hash that does not match `bytes`
        match c.prepare_verified(bytes, PolicyVersion(4), &wrong) {
            Err(PrepareError::HashMismatch { version }) => assert_eq!(version, PolicyVersion(4)),
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        // Fail-closed: nothing staged on a hash mismatch.
        assert!(
            c.staged.lock().unwrap().is_none(),
            "a hash-failing snapshot must never stage"
        );
        // The matching transported hash still stages (happy path unchanged).
        let token = c
            .prepare_verified(bytes, PolicyVersion(4), &sha256(bytes))
            .expect("matching hash stages");
        assert_eq!(token.content_hash, sha256(bytes));
        assert!(c.staged.lock().unwrap().is_some());
    }

    #[test]
    fn commit_rejects_unstaged_token_fail_closed() {
        let c = FakeConsumer::default();
        // A token never produced by this consumer's prepare.
        let foreign = token_for(99, b"not-staged");
        match c.commit(&foreign) {
            Err(ApplyError::UnknownToken { version }) => assert_eq!(version, PolicyVersion(99)),
            other => panic!("expected UnknownToken, got {other:?}"),
        }
    }

    // The host driver holds consumers behind `dyn Consumer` only inside Rust (if
    // it ever does); this proves the trait is usable through a trait object so a
    // heterogeneous set can be driven uniformly.
    #[test]
    fn trait_is_object_usable() {
        let c: Box<dyn Consumer> = Box::new(FakeConsumer::default());
        let token = c.prepare(b"y", PolicyVersion(1)).expect("prepare");
        c.commit(&token).expect("commit");
        let swept = c.sweep_and_advance_applied_seq(&token).expect("sweep");
        assert_eq!(swept, PolicyVersion(1));
    }
}
