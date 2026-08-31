// SPDX-License-Identifier: Apache-2.0

//! ds-dnsgate's side of the FROZEN D72 two-phase apply barrier (POL-4 part 2;
//! D72/D36, doc 13 §5, doc 15 §5.2).
//!
//! ds-dnsgate is the **admitter** — the consumer the host commits LAST in the
//! make-before-break order (ds-tlsproxy + the NFT flip move to `vN+1` first, so
//! every transient mixed-version window is FAIL-CLOSED; the admitter only starts
//! admitting under `vN+1` once the enforcers are already at-least-as-strict).
//! This module implements the [`ds_contracts::consumer::Consumer`] seam against
//! the gate's embedded `policy-core` evaluator.
//!
//! # This unit: the PREPARE hook (validate + stage while serving vN)
//!
//! [`Consumer::prepare_verified`] is the substance here (doc 13 §5; the seam's
//! only fallible-by-design phase). It is fail-closed end to end:
//!
//! 1. **Verify the snapshot identity against the PRODUCER-PINNED, separately
//!    transported `content_hash`.** The transported bytes are hashed via the
//!    single-source [`ds_contracts::snapshot_verify::verify_snapshot_bytes`] and
//!    compared to the `expected_hash` the producer pinned over those exact bytes
//!    and transported alongside them (doc 13 §5.1 identity tuple) — the same
//!    `content_hash` the host-local feed verifies before fan-out. A mismatch
//!    returns [`PrepareError::HashMismatch`] — NACK host-wide; the gate never
//!    parses bytes that do not hash to the producer's identity. This is the
//!    NON-VACUOUS gate (the hash is transported, so the check can actually NACK,
//!    unlike re-hashing the bytes and comparing them to their own hash). The bare
//!    [`Consumer::prepare`] default serves in-process callers without a separately
//!    transported hash: it derives the identity hash from the bytes and routes the
//!    SAME `prepare_verified` path (its verify cannot NACK on this entry, since the
//!    hash is of those exact bytes — the parse step below is then the fail-closed
//!    gate on malformed bytes).
//! 2. **Parse + validate via the embedded evaluator.** The verified bytes are
//!    parsed by `policy-core`'s schema layer ([`ds_contracts::pol1::parse_layer`],
//!    which runs the §8.1 structural validators — schema/syntax, the D53 rung-cap,
//!    `fail_open` legality, and the D74 mandatory-provenance checks — in one pass).
//!    Any rejection becomes a content-free [`PrepareError::SchemaInvalid`]. The
//!    parsed layer is then composed into the live evaluator shape
//!    ([`policy_core::pol1_eval::compose`]) — the SAME `ComposedPolicy` the gate's
//!    `dns_admission_decision` queries.
//! 3. **Stage, never flip.** The composed evaluator is parked in a SEPARATE,
//!    not-yet-active slot keyed by the snapshot identity; the gate keeps answering
//!    DNS admissions from the CURRENT (`vN`) slot. `prepare` returns an opaque
//!    [`ApplyToken`] carrying `(seq, content_hash)`; only the matching `commit`
//!    flips the staged evaluator live.
//!
//! # This unit: the COMMIT hook (atomic flip vN → vN+1, fail-closed + idempotent)
//!
//! [`Consumer::commit`] is the substance of POL-4 part 2c. It takes the
//! [`ApplyToken`] `prepare` returned and ATOMICALLY flips the gate from the
//! currently-serving `vN` evaluator to the staged `vN+1` one (D72, doc 13 §5):
//!
//! 1. **Take the token, find the matching stage.** A token that names no
//!    currently-staged snapshot (or a different one) is fail-closed
//!    [`ApplyError::UnknownToken`] — the gate never flips an unstaged version.
//! 2. **Atomic pointer swap.** The flip is one `RwLock` write that swaps the
//!    live `Arc<Evaluator>`. A concurrent admission reader holds a clone of the
//!    old `Arc` (taken under a read guard, never across the query) and sees the
//!    WHOLE old document, or the whole new one — never a torn evaluator. `vN`
//!    admissions are never interrupted: in-flight queries finish on `vN`, and
//!    every query that begins AFTER the swap returns observes `vN+1`.
//! 3. **Revert to `vN` on a flip fault.** If the swap cannot be made observable
//!    (a guard fault, modelled here by an injectable commit fault so the
//!    fail-closed contract is exercised), the gate stays on `vN`, leaves the
//!    stage intact for a re-drive, and returns [`ApplyError::CommitFailed`] —
//!    aborting the apply at the consumer level so the host driver detects it and
//!    aborts host-wide. The gate never half-flips.
//! 4. **Idempotent on the token.** A second `commit` with the same token (a
//!    re-driven barrier) is a no-op success — the second call sees `vN+1`
//!    already live and does not flip again.
//!
//! Commit returns success ONLY after the flip is observable to new traffic (the
//! write guard is dropped before it returns). `applied_seq` does NOT advance on
//! commit — only the post-commit sweep advances it (D72).
//!
//! `sweep_and_advance_applied_seq` (the post-commit revocation sweep) completes
//! the barrier; it is implemented here minimally so the type is a complete,
//! testable [`Consumer`], but the admitter-last sequencing, the sweep's
//! derived-state walk, and `applied_seq` heartbeat min are driven/elaborated by
//! the host apply driver and the sibling POL-4 units.
//!
//! NEVER-LOG-THE-SECRET: nothing here logs the composed document; the bytes cross
//! as opaque input and the error surfaces carry only structural reasons.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ds_contracts::consumer::{ApplyError, ApplyToken, Consumer, PolicyVersion, PrepareError};
use ds_contracts::pol1::{self, PolicyLayer};
use ds_contracts::snapshot_verify::{self, ContentHash};
use policy_core::pol1_eval::{self, ComposedPolicy};

use crate::policy::{PolicyCorePolicy, TtlClamp};
use crate::server::{LiveAdmissions, SweepEnforcer};
use crate::sweep::{sweep_revocations, SweepReport};

/// The set of capabilities currently present when composing a staged evaluator.
///
/// POL-1 v0 has no capability-providing component live yet (TLS-6's
/// `http-policy` lands later), so the gate composes with an EMPTY capability set:
/// a baseline-pack entry whose `requires:` is absent is tagged INERT (§1.7,
/// admits nothing) rather than silently over-admitting. This mirrors the gate's
/// existing handler-side composition; staging never changes the capability gate.
const AVAILABLE_CAPABILITIES: &[&str] = &[];

/// The gate's embedded admission evaluator — the composed `policy-core` document
/// the gate's `dns_admission_decision` queries. Wrapping `ComposedPolicy` in a
/// named type keeps the staged/live slots self-documenting and lets the
/// pointer-swap commit move an `Arc<Evaluator>` atomically.
#[derive(Debug)]
pub struct Evaluator {
    composed: ComposedPolicy,
}

impl Evaluator {
    /// Build a gate evaluator from a validated POL-1 layer by composing it into
    /// the deny-wins document `policy-core` evaluates (§1.2). The layer has
    /// already passed [`pol1::parse_layer`]'s structural validators by the time
    /// this is called from `prepare` (or by a caller that seeds the consumer's
    /// initial `vN` evaluator from a parsed boot layer).
    pub fn from_layer(layer: &PolicyLayer) -> Evaluator {
        Evaluator {
            composed: pol1_eval::compose(std::slice::from_ref(layer), AVAILABLE_CAPABILITIES),
        }
    }

    /// The composed document this evaluator serves — the input the gate's
    /// `consumer::dns_admission_decision` routes a query through.
    #[must_use]
    pub fn composed(&self) -> &ComposedPolicy {
        &self.composed
    }
}

/// One staged-but-not-yet-active evaluator, parked by `prepare` and consumed by
/// the matching `commit`. Keyed by the [`ApplyToken`] so a presented token can
/// only flip the exact `(seq, content_hash)` its `prepare` validated (no
/// cross-snapshot reuse), and so a re-driven barrier re-presenting the same token
/// is recognised (idempotence on the token).
#[derive(Clone)]
struct Staged {
    token: ApplyToken,
    evaluator: Arc<Evaluator>,
}

/// ds-dnsgate's [`Consumer`] implementor — the admitter's two-phase apply state.
///
/// It holds three pieces of state, all behind the per-consumer atomic-flip
/// contract (D72):
/// - `live` — the `vN` evaluator the gate currently serves admissions from. The
///   commit is a single `RwLock` write that swaps the `Arc`, so a reader either
///   sees the whole old evaluator or the whole new one — never a torn document.
/// - `staged` — the at-most-one prepared `vN+1` evaluator awaiting commit. A new
///   `prepare` atomically REPLACES any earlier staged slot (the host only ever
///   has one apply in flight per consumer; a superseded stage is simply dropped).
/// - `applied_seq` — advanced LAST, only after the post-commit sweep completes
///   (D72); the host heartbeat reports the MIN over the three consumers.
pub struct PolicyConsumer {
    live: RwLock<Arc<Evaluator>>,
    staged: Mutex<Option<Staged>>,
    committed: Mutex<Option<ApplyToken>>,
    applied_seq: AtomicU64,
    /// Injected commit-flip fault. When set, the next `commit` (for a not-yet
    /// committed token) detects the flip as un-makeable BEFORE swapping `live`,
    /// reverts to `vN` (the stage is left intact), and returns
    /// [`ApplyError::CommitFailed`]. This is the in-process stand-in for a real
    /// pointer-swap-guard fault, so the fail-closed/abort-at-consumer contract is
    /// exercised without a framework error type crossing the seam. Default
    /// `false`: a healthy gate always flips.
    commit_fault: AtomicBool,
    /// The POST-COMMIT REVOCATION SWEEP context (POL-4 part 3; D72/D53). `None` for
    /// the bare two-phase consumer (the prepare/commit-only callers, unchanged); `Some`
    /// when `main` (or a test) BINDS the live derived-state registry + the gate's
    /// re-sourced running evaluator + the enforcement surface via
    /// [`with_revocation_sweep`](Self::with_revocation_sweep). When bound,
    /// [`Self::commit`] also re-sources the bound [`PolicyCorePolicy`] to the staged
    /// `vN+1` (so the sweep re-evaluates against the NEW policy version), and
    /// [`Self::sweep_and_advance_applied_seq`] RUNS the sweep — re-evaluating both the
    /// DNS-2b admissions AND the parked ask-grants off the ONE shared reverse index,
    /// evicting what `vN+1` denies, and severing rung-conditionally through the ONE
    /// shared `flush_session` — BEFORE advancing `applied_seq` (D72: the seq advances
    /// only post-sweep). A bare consumer's sweep is the trivial advance (nothing to
    /// re-decide); a bound consumer's is the real eviction the heartbeat MIN feeds from.
    sweep_ctx: Option<SweepContext>,
}

/// The bound post-commit revocation-sweep context — the live derived-state registry the
/// sweep re-evaluates, the gate's re-sourced running evaluator it decides against, and the
/// enforcement surface the [`crate::server::SweepOutcome`] is routed to. Shared-handle
/// clones: the registry is the SAME one the W1/W2 transaction mints into and the POL-5
/// approval path parks grants in (`crate::server::RunningGate::live_admissions`); the
/// evaluator is the SAME shared `Arc` the gate's handlers read (so the commit's re-source
/// is observed by the sweep AND the hot path at once); the enforcer is the reportable
/// recorder by default, or the production `ds_nft::NftWriter` adapter behind `DS_NFTGATE_LIVE`.
struct SweepContext {
    admissions: LiveAdmissions,
    evaluator: PolicyCorePolicy,
    enforcer: Arc<dyn SweepEnforcer>,
}

impl PolicyConsumer {
    /// Create a consumer already serving an initial `vN` evaluator (the gate's
    /// boot snapshot). A booting host serves nothing beyond NFT-1 default-deny
    /// before its first verified snapshot; this constructor is fed that first
    /// verified, composed layer.
    #[must_use]
    pub fn new(initial: Evaluator, initial_seq: PolicyVersion) -> PolicyConsumer {
        PolicyConsumer {
            live: RwLock::new(Arc::new(initial)),
            staged: Mutex::new(None),
            committed: Mutex::new(None),
            applied_seq: AtomicU64::new(initial_seq.seq()),
            commit_fault: AtomicBool::new(false),
            sweep_ctx: None,
        }
    }

    /// Create a consumer WITH the post-commit revocation sweep wired (POL-4 part 3;
    /// D72/D53). Binds the live derived-state registry the sweep re-evaluates (the SAME
    /// [`LiveAdmissions`] the W1/W2 transaction mints into and the POL-5 approval path parks
    /// ask-grants in — `main` hands `crate::server::RunningGate::live_admissions`), the gate's
    /// re-sourced running evaluator (a shared-handle [`PolicyCorePolicy`] clone — the commit
    /// re-sources it to `vN+1` so the sweep decides against the NEW policy version), and the
    /// enforcement surface the [`crate::server::SweepOutcome`] is routed to (the reportable
    /// recorder, or the production `ds_nft::NftWriter` adapter behind `DS_NFTGATE_LIVE`).
    ///
    /// With this bound, `commit` re-sources the evaluator AND `sweep_and_advance_applied_seq`
    /// RUNS the eviction (both legs, severing rung-conditionally through the ONE shared
    /// `flush_session`) BEFORE advancing `applied_seq` — so the seq the host heartbeat reports
    /// as MIN over the three consumers advances ONLY post-sweep (D72). The bare
    /// [`new`](Self::new) consumer is unchanged (its sweep is the trivial advance).
    #[must_use]
    pub fn with_revocation_sweep(
        initial: Evaluator,
        initial_seq: PolicyVersion,
        admissions: LiveAdmissions,
        evaluator: PolicyCorePolicy,
        enforcer: Arc<dyn SweepEnforcer>,
    ) -> PolicyConsumer {
        PolicyConsumer {
            live: RwLock::new(Arc::new(initial)),
            staged: Mutex::new(None),
            committed: Mutex::new(None),
            applied_seq: AtomicU64::new(initial_seq.seq()),
            commit_fault: AtomicBool::new(false),
            sweep_ctx: Some(SweepContext {
                admissions,
                evaluator,
                enforcer,
            }),
        }
    }

    /// Arm/disarm the injected commit-flip fault (see [`Self::commit_fault`]).
    /// Operationally a no-op the gate never sets in steady state; it makes the
    /// `commit` revert-to-`vN` / [`ApplyError::CommitFailed`] path observable so
    /// the fail-closed abort-at-consumer contract is tested rather than asserted.
    pub fn set_commit_fault(&self, armed: bool) {
        self.commit_fault.store(armed, Ordering::SeqCst);
    }

    /// The evaluator currently SERVING admissions (`vN`). A clone of the `Arc`, so
    /// the caller holds the live document without keeping the `RwLock` read guard
    /// across a query.
    #[must_use]
    pub fn live(&self) -> Arc<Evaluator> {
        Arc::clone(&self.live.read().expect("live evaluator lock poisoned"))
    }

    /// The current `applied_seq` (advanced only after a completed sweep; D72).
    #[must_use]
    pub fn applied_seq(&self) -> PolicyVersion {
        PolicyVersion(self.applied_seq.load(Ordering::SeqCst))
    }

    /// Parse + structurally validate verified snapshot bytes into a gate
    /// evaluator, mapping a `policy-core` rejection onto a content-free
    /// [`PrepareError::SchemaInvalid`]. Shared by `prepare`; pulled out so the
    /// validate→compose step has one home.
    fn validate_and_build(
        snapshot: &[u8],
        version: PolicyVersion,
    ) -> Result<Evaluator, PrepareError> {
        // The transported bytes are UTF-8 POL-1 document text. A non-UTF-8 body
        // is a schema rejection (the reader only accepts text); never logged.
        let text = std::str::from_utf8(snapshot).map_err(|_| PrepareError::SchemaInvalid {
            version,
            reason: "snapshot bytes are not valid UTF-8 policy text".to_string(),
        })?;
        // `parse_layer` runs the §8.1 structural validators (schema/syntax, D53
        // rung-cap, fail_open legality, D74 mandatory provenance) in one pass.
        let layer = pol1::parse_layer(text).map_err(|errs| PrepareError::SchemaInvalid {
            version,
            // Content-free: the rejection CODES (never the document body) — the
            // first code names the structural class, the count gives the rest.
            reason: summarize_policy_errors(&errs),
        })?;
        Ok(Evaluator::from_layer(&layer))
    }
}

/// Render a `policy-core` rejection bundle as a short, CONTENT-FREE reason: the
/// structural error codes only (never the offending document text), suitable for
/// the [`PrepareError::SchemaInvalid`] reason field and a log line.
fn summarize_policy_errors(errs: &pol1::PolicyErrors) -> String {
    let first = errs
        .0
        .first()
        .map(|e| format!("{:?}", e.code))
        .unwrap_or_else(|| "Syntax".to_string());
    format!(
        "policy-core rejected snapshot: {first} (+{} more)",
        errs.0.len().saturating_sub(1)
    )
}

impl Consumer for PolicyConsumer {
    fn prepare(&self, snapshot: &[u8], version: PolicyVersion) -> Result<ApplyToken, PrepareError> {
        // In-process entry (no separately-transported hash): derive the identity
        // hash from the bytes and route through `prepare_verified` so the ONE
        // parse+stage path is shared. The derived hash is the hash of these exact
        // bytes, so the verify there cannot NACK on this path — the NON-VACUOUS gate
        // is `prepare_verified` against a SEPARATELY transported hash (the feed path).
        let expected_hash = snapshot_verify::sha256(snapshot);
        self.prepare_verified(snapshot, version, &expected_hash)
    }

    fn prepare_verified(
        &self,
        snapshot: &[u8],
        version: PolicyVersion,
        expected_hash: &ContentHash,
    ) -> Result<ApplyToken, PrepareError> {
        // (1) NON-VACUOUS fail-closed identity gate FIRST: verify the transported
        // bytes against the SEPARATELY-transported `expected_hash` the producer
        // pinned over those exact bytes (doc 13 §5.1) — exactly as the host-local
        // feed verifies the `content_hash` before prepare. A mismatch is fail-closed
        // [`PrepareError::HashMismatch`]: parse + stage NEVER run on bytes that do
        // not hash to the transported identity, so the admission map / live
        // evaluator are untouched and the gate stays on vN. (The transported hash
        // makes this real: re-hashing the bytes and comparing to their own hash can
        // never NACK.)
        if !snapshot_verify::verify_snapshot_bytes(snapshot, expected_hash).is_verified() {
            return Err(PrepareError::HashMismatch { version });
        }

        // (2) Parse + validate via the embedded policy-core evaluator, then
        // compose the staged evaluator. A rejection aborts the host-wide apply.
        let evaluator = PolicyConsumer::validate_and_build(snapshot, version)?;

        // (3) Stage — never flip. Park the new evaluator in the not-yet-active
        // slot; the gate keeps serving vN from `live`. Replacing any earlier
        // staged slot is atomic (one mutex section); a superseded stage drops. The
        // token pins the VERIFIED transported hash.
        let token = ApplyToken::new(version, *expected_hash);
        *self.staged.lock().expect("staged slot lock poisoned") = Some(Staged {
            token: token.clone(),
            evaluator: Arc::new(evaluator),
        });
        Ok(token)
    }

    fn commit(&self, token: &ApplyToken) -> Result<(), ApplyError> {
        // (1) Idempotent on the token: an already-committed token is a no-op
        // success — the second call sees vN+1 already live (a re-driven barrier
        // never double-flips).
        if self
            .committed
            .lock()
            .expect("committed lock poisoned")
            .as_ref()
            == Some(token)
        {
            return Ok(());
        }
        // Find the matching stage. A token naming no currently-staged snapshot
        // (or a different one) is fail-closed — never flip an unstaged version.
        let staged = self
            .staged
            .lock()
            .expect("staged slot lock poisoned")
            .clone();
        let Some(staged) = staged else {
            return Err(ApplyError::UnknownToken {
                version: token.version(),
            });
        };
        if &staged.token != token {
            return Err(ApplyError::UnknownToken {
                version: token.version(),
            });
        }

        // (2) Revert-to-vN on a flip fault. Detect an un-makeable flip BEFORE
        // touching `live`: the gate stays on vN, the stage is left intact for a
        // re-drive, and CommitFailed aborts the apply at the consumer level so
        // the host driver detects it and aborts host-wide. The gate never
        // half-flips.
        if self.commit_fault.load(Ordering::SeqCst) {
            return Err(ApplyError::CommitFailed {
                version: token.version(),
                reason: "evaluator pointer-swap guard refused the flip".to_string(),
            });
        }

        // (3) Atomic flip: one RwLock write swaps the live Arc. A concurrent
        // reader holds a clone of the old Arc (taken under a read guard, never
        // across the query) and sees the WHOLE old evaluator, or the whole new
        // one — never torn. In-flight vN admissions finish on vN; the write guard
        // is dropped before commit returns, so every query that begins after the
        // return observes vN+1 — the committed evaluator is immediately
        // observable to new traffic.
        // Re-source the bound running evaluator to vN+1 BEFORE recording the commit, when a
        // sweep is wired: the post-commit sweep must decide against the NEW policy version
        // (admitter-LAST → sweep, D72). A shared-handle clone, so the gate's hot path and the
        // sweep observe the SAME re-source. The bound evaluator is the policy-document twin of
        // this consumer's own `Evaluator` flip — the same composed `vN+1` document. (The bare
        // two-phase consumer has no bound evaluator and skips this.)
        if let Some(ctx) = &self.sweep_ctx {
            ctx.evaluator
                .reload(staged.evaluator.composed().clone(), TtlClamp::DEFAULT);
        }
        *self.live.write().expect("live evaluator lock poisoned") = staged.evaluator;
        *self.committed.lock().expect("committed lock poisoned") = Some(token.clone());
        *self.staged.lock().expect("staged slot lock poisoned") = None;
        Ok(())
    }

    fn sweep_and_advance_applied_seq(
        &self,
        token: &ApplyToken,
    ) -> Result<PolicyVersion, ApplyError> {
        // The sweep runs only on a token this consumer committed.
        if self
            .committed
            .lock()
            .expect("committed lock poisoned")
            .as_ref()
            != Some(token)
        {
            return Err(ApplyError::UnknownToken {
                version: token.version(),
            });
        }
        // Idempotent: applied_seq already at this version → no re-sweep (D72).
        if self.applied_seq.load(Ordering::SeqCst) == token.version().seq() {
            return Ok(token.version());
        }
        // RUN the post-commit revocation sweep BEFORE advancing applied_seq (D72: the seq
        // advances ONLY after the sweep completes). When a sweep is wired (`main` bound the
        // live registry + the re-sourced evaluator + the enforcer), this re-evaluates BOTH
        // legs — the DNS-2b admissions AND the parked ask-grants — against the just-committed
        // vN+1 off the ONE shared reverse index, evicts what vN+1 denies, and severs
        // rung-conditionally through the ONE shared `flush_session`. The bare two-phase
        // consumer has no bound registry, so its sweep is the trivial advance (nothing to
        // re-decide). Either way `applied_seq` advances ONLY after this returns.
        let _report: SweepReport = match &self.sweep_ctx {
            Some(ctx) => sweep_revocations(
                &ctx.admissions,
                &ctx.evaluator,
                token.version().seq(),
                ctx.enforcer.as_ref(),
            ),
            None => SweepReport {
                swept_seq: token.version().seq(),
                ..SweepReport::default()
            },
        };
        // applied_seq advances LAST — only now, after the eviction completed (D72).
        self.applied_seq.store(_report.swept_seq, Ordering::SeqCst);
        Ok(PolicyVersion(_report.swept_seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clean POL-1 session layer that stages successfully.
    const VALID_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                             dns:\n  boundary_zone: corp.example.\n";

    /// A POL-1 document that violates the D53 rung-cap (a generic content rule
    /// above block+log) — the embedded validator must REJECT it at prepare.
    const RUNG_CAP_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
         content:\n  generic:\n    rules:\n      - id: r1\n        match: badword\n        \
         rung: kill+snapshot\n";

    fn consumer_at(seq: u64, doc: &str) -> PolicyConsumer {
        let layer = pol1::parse_layer(doc).expect("seed layer parses");
        PolicyConsumer::new(Evaluator::from_layer(&layer), PolicyVersion(seq))
    }

    #[test]
    fn valid_snapshot_stages_without_serving_traffic() {
        let c = consumer_at(1, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());

        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: beta.example.\n";
        let token = c
            .prepare(next.as_bytes(), PolicyVersion(2))
            .expect("valid stages");
        assert_eq!(token.version(), PolicyVersion(2));
        assert_eq!(token.content_hash, snapshot_verify::sha256(next.as_bytes()));

        // The staged evaluator does NOT serve traffic: the live pointer and the
        // served document are unchanged until commit, and applied_seq is still vN.
        assert_eq!(
            Arc::as_ptr(&c.live()),
            live_before,
            "stage must not flip live"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(1));
        assert!(
            c.staged.lock().unwrap().is_some(),
            "evaluator is parked, not active"
        );
    }

    #[test]
    fn invalid_snapshot_returns_error_and_leaves_the_running_evaluator_unchanged() {
        let c = consumer_at(5, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());

        let err = c
            .prepare(RUNG_CAP_DOC.as_bytes(), PolicyVersion(6))
            .expect_err("rung-cap violation must be rejected");
        match err {
            PrepareError::SchemaInvalid { version, reason } => {
                assert_eq!(version, PolicyVersion(6));
                // Content-free: names the structural code, never the document.
                assert!(reason.contains("GenericRungCap"), "reason={reason}");
                assert!(!reason.contains("badword"), "reason must not echo doc body");
            }
            other => panic!("expected SchemaInvalid, got {other:?}"),
        }
        // Fail-closed: nothing staged, the running evaluator and seq are untouched.
        assert_eq!(Arc::as_ptr(&c.live()), live_before);
        assert_eq!(c.applied_seq(), PolicyVersion(5));
        assert!(
            c.staged.lock().unwrap().is_none(),
            "no partial staging on reject"
        );
    }

    #[test]
    fn non_utf8_and_garbage_bytes_are_rejected_fail_closed() {
        let c = consumer_at(1, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());

        // Non-UTF-8 bytes.
        match c.prepare(&[0xff, 0xfe, 0x00], PolicyVersion(2)) {
            Err(PrepareError::SchemaInvalid { version, .. }) => {
                assert_eq!(version, PolicyVersion(2))
            }
            other => panic!("expected SchemaInvalid for non-utf8, got {other:?}"),
        }
        // Garbage text the POL-1 reader cannot interpret.
        match c.prepare(b"\t\tnot: a: policy", PolicyVersion(3)) {
            Err(PrepareError::SchemaInvalid { .. }) => {}
            other => panic!("expected SchemaInvalid for garbage, got {other:?}"),
        }
        assert_eq!(Arc::as_ptr(&c.live()), live_before, "no flip on any reject");
        assert!(c.staged.lock().unwrap().is_none());
    }

    #[test]
    fn prepare_verified_nacks_a_transported_hash_mismatch_before_parse_or_stage() {
        // The NON-VACUOUS fail-closed identity gate (the substance of this unit): a
        // SEPARATELY-transported expected hash that does NOT match the bytes is
        // fail-closed PrepareError::HashMismatch — parse + stage NEVER run, so the
        // admission map / running evaluator + applied_seq are untouched and nothing
        // is staged (the gate stays on vN).
        let c = consumer_at(5, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());

        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        // A hash that does NOT match `next` (one flipped byte) — the producer
        // pinned a different identity than the transported bytes carry.
        let mut wrong = snapshot_verify::sha256(next.as_bytes());
        wrong[0] ^= 0x01;

        match c.prepare_verified(next.as_bytes(), PolicyVersion(6), &wrong) {
            Err(PrepareError::HashMismatch { version }) => assert_eq!(version, PolicyVersion(6)),
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        // Fail-closed: no parse/stage residue — running evaluator + seq untouched,
        // nothing staged (admission map untouched).
        assert_eq!(
            Arc::as_ptr(&c.live()),
            live_before,
            "no flip on hash mismatch"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(5));
        assert!(
            c.staged.lock().unwrap().is_none(),
            "a hash-failing snapshot must never stage (no parse/stage residue)"
        );

        // The MATCHING transported hash still stages exactly as today (happy path
        // unchanged), pinning the verified transported hash on the token.
        let token = c
            .prepare_verified(
                next.as_bytes(),
                PolicyVersion(6),
                &snapshot_verify::sha256(next.as_bytes()),
            )
            .expect("matching transported hash stages");
        assert_eq!(token.version(), PolicyVersion(6));
        assert_eq!(token.content_hash, snapshot_verify::sha256(next.as_bytes()));
        assert!(
            c.staged.lock().unwrap().is_some(),
            "the verified snapshot is staged"
        );
        // Still only STAGED — the live evaluator did not flip.
        assert_eq!(Arc::as_ptr(&c.live()), live_before);
        assert_eq!(c.applied_seq(), PolicyVersion(5));
    }

    #[test]
    fn prepare_default_forwards_to_the_verified_gate_and_stages_as_today() {
        // The bare `prepare(snapshot, version)` default derives the hash from the
        // bytes and forwards to prepare_verified — the in-process no-separate-hash
        // entry. It stages exactly as before (happy path unchanged), pinning the
        // bytes' identity hash on the token.
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: beta.example.\n";
        let token = c
            .prepare(next.as_bytes(), PolicyVersion(2))
            .expect("default forwarder stages");
        assert_eq!(
            token.content_hash,
            snapshot_verify::sha256(next.as_bytes()),
            "default forwarder pins the bytes' identity hash"
        );
        assert!(c.staged.lock().unwrap().is_some());
    }

    #[test]
    fn staging_multiple_snapshots_atomically_replaces_the_staged_slot() {
        let c = consumer_at(1, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());

        let a = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                 dns:\n  boundary_zone: a.example.\n";
        let b = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                 dns:\n  boundary_zone: b.example.\n";
        let ta = c.prepare(a.as_bytes(), PolicyVersion(2)).expect("stage a");
        let tb = c.prepare(b.as_bytes(), PolicyVersion(3)).expect("stage b");

        // The second stage REPLACED the first; the staged slot holds only b, and
        // vN traffic is unaffected throughout (live never moved).
        assert_ne!(ta, tb);
        let staged = c.staged.lock().unwrap().clone().expect("one staged slot");
        assert_eq!(staged.token, tb);
        assert_eq!(
            Arc::as_ptr(&c.live()),
            live_before,
            "no flip across re-stage"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(1));
    }

    #[test]
    fn commit_flips_atomically_only_after_prepare_and_sweep_advances_applied_seq() {
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");

        // applied_seq does NOT advance on commit — only after sweep (D72).
        c.commit(&token).expect("commit");
        assert_eq!(c.applied_seq(), PolicyVersion(1));
        // The live evaluator now serves vN+1 (the staged document).
        assert_eq!(c.live().composed().policy_version, "pol1/v0".to_string());
        assert!(
            c.staged.lock().unwrap().is_none(),
            "staged slot consumed on commit"
        );

        let swept = c.sweep_and_advance_applied_seq(&token).expect("sweep");
        assert_eq!(swept, PolicyVersion(2));
        assert_eq!(c.applied_seq(), PolicyVersion(2));
    }

    #[test]
    fn commit_and_sweep_are_idempotent_on_token_and_reject_unstaged_tokens() {
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        c.commit(&token).expect("commit 1");
        c.commit(&token).expect("commit 2 (idempotent no-op)");
        c.sweep_and_advance_applied_seq(&token).expect("sweep 1");
        c.sweep_and_advance_applied_seq(&token)
            .expect("sweep 2 (idempotent)");
        assert_eq!(c.applied_seq(), PolicyVersion(2));

        // A token this consumer never staged is fail-closed.
        let foreign = ApplyToken::new(PolicyVersion(99), snapshot_verify::sha256(b"x"));
        match c.commit(&foreign) {
            Err(ApplyError::UnknownToken { version }) => assert_eq!(version, PolicyVersion(99)),
            other => panic!("expected UnknownToken, got {other:?}"),
        }
    }

    #[test]
    fn commit_flip_is_observable_to_new_traffic_without_interrupting_vn() {
        // The gate's vN evaluator serves admissions from the boot snapshot; the
        // commit flip must be immediately observable to a query that begins after
        // commit returns, while a clone of the vN Arc taken BEFORE the flip (the
        // analog of an in-flight admission) keeps serving the whole vN document.
        let c = consumer_at(1, VALID_DOC);
        let in_flight_vn = c.live(); // an admission that began on vN
        let vn_ptr = Arc::as_ptr(&in_flight_vn);

        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        // Before commit, new traffic still observes vN.
        assert_eq!(Arc::as_ptr(&c.live()), vn_ptr, "pre-commit serves vN");

        c.commit(&token).expect("commit");

        // After commit returns, new traffic observes vN+1 (a different evaluator),
        // and the in-flight vN handle is untouched — vN was never interrupted.
        let new_traffic = c.live();
        assert_ne!(Arc::as_ptr(&new_traffic), vn_ptr, "new traffic sees vN+1");
        assert_eq!(
            Arc::as_ptr(&in_flight_vn),
            vn_ptr,
            "the in-flight vN admission is never torn or interrupted"
        );
    }

    #[test]
    fn commit_flip_fault_reverts_to_vn_fail_closed_and_unblocks_host_abort() {
        let c = consumer_at(7, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(8)).expect("stage");

        // Arm the flip fault: commit must abort at the consumer level (CommitFailed),
        // leaving the gate fully on vN so the host driver detects it and aborts.
        c.set_commit_fault(true);
        match c.commit(&token) {
            Err(ApplyError::CommitFailed { version, reason }) => {
                assert_eq!(version, PolicyVersion(8));
                assert!(!reason.is_empty());
                assert!(
                    !reason.contains("next.example"),
                    "reason must not echo doc body"
                );
            }
            other => panic!("expected CommitFailed, got {other:?}"),
        }
        // Fail-closed: still serving vN, applied_seq untouched, stage left intact
        // for the re-drive, nothing recorded as committed.
        assert_eq!(Arc::as_ptr(&c.live()), live_before, "gate stays on vN");
        assert_eq!(c.applied_seq(), PolicyVersion(7));
        assert!(
            c.staged.lock().unwrap().is_some(),
            "stage left intact for re-drive"
        );
        assert!(
            c.committed.lock().unwrap().is_none(),
            "no half-commit recorded"
        );

        // Disarming and re-driving commits cleanly (make-before-break recovery).
        c.set_commit_fault(false);
        c.commit(&token).expect("re-driven commit succeeds");
        assert_ne!(Arc::as_ptr(&c.live()), live_before, "now serving vN+1");
    }

    #[test]
    fn commit_is_idempotent_after_a_following_prepare_does_not_resurrect_an_old_flip() {
        // A committed token stays a no-op success even after a NEW prepare stages
        // a later snapshot: idempotence keys on the committed token, not the stage.
        let c = consumer_at(1, VALID_DOC);
        let two = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                   dns:\n  boundary_zone: two.example.\n";
        let t2 = c
            .prepare(two.as_bytes(), PolicyVersion(2))
            .expect("stage 2");
        c.commit(&t2).expect("commit 2");
        let after_two = Arc::as_ptr(&c.live());

        let three = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                     dns:\n  boundary_zone: three.example.\n";
        let _t3 = c
            .prepare(three.as_bytes(), PolicyVersion(3))
            .expect("stage 3");
        // Re-presenting the already-committed t2 is still a no-op success and must
        // NOT flip away from vN+1=2 to the freshly staged v3.
        c.commit(&t2).expect("commit 2 again (idempotent)");
        assert_eq!(
            Arc::as_ptr(&c.live()),
            after_two,
            "idempotent commit never re-flips"
        );
    }

    #[test]
    fn consumer_is_usable_through_a_trait_object() {
        let seed = pol1::parse_layer(VALID_DOC).expect("parses");
        let c: Box<dyn Consumer> = Box::new(PolicyConsumer::new(
            Evaluator::from_layer(&seed),
            PolicyVersion(0),
        ));
        let token = c
            .prepare(VALID_DOC.as_bytes(), PolicyVersion(1))
            .expect("prepare");
        c.commit(&token).expect("commit");
        assert_eq!(
            c.sweep_and_advance_applied_seq(&token).expect("sweep"),
            PolicyVersion(1)
        );
    }
}
