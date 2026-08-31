// SPDX-License-Identifier: Apache-2.0

//! ds-tlsproxy's side of the FROZEN D72 two-phase apply barrier (POL-4 part 2;
//! D72/D36, doc 13 §5, doc 15 §5.2).
//!
//! ds-tlsproxy is an **enforcer** — one of the two consumers the host commits
//! BEFORE the admitter (ds-tlsproxy + the NFT flip move to `vN+1` first, so every
//! transient mixed-version window is FAIL-CLOSED: the egress gateway is already on
//! the at-least-as-strict `vN+1` before ds-dnsgate starts admitting under it,
//! make-before-break). This module implements the
//! [`ds_contracts::consumer::Consumer`] seam against the proxy's embedded
//! `policy-core` evaluator — the SAME engine the TLS-2 explicit path's
//! `consumer::tls_connect_decision` reaches (no consumer reimplements a rule).
//!
//! # This unit: the PREPARE hook (validate + stage while serving vN)
//!
//! [`Consumer::prepare`] is the substance here (doc 13 §5; the seam's only
//! fallible-by-design phase), fail-closed end to end:
//!
//! 1. **Verify the snapshot identity** against the TRANSPORTED `content_hash` the
//!    producer pinned (the additive [`Consumer::prepare_verified`] seam): the bytes
//!    are run through [`ds_contracts::snapshot_verify::verify_snapshot_bytes`]
//!    against the SEPARATELY-transported expected hash BEFORE parse, exactly as
//!    `snapshot_feed.rs`'s envelope path verifies the `content_hash` before prepare.
//!    A mismatch is a fail-closed [`PrepareError::HashMismatch`] and parse + stage
//!    never run — the NON-VACUOUS gate (the hash comes from the producer, so it can
//!    actually NACK; re-hashing the bytes and comparing to their own hash never
//!    could). The verified hash is stamped into the [`ApplyToken`]. The in-process
//!    [`Consumer::prepare`] entry (no separately-transported hash — a host-wiring
//!    layer that verified upstream, or a test minting well-formed bytes) derives the
//!    identity hash from the bytes and routes the SAME `prepare_verified` path.
//! 2. **Parse + validate via the embedded evaluator.** The verified bytes are
//!    parsed by `policy-core`'s schema layer
//!    ([`ds_contracts::pol1::parse_layer`], which runs the §8.1 structural
//!    validators — schema/syntax, the D53 rung-cap, `fail_open` legality, and the
//!    D74 mandatory-provenance checks — in one pass); a rejection becomes a
//!    content-free [`PrepareError::SchemaInvalid`]. The parsed layer is composed
//!    into the live evaluator shape ([`policy_core::pol1_eval::compose`]) — the
//!    `ComposedPolicy` the proxy's `tls_connect_decision` queries.
//! 3. **Stage, never flip.** The composed evaluator parks in a SEPARATE,
//!    not-yet-active slot keyed by the snapshot identity; the proxy keeps deciding
//!    egress connects from the CURRENT (`vN`) slot. `prepare` returns an opaque
//!    [`ApplyToken`] carrying `(seq, content_hash)`; only the matching `commit`
//!    flips the staged evaluator live.
//!
//! # This unit: the COMMIT hook (atomic flip vN → vN+1, fail-closed + idempotent)
//!
//! [`Consumer::commit`] is the substance of POL-4 part 2c. It takes the
//! [`ApplyToken`] `prepare` returned and ATOMICALLY flips the proxy from the
//! currently-serving `vN` evaluator to the staged `vN+1` one (D72, doc 13 §5):
//!
//! 1. **Take the token, find the matching stage.** A token that names no
//!    currently-staged snapshot (or a different one) is fail-closed
//!    [`ApplyError::UnknownToken`] — the proxy never flips an unstaged version.
//! 2. **Atomic pointer swap.** The flip is one `RwLock` write that swaps the
//!    live `Arc<Evaluator>`. A concurrent `tls_connect_decision` reader holds a
//!    clone of the old `Arc` (taken under a read guard, never across the query)
//!    and sees the WHOLE old document or the whole new one — never torn. In-flight
//!    `vN` connect decisions finish on `vN`; every decision that begins AFTER the
//!    swap returns observes `vN+1`.
//! 3. **Revert to `vN` on a flip fault.** If the swap cannot be made observable
//!    (a guard fault, modelled here by an injectable commit fault so the
//!    fail-closed contract is exercised), the proxy stays on `vN`, leaves the
//!    stage intact for a re-drive, and returns [`ApplyError::CommitFailed`] —
//!    aborting the apply at the consumer level so the host driver detects it and
//!    aborts host-wide. As an enforcer committed BEFORE the admitter, the proxy
//!    staying on `vN` is at-least-as-strict as the still-`vN` admitter: the
//!    mixed-version window stays fail-closed. The proxy never half-flips.
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
//! testable [`Consumer`]. The sweep's tunnel/conntrack severing (rung-conditional,
//! D53, through the ONE shared [`ds_contracts::flush::FlushSession`] primitive)
//! and `applied_seq` heartbeat min are elaborated by the host apply driver and
//! the sibling POL-4 sweep unit.
//!
//! NEVER-LOG-THE-SECRET: nothing here logs the composed document; the bytes cross
//! as opaque input and the error surfaces carry only structural reasons. The
//! crate-root `#![forbid(unsafe_code)]` binds this module — the flip is safe-Rust
//! `Arc`/`RwLock` pointer-swap, no `unsafe`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ds_contracts::consumer::{ApplyError, ApplyToken, Consumer, PolicyVersion, PrepareError};
use ds_contracts::pol1::{self, Layer, PolicyLayer};
use ds_contracts::snapshot_verify;
use policy_core::pol1_eval::{self, ComposedPolicy};

use crate::scan::{
    GenericPack, GenericReloadEvent, GenericRule, InFlightStreams, SharedGenericPack,
};

/// Capabilities present when composing a staged evaluator. POL-1 v0 has no
/// capability-providing component live yet (TLS-6's `http-policy` lands later),
/// so composition uses the EMPTY set: a `requires:`-gated pack entry is tagged
/// INERT (§1.7, admits nothing) rather than silently over-admitting. Mirrors the
/// proxy's existing composition; staging never changes the capability gate.
const AVAILABLE_CAPABILITIES: &[&str] = &[];

/// The proxy's embedded egress-connect evaluator — the composed `policy-core`
/// document the proxy's `tls_connect_decision` queries. A named wrapper over
/// `ComposedPolicy` keeps the staged/live slots self-documenting and lets the
/// pointer-swap commit move an `Arc<Evaluator>` atomically.
#[derive(Debug)]
pub struct Evaluator {
    composed: ComposedPolicy,
}

impl Evaluator {
    /// Build a proxy evaluator from a validated POL-1 layer by composing it into
    /// the deny-wins document `policy-core` evaluates (§1.2). The layer has
    /// already passed [`pol1::parse_layer`]'s structural validators by the time
    /// this runs from `prepare`. Public so a host-wiring layer (and the POL-4 sweep
    /// integration test) can seed an initial `vN` [`PolicyConsumer`] from a parsed
    /// boot layer; the in-band `prepare` path stages every subsequent version.
    #[must_use]
    pub fn from_layer(layer: &PolicyLayer) -> Evaluator {
        Evaluator {
            composed: pol1_eval::compose(std::slice::from_ref(layer), AVAILABLE_CAPABILITIES),
        }
    }

    /// The composed document this evaluator serves — the input the proxy's
    /// `consumer::tls_connect_decision` routes a connect host through.
    #[must_use]
    pub fn composed(&self) -> &ComposedPolicy {
        &self.composed
    }
}

/// One staged-but-not-yet-active evaluator, parked by `prepare` and consumed by
/// the matching `commit`. Keyed by the [`ApplyToken`] so a presented token can
/// only flip the exact `(seq, content_hash)` its `prepare` validated (no
/// cross-snapshot reuse), and a re-driven barrier re-presenting the same token is
/// recognised (idempotence on the token).
#[derive(Clone)]
struct Staged {
    token: ApplyToken,
    evaluator: Arc<Evaluator>,
}

/// ds-tlsproxy's [`Consumer`] implementor — the egress-gateway enforcer's
/// two-phase apply state.
///
/// State held behind the per-consumer atomic-flip contract (D72):
/// - `live` — the `vN` evaluator the proxy currently decides egress connects
///   from. The commit is a single `RwLock` write swapping the `Arc`, so a reader
///   sees the whole old or the whole new evaluator — never a torn document.
/// - `staged` — the at-most-one prepared `vN+1` evaluator awaiting commit. A new
///   `prepare` atomically REPLACES any earlier staged slot (one apply in flight
///   per consumer; a superseded stage drops).
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
    /// [`ApplyError::CommitFailed`]. The in-process stand-in for a real
    /// pointer-swap-guard fault, exercising the fail-closed/abort-at-consumer
    /// contract without a framework error type crossing the seam. Default `false`.
    commit_fault: AtomicBool,
}

impl PolicyConsumer {
    /// Create a consumer already serving an initial `vN` evaluator (the proxy's
    /// first verified, composed boot snapshot). A booting host serves nothing
    /// beyond NFT-1 default-deny before its first verified snapshot.
    #[must_use]
    pub fn new(initial: Evaluator, initial_seq: PolicyVersion) -> PolicyConsumer {
        PolicyConsumer {
            live: RwLock::new(Arc::new(initial)),
            staged: Mutex::new(None),
            committed: Mutex::new(None),
            applied_seq: AtomicU64::new(initial_seq.seq()),
            commit_fault: AtomicBool::new(false),
        }
    }

    /// Arm/disarm the injected commit-flip fault (see [`Self::commit_fault`]).
    /// Operationally a no-op the proxy never sets in steady state; it makes the
    /// `commit` revert-to-`vN` / [`ApplyError::CommitFailed`] path observable so
    /// the fail-closed abort-at-consumer contract is tested rather than asserted.
    pub fn set_commit_fault(&self, armed: bool) {
        self.commit_fault.store(armed, Ordering::SeqCst);
    }

    /// The evaluator currently DECIDING egress connects (`vN`). A clone of the
    /// `Arc`, so the caller holds the live document without keeping the `RwLock`
    /// read guard across a query.
    #[must_use]
    pub fn live(&self) -> Arc<Evaluator> {
        Arc::clone(&self.live.read().expect("live evaluator lock poisoned"))
    }

    /// The current `applied_seq` (advanced only after a completed sweep; D72).
    #[must_use]
    pub fn applied_seq(&self) -> PolicyVersion {
        PolicyVersion(self.applied_seq.load(Ordering::SeqCst))
    }

    /// The POST-COMMIT REVOCATION SWEEP backed by REAL derived state (01KV9N17NN
    /// CV2-failclosed): sever the live tunnels + warm pooled upstream sockets the
    /// just-committed `vN+1` policy revokes, then advance `applied_seq` (D72: the seq
    /// advances ONLY after the sweep completes).
    ///
    /// This is the substantive sibling of the parameterless
    /// [`Consumer::sweep_and_advance_applied_seq`] (which runs the connect-decision
    /// no-op — correct, since allow/deny is a live evaluator query). The CONNECT
    /// opaque tunnel an admission established is derived state that OUTLIVES the
    /// commit: it keeps flowing until the client closes it. So a severing-rung
    /// (D53 block-or-higher) `vN+1` revocation must tear those flows down NOW — this
    /// drives the real [`crate::sweep::SeveringDerivedState`] over the live
    /// [`SeveringRegistry`] + per-session [`SessionUpstreamPools`] for the
    /// `revoked` set the host apply driver computed from the vN→vN+1 diff, through
    /// the SAME [`crate::sweep::sweep_revocations`] contract the no-op uses (so
    /// `applied_seq` still advances only post-sweep). It REPLACES the
    /// survivor-derived placeholder: a real flush, not a returned-zero.
    ///
    /// Fail-closed + idempotent: the token must be the committed one (else
    /// [`ApplyError::UnknownToken`]); a re-drive at the already-applied seq
    /// re-evaluates nothing (the sweep's flush is itself idempotent — a handle
    /// already severed counts once). `T` is the pooled upstream socket type.
    pub fn sweep_revocations<T>(
        &self,
        token: &ApplyToken,
        severing: &crate::SeveringRegistry,
        pools: &crate::SessionUpstreamPools<T>,
        revoked: &[crate::RevokedAdmission],
    ) -> Result<PolicyVersion, ApplyError> {
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
        // RUN the real severing sweep BEFORE advancing applied_seq (D72). The
        // SeveringDerivedState severs rung-conditionally through the ONE shared
        // FlushSession + drops the swept session's warm pool partition.
        let derived = crate::sweep::SeveringDerivedState::new(severing, pools, revoked);
        let report = crate::sweep::sweep_revocations(token.version().seq(), &derived);
        // applied_seq advances LAST — only now, after the sever completed (D72).
        self.applied_seq.store(report.swept_seq, Ordering::SeqCst);
        Ok(PolicyVersion(report.swept_seq))
    }

    /// The CONSUME side of the host-agent revocation-delta transport (doc 12 §8/§9):
    /// drive the post-commit revocation sweep from a delta the host fanned out over
    /// the host-local feed, identified ONLY by its `seq` (the transport carries the
    /// `(seq, revoked-set)` the host computed from the vN→vN+1 diff — never an
    /// `ApplyToken`, which is the proxy's private per-prepare opaque handle).
    ///
    /// This is the glue between the hand-rolled wire codec (confined to `main.rs`,
    /// per D40) and the already-substantive [`Self::sweep_revocations`]: it takes the
    /// ALREADY-DECODED `revoked` slice + the delta's version `seq`, re-keys the seq to
    /// THIS consumer's committed [`ApplyToken`] (the only token `sweep_revocations`
    /// will accept — it compares by full `(seq, content_hash)` equality so no
    /// cross-snapshot reuse is possible), and runs the sweep so `applied_seq` advances
    /// only post-sever (D72). A delta is HONOURED only once the matching version has
    /// been committed:
    ///
    /// * No token committed yet, or the committed token's seq ≠ the delta seq → the
    ///   delta names a version this consumer has not committed; fail-closed
    ///   [`ApplyError::UnknownToken`] (the host driver detects it and re-drives once
    ///   the commit barrier reaches this seq — an enforcer never severs against an
    ///   unconfirmed version).
    /// * `applied_seq` already at the delta seq → idempotent no-op (a re-driven delta
    ///   re-severs nothing; the [`Self::sweep_revocations`] guard + the per-handle
    ///   `sever` idempotence both hold, so a duplicate delta double-counts nothing).
    pub fn consume_revocation_delta<T>(
        &self,
        delta_seq: PolicyVersion,
        severing: &crate::SeveringRegistry,
        pools: &crate::SessionUpstreamPools<T>,
        revoked: &[crate::RevokedAdmission],
    ) -> Result<PolicyVersion, ApplyError> {
        // Re-key the wire `seq` to the committed token. The committed token is the
        // ONLY one `sweep_revocations` accepts; a delta for a version this consumer
        // has not committed is fail-closed (an enforcer never severs against an
        // unconfirmed version — the host re-drives once the barrier reaches it).
        let committed = self
            .committed
            .lock()
            .expect("committed lock poisoned")
            .clone();
        match committed {
            Some(token) if token.version() == delta_seq => {
                self.sweep_revocations(&token, severing, pools, revoked)
            }
            _ => Err(ApplyError::UnknownToken { version: delta_seq }),
        }
    }

    /// Parse + structurally validate verified snapshot bytes into a proxy
    /// evaluator, mapping a `policy-core` rejection onto a content-free
    /// [`PrepareError::SchemaInvalid`]. Shared by `prepare`.
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
        // bytes, so the verify there cannot NACK on this path — the non-vacuous gate
        // is `prepare_verified` against a SEPARATELY transported hash (the feed path).
        let expected_hash = snapshot_verify::sha256(snapshot);
        self.prepare_verified(snapshot, version, &expected_hash)
    }

    fn prepare_verified(
        &self,
        snapshot: &[u8],
        version: PolicyVersion,
        expected_hash: &snapshot_verify::ContentHash,
    ) -> Result<ApplyToken, PrepareError> {
        // (1) NON-VACUOUS fail-closed identity gate FIRST: verify the transported
        // bytes against the SEPARATELY-transported `expected_hash` the producer
        // pinned (doc 13 §5.1) — exactly as `snapshot_feed.rs`'s envelope path
        // verifies the `content_hash` before prepare. A mismatch is fail-closed
        // [`PrepareError::HashMismatch`]: parse and stage NEVER run on bytes that
        // do not hash to the transported identity. This replaces the old vacuous
        // self-hash note (re-hashing the bytes and comparing to their own hash can
        // never NACK); the hash now comes from the producer, so the check is real.
        if !snapshot_verify::verify_snapshot_bytes(snapshot, expected_hash).is_verified() {
            return Err(PrepareError::HashMismatch { version });
        }

        // (2) Parse + validate via the embedded policy-core evaluator, then
        // compose the staged evaluator. A rejection aborts the host-wide apply.
        let evaluator = PolicyConsumer::validate_and_build(snapshot, version)?;

        // (3) Stage — never flip. Park the new evaluator in the not-yet-active
        // slot; the proxy keeps deciding egress connects from `live` (vN). The
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
        // success — the second call sees vN+1 already live.
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
        // touching `live`: the proxy stays on vN, the stage is left intact for a
        // re-drive, and CommitFailed aborts the apply at the consumer level so the
        // host driver detects it and aborts host-wide. The proxy never half-flips.
        if self.commit_fault.load(Ordering::SeqCst) {
            return Err(ApplyError::CommitFailed {
                version: token.version(),
                reason: "evaluator pointer-swap guard refused the flip".to_string(),
            });
        }

        // (3) Atomic flip: one RwLock write swaps the live Arc. A concurrent
        // connect-decision reader holds a clone of the old Arc and sees the whole
        // old or whole new evaluator — never torn. In-flight vN decisions finish
        // on vN; the write guard is dropped before commit returns, so every
        // decision that begins after the return observes vN+1 — immediately
        // observable to new traffic.
        *self.live.write().expect("live evaluator lock poisoned") = staged.evaluator;
        *self.committed.lock().expect("committed lock poisoned") = Some(token.clone());
        *self.staged.lock().expect("staged slot lock poisoned") = None;
        Ok(())
    }

    fn sweep_and_advance_applied_seq(
        &self,
        token: &ApplyToken,
    ) -> Result<PolicyVersion, ApplyError> {
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
        // RUN the post-commit revocation sweep BEFORE advancing applied_seq (D72: the
        // seq advances ONLY after the sweep completes). ds-tlsproxy holds no cached
        // derived state — its allow/deny decisions are live `policy-core` queries, not a
        // cached set like ds-nft's allow-set or ds-dnsgate's admission map — so the sweep
        // re-evaluates nothing, evicts nothing, severs nothing, and returns the committed
        // seq unchanged (`crate::sweep::sweep_noop`). It still RUNS as the named
        // three-consumer-topology path (each consumer sweeps; doc 13 §5) and contributes
        // its swept seq to the host heartbeat's MIN over the three consumers. A future
        // TLS-path derived state slots into `crate::sweep` behind the same contract
        // without changing this hook.
        let report = crate::sweep::sweep_noop(token.version().seq());
        // applied_seq advances LAST — only now, after the (no-op) sweep completed (D72).
        self.applied_seq.store(report.swept_seq, Ordering::SeqCst);
        Ok(PolicyVersion(report.swept_seq))
    }
}

/// A SHARED [`PolicyConsumer`] handle: the ONE consumer the listener decides egress
/// connects from (via [`PolicyConsumer::live`]) is the SAME one the host-local
/// snapshot feed stages-and-commits into. Wrapping `Arc<PolicyConsumer>` in a LOCAL
/// newtype lets it implement the foreign [`Consumer`] seam (the orphan rule forbids
/// `impl Consumer for Arc<…>` directly) so a [`crate::snapshot_feed::SnapshotFeedConsumer`]
/// can drive THIS handle while the listeners hold clones of the same inner `Arc`.
///
/// Every method forwards to the inner consumer (each is `&self`-keyed; the state is
/// `RwLock`/`Mutex`/atomic-backed), so the feed driver and the per-connection
/// `PolicyCoreOracle` read/write through a single live evaluator slot — no parallel
/// policy state, no copy that could drift. The newtype is `Send + Sync` (the inner
/// state is), satisfying [`Consumer`]'s supertrait bound for the pingora worker
/// threads that hold the listener's shared handle (T2; doc 12 §8).
#[derive(Clone)]
pub struct SharedPolicyConsumer(Arc<PolicyConsumer>);

impl SharedPolicyConsumer {
    /// Wrap a shared consumer handle.
    #[must_use]
    pub fn new(inner: Arc<PolicyConsumer>) -> SharedPolicyConsumer {
        SharedPolicyConsumer(inner)
    }
}

impl Consumer for SharedPolicyConsumer {
    fn prepare(&self, snapshot: &[u8], version: PolicyVersion) -> Result<ApplyToken, PrepareError> {
        self.0.prepare(snapshot, version)
    }

    fn prepare_verified(
        &self,
        snapshot: &[u8],
        version: PolicyVersion,
        expected_hash: &snapshot_verify::ContentHash,
    ) -> Result<ApplyToken, PrepareError> {
        // Thread the transported hash through to the shared inner consumer so the
        // feed driver and the per-connection oracle share the ONE real gate.
        self.0.prepare_verified(snapshot, version, expected_hash)
    }

    fn commit(&self, token: &ApplyToken) -> Result<(), ApplyError> {
        self.0.commit(token)
    }

    fn sweep_and_advance_applied_seq(
        &self,
        token: &ApplyToken,
    ) -> Result<PolicyVersion, ApplyError> {
        self.0.sweep_and_advance_applied_seq(token)
    }
}

// ===========================================================================
// u2 — generic-pack HOT-RELOAD consumer in the D72 apply barrier.
// ===========================================================================
//
// The egress-connect plane above ([`PolicyConsumer`]) stages + flips a composed
// `policy-core` evaluator. The TLS-7 GENERIC plane is a SEPARATE artifact under
// the SAME `policy_log` seq (doc 12 §5.2, D72/D73): the POL-4 generic pack rides
// the policy-snapshot subscription and is hot-reloaded fleet-wide within seconds,
// no proxy restart (doc 12 §108). This consumer is that plane's side of the
// two-phase apply barrier — it shares the [`PolicyConsumer`]'s validate-then-stage
// -then-flip shape so the host driver commits BOTH planes from the one barrier:
//
//   prepare(snapshot) → extract + validate the generic pack from the POL-1 doc,
//                       STAGE it (the live pack keeps serving vN);
//   commit(token)     → the shared [`SharedGenericPack`] hot-swaps the staged pack
//                       live (the in-flight matchers' next scan reads vN+1);
//   sweep(token)      → re-evaluate every in-flight stream against the new pack and
//                       emit a policy-decision event for any NEWLY-matched generic
//                       rule, THEN advance applied_seq (D72: seq advances last).
//
// The generic plane is `policy_log`-seq policy data, so it travels the policy
// barrier (NOT the session-lifecycle digest channel the keyed plane uses). The
// `[GenericPackConsumer]` is driven alongside [`PolicyConsumer`] from the same
// snapshot; a future host-wiring layer feeds the same verified bytes to both.

/// Build a [`GenericPack`] from a validated POL-1 layer's `content.generic` block
/// (doc 13 §3 `content.generic.rules[]`; doc 14 §9). The `ruleset_version` becomes
/// the pack version stamped into generic-plane provenance (the SEPARATE non-policy
/// ruleset namespace, doc 14 §7), and the layer token becomes the POL-3
/// `policy_layer`. A layer with no generic rules yields an EMPTY pack (matches
/// nothing — the inspected path stays byte-clean). The `secret_group` /
/// `allowlists` carry through; `entropy` is present-but-unused in v0 (doc 14 §8) so
/// it is dropped at this seam. Generic rules are capped at block+log by the §8.1
/// validator already run in [`pol1::parse_layer`], so no rung is carried onto the
/// pack — every generic hit is block+log by construction (no suspend/kill).
#[must_use]
pub fn generic_pack_from_layer(layer: &PolicyLayer) -> GenericPack {
    let rules = layer
        .content
        .generic_rules
        .iter()
        .map(|r| GenericRule {
            id: r.id.clone(),
            regex: r.regex.clone(),
            keywords: r.keywords.clone(),
            secret_group: r.secret_group,
            allowlists: Vec::new(),
        })
        .collect();
    GenericPack {
        rules,
        pack_version: layer.content.ruleset_version.clone(),
        policy_layer: layer_token(layer.layer),
    }
}

/// The §3 layer token for POL-3 provenance (`system-baseline → org → repo →
/// session`). A small local mapping (the `policy-core` `layer_token` is private to
/// its composition module); kept faithful to the doc 13 §3 `layer:` token set.
fn layer_token(layer: Layer) -> String {
    match layer {
        Layer::SystemBaseline => "system-baseline",
        Layer::Org => "org",
        Layer::Repo => "repo",
        Layer::Session => "session",
    }
    .to_string()
}

/// One staged-but-not-yet-live generic pack, parked by [`GenericPackConsumer::prepare`]
/// and consumed by the matching `commit`. Keyed by the [`ApplyToken`] so a presented
/// token flips only the exact `(seq, content_hash)` its `prepare` validated, and a
/// re-driven barrier re-presenting the same token is recognised (idempotence).
#[derive(Clone)]
struct StagedPack {
    token: ApplyToken,
    pack: GenericPack,
}

/// ds-tlsproxy's TLS-7 generic-pack side of the D72 two-phase apply barrier
/// (doc 12 §5.2, D72/D73). It owns the SHARED live pack slot every in-flight
/// stream's matcher reads through ([`SharedGenericPack`]) and the in-flight-stream
/// registry the post-commit sweep re-evaluates ([`InFlightStreams`]).
///
/// State (mirrors [`PolicyConsumer`]'s atomic-flip contract):
/// - `live` — the [`SharedGenericPack`] the inspected path reads. `commit`
///   hot-swaps the staged pack into it (one `RwLock` write; never torn).
/// - `staged` — the at-most-one prepared pack awaiting commit (a new `prepare`
///   atomically replaces any earlier staged slot).
/// - `committed` — the last committed token (commit/sweep idempotence).
/// - `streams` — the in-flight inspected streams the post-commit sweep
///   re-evaluates against the just-committed pack.
/// - `applied_seq` — advanced LAST, only after the post-commit re-evaluation
///   sweep completes (D72; the host heartbeat reports the MIN over consumers).
pub struct GenericPackConsumer {
    live: SharedGenericPack,
    staged: Mutex<Option<StagedPack>>,
    committed: Mutex<Option<ApplyToken>>,
    streams: Mutex<InFlightStreams>,
    applied_seq: AtomicU64,
}

impl GenericPackConsumer {
    /// Create a consumer serving an initial generic pack at `initial_seq` (the
    /// proxy's first composed snapshot's generic pack, or [`GenericPack::default`]
    /// before the first POL-4 push — an empty pack matches nothing).
    #[must_use]
    pub fn new(initial: GenericPack, initial_seq: PolicyVersion) -> GenericPackConsumer {
        GenericPackConsumer {
            live: SharedGenericPack::new(initial),
            staged: Mutex::new(None),
            committed: Mutex::new(None),
            streams: Mutex::new(InFlightStreams::new()),
            applied_seq: AtomicU64::new(initial_seq.seq()),
        }
    }

    /// A handle to the SHARED live pack slot — cloned to each in-flight stream's
    /// matcher so one `commit` reloads every stream's view at once. The handle is a
    /// cheap `Arc` bump; reading it never blocks a concurrent hot-swap.
    #[must_use]
    pub fn shared_pack(&self) -> SharedGenericPack {
        self.live.clone()
    }

    /// The live pack version (the `pack_version` stamped into generic-plane
    /// provenance) — for audit, never a secret.
    #[must_use]
    pub fn live_pack_version(&self) -> String {
        self.live.version()
    }

    /// The current `applied_seq` (advanced only after a completed re-evaluation
    /// sweep; D72).
    #[must_use]
    pub fn applied_seq(&self) -> PolicyVersion {
        PolicyVersion(self.applied_seq.load(Ordering::SeqCst))
    }

    /// Register (or update) an open inspected stream's current scannable tail so a
    /// mid-stream generic-pack hot-reload can re-evaluate it. The proxy drives this
    /// as each chunk is scanned (the tail is the hold-back-bounded window, never the
    /// whole body — never-log-the-secret holds; the registry is never serialized).
    pub fn register_stream(&self, stream_id: impl Into<String>, tail: &[u8]) {
        self.streams
            .lock()
            .expect("in-flight streams lock poisoned")
            .upsert(stream_id, tail);
    }

    /// Drop a stream from the in-flight registry at its teardown (NFT-6 / close).
    pub fn deregister_stream(&self, stream_id: &str) {
        self.streams
            .lock()
            .expect("in-flight streams lock poisoned")
            .remove(stream_id);
    }

    /// Stage a generic pack extracted + validated from verified snapshot bytes
    /// against the TRANSPORTED `expected_hash` — the PREPARE step. Runs the
    /// NON-VACUOUS fail-closed identity gate FIRST (verify the bytes against the
    /// producer-pinned `expected_hash`, exactly as the egress-plane consumer + the
    /// `snapshot_feed.rs` envelope path do), then parses via the SAME embedded
    /// `policy-core` validators [`PolicyConsumer::prepare_verified`] uses (so a
    /// malformed / over-rung / missing-provenance document is rejected identically)
    /// and extracts the generic pack. NEVER flips: the live pack keeps serving vN
    /// until `commit`.
    pub fn prepare_verified(
        &self,
        snapshot: &[u8],
        version: PolicyVersion,
        expected_hash: &snapshot_verify::ContentHash,
    ) -> Result<ApplyToken, PrepareError> {
        // (1) NON-VACUOUS fail-closed identity gate FIRST: the transported bytes
        // must hash to the SEPARATELY-transported `expected_hash` (doc 13 §5.1)
        // BEFORE parse/stage. A mismatch is fail-closed HashMismatch — the generic
        // plane never parses or stages bytes that do not match the pinned identity.
        // This replaces the old vacuous self-hash note: the hash now comes from the
        // producer, so the check can actually NACK.
        if !snapshot_verify::verify_snapshot_bytes(snapshot, expected_hash).is_verified() {
            return Err(PrepareError::HashMismatch { version });
        }

        // (2) Parse + validate via policy-core (the §8.1 structural validators,
        // including the generic rung-cap + fail_open legality + D74 provenance),
        // then extract the generic pack from the validated layer. A rejection is a
        // content-free SchemaInvalid that aborts the host-wide apply.
        let text = std::str::from_utf8(snapshot).map_err(|_| PrepareError::SchemaInvalid {
            version,
            reason: "snapshot bytes are not valid UTF-8 policy text".to_string(),
        })?;
        let layer = pol1::parse_layer(text).map_err(|errs| PrepareError::SchemaInvalid {
            version,
            reason: summarize_policy_errors(&errs),
        })?;
        let pack = generic_pack_from_layer(&layer);

        // (3) Stage — never flip. A new prepare atomically replaces any earlier
        // staged slot (one apply in flight per consumer). The token pins the
        // VERIFIED transported hash.
        let token = ApplyToken::new(version, *expected_hash);
        *self.staged.lock().expect("staged pack lock poisoned") = Some(StagedPack {
            token: token.clone(),
            pack,
        });
        Ok(token)
    }

    /// In-process convenience over [`Self::prepare_verified`] for the seam that
    /// carries no separately-transported expected hash (a test that mints
    /// well-formed bytes, or a host-wiring layer that verified upstream). It derives
    /// the identity hash from the bytes and forwards; because the derived hash IS
    /// the hash of the passed bytes, the verify step can never NACK here — the
    /// non-vacuous gate is [`Self::prepare_verified`] against a SEPARATELY
    /// transported hash. Mirrors [`Consumer::prepare`]'s provided default for the
    /// egress-plane consumer.
    pub fn prepare(
        &self,
        snapshot: &[u8],
        version: PolicyVersion,
    ) -> Result<ApplyToken, PrepareError> {
        let expected_hash = snapshot_verify::sha256(snapshot);
        self.prepare_verified(snapshot, version, &expected_hash)
    }

    /// Hot-swap the staged generic pack live — the COMMIT step (atomic; idempotent;
    /// fail-closed on an unstaged token). One [`SharedGenericPack::hot_swap`] makes
    /// the new pack observable to every in-flight stream's next scan with no proxy
    /// restart (doc 12 §108). `applied_seq` does NOT advance here — only the
    /// post-commit re-evaluation sweep advances it (D72).
    pub fn commit(&self, token: &ApplyToken) -> Result<(), ApplyError> {
        // Idempotent on the token: an already-committed token is a no-op success.
        if self
            .committed
            .lock()
            .expect("committed lock poisoned")
            .as_ref()
            == Some(token)
        {
            return Ok(());
        }
        // Find the matching stage — an unstaged / mismatched token is fail-closed.
        let staged = self
            .staged
            .lock()
            .expect("staged pack lock poisoned")
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

        // Atomic hot-swap: the live slot now serves vN+1; every scan that begins
        // after this returns reads the whole new pack (never torn).
        self.live.hot_swap(staged.pack);
        *self.committed.lock().expect("committed lock poisoned") = Some(token.clone());
        *self.staged.lock().expect("staged pack lock poisoned") = None;
        Ok(())
    }

    /// Re-evaluate every in-flight stream against the just-committed pack and advance
    /// `applied_seq` — the post-commit SWEEP (doc 12 §5.2, D72). Returns the
    /// policy-decision events for any in-flight stream a NEWLY-pushed generic rule now
    /// matches (the caller ships them through the telemetry channel) PLUS the swept
    /// version. The re-evaluation runs BEFORE `applied_seq` advances (D72: the seq
    /// advances only after the sweep completes); it emits block+log policy-decisions
    /// (a generic rule never severs — severing is the rung-conditional revocation
    /// sweep's job, `crate::sweep`). Idempotent: a re-driven sweep at the already-
    /// applied seq re-evaluates nothing and returns no events.
    pub fn sweep_and_advance_applied_seq(
        &self,
        token: &ApplyToken,
    ) -> Result<(PolicyVersion, Vec<GenericReloadEvent>), ApplyError> {
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
            return Ok((token.version(), Vec::new()));
        }
        // Re-evaluate the in-flight streams against the just-committed (live) pack —
        // an exfiltration already in flight is caught by the freshly-pushed rule.
        // This runs BEFORE applied_seq advances (D72).
        let pack = self.live.current();
        let events = self
            .streams
            .lock()
            .expect("in-flight streams lock poisoned")
            .reevaluate_against(&pack);
        // applied_seq advances LAST — only now, after the re-evaluation completed.
        self.applied_seq
            .store(token.version().seq(), Ordering::SeqCst);
        Ok((token.version(), events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clean POL-1 session layer that stages successfully.
    const VALID_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                             dns:\n  boundary_zone: corp.example.\n";

    /// A POL-1 document with a baseline-pack entry missing mandatory provenance
    /// (`provenance_source_url` / `evidence`, D74) — the embedded validator must
    /// REJECT it at prepare.
    const MISSING_PROVENANCE_DOC: &str = "schema_version: pol1/v0\nlayer: org\nposture: standard\n\
         baseline_pack:\n  pack_version: tld-deny/1\n  entries:\n    - fqdn: evil.example\n";

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

        // Staged evaluator does NOT serve: live pointer + applied_seq unchanged.
        assert_eq!(
            Arc::as_ptr(&c.live()),
            live_before,
            "stage must not flip live"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(1));
        assert!(
            c.staged.lock().unwrap().is_some(),
            "evaluator parked, not active"
        );
    }

    #[test]
    fn invalid_snapshot_returns_error_and_leaves_the_running_evaluator_unchanged() {
        let c = consumer_at(5, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());

        let err = c
            .prepare(MISSING_PROVENANCE_DOC.as_bytes(), PolicyVersion(6))
            .expect_err("missing provenance must be rejected");
        match err {
            PrepareError::SchemaInvalid { version, reason } => {
                assert_eq!(version, PolicyVersion(6));
                assert!(reason.contains("MissingProvenance"), "reason={reason}");
                assert!(
                    !reason.contains("evil.example"),
                    "reason must not echo doc body"
                );
            }
            other => panic!("expected SchemaInvalid, got {other:?}"),
        }
        // Fail-closed: nothing staged, the running evaluator + seq untouched.
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

        match c.prepare(&[0xff, 0xfe, 0x00], PolicyVersion(2)) {
            Err(PrepareError::SchemaInvalid { version, .. }) => {
                assert_eq!(version, PolicyVersion(2))
            }
            other => panic!("expected SchemaInvalid for non-utf8, got {other:?}"),
        }
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
        // fail-closed PrepareError::HashMismatch — parse + stage NEVER run, the
        // running evaluator + applied_seq are untouched, and nothing is staged.
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
        // nothing staged.
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

        // The MATCHING transported hash still ACKs/stages (happy path unchanged).
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
    fn prepare_default_forwards_to_the_verified_gate_and_is_byte_identical() {
        // The provided `prepare(snapshot, version)` default derives the hash from
        // the bytes and forwards to prepare_verified — the in-process no-separate-
        // hash entry point. It stages exactly as before (happy path unchanged).
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: beta.example.\n";
        let via_default = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        assert_eq!(
            via_default.content_hash,
            snapshot_verify::sha256(next.as_bytes()),
            "default forwarder pins the bytes' identity hash"
        );
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

        assert_ne!(ta, tb);
        let staged = c.staged.lock().unwrap().clone().expect("one staged slot");
        assert_eq!(staged.token, tb, "second stage replaced the first");
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

        c.commit(&token).expect("commit");
        // applied_seq does NOT advance on commit — only after sweep (D72).
        assert_eq!(c.applied_seq(), PolicyVersion(1));
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

        let foreign = ApplyToken::new(PolicyVersion(99), snapshot_verify::sha256(b"x"));
        match c.commit(&foreign) {
            Err(ApplyError::UnknownToken { version }) => assert_eq!(version, PolicyVersion(99)),
            other => panic!("expected UnknownToken, got {other:?}"),
        }
    }

    #[test]
    fn commit_flip_is_observable_to_new_traffic_without_interrupting_vn() {
        // A connect decision that began on vN keeps the whole vN evaluator; a
        // decision that begins after commit returns observes vN+1.
        let c = consumer_at(1, VALID_DOC);
        let in_flight_vn = c.live();
        let vn_ptr = Arc::as_ptr(&in_flight_vn);

        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        assert_eq!(Arc::as_ptr(&c.live()), vn_ptr, "pre-commit serves vN");

        c.commit(&token).expect("commit");

        let new_traffic = c.live();
        assert_ne!(Arc::as_ptr(&new_traffic), vn_ptr, "new traffic sees vN+1");
        assert_eq!(
            Arc::as_ptr(&in_flight_vn),
            vn_ptr,
            "the in-flight vN connect decision is never torn or interrupted"
        );
    }

    #[test]
    fn commit_flip_fault_reverts_to_vn_fail_closed_and_unblocks_host_abort() {
        let c = consumer_at(7, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(8)).expect("stage");

        // Arm the flip fault: as an enforcer the proxy staying on vN is
        // at-least-as-strict, so the abort keeps the mixed-version window
        // fail-closed; the host driver detects CommitFailed and aborts host-wide.
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
        assert_eq!(Arc::as_ptr(&c.live()), live_before, "proxy stays on vN");
        assert_eq!(c.applied_seq(), PolicyVersion(7));
        assert!(
            c.staged.lock().unwrap().is_some(),
            "stage left intact for re-drive"
        );
        assert!(
            c.committed.lock().unwrap().is_none(),
            "no half-commit recorded"
        );

        c.set_commit_fault(false);
        c.commit(&token).expect("re-driven commit succeeds");
        assert_ne!(Arc::as_ptr(&c.live()), live_before, "now serving vN+1");
    }

    #[test]
    fn commit_is_idempotent_after_a_following_prepare_does_not_resurrect_an_old_flip() {
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

    // ---- CV2-failclosed (01KV9N17NN): the REAL revocation sweep severs ----------
    //
    // The post-commit revocation sweep, backed by the real SeveringDerivedState, must
    // actually TEAR DOWN an established CONNECT tunnel (and drop the swept session's
    // warm pool) at a severing rung — proving the placeholder "returned zero" no-op is
    // replaced by a flush through the shared FlushSession.

    use crate::{RevokedAdmission, Rung, SessionUpstreamPools, Severable, SeveringRegistry};
    use ds_contracts::flush::DstKey;
    use ds_contracts::session::SessionRef;
    use std::net::TcpStream;
    use std::sync::atomic::AtomicBool;

    /// A severable test handle: a live flag flipped false on the first `sever()`.
    struct SeverFlag {
        live: AtomicBool,
    }
    impl SeverFlag {
        fn new() -> Arc<SeverFlag> {
            Arc::new(SeverFlag {
                live: AtomicBool::new(true),
            })
        }
    }
    impl Severable for Arc<SeverFlag> {
        fn sever(&self) -> bool {
            self.live.swap(false, Ordering::SeqCst)
        }
        fn is_live(&self) -> bool {
            self.live.load(Ordering::SeqCst)
        }
    }

    fn rev_session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    #[test]
    fn sweep_revocations_severs_an_established_tunnel_at_a_severing_rung_then_advances_seq() {
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        c.commit(&token).expect("commit");

        let severing = SeveringRegistry::new();
        let pools: SessionUpstreamPools<TcpStream> = SessionUpstreamPools::new();
        let sev = rev_session(7);

        // A LIVE established tunnel for the destination vN+1 now blocks (severing rung).
        let tunnel = SeverFlag::new();
        severing.register_tunnel(
            &sev,
            &DstKey("203.0.113.10:443".into()),
            Box::new(tunnel.clone()),
        );
        assert_eq!(
            severing.live_handles(&sev),
            1,
            "the tunnel is live pre-sweep"
        );

        let revoked = vec![RevokedAdmission {
            session: sev.clone(),
            dst_keys: vec![DstKey("203.0.113.10:443".into())],
            rung: Rung::BlockLog, // block-or-higher → sever
        }];

        // The REAL sweep severs the tunnel BEFORE advancing applied_seq (D72).
        let swept = c
            .sweep_revocations(&token, &severing, &pools, &revoked)
            .expect("real revocation sweep");
        assert_eq!(swept, PolicyVersion(2));
        assert_eq!(
            c.applied_seq(),
            PolicyVersion(2),
            "applied_seq advanced post-sweep"
        );
        assert!(
            !tunnel.live.load(Ordering::SeqCst),
            "the established CONNECT tunnel was actually severed (not a survivor no-op)"
        );
        assert_eq!(
            severing.live_handles(&sev),
            0,
            "no live handle survives a severing-rung revocation"
        );
    }

    #[test]
    fn sweep_revocations_leaves_a_sub_block_rung_tunnel_alive_d53() {
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        c.commit(&token).expect("commit");

        let severing = SeveringRegistry::new();
        let pools: SessionUpstreamPools<TcpStream> = SessionUpstreamPools::new();
        let sev = rev_session(8);
        let tunnel = SeverFlag::new();
        severing.register_tunnel(
            &sev,
            &DstKey("203.0.113.11:443".into()),
            Box::new(tunnel.clone()),
        );

        let revoked = vec![RevokedAdmission {
            session: sev.clone(),
            dst_keys: vec![DstKey("203.0.113.11:443".into())],
            rung: Rung::AllowLog, // sub-block → sever NOTHING (D53 non-severing rung)
        }];
        c.sweep_revocations(&token, &severing, &pools, &revoked)
            .expect("sweep");
        assert!(
            tunnel.live.load(Ordering::SeqCst),
            "a sub-block (allow+log) revocation leaves the established flow untouched (D53)"
        );
        assert_eq!(
            severing.live_handles(&sev),
            1,
            "the flow survives a non-severing rung"
        );
    }

    #[test]
    fn sweep_revocations_rejects_an_uncommitted_token_and_is_idempotent() {
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");

        let severing = SeveringRegistry::new();
        let pools: SessionUpstreamPools<TcpStream> = SessionUpstreamPools::new();

        // Before commit, the token is not the committed one → fail-closed UnknownToken.
        match c.sweep_revocations(&token, &severing, &pools, &[]) {
            Err(ApplyError::UnknownToken { version }) => assert_eq!(version, PolicyVersion(2)),
            other => panic!("expected UnknownToken before commit, got {other:?}"),
        }

        c.commit(&token).expect("commit");
        let s1 = c
            .sweep_revocations(&token, &severing, &pools, &[])
            .expect("sweep 1");
        let s2 = c
            .sweep_revocations(&token, &severing, &pools, &[])
            .expect("sweep 2 (idempotent)");
        assert_eq!(s1, PolicyVersion(2));
        assert_eq!(
            s2,
            PolicyVersion(2),
            "a re-drive at the applied seq is idempotent"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(2));
    }

    // ---- revocation-delta (01KVJ8EAEB): the host-agent delta drives the sweep ----
    //
    // The TRANSPORT (the hand-rolled UDS frame codec) lives in main.rs and is tested
    // there; here we prove the CONSUME path — `consume_revocation_delta`, the seq→token
    // re-key that bridges a wire delta (identified only by `seq`) onto the committed
    // ApplyToken `sweep_revocations` accepts — actually severs an established tunnel
    // registered in the SeveringRegistry, and is idempotent on a re-driven delta.

    #[test]
    fn consume_revocation_delta_severs_an_established_tunnel_end_to_end() {
        // ACCEPTANCE: an established tunnel registered in the SeveringRegistry is
        // SEVERED end to end when a revocation-delta carrying its token (re-keyed
        // from the wire `seq`) is applied — exactly the path the live UDS feed drives.
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        c.commit(&token).expect("commit");

        let severing = SeveringRegistry::new();
        let pools: SessionUpstreamPools<TcpStream> = SessionUpstreamPools::new();
        let sev = rev_session(11);

        let tunnel = SeverFlag::new();
        severing.register_tunnel(
            &sev,
            &DstKey("203.0.113.21:443".into()),
            Box::new(tunnel.clone()),
        );
        assert_eq!(severing.live_handles(&sev), 1, "tunnel live pre-delta");

        // The host fanned this delta out over the feed: keyed by `seq` (NOT the proxy's
        // private ApplyToken), carrying the revoked (session, dst, rung) set.
        let revoked = vec![RevokedAdmission {
            session: sev.clone(),
            dst_keys: vec![DstKey("203.0.113.21:443".into())],
            rung: Rung::BlockLog,
        }];

        let swept = c
            .consume_revocation_delta(PolicyVersion(2), &severing, &pools, &revoked)
            .expect("delta consumed");
        assert_eq!(swept, PolicyVersion(2));
        assert_eq!(
            c.applied_seq(),
            PolicyVersion(2),
            "applied_seq advanced post-sever"
        );
        assert!(
            !tunnel.live.load(Ordering::SeqCst),
            "the established CONNECT tunnel was severed by the consumed delta"
        );
        assert_eq!(
            severing.live_handles(&sev),
            0,
            "no live handle survives the consumed severing-rung delta"
        );
    }

    #[test]
    fn consume_revocation_delta_is_idempotent_on_a_re_driven_delta() {
        // Re-driving the SAME delta (the feed re-delivering, or a retry) severs nothing
        // a second time and never advances past the applied seq (D72 applied_seq guard +
        // per-handle sever idempotence).
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        c.commit(&token).expect("commit");

        let severing = SeveringRegistry::new();
        let pools: SessionUpstreamPools<TcpStream> = SessionUpstreamPools::new();
        let sev = rev_session(12);
        let tunnel = SeverFlag::new();
        severing.register_tunnel(
            &sev,
            &DstKey("203.0.113.22:443".into()),
            Box::new(tunnel.clone()),
        );
        let revoked = vec![RevokedAdmission {
            session: sev.clone(),
            dst_keys: vec![DstKey("203.0.113.22:443".into())],
            rung: Rung::BlockLog,
        }];

        let s1 = c
            .consume_revocation_delta(PolicyVersion(2), &severing, &pools, &revoked)
            .expect("first delta severs");
        assert_eq!(s1, PolicyVersion(2));
        assert!(
            !tunnel.live.load(Ordering::SeqCst),
            "first delta severed it"
        );

        // Re-drive the SAME delta: idempotent (applied_seq already at the version → no
        // re-sweep; nothing double-severed).
        let s2 = c
            .consume_revocation_delta(PolicyVersion(2), &severing, &pools, &revoked)
            .expect("re-driven delta is an idempotent no-op");
        assert_eq!(s2, PolicyVersion(2), "re-drive returns the applied seq");
        assert_eq!(c.applied_seq(), PolicyVersion(2));
    }

    #[test]
    fn consume_revocation_delta_for_an_uncommitted_version_fails_closed() {
        // A delta for a version this consumer has not committed (seq mismatch, or no
        // token committed at all) is fail-closed UnknownToken — an enforcer never
        // severs against an unconfirmed version; the host re-drives once the barrier
        // reaches the seq.
        let c = consumer_at(1, VALID_DOC);
        let severing = SeveringRegistry::new();
        let pools: SessionUpstreamPools<TcpStream> = SessionUpstreamPools::new();

        // Nothing committed yet → fail-closed at the delta's seq.
        match c.consume_revocation_delta(PolicyVersion(2), &severing, &pools, &[]) {
            Err(ApplyError::UnknownToken { version }) => assert_eq!(version, PolicyVersion(2)),
            other => panic!("expected UnknownToken before any commit, got {other:?}"),
        }

        // Commit seq 2, then a delta naming a DIFFERENT seq (3) is still fail-closed.
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        c.commit(&token).expect("commit");
        match c.consume_revocation_delta(PolicyVersion(3), &severing, &pools, &[]) {
            Err(ApplyError::UnknownToken { version }) => assert_eq!(version, PolicyVersion(3)),
            other => panic!("expected UnknownToken for a mismatched seq, got {other:?}"),
        }
        // The committed version's applied_seq is untouched by the failed deltas.
        assert_eq!(c.applied_seq(), PolicyVersion(1));
    }

    // ---- u2: generic-pack hot-reload consumer in the apply barrier -----------

    use crate::scan::{
        DigestHasher, DigestSetMatcher, FailMode, Plane, ScanCtx, ScanGate, SecretMatcher, Verdict,
    };

    /// A POL-1 org layer carrying a `content.generic` pack with one AKIA rule. The
    /// `ruleset_version` is the generic-pack version stamped into provenance.
    fn org_doc_with_generic(ruleset_version: &str, regex: &str, keyword: &str) -> String {
        format!(
            "schema_version: pol1/v0\nlayer: org\nposture: standard\n\
             content:\n  generic:\n    fail_open: false\n    ruleset_version: {ruleset_version:?}\n\
             \x20   rules:\n      - id: generic-akid\n        regex: {regex:?}\n\
             \x20       keywords: [{keyword}]\n        secret_group: 0\n        entropy: null\n\
             \x20       rung: block+log\n"
        )
    }

    /// A test hasher that knows no key (no live keyed plane) — the generic plane is
    /// the only loaded plane, exactly the body-filter prestage shape.
    struct NoKeyHasher;
    impl DigestHasher for NoKeyHasher {
        fn hash(&self, _k: &str, _c: &[u8], _t: usize) -> Option<Vec<u8>> {
            None
        }
    }

    #[test]
    fn applying_a_snapshot_with_a_new_generic_pack_ingests_it_into_the_live_matcher() {
        // ACCEPTANCE (unit): apply a policy snapshot with a new GenericPack; it is
        // ingested into the live matcher; a scan against the new rules matches and
        // returns Block with plane=Generic.
        let c = GenericPackConsumer::new(GenericPack::default(), PolicyVersion(1));
        assert_eq!(c.live_pack_version(), "", "starts empty (matches nothing)");

        let doc = org_doc_with_generic("pack-2026.6", "AKIA", "AKIA");
        let token = c.prepare(doc.as_bytes(), PolicyVersion(2)).expect("stages");

        // prepare STAGES — the live pack is unchanged until commit (vN still empty).
        assert_eq!(
            c.live_pack_version(),
            "",
            "stage does not flip the live pack"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(1));

        c.commit(&token)
            .expect("commit hot-swaps the staged pack live");
        assert_eq!(c.live_pack_version(), "pack-2026.6", "live pack reloaded");
        // applied_seq does NOT advance on commit — only the post-commit sweep (D72).
        assert_eq!(c.applied_seq(), PolicyVersion(1));

        // The live shared pack drives a matcher: a scan against the new rules
        // matches and returns Block with plane=Generic.
        let pack = c.shared_pack().current();
        let mut matcher = DigestSetMatcher::new(NoKeyHasher, 64);
        matcher.ingest_generic((*pack).clone());
        let v = matcher
            .scan(b"k=AKIAEXAMPLE1234", true, &ScanCtx::egress())
            .expect("scan");
        match &v {
            Verdict::Block(p) => {
                assert_eq!(p.plane, Plane::Generic, "generic plane hit");
                assert_eq!(p.rule_id, "generic-akid");
                assert_eq!(p.ruleset_version, "pack-2026.6");
                assert_eq!(p.policy_layer, "org");
            }
            other => panic!("expected generic Block, got {other:?}"),
        }

        // Post-commit sweep advances applied_seq (no in-flight stream registered, so
        // no policy-decision event is emitted).
        let (swept, events) = c.sweep_and_advance_applied_seq(&token).expect("sweep");
        assert_eq!(swept, PolicyVersion(2));
        assert_eq!(c.applied_seq(), PolicyVersion(2));
        assert!(events.is_empty(), "no in-flight stream → no event");
    }

    #[test]
    fn pushing_a_generic_pack_update_while_traffic_flows_respects_the_new_rules() {
        // ACCEPTANCE (integration): a mock POL-4 feeder pushes a generic-pack update
        // while a stream is in flight; NEW scans respect the updated rules within
        // test-latency, and the already-open stream is caught by the sweep.
        let c = GenericPackConsumer::new(GenericPack::default(), PolicyVersion(1));

        // A stream is in flight scanning over the EMPTY pack: a chunk with a secret
        // passes clean (no rule loaded yet). The proxy registers the stream's tail.
        let shared = c.shared_pack();
        let mut matcher = DigestSetMatcher::new(NoKeyHasher, 64);
        matcher.ingest_generic((*shared.current()).clone());
        let mut gate = ScanGate::new(matcher, 64, false, FailMode::Closed).unwrap();
        let v_before = gate.scan_chunk(b"GET /?k=AKIAINFLIGHT", true, &ScanCtx::egress());
        assert!(
            matches!(v_before, Verdict::Pass { .. }),
            "pre-push: empty pack passes the secret; got {v_before:?}"
        );
        c.register_stream("dstap-7", b"GET /?k=AKIAINFLIGHT");

        // The mock POL-4 feeder pushes a pack update through the apply barrier.
        let doc = org_doc_with_generic("pack-push-1", "AKIA", "AKIA");
        let token = c.prepare(doc.as_bytes(), PolicyVersion(2)).expect("stage");
        c.commit(&token).expect("commit");

        // A NEW connection's matcher reads the hot-swapped live pack and now BLOCKS
        // the same secret (the update took effect with no restart).
        let mut fresh = DigestSetMatcher::new(NoKeyHasher, 64);
        fresh.ingest_generic((*c.shared_pack().current()).clone());
        let v_after = fresh
            .scan(b"k=AKIAINFLIGHT", true, &ScanCtx::egress())
            .expect("scan");
        assert!(
            matches!(&v_after, Verdict::Block(p) if p.plane == Plane::Generic),
            "post-push: a new connection blocks under the updated rules; got {v_after:?}"
        );

        // The post-commit sweep re-evaluates the ALREADY-OPEN stream and emits one
        // policy-decision naming it + the rule (plane=Generic).
        let (swept, events) = c.sweep_and_advance_applied_seq(&token).expect("sweep");
        assert_eq!(swept, PolicyVersion(2));
        assert_eq!(
            events.len(),
            1,
            "the in-flight stream is caught by the sweep"
        );
        assert_eq!(events[0].stream_id, "dstap-7");
        assert_eq!(events[0].provenance.plane, Plane::Generic);
        assert_eq!(events[0].provenance.rule_id, "generic-akid");
        assert!(
            !format!("{:?}", events[0]).contains("AKIAINFLIGHT"),
            "the policy-decision event carries no matched byte"
        );
    }

    #[test]
    fn generic_commit_and_sweep_are_idempotent_and_reject_unstaged_tokens() {
        let c = GenericPackConsumer::new(GenericPack::default(), PolicyVersion(1));
        let doc = org_doc_with_generic("v", "AKIA", "AKIA");
        let token = c.prepare(doc.as_bytes(), PolicyVersion(2)).expect("stage");
        c.commit(&token).expect("commit 1");
        c.commit(&token).expect("commit 2 (idempotent no-op)");
        c.sweep_and_advance_applied_seq(&token).expect("sweep 1");
        let (_, events2) = c
            .sweep_and_advance_applied_seq(&token)
            .expect("sweep 2 (idempotent)");
        assert!(
            events2.is_empty(),
            "idempotent re-sweep re-evaluates nothing"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(2));

        // An unstaged token is fail-closed (never flips an unstaged pack).
        let foreign = ApplyToken::new(PolicyVersion(99), snapshot_verify::sha256(b"x"));
        match c.commit(&foreign) {
            Err(ApplyError::UnknownToken { version }) => assert_eq!(version, PolicyVersion(99)),
            other => panic!("expected UnknownToken, got {other:?}"),
        }
    }

    #[test]
    fn generic_prepare_rejects_a_schema_invalid_document_content_free() {
        // A document whose baseline-pack entry is missing mandatory provenance (D74)
        // is rejected at prepare by the SAME policy-core validators — the generic
        // plane never flips on an invalid snapshot (fail-closed), and the reason is
        // content-free (no document body echoed).
        let c = GenericPackConsumer::new(GenericPack::default(), PolicyVersion(1));
        let err = c
            .prepare(MISSING_PROVENANCE_DOC.as_bytes(), PolicyVersion(2))
            .expect_err("schema-invalid is rejected");
        match err {
            PrepareError::SchemaInvalid { version, reason } => {
                assert_eq!(version, PolicyVersion(2));
                assert!(reason.contains("MissingProvenance"), "reason={reason}");
                assert!(!reason.contains("evil.example"), "no doc body echoed");
            }
            other => panic!("expected SchemaInvalid, got {other:?}"),
        }
        // Fail-closed: nothing staged, the live pack + seq untouched.
        assert_eq!(c.live_pack_version(), "");
        assert_eq!(c.applied_seq(), PolicyVersion(1));
    }

    #[test]
    fn generic_prepare_verified_nacks_a_transported_hash_mismatch_before_parse_or_stage() {
        // The generic plane carries the SAME non-vacuous identity gate: a
        // transported expected hash that does not match the bytes is fail-closed
        // HashMismatch — the live pack + applied_seq are untouched, nothing stages.
        let c = GenericPackConsumer::new(GenericPack::default(), PolicyVersion(1));
        let doc = org_doc_with_generic("pack-x", "AKIA", "AKIA");
        let mut wrong = snapshot_verify::sha256(doc.as_bytes());
        wrong[3] ^= 0xff;

        match c.prepare_verified(doc.as_bytes(), PolicyVersion(2), &wrong) {
            Err(PrepareError::HashMismatch { version }) => assert_eq!(version, PolicyVersion(2)),
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        // Fail-closed: live pack + seq untouched, nothing staged.
        assert_eq!(c.live_pack_version(), "", "no flip on hash mismatch");
        assert_eq!(c.applied_seq(), PolicyVersion(1));
        assert!(
            c.staged.lock().unwrap().is_none(),
            "a hash-failing snapshot must never stage on the generic plane"
        );

        // The MATCHING transported hash still stages + commits + reloads the pack.
        let token = c
            .prepare_verified(
                doc.as_bytes(),
                PolicyVersion(2),
                &snapshot_verify::sha256(doc.as_bytes()),
            )
            .expect("matching transported hash stages");
        c.commit(&token).expect("commit");
        assert_eq!(c.live_pack_version(), "pack-x", "verified pack reloaded");
    }

    #[test]
    fn an_empty_generic_pack_matches_nothing_and_keeps_the_path_byte_clean() {
        // Backward / default-path: a snapshot with NO generic rules yields an empty
        // pack; a scan over it passes every byte (the byte-identical default the
        // DS_TLS3_LIVE-unset path relies on — nothing is synthetically blocked).
        let c = GenericPackConsumer::new(GenericPack::default(), PolicyVersion(1));
        // VALID_DOC carries no content.generic block.
        let token = c
            .prepare(VALID_DOC.as_bytes(), PolicyVersion(2))
            .expect("stage");
        c.commit(&token).expect("commit");
        let pack = c.shared_pack().current();
        assert!(pack.rules.is_empty(), "no generic rules → empty pack");
        let mut matcher = DigestSetMatcher::new(NoKeyHasher, 64);
        matcher.ingest_generic((*pack).clone());
        let v = matcher
            .scan(b"k=AKIAWOULDMATCHIFLOADED", true, &ScanCtx::egress())
            .expect("scan");
        assert_eq!(
            v,
            Verdict::Pass {
                release_n: b"k=AKIAWOULDMATCHIFLOADED".len()
            },
            "empty pack passes every byte (byte-clean default)"
        );
    }
}
