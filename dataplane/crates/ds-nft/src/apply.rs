// SPDX-License-Identifier: Apache-2.0

//! The NFTables programmer's side of the FROZEN D72 two-phase apply barrier
//! (POL-4 part 2; D72/D36, doc 13 §5, doc 15 §5.2).
//!
//! The `ds-nft` programmer is an **enforcer** — one of the two consumers the host
//! commits BEFORE the admitter (the NFT flip + ds-tlsproxy move to `vN+1` first,
//! so every transient mixed-version window is FAIL-CLOSED: the ruleset is already
//! on the at-least-as-strict `vN+1` before ds-dnsgate starts admitting under it,
//! make-before-break). This module implements the
//! [`ds_contracts::consumer::Consumer`] seam.
//!
//! # Mechanism boundary (this crate's charter)
//!
//! `ds-nft` executes mechanism only and depends on ONLY `ds-contracts` (the crate
//! map's "ONLY dependency" rule). So its embedded "policy-core evaluator" is the
//! `policy-core` SCHEMA layer that lives in `ds-contracts`
//! ([`ds_contracts::pol1::parse_layer`], per doc 13 §1 rule 1: the schema, reader,
//! and parse-time validators live in ds-contracts). That one call runs the §8.1
//! structural validators — schema/syntax, the D53 rung-cap, `fail_open` legality,
//! and the D74 mandatory-provenance checks. The crate pulls in NO new dependency
//! (no `policy-core` edge), honouring the charter, while still validating the
//! exact frozen rejection set the spec requires.
//!
//! The staged "evaluator" the programmer parks is the validated
//! [`ds_contracts::pol1::PolicyLayer`] — the NFT ruleset-DERIVATION input the
//! programmer derives its allow-set / mark-discipline ruleset from. Rung values
//! (D53) are validated structurally by the parse pass; deriving the actual
//! ruleset text and the netlink transaction is downstream of this prepare unit.
//!
//! # This unit: the PREPARE hook (validate + stage while serving vN)
//!
//! [`Consumer::prepare_verified`] is the substance here (doc 13 §5; the seam's
//! only fallible-by-design phase), fail-closed end to end:
//!
//! 1. **Verify the snapshot identity against the PRODUCER-PINNED, separately
//!    transported `content_hash`** via the single-source
//!    [`ds_contracts::snapshot_verify::verify_snapshot_bytes`]; a mismatch returns
//!    [`PrepareError::HashMismatch`] (NACK host-wide — never parse bytes that do
//!    not hash to the producer's transported identity, doc 13 §5.1). The
//!    transported hash makes this a NON-VACUOUS gate (it can actually NACK, unlike
//!    re-hashing the bytes and comparing them to their own hash). The bare
//!    [`Consumer::prepare`] default serves in-process callers without a separately
//!    transported hash: it derives the identity hash from the bytes and routes the
//!    SAME `prepare_verified` path (its verify cannot NACK on this entry — the
//!    parse step is then the fail-closed gate on malformed bytes).
//! 2. **Parse + validate** via [`ds_contracts::pol1::parse_layer`]; any rejection
//!    becomes a content-free [`PrepareError::SchemaInvalid`].
//! 3. **Stage, never flip.** The validated derivation input parks in a SEPARATE,
//!    not-yet-active slot keyed by the snapshot identity; the live ruleset stays
//!    on `vN`. `prepare` returns an opaque [`ApplyToken`] carrying
//!    `(seq, content_hash)`; only the matching `commit` flips it live.
//!
//! # This unit: the COMMIT hook (the atomic flip — ONE netlink transaction)
//!
//! [`Consumer::commit`] is the substance of POL-4 part 2c. It takes the
//! [`ApplyToken`] `prepare` returned and flips the programmer from `vN` to the
//! staged `vN+1` derivation input as ONE ATOMIC transaction (D72: one netlink
//! batch / one conntrack command; here modelled as the single pointer-swap of the
//! staged input into the live slot, the in-process analog of the netlink batch):
//!
//! 1. **Take the token, find the matching stage.** A token that names no
//!    currently-staged snapshot (or a different one) is fail-closed
//!    [`ApplyError::UnknownToken`] — the programmer never flips an unstaged
//!    version.
//! 2. **One atomic transaction.** The flip is one `RwLock` write that swaps the
//!    live `Arc<RulesetSource>` — the in-process stand-in for the single netlink
//!    batch that replaces the whole ruleset atomically. A concurrent reader sees
//!    the WHOLE old input or the whole new one — never a torn ruleset. The live
//!    `vN` ruleset is never interrupted: the kernel either has the old table or
//!    the new one, and every derivation that begins AFTER the swap returns reads
//!    `vN+1`.
//! 3. **Revert to `vN` on a transaction fault.** If the netlink batch does not
//!    apply (modelled here by an injectable commit fault), the programmer stays
//!    on `vN`, leaves the stage intact for a re-drive, and returns
//!    [`ApplyError::CommitFailed`] — aborting the apply at the consumer level so
//!    the host driver detects it and aborts host-wide. As an enforcer committed
//!    BEFORE the admitter, staying on `vN` is at-least-as-strict: the
//!    mixed-version window stays fail-closed. The programmer never half-flips
//!    (a netlink batch is all-or-none).
//! 4. **Idempotent on the token.** A second `commit` with the same token (a
//!    re-driven barrier) is a no-op success — the second call sees `vN+1` already
//!    live and runs no second transaction.
//!
//! Commit returns success ONLY after the transaction is observable to new traffic
//! (the write guard is dropped before it returns). `applied_seq` does NOT advance
//! on commit — only the post-commit sweep advances it (D72).
//!
//! `sweep_and_advance_applied_seq` (the post-commit revocation sweep, which for
//! the programmer severs through the ONE shared
//! [`ds_contracts::flush::FlushSession`] primitive, rung-conditional per D53) is
//! implemented here minimally so the type is a complete, testable [`Consumer`];
//! the sweep's allow-set walk is elaborated by the host apply driver and the
//! sibling POL-4 sweep unit.
//!
//! NEVER-LOG-THE-SECRET: nothing here logs the composed document; the bytes cross
//! as opaque input and the error surfaces carry only structural reasons. The
//! crate-root `#![deny(unsafe_code)]` binds this module — the flip is safe-Rust
//! `Arc`/`RwLock` pointer-swap, no `unsafe`. (The crate root is `deny`, not
//! `forbid`, so the single reviewed [`crate::ffi`] FFI carve-out (D4) can downgrade
//! to `allow`; every other module, this one included, stays unable to opt back in.)

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use ds_contracts::consumer::{ApplyError, ApplyToken, Consumer, PolicyVersion, PrepareError};
use ds_contracts::flush::{DstFilter, FlushSession, LegSelector};
use ds_contracts::pol1::{self, PolicyLayer, Rung};
use ds_contracts::session::SessionRef;
use ds_contracts::snapshot_verify::{self, ContentHash};

use crate::backend::NftBackend;
use crate::flush::NftWriter;

/// The programmer's staged NFT ruleset-DERIVATION input — the validated POL-1
/// layer the programmer derives its allow-set / mark-discipline ruleset from. A
/// named wrapper over [`PolicyLayer`] keeps the staged/live slots
/// self-documenting and lets the atomic flip move an `Arc<RulesetSource>`.
///
/// `ds-nft` deriving the actual nftables text + the netlink transaction is
/// downstream of this prepare unit (mechanism, this crate's job); the prepare
/// hook stages the validated INPUT, not the rendered ruleset.
#[derive(Debug)]
pub struct RulesetSource {
    layer: PolicyLayer,
}

impl RulesetSource {
    /// Wrap a validated POL-1 layer as the staged derivation input — the
    /// owner-internal PUBLIC seeding path (the ds-nft analog of the sibling
    /// `ds_dnsgate::apply::Evaluator::from_layer` /
    /// `ds_tlsproxy::apply::Evaluator::from_layer`).
    ///
    /// The layer has already passed [`pol1::parse_layer`]'s structural validators
    /// by the time this runs from `prepare` (or by a caller that seeds the
    /// consumer's initial `vN` input from a parsed boot layer). This is `pub` so the
    /// LIVE host-agent NFT-programmer fan-out can construct the REAL
    /// [`PolicyConsumer`] (`PolicyConsumer::new(RulesetSource::from_layer(layer),
    /// seq)`) and drive it through the non-vacuous [`Consumer::prepare_verified`]
    /// gate via [`crate::ingest::ingest_snapshot`] — the production path the bare
    /// in-crate constructor could never reach, and the gap the cross-consumer
    /// conformance test names (the ds-nft leg previously drove a fake because the
    /// real consumer had no public constructor). It composes NOTHING and runs no
    /// netlink/kernel side effect — it only wraps an already-validated layer; the
    /// ruleset DERIVATION + the netlink transaction stay downstream (mechanism;
    /// `prepare_verified` only STAGES).
    pub fn from_layer(layer: PolicyLayer) -> RulesetSource {
        RulesetSource { layer }
    }

    /// The validated POL-1 layer the programmer derives the ruleset from.
    #[must_use]
    pub fn layer(&self) -> &PolicyLayer {
        &self.layer
    }
}

/// One staged-but-not-yet-active derivation input, parked by `prepare` and
/// consumed by the matching `commit`. Keyed by the [`ApplyToken`] so a presented
/// token can only flip the exact `(seq, content_hash)` its `prepare` validated
/// (no cross-snapshot reuse), and a re-driven barrier re-presenting the same token
/// is recognised (idempotence on the token).
#[derive(Clone)]
struct Staged {
    token: ApplyToken,
    source: Arc<RulesetSource>,
}

/// The NFTables programmer's [`Consumer`] implementor — the enforcer's two-phase
/// apply state.
///
/// State held behind the per-consumer atomic-flip contract (D72):
/// - `live` — the `vN` derivation input the live ruleset is programmed from. The
///   commit is a single `RwLock` write swapping the `Arc` (the in-process analog
///   of the one netlink transaction), so a reader sees the whole old or the whole
///   new input — never a torn document.
/// - `staged` — the at-most-one prepared `vN+1` input awaiting commit. A new
///   `prepare` atomically REPLACES any earlier staged slot (one apply in flight
///   per consumer; a superseded stage drops).
/// - `applied_seq` — advanced LAST, only after the post-commit sweep completes
///   (D72); the host heartbeat reports the MIN over the three consumers.
pub struct PolicyConsumer {
    live: RwLock<Arc<RulesetSource>>,
    staged: Mutex<Option<Staged>>,
    committed: Mutex<Option<ApplyToken>>,
    applied_seq: AtomicU64,
    /// Injected commit-transaction fault. When set, the next `commit` (for a
    /// not-yet committed token) detects the netlink batch as un-applicable BEFORE
    /// swapping `live`, reverts to `vN` (the stage is left intact), and returns
    /// [`ApplyError::CommitFailed`]. The in-process stand-in for a real netlink
    /// transaction that did not apply, exercising the fail-closed/abort-at-consumer
    /// contract without a framework error type crossing the seam. Default `false`.
    commit_fault: AtomicBool,
}

impl PolicyConsumer {
    /// Create a programmer already holding an initial `vN` derivation input (the
    /// host's first verified boot snapshot). A booting host serves nothing beyond
    /// NFT-1 default-deny before its first verified snapshot.
    #[must_use]
    pub fn new(initial: RulesetSource, initial_seq: PolicyVersion) -> PolicyConsumer {
        PolicyConsumer {
            live: RwLock::new(Arc::new(initial)),
            staged: Mutex::new(None),
            committed: Mutex::new(None),
            applied_seq: AtomicU64::new(initial_seq.seq()),
            commit_fault: AtomicBool::new(false),
        }
    }

    /// Seed a programmer's initial `vN` input directly from a validated POL-1 layer
    /// — the live host-agent NFT-programmer fan-out's one-liner seeding entrypoint
    /// (the public seeding path this unit adds, so the REAL consumer is reachable
    /// from the production fan-out + the cross-consumer conformance test). It is
    /// exactly `PolicyConsumer::new(RulesetSource::from_layer(boot_layer),
    /// initial_seq)` — the host parses its first verified boot snapshot once
    /// (`ds_contracts::pol1::parse_layer`), then seeds the programmer with the
    /// parsed layer; thereafter every fanned-out version rides
    /// [`crate::ingest::ingest_snapshot`] into the non-vacuous
    /// [`Consumer::prepare_verified`] gate. No netlink/kernel side effect — it only
    /// wraps the validated layer as the `vN` derivation input.
    #[must_use]
    pub fn seed_from_layer(boot_layer: PolicyLayer, initial_seq: PolicyVersion) -> PolicyConsumer {
        PolicyConsumer::new(RulesetSource::from_layer(boot_layer), initial_seq)
    }

    /// Arm/disarm the injected commit-transaction fault (see
    /// [`Self::commit_fault`]). Operationally a no-op the programmer never sets in
    /// steady state; it makes the `commit` revert-to-`vN` /
    /// [`ApplyError::CommitFailed`] path observable so the fail-closed
    /// abort-at-consumer contract is tested rather than asserted.
    pub fn set_commit_fault(&self, armed: bool) {
        self.commit_fault.store(armed, Ordering::SeqCst);
    }

    /// The derivation input the live ruleset is currently programmed from (`vN`).
    /// A clone of the `Arc`, so the caller holds the live input without keeping the
    /// `RwLock` read guard.
    #[must_use]
    pub fn live(&self) -> Arc<RulesetSource> {
        Arc::clone(&self.live.read().expect("live ruleset source lock poisoned"))
    }

    /// The current `applied_seq` (advanced only after a completed sweep; D72).
    #[must_use]
    pub fn applied_seq(&self) -> PolicyVersion {
        PolicyVersion(self.applied_seq.load(Ordering::SeqCst))
    }

    /// Parse + structurally validate verified snapshot bytes into a derivation
    /// input, mapping a `policy-core`-schema rejection onto a content-free
    /// [`PrepareError::SchemaInvalid`]. Shared by `prepare`.
    fn validate_and_build(
        snapshot: &[u8],
        version: PolicyVersion,
    ) -> Result<RulesetSource, PrepareError> {
        // The transported bytes are UTF-8 POL-1 document text. A non-UTF-8 body
        // is a schema rejection (the reader only accepts text); never logged.
        let text = std::str::from_utf8(snapshot).map_err(|_| PrepareError::SchemaInvalid {
            version,
            reason: "snapshot bytes are not valid UTF-8 policy text".to_string(),
        })?;
        // `parse_layer` runs the §8.1 structural validators (schema/syntax, D53
        // rung-cap, fail_open legality, D74 mandatory provenance) in one pass —
        // the policy-core schema layer, owned by ds-contracts.
        let layer = pol1::parse_layer(text).map_err(|errs| PrepareError::SchemaInvalid {
            version,
            reason: summarize_policy_errors(&errs),
        })?;
        Ok(RulesetSource::from_layer(layer))
    }
}

/// Render a `policy-core`-schema rejection bundle as a short, CONTENT-FREE reason:
/// the structural error codes only (never the offending document text), suitable
/// for the [`PrepareError::SchemaInvalid`] reason field and a log line.
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

/// One flow to consider severing in a post-commit fleet-revocation sweep (D102 /
/// P-R6, doc 19 §7): a live session admitted under a fleet-revoked token, paired
/// with the D53 rung the revocation was published at. The host agent resolves the
/// revoked token's fingerprint (carried in the committed document, which
/// `ds-policy-snapshot` recognizes) to the sessions it admitted; this crate
/// severs them mechanism-only, encoding no policy beyond the rung gate.
#[derive(Clone, Debug)]
pub struct RevokedFlow {
    /// The live session whose established flows a severing revocation drops.
    pub session: SessionRef,
    /// The D53 rung the fleet revocation was published at.
    pub rung: Rung,
}

/// The accounting of a post-commit fleet-revocation sweep (doc 19 §13
/// fleet-revocation-clock; D72). Counters only — no session identity is retained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RevocationFlushReport {
    /// Sessions severed through `flush_session` (rung was block-or-higher).
    pub sessions_severed: u64,
    /// Flows left alone because the rung was below block-or-higher.
    pub rung_skipped: u64,
    /// Conntrack entries destroyed across every severed session.
    pub entries_flushed: u64,
}

impl PolicyConsumer {
    /// The post-commit fleet-revocation sweep (D72 sweep phase; doc 19 §7). After
    /// the ruleset flip has already gated NEW flows on `vN+1`, this severs the
    /// ESTABLISHED flows admitted under fleet-revoked tokens RUNG-CONDITIONALLY
    /// (D53/D77), then advances `applied_seq` LAST — only once the sweep completes
    /// (the D72 ordering [`Consumer::sweep_and_advance_applied_seq`]'s doc names,
    /// here elaborated with the real flush).
    ///
    /// Severing goes through the shared [`ds_contracts::flush::FlushSession`]
    /// primitive (D68) exactly as-is — `DstFilter::All` (a token revocation drops
    /// the whole session) on [`LegSelector::sever_pair`] — a CALL-SITE onto
    /// `flush_session`; its signature (`ds-contracts`) and this crate's `flush.rs`
    /// body are UNTOUCHED. The rung gate is the single shared threshold
    /// [`ds_contracts::pol1::Rung::is_block_or_higher`] — the same predicate
    /// `policy-core`'s `Decision::is_revocation_severing` wraps.
    ///
    /// Fail-closed: the token must name the currently-committed version (a sweep
    /// runs post-commit), and a flush failure ABORTS the sweep BEFORE `applied_seq`
    /// advances — the host never reports a version applied whose revocations did
    /// not enforce.
    pub fn sweep_revocations_and_advance<B: NftBackend>(
        &self,
        token: &ApplyToken,
        writer: &NftWriter<B>,
        revoked: &[RevokedFlow],
    ) -> Result<(PolicyVersion, RevocationFlushReport), ApplyError> {
        // The sweep runs only for the currently-committed token (mirrors
        // `sweep_and_advance_applied_seq`'s guard): never flush against an
        // uncommitted / stale version.
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
        let mut report = RevocationFlushReport::default();
        for flow in revoked {
            // Rung-conditional (D53/D77): only block-or-higher severs established
            // flows; a lower rung already gated new flows via the committed ruleset.
            if !flow.rung.is_block_or_higher() {
                report.rung_skipped += 1;
                continue;
            }
            let outcome = writer
                .flush_session(&flow.session, &DstFilter::All, &LegSelector::sever_pair())
                .map_err(|e| ApplyError::CommitFailed {
                    version: token.version(),
                    reason: format!("fleet-revocation flush failed: {e:?}"),
                })?;
            report.sessions_severed += 1;
            report.entries_flushed += outcome.entries_flushed;
        }
        // `applied_seq` advances LAST — only now that the sweep-plus-flush has
        // completed (D72). Delegates to the existing idempotent advance, which
        // re-checks the committed token.
        let version = self.sweep_and_advance_applied_seq(token)?;
        Ok((version, report))
    }
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
        // not hash to the transported identity, so the allow-set is never re-staged
        // and the programmer stays on vN. (The transported hash makes this real:
        // re-hashing the bytes and comparing to their own hash can never NACK.)
        if !snapshot_verify::verify_snapshot_bytes(snapshot, expected_hash).is_verified() {
            return Err(PrepareError::HashMismatch { version });
        }

        // (2) Parse + validate via the embedded policy-core schema layer, then
        // build the staged derivation input. A rejection aborts the host-wide apply.
        let source = PolicyConsumer::validate_and_build(snapshot, version)?;

        // (3) Stage — never flip. Park the new derivation input in the
        // not-yet-active slot; the live ruleset stays on `vN`. The token pins the
        // VERIFIED transported hash.
        let token = ApplyToken::new(version, *expected_hash);
        *self.staged.lock().expect("staged slot lock poisoned") = Some(Staged {
            token: token.clone(),
            source: Arc::new(source),
        });
        Ok(token)
    }

    fn commit(&self, token: &ApplyToken) -> Result<(), ApplyError> {
        // (1) Idempotent on the token: an already-committed token is a no-op
        // success — the second call sees vN+1 already live and runs no second
        // transaction.
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

        // (2) Revert-to-vN on a transaction fault. Detect an un-applicable netlink
        // batch BEFORE touching `live`: the programmer stays on vN, the stage is
        // left intact for a re-drive, and CommitFailed aborts the apply at the
        // consumer level so the host driver detects it and aborts host-wide. A
        // netlink batch is all-or-none — the programmer never half-flips.
        if self.commit_fault.load(Ordering::SeqCst) {
            return Err(ApplyError::CommitFailed {
                version: token.version(),
                reason: "netlink ruleset transaction did not apply".to_string(),
            });
        }

        // (3) The atomic flip — the in-process analog of the one netlink
        // transaction: a single RwLock write swaps the live Arc. A reader sees the
        // whole old or whole new ruleset input — never torn. The write guard is
        // dropped before commit returns, so every derivation that begins after the
        // return reads vN+1 — immediately observable to new traffic, vN never
        // interrupted.
        *self
            .live
            .write()
            .expect("live ruleset source lock poisoned") = staged.source;
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
        // applied_seq advances LAST — only after the (here trivial, elaborated by
        // the sibling sweep unit) post-commit revocation eviction completes (D72).
        self.applied_seq
            .store(token.version().seq(), Ordering::SeqCst);
        Ok(token.version())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clean POL-1 session layer that stages successfully.
    const VALID_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                             dns:\n  boundary_zone: corp.example.\n";

    /// A POL-1 document with an unknown rung token — the embedded schema validator
    /// (D53 rung values) must REJECT it at prepare.
    const BAD_RUNG_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
         content:\n  generic:\n    rules:\n      - id: r1\n        match: badword\n        \
         rung: obliterate+now\n";

    fn consumer_at(seq: u64, doc: &str) -> PolicyConsumer {
        let layer = pol1::parse_layer(doc).expect("seed layer parses");
        PolicyConsumer::new(RulesetSource::from_layer(layer), PolicyVersion(seq))
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

        // Staged input does NOT program the live ruleset: live pointer + seq fixed.
        assert_eq!(
            Arc::as_ptr(&c.live()),
            live_before,
            "stage must not flip live"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(1));
        assert!(
            c.staged.lock().unwrap().is_some(),
            "input parked, not active"
        );
    }

    #[test]
    fn invalid_snapshot_returns_error_and_leaves_the_running_input_unchanged() {
        let c = consumer_at(5, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());

        let err = c
            .prepare(BAD_RUNG_DOC.as_bytes(), PolicyVersion(6))
            .expect_err("unsupported rung must be rejected");
        match err {
            PrepareError::SchemaInvalid { version, reason } => {
                assert_eq!(version, PolicyVersion(6));
                assert!(reason.contains("BadRung"), "reason={reason}");
                assert!(!reason.contains("badword"), "reason must not echo doc body");
            }
            other => panic!("expected SchemaInvalid, got {other:?}"),
        }
        // Fail-closed: nothing staged, the running input + seq untouched.
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
        // fail-closed PrepareError::HashMismatch — parse + stage NEVER run, so the
        // allow-set is never re-staged, the running derivation input + applied_seq
        // are untouched, and nothing is staged (the programmer stays on vN).
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
        // Fail-closed: no parse/stage residue — running input + seq untouched,
        // nothing staged (allow-set never re-staged).
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
        // Still only STAGED — the live ruleset input did not flip.
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
        // The live derivation input now reflects vN+1 (the staged layer).
        assert_eq!(c.live().layer().dns.boundary_zone, "next.example.");
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
    fn commit_transaction_is_observable_to_new_traffic_without_interrupting_vn() {
        // A derivation that began on vN keeps the whole vN ruleset input; one that
        // begins after commit returns reads vN+1. The netlink batch is all-or-none.
        let c = consumer_at(1, VALID_DOC);
        let in_flight_vn = c.live();
        let vn_ptr = Arc::as_ptr(&in_flight_vn);

        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        assert_eq!(Arc::as_ptr(&c.live()), vn_ptr, "pre-commit serves vN");

        c.commit(&token).expect("commit");

        let new_traffic = c.live();
        assert_ne!(Arc::as_ptr(&new_traffic), vn_ptr, "new traffic reads vN+1");
        assert_eq!(new_traffic.layer().dns.boundary_zone, "next.example.");
        assert_eq!(
            Arc::as_ptr(&in_flight_vn),
            vn_ptr,
            "the in-flight vN derivation is never torn or interrupted"
        );
    }

    #[test]
    fn commit_transaction_fault_reverts_to_vn_fail_closed_and_unblocks_host_abort() {
        let c = consumer_at(7, VALID_DOC);
        let live_before = Arc::as_ptr(&c.live());
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(8)).expect("stage");

        // Arm the transaction fault: as an enforcer the programmer staying on vN
        // is at-least-as-strict, so the abort keeps the mixed-version window
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
        assert_eq!(
            Arc::as_ptr(&c.live()),
            live_before,
            "programmer stays on vN"
        );
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
        assert_eq!(c.live().layer().dns.boundary_zone, "two.example.");
    }

    #[test]
    fn consumer_is_usable_through_a_trait_object() {
        let seed = pol1::parse_layer(VALID_DOC).expect("parses");
        let c: Box<dyn Consumer> = Box::new(PolicyConsumer::new(
            RulesetSource::from_layer(seed),
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

    #[test]
    fn seed_from_layer_builds_the_real_consumer_at_vn() {
        // The PUBLIC seeding path the live fan-out uses: parse the boot snapshot once,
        // seed the REAL PolicyConsumer with the parsed layer. It is `vN` exactly as
        // `new(RulesetSource::from_layer(..), seq)` would be — no flip, no side effect.
        let layer = pol1::parse_layer(VALID_DOC).expect("boot layer parses");
        let c = PolicyConsumer::seed_from_layer(layer, PolicyVersion(3));
        assert_eq!(c.applied_seq(), PolicyVersion(3));
        assert_eq!(c.live().layer().dns.boundary_zone, "corp.example.");
        assert!(
            c.staged.lock().unwrap().is_none(),
            "a freshly-seeded programmer stages nothing"
        );
    }

    #[test]
    fn live_ingest_nacks_a_transported_hash_mismatch_before_re_staging_the_allow_set() {
        // The LIVE-INGEST production path: the host fan-out routes a snapshot through
        // `ingest::ingest_snapshot` into the REAL consumer's non-vacuous
        // `prepare_verified` gate (the gap this unit closes — the real consumer is now
        // reachable from outside the crate via the public `seed_from_layer`). A
        // SEPARATELY-transported hash that does NOT match the bytes is fail-closed
        // HashMismatch: parse / stage / allow-set re-derivation NEVER runs, so nothing is
        // staged and the programmer stays on vN.
        use crate::ingest::{ingest_snapshot, NftSnapshotIngest};

        let seed = pol1::parse_layer(VALID_DOC).expect("boot layer parses");
        let c = PolicyConsumer::seed_from_layer(seed, PolicyVersion(5));
        let live_before = Arc::as_ptr(&c.live());

        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        // A producer-pinned hash that does NOT match `next` (one flipped byte): the
        // transported identity tuple is torn (a tampered/torn transport, D120).
        let mut wrong = snapshot_verify::sha256(next.as_bytes());
        wrong[0] ^= 0x01;
        let ingest = NftSnapshotIngest::new(6, wrong, next.as_bytes().to_vec());

        match ingest_snapshot(&c, &ingest) {
            Err(PrepareError::HashMismatch { version }) => assert_eq!(version, PolicyVersion(6)),
            other => panic!("expected HashMismatch from the live ingest, got {other:?}"),
        }
        // Fail-closed: no parse/stage residue — the programmer stays on vN, nothing staged
        // (allow-set never re-staged).
        assert_eq!(
            Arc::as_ptr(&c.live()),
            live_before,
            "a transported-hash mismatch must not flip the programmer off vN"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(5));
        assert!(
            c.staged.lock().unwrap().is_none(),
            "a hash-failing snapshot must never stage (allow-set never re-staged)"
        );

        // The MATCHING transported hash stages as today (happy path unchanged), pinning
        // the verified transported hash on the token — STAGED only, no flip.
        let good = NftSnapshotIngest::new(
            6,
            snapshot_verify::sha256(next.as_bytes()),
            next.as_bytes().to_vec(),
        );
        let token = ingest_snapshot(&c, &good).expect("matching transported hash stages");
        assert_eq!(token.version(), PolicyVersion(6));
        assert_eq!(token.content_hash, snapshot_verify::sha256(next.as_bytes()));
        assert!(
            c.staged.lock().unwrap().is_some(),
            "the verified snapshot is staged"
        );
        assert_eq!(
            Arc::as_ptr(&c.live()),
            live_before,
            "the live ruleset input did not flip on a stage"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(5));
    }

    // ── Fleet token-revocation sweep (D102 / P-R6, doc 19 §7/§13) ────────────

    use crate::backend::{BackendError, ConntrackOutput, RecordingBackend};

    /// Build a consumer committed at v2 and return (consumer, committed token) —
    /// the state a post-commit revocation sweep runs in.
    fn committed_consumer() -> (PolicyConsumer, ApplyToken) {
        let c = consumer_at(1, VALID_DOC);
        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let token = c.prepare(next.as_bytes(), PolicyVersion(2)).expect("stage");
        c.commit(&token).expect("commit");
        (c, token)
    }

    fn rev_session(idx: u32) -> SessionRef {
        SessionRef::new(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    /// One destroyed-entry conntrack accounting line (inline; no fixtures) — the
    /// shape [`crate::outcome::parse_destroy_output`] counts one record from.
    fn acct(dst: &str) -> ConntrackOutput {
        ConntrackOutput {
            lines: vec![format!(
                "tcp 6 110 src=10.0.0.5 dst={dst} sport=51514 dport=443 packets=12 \
                 bytes=1000 src={dst} dst=10.0.0.5 sport=443 dport=51514 packets=10 \
                 bytes=800 [ASSURED]"
            )],
        }
    }

    #[test]
    fn fleet_revocation_sweep_severs_block_or_higher_flows_and_advances_applied_seq() {
        let (c, token) = committed_consumer();
        let writer = NftWriter::new(RecordingBackend::new());
        // sever_pair spans 2 legs → 2 destroys per session; seed one accounting
        // line per destroy so `entries_flushed` is observable (2 sessions × 2 legs).
        for _ in 0..4 {
            writer.backend().push_conntrack_output(acct("203.0.113.10"));
        }
        let revoked = vec![
            RevokedFlow {
                session: rev_session(7),
                rung: Rung::KillSnapshot,
            },
            RevokedFlow {
                session: rev_session(8),
                rung: Rung::BlockLog,
            },
        ];
        // applied_seq is still vN before the sweep (it advances LAST, D72).
        assert_eq!(c.applied_seq(), PolicyVersion(1));

        let (version, report) = c
            .sweep_revocations_and_advance(&token, &writer, &revoked)
            .expect("sweep");

        assert_eq!(version, PolicyVersion(2));
        assert_eq!(
            c.applied_seq(),
            PolicyVersion(2),
            "applied_seq advances only AFTER the sweep-plus-flush completes"
        );
        assert_eq!(report.sessions_severed, 2);
        assert_eq!(report.rung_skipped, 0);
        assert_eq!(
            report.entries_flushed, 4,
            "one conntrack destroy record per (leg, session)"
        );

        // The real flush_session reached the backend: 2 sessions × 2 legs = 4
        // destroys, each DstFilter::All (dst=None) — a token revocation drops the
        // whole session.
        let destroys = writer.backend().destroys();
        assert_eq!(destroys.len(), 4);
        assert!(
            destroys.iter().all(|d| d.dst.is_none()),
            "a token revocation flushes every destination (DstFilter::All)"
        );
    }

    #[test]
    fn fleet_revocation_sweep_skips_below_block_rungs_but_still_advances() {
        let (c, token) = committed_consumer();
        let writer = NftWriter::new(RecordingBackend::new());
        let revoked = vec![RevokedFlow {
            session: rev_session(9),
            rung: Rung::AllowLog,
        }];
        let (version, report) = c
            .sweep_revocations_and_advance(&token, &writer, &revoked)
            .expect("sweep");
        assert_eq!(version, PolicyVersion(2));
        assert_eq!(report.sessions_severed, 0);
        assert_eq!(report.rung_skipped, 1);
        assert_eq!(report.entries_flushed, 0);
        assert!(
            writer.backend().destroys().is_empty(),
            "allow+log severs no established flow (expiry-is-not-revocation sibling)"
        );
        assert_eq!(c.applied_seq(), PolicyVersion(2));
    }

    #[test]
    fn fleet_revocation_sweep_is_fail_closed_on_a_flush_failure() {
        let (c, token) = committed_consumer();
        let writer = NftWriter::new(RecordingBackend::new());
        writer
            .backend()
            .arm_error(BackendError::new("conntrack -D failed"));
        let revoked = vec![RevokedFlow {
            session: rev_session(7),
            rung: Rung::KillSnapshot,
        }];
        match c.sweep_revocations_and_advance(&token, &writer, &revoked) {
            Err(ApplyError::CommitFailed { version, .. }) => assert_eq!(version, PolicyVersion(2)),
            other => panic!("expected CommitFailed on a flush failure, got {other:?}"),
        }
        // Fail-closed: applied_seq did NOT advance — the host never reports a
        // version applied whose revocations did not enforce.
        assert_eq!(c.applied_seq(), PolicyVersion(1));
    }

    #[test]
    fn fleet_revocation_sweep_rejects_an_uncommitted_token() {
        let (c, _token) = committed_consumer();
        let writer = NftWriter::new(RecordingBackend::new());
        let foreign = ApplyToken::new(PolicyVersion(99), snapshot_verify::sha256(b"x"));
        match c.sweep_revocations_and_advance(&foreign, &writer, &[]) {
            Err(ApplyError::UnknownToken { version }) => assert_eq!(version, PolicyVersion(99)),
            other => panic!("expected UnknownToken for a non-committed token, got {other:?}"),
        }
    }
}
