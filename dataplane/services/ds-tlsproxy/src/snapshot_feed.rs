// SPDX-License-Identifier: Apache-2.0

//! ds-tlsproxy's HOST-LOCAL policy-snapshot feed CONSUMER — the transport /
//! feed-dispatch layer that routes the host agent's fanned-out snapshots into the
//! [`ds_contracts::consumer::Consumer`] seam (POL-4 part 2; D72/D36, doc 12 §8,
//! doc 13 §5).
//!
//! # What this is (and what it is NOT)
//!
//! ds-tlsproxy is one of the THREE data-plane consumers, and it **never opens a
//! control-plane policy stream** (D36 / D72 §1: the host agent is the SINGLE
//! `WatchPolicies(from_seq)` subscriber per host). The proxy consumes the
//! HOST-LOCAL snapshot feed the host agent fans out behind its prepare/commit
//! barrier. This module is that ingest side: it receives
//! `(seq, content_hash, full composed policy document)` tuples from the host
//! agent's fan-out and routes them — bytes plus the producer-pinned
//! `content_hash` — through the SINGLE verify-before-parse identity gate
//! [`Consumer::prepare_verified`], then ACKs (or NACKs) the
//! `(seq, content_hash)` back to the host agent.
//!
//! The TRANSPORT is free (doc 12 §9; UDS gRPC is the default) — so this module
//! does NOT hard-wire a wire framework. It declares:
//!
//! - [`SnapshotEnvelope`] — the host-local snapshot identity tuple the host agent
//!   fans out: `(seq, content_hash, document bytes)`. Plain data, no framework
//!   type (doc 14 §6).
//! - [`SnapshotAck`] — the consumer's per-snapshot verdict back to the host agent:
//!   [`AckOutcome::Ack`] (verified + staged) naming `(seq, content_hash)`, or
//!   [`AckOutcome::Nack`] (refused) naming the structural reason. A NACK aborts
//!   the apply host-wide and the host stays on `vN` (D72 fail-closed).
//! - [`SnapshotSubscription`] — the receive seam: pull the next envelope off the
//!   host-local feed. A trait so the live UDS-gRPC subscriber and a mock
//!   host-agent stream both drive the SAME dispatch loop.
//! - [`SnapshotAckSink`] — the send seam: deliver one [`SnapshotAck`] back. A
//!   trait for the same reason.
//! - [`SnapshotFeedConsumer`] — the dispatcher: holds a [`Consumer`] (the proxy's
//!   `apply::PolicyConsumer`) and, per envelope, routes the transported bytes +
//!   `content_hash` through the SINGLE [`Consumer::prepare_verified`] identity
//!   gate, mapping the result onto an [`SnapshotAck`].
//! - [`run_snapshot_feed`] — the host-local feed loop: pull → dispatch → ACK,
//!   until the feed closes. Drive it on a dedicated task alongside the proxy's
//!   listeners; production wires a UDS-gRPC subscription + ack-sink, tests a mock
//!   stream.
//!
//! # The single verify-before-parse gate (fail-closed; D72 §5.1)
//!
//! The dispatcher routes the transported bytes AND the envelope's producer-pinned
//! `content_hash` into the ONE non-vacuous identity gate
//! [`Consumer::prepare_verified`], which verifies the bytes against that
//! SEPARATELY-transported hash BEFORE parse (produce-once / verify-only — the host
//! serialized the composed document exactly once and hashed those exact bytes; the
//! consumer never re-serializes). A mismatch is a [`AckOutcome::Nack`] with
//! [`NackReason::HashMismatch`] and **the parse/stage step is never entered** —
//! the staged evaluator is never touched, the proxy stays on `vN`, and the host
//! aborts the apply host-wide. There is NO duplicate inline verify here: the feed
//! exercises the EXACT same gate the in-process callers do (single-source). Only
//! verified bytes reach the parse + `policy-core` schema validation behind the
//! gate; a schema rejection there becomes a [`NackReason::SchemaInvalid`] NACK.
//!
//! `prepare` STAGES; it never flips. This ingest layer therefore advances NOTHING
//! that serves traffic — an ACK means "staged `vN+1`, ready for the host's commit
//! barrier", not "now enforcing `vN+1`". The atomic commit and the post-commit
//! sweep stay with `apply::PolicyConsumer` and the host driver (D72).
//!
//! NEVER-LOG-THE-SECRET: nothing here logs the composed document; the bytes cross
//! as opaque input, the ACK/NACK carry only `(seq, content_hash)` and structural
//! reasons. `#![forbid(unsafe_code)]` (crate root) binds this module.

use ds_contracts::consumer::{Consumer, PolicyVersion, PrepareError};
use ds_contracts::snapshot_verify::{self, ContentHash};

/// One host-local snapshot the host agent fans out to ds-tlsproxy — the
/// `(seq, content_hash, full composed policy document)` identity tuple (doc 13
/// §5). Plain data: no framework type crosses this seam (doc 14 §6), so the same
/// envelope rides a UDS-gRPC message in production and an in-process channel in
/// tests.
///
/// The `document` is the host's ONE composed POL-1 document, serialized EXACTLY
/// ONCE by the host agent (produce-once); `content_hash` is the SHA-256 over
/// those exact bytes. The consumer re-hashes `document` and compares to
/// `content_hash` before parsing (verify-only), never re-serializing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotEnvelope {
    /// The D36 `policy_log` `seq` — the single monotonic policy version end to end
    /// (`vN+1`). No per-service version namespace (D72).
    pub seq: u64,
    /// The SHA-256 `content_hash` the host agent pinned over the produce-once
    /// serialization of `document` (doc 13 §5.1). The consumer re-verifies the
    /// transported bytes hash to exactly this.
    pub content_hash: ContentHash,
    /// The transported composed policy document bytes — the host's ONE composed
    /// POL-1 document. Routed (with `content_hash`) into
    /// [`Consumer::prepare_verified`], which verifies BEFORE parse.
    pub document: Vec<u8>,
}

impl SnapshotEnvelope {
    /// Build an envelope for a `(seq, document)` pair, deriving the `content_hash`
    /// the same single-source way the host agent does (SHA-256 over the exact
    /// bytes). The host-agent fan-out carries the hash it already computed; this
    /// helper is for the mock stream / tests that mint a well-formed envelope.
    #[must_use]
    pub fn new(seq: u64, document: impl Into<Vec<u8>>) -> SnapshotEnvelope {
        let document = document.into();
        let content_hash = snapshot_verify::sha256(&document);
        SnapshotEnvelope {
            seq,
            content_hash,
            document,
        }
    }

    /// Build an envelope carrying an EXPLICIT `content_hash` — the production
    /// shape, where the host agent transports the hash it pinned alongside the
    /// bytes. Lets a test construct a TAMPERED envelope (a hash that does not
    /// match the bytes) to exercise the fail-closed NACK path.
    #[must_use]
    pub fn with_hash(
        seq: u64,
        content_hash: ContentHash,
        document: impl Into<Vec<u8>>,
    ) -> SnapshotEnvelope {
        SnapshotEnvelope {
            seq,
            content_hash,
            document: document.into(),
        }
    }

    /// The version (`seq`) this envelope carries.
    #[must_use]
    pub fn version(&self) -> PolicyVersion {
        PolicyVersion(self.seq)
    }
}

/// Why the consumer NACK'd a snapshot — the structural reason the host agent
/// reads to attribute the host-wide abort. Content-free (NEVER-LOG-THE-SECRET):
/// a phase + a short reason, never the document body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NackReason {
    /// The transported bytes did NOT hash to the envelope's `content_hash` — the
    /// SINGLE verify-before-parse gate inside [`Consumer::prepare_verified`]
    /// refused them BEFORE parse (doc 13 §5.1). Parse/stage never ran; the staged
    /// evaluator is untouched.
    HashMismatch,
    /// The bytes verified but the embedded `policy-core` rejected the document as
    /// structurally invalid (a schema violation, an illegal rung-cap, missing
    /// mandatory provenance — doc 13 §8.1). Carries the content-free reason
    /// `prepare` produced.
    SchemaInvalid {
        /// A short, content-free reason (the structural error codes only).
        reason: String,
    },
    /// The document was valid but the consumer could not stage a new evaluator (a
    /// resource limit / internal staging fault). Re-drivable.
    StageFailed {
        /// A short, content-free reason.
        reason: String,
    },
}

impl core::fmt::Display for NackReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NackReason::HashMismatch => f.write_str("content_hash mismatch (verify-only gate)"),
            NackReason::SchemaInvalid { reason } => write!(f, "schema invalid: {reason}"),
            NackReason::StageFailed { reason } => write!(f, "stage failed: {reason}"),
        }
    }
}

/// The consumer's per-snapshot verdict back to the host agent: ACK (verified +
/// staged) or NACK (refused, abort host-wide). A NACK keeps the host on `vN`
/// (all-or-none, fail-closed; D72).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AckOutcome {
    /// The snapshot verified and STAGED (`prepare` returned a token): the proxy is
    /// ready for the host's commit barrier. An ACK does NOT mean the proxy is
    /// enforcing `vN+1` — the atomic flip is the separate commit phase (D72).
    Ack,
    /// The snapshot was REFUSED — the apply aborts host-wide and the host stays on
    /// `vN`. Carries the structural reason.
    Nack {
        /// Why the snapshot was refused (content-free).
        reason: NackReason,
    },
}

impl AckOutcome {
    /// Whether this outcome staged the snapshot (an ACK).
    #[must_use]
    pub fn is_ack(&self) -> bool {
        matches!(self, AckOutcome::Ack)
    }
}

/// The ACK message returned to the host agent for one snapshot — names the
/// `(seq, content_hash)` it pertains to (the snapshot identity the host pinned)
/// and the [`AckOutcome`]. The host routes this back to its commit barrier: an
/// ACK from every consumer is the green-light to commit; any NACK aborts.
///
/// Carrying BOTH `seq` and `content_hash` (not just `seq`) lets the host agent
/// match the ACK to the exact snapshot it fanned out — a stale ACK for a
/// superseded `content_hash` is recognisable, never mistaken for the live one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotAck {
    /// The `seq` (`vN+1`) this ACK pertains to.
    pub seq: u64,
    /// The `content_hash` of the snapshot this ACK pertains to — the exact bytes
    /// identity, so the host matches the ACK to the snapshot it fanned out.
    pub content_hash: ContentHash,
    /// The verdict: staged (ACK) or refused (NACK).
    pub outcome: AckOutcome,
}

impl SnapshotAck {
    /// An ACK naming the staged snapshot identity.
    #[must_use]
    pub fn ack(seq: u64, content_hash: ContentHash) -> SnapshotAck {
        SnapshotAck {
            seq,
            content_hash,
            outcome: AckOutcome::Ack,
        }
    }

    /// A NACK naming the refused snapshot identity and the structural reason.
    #[must_use]
    pub fn nack(seq: u64, content_hash: ContentHash, reason: NackReason) -> SnapshotAck {
        SnapshotAck {
            seq,
            content_hash,
            outcome: AckOutcome::Nack { reason },
        }
    }

    /// Whether this ACK staged the snapshot.
    #[must_use]
    pub fn is_ack(&self) -> bool {
        self.outcome.is_ack()
    }
}

/// The RECEIVE seam: pull the next host-local snapshot off the feed. The live
/// UDS-gRPC subscriber and a mock host-agent stream both implement this so the
/// SAME [`run_snapshot_feed`] dispatch loop drives either. `None` means the feed
/// is closed (the host agent fan-out went away — the proxy is shutting down) and
/// the loop ends.
///
/// The transport is FREE (doc 12 §9): an implementor over UDS gRPC pulls the next
/// streamed message; the in-process test impl pops a queue. No framework type
/// crosses — the trait yields only the plain [`SnapshotEnvelope`].
pub trait SnapshotSubscription {
    /// Pull the next snapshot envelope, or `None` once the feed is closed.
    fn next_snapshot(&mut self) -> Option<SnapshotEnvelope>;
}

/// The ack channel back to the host agent is gone (the host agent went away —
/// the proxy is shutting down). Returned by [`SnapshotAckSink::send_ack`] so the
/// feed loop can stop (nothing left to ACK to). A content-free marker — it
/// carries no document and no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckSinkClosed;

impl core::fmt::Display for AckSinkClosed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("snapshot ack sink closed (host agent went away)")
    }
}

impl std::error::Error for AckSinkClosed {}

/// The SEND seam: deliver one ACK/NACK back to the host agent. Same dual-impl
/// rationale as [`SnapshotSubscription`] — UDS gRPC in production, an in-process
/// recorder in tests. Returns [`AckSinkClosed`] if the ack channel is gone (the
/// host agent went away); the loop then stops (nothing left to ACK to).
pub trait SnapshotAckSink {
    /// Send one ACK back to the host agent. [`AckSinkClosed`] if the sink is
    /// closed.
    fn send_ack(&mut self, ack: SnapshotAck) -> Result<(), AckSinkClosed>;
}

/// The host-local snapshot-feed DISPATCHER — routes one verified snapshot into
/// the [`Consumer`] seam and produces its ACK/NACK. Generic over the consumer so
/// it binds the proxy's concrete `apply::PolicyConsumer` (and any other
/// [`Consumer`] in a test) with no `dyn` indirection.
///
/// The dispatcher owns NO transport — it is the pure prepare_verified→ack
/// mapping (the verify-before-parse gate lives inside that one call).
/// [`run_snapshot_feed`] supplies the transport (the subscription + ack sink).
pub struct SnapshotFeedConsumer<C: Consumer> {
    consumer: C,
}

impl<C: Consumer> SnapshotFeedConsumer<C> {
    /// Wrap a [`Consumer`] (the proxy's `apply::PolicyConsumer`) as the
    /// feed-dispatch target.
    #[must_use]
    pub fn new(consumer: C) -> SnapshotFeedConsumer<C> {
        SnapshotFeedConsumer { consumer }
    }

    /// Borrow the wrapped consumer (so the proxy can drive `commit` /
    /// `sweep_and_advance_applied_seq` and read `live` off the SAME consumer this
    /// feed stages into).
    #[must_use]
    pub fn consumer(&self) -> &C {
        &self.consumer
    }

    /// Dispatch one snapshot through the SINGLE verify-before-parse gate — the
    /// fail-closed core (D72 §5.1):
    ///
    /// Route the transported bytes AND the envelope's producer-pinned
    /// `content_hash` into [`Consumer::prepare_verified`], the ONE non-vacuous
    /// identity gate (verify-before-parse against the SEPARATELY-transported hash;
    /// the same gate the in-process callers exercise — no duplicate inline
    /// verify). On a hash mismatch `prepare_verified` returns
    /// [`PrepareError::HashMismatch`] and **the parse/stage step is never entered**
    /// — the staged evaluator is untouched, the proxy stays on `vN`. Only verified
    /// bytes reach the parse + `policy-core` schema validation behind the gate;
    /// success means the snapshot STAGED, a rejection maps onto the matching NACK
    /// reason.
    ///
    /// Returns the [`SnapshotAck`] to hand back to the host agent. The wrapped
    /// consumer is borrowed `&self` — `prepare_verified` is the only consumer call
    /// here (commit/sweep are the host driver's, post-barrier).
    #[must_use]
    pub fn dispatch(&self, envelope: &SnapshotEnvelope) -> SnapshotAck {
        let seq = envelope.seq;
        let content_hash = envelope.content_hash;

        // Route bytes + the producer-pinned content_hash through the ONE
        // verify-before-parse gate. A mismatch is fail-closed HashMismatch and the
        // parse/stage step is NEVER entered (produce-once / verify-only; doc 13
        // §5.1, D120) — the staged evaluator is untouched, the proxy stays on vN.
        // Only verified bytes reach the parse + policy-core schema validation
        // behind the gate; prepare_verified STAGES (never flips). Map onto ACK/NACK.
        match self
            .consumer
            .prepare_verified(&envelope.document, envelope.version(), &content_hash)
        {
            Ok(_token) => SnapshotAck::ack(seq, content_hash),
            Err(err) => SnapshotAck::nack(seq, content_hash, nack_reason_from_prepare(err)),
        }
    }
}

/// Map a [`PrepareError`] onto the NACK reason the host agent reads. The reason
/// strings are already content-free (`prepare` produced them); this only re-tags
/// the phase.
fn nack_reason_from_prepare(err: PrepareError) -> NackReason {
    match err {
        // The single verify-before-parse gate inside prepare_verified refused the
        // bytes: the transported content_hash did not match, so parse/stage never
        // ran (fail-closed; the proxy stays on vN).
        PrepareError::HashMismatch { .. } => NackReason::HashMismatch,
        PrepareError::SchemaInvalid { reason, .. } => NackReason::SchemaInvalid { reason },
        PrepareError::StageFailed { reason, .. } => NackReason::StageFailed { reason },
    }
}

/// The outcome of running the host-local snapshot feed to completion (the feed
/// closed). A small audit tally so the spawning task can report what the
/// subscriber did over its lifetime — purely observational, never gates behavior.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeedRunOutcome {
    /// How many snapshots verified + staged (ACK'd).
    pub acked: u64,
    /// How many snapshots were refused (NACK'd) — host-wide aborts.
    pub nacked: u64,
}

impl FeedRunOutcome {
    /// Total snapshots dispatched (ACK + NACK).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.acked + self.nacked
    }
}

/// The host-local snapshot-feed LOOP: pull → dispatch (verify → `prepare`) → ACK,
/// until the feed closes (the host agent fan-out went away). This is the wiring
/// the proxy spawns on a dedicated task alongside its listeners; the
/// `subscription` + `ack_sink` are the transport (UDS gRPC in production, a mock
/// host-agent stream in tests).
///
/// ds-tlsproxy NEVER opens a control-plane policy stream here (D36/D72 §1): the
/// `subscription` is the HOST-LOCAL feed only. Each pulled envelope is verified
/// and staged through `consumer`; the resulting ACK/NACK is sent back. The loop
/// ends when the feed closes (`next_snapshot` → `None`) or the ack sink closes
/// (the host agent went away — nothing to ACK to), returning the run tally.
///
/// Fail-closed: a NACK does not stop the loop (the host agent decides the
/// host-wide abort off the NACK it receives); the loop just keeps serving the
/// feed. Staging never disturbs `vN` (that is `prepare`'s contract), so a NACK'd
/// or ACK'd snapshot both leave the proxy deciding egress connects on whatever it
/// was serving — only the host's later commit barrier flips it.
pub fn run_snapshot_feed<C, S, A>(
    consumer: &SnapshotFeedConsumer<C>,
    mut subscription: S,
    ack_sink: &mut A,
) -> FeedRunOutcome
where
    C: Consumer,
    S: SnapshotSubscription,
    A: SnapshotAckSink,
{
    let mut outcome = FeedRunOutcome::default();
    while let Some(envelope) = subscription.next_snapshot() {
        let ack = consumer.dispatch(&envelope);
        if ack.is_ack() {
            outcome.acked += 1;
        } else {
            outcome.nacked += 1;
        }
        // Send the ACK/NACK back; if the host agent's ack channel is gone there is
        // nothing left to coordinate with, so stop serving the feed.
        if ack_sink.send_ack(ack).is_err() {
            break;
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::{Evaluator, PolicyConsumer};
    use ds_contracts::pol1;

    /// A clean POL-1 session layer that verifies + stages.
    const VALID_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                             dns:\n  boundary_zone: corp.example.\n";

    /// A POL-1 document with a baseline-pack entry missing mandatory provenance
    /// (D74) — verifies (the hash matches its own bytes) but `policy-core` REJECTS
    /// it at prepare, so it NACKs with `SchemaInvalid`.
    const MISSING_PROVENANCE_DOC: &str = "schema_version: pol1/v0\nlayer: org\nposture: standard\n\
         baseline_pack:\n  pack_version: tld-deny/1\n  entries:\n    - fqdn: evil.example\n";

    fn proxy_consumer_at(seq: u64, doc: &str) -> PolicyConsumer {
        let layer = pol1::parse_layer(doc).expect("seed layer parses");
        PolicyConsumer::new(Evaluator::from_layer(&layer), PolicyVersion(seq))
    }

    /// A mock host-agent snapshot STREAM: hands out a queued set of envelopes in
    /// order, then closes (the production UDS-gRPC subscriber is the other impl).
    struct MockStream {
        queue: std::collections::VecDeque<SnapshotEnvelope>,
    }

    impl MockStream {
        fn new(envelopes: impl IntoIterator<Item = SnapshotEnvelope>) -> MockStream {
            MockStream {
                queue: envelopes.into_iter().collect(),
            }
        }
    }

    impl SnapshotSubscription for MockStream {
        fn next_snapshot(&mut self) -> Option<SnapshotEnvelope> {
            self.queue.pop_front()
        }
    }

    /// A recording ack sink — captures every ACK the host agent would receive.
    #[derive(Default)]
    struct RecordingAckSink {
        acks: Vec<SnapshotAck>,
        closed: bool,
    }

    impl SnapshotAckSink for RecordingAckSink {
        fn send_ack(&mut self, ack: SnapshotAck) -> Result<(), AckSinkClosed> {
            if self.closed {
                return Err(AckSinkClosed);
            }
            self.acks.push(ack);
            Ok(())
        }
    }

    #[test]
    fn verified_snapshot_is_staged_and_acked_naming_seq_and_hash() {
        // ACCEPTANCE: a snapshot published by the host agent arrives, is verified
        // (hash matches), passed to Consumer::prepare, and an ACK is sent back
        // naming (seq, content_hash).
        let consumer = SnapshotFeedConsumer::new(proxy_consumer_at(1, VALID_DOC));
        let live_before = std::sync::Arc::as_ptr(&consumer.consumer().live());

        let next = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                    dns:\n  boundary_zone: next.example.\n";
        let env = SnapshotEnvelope::new(2, next.as_bytes());
        let expected_hash = env.content_hash;

        let ack = consumer.dispatch(&env);
        assert_eq!(ack, SnapshotAck::ack(2, expected_hash));
        assert!(ack.is_ack());
        assert_eq!(ack.seq, 2);
        assert_eq!(ack.content_hash, expected_hash);

        // prepare STAGED — it did not flip: live + applied_seq unchanged, one
        // staged slot now present (the host's commit barrier flips it later).
        assert_eq!(
            std::sync::Arc::as_ptr(&consumer.consumer().live()),
            live_before,
            "dispatch stages, never flips"
        );
        assert_eq!(consumer.consumer().applied_seq(), PolicyVersion(1));
    }

    #[test]
    fn mismatched_hash_nacks_before_parse_via_the_single_gate() {
        // ACCEPTANCE: a TAMPERED envelope NACKs with NackReason::HashMismatch
        // naming (seq, content_hash), and the parse/stage step behind
        // prepare_verified's verify gate is NEVER entered (the staged evaluator is
        // untouched, the proxy stays on vN). dispatch routes the transported
        // content_hash into Consumer::prepare_verified, whose default verifies
        // BEFORE parse; a consumer whose parse/stage (`prepare`) PANICS proves the
        // single gate short-circuits before parse on a mismatch.
        struct PanicOnParse;
        impl Consumer for PanicOnParse {
            fn prepare(
                &self,
                _snapshot: &[u8],
                _version: PolicyVersion,
            ) -> Result<ds_contracts::consumer::ApplyToken, PrepareError> {
                panic!("parse/stage must NOT run past the verify gate on a hash mismatch");
            }
            fn commit(
                &self,
                _token: &ds_contracts::consumer::ApplyToken,
            ) -> Result<(), ds_contracts::consumer::ApplyError> {
                unreachable!()
            }
            fn sweep_and_advance_applied_seq(
                &self,
                _token: &ds_contracts::consumer::ApplyToken,
            ) -> Result<PolicyVersion, ds_contracts::consumer::ApplyError> {
                unreachable!()
            }
        }

        let consumer = SnapshotFeedConsumer::new(PanicOnParse);
        // A TAMPERED envelope: the carried content_hash does not match the bytes.
        let bytes = b"schema_version: pol1/v0\nlayer: session\nposture: standard\n";
        let mut wrong_hash = snapshot_verify::sha256(bytes);
        wrong_hash[0] ^= 0x01;
        let env = SnapshotEnvelope::with_hash(7, wrong_hash, bytes.to_vec());

        // NACKs via the SINGLE prepare_verified gate BEFORE any parse, naming
        // (seq=7, content_hash=wrong_hash) — the PanicOnParse consumer would have
        // panicked if parse ran, so reaching this assert proves verify-before-parse.
        let ack = consumer.dispatch(&env);
        assert_eq!(
            ack,
            SnapshotAck::nack(7, wrong_hash, NackReason::HashMismatch)
        );
        assert!(!ack.is_ack());
        match ack.outcome {
            AckOutcome::Nack {
                reason: NackReason::HashMismatch,
            } => {}
            other => panic!("expected HashMismatch NACK, got {other:?}"),
        }
    }

    #[test]
    fn verified_but_schema_invalid_document_is_nacked_content_free() {
        // The hash verifies (the envelope hashes its own bytes), but policy-core
        // rejects the document at prepare → SchemaInvalid NACK. The reason is
        // content-free: it names the structural code, never the document body.
        let consumer = SnapshotFeedConsumer::new(proxy_consumer_at(5, VALID_DOC));
        let env = SnapshotEnvelope::new(6, MISSING_PROVENANCE_DOC.as_bytes());
        let hash = env.content_hash;

        let ack = consumer.dispatch(&env);
        assert_eq!(ack.seq, 6);
        assert_eq!(ack.content_hash, hash);
        match &ack.outcome {
            AckOutcome::Nack {
                reason: NackReason::SchemaInvalid { reason },
            } => {
                assert!(reason.contains("MissingProvenance"), "reason={reason}");
                assert!(
                    !reason.contains("evil.example"),
                    "NACK reason must not echo the document body"
                );
            }
            other => panic!("expected SchemaInvalid NACK, got {other:?}"),
        }
        // Fail-closed: the proxy stays on vN (applied_seq untouched).
        assert_eq!(consumer.consumer().applied_seq(), PolicyVersion(5));
    }

    #[test]
    fn feed_loop_dispatches_a_mock_host_agent_stream_and_acks_each() {
        // INTEGRATION: a mock host-agent snapshot stream of three envelopes — two
        // verifiable, one tampered — drives the loop end to end; the ack sink
        // captures one ACK/NACK per snapshot, in order, naming the right identity.
        let consumer = SnapshotFeedConsumer::new(proxy_consumer_at(0, VALID_DOC));

        let a = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                 dns:\n  boundary_zone: a.example.\n";
        let env_a = SnapshotEnvelope::new(1, a.as_bytes());
        let hash_a = env_a.content_hash;

        // A tampered middle snapshot: NACK'd, but the loop keeps serving the feed.
        let b_bytes = b"schema_version: pol1/v0\nlayer: session\nposture: standard\n";
        let mut bad = snapshot_verify::sha256(b_bytes);
        bad[5] ^= 0xff;
        let env_b = SnapshotEnvelope::with_hash(2, bad, b_bytes.to_vec());

        let c = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                 dns:\n  boundary_zone: c.example.\n";
        let env_c = SnapshotEnvelope::new(3, c.as_bytes());
        let hash_c = env_c.content_hash;

        let stream = MockStream::new([env_a, env_b, env_c]);
        let mut sink = RecordingAckSink::default();
        let outcome = run_snapshot_feed(&consumer, stream, &mut sink);

        assert_eq!(outcome.acked, 2);
        assert_eq!(outcome.nacked, 1);
        assert_eq!(outcome.total(), 3);
        assert_eq!(
            sink.acks,
            vec![
                SnapshotAck::ack(1, hash_a),
                SnapshotAck::nack(2, bad, NackReason::HashMismatch),
                SnapshotAck::ack(3, hash_c),
            ]
        );
        // The last verified snapshot (seq 3) is the one staged (a re-stage
        // atomically replaces the slot — apply.rs's contract).
        assert_eq!(consumer.consumer().applied_seq(), PolicyVersion(0));
    }

    #[test]
    fn feed_loop_stops_when_the_ack_sink_closes() {
        // If the host agent's ack channel goes away there is nothing to coordinate
        // with: the loop stops rather than spinning the feed into a closed sink.
        let consumer = SnapshotFeedConsumer::new(proxy_consumer_at(0, VALID_DOC));
        let env = SnapshotEnvelope::new(1, VALID_DOC.as_bytes());
        let stream = MockStream::new([env.clone(), env]);
        let mut sink = RecordingAckSink {
            closed: true,
            ..Default::default()
        };
        let outcome = run_snapshot_feed(&consumer, stream, &mut sink);
        // First dispatch ran (ACK counted) but the send failed → loop broke before
        // the second envelope.
        assert_eq!(outcome.total(), 1);
        assert!(sink.acks.is_empty(), "closed sink recorded nothing");
    }

    #[test]
    fn empty_feed_closes_cleanly() {
        let consumer = SnapshotFeedConsumer::new(proxy_consumer_at(0, VALID_DOC));
        let stream = MockStream::new([]);
        let mut sink = RecordingAckSink::default();
        let outcome = run_snapshot_feed(&consumer, stream, &mut sink);
        assert_eq!(outcome, FeedRunOutcome::default());
    }

    #[test]
    fn nack_reason_display_is_content_free() {
        assert!(NackReason::HashMismatch
            .to_string()
            .contains("content_hash mismatch"));
        let s = NackReason::SchemaInvalid {
            reason: "RungCapExceeded".into(),
        }
        .to_string();
        assert!(s.contains("RungCapExceeded"));
    }
}
