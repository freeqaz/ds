//! ds-nft — the one nft/netlink writing API (doc 14 §6 crate map, "nft-writer"
//! row). NFTables has no policy brain of its own (D3, doc 09 §3); this crate is
//! the only code anywhere allowed to write nftables objects, so the
//! single-writer discipline, the dual kernel refresh paths, and the mark-mask
//! discipline are all enforceable in one place.
//!
//! # What lives here
//!
//! - [`flush`] — the [`ds_contracts::flush::FlushSession`] IMPLEMENTATION on
//!   [`flush::NftWriter`]: the one `flush_session(session, dst_filter, legs)`
//!   primitive, DS_MARK_MASK-aware (a bare-index match never fires against the
//!   D76 composite layout), spanning leg nibbles `0x1`/`0x2` when the rung
//!   severs (doc 14 §5; doc 11 §5.4). Serves all three callers — D68
//!   revocation, D72 sweep, NFT-6 teardown — with ONE body.
//! - [`backend`] — the internal [`backend::NftBackend`] trait that hides the
//!   nft/conntrack mechanism, plus the recording fake unit tests run against.
//! - [`refresh`] — BOTH kernel refresh paths behind one internal API (D68, doc
//!   14 §6/§11): the kernel ≥6.12 in-place element-timeout update and the
//!   pre-6.12 delete+add fallback, selected by a kernel probe with an explicit
//!   test override.
//! - [`session`] — the MODEL A per-session admit surface (session doc 11 §3,
//!   D1/D3/D4/D75): [`session::NftWriter::instantiate_session`] ensures the
//!   `inet ds_filter` table (idempotent `add table`, no host bootstrap owns it),
//!   then creates the EMPTY per-session `allow4_<idx>` / `allow6_<idx>` sets in it
//!   (the set NAME is the single-source
//!   [`ds_contracts::session::allow_set_name`]; `allow6` dormant under D75), and
//!   [`session::NftWriter::teardown_session`] removes them. It writes NOTHING
//!   else — the `dstap-*` glob floor owns default-deny/redirect/closure/mark; the
//!   NFT-3b OUTPUT chain that reads the sets is Stage-3, out of scope.
//! - [`redirect`] — the NFT-2 interface-matched transparent-redirect rule-shape
//!   predicate (doc 09 §3 NFT-2, D69): a pure-text contract lint that the udp/tcp
//!   53 → ds-dnsgate redirect (and the NFT-2b 80/443 → ds-tlsproxy cutover) must
//!   satisfy — `iifname`-anchored, never source-IP (the doc 06 (c) spoofing
//!   invariant at the ruleset layer), redirect/dnat verdict, never `dnat to
//!   127.0.0.1`. Same idiom as [`quic_reject`]; the live-kernel half is the
//!   `tests/nft2_spoofing_netns.rs` namespace proof.
//! - [`dot853`] — the NFT-4 port-853 DNS-over-TLS (DoT) drop-rule-shape predicate
//!   (doc 09 §3 NFT-4, D42/D69): a pure-text contract lint that the DoT 853 drop
//!   rules must satisfy — `iifname`-anchored on the unforgeable `dstap-*` session
//!   tap (never the forgeable `ip saddr`), `drop` verdict on BOTH transports.
//!   The Rust mirror of the Go `ErrDoTNotInterfaceAnchored` sentinel
//!   (`assurance/conformance-adapter/resolverlock/nft4_closure.go`), completing the
//!   per-control anchoring trilogy with [`redirect`] (port-53) and [`quic_reject`]
//!   (udp/443). Same idiom as [`quic_reject`]; validated against synthetic fixtures.
//! - [`quic_reject`] — the NFT-4/D70 udp/443 QUIC reject-rule-shape predicate AND
//!   the composer's single source for the floor's reject rule (doc 09 §3, doc 14
//!   §10; taskdb 01KTZV3XN / 01KV8YYA7N). The shape lint (`check_text`) enforces
//!   reject-not-drop + icmpx port-unreachable + per-session `counter` against
//!   synthetic fixtures; [`quic_reject::floor_quic_reject_rule`] renders the
//!   canonical `dstap-*`-anchored, `ct state new`-scoped line the NFT-1 floor
//!   carries (tied to [`ds_contracts::reject::RejectReason::QuicBlocked`]); and
//!   [`quic_reject::floor_quic_reject_is_unshadowed`] is the composition-order
//!   guard — it reads the shipped NFT-1 artifact and proves the reject precedes
//!   the terminal `ct state new drop` (a base-chain `drop` is terminal, so a reject
//!   in NFT-4's later-priority chain alone would be SHADOWED → QUIC silently
//!   dropped, the D70 regression). Kernel-free; the live half is the `RowQUICReject`
//!   conformance row (CAP_NET_ADMIN, deferred).
//! - [`mark_match`] — composes the masked conntrack match from a
//!   `(Leg, session_index)` pair using ONLY [`ds_contracts::mark`]
//!   (compose / DS_MARK_MASK). No raw mark literals live in this crate.
//! - [`flowtag`] — the NFT-5 per-session `ct mark` flow-tag STAMPING writer (doc
//!   09 §3 NFT-5; doc 14 §5, D76): the masked read-modify-write `ct mark set ct
//!   mark & ~DS_MARK_MASK | <composed>` on the VM leg, rendered from
//!   [`mark_match`]/[`ds_contracts::mark`] and applied per session into the
//!   `inet ds_flowtag` table the versioned `nft-5-flowtag.nft` artifact skeletons.
//!   Also the single source of the floor `nflog` drop-observe rule shape
//!   ([`flowtag::floor_drop_observe_rule`]) the `ds-telemetry` drop parser keys on.
//!   Stamps at `priority mangle` (before the floor drop) so a dropped flow's
//!   `nflog` still carries the session. No verdict — the floor keeps drop authority.
//! - [`outcome`] — the richer internal flush outcome (per-entry destroy records
//!   with byte counts parsed from conntrack accounting output, `nf_conntrack_acct=1`,
//!   doc 14 §11) that callers map into ds-flowlog later. The frozen
//!   [`ds_contracts::flush::FlushOutcome`] stays untouched.
//! - [`alarm`] — the doc 14 §4 monitored wrap/exhaustion alarm predicate (live
//!   retention-window indices per host approaching 2^14 → page), threshold
//!   parameterized (ships with NFT-5; emission wiring is later integration).
//! - [`precondition`] — the `nf_conntrack_tcp_loose=0` effectiveness probe (doc
//!   14 §11): without it the flush is a no-op.
//!
//! # What must NOT live here (README "What must NOT live here")
//!
//! - **Policy decisions.** This crate executes mechanism only. Rung-conditionality
//!   (D53: flush when rung ≥ block) is the CALLER's decision, not encoded here
//!   (doc 14 §5; doc 11 §5.4). `flush_session` does exactly what its arguments
//!   say — narrow by `dst_filter`, span the legs in `legs`, destroy.
//! - **The `flush_session` signature or mark constants.** `ds-contracts` owns
//!   those shapes; this crate only implements against them.
//! - **Any linkage from `ds-tlsproxy`** (doc 12 §4.2; doc 14 §5): it runs with
//!   `CAP_NET_RAW` only, never `CAP_NET_ADMIN`, so it cannot rewrite the ruleset
//!   that contains it. A frozen non-edge.
//!
//! # Mechanism (free, doc 11 §4)
//!
//! Under the workspace offline / stdlib-only constraint the recommended path is
//! a spawned `nft -f` batch for set-element ops and a spawned
//! `conntrack -D --mark <composed>/<DS_MARK_MASK>` for the destroy — both behind
//! [`backend::NftBackend`] so unit tests run against a recording fake and never
//! touch the kernel. The shape can be refined to `nftnl-rs`/netlink later
//! WITHOUT changing the callers, because the mechanism is hidden behind the
//! trait.

//! # C-ABI staticlib edge ([`ffi`])
//!
//! The host agent links this crate as a C-ABI `staticlib` through
//! `orchestrator/internal/nftbridge/` (doc 14 §6; the one Go↔Rust write edge).
//! [`ffi`] is the `#[no_mangle] extern "C"` surface the cgo binding calls —
//! `ds_nft_create_tap` / `ds_nft_delete_tap` / `ds_nft_flush_session` /
//! `ds_nft_instantiate_session` / `ds_nft_teardown_session` / `ds_nft_last_error`,
//! declared for `#include` in `include/ds_nft.h`. The crate root denies unsafe
//! code crate-wide; [`ffi`] carries the single, conscious, reviewed FFI carve-out
//! (D4). The per-session INSTANTIATE / teardown symbols ship under the
//! ratified Model A (D1/D3/D4): they program the admit SURFACE only (the
//! empty `allow{4,6}_<idx>` sets), never floor enforcement — see [`ffi`] and
//! [`session`].

// The single-writer crate denies `unsafe` crate-wide: unsafe is a hard compile
// error in every module EXCEPT the one reviewed FFI carve-out (`ffi`, D4),
// which downgrades to `#![allow(unsafe_code)]` for its `extern "C"` ABI. This is
// `deny`, not `forbid`, precisely so that the D4 exception can be expressed —
// `forbid` is, by language rule, un-downgradeable and would make the reviewed
// C-ABI edge impossible. Every other module remains unable to opt back in (a
// lone `#[allow(unsafe_code)]` outside `ffi` would still trip review here).
#![deny(unsafe_code)]

pub mod alarm;
pub mod apply;
pub mod backend;
pub mod dot853;
pub mod ffi;
pub mod flowtag;
pub mod flush;
pub mod mark_match;
pub mod outcome;
pub mod precondition;
pub mod quic_reject;
pub mod redirect;
pub mod refresh;
pub mod session;

pub use flush::{NftFlushError, NftWriter};
pub use session::NftSessionError;

/// The NFT programmer's LIVE policy-snapshot INGEST entrypoint — the production
/// fan-out call-site that routes a host-agent-delivered snapshot into the frozen
/// [`ds_contracts::consumer::Consumer`] seam through the NON-VACUOUS identity gate
/// [`Consumer::prepare_verified`] (POL-4 part 2; D72/D36, doc 13 §5).
///
/// # Why this exists (the gap this closes)
///
/// The enforcer's [`apply::PolicyConsumer`] already implements the whole D72
/// barrier, and its [`Consumer::prepare_verified`] is the non-vacuous,
/// verify-the-SEPARATELY-transported-hash-BEFORE-parse gate (a transported hash
/// CAN NACK; re-hashing the bytes and comparing to their own hash never can). But
/// the production fan-out reaches the programmer with the host-pinned, separately
/// transported `content_hash` ALONGSIDE the bytes — and the bare
/// [`Consumer::prepare`] (bytes, version) DISCARDS that transported hash, deriving
/// the identity from the bytes themselves, so its verify can never NACK a tampered
/// snapshot. This entrypoint is the missing seam that THREADS the transported
/// `content_hash` into [`Consumer::prepare_verified`] so the live ingest gets the
/// SAME real identity gate the ds-tlsproxy `snapshot_feed` dispatcher already
/// applies (its `SnapshotEnvelope::with_hash` carries the explicit hash; its
/// `dispatch` verifies before prepare). A transported-hash mismatch returns
/// [`PrepareError::HashMismatch`] and the parse / stage / allow-set re-derivation
/// NEVER runs — the programmer stays on `vN`, the host aborts host-wide.
///
/// It is the in-process analog of ds-tlsproxy's feed dispatcher: pure
/// `prepare_verified` → token mapping, owning NO transport (the host-local feed
/// transport — UDS gRPC in production — is the host agent's, OUTSIDE this crate).
/// `prepare_verified` STAGES; it never flips. An `Ok(token)` means "staged `vN+1`,
/// ready for the host's commit barrier", not "now enforcing `vN+1`"; the atomic
/// netlink flip and the post-commit sweep stay with [`apply::PolicyConsumer`] and
/// the host driver (D72).
///
/// NEVER-LOG-THE-SECRET: nothing here logs the snapshot bytes; they cross as
/// opaque input and the [`PrepareError`] surfaces carry only content-free
/// structural reasons. `#![deny(unsafe_code)]` (crate root) binds this module.
pub mod ingest {
    use ds_contracts::consumer::{ApplyToken, Consumer, PolicyVersion, PrepareError};
    use ds_contracts::snapshot_verify::ContentHash;

    /// One host-local snapshot the host agent fans out to the NFT programmer — the
    /// `(seq, content_hash, transported document bytes)` identity tuple (doc 13 §5).
    /// Plain data: no framework type crosses this seam (doc 14 §6), so the same
    /// shape rides the host-local transport in production and an in-process value in
    /// tests. Mirrors ds-tlsproxy's `snapshot_feed::SnapshotEnvelope`.
    ///
    /// The `content_hash` is the SHA-256 the PRODUCER (the host agent) pinned over
    /// the produce-once serialization of `document` and TRANSPORTED ALONGSIDE the
    /// bytes — the separately-transported half that makes the verify in
    /// [`ingest_snapshot`] non-vacuous.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct NftSnapshotIngest {
        /// The D36 `policy_log` `seq` — the single monotonic policy version end to
        /// end (`vN+1`). No per-service version namespace (D72).
        pub seq: u64,
        /// The producer-pinned, SEPARATELY-transported `content_hash` over the
        /// produce-once serialization of `document` (doc 13 §5.1). Fed into
        /// [`Consumer::prepare_verified`], which verifies the bytes against it BEFORE
        /// parse.
        pub content_hash: ContentHash,
        /// The transported composed policy document bytes — the host's ONE composed
        /// POL-1 document. Verified (against `content_hash`) before parse.
        pub document: Vec<u8>,
    }

    impl NftSnapshotIngest {
        /// Build an ingest carrying the producer's EXPLICIT, separately-transported
        /// `content_hash` alongside the bytes — the production shape. (A test can pass
        /// a hash that does NOT match `document` to exercise the fail-closed NACK
        /// path, exactly as ds-tlsproxy's `SnapshotEnvelope::with_hash` does.)
        #[must_use]
        pub fn new(seq: u64, content_hash: ContentHash, document: impl Into<Vec<u8>>) -> Self {
            Self {
                seq,
                content_hash,
                document: document.into(),
            }
        }

        /// The version (`seq`) this ingest carries.
        #[must_use]
        pub fn version(&self) -> PolicyVersion {
            PolicyVersion(self.seq)
        }
    }

    /// Route one host-fanned-out snapshot into the programmer's [`Consumer`] through
    /// the SINGLE non-vacuous identity gate — the fail-closed core (doc 13 §5.1).
    ///
    /// Threads the transported bytes AND the producer-pinned `content_hash` into
    /// [`Consumer::prepare_verified`], which verifies the bytes against that
    /// SEPARATELY-transported hash BEFORE parse (the SAME gate the in-process callers
    /// exercise — no duplicate inline verify here). On a transported-hash mismatch
    /// `prepare_verified` returns [`PrepareError::HashMismatch`] and **the parse /
    /// stage / allow-set re-derivation step is NEVER entered** — the staged
    /// derivation input is untouched, the programmer stays on `vN`, and the host
    /// aborts the apply host-wide. Only verified bytes reach the parse + `policy-core`
    /// schema validation behind the gate; success returns the staged [`ApplyToken`]
    /// (`prepare_verified` STAGES, never flips — the host's commit barrier flips it
    /// later).
    ///
    /// `consumer` is borrowed `&C` — `prepare_verified` is the only consumer call
    /// here (commit / sweep are the host driver's, post-barrier). Generic over the
    /// [`Consumer`] so it binds the programmer's concrete [`apply::PolicyConsumer`]
    /// (and any [`Consumer`] in a test) with no `dyn` indirection.
    ///
    /// [`apply::PolicyConsumer`]: crate::apply::PolicyConsumer
    pub fn ingest_snapshot<C: Consumer>(
        consumer: &C,
        ingest: &NftSnapshotIngest,
    ) -> Result<ApplyToken, PrepareError> {
        // Route bytes + the producer-pinned content_hash through the ONE
        // verify-before-parse gate. A mismatch is fail-closed HashMismatch and the
        // parse / stage / allow-set re-derivation is NEVER entered (produce-once /
        // verify-only; doc 13 §5.1) — the programmer stays on vN. The non-vacuous
        // gate is `prepare_verified` against the SEPARATELY transported hash, NOT the
        // bare `prepare` (which derives the hash from the bytes and can never NACK).
        consumer.prepare_verified(&ingest.document, ingest.version(), &ingest.content_hash)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use ds_contracts::snapshot_verify::sha256;

        // A consumer whose parse/stage (`prepare`) PANICS, proving the ONE
        // verify-before-parse gate inside `prepare_verified` SHORT-CIRCUITS before any
        // parse / stage / allow-set re-derivation on a transported-hash mismatch. (The
        // REAL `apply::PolicyConsumer` is seeded only from within `apply` — its
        // `RulesetSource` has no public constructor — so its identical override is
        // proven by the `apply` unit tests + the cross-consumer conformance test that
        // drives the externally-constructible REAL consumers; here the fake isolates
        // the entrypoint's threading + the gate's fail-closed short-circuit.)
        struct PanicOnParse;
        impl Consumer for PanicOnParse {
            fn prepare(
                &self,
                _snapshot: &[u8],
                _version: PolicyVersion,
            ) -> Result<ApplyToken, PrepareError> {
                panic!("parse/stage (allow-set re-derive) must NOT run past the verify gate on a hash mismatch");
            }
            fn commit(
                &self,
                _token: &ApplyToken,
            ) -> Result<(), ds_contracts::consumer::ApplyError> {
                unreachable!()
            }
            fn sweep_and_advance_applied_seq(
                &self,
                _token: &ApplyToken,
            ) -> Result<PolicyVersion, ds_contracts::consumer::ApplyError> {
                unreachable!()
            }
        }

        // A consumer that STAGES on any verified bytes (records the token it would
        // stage) — proves the entrypoint forwards verified bytes into the consumer's
        // parse/stage path with the version + transported hash intact.
        #[derive(Default)]
        struct RecordingConsumer {
            staged: std::sync::Mutex<Option<ApplyToken>>,
        }
        impl Consumer for RecordingConsumer {
            fn prepare(
                &self,
                snapshot: &[u8],
                version: PolicyVersion,
            ) -> Result<ApplyToken, PrepareError> {
                let token = ApplyToken::new(version, sha256(snapshot));
                *self.staged.lock().unwrap() = Some(token.clone());
                Ok(token)
            }
            fn commit(
                &self,
                _token: &ApplyToken,
            ) -> Result<(), ds_contracts::consumer::ApplyError> {
                unreachable!()
            }
            fn sweep_and_advance_applied_seq(
                &self,
                _token: &ApplyToken,
            ) -> Result<PolicyVersion, ds_contracts::consumer::ApplyError> {
                unreachable!()
            }
        }

        #[test]
        fn matching_transported_hash_forwards_to_parse_and_stages() {
            // A matching transported hash verifies and forwards into the consumer's
            // parse/stage path — the entrypoint threads (bytes, version, hash) intact.
            let c = RecordingConsumer::default();
            let bytes = b"schema_version: pol1/v0\nlayer: session\nposture: standard\n";
            let ingest = NftSnapshotIngest::new(2, sha256(bytes), bytes.to_vec());

            let token = ingest_snapshot(&c, &ingest).expect("matching hash stages");
            assert_eq!(token.version(), PolicyVersion(2));
            assert_eq!(token.content_hash, sha256(bytes));
            assert_eq!(c.staged.lock().unwrap().as_ref(), Some(&token));
        }

        #[test]
        fn transported_hash_mismatch_nacks_before_the_allow_set_is_re_staged() {
            // The NON-VACUOUS gate: a SEPARATELY-transported hash that does NOT match
            // the bytes is fail-closed HashMismatch — the parse / stage / allow-set
            // re-derivation behind prepare_verified is NEVER entered. PanicOnParse
            // would panic if parse ran, so reaching the assert proves verify-before-parse.
            let bytes = b"schema_version: pol1/v0\nlayer: session\nposture: standard\n";
            let mut wrong = sha256(bytes);
            wrong[0] ^= 0x01; // a hash that does NOT match `bytes`
            let ingest = NftSnapshotIngest::new(7, wrong, bytes.to_vec());

            match ingest_snapshot(&PanicOnParse, &ingest) {
                Err(PrepareError::HashMismatch { version }) => {
                    assert_eq!(version, PolicyVersion(7))
                }
                other => panic!("expected HashMismatch, got {other:?}"),
            }
        }

        #[test]
        fn the_ingest_carries_the_seq_and_transported_hash_identity() {
            // The ingest is the (seq, content_hash, document) identity tuple; version()
            // surfaces the seq as a PolicyVersion the gate keys on.
            let bytes = b"doc-bytes";
            let h = sha256(bytes);
            let ingest = NftSnapshotIngest::new(9, h, bytes.to_vec());
            assert_eq!(ingest.version(), PolicyVersion(9));
            assert_eq!(ingest.content_hash, h);
            assert_eq!(ingest.document, bytes.to_vec());
        }
    }
}
