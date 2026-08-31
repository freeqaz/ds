//! ds-policy-snapshot — host policy snapshot load + hot-reload (doc 14 §6 crate map,
//! "snapshot loader" row).
//!
//! When fully built, this crate holds (doc 14 §6; doc 13 §5, D72):
//! - loading + validation of the host-local composed-policy snapshot
//!   `(seq, content_hash, document)`; NACK on any hash/schema failure;
//! - hot-reload staging for the two-phase, admitter-LAST apply barrier
//!   (prepare a new evaluator side-by-side, atomic pointer-swap commit);
//! - applied-seq reporting, surfaced via the host-agent heartbeat — reported
//!   only AFTER the revocation sweep completes (D72).
//!
//! One host subscriber (the D35 host agent) feeds this crate; consumers never
//! open control-plane policy streams.
//!
//! # First field on the snapshot: the D71 authored-SOA `boundary_zone`
//!
//! The whole loader/hot-reload machinery above is still skeleton; what lands here
//! NOW is the carrier shape for the first policy-pushed field a boundary service
//! reads off the snapshot — the D71 authored-SOA MNAME suffix `ds-dnsgate` signs
//! every deny / NODATA with (`SOA MNAME = denied.policy.<boundary_zone>.`; doc 11
//! §3.2). The VALUE moves from a ds-dnsgate handler-local const
//! (`DEFAULT_BOUNDARY_ZONE = "boundary."`) to this policy-pushed field, sourced from
//! the POL-1 [`ds_contracts::pol1::DnsConfig::boundary_zone`] of the composed
//! document. The D71 SHAPE is unchanged: the `denied.policy.` prefix, the
//! always-authored SOA on every deny / NODATA, and TTL==MINIMUM==the POL-1
//! negative-TTL all stay frozen — only WHERE the suffix value comes from moves.

use ds_contracts::flush::{DstFilter, FlushSession, LegSelector};
use ds_contracts::pol1;
use ds_contracts::pol1::Rung;
use ds_contracts::session::SessionRef;
use ds_contracts::snapshot_verify::{self, ContentHash, Verdict};

/// The outcome of the produce-once / verify-only LOADER over transported snapshot bytes (doc 13
/// §5 identity row / §5.1, D72/D120) — the single-call hash-check-BEFORE-parse step the
/// `WatchPolicies` subscriber drives. It folds the two failure modes the loader must keep
/// OPERATIONALLY DISTINCT into one matchable verdict:
///
///   * [`LoadVerdict::Loaded`] — the transported bytes hashed to the wire `content_hash`
///     ([`verify_transported_bytes`] returned [`Verdict::Verified`]) AND parsed with zero
///     `PolicyError`s; the carried [`PolicySnapshot`] is the committed snapshot, self-identifying on
///     the FULL D72 identity (`seq`, the local fingerprint, AND the verified D120 wire hash via
///     [`PolicySnapshot::from_verified_bytes_and_layer`]).
///   * [`LoadVerdict::HashNack`] — a D120 content_hash MISMATCH (doc 13 §5.1 produce-once /
///     verify-only): the recomputed hash did NOT match the wire hash, so the loader NACKed
///     host-wide and NEVER parsed the bytes (the host stays on vN). Carries the ds-contracts
///     [`Verdict::Nack`] `{expected, computed}` verbatim so the subscriber can route a
///     `content_hash_mismatch` telemetry signal DISTINCT from a benign forward-only-seq stale
///     fan-out.
///   * [`LoadVerdict::ParseError`] — the bytes verified against the wire hash but FAILED the POL-1
///     schema parse (a "schema failure" in the §5 identity row, which NACKs the apply just like a
///     hash failure). Rendered to a stable message so the subscriber surfaces it as the same
///     integrity-rejection class as a hash NACK (the host stays on vN), never a silent drop.
///
/// The loader is VERIFY-ONLY: hashing delegates to the frozen [`ds_contracts::snapshot_verify`]
/// (the SINGLE source of wire hashing) and the bytes are parsed EXACTLY ONCE with no
/// re-serialization or re-canonicalization (doc 13 §5.1). A `HashNack` short-circuits BEFORE the
/// parse, so a tampered transport is never fed to the reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadVerdict {
    /// The transported bytes verified against the wire `content_hash` AND parsed — the committed
    /// snapshot carrying the FULL D72 identity (`seq` + local fingerprint + verified wire hash).
    /// `Box`ed so the loaded snapshot does not bloat the small NACK / parse-error variants (the
    /// loader returns this by value on every push; the failure variants are the rare path).
    Loaded(Box<PolicySnapshot>),
    /// A D120 content_hash MISMATCH: the loader NACKed host-wide and never parsed (doc 13 §5.1).
    /// Carries the ds-contracts verdict's `{expected, computed}` for the distinct NACK telemetry.
    HashNack {
        /// The wire `content_hash` the snapshot identity tuple claimed.
        expected: ContentHash,
        /// The hash actually computed over the transported bytes (≠ `expected`).
        computed: ContentHash,
    },
    /// The bytes verified but failed the POL-1 schema parse (a §5 "schema failure" — NACKs the
    /// apply host-wide). The rendered `PolicyErrors` message, for the integrity-rejection log.
    ParseError(String),
}

impl LoadVerdict {
    /// The committed snapshot iff the loader [`LoadVerdict::Loaded`] it (verified AND parsed), else
    /// `None` (a `HashNack` / `ParseError` — the host stays on vN). The accessor the subscriber
    /// uses to commit ONLY a fully-loaded snapshot.
    pub fn loaded(&self) -> Option<&PolicySnapshot> {
        match self {
            LoadVerdict::Loaded(snap) => Some(snap.as_ref()),
            LoadVerdict::HashNack { .. } | LoadVerdict::ParseError(_) => None,
        }
    }

    /// True iff this is a content_hash MISMATCH NACK (D120) — the integrity rejection the loader
    /// keeps DISTINCT from a benign forward-only-seq stale fan-out, so an operator routes it to the
    /// integrity-alert path, never the dedup path.
    pub fn is_hash_nack(&self) -> bool {
        matches!(self, LoadVerdict::HashNack { .. })
    }
}

/// The produce-once / verify-only LOADER the single-per-host `WatchPolicies` subscriber drives
/// over transported snapshot bytes (doc 13 §5 identity row / §5.1, D72/D120) — the one call that
/// hash-checks BEFORE parsing. The host agent (Go) formed the canonical bytes EXACTLY ONCE and
/// hashed them into `wire_content_hash`; this consumer is VERIFY-ONLY:
///
///   1. hash the TRANSPORTED bytes via [`verify_transported_bytes`] (delegating to the frozen
///      [`ds_contracts::snapshot_verify`], the single source of wire hashing) and compare to
///      `wire_content_hash`. On a mismatch, return [`LoadVerdict::HashNack`] and NEVER parse —
///      the host stays on vN (doc 13 §5.1 produce-once / verify-only; the §5 NACK-host-wide rule).
///   2. on a verified hash, parse the bytes ONCE into a POL-1 layer (no re-serialization). A
///      schema failure returns [`LoadVerdict::ParseError`] (the §5 "any hash/schema failure NACKs"
///      clause), still never re-canonicalizing.
///   3. build the committed snapshot via [`PolicySnapshot::from_verified_bytes_and_layer`], so the
///      snapshot carries the FULL D72 identity — `seq`, the build-local fingerprint, AND the
///      VERIFIED D120 wire hash — and self-identifies on the §5 identity tuple, not only the local
///      fingerprint.
///
/// This is the SINGLE entry point that closes the produce-once / verify-only loop end to end: the
/// caller hands the transported bytes + the wire `(seq, content_hash)` identity and gets back a
/// matchable verdict, with the hash check provably BEFORE the parse and no second canonicalizer.
#[must_use]
pub fn load_verified_snapshot(
    transported: &[u8],
    seq: u64,
    wire_content_hash: &ContentHash,
) -> LoadVerdict {
    // Step 1 — hash-check BEFORE parse (verify-only, doc 13 §5.1): a NACK short-circuits so the
    // tampered transport is NEVER fed to the POL-1 reader; the host stays on vN.
    match verify_transported_bytes(transported, wire_content_hash) {
        Verdict::Verified => {}
        Verdict::Nack { expected, computed } => {
            return LoadVerdict::HashNack { expected, computed };
        }
    }
    // Step 2 — parse the VERIFIED bytes EXACTLY ONCE (no re-serialization). A schema failure is a
    // §5 "schema failure" → NACK the apply host-wide (the host stays on vN), surfaced distinctly
    // from a hash mismatch but in the same integrity-rejection class.
    let text = match std::str::from_utf8(transported) {
        Ok(text) => text,
        Err(e) => {
            return LoadVerdict::ParseError(format!("transported snapshot is not UTF-8: {e}"))
        }
    };
    let layer = match pol1::parse_layer(text) {
        Ok(layer) => layer,
        Err(errs) => return LoadVerdict::ParseError(errs.to_string()),
    };
    // Step 3 — build the committed snapshot carrying the VERIFIED wire hash on its identity, so the
    // snapshot self-identifies on the full D72 `(seq, content_hash, document)` tuple.
    LoadVerdict::Loaded(Box::new(PolicySnapshot::from_verified_bytes_and_layer(
        &layer,
        seq,
        *wire_content_hash,
    )))
}

/// The D120 WIRE `content_hash` length — re-exported from the frozen
/// [`snapshot_verify`] home so the snapshot never restates `32` (one home for the
/// length; doc 13 §5.1 "SHA-256, full 32 bytes, no truncation").
pub const WIRE_CONTENT_HASH_LEN: usize = snapshot_verify::CONTENT_HASH_LEN;

/// The D120 WIRE `content_hash` type — the 32-byte SHA-256 the host snapshot
/// identity tuple carries on the wire (doc 13 §5.1). Re-exported verbatim from the
/// frozen [`ds_contracts::snapshot_verify`] home (this crate CONSUMES that contract,
/// never re-implements it), so a caller of [`CommittedPolicy::wire_content_hash`] /
/// [`verify_transported_bytes`] names the SAME type the loader's NACK path checks.
pub type WireContentHash = ContentHash;

/// The verdict of verifying transported snapshot bytes against the wire
/// `content_hash` — re-exported from [`ds_contracts::snapshot_verify`] so the
/// loader NACK-on-hash path names the SINGLE source-of-truth verdict (doc 13 §5
/// identity row, D72/D120). [`verify_transported_bytes`] returns this.
pub type WireVerdict = Verdict;

// ── LOCAL self-identity fingerprint vs the D120 WIRE content_hash ──────────────────
//
// This crate carries TWO distinct content fingerprints, and they are NOT the same
// thing — keeping them separate is the whole point of the D120 reconcile:
//
//   * the LOCAL fingerprint ([`content_hash_of_layer`], the FNV-1a-over-`Debug`
//     `SnapshotIdentity::content_hash`) is an in-process, build-local self-identity:
//     deterministic WITHIN a build, stdlib-friendly (doc 14 §6 keeps this reader
//     crypto-dependency-free), good for detecting a duplicate / stale fan-out by
//     identity. It is NOT cross-build stable and is NOT the wire contract.
//
//   * the D120 WIRE `content_hash` ([`WireContentHash`], a SHA-256 full 32 bytes over
//     a PRODUCE-ONCE RFC 8785 (JCS) payload, doc 13 §5.1) is the cross-language,
//     cross-build integrity digest. Per the produce-once / verify-only rule the Go
//     host agent forms the canonical bytes EXACTLY ONCE and hashes them; this Rust
//     consumer is VERIFY-ONLY — it hashes the TRANSPORTED bytes via the frozen
//     [`ds_contracts::snapshot_verify::verify_snapshot_bytes`], compares to the wire
//     `content_hash`, NACKs host-wide on mismatch, then parses. It NEVER re-serializes
//     or re-canonicalizes, so there is ONE source of hashing (ds-contracts) and no
//     second incompatible fingerprint competing with the wire contract.
//
// The reconcile is ADDITIVE: the wire hash rides the [`SnapshotIdentity`] alongside
// the local fingerprint, and the verify-only path delegates to ds-contracts — the
// wave30/wave31 [`PolicySnapshot::from_policy_layer`] / [`CommittedPolicy`] accessor
// signatures the sibling ds-dnsgate hot-reload unit consumes are unchanged.

/// The D72 snapshot-identity tuple component this crate computes locally: a stable,
/// content-derived LOCAL fingerprint over the composed-document MATERIAL (doc 13 §5 /
/// D72's `(seq, content_hash, document)` identity). The full tuple is `(seq,
/// content_hash, document)`; the `document` is the [`CommittedPolicy::composed_layer`]
/// the snapshot already carries, so the identity adds only `seq` + the fingerprint.
///
/// The fingerprint is a deterministic 64-bit FNV-1a digest of the layer's stable
/// `Debug` rendering — stdlib-only (this crate has NO crypto dependency; doc 14 §6
/// keeps the reader stdlib-bounded), order-stable across runs (FNV-1a is not the
/// randomized `std::collections::hash_map::DefaultHasher`, whose seed varies per
/// process), and a pure function of the layer's content. It is a build-LOCAL
/// self-identity, NOT the cross-build WIRE integrity digest: the D120 wire
/// `content_hash` (SHA-256 over a produce-once JCS payload, doc 13 §5.1) rides the
/// identity SEPARATELY as [`SnapshotIdentity::wire_content_hash`] and is checked by
/// the verify-only [`verify_transported_bytes`] path that delegates to
/// [`ds_contracts::snapshot_verify`]. This local fingerprint stays the in-process
/// self-identifier so the loader can detect duplicate / stale fan-outs by identity
/// (D72 forward-only-seq) without pulling a crypto dependency into the reader.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Compute the LOCAL self-identity fingerprint of a composed POL-1 layer (doc 13 §5).
/// Deterministic FNV-1a over the layer's derived `Debug` rendering: the `Debug` impl is
/// field-by-field deterministic (no maps with randomized iteration; POL-1 collections
/// are `Vec`s in document order), so two layers with the same content hash to the same
/// value, and distinct content hashes differ. Stdlib only — no `sha2`/`blake3`
/// dependency is pulled into the reader crate.
///
/// This is the build-LOCAL fingerprint, NOT the D120 wire `content_hash`: the wire hash
/// is SHA-256 over the producer's canonical bytes ([`verify_transported_bytes`] /
/// [`ds_contracts::snapshot_verify`]). The two never share a hashing primitive — there
/// is exactly one source of WIRE hashing (ds-contracts), and this local digest never
/// competes with it.
fn content_hash_of_layer(layer: &pol1::PolicyLayer) -> u64 {
    // `{:?}` on the derived Debug is a pure function of the layer's fields and stable
    // within a build; FNV-1a folds it to a 64-bit fingerprint without a randomized seed.
    let rendered = format!("{layer:?}");
    let mut hash = FNV_OFFSET_BASIS;
    for byte in rendered.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Verify TRANSPORTED snapshot bytes against the D120 wire `content_hash` from the
/// identity tuple — the loader's hash-check-BEFORE-parse step (doc 13 §5.1 produce-once
/// / verify-only; doc 14 §6, D120). This crate is VERIFY-ONLY: it delegates verbatim to
/// the frozen [`ds_contracts::snapshot_verify::verify_snapshot_bytes`], which hashes the
/// transported bytes with the single source-of-truth SHA-256 and compares to `expected`.
/// It NEVER re-serializes or re-canonicalizes the document — only Go ever forms the
/// canonical bytes, so the cross-language reproduction surface is zero.
///
/// On [`Verdict::Verified`] the bytes are safe to parse and the verified
/// `expected` hash can be threaded onto the snapshot identity via
/// [`PolicySnapshot::from_verified_bytes_and_layer`]. On [`Verdict::Nack`] the host
/// MUST reject the snapshot host-wide and stay on the prior version (doc 13 §5 identity
/// row, D72) — never parse the bytes.
#[must_use]
pub fn verify_transported_bytes(transported: &[u8], expected: &ContentHash) -> Verdict {
    snapshot_verify::verify_snapshot_bytes(transported, expected)
}

/// Assemble the [`CommittedPolicy`] a layer-sourced snapshot carries — the shared body of
/// [`PolicySnapshot::from_policy_layer_with_seq`] (no wire hash: layer-only path) and
/// [`PolicySnapshot::from_verified_bytes_and_layer`] (carries the verified wire hash).
/// One place lifts the composed-doc material + clamp + zone + identity off the SAME layer,
/// so the two constructors can never drift on anything but the wire-hash component.
fn committed_from_layer(
    layer: &pol1::PolicyLayer,
    seq: u64,
    wire_content_hash: Option<ContentHash>,
) -> PolicySnapshot {
    // Lift the D71 boundary zone the same way `from_dns_config` does (the reader already
    // defaulted an omitted field to the working name), so the boundary-zone accessors
    // return the identical value whether the snapshot was built from a DNS block or a
    // full layer.
    let snap = PolicySnapshot::from_dns_config(&layer.dns);
    let committed = CommittedPolicy {
        composed_layer: layer.clone(),
        ttl_clamp: W2TtlClamp::from_admission_timers(&layer.admission),
        boundary_zone: snap.boundary_zone.clone(),
        // The D72 identity travels WITH the composed document: the local fingerprint is
        // the stable digest of THIS layer, seq is the supplied forward-only number, and
        // the D120 wire hash (when the bytes were verified) rides alongside.
        identity: SnapshotIdentity {
            seq,
            content_hash: content_hash_of_layer(layer),
            wire_content_hash,
        },
    };
    PolicySnapshot {
        committed: Some(committed),
        ..snap
    }
}

/// The D72 snapshot-identity pair a committed snapshot carries ALONGSIDE its composed
/// document (doc 13 §5: the full identity is `(seq, content_hash, document)`; the
/// `document` is the [`CommittedPolicy::composed_layer`], so this carrier holds the two
/// scalar identity components). It makes a committed snapshot self-identifying: the
/// loader can detect a duplicate fan-out (same `(seq, content_hash)`) or a stale one
/// (an older `seq`) by identity, supporting the D72 forward-only-seq + admitter-LAST
/// apply barrier — one snapshot → one seq → one composed doc + clamp + zone.
///
/// `seq` is the host-applied sequence number (forward-only, D72): the boundary-zone /
/// DNS-block-only carriers and the seq-less [`PolicySnapshot::from_policy_layer`] path
/// default it to `0` (no control-plane seq was supplied); the opt-in
/// [`PolicySnapshot::from_policy_layer_with_seq`] threads the real applied seq through.
/// `content_hash` is the [`content_hash_of_layer`] fingerprint of the SAME composed
/// document, so identity and document can never disagree about which policy is carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SnapshotIdentity {
    /// The host-applied, forward-only sequence number (doc 13 §5 / D72). `0` when no
    /// control-plane seq was supplied (the seq-less constructor and the boundary-zone
    /// carriers).
    seq: u64,
    /// The build-LOCAL self-identity fingerprint of the composed document
    /// ([`content_hash_of_layer`]). Distinct from the D120 wire hash in `wire_content_hash`.
    content_hash: u64,
    /// The D120 WIRE `content_hash` (SHA-256 full 32 bytes over the producer's
    /// produce-once RFC 8785 (JCS) payload; doc 13 §5.1) when the snapshot was built from
    /// VERIFIED transported bytes ([`PolicySnapshot::from_verified_bytes_and_layer`]).
    /// `None` on the layer-only paths that never saw transported wire bytes
    /// ([`PolicySnapshot::from_policy_layer`] / `..._with_seq`), keeping those carriers'
    /// existing behavior byte-identical (ADDITIVE). This is the SAME 32-byte hash the
    /// loader's NACK-on-hash check ([`ds_contracts::snapshot_verify::verify_snapshot_bytes`])
    /// validated, carried on the identity so a committed snapshot self-identifies on the
    /// wire contract, not only the local fingerprint.
    wire_content_hash: Option<ContentHash>,
}

impl SnapshotIdentity {
    /// The host-applied, forward-only sequence number (doc 13 §5 / D72). `0` means no
    /// control-plane seq was supplied for this snapshot.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The build-LOCAL self-identity fingerprint of the composed document — equal across
    /// two snapshots built from the same document, distinct across different documents.
    /// This is NOT the D120 wire hash; for the cross-build wire contract see
    /// [`wire_content_hash`](SnapshotIdentity::wire_content_hash).
    pub fn content_hash(&self) -> u64 {
        self.content_hash
    }

    /// The D120 WIRE `content_hash` (SHA-256 full 32 bytes over the producer's canonical
    /// JCS payload; doc 13 §5.1) when this snapshot was built from VERIFIED transported
    /// bytes, else `None`. ADDITIVE accessor — it carries the SAME hash the verify-only
    /// loader ([`verify_transported_bytes`]) checked against the transported bytes, so the
    /// snapshot's wire identity matches what the loader's NACK-on-hash validation enforces.
    pub fn wire_content_hash(&self) -> Option<ContentHash> {
        self.wire_content_hash
    }
}

/// The default authored-SOA boundary-zone working name (`boundary.`; doc 11 §3.2,
/// D71). Re-exported from the POL-1 schema home ([`pol1::DEFAULT_BOUNDARY_ZONE`]) so
/// the snapshot's fallback is the SAME value the POL-1 reader materializes for a
/// layer that omits `dns.boundary_zone` — one source of truth, never two drifting
/// `"boundary."` literals.
pub const DEFAULT_BOUNDARY_ZONE: &str = pol1::DEFAULT_BOUNDARY_ZONE;

/// The W2 admission TTL clamp window in seconds (doc 11 §4 / W2, D68): the answer TTL
/// the VM sees is `clamp(chain_min_ttl, floor, ceil)`. This is the policy VALUE the
/// snapshot lifts off the committed POL-1 [`pol1::AdmissionTimers`]
/// (`ttl_floor`/`ttl_ceil`, defaulted to 60s/900s by the reader when a layer omits
/// them) — NOT a wire type, and NOT the gate's clamp behavior (`ds-dnsgate`'s
/// `TtlClamp` owns the `clamp()`/`to_admit()` projection). The snapshot carries only
/// the WINDOW so the boundary service re-sources the clamp from the SAME snapshot
/// that yielded its composed document — one snapshot → one clamp, never a default
/// echo decoupled from the live policy version (D72).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct W2TtlClamp {
    /// The clamp floor in seconds (POL-1 `ttl_floor`, default 60).
    pub floor: u32,
    /// The clamp ceiling in seconds (POL-1 `ttl_ceil`, default 900).
    pub ceil: u32,
}

impl W2TtlClamp {
    /// Lift the W2 clamp window off a committed POL-1 [`pol1::AdmissionTimers`] block
    /// — the floor/ceil the reader already defaulted to 60s/900s when a layer omits
    /// them (doc 11 §4 / D68). This is the SAME projection `ds-dnsgate`'s
    /// `live_ttl_clamp` performs (`TtlClamp { floor: admission.ttl_floor, ceil:
    /// admission.ttl_ceil }`); sourcing it HERE lets the gate lift the clamp through
    /// the snapshot instead of re-mirroring the lift.
    pub fn from_admission_timers(admission: &pol1::AdmissionTimers) -> W2TtlClamp {
        W2TtlClamp {
            floor: admission.ttl_floor,
            ceil: admission.ttl_ceil,
        }
    }
}

/// The host's ONE committed policy — the composed-document MATERIAL plus the W2 TTL
/// clamp window, both lifted off the SAME committed POL-1 snapshot layer (doc 13 §5,
/// D72: one snapshot → one composed doc + one clamp + one boundary zone). This is the
/// carrier `ds-dnsgate` lifts a `CommittedPolicy` from THROUGH the snapshot rather
/// than re-deriving parse → compose → lift in its handler (the wave29 re-mirror).
///
/// The composed-document material the snapshot carries is the parsed POL-1
/// [`pol1::PolicyLayer`] ([`composed_layer`](CommittedPolicy::composed_layer)) — the
/// deny-wins composition itself (`policy-core::compose`) is the EVALUATOR's job (doc
/// 13 §1 rule 1: `policy-core` is THE one evaluator, never re-run by a carrier), so
/// the snapshot stops at the schema/contract edge ds-contracts owns and hands the
/// boundary service the exact layer it composes from. The clamp window
/// ([`ttl_clamp`](CommittedPolicy::ttl_clamp)) and boundary zone
/// ([`boundary_zone`](CommittedPolicy::boundary_zone)) are lifted off that SAME layer,
/// so the evaluator re-source, the authored-SOA suffix, and the clamp can never
/// disagree about which policy version is live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedPolicy {
    /// The committed POL-1 layer the boundary service composes the evaluator from —
    /// the composed-document MATERIAL (`policy-core::compose(&[layer], &[])` is
    /// downstream of this, owned by the evaluator, never re-run here).
    composed_layer: pol1::PolicyLayer,
    /// The W2 TTL clamp window lifted off the same layer's `admission` block (doc 11
    /// §4 / D68).
    ttl_clamp: W2TtlClamp,
    /// The D71 authored-SOA boundary zone lifted off the same layer's `dns` block
    /// (defaulted to the working name by the reader when the layer omits it).
    boundary_zone: String,
    /// The D72 `(seq, content_hash)` snapshot-identity pair (doc 13 §5) carried
    /// ALONGSIDE the composed document above. ADDITIVE: the wave30 accessors
    /// (`composed_layer`/`ttl_clamp`/`boundary_zone`) are unchanged; the identity is a
    /// new field surfaced by [`identity`](CommittedPolicy::identity) /
    /// [`seq`](CommittedPolicy::seq) / [`content_hash`](CommittedPolicy::content_hash).
    /// `content_hash` is the [`content_hash_of_layer`] fingerprint of `composed_layer`,
    /// so the identity and the document it identifies always move together (D72).
    identity: SnapshotIdentity,
}

impl CommittedPolicy {
    /// The committed POL-1 layer the boundary service composes the live evaluator
    /// from. `ds-dnsgate` feeds this to `policy-core::compose(&[layer], &[])` to build
    /// the `PolicyCorePolicy` — the snapshot carries the composition INPUT (the doc
    /// 13 §1.2 layer), never the composed output, because the composition is the
    /// evaluator's job, not the carrier's.
    pub fn composed_layer(&self) -> &pol1::PolicyLayer {
        &self.composed_layer
    }

    /// The W2 TTL clamp window (doc 11 §4 / D68) lifted off the same committed layer's
    /// `admission` block — the clamp the gate projects onto each `Allow`. It travels
    /// WITH the composed-document material so the evaluator never reads a document from
    /// one snapshot with a clamp from another (D72: one policy version).
    pub fn ttl_clamp(&self) -> W2TtlClamp {
        self.ttl_clamp
    }

    /// The D71 authored-SOA boundary zone (`SOA MNAME = denied.policy.<boundary_zone>.`)
    /// lifted off the same committed layer's `dns` block — the SAME value
    /// [`PolicySnapshot::boundary_zone`] carries, surfaced here so a boundary service
    /// can lift the whole committed policy (doc + clamp + zone) off ONE accessor.
    pub fn boundary_zone(&self) -> &str {
        &self.boundary_zone
    }

    /// The D72 `(seq, content_hash)` snapshot-identity pair carried alongside the
    /// composed document (doc 13 §5). ADDITIVE accessor — the wave30 surface
    /// ([`composed_layer`](CommittedPolicy::composed_layer) /
    /// [`ttl_clamp`](CommittedPolicy::ttl_clamp) /
    /// [`boundary_zone`](CommittedPolicy::boundary_zone)) is unchanged. The loader uses
    /// this to detect duplicate / stale fan-outs by identity (same `(seq, content_hash)`
    /// ⇒ duplicate; older `seq` ⇒ stale) supporting D72 forward-only-seq.
    pub fn identity(&self) -> SnapshotIdentity {
        self.identity
    }

    /// The host-applied, forward-only sequence number of this committed snapshot (doc 13
    /// §5 / D72). `0` when no control-plane seq was supplied (the seq-less
    /// [`PolicySnapshot::from_policy_layer`] path); the opt-in
    /// [`PolicySnapshot::from_policy_layer_with_seq`] threads the real applied seq.
    pub fn seq(&self) -> u64 {
        self.identity.seq
    }

    /// The build-LOCAL self-identity fingerprint of the composed document
    /// ([`content_hash_of_layer`]) — equal across two committed policies built from the
    /// SAME document, distinct across different documents (doc 13 §5 / D72). NOT the D120
    /// wire hash; for the cross-build wire contract see
    /// [`wire_content_hash`](CommittedPolicy::wire_content_hash).
    pub fn content_hash(&self) -> u64 {
        self.identity.content_hash
    }

    /// The D120 WIRE `content_hash` (SHA-256 full 32 bytes over the producer's canonical
    /// JCS payload; doc 13 §5.1) when this committed policy was built from VERIFIED
    /// transported bytes ([`PolicySnapshot::from_verified_bytes_and_layer`]), else `None`
    /// (the layer-only [`PolicySnapshot::from_policy_layer`] path never saw wire bytes).
    /// ADDITIVE accessor — it surfaces the SAME hash the verify-only loader
    /// ([`verify_transported_bytes`]) validated, so a committed snapshot self-identifies
    /// against the wire contract, not only the local fingerprint.
    pub fn wire_content_hash(&self) -> Option<ContentHash> {
        self.identity.wire_content_hash
    }
}

/// The host policy snapshot the boundary services read policy-pushed fields off of.
///
/// Today it carries the D71 [`boundary_zone`](PolicySnapshot::boundary_zone) — the
/// first field a boundary service (`ds-dnsgate`) reads from the snapshot rather than
/// from a handler-local const — AND, when built from a parsed POL-1 layer, the
/// committed-policy material the service lifts the live evaluator + W2 clamp off of
/// ([`committed_policy`](PolicySnapshot::committed_policy)). The `(seq, content_hash,
/// full composed document)` identity tuple (doc 13 §5, D72) and the loader/hot-reload
/// machinery land with that work; this type grows additively as they do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicySnapshot {
    /// The D71 authored-SOA MNAME suffix (`SOA MNAME = denied.policy.<boundary_zone>.`;
    /// doc 11 §3.2). Policy-pushed: it is the POL-1 `dns.boundary_zone` of the composed
    /// document, defaulting to [`DEFAULT_BOUNDARY_ZONE`] (`boundary.`) when the policy
    /// omits it. `ds-dnsgate` reads this instead of its handler-local const; the const
    /// is the fallback only.
    boundary_zone: String,
    /// The committed POL-1 policy the boundary service lifts the live evaluator + W2
    /// clamp off of, present ONLY when the snapshot is built from a parsed POL-1 layer
    /// ([`PolicySnapshot::from_policy_layer`]). The boundary-zone-only constructors
    /// ([`from_boundary_zone`](PolicySnapshot::from_boundary_zone) /
    /// [`from_dns_config`](PolicySnapshot::from_dns_config)) and [`Default`] carry no
    /// committed layer (they never saw a full document), so this is `None` for them —
    /// keeping the existing carriers byte-identical while the layer-sourced path
    /// surfaces the whole committed policy.
    committed: Option<CommittedPolicy>,
}

impl PolicySnapshot {
    /// Build a snapshot directly from a boundary-zone value (the carrier the boundary
    /// service reads). An empty value falls back to [`DEFAULT_BOUNDARY_ZONE`] so the
    /// authored SOA suffix is never blank — mirroring the POL-1 reader's empty-string
    /// skip.
    pub fn from_boundary_zone(boundary_zone: impl Into<String>) -> PolicySnapshot {
        let boundary_zone = boundary_zone.into();
        let boundary_zone = if boundary_zone.is_empty() {
            DEFAULT_BOUNDARY_ZONE.to_string()
        } else {
            boundary_zone
        };
        PolicySnapshot {
            boundary_zone,
            committed: None,
        }
    }

    /// Build a snapshot from a composed POL-1 DNS block — the production path: the
    /// snapshot lifts [`pol1::DnsConfig::boundary_zone`] (already defaulted to the
    /// working name by the POL-1 reader when the layer omits it) onto the snapshot.
    pub fn from_dns_config(dns: &pol1::DnsConfig) -> PolicySnapshot {
        PolicySnapshot::from_boundary_zone(dns.boundary_zone.clone())
    }

    /// Build a snapshot from a parsed POL-1 [`pol1::PolicyLayer`] — the layer-sourced
    /// production path that carries the WHOLE committed policy, not just the boundary
    /// zone. One parsed snapshot layer yields one committed policy: the composed-document
    /// material (the layer itself), the W2 TTL clamp lifted off its `admission` block,
    /// and the D71 boundary zone lifted off its `dns` block — the D72 "one snapshot →
    /// one composed doc + one clamp + one boundary zone" identity.
    ///
    /// This is the accessor `ds-dnsgate` lifts a `CommittedPolicy` THROUGH (its
    /// `snapshot_host_policy` re-mirror of parse → compose → lift collapses to: parse
    /// once, hand the layer here, read [`committed_policy`](PolicySnapshot::committed_policy)).
    /// The boundary zone is still surfaced by the existing
    /// [`boundary_zone`](PolicySnapshot::boundary_zone) /
    /// [`boundary_zone_value`](PolicySnapshot::boundary_zone_value) accessors with the
    /// SAME value, so this is purely additive — no existing carrier changes.
    pub fn from_policy_layer(layer: &pol1::PolicyLayer) -> PolicySnapshot {
        // ADDITIVE-ONLY: the wave30 arity (`&pol1::PolicyLayer` → `PolicySnapshot`) is
        // unchanged so the sibling ds-dnsgate adoption keeps compiling. No control-plane
        // seq is supplied on this path, so the D72 identity defaults seq=0 and computes
        // content_hash from the layer; the opt-in `from_policy_layer_with_seq` threads a
        // real applied seq.
        PolicySnapshot::from_policy_layer_with_seq(layer, 0)
    }

    /// Build a layer-sourced snapshot WITH an explicit host-applied sequence number — the
    /// opt-in path that supplies the D72 forward-only `seq` for the `(seq, content_hash)`
    /// snapshot identity (doc 13 §5). The `content_hash` is computed from the layer the
    /// same way the seq-less [`from_policy_layer`](PolicySnapshot::from_policy_layer) does,
    /// so the only difference is the supplied `seq`. ADDITIVE: a NEW constructor — the
    /// existing `from_policy_layer(&layer)` arity the sibling adoption depends on is
    /// untouched, and `from_policy_layer` simply delegates here with `seq = 0`.
    ///
    /// The loader (doc 13 §5.3 admitter-LAST hot-reload) threads the applied seq here so a
    /// committed snapshot is self-identifying: a re-applied document carries the same
    /// `content_hash`, and a forward-only `seq` distinguishes a fresh apply from a stale /
    /// duplicate fan-out — one snapshot → one seq → one composed doc + clamp + zone (D72).
    pub fn from_policy_layer_with_seq(layer: &pol1::PolicyLayer, seq: u64) -> PolicySnapshot {
        // The layer-only path never saw transported wire bytes, so the wire content_hash
        // is absent here (ADDITIVE: the local fingerprint + boundary zone are unchanged).
        // The verify-only `from_verified_bytes_and_layer` path threads the verified wire
        // hash through `committed_from_layer`'s shared body.
        committed_from_layer(layer, seq, None)
    }

    /// Build a layer-sourced snapshot from bytes that have ALREADY been verified against
    /// their D120 wire `content_hash` — the loader's hash-check-BEFORE-parse path (doc 13
    /// §5.1 / doc 14 §6, D120). The caller drives [`verify_transported_bytes`] over the
    /// TRANSPORTED bytes first (NACK host-wide on mismatch, never parse on a NACK), parses
    /// the verified bytes into `layer` outside this crate's POL-1 reader, and hands BOTH
    /// the parsed layer and the verified wire hash here. The snapshot then carries the wire
    /// `content_hash` on its identity ([`SnapshotIdentity::wire_content_hash`]) alongside
    /// the build-local fingerprint, so identity-on-the-wire and the composed document can
    /// never disagree about which policy is carried.
    ///
    /// This is the reconcile of the wave31 local fingerprint with the D120 wire hash: ONE
    /// source of wire hashing (the frozen [`ds_contracts::snapshot_verify`]), consumed
    /// verify-only — this crate never re-serializes or re-canonicalizes the document.
    /// ADDITIVE: a NEW constructor; the wave30/wave31 `from_policy_layer`/
    /// `from_policy_layer_with_seq` arities the sibling ds-dnsgate adoption depends on are
    /// untouched.
    pub fn from_verified_bytes_and_layer(
        layer: &pol1::PolicyLayer,
        seq: u64,
        wire_content_hash: ContentHash,
    ) -> PolicySnapshot {
        committed_from_layer(layer, seq, Some(wire_content_hash))
    }

    /// The D71 authored-SOA boundary-zone suffix the boundary services should sign
    /// with. `ds-dnsgate` threads this into its `with_forwarder_and_boundary_zone`
    /// seam in place of the handler-local const default.
    pub fn boundary_zone(&self) -> &str {
        &self.boundary_zone
    }

    /// The LIVE-WIRE read `ds-dnsgate` sources its authored-SOA boundary zone from at
    /// main startup AND on the doc 13 §5.3 admitter-LAST D72 hot-reload — an owned
    /// `String` clone of [`boundary_zone`](PolicySnapshot::boundary_zone), so the gate's
    /// `GateConfig.boundary_zone` carries the snapshot's value by value (no borrow held
    /// across the listener's lifetime, and a hot-reload re-sources it from the NEW
    /// snapshot, never the constructor default).
    ///
    /// This is the single read the live wire is built on: the value moves from the
    /// ds-dnsgate handler-local `DEFAULT_BOUNDARY_ZONE` const to THIS snapshot field, and
    /// a D72 admitter-LAST commit swaps the snapshot, so the next `boundary_zone_value()`
    /// returns the freshly-applied policy suffix.
    pub fn boundary_zone_value(&self) -> String {
        self.boundary_zone.clone()
    }

    /// The committed POL-1 policy the boundary service lifts the live evaluator + W2
    /// clamp + boundary zone off of — present ONLY when the snapshot was built from a
    /// parsed POL-1 layer ([`from_policy_layer`](PolicySnapshot::from_policy_layer)).
    ///
    /// `ds-dnsgate` reads this in place of re-mirroring parse → compose → lift in its
    /// handler: it lifts the [`CommittedPolicy::composed_layer`] (the composed-document
    /// material it feeds to `policy-core::compose`), the [`CommittedPolicy::ttl_clamp`]
    /// (the W2 window it projects onto each `Allow`), and the
    /// [`CommittedPolicy::boundary_zone`] (the authored-SOA suffix) — all from the SAME
    /// snapshot, so the evaluator, the clamp, and the suffix can never drift apart (D72).
    /// The committed policy also carries the D72 `(seq, content_hash)`
    /// [`CommittedPolicy::identity`] of that same document, so the loader can detect a
    /// duplicate / stale fan-out by identity (doc 13 §5).
    ///
    /// `None` for the boundary-zone-only carriers
    /// ([`from_boundary_zone`](PolicySnapshot::from_boundary_zone) /
    /// [`from_dns_config`](PolicySnapshot::from_dns_config)) and [`Default`], which never
    /// saw a full document; those still surface the boundary zone via
    /// [`boundary_zone`](PolicySnapshot::boundary_zone) unchanged.
    pub fn committed_policy(&self) -> Option<&CommittedPolicy> {
        self.committed.as_ref()
    }
}

impl Default for PolicySnapshot {
    /// The pre-policy default: the D71 working-name boundary zone (`boundary.`),
    /// matching the ds-dnsgate handler-local fallback.
    fn default() -> PolicySnapshot {
        PolicySnapshot {
            boundary_zone: DEFAULT_BOUNDARY_ZONE.to_string(),
            committed: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Fleet token-revocation recognition + rung-conditional severing
// (D102 / P-R6, doc 19 §7; D53/D77 rung gate; D68 flush_session; D72 sweep).
//
// EMERGENCY fleet-wide token revocation rides the `policy_log` stream as another
// versioned policy artifact (the producer half is identity/fleetreg). This is the
// CONSUMER-side recognition: the one-per-host policy subscriber recognizes
// token-revocation entries on the composed document and, in the post-commit
// revocation sweep (D72), severs the flows established under a revoked token
// RUNG-CONDITIONALLY (D53/D77) through the shared `flush_session` primitive (D68).
//
// This module adds a CALL-SITE onto `flush_session` and encodes the rung gate —
// it never touches `flush_session`'s signature (ds-contracts) or ds-nft's body.
// The rung threshold is the SINGLE shared predicate
// `ds_contracts::pol1::Rung::is_block_or_higher` — the exact logic policy-core's
// `Decision::is_revocation_severing` wraps (`denies() && rung.is_block_or_higher()`);
// a revocation entry is a deny by construction, so it reduces to the rung gate.
// ─────────────────────────────────────────────────────────────────────────────

/// One recognized fleet token-revocation entry off the composed policy document
/// (doc 19 §7; D102). Each names a revoked token by a chain FINGERPRINT / unique
/// block identifier — NEVER token bytes (the producer, identity/fleetreg,
/// guarantees that structurally) — and carries the D53 rung the fleet revocation
/// is published at, which gates whether established flows are severed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetRevocationEntry {
    /// The revoked token's chain fingerprint / unique block id (hex; opaque to
    /// this crate). Carried for provenance + the host's fingerprint→session
    /// resolution; it is never token bytes and is never rendered into a flush.
    pub fingerprint: String,
    /// The D53 rung this revocation is published at. Drives the §5 severing gate.
    pub rung: Rung,
}

impl FleetRevocationEntry {
    /// Build a recognized entry from a fingerprint + its D53 rung.
    pub fn new(fingerprint: impl Into<String>, rung: Rung) -> FleetRevocationEntry {
        FleetRevocationEntry {
            fingerprint: fingerprint.into(),
            rung,
        }
    }

    /// Whether this revocation severs ESTABLISHED flows (doc 13 §5 rule 6/8;
    /// D53/D77). It is the same predicate policy-core's
    /// `Decision::is_revocation_severing` encodes — `denies() &&
    /// rung.is_block_or_higher()` — reduced to the rung gate because a
    /// revocation entry is a deny by construction. Delegates to the single
    /// shared threshold [`ds_contracts::pol1::Rung::is_block_or_higher`], so this
    /// consumer and the NFT programmer can never disagree on the block-or-higher
    /// line. A below-block rung gates NEW flows only and severs nothing (expiry
    /// is not revocation — a TTL lapse produces no entry here at all).
    #[must_use]
    pub fn severs_established_flows(&self) -> bool {
        self.rung.is_block_or_higher()
    }
}

/// The outcome of a fleet-revocation sweep — the accounting the host heartbeat
/// reports once the post-commit sweep completes (D72: `applied_seq` advances only
/// AFTER the sweep). Counters only; no session identity or fingerprint is retained.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RevocationSweep {
    /// Revocation entries recognized on the committed document.
    pub entries_seen: u64,
    /// Entries whose rung was below block-or-higher — new flows gated, no flush.
    pub rung_skipped: u64,
    /// Established sessions severed through `flush_session`.
    pub sessions_severed: u64,
    /// Conntrack entries destroyed across every severed session.
    pub entries_flushed: u64,
}

/// Sever the flows established under fleet-revoked tokens, rung-conditionally
/// (D53/D77) — the consumer-side post-commit revocation sweep (D72; doc 19 §7).
///
/// For each recognized entry whose rung [`FleetRevocationEntry::severs_established_flows`],
/// the live sessions `resolve_sessions` maps the revoked fingerprint to are
/// flushed through the shared [`ds_contracts::flush::FlushSession`] primitive
/// (D68) exactly as-is: `DstFilter::All` (every destination the revoked session
/// reached — a token revocation drops the whole session, unlike a
/// single-destination sweep) on the [`LegSelector::sever_pair`] leg pair (the
/// agent-VM and ds-tlsproxy-upstream nibbles). A below-block entry is counted and
/// skipped: its new flows were already gated by the committed ruleset, and its
/// established flows stay.
///
/// `resolve_sessions` is the host-agent's admission book (fingerprint → the
/// sessions admitted under that token); it is injected so this crate stays a pure
/// consumer with no admission state. `flush_session`'s signature and the ds-nft
/// body are untouched — this is a CALL-SITE only. A flush error short-circuits the
/// sweep fail-closed (the caller must not advance `applied_seq` on a failed sweep).
pub fn sweep_fleet_revocations<F, R>(
    flusher: &F,
    entries: &[FleetRevocationEntry],
    mut resolve_sessions: R,
) -> Result<RevocationSweep, F::Error>
where
    F: FlushSession,
    R: FnMut(&str) -> Vec<SessionRef>,
{
    let mut sweep = RevocationSweep::default();
    for entry in entries {
        sweep.entries_seen += 1;
        if !entry.severs_established_flows() {
            sweep.rung_skipped += 1;
            continue;
        }
        for session in resolve_sessions(&entry.fingerprint) {
            let outcome =
                flusher.flush_session(&session, &DstFilter::All, &LegSelector::sever_pair())?;
            sweep.sessions_severed += 1;
            sweep.entries_flushed += outcome.entries_flushed;
        }
    }
    Ok(sweep)
}

/// The host-agent's ADMISSION BOOK — the fingerprint→sessions resolver the post-commit
/// fleet-revocation sweep queries (doc 19 §7; D102/P-R6). An OBJECT-SAFE surface so the live
/// `WatchPolicies` serving loop can pass a REAL admission book (a shared registry the admission
/// path records into) rather than an injected test closure: [`sweep_fleet_revocations`]'s generic
/// `R: FnMut(&str) -> Vec<SessionRef>` resolver is ergonomic for a closure but not object-safe, and
/// the serving loop holds its admission book behind a trait object, so it routes through THIS
/// surface. A revoked token's fingerprint resolves to the live sessions admitted under it; the
/// sweep then severs each rung-conditionally through the shared `flush_session` primitive (D68).
///
/// The `fingerprint` is a hex chain fingerprint / unique block id — NEVER token bytes (the
/// producer, identity/fleetreg, guarantees that structurally, `TestRevocation_NoTokenBytes`); this
/// consumer treats it as an opaque key and never renders it into a flush.
pub trait SessionAdmissionBook {
    /// The live sessions admitted under the revoked token named by `fingerprint` (empty when the
    /// host admitted nothing under that token — a no-op sever for that entry). The object-safe
    /// twin of the `resolve_sessions` closure [`sweep_fleet_revocations`] takes.
    fn sessions_for_fingerprint(&self, fingerprint: &str) -> Vec<SessionRef>;
}

/// Run the post-commit fleet-revocation sweep against a REAL admission book (doc 19 §7; D72) — the
/// object-safe entry the live `WatchPolicies` serving loop drives, so it passes its shared
/// fingerprint→sessions admission book (a `&dyn SessionAdmissionBook`) instead of an injected test
/// closure. Delegates VERBATIM to [`sweep_fleet_revocations`] with `book`'s resolver, so the
/// rung-conditional severing, the `DstFilter::All`/`sever_pair` flush shape, and the fail-closed
/// short-circuit on a flush error are IDENTICAL — this only adapts the resolver from a closure to
/// the trait object the serving loop holds. `flush_session`'s signature (`ds-contracts`) and the
/// ds-nft body stay frozen (a CALL-SITE only).
pub fn sweep_fleet_revocations_with_book<F>(
    flusher: &F,
    entries: &[FleetRevocationEntry],
    book: &dyn SessionAdmissionBook,
) -> Result<RevocationSweep, F::Error>
where
    F: FlushSession,
{
    sweep_fleet_revocations(flusher, entries, |fp| book.sessions_for_fingerprint(fp))
}

// ─────────────────────────────────────────────────────────────────────────────
// ds.fleet_revocation.v1 wire RECOGNIZER — golden-coupled to the Go writer.
//
// The orchestrator's `marshalRevocationArtifact` (Go) frames an emergency
// fleet-revocation as a versioned, line-framed `ds.fleet_revocation.v1` payload on
// the policy_log; this is the DATA-PLANE decode of that exact wire shape. The two
// sides share ONE golden byte payload on disk ([`GOLDEN_REVOCATION_V1`], identical
// to the Go test's `goldenRevocationV1Payload`) rather than a cross-tree import
// (D80-legal: this crate imports neither the orchestrator nor identity/fleetreg).
// A Go framing edit that drifts from what this recognizer accepts flips the golden
// test on one side at review time.
//
// The envelope is:
//
//   ds.fleet_revocation.v1\n
//   schema=<schema tag>\n
//   batch=<batch id>\n
//   entries=<n>\n
//   e=<f|b>:<lower-hex id>\n            (× n, sorted by encoded form)
//
// SECRET DISCIPLINE (doc 19 §7/§9): each entry names a revoked token by EXACTLY
// one bounded lower-hex identifier — a 64-hex chain fingerprint or a ≤128-hex block
// id — NEVER token bytes. The decoder re-checks that structural fence and rejects
// (fail-closed) any id that is not bounded lower-hex, so a raw secret smuggled onto
// an entry line never parses. Decode failures return `None`: a malformed artifact
// revokes nothing, exactly as the Go `decodeRevocationArtifact` fails closed.

/// The self-describing header line of a `ds.fleet_revocation.v1` payload. Matches
/// the Go writer's `revEnvelopeHeader`.
pub const FLEET_REVOCATION_V1_HEADER: &str = "ds.fleet_revocation.v1";

/// Hex length of a SHA-256 chain fingerprint (D124, SHA-256 only): 32 bytes → 64
/// lower-hex chars. Mirrors the Go `fingerprintHexLen`.
const FLEET_REV_FINGERPRINT_HEX_LEN: usize = 64;

/// Upper bound on a block-id's hex length: a Biscuit native per-block revocation id
/// is a 64-byte Ed25519 block signature → 128 hex (doc 19 §7 OQ6). Mirrors the Go
/// `blockIDHexMaxLen`; an over-long blob (a possible token smuggle) is rejected.
const FLEET_REV_BLOCK_ID_HEX_MAX_LEN: usize = 128;

/// One decoded entry off a `ds.fleet_revocation.v1` envelope: a revoked token named
/// by EXACTLY one lower-hex identifier — a chain fingerprint or a unique block id,
/// NEVER token bytes (doc 19 §7/§9). The variant records which identifier the
/// producer set so a consumer reconstructs the exact field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FleetRevocationV1Id {
    /// A hex-lowercase SHA-256 chain fingerprint (64 hex chars).
    Fingerprint(String),
    /// A hex-lowercase unique block/revocation identifier (≤128 hex chars).
    BlockId(String),
}

/// A decoded `ds.fleet_revocation.v1` envelope — the recognizer's view of a
/// policy-log fleet-revocation artifact. Carries the schema tag, the batch id
/// (append↔ack provenance, doc 16 §6.5), and the revoked-token id set. It does NOT
/// carry a rung: the wire envelope names tokens only; the D53 rung that gates
/// severing is supplied by the composed-document context around the artifact (see
/// [`FleetRevocationEntry`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetRevocationV1Envelope {
    /// The versioned schema tag; a recognizer that negotiates on it compares
    /// against the producer's `fleet-revocation/v1`.
    pub schema_version: String,
    /// The batch id correlating this append with its ack.
    pub batch_id: String,
    /// The revoked-token identifiers (fingerprint / block id only, never bytes).
    pub ids: Vec<FleetRevocationV1Id>,
}

/// `true` iff `id` is an even-length lower-hex string in `[min,max]`. Lower-hex +
/// even-length + bounded is the structural fence that keeps a raw token (neither
/// fixed-length nor hex) out of a decoded artifact — the data-plane twin of the Go
/// `validateRevHexID`.
fn is_bounded_lower_hex(id: &str, min: usize, max: usize) -> bool {
    let n = id.len();
    if !(min..=max).contains(&n) || !n.is_multiple_of(2) {
        return false;
    }
    id.bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Split off the bytes up to (not including) the next `\n`, returning the line and
/// the remainder after the `\n`. `None` when no terminator is found — a trailing
/// unterminated segment is a framing violation (matches the Go `revNextLine`).
fn next_framed_line(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = b.iter().position(|&c| c == b'\n')?;
    Some((&b[..i], &b[i + 1..]))
}

/// Decode a `ds.fleet_revocation.v1` payload into its schema tag, batch id, and
/// revoked-token id set — the inverse of the Go `marshalRevocationArtifact`.
/// Returns `None` on ANY framing violation (unknown header, missing/reordered
/// field line, bad count, an entry that is not `<f|b>:<bounded-lower-hex>`, or
/// trailing bytes) — fail-closed: a malformed artifact revokes nothing. Because
/// every id is bounded lower-hex, a `\n` is an unambiguous entry delimiter.
#[must_use]
pub fn decode_fleet_revocation_v1(payload: &[u8]) -> Option<FleetRevocationV1Envelope> {
    let mut rest = payload;

    let (line, r) = next_framed_line(rest)?;
    rest = r;
    if line != FLEET_REVOCATION_V1_HEADER.as_bytes() {
        return None;
    }

    let (line, r) = next_framed_line(rest)?;
    rest = r;
    let schema = std::str::from_utf8(line.strip_prefix(b"schema=")?).ok()?;

    let (line, r) = next_framed_line(rest)?;
    rest = r;
    let batch = std::str::from_utf8(line.strip_prefix(b"batch=")?).ok()?;

    let (line, r) = next_framed_line(rest)?;
    rest = r;
    let count_str = std::str::from_utf8(line.strip_prefix(b"entries=")?).ok()?;
    let count: usize = count_str.parse().ok()?;

    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let (line, r) = next_framed_line(rest)?;
        rest = r;
        let body = line.strip_prefix(b"e=")?;
        let colon = body.iter().position(|&c| c == b':')?;
        let kind = &body[..colon];
        let id = std::str::from_utf8(&body[colon + 1..]).ok()?;
        let entry = match kind {
            b"f" => {
                if !is_bounded_lower_hex(
                    id,
                    FLEET_REV_FINGERPRINT_HEX_LEN,
                    FLEET_REV_FINGERPRINT_HEX_LEN,
                ) {
                    return None;
                }
                FleetRevocationV1Id::Fingerprint(id.to_string())
            }
            b"b" => {
                if !is_bounded_lower_hex(id, 2, FLEET_REV_BLOCK_ID_HEX_MAX_LEN) {
                    return None;
                }
                FleetRevocationV1Id::BlockId(id.to_string())
            }
            _ => return None,
        };
        ids.push(entry);
    }
    if !rest.is_empty() {
        return None;
    }

    Some(FleetRevocationV1Envelope {
        schema_version: schema.to_string(),
        batch_id: batch.to_string(),
        ids,
    })
}

/// Map a decoded `ds.fleet_revocation.v1` id set onto the rung-tagged
/// [`FleetRevocationEntry`] set the sweep severs — the production bridge from the
/// on-wire envelope to [`sweep_fleet_revocations`]. Each decoded identifier (a chain
/// fingerprint OR a unique block id — NEVER token bytes, doc 19 §7/§9) becomes one
/// entry carrying the D53 `rung` the composed-document context published the revocation
/// at (the envelope itself names tokens only; the rung is NOT on the wire — see
/// [`FleetRevocationV1Envelope`]). Returns `None` on ANY framing violation — fail-closed,
/// exactly as [`decode_fleet_revocation_v1`]: a malformed artifact yields no entries and
/// so severs nothing.
#[must_use]
pub fn fleet_revocation_entries_from_v1(
    payload: &[u8],
    rung: Rung,
) -> Option<Vec<FleetRevocationEntry>> {
    let envelope = decode_fleet_revocation_v1(payload)?;
    Some(
        envelope
            .ids
            .into_iter()
            .map(|id| {
                // Both id kinds name a revoked token by an opaque lower-hex key the sweep
                // resolves against the admission book; `FleetRevocationEntry` carries a
                // single `fingerprint` field ("chain fingerprint / unique block id"), so a
                // block id flows into the same field.
                let fingerprint = match id {
                    FleetRevocationV1Id::Fingerprint(f) => f,
                    FleetRevocationV1Id::BlockId(b) => b,
                };
                FleetRevocationEntry::new(fingerprint, rung)
            })
            .collect(),
    )
}

/// The error a decode-driven fleet-revocation sweep can surface (doc 19 §7; D72). It
/// separates the fail-closed DECODE rejection from a `flush_session` error so the caller
/// routes each correctly: a [`EncodedRevocationSweepError::Malformed`] artifact severed
/// nothing (a framing violation / a non-hex id — a possible token smuggle), whereas a
/// [`EncodedRevocationSweepError::Flush`] means the sweep short-circuited mid-flight and
/// the caller MUST NOT advance `applied_seq`.
#[derive(Debug)]
pub enum EncodedRevocationSweepError<E> {
    /// The `ds.fleet_revocation.v1` payload failed to decode — fail-closed: nothing was
    /// severed. The data-plane twin of the Go `decodeRevocationArtifact` returning
    /// `ok == false`.
    Malformed,
    /// A `flush_session` error short-circuited the sweep; the caller must not advance
    /// `applied_seq` on a failed sweep.
    Flush(E),
}

/// The LIVE sweep path over an on-wire `ds.fleet_revocation.v1` artifact — the production
/// caller of [`decode_fleet_revocation_v1`] (doc 19 §7; D72). The one-per-host policy
/// subscriber hands the committed artifact bytes off the `policy_log`, the D53 `rung` the
/// composed document published the revocation at, and its REAL fingerprint→sessions
/// admission book; this decodes the payload into the {fingerprint, block-id} id set
/// (fail-closed on a framing violation — a malformed artifact severs nothing) and severs
/// the resolved sessions rung-conditionally through the shared `flush_session` primitive
/// (D68), returning the sweep accounting the host heartbeat reports.
///
/// The severing itself delegates VERBATIM to [`sweep_fleet_revocations_with_book`], so the
/// rung gate, the `DstFilter::All`/`sever_pair` flush shape, and the fail-closed
/// short-circuit on a flush error are identical — this only adds the decode-then-map step
/// in front, wiring the golden-coupled recognizer into the datapath rather than leaving it
/// a golden-test-only reader. `flush_session`'s signature (`ds-contracts`) and the ds-nft
/// body stay frozen (a CALL-SITE only).
pub fn sweep_fleet_revocation_v1<F>(
    flusher: &F,
    payload: &[u8],
    rung: Rung,
    book: &dyn SessionAdmissionBook,
) -> Result<RevocationSweep, EncodedRevocationSweepError<F::Error>>
where
    F: FlushSession,
{
    let entries = fleet_revocation_entries_from_v1(payload, rung)
        .ok_or(EncodedRevocationSweepError::Malformed)?;
    sweep_fleet_revocations_with_book(flusher, &entries, book)
        .map_err(EncodedRevocationSweepError::Flush)
}

/// The ONE canonical, committed `ds.fleet_revocation.v1` golden byte payload,
/// INCLUDED byte-for-byte from the single authoritative on-disk file
/// `orchestrator/internal/policylog/testdata/ds.fleet_revocation.v1.golden` — the
/// SAME file the Go side embeds via `//go:embed` as `goldenRevocationV1Payload`.
/// This crate decodes it ([`fleet_revocation_v1_golden_decodes_to_expected_fields`])
/// while the Go side asserts its writer emits it exactly; the golden bytes on disk
/// are the D80-legal coupling between the two trees (this crate imports neither the
/// orchestrator nor identity/fleetreg). Loading ONE authoritative file from both
/// sides (`include_bytes!` here, `//go:embed` there) makes that coupling mechanical
/// rather than a hand-kept pair of literals: a Go framing edit that drifts from what
/// this recognizer accepts flips the golden test on one side at review time.
#[cfg(test)]
pub(crate) const GOLDEN_REVOCATION_V1: &[u8] = include_bytes!(
    "../../../../orchestrator/internal/policylog/testdata/ds.fleet_revocation.v1.golden"
);

#[cfg(test)]
mod fleet_revocation_v1_golden_tests {
    use super::*;

    // The two synthetic identifiers the golden encodes (D50). Fixed-length
    // lower-hex, so NO token bytes ride the payload (doc 19 §7/§9).
    const GOLDEN_FINGERPRINT: &str =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const GOLDEN_BLOCK_ID: &str = "0123456789abcdef0123456789abcdef";
    const GOLDEN_BATCH_ID: &str = "kill-switch-golden-1";

    #[test]
    fn fleet_revocation_v1_golden_decodes_to_expected_fields() {
        let env = decode_fleet_revocation_v1(GOLDEN_REVOCATION_V1)
            .expect("golden ds.fleet_revocation.v1 payload must decode");
        assert_eq!(env.schema_version, "fleet-revocation/v1");
        assert_eq!(env.batch_id, GOLDEN_BATCH_ID);
        // Entry lines are sorted by encoded form, so block-id ("b:") precedes
        // fingerprint ("f:") — the SAME order the Go writer emits.
        assert_eq!(
            env.ids,
            vec![
                FleetRevocationV1Id::BlockId(GOLDEN_BLOCK_ID.to_string()),
                FleetRevocationV1Id::Fingerprint(GOLDEN_FINGERPRINT.to_string()),
            ]
        );
    }

    #[test]
    fn fleet_revocation_v1_golden_carries_no_token_bytes() {
        // The load-bearing §7/§9 guard on the recognizer side: every decoded id is
        // a bounded lower-hex fingerprint / block id — never token bytes.
        let env = decode_fleet_revocation_v1(GOLDEN_REVOCATION_V1).expect("decode");
        for id in &env.ids {
            match id {
                FleetRevocationV1Id::Fingerprint(f) => assert!(
                    is_bounded_lower_hex(
                        f,
                        FLEET_REV_FINGERPRINT_HEX_LEN,
                        FLEET_REV_FINGERPRINT_HEX_LEN
                    ),
                    "fingerprint {f:?} is not a bounded lower-hex id (possible token smuggle)"
                ),
                FleetRevocationV1Id::BlockId(b) => assert!(
                    is_bounded_lower_hex(b, 2, FLEET_REV_BLOCK_ID_HEX_MAX_LEN),
                    "block id {b:?} is not a bounded lower-hex id (possible token smuggle)"
                ),
            }
        }
    }

    #[test]
    fn mutating_one_golden_byte_fails_the_recognizer() {
        // The acceptance guard: hand-mutating one byte of the reader's expectation
        // (here, the golden bytes it decodes) changes the decoded fields — proving
        // the test actually pins the wire shape. Flip the first hex char of the
        // block id from '0' to '1'.
        let mut mutated = GOLDEN_REVOCATION_V1.to_vec();
        let needle = b"e=b:0";
        let pos = mutated
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("golden contains the block-id line");
        let flip = pos + needle.len() - 1; // the '0' after "e=b:"
        assert_eq!(mutated[flip], b'0');
        mutated[flip] = b'1';
        let env = decode_fleet_revocation_v1(&mutated).expect("still valid framing");
        assert_ne!(
            env.ids,
            vec![
                FleetRevocationV1Id::BlockId(GOLDEN_BLOCK_ID.to_string()),
                FleetRevocationV1Id::Fingerprint(GOLDEN_FINGERPRINT.to_string()),
            ],
            "a mutated golden byte must change the decoded fields"
        );
    }

    #[test]
    fn non_hex_entry_fails_closed() {
        // A raw-token smuggle onto an entry line (non-hex id) must not decode.
        let payload = b"ds.fleet_revocation.v1\n\
schema=fleet-revocation/v1\n\
batch=b\n\
entries=1\n\
e=f:this-is-a-raw-token-not-a-hex-fingerprint\n";
        assert!(
            decode_fleet_revocation_v1(payload).is_none(),
            "a non-hex entry must fail closed"
        );
    }

    #[test]
    fn trailing_bytes_fail_closed() {
        // Extra bytes after the framed entries are a framing violation.
        let mut extra = GOLDEN_REVOCATION_V1.to_vec();
        extra.extend_from_slice(b"e=f:deadbeef\n");
        assert!(
            decode_fleet_revocation_v1(&extra).is_none(),
            "trailing bytes past the declared entry count must fail closed"
        );
    }

    #[test]
    fn golden_include_bytes_matches_the_on_disk_authoritative_file() {
        // The included golden is byte-for-byte the single authoritative on-disk file —
        // the SAME file the Go side embeds via `//go:embed`. Reading it at test time and
        // comparing to `include_bytes!` proves the two trees load ONE file (the D80-legal
        // coupling), so a framing edit that skips the file flips a golden test on one side.
        let on_disk = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../orchestrator/internal/policylog/testdata/ds.fleet_revocation.v1.golden"
        ))
        .expect("the authoritative golden file is readable from the crate");
        assert_eq!(
            GOLDEN_REVOCATION_V1,
            on_disk.as_slice(),
            "include_bytes! drifted from the on-disk authoritative golden"
        );
        assert_eq!(on_disk.len(), 193, "the pinned 193-byte golden length");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_snapshot_carries_the_working_name_boundary_zone() {
        assert_eq!(DEFAULT_BOUNDARY_ZONE, "boundary.");
        assert_eq!(PolicySnapshot::default().boundary_zone(), "boundary.");
    }

    #[test]
    fn snapshot_re_export_matches_the_pol1_home() {
        // The snapshot's fallback is the SAME literal the POL-1 schema home pins.
        assert_eq!(DEFAULT_BOUNDARY_ZONE, pol1::DEFAULT_BOUNDARY_ZONE);
    }

    #[test]
    fn from_boundary_zone_carries_an_explicit_value() {
        let snap = PolicySnapshot::from_boundary_zone("example.test.");
        assert_eq!(snap.boundary_zone(), "example.test.");
    }

    #[test]
    fn empty_boundary_zone_falls_back_to_the_default() {
        let snap = PolicySnapshot::from_boundary_zone("");
        assert_eq!(snap.boundary_zone(), DEFAULT_BOUNDARY_ZONE);
    }

    #[test]
    fn from_dns_config_lifts_the_policy_pushed_zone() {
        // A POL-1 layer that names dns.boundary_zone flows onto the snapshot.
        let doc = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                   dns:\n  boundary_zone: corp.example.\n";
        let layer = pol1::parse_layer(doc).expect("clean layer parses");
        let snap = PolicySnapshot::from_dns_config(&layer.dns);
        assert_eq!(snap.boundary_zone(), "corp.example.");
    }

    #[test]
    fn from_dns_config_default_preserves_the_working_name() {
        // A POL-1 layer that omits dns.boundary_zone => the working-name default,
        // so the snapshot carries the same value the handler-local const did.
        let doc = "schema_version: pol1/v0\nlayer: org\nposture: standard\n";
        let layer = pol1::parse_layer(doc).expect("clean layer parses");
        let snap = PolicySnapshot::from_dns_config(&layer.dns);
        assert_eq!(snap.boundary_zone(), DEFAULT_BOUNDARY_ZONE);
    }

    #[test]
    fn boundary_zone_value_is_the_owned_live_wire_read() {
        // The live wire reads an OWNED String off the snapshot (no borrow held across
        // the gate's listener lifetime), equal to the borrowing accessor's value.
        let snap = PolicySnapshot::from_boundary_zone("corp.example.");
        assert_eq!(snap.boundary_zone_value(), "corp.example.");
        assert_eq!(snap.boundary_zone_value(), snap.boundary_zone());
    }

    #[test]
    fn d72_hot_reload_resources_the_boundary_zone_from_the_new_snapshot() {
        // Doc 13 §5.3 admitter-LAST D72 hot-reload: the gate sources boundary_zone from
        // the LIVE snapshot at startup, and a hot-reload swaps the snapshot, so the next
        // live-wire read returns the NEWLY-applied policy suffix — never the constructor
        // default and never the previous snapshot's value.
        let startup = PolicySnapshot::from_dns_config(&dns_layer("alpha.example."));
        assert_eq!(startup.boundary_zone_value(), "alpha.example.");

        // The admitter-LAST commit installs a new snapshot; the gate re-sources from it.
        let reloaded = PolicySnapshot::from_dns_config(&dns_layer("beta.example."));
        assert_eq!(reloaded.boundary_zone_value(), "beta.example.");
        assert_ne!(
            reloaded.boundary_zone_value(),
            startup.boundary_zone_value()
        );

        // A reload to a layer that OMITS the field falls back to the working name — the
        // same value the constructor default carries, sourced from the snapshot all the
        // same (never a stale previous suffix).
        let omitted = PolicySnapshot::from_dns_config(&dns_layer_no_dns());
        assert_eq!(omitted.boundary_zone_value(), DEFAULT_BOUNDARY_ZONE);
    }

    // ── committed-policy accessor (the ds-dnsgate re-mirror, lifted THROUGH the snapshot) ──

    /// A POL-1 snapshot naming a boundary zone AND non-default admission timers — the
    /// fixture `ds-dnsgate`'s seam tests use to prove a committed snapshot carries its OWN
    /// composed doc + clamp, not a `TtlClamp::DEFAULT` echo (30s/600s ≠ the 60s/900s
    /// default).
    const COMMITTED_SNAPSHOT: &str = "schema_version: pol1/v0\nlayer: session\n\
         posture: standard\nadmission:\n  ttl_floor: 30\n  ttl_ceil: 600\n\
         dns:\n  boundary_zone: corp.example.\n";

    #[test]
    fn committed_policy_lifts_the_composed_doc_clamp_and_zone_off_one_layer() {
        // The whole point of the accessor: one parsed snapshot layer yields ONE committed
        // policy carrying the composed-document material (the layer itself), the W2 clamp,
        // and the boundary zone — the D72 "one snapshot → one doc + one clamp + one zone".
        let layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("clean layer parses");
        let snap = PolicySnapshot::from_policy_layer(&layer);

        let committed = snap
            .committed_policy()
            .expect("a layer-sourced snapshot carries a committed policy");

        // (1) Composed-document MATERIAL: the layer the boundary service feeds to
        //     policy-core::compose is exactly the parsed snapshot layer (no re-parse drift).
        assert_eq!(committed.composed_layer(), &layer);

        // (2) W2 clamp: lifted off THIS layer's admission block (30s/600s), not the
        //     60s/900s reader default — the same projection ds-dnsgate's live_ttl_clamp does.
        assert_eq!(
            committed.ttl_clamp(),
            W2TtlClamp {
                floor: 30,
                ceil: 600
            }
        );

        // (3) Boundary zone: the same value the existing boundary-zone accessors carry.
        assert_eq!(committed.boundary_zone(), "corp.example.");
        assert_eq!(committed.boundary_zone(), snap.boundary_zone());
        assert_eq!(committed.boundary_zone(), &snap.boundary_zone_value());
    }

    #[test]
    fn committed_policy_matches_the_ds_dnsgate_re_mirror() {
        // ds-dnsgate's snapshot_host_policy re-mirrors: parse_layer(text) -> { compose(&[layer], &[]),
        // live_boundary_zone(&layer.dns) = dns.boundary_zone.clone(),
        // live_ttl_clamp(&layer.admission) = TtlClamp { floor: ttl_floor, ceil: ttl_ceil } }.
        // The accessor lifts the SAME pieces through the snapshot; prove each one matches the
        // hand-rolled re-mirror so the gate can delete the duplicated lift with zero drift.
        let layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("clean layer parses");

        // The re-mirror's three lifts, computed locally (compose's INPUT is the layer):
        let mirror_boundary_zone = layer.dns.boundary_zone.clone();
        let mirror_floor = layer.admission.ttl_floor;
        let mirror_ceil = layer.admission.ttl_ceil;

        let committed = PolicySnapshot::from_policy_layer(&layer)
            .committed_policy()
            .cloned()
            .expect("a layer-sourced snapshot carries a committed policy");

        // The composed-doc material the gate composes from is the SAME layer it parsed.
        assert_eq!(committed.composed_layer(), &layer);
        // The clamp window equals the gate's live_ttl_clamp projection field-for-field.
        assert_eq!(committed.ttl_clamp().floor, mirror_floor);
        assert_eq!(committed.ttl_clamp().ceil, mirror_ceil);
        // The boundary zone equals the gate's live_boundary_zone lift.
        assert_eq!(committed.boundary_zone(), mirror_boundary_zone);
    }

    #[test]
    fn committed_policy_defaults_the_clamp_and_zone_when_the_layer_omits_them() {
        // A bare layer (no admission, no dns) => the reader's 60s/900s clamp + working-name
        // zone, lifted onto the committed policy exactly as the snapshot's boundary-zone path
        // already defaults — the committed clamp is the W2 default WINDOW (not a magic echo).
        let layer = pol1::parse_layer("schema_version: pol1/v0\nlayer: org\nposture: standard\n")
            .expect("clean layer parses");
        let committed = PolicySnapshot::from_policy_layer(&layer)
            .committed_policy()
            .cloned()
            .expect("a layer-sourced snapshot carries a committed policy");

        assert_eq!(
            committed.ttl_clamp(),
            W2TtlClamp {
                floor: 60,
                ceil: 900
            }
        );
        assert_eq!(committed.boundary_zone(), DEFAULT_BOUNDARY_ZONE);
    }

    #[test]
    fn committed_policy_is_absent_on_the_boundary_zone_only_carriers() {
        // ADDITIVE-ONLY: the existing constructors carry no committed policy (they never saw
        // a full document), so their boundary-zone behavior is byte-identical — the new field
        // is None and the existing accessors are untouched.
        assert!(PolicySnapshot::default().committed_policy().is_none());
        assert!(PolicySnapshot::from_boundary_zone("corp.example.")
            .committed_policy()
            .is_none());
        let dns_only = PolicySnapshot::from_dns_config(&dns_layer("corp.example."));
        assert!(dns_only.committed_policy().is_none());
        // …and the boundary zone still surfaces unchanged on those carriers.
        assert_eq!(dns_only.boundary_zone(), "corp.example.");
    }

    #[test]
    fn d72_reload_re_sources_the_committed_policy_from_the_new_layer() {
        // A D72 admitter-LAST commit swaps the snapshot; the gate re-sources its WHOLE
        // committed policy (doc material + clamp) from the NEW layer — never a stale doc or a
        // clamp from the previous snapshot (one snapshot → one policy version).
        let startup_layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");
        let startup = PolicySnapshot::from_policy_layer(&startup_layer);
        let startup_committed = startup.committed_policy().expect("committed").clone();
        assert_eq!(
            startup_committed.ttl_clamp(),
            W2TtlClamp {
                floor: 30,
                ceil: 600
            }
        );

        let reloaded_layer = pol1::parse_layer(
            "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             admission:\n  ttl_floor: 120\n  ttl_ceil: 1200\n\
             dns:\n  boundary_zone: beta.example.\n",
        )
        .expect("parses");
        let reloaded = PolicySnapshot::from_policy_layer(&reloaded_layer);
        let reloaded_committed = reloaded.committed_policy().expect("committed");

        // The reloaded committed policy carries the NEW layer's doc + clamp + zone, distinct
        // from the startup snapshot's — proving the source is the live snapshot, not a cache.
        assert_eq!(reloaded_committed.composed_layer(), &reloaded_layer);
        assert_eq!(
            reloaded_committed.ttl_clamp(),
            W2TtlClamp {
                floor: 120,
                ceil: 1200
            }
        );
        assert_eq!(reloaded_committed.boundary_zone(), "beta.example.");
        assert_ne!(
            reloaded_committed.ttl_clamp(),
            startup_committed.ttl_clamp()
        );
        assert_ne!(
            reloaded_committed.composed_layer(),
            startup_committed.composed_layer()
        );
    }

    #[test]
    fn w2_ttl_clamp_lifts_directly_off_admission_timers() {
        // The clamp lift is a standalone, ds-contracts-bounded projection: floor/ceil copied
        // off the POL-1 admission block, matching ds-dnsgate's TtlClamp { floor, ceil } shape.
        let layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");
        let clamp = W2TtlClamp::from_admission_timers(&layer.admission);
        assert_eq!(clamp.floor, layer.admission.ttl_floor);
        assert_eq!(clamp.ceil, layer.admission.ttl_ceil);
        // The defaulted timers give the W2 default window (60s/900s).
        let default_clamp = W2TtlClamp::from_admission_timers(&pol1::AdmissionTimers::default());
        assert_eq!(
            default_clamp,
            W2TtlClamp {
                floor: 60,
                ceil: 900
            }
        );
    }

    // ── D72 (seq, content_hash) snapshot identity (doc 13 §5) ──────────────────────

    #[test]
    fn identical_documents_produce_a_stable_content_hash() {
        // doc 13 §5 / D72: the content_hash is a pure function of the composed document —
        // two snapshots built from the SAME document carry the SAME content_hash (the
        // loader can detect a duplicate fan-out by identity). Re-parse the same text and
        // build twice; the hashes must be equal AND stable across calls.
        let layer_a = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");
        let layer_b = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");

        let hash_a = PolicySnapshot::from_policy_layer(&layer_a)
            .committed_policy()
            .expect("committed")
            .content_hash();
        let hash_b = PolicySnapshot::from_policy_layer(&layer_b)
            .committed_policy()
            .expect("committed")
            .content_hash();
        assert_eq!(hash_a, hash_b, "same document => same content_hash");

        // Stable across repeated computation of the SAME layer (no per-process seed).
        assert_eq!(
            content_hash_of_layer(&layer_a),
            content_hash_of_layer(&layer_a)
        );
        assert_eq!(content_hash_of_layer(&layer_a), hash_a);
    }

    #[test]
    fn distinct_documents_produce_distinct_content_hashes() {
        // doc 13 §5 / D72: different composed documents => different content_hash, so the
        // loader never mistakes a changed policy for a duplicate. The two fixtures differ
        // only in the boundary zone + admission timers — still a distinct content hash.
        let committed_layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");
        let other_layer = pol1::parse_layer(
            "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             admission:\n  ttl_floor: 120\n  ttl_ceil: 1200\n\
             dns:\n  boundary_zone: beta.example.\n",
        )
        .expect("parses");

        let committed_hash = content_hash_of_layer(&committed_layer);
        let other_hash = content_hash_of_layer(&other_layer);
        assert_ne!(
            committed_hash, other_hash,
            "distinct documents => distinct content_hash"
        );

        // Surfaced identically through the committed-policy accessor.
        let a = PolicySnapshot::from_policy_layer(&committed_layer)
            .committed_policy()
            .expect("committed")
            .identity();
        let b = PolicySnapshot::from_policy_layer(&other_layer)
            .committed_policy()
            .expect("committed")
            .identity();
        assert_ne!(a.content_hash(), b.content_hash());
        assert_eq!(a.content_hash(), committed_hash);
        assert_eq!(b.content_hash(), other_hash);
    }

    #[test]
    fn the_seqless_path_defaults_seq_to_zero_with_a_real_content_hash() {
        // ADDITIVE-ONLY: the wave30 `from_policy_layer(&layer)` arity is unchanged; with no
        // control-plane seq supplied, the D72 identity defaults seq=0 but still carries the
        // real content_hash of the composed document.
        let layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");
        let committed = PolicySnapshot::from_policy_layer(&layer)
            .committed_policy()
            .cloned()
            .expect("committed");
        assert_eq!(committed.seq(), 0);
        assert_eq!(committed.content_hash(), content_hash_of_layer(&layer));
        // The identity pair surfaces the same scalars as the dedicated accessors.
        assert_eq!(committed.identity().seq(), 0);
        assert_eq!(
            committed.identity().content_hash(),
            committed.content_hash()
        );
    }

    #[test]
    fn the_opt_in_seq_constructor_threads_the_forward_only_seq() {
        // The opt-in `from_policy_layer_with_seq` supplies the D72 forward-only seq; the
        // content_hash is identical to the seq-less path (same document), so seq is the
        // ONLY differing identity component. The loader uses (seq, content_hash) together:
        // same content_hash + a higher seq = a fresh re-apply of the same document.
        let layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");
        let seqless = PolicySnapshot::from_policy_layer(&layer)
            .committed_policy()
            .cloned()
            .expect("committed");
        let seq_7 = PolicySnapshot::from_policy_layer_with_seq(&layer, 7)
            .committed_policy()
            .cloned()
            .expect("committed");

        assert_eq!(seq_7.seq(), 7);
        assert_eq!(seq_7.content_hash(), seqless.content_hash());
        // The composed document + clamp + zone (the wave30 surface) are byte-identical:
        // the only change a supplied seq makes is the identity's seq component.
        assert_eq!(seq_7.composed_layer(), seqless.composed_layer());
        assert_eq!(seq_7.ttl_clamp(), seqless.ttl_clamp());
        assert_eq!(seq_7.boundary_zone(), seqless.boundary_zone());
        // Two distinct applied seqs => distinct full identities (forward-only-seq, D72).
        assert_ne!(seq_7.identity(), seqless.identity());
    }

    #[test]
    fn identity_travels_with_the_document_on_a_d72_reload() {
        // A D72 admitter-LAST commit swaps the snapshot; the reloaded committed policy
        // carries the NEW document's identity (distinct content_hash, the supplied seq) —
        // never a stale identity from the previous snapshot. One snapshot => one seq => one
        // composed doc + clamp + zone.
        let startup_layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");
        let startup = PolicySnapshot::from_policy_layer_with_seq(&startup_layer, 3)
            .committed_policy()
            .cloned()
            .expect("committed");

        let reloaded_layer = pol1::parse_layer(
            "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             admission:\n  ttl_floor: 120\n  ttl_ceil: 1200\n\
             dns:\n  boundary_zone: beta.example.\n",
        )
        .expect("parses");
        let reloaded = PolicySnapshot::from_policy_layer_with_seq(&reloaded_layer, 4)
            .committed_policy()
            .cloned()
            .expect("committed");

        assert_ne!(startup.identity(), reloaded.identity());
        assert_ne!(startup.content_hash(), reloaded.content_hash());
        assert_eq!(reloaded.seq(), 4);
        // The reloaded identity's content_hash matches the NEW document it identifies.
        assert_eq!(
            reloaded.content_hash(),
            content_hash_of_layer(reloaded.composed_layer())
        );
    }

    // ── D120 WIRE content_hash reconcile (doc 13 §5.1 / D120) ──────────────────────
    //
    // The local FNV fingerprint above is the build-LOCAL self-identity; the D120 wire
    // content_hash is SHA-256 (full 32 bytes) over the PRODUCE-ONCE RFC 8785 (JCS)
    // payload the Go host agent forms. This crate is VERIFY-ONLY: it delegates hashing
    // to the frozen `ds_contracts::snapshot_verify`, never re-canonicalizing. These
    // tests pin that there is ONE source of wire hashing and the snapshot carries the
    // SAME 32-byte hash the loader's NACK-on-hash check validates.
    //
    // The representative transported payloads + pinned hashes below are the canonical
    // D120 examples from the shared frozen golden fixture
    // (`ds-contracts/testdata/snapshot-goldens.json`): a DNS-block policy document with a
    // meaningful-zero `negative_ttl` and a doc 18 role document on the identical path.

    /// `dns_zero_present` golden — a DNS policy block on the canonical JCS path.
    const WIRE_DNS_PAYLOAD: &[u8] =
        b"{\"negative_ttl\":0,\"upstream_resolvers\":[\"1.1.1.1\",\"8.8.8.8\"]}";
    const WIRE_DNS_HASH_HEX: &str =
        "87511efd433682ce4c4a792a9748a3f5e134344fac5274f09295345438ad0454";
    /// `role_document` golden — one canonicalizer, two documents (doc 13 §5.1).
    const WIRE_ROLE_PAYLOAD: &[u8] =
        b"{\"name\":\"reviewer\",\"permissions\":[\"read\",\"comment\"],\"version\":3}";
    const WIRE_ROLE_HASH_HEX: &str =
        "5e75653b5b4044ccaeb4097e811dddbf3a67b40931b79d448d287bdd8324948b";

    #[test]
    fn local_wire_hash_equals_ds_contracts_wire_content_hash_for_the_dns_document() {
        // The single-source-of-hashing property: the snapshot's wire content_hash for a
        // transported document is byte-identical to `ds_contracts::snapshot_verify::sha256`
        // over the SAME transported bytes — there is no second incompatible fingerprint.
        let contracts_hash = snapshot_verify::sha256(WIRE_DNS_PAYLOAD);
        let pinned = snapshot_verify::parse_content_hash_hex(WIRE_DNS_HASH_HEX)
            .expect("pinned golden hash is 32-byte hex");
        // The ds-contracts hash reproduces the pinned D120 golden (the wire contract).
        assert_eq!(contracts_hash, pinned, "ds-contracts hash != pinned golden");

        // The crate's verify-only path delegates to ds-contracts and VERIFIES the
        // transported bytes against that hash — never re-canonicalizing.
        assert_eq!(
            verify_transported_bytes(WIRE_DNS_PAYLOAD, &contracts_hash),
            Verdict::Verified,
            "verify-only path must accept the producer's bytes against their wire hash"
        );

        // A snapshot built from the VERIFIED bytes carries EXACTLY that wire hash on its
        // identity — the local fingerprint and the wire hash are distinct fields, but the
        // wire hash is the SAME one ds-contracts (the single source) computed.
        let layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");
        let committed = PolicySnapshot::from_verified_bytes_and_layer(&layer, 9, contracts_hash)
            .committed_policy()
            .cloned()
            .expect("committed");
        assert_eq!(
            committed.wire_content_hash(),
            Some(contracts_hash),
            "the snapshot's wire content_hash must equal the ds-contracts wire hash"
        );
        assert_eq!(committed.wire_content_hash(), Some(pinned));
        assert_eq!(committed.identity().wire_content_hash(), Some(pinned));
        // The wire hash is the loader-checked one; same length as the D120 contract (32).
        assert_eq!(
            committed.wire_content_hash().map(|h| h.len()),
            Some(WIRE_CONTENT_HASH_LEN)
        );
        assert_eq!(WIRE_CONTENT_HASH_LEN, snapshot_verify::CONTENT_HASH_LEN);
    }

    #[test]
    fn local_wire_hash_equals_ds_contracts_wire_content_hash_for_the_role_document() {
        // One spec, two documents (doc 13 §5.1): the role document hashes on the IDENTICAL
        // path. The crate's wire hash for a representative role payload equals the
        // ds-contracts wire content_hash byte-for-byte, the same single source of hashing.
        let contracts_hash = snapshot_verify::sha256(WIRE_ROLE_PAYLOAD);
        let pinned = snapshot_verify::parse_content_hash_hex(WIRE_ROLE_HASH_HEX)
            .expect("pinned golden hash is 32-byte hex");
        assert_eq!(contracts_hash, pinned, "ds-contracts hash != pinned golden");
        assert_eq!(
            verify_transported_bytes(WIRE_ROLE_PAYLOAD, &pinned),
            Verdict::Verified
        );

        // Two representative documents produce DISTINCT wire hashes — the wire hash
        // discriminates documents exactly as ds-contracts does.
        let dns_hash = snapshot_verify::sha256(WIRE_DNS_PAYLOAD);
        assert_ne!(
            contracts_hash, dns_hash,
            "distinct documents => distinct wire content_hash"
        );
    }

    #[test]
    fn verify_transported_bytes_nacks_a_mutated_transport_host_wide() {
        // The loader's hash-check-BEFORE-parse step: a byte-mutated transport must NACK
        // host-wide against the producer's wire hash (doc 13 §5 identity row, D72) — never
        // accepted, never re-canonicalized. The verdict is the ds-contracts verdict verbatim.
        let good = snapshot_verify::sha256(WIRE_DNS_PAYLOAD);
        let mutated: &[u8] =
            b"{\"negative_ttl\":1,\"upstream_resolvers\":[\"1.1.1.1\",\"8.8.8.8\"]}";
        match verify_transported_bytes(mutated, &good) {
            Verdict::Nack { expected, computed } => {
                assert_eq!(expected, good, "NACK reports the producer's expected hash");
                assert_ne!(computed, good, "the mutation changed the computed hash");
            }
            Verdict::Verified => panic!("byte-mutated transport wrongly VERIFIED — NACK expected"),
        }
        // And the unmutated transport verifies against the same hash.
        assert!(verify_transported_bytes(WIRE_DNS_PAYLOAD, &good).is_verified());
    }

    #[test]
    fn the_layer_only_paths_carry_no_wire_hash_additive_unchanged() {
        // ADDITIVE: the wave30/wave31 layer-only constructors never saw transported wire
        // bytes, so the wire content_hash is None on them — the LOCAL fingerprint and the
        // composed-doc surface are byte-identical to before this reconcile.
        let layer = pol1::parse_layer(COMMITTED_SNAPSHOT).expect("parses");
        let seqless = PolicySnapshot::from_policy_layer(&layer)
            .committed_policy()
            .cloned()
            .expect("committed");
        assert_eq!(seqless.wire_content_hash(), None);
        assert_eq!(seqless.identity().wire_content_hash(), None);

        let with_seq = PolicySnapshot::from_policy_layer_with_seq(&layer, 5)
            .committed_policy()
            .cloned()
            .expect("committed");
        assert_eq!(with_seq.wire_content_hash(), None);

        // The verified-bytes path is the ONLY one that carries a wire hash; its local
        // fingerprint + seq remain the SAME as the layer-only path (only the wire hash and
        // supplied seq differ), so the wave30 surface never moves.
        let hash = snapshot_verify::sha256(WIRE_DNS_PAYLOAD);
        let verified = PolicySnapshot::from_verified_bytes_and_layer(&layer, 5, hash)
            .committed_policy()
            .cloned()
            .expect("committed");
        assert_eq!(verified.wire_content_hash(), Some(hash));
        assert_eq!(verified.content_hash(), with_seq.content_hash());
        assert_eq!(verified.seq(), with_seq.seq());
        assert_eq!(verified.composed_layer(), with_seq.composed_layer());
        assert_eq!(verified.ttl_clamp(), with_seq.ttl_clamp());
        assert_eq!(verified.boundary_zone(), with_seq.boundary_zone());
    }

    // ── The produce-once / verify-only LOADER (doc 13 §5 identity row / §5.1, D72/D120) ──────
    //
    // `load_verified_snapshot` is the SINGLE call the `WatchPolicies` subscriber drives: hash the
    // transported bytes BEFORE parsing, NACK host-wide on a content_hash mismatch (never parse a
    // tampered transport), and on a verified hash parse ONCE + build a snapshot carrying the
    // VERIFIED wire hash on its identity. These pin that the hash check is provably before the
    // parse, that a NACK is operationally DISTINCT from a parse failure, and that a loaded snapshot
    // self-identifies on the full D72 tuple.

    /// A representative transported POL-1 snapshot document (a NEW committed version) — the bytes
    /// the produce-once Go host agent would fan out and hash exactly once. The loader hashes THESE
    /// transported bytes; it never re-serializes the parsed layer.
    const TRANSPORTED_SNAPSHOT: &[u8] = b"schema_version: pol1/v2\nlayer: session\n\
         posture: standard\nadmission:\n  ttl_floor: 30\n  ttl_ceil: 600\n\
         dns:\n  boundary_zone: loaded.example.\n";

    #[test]
    fn load_verified_snapshot_loads_a_self_identifying_snapshot_on_a_verified_hash() {
        // The produce-once / verify-only loop end to end: the Go producer hashed the transported
        // bytes EXACTLY ONCE; the loader hashes the SAME transported bytes (via the single source
        // of wire hashing), verifies, parses ONCE, and builds a snapshot self-identifying on the
        // FULL D72 identity — seq, the local fingerprint, AND the VERIFIED wire hash.
        let wire_hash = snapshot_verify::sha256(TRANSPORTED_SNAPSHOT);
        let seq = 11u64;
        let verdict = load_verified_snapshot(TRANSPORTED_SNAPSHOT, seq, &wire_hash);

        let snap = verdict
            .loaded()
            .expect("a verified+parsed transport loads a snapshot");
        assert!(!verdict.is_hash_nack(), "a verified hash is not a NACK");
        let committed = snap
            .committed_policy()
            .expect("a loaded snapshot is committed");

        // The full D72 identity rides the loaded snapshot: the supplied seq, the local fingerprint
        // of the parsed document, AND the verified D120 wire hash (the SAME 32 bytes the producer
        // hashed). The loader threaded the wire hash through `from_verified_bytes_and_layer`.
        assert_eq!(committed.seq(), seq);
        assert_eq!(committed.wire_content_hash(), Some(wire_hash));
        assert_eq!(committed.identity().wire_content_hash(), Some(wire_hash));

        // The loaded document is the parse of the transported bytes — equal to building from the
        // separately-parsed layer (the loader parses the verified bytes EXACTLY ONCE, no drift).
        let layer = pol1::parse_layer(std::str::from_utf8(TRANSPORTED_SNAPSHOT).expect("utf8"))
            .expect("parses");
        assert_eq!(committed.composed_layer(), &layer);
        assert_eq!(committed.boundary_zone(), "loaded.example.");
        assert_eq!(committed.content_hash(), content_hash_of_layer(&layer));
    }

    #[test]
    fn load_verified_snapshot_nacks_a_mutated_transport_host_wide_without_parsing() {
        // A byte-mutated transport: the recomputed hash does NOT match the producer's wire hash, so
        // the loader returns a HashNack carrying {expected, computed} and NEVER parses (the host
        // stays on vN). This is the D120 integrity rejection, DISTINCT from a parse failure.
        let producer_hash = snapshot_verify::sha256(TRANSPORTED_SNAPSHOT);
        let mut mutated = TRANSPORTED_SNAPSHOT.to_vec();
        *mutated.last_mut().expect("non-empty") ^= 0x20; // flip a byte in the transport

        let verdict = load_verified_snapshot(&mutated, 11, &producer_hash);
        assert!(
            verdict.is_hash_nack(),
            "a mutated transport NACKs on the wire hash"
        );
        assert!(
            verdict.loaded().is_none(),
            "a NACK never yields a committed snapshot"
        );
        match verdict {
            LoadVerdict::HashNack { expected, computed } => {
                assert_eq!(
                    expected, producer_hash,
                    "the NACK reports the producer's wire hash"
                );
                assert_ne!(
                    computed, producer_hash,
                    "the mutation changed the computed hash"
                );
            }
            other => panic!("expected a HashNack, got {other:?}"),
        }
    }

    #[test]
    fn load_verified_snapshot_distinguishes_a_schema_failure_from_a_hash_nack() {
        // A §5 "schema failure": bytes that verify against their OWN wire hash but FAIL the POL-1
        // parse. The loader returns ParseError (an integrity rejection, host stays on vN) — a
        // DISTINCT variant from a content_hash NACK, so an operator never conflates the two.
        let garbage: &[u8] = b"schema_version: not-a-real-schema\nthis: is not pol1\n";
        let wire_hash = snapshot_verify::sha256(garbage); // verifies (self-consistent), then fails parse
        let verdict = load_verified_snapshot(garbage, 12, &wire_hash);
        assert!(
            !verdict.is_hash_nack(),
            "a schema failure is not a hash NACK"
        );
        assert!(
            verdict.loaded().is_none(),
            "a parse failure never loads a snapshot"
        );
        assert!(
            matches!(verdict, LoadVerdict::ParseError(_)),
            "verified-but-unparseable bytes are a ParseError, distinct from a HashNack"
        );
    }

    #[test]
    fn loader_carries_the_same_identity_as_from_verified_bytes_and_layer() {
        // The loader is exactly: verify → parse-once → from_verified_bytes_and_layer. Pin that the
        // loaded snapshot is byte-identical to building from the separately-parsed layer with the
        // verified wire hash — the loader adds the hash-check-before-parse, nothing else.
        let wire_hash = snapshot_verify::sha256(TRANSPORTED_SNAPSHOT);
        let layer = pol1::parse_layer(std::str::from_utf8(TRANSPORTED_SNAPSHOT).expect("utf8"))
            .expect("parses");
        let direct = PolicySnapshot::from_verified_bytes_and_layer(&layer, 9, wire_hash);
        let loaded = load_verified_snapshot(TRANSPORTED_SNAPSHOT, 9, &wire_hash)
            .loaded()
            .cloned()
            .expect("loads");
        assert_eq!(
            loaded, direct,
            "the loader builds the from_verified_bytes_and_layer snapshot"
        );
    }

    fn dns_layer(zone: &str) -> pol1::DnsConfig {
        let doc = format!(
            "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
             dns:\n  boundary_zone: {zone}\n"
        );
        pol1::parse_layer(&doc).expect("clean layer parses").dns
    }

    fn dns_layer_no_dns() -> pol1::DnsConfig {
        pol1::parse_layer("schema_version: pol1/v0\nlayer: org\nposture: standard\n")
            .expect("clean layer parses")
            .dns
    }
}

#[cfg(test)]
mod revocation_tests {
    use super::*;
    use ds_contracts::flush::{DstFilter, FlushError, FlushOutcome, FlushSession, LegSelector};
    use ds_contracts::mark::Leg;
    use ds_contracts::session::SessionRef;
    use std::cell::Cell;

    // ── a synthetic clock (D50): logical milliseconds, no wall time ──────────
    //
    // POL-4 is a seconds-scale push-to-enforced bar (doc 13 §5). We model it on a
    // deterministic synthetic clock so "enforced within the bar" is an exact
    // assertion, not a flaky wall-time race: pushing the revocation is t=0, and
    // each per-session flush advances the clock by a modeled cost; the sweep
    // completing is the enforced instant.
    struct SyntheticClock {
        now_ms: Cell<u64>,
    }

    impl SyntheticClock {
        fn new() -> SyntheticClock {
            SyntheticClock {
                now_ms: Cell::new(0),
            }
        }
        fn now_ms(&self) -> u64 {
            self.now_ms.get()
        }
        fn advance(&self, ms: u64) {
            self.now_ms.set(self.now_ms.get() + ms);
        }
    }

    /// The POL-4 seconds-scale bar, in the synthetic clock's milliseconds.
    const POL4_BAR_MS: u64 = 5_000;
    /// Modeled per-session flush cost (recognize → conntrack destroy), synthetic.
    const PER_FLUSH_MS: u64 = 50;

    /// A recording [`FlushSession`] fake (the wave's synthetic-fixture rule, D50):
    /// it records every `(session, dst_filter, legs)` call, returns a fixed
    /// per-flush entry count, and ticks the synthetic clock so the POL-4 test can
    /// observe elapsed time deterministically. It depends on NOTHING beyond
    /// ds-contracts (keeping this crate's single-dependency posture), unlike the
    /// real `ds-nft` `NftWriter`.
    struct RecordingFlusher<'a> {
        clock: &'a SyntheticClock,
        entries_per_flush: u64,
        calls: Cell<usize>,
        last_filter_all: Cell<bool>,
        last_legs_sever_pair: Cell<bool>,
    }

    impl<'a> RecordingFlusher<'a> {
        fn new(clock: &'a SyntheticClock, entries_per_flush: u64) -> RecordingFlusher<'a> {
            RecordingFlusher {
                clock,
                entries_per_flush,
                calls: Cell::new(0),
                last_filter_all: Cell::new(false),
                last_legs_sever_pair: Cell::new(false),
            }
        }
    }

    #[derive(Debug)]
    struct NeverFails;
    impl FlushError for NeverFails {}

    impl FlushSession for RecordingFlusher<'_> {
        type Error = NeverFails;
        fn flush_session(
            &self,
            _session: &SessionRef,
            dst_filter: &DstFilter,
            legs: &LegSelector,
        ) -> Result<FlushOutcome, Self::Error> {
            self.calls.set(self.calls.get() + 1);
            self.last_filter_all
                .set(matches!(dst_filter, DstFilter::All));
            self.last_legs_sever_pair
                .set(legs == &LegSelector::sever_pair());
            self.clock.advance(PER_FLUSH_MS);
            Ok(FlushOutcome {
                entries_flushed: self.entries_per_flush,
            })
        }
    }

    fn session(idx: u32) -> SessionRef {
        SessionRef::new(
            "11111111-2222-3333-4444-555555555555".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    #[test]
    fn severing_predicate_is_the_shared_block_or_higher_rung_gate() {
        // block+log and above sever established flows; allow+log gates new flows only
        // (expiry-is-not-revocation: a TTL lapse never produces an entry at all).
        assert!(FleetRevocationEntry::new("fp", Rung::BlockLog).severs_established_flows());
        assert!(FleetRevocationEntry::new("fp", Rung::SuspendAsk).severs_established_flows());
        assert!(FleetRevocationEntry::new("fp", Rung::KillSnapshot).severs_established_flows());
        assert!(!FleetRevocationEntry::new("fp", Rung::AllowLog).severs_established_flows());
        // …and it is exactly the shared ds-contracts threshold, so this consumer and
        // the NFT programmer can never diverge on the block-or-higher line.
        for rung in [
            Rung::AllowLog,
            Rung::BlockLog,
            Rung::SuspendAsk,
            Rung::KillSnapshot,
        ] {
            assert_eq!(
                FleetRevocationEntry::new("fp", rung).severs_established_flows(),
                rung.is_block_or_higher()
            );
        }
    }

    #[test]
    fn below_block_rung_severs_nothing_but_is_still_counted() {
        let clock = SyntheticClock::new();
        let flusher = RecordingFlusher::new(&clock, 3);
        let entries = vec![FleetRevocationEntry::new("fp-allowlog", Rung::AllowLog)];
        // Even though the fingerprint resolves to a live session, an allow+log rung
        // does NOT sever it.
        let sweep =
            sweep_fleet_revocations(&flusher, &entries, |_| vec![session(7)]).expect("sweep");
        assert_eq!(sweep.entries_seen, 1);
        assert_eq!(sweep.rung_skipped, 1);
        assert_eq!(sweep.sessions_severed, 0);
        assert_eq!(sweep.entries_flushed, 0);
        assert_eq!(flusher.calls.get(), 0, "no flush for a below-block rung");
    }

    #[test]
    fn severing_entry_flushes_every_resolved_session_with_all_dst_and_sever_pair_legs() {
        let clock = SyntheticClock::new();
        let flusher = RecordingFlusher::new(&clock, 2);
        let entries = vec![FleetRevocationEntry::new("fp-stolen", Rung::KillSnapshot)];
        // The stolen token was admitted on two sessions on this host.
        let sweep = sweep_fleet_revocations(&flusher, &entries, |fp| {
            assert_eq!(fp, "fp-stolen");
            vec![session(7), session(8)]
        })
        .expect("sweep");
        assert_eq!(sweep.sessions_severed, 2);
        assert_eq!(sweep.entries_flushed, 4); // 2 sessions × 2 entries each
        assert_eq!(flusher.calls.get(), 2);
        // A token revocation drops the WHOLE session (every destination) on the
        // agent-VM + ds-tlsproxy-upstream leg pair — flush_session called exactly
        // as the shared primitive expects, unmodified.
        assert!(
            flusher.last_filter_all.get(),
            "DstFilter::All for a token revocation"
        );
        assert!(
            flusher.last_legs_sever_pair.get(),
            "LegSelector::sever_pair() legs (0x1 + 0x2)"
        );
    }

    /// A REAL admission book (not an injected closure) — a fingerprint→sessions registry the
    /// serving loop's admission path records into. The object-safe [`SessionAdmissionBook`] the
    /// live loop passes to [`sweep_fleet_revocations_with_book`].
    #[derive(Default)]
    struct MapAdmissionBook {
        by_fingerprint: std::collections::HashMap<String, Vec<SessionRef>>,
    }
    impl MapAdmissionBook {
        fn record(&mut self, fingerprint: &str, session: SessionRef) {
            self.by_fingerprint
                .entry(fingerprint.to_string())
                .or_default()
                .push(session);
        }
    }
    impl SessionAdmissionBook for MapAdmissionBook {
        fn sessions_for_fingerprint(&self, fingerprint: &str) -> Vec<SessionRef> {
            self.by_fingerprint
                .get(fingerprint)
                .cloned()
                .unwrap_or_default()
        }
    }

    #[test]
    fn book_backed_sweep_severs_the_sessions_the_real_admission_book_resolves() {
        // The object-safe entry the live serving loop drives: it passes a REAL admission book
        // (a `&dyn SessionAdmissionBook`), NOT an injected test closure. The result is identical
        // to the closure form — the book's two sessions for the revoked fingerprint are severed
        // through the SAME flush_session shape.
        let clock = SyntheticClock::new();
        let flusher = RecordingFlusher::new(&clock, 2);
        let mut book = MapAdmissionBook::default();
        book.record("fp-stolen", session(7));
        book.record("fp-stolen", session(8));
        book.record("fp-other", session(9));

        let entries = vec![FleetRevocationEntry::new("fp-stolen", Rung::KillSnapshot)];
        let sweep = sweep_fleet_revocations_with_book(&flusher, &entries, &book).expect("sweep");
        assert_eq!(sweep.sessions_severed, 2, "only fp-stolen's two sessions");
        assert_eq!(sweep.entries_flushed, 4); // 2 sessions × 2 entries each
        assert_eq!(flusher.calls.get(), 2);
        assert!(flusher.last_filter_all.get(), "DstFilter::All");
        assert!(flusher.last_legs_sever_pair.get(), "sever_pair legs");
    }

    #[test]
    fn book_backed_sweep_of_an_unknown_fingerprint_severs_nothing() {
        // A revoked token this host admitted nothing under resolves to no sessions — a no-op
        // sever, the sweep still completes so the caller advances applied_seq.
        let clock = SyntheticClock::new();
        let flusher = RecordingFlusher::new(&clock, 2);
        let book = MapAdmissionBook::default();
        let entries = vec![FleetRevocationEntry::new(
            "fp-never-admitted",
            Rung::KillSnapshot,
        )];
        let sweep = sweep_fleet_revocations_with_book(&flusher, &entries, &book).expect("sweep");
        assert_eq!(sweep.entries_seen, 1);
        assert_eq!(sweep.sessions_severed, 0);
        assert_eq!(flusher.calls.get(), 0, "nothing to sever");
    }

    #[test]
    fn pol4_synthetic_clock_pushed_revocation_is_enforced_within_the_bar_with_sweep_plus_flush() {
        // The POL-4 assurance row (doc 19 §13, "fleet-revocation-clock"): a pushed
        // token-revocation entry is enforced fleet-wide inside the seconds-scale bar,
        // INCLUDING the sweep-plus-flush. Modeled end-to-end over fakes on a synthetic
        // clock so the timing assertion is deterministic.
        let clock = SyntheticClock::new();
        let flusher = RecordingFlusher::new(&clock, 5);

        // t=0: the revocation lands on the policy_log subscriber.
        let pushed_at = clock.now_ms();
        assert_eq!(pushed_at, 0);

        // A block-or-higher fleet revocation of a stolen token, admitted on three
        // sessions across this host.
        let entries = vec![FleetRevocationEntry::new(
            "fp-emergency",
            Rung::KillSnapshot,
        )];
        let sweep = sweep_fleet_revocations(&flusher, &entries, |_| {
            vec![session(1), session(2), session(3)]
        })
        .expect("sweep");

        // Enforced == the sweep-plus-flush completed.
        let enforced_at = clock.now_ms();
        let latency = enforced_at - pushed_at;

        // (1) Sweep-plus-flush was actually OBSERVED (not a silent no-op): three
        //     sessions severed, conntrack entries destroyed.
        assert_eq!(sweep.sessions_severed, 3, "all three flows severed");
        assert_eq!(
            sweep.entries_flushed, 15,
            "conntrack destroys observed (3×5)"
        );
        assert_eq!(flusher.calls.get(), 3);

        // (2) …and enforcement happened INSIDE the POL-4 seconds-scale bar.
        assert!(
            latency <= POL4_BAR_MS,
            "push→enforce latency {latency}ms exceeded the POL-4 bar {POL4_BAR_MS}ms"
        );
        // Sanity: the clock did advance (the flush cost is real, not skipped).
        assert!(latency > 0, "sweep must consume synthetic time");
    }

    #[test]
    fn sever_pair_legs_are_the_agent_and_tlsproxy_nibbles() {
        // Guard the leg-pair identity this sweep passes to flush_session.
        assert_eq!(
            LegSelector::sever_pair(),
            LegSelector::Some(vec![Leg::AgentVm, Leg::TlsproxyUpstream])
        );
    }

    // ── decode-driven LIVE sweep over the on-wire ds.fleet_revocation.v1 artifact ──────
    //
    // These drive `decode_fleet_revocation_v1` through the production `sweep_fleet_revocation_v1`
    // caller — the wiring that makes the golden-coupled recognizer the datapath decode step in
    // front of the sever, not a golden-test-only reader. The revoked-token ids are the golden's
    // (a 32-hex block id + a 64-hex fingerprint), both mapped onto the resolver key set.

    /// The two revoked-token ids the golden `ds.fleet_revocation.v1` payload names.
    const GOLDEN_BLOCK_ID_KEY: &str = "0123456789abcdef0123456789abcdef";
    const GOLDEN_FINGERPRINT_KEY: &str =
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn fleet_revocation_entries_from_v1_maps_the_golden_id_set() {
        // The decode-then-map step produces one rung-tagged entry per revoked id, keyed by
        // the SAME lower-hex id the envelope carried (block-id first — sorted encoded-form
        // order), never token bytes.
        let entries = fleet_revocation_entries_from_v1(GOLDEN_REVOCATION_V1, Rung::KillSnapshot)
            .expect("the golden decodes into rung-tagged entries");
        let ids: Vec<&str> = entries.iter().map(|e| e.fingerprint.as_str()).collect();
        assert_eq!(ids, vec![GOLDEN_BLOCK_ID_KEY, GOLDEN_FINGERPRINT_KEY]);
        for e in &entries {
            assert_eq!(e.rung, Rung::KillSnapshot);
            assert!(e.severs_established_flows());
        }
    }

    #[test]
    fn sweep_fleet_revocation_v1_decodes_then_severs_the_resolved_sessions() {
        // The live path end to end: raw artifact bytes → decode → the {fingerprint, block-id}
        // id set → rung-conditional sever against a REAL admission book. The host admitted one
        // session under EACH revoked id the golden names; both are severed through the shared
        // flush_session shape.
        let clock = SyntheticClock::new();
        let flusher = RecordingFlusher::new(&clock, 2);
        let mut book = MapAdmissionBook::default();
        book.record(GOLDEN_BLOCK_ID_KEY, session(7));
        book.record(GOLDEN_FINGERPRINT_KEY, session(8));
        book.record("fp-other", session(9));

        let sweep =
            sweep_fleet_revocation_v1(&flusher, GOLDEN_REVOCATION_V1, Rung::KillSnapshot, &book)
                .expect("the golden artifact sweeps");

        assert_eq!(sweep.entries_seen, 2, "both golden ids recognized");
        assert_eq!(sweep.sessions_severed, 2, "one session per revoked id");
        assert_eq!(sweep.entries_flushed, 4); // 2 sessions × 2 entries each
        assert_eq!(flusher.calls.get(), 2);
        assert!(flusher.last_filter_all.get(), "DstFilter::All");
        assert!(flusher.last_legs_sever_pair.get(), "sever_pair legs");
    }

    #[test]
    fn sweep_fleet_revocation_v1_below_block_rung_severs_nothing() {
        // The rung the composed-document context supplies gates severing: an allow+log
        // revocation is decoded + counted but severs no established flow.
        let clock = SyntheticClock::new();
        let flusher = RecordingFlusher::new(&clock, 2);
        let mut book = MapAdmissionBook::default();
        book.record(GOLDEN_BLOCK_ID_KEY, session(7));
        book.record(GOLDEN_FINGERPRINT_KEY, session(8));

        let sweep =
            sweep_fleet_revocation_v1(&flusher, GOLDEN_REVOCATION_V1, Rung::AllowLog, &book)
                .expect("decodes");
        assert_eq!(sweep.entries_seen, 2);
        assert_eq!(sweep.rung_skipped, 2);
        assert_eq!(sweep.sessions_severed, 0);
        assert_eq!(flusher.calls.get(), 0, "below-block rung severs nothing");
    }

    #[test]
    fn sweep_fleet_revocation_v1_fails_closed_on_a_malformed_artifact() {
        // A raw-token smuggle on an entry line fails the decode (non-hex id), so the whole
        // sweep fails closed with `Malformed` and severs NOTHING — the data-plane twin of the
        // Go decoder returning ok == false.
        let clock = SyntheticClock::new();
        let flusher = RecordingFlusher::new(&clock, 2);
        let mut book = MapAdmissionBook::default();
        book.record(GOLDEN_BLOCK_ID_KEY, session(7));
        let malformed = b"ds.fleet_revocation.v1\n\
schema=fleet-revocation/v1\n\
batch=b\n\
entries=1\n\
e=f:this-is-a-raw-token-not-a-hex-fingerprint\n";

        let err = sweep_fleet_revocation_v1(&flusher, malformed, Rung::KillSnapshot, &book)
            .expect_err("a malformed artifact must fail closed");
        assert!(matches!(err, EncodedRevocationSweepError::Malformed));
        assert_eq!(flusher.calls.get(), 0, "fail-closed severs nothing");
    }
}
