//! The §8.3 insert-then-answer admission transaction (W1–W4; D68; doc 11 §3.1).
//!
//! On an `Allow` verdict the handler resolves the original query name upstream
//! (CNAME chain followed internally) and lands here with the *terminal* resolved
//! addresses and the chain-minimum upstream TTL. This module performs, in order:
//!
//!  1. **DNS-4 sanity filter** (W5): a pure scrub of the terminal addresses that
//!     rejects martians / unplumbable ranges (RFC1918, loopback, link-local,
//!     CGNAT, the unspecified and multicast/reserved blocks, and the v6
//!     equivalents incl. the IPv4-mapped unwrap). A `normal` admission that
//!     resolves entirely to scrubbed addresses is refused — no IP that cannot be
//!     plumbed is ever admitted or answered (doc 11 §3.1/W5).
//!  2. **Shared deadline** (W2): the ONE deadline written to both stores,
//!     `compose_deadline(answer_time, chain_min_ttl, FLOOR, CEIL, GRACE)` from
//!     [`ds_contracts::dns_admission`]. FLOOR/CEIL ride the verdict's frozen
//!     `Admit` (POL-1 `ttl_floor`/`ttl_ceil`); GRACE is the POL-1 `admission.grace`
//!     field threaded from the snapshot — NEVER a code constant. The VM is
//!     answered the clamp WITHOUT grace (`clamped_ttl`); the deadline carries the
//!     grace.
//!  3. **Atomic, fail-closed two-store write** (W1): the NFT-3 per-session set
//!     insert (the [`NftSetProgrammer`] surface, the abstract shape of `ds-nft`'s
//!     `NftWriter::apply_batch` / `refresh_batch`) AND the DNS-2b
//!     `AdmissionKey -> AdmissionEntry` map write (the frozen
//!     [`ds_contracts::dns_admission::AdmissionMap`]) AND the
//!     [`LiveAdmission`](crate::server::LiveAdmission) record, all keyed on the
//!     **original query name** (W3). Insert-then-answer: both stores are visible
//!     before the answer leaves. Any set-programming OR map failure yields
//!     `SERVFAIL` with **zero residue** — no map entry, no kernel element, no live
//!     admission, never an unplumbed IP. The two stores are SEQUENCED (set first,
//!     then map, then live-record) with compensating rollback, never fired in
//!     parallel (doc 11 §8.3 step 4).
//!  4. **Answer** the VM the clamped TTL (no grace).
//!
//! **Refresh** (W4): a re-resolution of a live name extends the deadline in both
//! stores via [`AdmissionEntry::refreshed_deadline`] — `max(existing, new)`, never
//! shortened. `is_expired_at` gates NEW flows only; it never severs an in-flight
//! flow (expiry is not revocation, W4).
//!
//! **Two-store lockstep is a security property** (doc 11 W2): TLS-1's
//! expired-admission refusal depends on the kernel element and the map entry
//! agreeing on one deadline. The deadline is computed ONCE here and handed to both
//! stores verbatim — neither recomputes a timer.
//!
//! # D67 boundary discipline / file-grant honesty
//!
//! This module speaks ONLY the family-agnostic frozen contract types
//! ([`ds_contracts::dns_admission`], [`ds_contracts::flush`],
//! [`ds_contracts::mark`]) and `std` — no hickory type crosses into it (the
//! handler destructures the resolved records into `std::net::IpAddr` + a `u32`
//! TTL at the call boundary). The **NFT-3 programming surface is consumed as a
//! trait** ([`NftSetProgrammer`]) whose shape is the `ds-nft`
//! `NftBackend::apply_batch` contract (program a per-session set element carrying
//! the W2 deadline; fail closed on a backend error). The production binding of
//! that trait onto `ds-nft`'s `NftWriter` NOW LANDS in this module (the workspace-
//! internal `ds-nft` path-dep + `impl NftSetProgrammer for ds_nft::NftWriter<B>`):
//! `program` renders the `add element … timeout Ns` batch via
//! `ds_nft::refresh::refresh_batch` (the W2 deadline riding the element timeout)
//! and applies it through `NftWriter::backend().apply_batch` (an `Err` is the
//! fail-closed W1 signal); `withdraw` applies the compensating `delete element`
//! batch. It is selected ONLY behind `DS_NFTGATE_LIVE` (default OFF): the in-memory
//! [`RecordingSetProgrammer`] stays the default and drives the SAME reportable path
//! the `ds-nft` recording backend exposes, so the lockstep / fail-closed / refresh
//! invariants are all sandbox-verifiable with no live kernel (the discipline doc 11
//! §8.3 and the `ds-nft` `RecordingBackend` both mandate). The honest RESIDUAL seam
//! is now the live-PATH wiring through the handler: `handler.rs`'s `admission` field
//! is monomorphic `AdmissionStores<RecordingSetProgrammer>` (a frozen, not-owned
//! seam), so the production `NftWriter` programmer rides
//! [`AdmissionStores::with_parts`] (the seam that already accepts an
//! `Arc<S: NftSetProgrammer>`) but cannot replace the handler-held store until that
//! field is made generic. The structure, the FIELD-FOR-FIELD `SetInsert` →
//! `RefreshRequest` map, and every invariant are real and tested; the live kernel
//! write is `DS_NFTGATE_LIVE`-gated and CI/manual-only.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};

use ds_contracts::dns_admission::{
    compose_deadline, AddressFamily, AdmissionEntry, AdmissionError, AdmissionKey, AdmissionMap,
    AdmissionType, AdmittedAddr, Instant, Provenance, ReverseIndex,
};
use ds_contracts::mark::{compose, Leg, DS_MARK_MASK};
use ds_contracts::session::{allow_set_name, SessionRef};

use crate::server::{FleetRevocationBook, LiveAdmission, LiveAdmissions};

/// One NFT-3 set-element insert leg the transaction programs: the per-session
/// `(leg, session_index)` mark identity, the set the element lives in, the element
/// value (the admitted destination), and the W2 deadline as a whole-second
/// timeout.
///
/// This is the family-agnostic, hickory-free shape the [`NftSetProgrammer`]
/// consumes; it mirrors `ds-nft`'s `refresh::RefreshRequest` field-for-field in
/// intent (set name + masked mark + opaque element + clamped timeout) without
/// binding the `ds-nft` type (file-grant boundary). The mark is composed from
/// [`ds_contracts::mark`] under [`DS_MARK_MASK`] — never a raw literal — so a
/// bare-index match can never fire (the same discipline `ds-nft`'s `MarkMatch`
/// enforces).
///
/// The production `impl NftSetProgrammer for ds_nft::NftWriter<B>` maps this struct
/// onto the `ds-nft` programming surface field-for-field: `program(insert)` builds a
/// `ds_nft::refresh::RefreshRequest { set_name, mark, element, timeout_secs }` where
/// `mark` is the `ds_nft::mark_match::MarkMatch` recovered from
/// [`SetInsert::mark_value`] via `ds_contracts::mark::decompose` →
/// `MarkMatch::for_leg(leg, session_index)` (the strict inverse of the `compose`
/// the txn ran, so the round-trip is byte-exact — the leg/index ride the value, never
/// re-derived from session data), renders the `add element … timeout {timeout_secs}s`
/// batch via `ds_nft::refresh::refresh_batch(strategy, &req)` (the W2 deadline rides
/// [`SetInsert::timeout_secs`] as the kernel element's `timeout Ns`), and applies
/// it through `NftWriter::backend().apply_batch(&batch)` (`Err` → fail-closed W1);
/// `withdraw(insert)` applies the compensating `delete element` batch. The masked
/// [`SetInsert::value_mask_token`] equals `MarkMatch::to_value_mask_token`
/// byte-exact, and [`SetInsert::element`] is the [`AdmittedAddr::to_dst_key`] form,
/// so a later `flush_session` `DstFilter::Only` agrees on both keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetInsert {
    /// The PER-SESSION set the element lives in — `allow4_<idx>` for v4 / synthetic,
    /// `allow6_<idx>` dormant — the single-source `ds_contracts::session::allow_set_name`
    /// name keyed on the `host_session_index` (D3/D4). Authored by the caller — the
    /// programmer never invents set names.
    pub set_name: String,
    /// The composed `(magic ∪ leg ∪ index)` mark value, masked-by-construction.
    pub mark_value: u32,
    /// The frozen [`DS_MARK_MASK`] the match is applied under — carried so the
    /// element is never programmed with a bare value (security invariant).
    pub mark_mask: u32,
    /// The element value as the set stores it — the canonical
    /// [`AdmittedAddr::to_dst_key`] textual form, so the element key, the reverse
    /// index, and a later `flush_session` `DstFilter::Only` all agree byte-exact.
    pub element: String,
    /// The W2 deadline expressed as a whole-second timeout (the kernel element's
    /// `timeout Ns`). Carried alongside [`SetInsert::deadline`] so a programmer can
    /// emit either an absolute or a relative kernel timeout; the two describe the
    /// SAME instant.
    pub timeout_secs: u32,
    /// The W2 shared deadline as an absolute [`Instant`] — the SAME value written
    /// to the map entry's `expires_at`. The whole point of the lockstep: this
    /// instant is computed once and handed to both stores.
    pub deadline: Instant,
}

impl SetInsert {
    /// The `value/mask` token an `nft` expression / a `conntrack -D --mark`
    /// argument consumes — the lower-case-hex composed value over
    /// [`DS_MARK_MASK`]. The identical rendering `ds-nft`'s
    /// `MarkMatch::to_value_mask_token` produces, so the kernel-side identity is
    /// stable across the seam.
    pub fn value_mask_token(&self) -> String {
        format!("0x{:x}/0x{:x}", self.mark_value, self.mark_mask)
    }
}

/// The NFT-3 per-session set-programming surface, consumed (not owned) by the
/// admission transaction.
///
/// This is the abstract shape of `ds-nft`'s programming path: `program` makes a
/// set element visible carrying the W2 deadline (the `add element … timeout Ns`
/// batch `ds-nft`'s `refresh_batch` emits and `NftBackend::apply_batch` applies),
/// and `withdraw` removes it (the compensating delete the fail-closed rollback
/// fires). A success means the element is **observed-committed** before the caller
/// proceeds (insert-then-answer ordering, doc 11 §8.3 step 2); an `Err` is the
/// fail-closed signal (W1) — the caller withholds the answer and rolls back.
///
/// `&self` interior mutability mirrors `ds-nft`'s `RecordingBackend` /
/// `SpawnBackend`, both of which are genuinely `&self` (they spawn processes /
/// accumulate a call log), so the trait stays shared-ref and the handler can hold
/// the programmer behind a shared handle without distorting the production
/// signature.
pub trait NftSetProgrammer {
    /// Program (insert or in-place refresh) one NFT-3 set element carrying the W2
    /// deadline. Must be observed-committed on `Ok`. On `Err` the element is NOT
    /// visible (fail-closed) and the caller withholds the answer.
    fn program(&self, insert: &SetInsert) -> Result<(), AdmissionError>;

    /// Withdraw a previously-programmed element — the compensating action the
    /// fail-closed rollback fires when a LATER leg of the same transaction fails,
    /// so no half-written kernel element survives (W1 zero residue). Idempotent:
    /// withdrawing an absent element is a no-op success.
    fn withdraw(&self, insert: &SetInsert) -> Result<(), AdmissionError>;
}

/// An in-memory recording [`NftSetProgrammer`] — the sandbox-verifiable path
/// (loopback/synthetic only; no live kernel write), the exact role `ds-nft`'s
/// `RecordingBackend` plays for the flush/refresh batches.
///
/// It records every program/withdraw in order, and can arm a one-shot failure to
/// drive the W1 fail-closed path (the same `RecordingBackend::arm_error` shape).
/// `committed()` reports the elements currently live (programmed minus withdrawn),
/// so a test can assert ZERO residue after a fail-closed transaction.
#[derive(Debug, Default)]
pub struct RecordingSetProgrammer {
    programmed: std::sync::Mutex<Vec<SetInsert>>,
    withdrawn: std::sync::Mutex<Vec<SetInsert>>,
    /// If set, the next `program` call returns this error (one-shot) — the
    /// fail-closed lever.
    next_error: std::sync::Mutex<Option<AdmissionError>>,
}

impl RecordingSetProgrammer {
    /// A fresh recording programmer with no armed error.
    pub fn new() -> Self {
        Self::default()
    }

    /// Arm a one-shot failure for the next `program` call (the W1 fail-closed
    /// lever — mirrors `ds-nft`'s `RecordingBackend::arm_error`).
    pub fn arm_error(&self, err: AdmissionError) {
        *self.next_error.lock().expect("set-programmer lock") = Some(err);
    }

    /// The set elements PROGRAMMED so far, in order (includes any later
    /// withdrawn).
    pub fn programmed(&self) -> Vec<SetInsert> {
        self.programmed.lock().expect("set-programmer lock").clone()
    }

    /// The set elements WITHDRAWN so far (the rollback compensations).
    pub fn withdrawn(&self) -> Vec<SetInsert> {
        self.withdrawn.lock().expect("set-programmer lock").clone()
    }

    /// The elements currently LIVE in the kernel model: programmed minus
    /// withdrawn (matched on the full [`SetInsert`]). After a fail-closed
    /// transaction this MUST be empty for every element the transaction touched —
    /// the W1 zero-residue assertion.
    pub fn committed(&self) -> Vec<SetInsert> {
        let withdrawn = self.withdrawn();
        self.programmed()
            .into_iter()
            .filter(|p| !withdrawn.contains(p))
            .collect()
    }
}

impl NftSetProgrammer for RecordingSetProgrammer {
    fn program(&self, insert: &SetInsert) -> Result<(), AdmissionError> {
        if let Some(err) = self.next_error.lock().expect("set-programmer lock").take() {
            return Err(err);
        }
        self.programmed
            .lock()
            .expect("set-programmer lock")
            .push(insert.clone());
        Ok(())
    }

    fn withdraw(&self, insert: &SetInsert) -> Result<(), AdmissionError> {
        self.withdrawn
            .lock()
            .expect("set-programmer lock")
            .push(insert.clone());
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The PRODUCTION NftSetProgrammer binding: `impl NftSetProgrammer for
// ds_nft::NftWriter<B>` — the kernel-write seam wave35-37 deferred (the one-line
// Cargo.toml ds-nft path-dep + this adapter). LOOPBACK/SYNTHETIC DEFAULT: this is
// selected ONLY behind `DS_NFTGATE_LIVE` (default OFF → the reportable
// `RecordingSetProgrammer` above stays the default); the SANDBOX/CI kernel has no
// nf_conntrack + restricted netlink, so a REAL `SpawnBackend` write is a
// CI/manual-only `#[ignore]`/env-gated test, never on the `cargo test --offline`
// path. The adapter maps `SetInsert` FIELD-FOR-FIELD onto the ds-nft program path,
// never re-deriving the byte-exact key agreement the wave35-37 reports established.
// ─────────────────────────────────────────────────────────────────────────────

/// The whole `inet ds_filter` table the per-session NFT-3 sets live under — the
/// SAME table `ds_nft::refresh::refresh_batch` names its `add element` / `delete
/// element` ops against (private `const TABLE = "inet ds_filter"` there, doc 14
/// §6). ds-nft exports no standalone `delete element` batch helper (only the
/// `refresh_batch` DeleteAdd embeds it) and is READ-ONLY for this wave, so the
/// compensating-withdraw batch is rendered HERE in the SAME shape DeleteAdd embeds;
/// this const is the one honest duplication — named so the withdraw batch and a
/// later ds-nft `refresh_batch` insert agree on the table byte-exact.
const NFT_FILTER_TABLE: &str = "inet ds_filter";

/// Recover the `(leg, host_session_index)` the txn composed `insert.mark_value`
/// from, and rebuild the ds-nft [`ds_nft::mark_match::MarkMatch`] from them — the
/// FIELD-FOR-FIELD carry of the masked mark the wave35-37 contract projection
/// pinned. `decompose` is the strict inverse of the `compose` the transaction ran,
/// and `MarkMatch::for_leg` re-composes the SAME value, so the round-trip is
/// byte-exact (`MarkMatch::value() == insert.mark_value`,
/// `to_value_mask_token() == insert.value_mask_token()`); the adapter NEVER
/// re-derives the mark from session data. A `mark_value` that is not a DS mark
/// (cannot happen — the txn composes it under [`DS_MARK_MASK`]) fails closed (W1).
fn mark_match_of(insert: &SetInsert) -> Result<ds_nft::mark_match::MarkMatch, AdmissionError> {
    let parts = ds_contracts::mark::decompose(insert.mark_value)
        .map_err(|_| AdmissionError::SetProgrammingFailed)?;
    Ok(ds_nft::mark_match::MarkMatch::for_leg(
        parts.leg,
        u32::from(parts.session_index),
    ))
}

/// Build the ds-nft [`ds_nft::refresh::RefreshRequest`] one [`SetInsert`] maps to —
/// the set name, the recovered masked mark, the [`AdmittedAddr::to_dst_key`]
/// element, and the W2 deadline as the kernel element's whole-second `timeout Ns`.
/// FIELD-FOR-FIELD: `set_name` ← `insert.set_name`, `mark` ← the round-trip of
/// `insert.mark_value`, `element` ← `insert.element`, `timeout_secs` ←
/// `insert.timeout_secs` (the W2 deadline the kernel element carries; never
/// recomputed here — doc 11 §8.3 step 1).
fn refresh_request_of(
    insert: &SetInsert,
) -> Result<ds_nft::refresh::RefreshRequest, AdmissionError> {
    Ok(ds_nft::refresh::RefreshRequest {
        set_name: insert.set_name.clone(),
        mark: mark_match_of(insert)?,
        element: insert.element.clone(),
        timeout_secs: insert.timeout_secs,
    })
}

/// Render the compensating `delete element` batch for one programmed [`SetInsert`]
/// — the SAME `delete element {table} {set} {{ {elem} }}` shape
/// `ds_nft::refresh::refresh_batch`'s DeleteAdd fallback embeds (ds-nft is
/// READ-ONLY and exports no standalone delete helper, so the batch text is built
/// here against [`NFT_FILTER_TABLE`]). Idempotent at the kernel: deleting an absent
/// element is a no-op (the W1 rollback's zero-residue compensation).
///
/// The element renders to the nft-accepted address literal (`DstKey::address_literal`),
/// MATCHING what `refresh_batch`'s DeleteAdd boundary now emits — `nft` rejects the
/// frozen `v4:<hex>` `to_dst_key` identity outright (`syntax error`), so a raw-hex
/// `delete element` fails closed and the rollback would leave a stale allow-set
/// element until its W2 timeout. The in-memory `insert.element` stays the frozen hex.
fn delete_element_batch(insert: &SetInsert) -> ds_nft::backend::NftBatch {
    let elem = ds_contracts::flush::DstKey(insert.element.clone()).address_literal();
    ds_nft::backend::NftBatch::new(format!(
        "delete element {table} {set} {{ {elem} }}\n",
        table = NFT_FILTER_TABLE,
        set = insert.set_name,
    ))
}

/// The PRODUCTION [`NftSetProgrammer`]: bind `ds_nft::NftWriter<B>` (the ONE
/// nft/netlink writer, doc 14 §6) as the W1 set programmer. `program` renders the
/// `add element … timeout Ns` batch via `ds_nft::refresh::refresh_batch` (the W2
/// deadline riding `RefreshRequest::timeout_secs`) and applies it through
/// `NftWriter::backend().apply_batch` — an `Err` is the fail-closed W1 signal;
/// `withdraw` applies the compensating `delete element` batch (the rollback's
/// zero-residue compensation). The kernel refresh STRATEGY is probed LIVE per
/// apply (`KernelProbe::Live` over `uname -r`, falling back to the conservative
/// `DeleteAdd` when the version is unreadable — never assume the in-place fast
/// path) so a ≥6.12 host takes the in-place element-timeout update and a pre-6.12
/// host takes the delete+add-in-one-batch fallback, the SAME D68 boundary ds-nft's
/// own `refresh_batch` honours. Selected ONLY behind `DS_NFTGATE_LIVE`; the default
/// loopback path keeps the reportable [`RecordingSetProgrammer`].
impl<B: ds_nft::backend::NftBackend> NftSetProgrammer for ds_nft::NftWriter<B> {
    fn program(&self, insert: &SetInsert) -> Result<(), AdmissionError> {
        let req = refresh_request_of(insert)?;
        // Probe the live kernel for the refresh strategy (D68 boundary at 6.12),
        // fail-safe to the delete+add fallback when the version is unreadable —
        // never assume the in-place fast path on an unknown kernel.
        let strategy = ds_nft::refresh::KernelProbe::Live.resolve(&live_uname_release());
        let batch = ds_nft::refresh::refresh_batch(strategy, &req);
        self.backend()
            .apply_batch(&batch)
            .map_err(|_| AdmissionError::SetProgrammingFailed)
    }

    fn withdraw(&self, insert: &SetInsert) -> Result<(), AdmissionError> {
        let batch = delete_element_batch(insert);
        self.backend()
            .apply_batch(&batch)
            .map_err(|_| AdmissionError::SetProgrammingFailed)
    }
}

/// The live `uname -r` kernel release the [`ds_nft::refresh::KernelProbe::Live`]
/// strategy probe reads — spawned once per program apply on the live path. Returns
/// an empty string when `uname` cannot be run (the probe then conservatively falls
/// back to the delete+add path), so the production binding never panics on a host
/// without `uname`. NOT on the offline/CI path — the reportable programmer is the
/// default, and the live-kernel test forces the strategy directly.
fn live_uname_release() -> String {
    std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default()
}

/// The inputs the handler hands the transaction once an `Allow` has resolved.
///
/// All hickory types are destructured away before this is built (the handler owns
/// the `Record` → `IpAddr` + `u32` projection): `terminal_addrs` are the resolved
/// terminal A/AAAA addresses (post-CNAME-chase), `chain_min_ttl` is the
/// chain-minimum upstream TTL the W2 clamp consumes.
#[derive(Clone, Debug)]
pub struct AdmissionInputs {
    /// The attributed session UUID (doc 11 §5.1) — one third of the DNS-2b map key
    /// and the NFT-3 set's per-session mark identity.
    pub session_uuid: String,
    /// The host-local session index that composes the NFT-3 element mark
    /// (`compose(leg, index)`); the disambiguator within the session (doc 11 §5.1
    /// / D76). Reduced `mod 2^14` by `compose`.
    pub session_index: u32,
    /// The **original query FQDN** the guest asked (pre-CNAME-chase), lower-cased
    /// trailing-dot form — the W3 admission key. NEVER an intermediate CNAME
    /// target.
    pub original_query_fqdn: String,
    /// The resolved TERMINAL addresses (post-CNAME-chase), exactly as the handler
    /// extracted them from the answer records. The DNS-4 filter scrubs these.
    pub terminal_addrs: Vec<IpAddr>,
    /// The chain-minimum upstream TTL (seconds) the W2 clamp consumes.
    pub chain_min_ttl: u32,
    /// The W2 clamp FLOOR (seconds) — the verdict's frozen `Admit.ttl_floor`
    /// (POL-1 `ttl_floor`), threaded in; NEVER hardcoded.
    pub ttl_floor: u32,
    /// The W2 clamp CEIL (seconds) — the verdict's frozen `Admit.ttl_ceil`
    /// (POL-1 `ttl_ceil`), threaded in; NEVER hardcoded.
    pub ttl_ceil: u32,
    /// The flat admission GRACE (seconds) — the POL-1 `admission.grace` field
    /// threaded from the snapshot; NEVER hardcoded.
    pub grace: u32,
    /// POL-3 provenance from the verdict (rule id / layer / policy version),
    /// preserved on the admission entry on every arm.
    pub provenance: Provenance,
    /// The admission class (doc 11 §3.5 / §5.2): `Normal` at v0; `Synthetic` for a
    /// phase-B synthetic-A admission. The transaction writes the synthetic into
    /// `allow4` and carries the real (v6) targets on the entry.
    pub admission_type: AdmissionType,
    /// The phase-B real (v6) targets a SYNTHETIC entry stands for — empty for a
    /// NORMAL admission (doc 11 §5.2).
    pub real_targets: Vec<IpAddr>,
}

/// The outcome of the transaction the handler acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// Admitted: both stores are visible (insert-then-answer). The handler answers
    /// the VM with `answered_ttl` — the W2 clamp WITHOUT grace.
    Admitted {
        /// The clamped TTL (no grace) the VM is answered (`clamped_ttl`).
        answered_ttl: u32,
        /// The single shared deadline written to BOTH stores (W2 lockstep) — the
        /// kernel element timeout and the map entry's `expires_at` are this one
        /// value.
        deadline: Instant,
    },
    /// Fail-closed (W1): a set-programming or map failure. The handler authors
    /// SERVFAIL; the transaction left ZERO residue (no map entry, no kernel
    /// element, no live admission). NEVER a policy verdict — a genuine ds-dnsgate
    /// failure (doc 11 §3.2).
    FailClosed,
    /// Every resolved terminal address was scrubbed by the DNS-4 filter (W5): the
    /// admission would carry no plumbable IP, so it is refused. The handler
    /// authors SERVFAIL (a genuine failure — the resolved set is unusable), and no
    /// store is touched.
    NoPlumbableAddress,
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS-4 sanity filter (W5; doc 11 §3.1 / §3.5).
// ─────────────────────────────────────────────────────────────────────────────

/// The DNS-4 dual-stack sanity scrub (W5): a PURE predicate that decides whether a
/// resolved terminal address is plumbable, run ahead of every insert and every
/// answer (doc 11 §3.1).
///
/// Rejects the documented martian / unplumbable ranges:
/// - v4: unspecified `0.0.0.0/8`, loopback `127.0.0.0/8`, private `10/8`,
///   `172.16/12`, `192.168/16`, link-local `169.254/16`, CGNAT `100.64/10`,
///   multicast `224/4`, and the reserved `240/4` (incl. broadcast).
/// - v6: unspecified `::`, loopback `::1`, link-local `fe80::/10`, ULA `fc00::/7`,
///   multicast `ff00::/8`; the IPv4-mapped `::ffff:0:0/96` and IPv4/IPv6
///   translation `64:ff9b::/96` are UNWRAPPED to their embedded v4 and checked
///   against the v4 rules (so a martian cannot smuggle in mapped).
///
/// Deliberately does NOT reject `198.18.0.0/15` — that range is the doc 11 §3.5
/// phase-B synthetic-A pool (a first-class admission type, exempt by type, not by
/// an ad-hoc range hole) and the RFC 2544 benchmark range; a `normal` answer
/// carrying it is plumbable.
pub fn is_plumbable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_plumbable_v4(v4),
        IpAddr::V6(v6) => {
            // Unwrap IPv4-mapped (::ffff:0:0/96) and the well-known NAT64 prefix
            // (64:ff9b::/96) to the embedded v4 and apply the v4 rules — a martian
            // must not slip through wrapped as v6.
            if let Some(embedded) = embedded_v4(v6) {
                return is_plumbable_v4(embedded);
            }
            is_plumbable_v6(v6)
        }
    }
}

/// The v4 half of the DNS-4 filter. `true` == plumbable (admittable / answerable).
fn is_plumbable_v4(ip: Ipv4Addr) -> bool {
    // `0.0.0.0/8` (incl. the unspecified address) — never a real destination.
    if ip.octets()[0] == 0 {
        return false;
    }
    // The stdlib classifiers cover loopback, private (RFC1918), link-local,
    // broadcast, documentation, and the unspecified/this-host special cases.
    if ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
    {
        return false;
    }
    // CGNAT `100.64.0.0/10` (RFC 6598) — not flagged by the stdlib classifiers on
    // the pinned toolchain, so checked explicitly.
    let [a, b, ..] = ip.octets();
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    // Reserved `240.0.0.0/4` (incl. `255.255.255.255` broadcast, already caught).
    if a >= 240 {
        return false;
    }
    true
}

/// The v6 half of the DNS-4 filter (after IPv4-mapped/NAT64 unwrap). `true` ==
/// plumbable.
fn is_plumbable_v6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let seg0 = ip.segments()[0];
    // Link-local `fe80::/10`.
    if (seg0 & 0xffc0) == 0xfe80 {
        return false;
    }
    // Unique-local `fc00::/7` (ULA).
    if (seg0 & 0xfe00) == 0xfc00 {
        return false;
    }
    true
}

/// Unwrap an IPv4-mapped (`::ffff:0:0/96`) or NAT64 (`64:ff9b::/96`) v6 address to
/// its embedded v4 (doc 11 W5: the embedded-IPv4 unwrap), else `None`.
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    // ::ffff:a.b.c.d — segments 0..=4 are zero, segment 5 is 0xffff.
    if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0xffff {
        let o = ip.octets();
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    // 64:ff9b::/96 — the well-known NAT64 prefix.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        let o = ip.octets();
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

/// Project a `std::net::IpAddr` onto the frozen family-agnostic
/// [`AdmittedAddr`] (network-byte-order octets + family tag) — the contract shape
/// both the map's reverse index and a later `flush_session` `DstFilter::Only`
/// agree on (doc 14 §5; no stdlib/framework address type crosses the map API).
fn to_admitted_addr(addr: IpAddr) -> AdmittedAddr {
    match addr {
        IpAddr::V4(v4) => AdmittedAddr {
            family: AddressFamily::V4,
            octets: v4.octets().to_vec(),
        },
        IpAddr::V6(v6) => AdmittedAddr {
            family: AddressFamily::V6,
            octets: v6.octets().to_vec(),
        },
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The insert-then-answer transaction (W1–W4; D68).
// ─────────────────────────────────────────────────────────────────────────────

/// The admission transaction: the single-deadline coupling of the NFT-3 set write,
/// the DNS-2b map write, and the live-admission record (doc 11 §8.3). It borrows
/// the three stores; the handler holds them behind shared handles so the UDP and
/// TCP transports admit into the same state.
///
/// `M` is the frozen [`AdmissionMap`]; `S` is the [`NftSetProgrammer`] surface.
pub struct AdmissionTransaction<'a, M: AdmissionMap, S: NftSetProgrammer> {
    map: &'a mut M,
    set: &'a S,
    live: &'a LiveAdmissions,
}

impl<'a, M: AdmissionMap, S: NftSetProgrammer> AdmissionTransaction<'a, M, S> {
    /// Build a transaction over the three stores.
    pub fn new(map: &'a mut M, set: &'a S, live: &'a LiveAdmissions) -> Self {
        Self { map, set, live }
    }

    /// Run the insert-then-answer admission for an `Allow` (W1–W4).
    ///
    /// Steps (doc 11 §3.1 / §8.3): DNS-4 filter the terminal addresses → compose
    /// the ONE shared deadline from POL-1 floor/ceil/grace → in ONE fail-closed
    /// transaction program every NFT-3 set element, write the DNS-2b map entry,
    /// and record the live admission, all keyed on the ORIGINAL query name → then
    /// return the clamped TTL (no grace) for the handler to answer with.
    ///
    /// `answer_time` is the gate's clock at answer authorship — the W2 deadline
    /// base. Passed in (not read from a global clock) so the same value seeds both
    /// stores and tests are deterministic.
    pub fn admit(&mut self, inputs: &AdmissionInputs, answer_time: Instant) -> AdmissionOutcome {
        // (1) DNS-4 sanity filter (W5) — scrub the terminal addresses ahead of any
        // insert. A `normal`/synthetic answer must carry at least one plumbable
        // address; an answer that resolves entirely to martians is refused (no IP
        // that cannot be plumbed is ever admitted or answered).
        //
        // The plumbable set is CANONICALIZED to a first-occurrence-stable DISTINCT
        // set in the SAME pass: `admitted_ips`, the derived NFT-3 `set_inserts`, and
        // the §5.4 live-record fan-out below are all built 1:1 from `plumbable`, so a
        // duplicate address here would double-program one allow-set element and double
        // a `(session, ip)` membership the refcount loop counts on. The handler is the
        // SOLE producer that canonicalizes `terminal_addrs` today (a distinct set in →
        // a no-op here, byte-identical output), but the distinct-IP invariant the
        // allow set + reverse index depend on must hold REGARDLESS of producer: a
        // warm-restart replay, a phase-B synthetic admission (doc 11 §3.5), or a new
        // harness feeding non-canonical inputs must NOT re-introduce a double
        // `SetInsert` or double membership. Dedup is HashSet-guarded with stable
        // first-occurrence insertion order — the same distinct-IP discipline the
        // map-write incref delta (`HashSet<&AdmittedAddr>`) and the `revoke` decref
        // already enforce on their side. The W1 program-then-map ordering and the
        // FailClosed rollback are untouched; only the input set is canonicalized first.
        let mut seen: std::collections::HashSet<IpAddr> = std::collections::HashSet::new();
        let plumbable: Vec<IpAddr> = inputs
            .terminal_addrs
            .iter()
            .copied()
            .filter(|a| is_plumbable(*a))
            .filter(|a| seen.insert(*a))
            .collect();
        if plumbable.is_empty() {
            return AdmissionOutcome::NoPlumbableAddress;
        }

        // (2) Compose the SINGLE shared deadline ONCE (W2). FLOOR/CEIL/GRACE are
        // POL-1 schema fields threaded through `inputs` — NEVER code constants. The
        // VM is answered the clamp WITHOUT grace; the deadline carries the grace.
        let answered_ttl = ds_contracts::dns_admission::clamped_ttl(
            inputs.chain_min_ttl,
            inputs.ttl_floor,
            inputs.ttl_ceil,
        );
        let fresh_deadline = compose_deadline(
            answer_time,
            inputs.chain_min_ttl,
            inputs.ttl_floor,
            inputs.ttl_ceil,
            inputs.grace,
        );

        // (3) W4 refresh: if this name is already admitted for the session, the
        // deadline only ever extends — `max(existing, new)` — never shortens. The
        // ONE deadline written to both stores is the refreshed value.
        let key = AdmissionKey {
            session_uuid: inputs.session_uuid.clone(),
            original_query_fqdn: inputs.original_query_fqdn.clone(),
        };
        // Capture the PRIOR membership of this name BEFORE the map write rewrites it.
        // A refresh that re-resolves to a CHANGED IP set (DNS rotation, the W3 full
        // path) drops every IP in `prior_admitted_ips` that the new set no longer
        // holds; the map write below decrefs those dropped IPs in the reverse index,
        // and the post-write step withdraws the KERNEL allow-set element for any that
        // reach refcount zero — without this, the dropped IP's element lingers until
        // its original W2 timeout (≤ CEIL+GRACE) while the map says it is no longer
        // admitted (the F2 map/kernel divergence). `deadline` is `max(existing, new)`
        // (W4 — never shortened); the membership snapshot is read off the SAME entry.
        let (prior_admitted_ips, deadline) = match self.map.lookup(&key) {
            Some(existing) => (
                existing.admitted_ips.clone(),
                existing.refreshed_deadline(fresh_deadline),
            ),
            None => (Vec::new(), fresh_deadline),
        };

        // The element timeout the kernel set carries is the SAME deadline as a
        // whole-second relative timeout from `answer_time`. Both describe one
        // instant (the lockstep) — neither store recomputes a timer.
        let timeout_secs = deadline_to_timeout_secs(answer_time, deadline);

        let admitted_ips: Vec<AdmittedAddr> =
            plumbable.iter().map(|a| to_admitted_addr(*a)).collect();
        let real_targets: Vec<AdmittedAddr> = inputs
            .real_targets
            .iter()
            .map(|a| to_admitted_addr(*a))
            .collect();

        // Build the per-IP NFT-3 set inserts (the `(leg, index)` mark identity is
        // composed under DS_MARK_MASK — never a raw literal). The set name is the
        // PER-SESSION name from the single-source `ds_contracts::session::allow_set_name`
        // (D3/D4): v4 → `allow4_<idx>`, v6 → `allow6_<idx>` (dormant phase C, but the
        // leg is shaped from the start so a dual-family admission is one transaction),
        // where `<idx>` is the SAME `host_session_index` (`inputs.session_index`) the
        // mark composes from. ds-nft's `InstantiateSessionNFT` CREATES the sets under
        // this very name, so the gate FILLS the set the creator made — byte-exact, no
        // handshake (doc 11 §2.5/§4 D3/D4). A synthetic admission writes its synthetic
        // v4 into the per-session `allow4_<idx>` (doc 11 §3.5 phase B).
        let mark_value = compose(Leg::AgentVm, inputs.session_index);
        let set_inserts: Vec<SetInsert> = admitted_ips
            .iter()
            .map(|ip| {
                let set_name = allow_set_name(ip.family, inputs.session_index);
                SetInsert {
                    set_name,
                    mark_value,
                    mark_mask: DS_MARK_MASK,
                    element: ip.to_dst_key().0,
                    timeout_secs,
                    deadline,
                }
            })
            .collect();

        // ── The ONE fail-closed transaction (W1) ────────────────────────────────
        // Order: program the NFT-3 set elements FIRST (observed-committed before
        // any answer), then the DNS-2b map, then the live record. Any failure rolls
        // back EVERY element programmed so far — zero residue: no kernel element, no
        // map entry, no live admission, never an unplumbed IP. The two stores are
        // SEQUENCED with compensation, never fired in parallel (doc 11 §8.3 step 4).
        let mut programmed: Vec<SetInsert> = Vec::with_capacity(set_inserts.len());
        for insert in &set_inserts {
            match self.set.program(insert) {
                Ok(()) => programmed.push(insert.clone()),
                Err(_) => {
                    // Set-programming failure (W1): withdraw everything programmed
                    // so far and withhold the answer. SERVFAIL, zero residue.
                    self.rollback(&programmed);
                    return AdmissionOutcome::FailClosed;
                }
            }
        }

        // The IPs this name held in its PRIOR entry that the new resolved set no
        // longer holds — the refresh DROP set (DNS rotation). Computed BEFORE the map
        // write moves `admitted_ips`; membership compares on the SAME `AdmittedAddr`
        // octets the reverse index counts on (`Hash + Eq`), so the drop set and the
        // map's own decref delta agree byte-exact. Empty on a first admission or an
        // unchanged refresh (the common case): no withdraw fires.
        let next_set: std::collections::HashSet<&AdmittedAddr> = admitted_ips.iter().collect();
        let dropped_ips: Vec<AdmittedAddr> = prior_admitted_ips
            .iter()
            .filter(|ip| !next_set.contains(ip))
            .cloned()
            .collect();

        // The DNS-2b map write — the AdmissionKey -> AdmissionEntry store. The
        // entry's `expires_at` is the SAME `deadline` the kernel elements carry
        // (W2 lockstep). On a map failure, roll the kernel elements back too.
        let entry = AdmissionEntry {
            admitted_ips,
            admission_type: inputs.admission_type,
            real_targets,
            expires_at: deadline,
            admitted_at: answer_time,
            provenance: inputs.provenance.clone(),
        };
        if self.map.admit(key.clone(), entry).is_err() {
            self.rollback(&programmed);
            return AdmissionOutcome::FailClosed;
        }

        // ── F2 refresh-time DROPPED-IP withdraw (map/kernel re-convergence) ──────
        // The map write above decref'd, in the SAME `(session, ip)` reverse index the
        // §5.4 sweep reads, every IP this name dropped on the refresh. For each
        // dropped IP whose count has now reached ZERO (no surviving sibling name in
        // the session vouches it), withdraw its KERNEL allow-set element IN THIS SAME
        // transaction — mirroring the §5.4 sweep's refcount-zero-deletes-element
        // discipline (doc 11 §5.4 leg (a)). Without this the dropped IP's element
        // would linger in the allow set until its original W2 timeout (≤ CEIL+GRACE)
        // while the map says it is no longer admitted (the F2 divergence). A
        // still-shared dropped IP (refcount > 0 — a live sibling fqdn holds it) is
        // NEVER withdrawn (bias to under-delete, W4). The set name + element are
        // derived EXACTLY as the admit inserts above derive them, so the withdraw
        // targets the SAME set element the insert wrote (byte-exact key agreement).
        for ip in &dropped_ips {
            if self.map.reverse_index().refcount(&inputs.session_uuid, ip) != 0 {
                // A surviving sibling name still references this IP — under-delete.
                continue;
            }
            let withdraw = SetInsert {
                // Derived EXACTLY as the per-session admit inserts above
                // (`allow_set_name(ip.family, inputs.session_index)`, D3/D4) so the
                // withdraw targets the SAME per-session allow set element the insert
                // wrote — byte-exact key + set-name agreement.
                set_name: allow_set_name(ip.family, inputs.session_index),
                mark_value,
                mark_mask: DS_MARK_MASK,
                element: ip.to_dst_key().0,
                // The delete identity is (set_name, element, mark) only — the
                // timeout/deadline never enter a `delete element` (kernel) nor the
                // recorded withdrawal's set-membership key. Carried as the refresh's
                // current values so the struct is well-formed; they are not part of
                // the element's identity.
                timeout_secs,
                deadline,
            };
            // Idempotent at the kernel (deleting an absent element is a no-op); a
            // withdraw error here cannot worsen residue and must not wedge a
            // successful admission (the under-delete bias, D53/W4), so it is not
            // surfaced — the answer has already been authored into both stores.
            let _ = self.set.withdraw(&withdraw);
        }

        // The §5.4 revocation-sweep live record — `(session, original-fqdn, ip)`
        // per plumbable IP, keyed on the ORIGINAL query name (W3). Recorded LAST so
        // a failure in either store above never leaves a dangling live admission.
        //
        // The record carries the REAL `inputs.session_index` (D3/D4) — the SAME index
        // the NFT-3 set write above keyed `allow_set_name(family, inputs.session_index)`
        // and the mark keyed `compose(Leg::AgentVm, inputs.session_index)` on. Stamping
        // it here closes the ADMIT side of the §5.4 sweep: the sweep reads the freed
        // admission's own `host_session_index` off this record and deletes from its real
        // `allow4_<idx>` / `(leg, idx)` mark, never the index-0 approximation — so a
        // withdraw under concurrent sessions targets the freed admission's own set.
        for ip in &plumbable {
            self.live.admit(
                LiveAdmission::new(
                    inputs.session_uuid.clone(),
                    inputs.original_query_fqdn.clone(),
                    *ip,
                )
                .with_host_session_index(inputs.session_index),
            );
        }

        // (4) Only now is the answer authored — both stores are visible
        // (insert-then-answer). The VM is answered the clamp WITHOUT grace.
        AdmissionOutcome::Admitted {
            answered_ttl,
            deadline,
        }
    }

    /// Withdraw every element programmed so far — the fail-closed compensation
    /// (W1 zero residue). The map write is gated on the set write succeeding, so a
    /// rollback here is the only kernel-side cleanup needed; the map entry is never
    /// written on a failed admission.
    fn rollback(&self, programmed: &[SetInsert]) {
        for insert in programmed {
            // Withdraw is idempotent; a withdraw error cannot make residue worse
            // (the element either never committed or is being removed), so we do
            // not surface it — the outcome is already FailClosed.
            let _ = self.set.withdraw(insert);
        }
    }
}

/// The whole-second relative timeout from `answer_time` to the absolute `deadline`
/// — the kernel element's `timeout Ns`. Saturating and floored at zero so a
/// deadline already in the past (cannot happen for a freshly-composed deadline,
/// but a refresh `max()` keeps an existing future deadline) yields a non-negative
/// timeout. Rounds UP to the whole second so the kernel element never expires
/// before the absolute deadline the map entry carries (lockstep: the element
/// outlives, never undercuts, the map's `expires_at`).
fn deadline_to_timeout_secs(answer_time: Instant, deadline: Instant) -> u32 {
    const NANOS_PER_SEC: u64 = 1_000_000_000;
    let delta_nanos = deadline.unix_nanos.saturating_sub(answer_time.unix_nanos);
    // Ceil-divide to whole seconds.
    let secs = delta_nanos.div_ceil(NANOS_PER_SEC);
    u32::try_from(secs).unwrap_or(u32::MAX)
}

// ─────────────────────────────────────────────────────────────────────────────
// The concrete in-memory DNS-2b store + the handler-held store bundle.
// ─────────────────────────────────────────────────────────────────────────────

/// The per-session IP ↔ domain reverse-index body (doc 14 §3) — required from day
/// one. Keyed `(session, ip-octets)`; the count is the number of live admissions
/// holding the IP, so a shared-CDN IP survives a sibling name's revocation (bias to
/// under-delete, W4). The frozen [`ReverseIndex`] trait shape; this is the storage
/// owner's body.
#[derive(Debug, Default)]
pub struct InMemoryReverseIndex {
    counts: HashMap<(String, Vec<u8>), u32>,
}

impl ReverseIndex for InMemoryReverseIndex {
    fn incref(&mut self, session_uuid: &str, ip: &AdmittedAddr, _domain: &str) -> u32 {
        let c = self
            .counts
            .entry((session_uuid.to_string(), ip.octets.clone()))
            .or_insert(0);
        *c += 1;
        *c
    }
    fn decref(&mut self, session_uuid: &str, ip: &AdmittedAddr, _domain: &str) -> u32 {
        let c = self
            .counts
            .entry((session_uuid.to_string(), ip.octets.clone()))
            .or_insert(0);
        // Saturate at zero, never underflow (bias to under-delete, doc 14 §3).
        *c = c.saturating_sub(1);
        *c
    }
    fn refcount(&self, session_uuid: &str, ip: &AdmittedAddr) -> u32 {
        *self
            .counts
            .get(&(session_uuid.to_string(), ip.octets.clone()))
            .unwrap_or(&0)
    }
}

/// The concrete in-memory DNS-2b [`AdmissionMap`] the gate writes through
/// (doc 11 §5.2 / doc 14 §3). The storage mechanism behind the frozen API is free
/// (doc 14 OQ6); this is the v0 in-process body — the SAME API surface a later
/// shared-mmap / shm / UDS backing resolves to. It does NOT self-evict (W4): a
/// `lookup` returns an expired entry; expiry is the caller's gate.
#[derive(Debug, Default)]
pub struct InMemoryAdmissionMap {
    entries: HashMap<(String, String), AdmissionEntry>,
    reverse: InMemoryReverseIndex,
}

impl AdmissionMap for InMemoryAdmissionMap {
    type Reverse = InMemoryReverseIndex;

    fn admit(&mut self, key: AdmissionKey, entry: AdmissionEntry) -> Result<(), AdmissionError> {
        // The reverse-index count for `(session, ip)` is the number of DISTINCT
        // admitted FQDNs in the session that reference the IP (doc 14 §3 / doc 11
        // §5.2) — so a sole-reference IP frees EXACTLY once on revoke and a
        // shared-CDN IP survives a sibling name's revocation. `admit` is "insert OR
        // refresh" (frozen `AdmissionMap::admit`): a W4 refresh re-admits an
        // ALREADY-live `(session, original_query_fqdn)` key, so we must refcount by
        // the IP-SET MEMBERSHIP DELTA of THIS NAME against its prior entry, NOT
        // unconditionally per call. An unconditional per-call incref would inflate
        // the count to K after K refreshes while `revoke` decrefs once — leaking a
        // sole-reference IP (residual K-1) the W2 deadline would have to expire.
        //
        // Delta against the prior membership of this name: incref the IPs this name
        // newly references (in the new set, not the prior), decref the IPs this name
        // no longer references (in the prior set, not the new). A refresh with an
        // unchanged IP set is a refcount NO-OP; an IP added/dropped by the refresh
        // moves the count by exactly one. Membership is keyed on the SAME
        // `AdmittedAddr` octets the reverse index counts on (`Hash + Eq`), so the
        // delta and the count agree byte-exact.
        let map_key = (key.session_uuid.clone(), key.original_query_fqdn.clone());

        let prior: std::collections::HashSet<&AdmittedAddr> = self
            .entries
            .get(&map_key)
            .map(|e| e.admitted_ips.iter().collect())
            .unwrap_or_default();
        let next: std::collections::HashSet<&AdmittedAddr> = entry.admitted_ips.iter().collect();

        // Decref the IPs this name dropped (prior membership the new set no longer
        // holds) — saturating at zero (bias to under-delete; never underflow).
        for ip in prior.difference(&next) {
            self.reverse
                .decref(&key.session_uuid, ip, &key.original_query_fqdn);
        }
        // Incref the IPs this name newly references (new membership the prior did
        // not hold) — a re-admit of an unchanged set adds nothing here.
        for ip in next.difference(&prior) {
            self.reverse
                .incref(&key.session_uuid, ip, &key.original_query_fqdn);
        }

        self.entries.insert(map_key, entry);
        Ok(())
    }

    fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
        // No expiry check — the map never self-evicts (W4, doc 11 §3.1).
        self.entries
            .get(&(key.session_uuid.clone(), key.original_query_fqdn.clone()))
            .cloned()
    }

    fn revoke(&mut self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
        let k = (key.session_uuid.clone(), key.original_query_fqdn.clone());
        // Absent key: idempotent empty success (doc 14 §3).
        let Some(entry) = self.entries.remove(&k) else {
            return Ok(vec![]);
        };
        // Decref over the DISTINCT IP membership of this name — SYMMETRIC with
        // `admit`, which increfs by the distinct-IP-set delta (a `(session, ip)`
        // count is distinct-name membership, NOT a raw RR count). A malformed answer
        // can carry the SAME plumbable IP in two A RRs, so `entry.admitted_ips` may
        // hold duplicates; decref'ing per raw element would drive a sole-reference
        // count past zero on the FIRST duplicate (freeing the IP) AND, because the
        // saturating decref still returns 0, push the IP into `freed` a SECOND time —
        // an over-/double-free of a possibly shared-CDN IP a sibling name still holds
        // (a W4 / bias-to-under-delete violation). Decref'ing once per distinct IP
        // mirrors the admit-side incref exactly: a sole-reference IP frees EXACTLY
        // once, a shared IP a survivor still holds is not freed.
        let mut seen: std::collections::HashSet<&AdmittedAddr> = std::collections::HashSet::new();
        let mut freed = Vec::new();
        for ip in &entry.admitted_ips {
            if !seen.insert(ip) {
                continue;
            }
            if self
                .reverse
                .decref(&key.session_uuid, ip, &key.original_query_fqdn)
                == 0
            {
                freed.push(ip.clone());
            }
        }
        Ok(freed)
    }

    fn reverse_index(&self) -> &Self::Reverse {
        &self.reverse
    }
}

/// The handler-held admission stores: the DNS-2b map, the NFT-3 set programmer, and
/// the §5.4 live-admission registry, all behind shared handles so the UDP and TCP
/// transports admit into the SAME state (the gate is the sole writer; doc 11 §5.2).
///
/// Cloning is a shared-handle clone (every transport sees one set of stores). The
/// handler runs the [`AdmissionTransaction`] over these on every `Allow` answer
/// (fresh or cache-shaped — W3 full-path). The set programmer is generic so a
/// deployment can bind the production `ds-nft` `NftWriter` (the one-line crate-dep
/// edge outside this unit's grant) without touching the transaction; the default
/// [`RecordingSetProgrammer`] drives the reportable in-memory path (no live kernel).
pub struct AdmissionStores<
    M: AdmissionMap = InMemoryAdmissionMap,
    S: NftSetProgrammer = RecordingSetProgrammer,
> {
    // Interim DNS-2b read-contention fix (doc 04 §6 D131): the map is read on every
    // ds-tlsproxy TLS connection (many concurrent readers, one occasional writer) and
    // written only on admit/revoke. A `Mutex` serializes the readers — its aggregate
    // read throughput FALLS as readers scale (2026-06-15 bench: p99 ~238µs @ 32t) — so
    // reads take a `.read()` guard and writes a `.write()` guard here. The DURABLE fix
    // is the lock-free seqlock/shm read path in the survivable-storage map (taskdb
    // 01KV52NCG7).
    //
    // The map is now GENERIC over `M: AdmissionMap` (default `InMemoryAdmissionMap`, so
    // every existing call site / test is byte-unchanged). The D131 Candidate-A
    // production path binds `M = ds_admission_shm::ShmAdmissionMap` (the live shm writer)
    // via [`AdmissionStores::with_shm_writer`]. The `RwLock` here serializes the SINGLE
    // in-process WRITER across the UDP + TCP transports (both hold a shared-handle clone,
    // and `AdmissionMap::admit`/`revoke` take `&mut`) — a job ORTHOGONAL to the shm
    // seqlock, which gives CROSS-PROCESS readers (ds-tlsproxy, a separate process
    // attaching its own `ShmAdmissionReader`) torn-read-free lock-free lookups. The shm
    // readers NEVER go through this `AdmissionStores` / this lock, so binding the shm
    // writer here introduces NO in-process reader contention; the lock-free read benefit
    // is realized in the ds-tlsproxy process, exactly as D131 intends. (`std::sync::RwLock`
    // plateaus past ~8 cores in the bench; `parking_lot::RwLock` scales better if a dep is
    // ever added — but we keep std, no new dependency.)
    map: Arc<RwLock<M>>,
    set: Arc<S>,
    live: LiveAdmissions,
    /// The fingerprint→sessions FLEET-revocation admission book (doc 19 §7; D102/P-R6) the W1/W2
    /// mint path records a session into as it admits it under a scoped token. A shared-handle
    /// clone of the gate's book (`RunningGate::fleet_revocation_book`), so the post-commit fleet
    /// sweep resolves a revoked token's fingerprint to the sessions the gate ACTUALLY admitted
    /// under it. Recording is GATED on [`fleet_token_fingerprint`](Self::fleet_token_fingerprint)
    /// being `Some` — a store with no fingerprint wired records nothing (behavior-preserving for
    /// every existing caller / test), so the book stays empty until the scoped-token identity is
    /// threaded in. A clone shares the inner `Arc`, so both transports' mint paths and the sweep
    /// hold one book with no copy skew.
    fleet_book: FleetRevocationBook,
    /// The host id stamped into the [`SessionRef`] the fleet-revocation record carries (doc 14 §4).
    /// Opaque to the sweep (`flush_session` joins on `tap_name`), so a stable per-gate value is
    /// sufficient; sourced from `GateConfig.host_id` (`DS_HOST_ID`) at spawn, else the
    /// [`DEFAULT_FLEET_HOST_ID`] stand-in for the loopback/synthetic pre-stage.
    fleet_host_id: Arc<str>,
    /// How the mint path resolves the scoped-token chain FINGERPRINT / block id (opaque hex; NEVER
    /// token bytes, D50) each admitted session is recorded under in the fleet-revocation book —
    /// resolved PER SESSION at admission time (doc 19 §7; D102/P-R6). The `None` variant is the
    /// pre-token-plumbing default (records nothing, byte-identical to today); the `Fixed` variant is
    /// the single-session `DS_TOKEN_FINGERPRINT` stand-in (mirrors the `fixed_session_uuid` idiom);
    /// the `PerSession` variant is the LIVE multi-session feed the deliverable adds — it resolves
    /// each admitting session's own scoped-token fingerprint from its `session_uuid`, so two sessions
    /// admitted under two distinct tokens key two DISTINCT book rows and a revocation of one severs
    /// only its own sessions (the single-fingerprint stand-in could not). The real cross-process feed
    /// is a deferred seam outside this workspace; the resolver closure is its loopback/synthetic
    /// stand-in.
    fleet_fingerprint: FleetFingerprintSource,
}

/// Resolves the scoped-token chain FINGERPRINT (opaque hex / block id — NEVER token bytes, D50) an
/// admitted session is recorded under in the [`FleetRevocationBook`], keyed on the admitting session
/// at ADMISSION time (doc 19 §7). This is the seam that replaces the single-session
/// `fixed_token_fingerprint` stand-in with a live PER-SESSION feed: a multi-session gate resolves
/// EACH session's own token fingerprint, so distinct sessions land distinct book rows.
///
/// A live per-session fingerprint resolver: `session_uuid → Option<fingerprint>` (opaque hex /
/// block id — NEVER token bytes, D50). `None` for a session with no scoped token wired. Shared
/// behind an `Arc` so an [`AdmissionStores`] clone shares one resolver across both transports.
pub type FleetFingerprintResolver = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// A shared-handle `Clone` (the `PerSession` closure rides behind an `Arc`), so an
/// [`AdmissionStores`] clone shares one resolver across both transports.
#[derive(Clone)]
pub enum FleetFingerprintSource {
    /// No fingerprint wired — the mint path records NOTHING (the pre-token-plumbing default;
    /// behavior-preserving for every existing caller/test, so the fleet book stays empty).
    None,
    /// A SINGLE fixed fingerprint for every session (the single-session `DS_TOKEN_FINGERPRINT`
    /// stand-in, kept for the one-VM testbed — mirrors `fixed_session_uuid` key agreement).
    Fixed(String),
    /// A LIVE per-session feed: resolve the admitting session's own scoped-token fingerprint from
    /// its `session_uuid` at admission time. Returns `None` for a session with no scoped token wired
    /// (that admission records nothing — fail-open to the pre-plumbing behavior for THAT session).
    /// The closure is the loopback/synthetic stand-in for the real cross-process per-session
    /// fingerprint feed (a deferred seam outside this workspace, D50).
    PerSession(FleetFingerprintResolver),
}

impl FleetFingerprintSource {
    /// Resolve the fingerprint to record `session_uuid`'s admission under, or `None` to record
    /// nothing for this admission (the pre-plumbing default, or a session the live feed has no
    /// scoped token for).
    fn resolve(&self, session_uuid: &str) -> Option<String> {
        match self {
            FleetFingerprintSource::None => Option::None,
            FleetFingerprintSource::Fixed(fingerprint) => Some(fingerprint.clone()),
            FleetFingerprintSource::PerSession(feed) => feed(session_uuid),
        }
    }
}

impl std::fmt::Debug for FleetFingerprintSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render only the VARIANT — never a fingerprint value (opaque token-chain material, D50).
        let variant = match self {
            FleetFingerprintSource::None => "None",
            FleetFingerprintSource::Fixed(_) => "Fixed",
            FleetFingerprintSource::PerSession(_) => "PerSession",
        };
        f.debug_tuple("FleetFingerprintSource")
            .field(&variant)
            .finish()
    }
}

// A SHARED-HANDLE clone: every field is an `Arc`/`LiveAdmissions` handle, so a clone points at the
// SAME map, set programmer, live registry, and fleet-revocation book (the UDP + TCP transports
// admit into one state, doc 11 §5.2). Implemented by hand so the bound is `S: NftSetProgrammer`
// (NOT `S: Clone`) — the set programmer rides behind `Arc<S>`, so a non-`Clone` programmer (the
// `RecordingSetProgrammer`, and the production `ds-nft` `NftWriter`) is shared by Arc-clone, never
// deep-copied. `#[derive(Clone)]` would wrongly demand `S: Clone`.
impl<M: AdmissionMap, S: NftSetProgrammer> Clone for AdmissionStores<M, S> {
    fn clone(&self) -> Self {
        Self {
            map: Arc::clone(&self.map),
            set: Arc::clone(&self.set),
            live: self.live.clone(),
            fleet_book: self.fleet_book.clone(),
            fleet_host_id: Arc::clone(&self.fleet_host_id),
            fleet_fingerprint: self.fleet_fingerprint.clone(),
        }
    }
}

/// The loopback/synthetic pre-stage host id the fleet-revocation [`SessionRef`] carries when
/// `GateConfig.host_id` (`DS_HOST_ID`) is unset. The value is opaque to the sweep (the flush joins
/// on `tap_name`), so a stable placeholder is honest for a single-host pre-stage gate.
pub const DEFAULT_FLEET_HOST_ID: &str = "local-host";

impl Default for AdmissionStores<InMemoryAdmissionMap, RecordingSetProgrammer> {
    fn default() -> Self {
        let map = Arc::new(RwLock::new(InMemoryAdmissionMap::default()));
        let mut live = LiveAdmissions::new();
        // Close the admission ↔ revocation refcount loop onto ONE index: bind the SAME DNS-2b map
        // handle into the live registry so the §5.4 sweep reads its allow-set-deletion decision off
        // the SAME `(session, ip)` reverse-index count the W1/W2 transaction maintains, never a
        // second independently-derived survivor count (doc 11 §5.4).
        live.bind_admission_map(Arc::clone(&map));
        Self {
            map,
            set: Arc::new(RecordingSetProgrammer::new()),
            live,
            fleet_book: FleetRevocationBook::new(),
            fleet_host_id: Arc::from(DEFAULT_FLEET_HOST_ID),
            fleet_fingerprint: FleetFingerprintSource::None,
        }
    }
}

impl AdmissionStores<InMemoryAdmissionMap, RecordingSetProgrammer> {
    /// A fresh in-memory store bundle (the default the gate runs with at the
    /// pre-stage — loopback/synthetic, no live kernel).
    pub fn new() -> Self {
        Self::default()
    }
}

// The InMemory-map constructors that BIND the §5.4 revocation-sweep map handle. The
// `bind_admission_map` seam (`server.rs`) is now generic over any `M: AdmissionMap`
// (it stores the `Arc<RwLock<M>>` as a `SweepRevocable` trait object), so BOTH this
// InMemory path AND the live shm-writer path ([`AdmissionStores::with_shm_writer`]) bind
// their concrete map handle into the sweep — the sweep revokes through whichever real map
// the stores write through (doc 11 §5.4, D131).
impl<S: NftSetProgrammer> AdmissionStores<InMemoryAdmissionMap, S> {
    /// Build a store bundle over an explicit set programmer + live registry — the
    /// seam a deployment uses to bind the production `ds-nft` writer, and the seam
    /// the gate uses to share its existing [`LiveAdmissions`] registry with the
    /// §5.4 revocation sweep (so the sweep and the W1/W2 transaction hold the SAME
    /// live set, doc 11 §5.4).
    pub fn with_parts(set: Arc<S>, mut live: LiveAdmissions) -> Self {
        let map = Arc::new(RwLock::new(InMemoryAdmissionMap::default()));
        // Bind the SAME DNS-2b map handle into the caller's live registry so the §5.4 sweep reads
        // its allow-set-deletion decision off the SAME `(session, ip)` reverse-index count the W1/W2
        // transaction maintains — closing the admission ↔ revocation refcount loop onto ONE index
        // (doc 11 §5.4). The gate shares this `live` with the sweep via `live()`; the bound map is
        // the very one this bundle writes through, so the sweep's revoke decrefs the index the admit
        // incref'd. A clone of `live` (a shared-handle clone) sees the same binding.
        live.bind_admission_map(Arc::clone(&map));
        Self {
            map,
            set,
            live,
            fleet_book: FleetRevocationBook::new(),
            fleet_host_id: Arc::from(DEFAULT_FLEET_HOST_ID),
            fleet_fingerprint: FleetFingerprintSource::None,
        }
    }
}

/// The default DNS-2b admission-map entry-slot capacity for the live shm segment — the
/// number of `(session, fqdn)` admissions a host's map holds before the open-addressed
/// table is full (a full table fails the admit closed → SERVFAIL re-admit on the next
/// query, never silent overwrite). Rounded up to a power of two by `create_named`.
/// Sized generously for a pre-stage single-host map; a later refinement sizes it off the
/// host session count. A v1 default, not a frozen contract value.
pub const ADMISSION_SHM_DEFAULT_SLOTS: u32 = 4096;

/// The default reverse-index slot capacity for the live shm segment (the per-`(session,
/// ip)` distinct-name refcount table). Sized alongside [`ADMISSION_SHM_DEFAULT_SLOTS`];
/// `create_named` rounds it relative to the entry-slot count.
pub const ADMISSION_SHM_DEFAULT_REV_SLOTS: u32 = 4096;

impl<S: NftSetProgrammer> AdmissionStores<ds_admission_shm::ShmAdmissionMap, S> {
    /// Build a store bundle whose DNS-2b map is the LIVE D131 Candidate-A shm writer
    /// (`ds_admission_shm::ShmAdmissionMap`) over the host-wide named POSIX shm segment
    /// the readers (ds-tlsproxy) attach to by the SAME name — the production wiring of the
    /// single-writer / many-reader admission map (doc 11 §8.4 / doc 14 §3 / OQ6, D131).
    /// `name` is the segment name both sides single-source through
    /// [`ds_contracts::dns_admission::admission_shm_name`].
    ///
    /// **Create-or-reattach (warm-restart safe).** POSIX shm persists across a ds-dnsgate
    /// restart, so this FIRST tries [`ShmAdmissionMap::attach_named_writer`] (re-attach to
    /// a surviving segment: re-open, validate the header, bump `writer_epoch`, repair any
    /// torn slot, rebuild the reverse index — doc 11 §8.4.1) and, only if that fails
    /// (segment absent on first boot, or a header/version mismatch), CREATES a fresh
    /// segment with [`ShmAdmissionMap::create_named`] sized at
    /// [`ADMISSION_SHM_DEFAULT_SLOTS`] / [`ADMISSION_SHM_DEFAULT_REV_SLOTS`]. The created
    /// segment is NOT unlinked on drop (survivability); a deliberate teardown calls
    /// [`ShmAdmissionMap::unlink`].
    ///
    /// The shm map IS bound into the §5.4 revocation sweep's `LiveAdmissions` handle (via the
    /// now-generic [`LiveAdmissions::bind_admission_map`], which stores the `Arc<RwLock<M>>` as a
    /// `SweepRevocable` trait object), exactly as `with_parts`/`Default` bind the in-memory map. So a
    /// policy-revocation/blocklist sweep revokes each now-denied `(session, fqdn)` THROUGH this shm
    /// map: it tombstones the shm slot and decrefs the shm reverse index, deleting only the allow-set
    /// IPs whose shm refcount reached zero (a shared-CDN IP a surviving sibling still holds keeps a
    /// non-zero shm count and survives — bias to under-delete, W4). A cross-process ds-tlsproxy reader
    /// therefore stops seeing a revoked domain vouched immediately — the security-relevant fix this
    /// closes (without it the sweep fell back to the survivor-derived refcount, which is correct for
    /// the in-process Vec but never touched the shm segment; doc 11 §5.4, D131).
    ///
    /// Errors surface the shm `AdmissionError` so `main` can fail-closed (refuse to serve
    /// the live path rather than silently fall back to in-memory) — a failed-and-reported
    /// posture beats a fabricated default.
    pub fn with_shm_writer(
        name: &str,
        set: Arc<S>,
        mut live: LiveAdmissions,
    ) -> Result<Self, AdmissionError> {
        // Create-or-reattach: warm re-attach first (a segment that survived a restart),
        // CREATE on any attach failure (first boot / absent / header mismatch). Both land
        // a writer mapped RW; the seqlock inside it synchronizes the cross-process readers.
        let map = match ds_admission_shm::ShmAdmissionMap::attach_named_writer(name) {
            Ok(reattached) => reattached,
            Err(_) => ds_admission_shm::ShmAdmissionMap::create_named(
                name,
                ADMISSION_SHM_DEFAULT_SLOTS,
                ADMISSION_SHM_DEFAULT_REV_SLOTS,
            )?,
        };
        // The RwLock serializes the SINGLE in-process writer across the UDP + TCP
        // transports (orthogonal to the seqlock — see the struct field doc). The shm
        // readers are a SEPARATE process and never take this lock.
        let map = Arc::new(RwLock::new(map));
        // Bind the SAME shm map handle into the caller's live registry (AFTER the
        // attach/create, so the bound handle is the LIVE segment) so the §5.4 revocation
        // sweep revokes each now-denied `(session, fqdn)` THROUGH this shm map — tombstoning
        // the shm slot + decref-ing the shm reverse index, refcount-correct for shared-CDN
        // IPs — exactly as `with_parts`/`Default` bind the in-memory map. A clone of `live`
        // (a shared-handle clone) sees the same binding (doc 11 §5.4, D131).
        live.bind_admission_map(Arc::clone(&map));
        Ok(Self {
            map,
            set,
            live,
            fleet_book: FleetRevocationBook::new(),
            fleet_host_id: Arc::from(DEFAULT_FLEET_HOST_ID),
            fleet_fingerprint: FleetFingerprintSource::None,
        })
    }
}

impl<M: AdmissionMap, S: NftSetProgrammer> AdmissionStores<M, S> {
    /// The shared live-admission registry (so the gate wires the SAME one into the
    /// §5.4 revocation-sweep sink).
    pub fn live(&self) -> &LiveAdmissions {
        &self.live
    }

    /// The fingerprint→sessions FLEET-revocation admission book the W1/W2 mint path records into
    /// (doc 19 §7; D102/P-R6) — a shared-handle clone. The gate hands this to
    /// `RunningGate::fleet_revocation_book`, and `main` wires the post-commit
    /// `SnapshotCommitSink::with_fleet_revocation_sweep` against it, so the sweep resolves a revoked
    /// token's fingerprint to the sessions THIS store actually admitted under it (the closed
    /// admission ↔ fleet-revocation loop, not a fresh book the sweep could never see).
    pub fn fleet_revocation_book(&self) -> FleetRevocationBook {
        self.fleet_book.clone()
    }

    /// Configure the FLEET-revocation recording the W1/W2 mint path performs (doc 19 §7): the
    /// [`SessionRef`] host id and the SINGLE-SESSION scoped-token FINGERPRINT every session this
    /// store admits is recorded under. `main`/the gate spawn threads `GateConfig.host_id`
    /// (`DS_HOST_ID`) and `GateConfig.fixed_token_fingerprint` (`DS_TOKEN_FINGERPRINT`) here. With
    /// `fingerprint` `None` (the default) the mint path records NOTHING — behavior-preserving for
    /// every existing caller — so the fleet book stays empty until a scoped-token identity is wired.
    /// A `host_id` of `None` keeps the [`DEFAULT_FLEET_HOST_ID`] stand-in. Returns `self` for the
    /// builder chain; the binding is a shared-handle-preserving field set (the book handle is
    /// untouched).
    ///
    /// For a MULTI-session gate that resolves each session's OWN token fingerprint, chain
    /// [`with_fleet_fingerprint_resolver`](Self::with_fleet_fingerprint_resolver) instead (it
    /// overrides the fixed fingerprint set here with a live per-session feed while keeping the
    /// host id this method sets).
    pub fn with_fleet_recording(
        mut self,
        host_id: Option<String>,
        fingerprint: Option<String>,
    ) -> Self {
        if let Some(host_id) = host_id {
            self.fleet_host_id = Arc::from(host_id.as_str());
        }
        self.fleet_fingerprint = match fingerprint {
            Some(fingerprint) => FleetFingerprintSource::Fixed(fingerprint),
            Option::None => FleetFingerprintSource::None,
        };
        self
    }

    /// Install a LIVE PER-SESSION scoped-token fingerprint feed (doc 19 §7): the mint path resolves
    /// EACH admitting session's own token fingerprint from its `session_uuid` at admission time,
    /// replacing the single-session `fixed_token_fingerprint` stand-in. So a gate admitting two
    /// sessions under two distinct scoped tokens records two DISTINCT book rows — a revocation of one
    /// severs only its own sessions, which the single-fingerprint stand-in structurally could not.
    /// The `resolver` returns `None` for a session with no scoped token wired (that admission records
    /// nothing — fail-open to the pre-plumbing behavior for THAT session). Overrides any fingerprint
    /// set by [`with_fleet_recording`](Self::with_fleet_recording) while leaving the host id it set
    /// intact; a shared-handle field set (the book handle is untouched). The resolver is the
    /// loopback/synthetic stand-in for the real cross-process feed (a deferred seam outside this
    /// workspace, D50 — it must never surface token bytes, only an opaque fingerprint/block id).
    pub fn with_fleet_fingerprint_resolver(mut self, resolver: FleetFingerprintResolver) -> Self {
        self.fleet_fingerprint = FleetFingerprintSource::PerSession(resolver);
        self
    }

    /// Run the insert-then-answer admission over these stores (W1–W4). Returns the
    /// [`AdmissionOutcome`] the handler acts on: `Admitted{answered_ttl,..}` →
    /// author the answer with the clamped TTL; `FailClosed`/`NoPlumbableAddress` →
    /// SERVFAIL (a genuine failure, never a policy verdict).
    pub fn run_admission(
        &self,
        inputs: &AdmissionInputs,
        answer_time: Instant,
    ) -> AdmissionOutcome {
        // WRITE path: the insert-then-answer transaction mutates the map (`admit` takes
        // `&mut`), so it takes the RwLock write guard (interim contention fix, D131).
        let outcome = {
            let mut map = self.map.write().expect("admission-map lock poisoned");
            let mut txn = AdmissionTransaction::new(&mut *map, &*self.set, &self.live);
            txn.admit(inputs, answer_time)
        };
        // FLEET-revocation record (doc 19 §7; D102/P-R6): on a SUCCESSFUL admission under a scoped
        // token, record `(token fingerprint → this session)` in the shared `FleetRevocationBook` the
        // post-commit fleet sweep resolves against — so a pushed revocation of that token severs the
        // flows THIS mint path established. Recorded ONLY on `Admitted` (a fail-closed / no-plumbable
        // admission establishes no flow, so it registers no session), and ONLY when the fingerprint
        // SOURCE resolves a fingerprint for THIS session — the pre-token-plumbing default (`None`)
        // records nothing (behavior-preserving). The fingerprint is now resolved PER SESSION at
        // admission time off `inputs.session_uuid` (the live per-session feed the deliverable adds),
        // so two sessions admitted under two distinct tokens key two DISTINCT book rows; the fixed
        // single-session stand-in is just the `Fixed` variant of that same source. The `SessionRef`
        // carries the REAL `session_index` (the SAME one the NFT-3 set write keyed
        // `allow_set_name`/`compose` on) and the never-recycled `dstap-<idx>` tap name the flush
        // joins on; the fingerprint is opaque (hex chain fingerprint / block id, NEVER token bytes)
        // and is used only as the book key. `record` dedups, so re-admitting the same session under
        // the same token (a refresh, a sibling name) does not double the session in the book.
        if let AdmissionOutcome::Admitted { .. } = &outcome {
            if let Some(fingerprint) = self.fleet_fingerprint.resolve(&inputs.session_uuid) {
                self.fleet_book.record(
                    fingerprint,
                    SessionRef::new(
                        inputs.session_uuid.clone(),
                        self.fleet_host_id.to_string(),
                        inputs.session_index,
                        format!("dstap-{}", inputs.session_index),
                    ),
                );
            }
        }
        outcome
    }

    /// Look up an admission entry — the ds-tlsproxy synchronous-read shape, exposed
    /// so the gate's own tests can assert the two-store lockstep end to end (the map
    /// entry the transaction wrote).
    pub fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
        // READ path (the ds-tlsproxy synchronous read): a `.read()` guard so concurrent
        // lookups run in parallel; the entry is still cloned out under the guard (D131).
        self.map
            .read()
            .expect("admission-map lock poisoned")
            .lookup(key)
    }

    /// The CURRENT `(session, ip)` distinct-name refcount the SHARED reverse index holds — read
    /// through the frozen [`AdmissionMap::reverse_index`] accessor (no new trait surface). The
    /// companion read to [`lookup`](Self::lookup): the §5.4 revocation sweep reads its allow-set-
    /// deletion decision off THIS index (the one the W1/W2 admit increfs and the sweep's revoke
    /// decrefs — one refcount, no drift), so the gate's tests assert the shared count directly here.
    pub fn reverse_refcount(&self, session_uuid: &str, ip: &AdmittedAddr) -> u32 {
        // READ path: only reads the shared reverse index, so a `.read()` guard (D131).
        self.map
            .read()
            .expect("admission-map lock poisoned")
            .reverse_index()
            .refcount(session_uuid, ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NANOS_PER_SEC: u64 = 1_000_000_000;

    // POL-1 default schema values, PINNED here so a silent drift of the documented
    // numbers is a test failure — the transaction itself reads them off `inputs`
    // (never a code constant), exactly as the floor/ceil/grace fields are policy
    // values, not hardcodes (doc 11 §4 / doc 13 §1.5).
    const FLOOR: u32 = 60;
    const CEIL: u32 = 900;
    const GRACE: u32 = 60;

    // The success-path map IS the production in-memory body ([`InMemoryAdmissionMap`])
    // — the caller-visible contract, not a test-only shim. `MemMap` is the alias the
    // tests bind so the map-failure injection below stays a thin wrapper over it.
    type MemMap = InMemoryAdmissionMap;

    // A map whose first `admit` fails — drives the W1 fail-closed MAP arm. It defers
    // every other method to the production in-memory body, so only the one-shot
    // failure is synthetic.
    #[derive(Default)]
    struct FailingMap {
        inner: InMemoryAdmissionMap,
        next_error: Option<AdmissionError>,
    }
    impl AdmissionMap for FailingMap {
        type Reverse = InMemoryReverseIndex;
        fn admit(
            &mut self,
            key: AdmissionKey,
            entry: AdmissionEntry,
        ) -> Result<(), AdmissionError> {
            if let Some(err) = self.next_error.take() {
                return Err(err);
            }
            self.inner.admit(key, entry)
        }
        fn lookup(&self, key: &AdmissionKey) -> Option<AdmissionEntry> {
            self.inner.lookup(key)
        }
        fn revoke(&mut self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
            self.inner.revoke(key)
        }
        fn reverse_index(&self) -> &Self::Reverse {
            self.inner.reverse_index()
        }
    }

    fn provenance() -> Provenance {
        Provenance {
            rule_id: "rule-allow-1".into(),
            policy_layer: "org".into(),
            policy_version: "2026-06-13".into(),
        }
    }

    fn normal_inputs(fqdn: &str, addrs: Vec<IpAddr>) -> AdmissionInputs {
        AdmissionInputs {
            session_uuid: "sess-uuid-1".into(),
            session_index: 7,
            original_query_fqdn: fqdn.into(),
            terminal_addrs: addrs,
            chain_min_ttl: 300,
            ttl_floor: FLOOR,
            ttl_ceil: CEIL,
            grace: GRACE,
            provenance: provenance(),
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
        }
    }

    fn t0() -> Instant {
        // A round second so timeout maths are exact.
        Instant::from_unix_nanos(1_000 * NANOS_PER_SEC)
    }

    fn pub_v4() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }

    // ── W2: the shared deadline is ONE value across BOTH stores ─────────────────

    #[test]
    fn shared_deadline_is_one_value_across_both_stores() {
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let inputs = normal_inputs("example.test.", vec![pub_v4()]);

        let outcome = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0())
        };

        let (answered_ttl, deadline) = match outcome {
            AdmissionOutcome::Admitted {
                answered_ttl,
                deadline,
            } => (answered_ttl, deadline),
            other => panic!("expected Admitted, got {other:?}"),
        };

        // The VM is answered the clamp WITHOUT grace.
        assert_eq!(
            answered_ttl, 300,
            "answered TTL is clamp(300,60,900) no grace"
        );

        // The map entry's expires_at is exactly the returned deadline …
        let key = AdmissionKey {
            session_uuid: "sess-uuid-1".into(),
            original_query_fqdn: "example.test.".into(),
        };
        let entry = map.lookup(&key).expect("entry present");
        assert_eq!(
            entry.expires_at, deadline,
            "map deadline == the one shared deadline"
        );

        // … and the NFT-3 element carries the SAME instant (as a whole-second
        // timeout from answer_time). One element committed, no residue.
        let committed = set.committed();
        assert_eq!(committed.len(), 1, "one v4 set element committed");
        assert_eq!(
            committed[0].deadline, deadline,
            "kernel element deadline == map deadline (lockstep)"
        );
        // The deadline is answer_time + clamp + grace = 1000 + 300 + 60 = 1360s.
        assert_eq!(deadline.unix_nanos, (1_000 + 300 + 60) * NANOS_PER_SEC);
        // The element timeout is the relative whole-second form of the SAME instant.
        assert_eq!(
            committed[0].timeout_secs, 360,
            "element timeout = clamp+grace seconds"
        );
        // The answered TTL is exactly GRACE seconds shorter than the deadline span.
        assert_eq!(committed[0].timeout_secs - answered_ttl, GRACE);

        // The live record was minted, keyed on the original name.
        assert_eq!(live.len(), 1);
        assert_eq!(live.snapshot()[0].fqdn, "example.test.");
    }

    #[test]
    fn floor_and_ceil_and_grace_are_read_from_inputs_not_hardcoded() {
        // A per-domain override pushes a different floor/ceil/grace; the deadline
        // honours the PASSED values, proving they are policy parameters.
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let mut inputs = normal_inputs("override.test.", vec![pub_v4()]);
        inputs.chain_min_ttl = 100_000; // above any ceil
        inputs.ttl_floor = 30;
        inputs.ttl_ceil = 3_600;
        inputs.grace = 120;

        let outcome = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0())
        };
        let (answered_ttl, deadline) = match outcome {
            AdmissionOutcome::Admitted {
                answered_ttl,
                deadline,
            } => (answered_ttl, deadline),
            other => panic!("expected Admitted, got {other:?}"),
        };
        // clamp(100000, 30, 3600) = 3600; deadline adds grace 120.
        assert_eq!(answered_ttl, 3_600);
        assert_eq!(deadline.unix_nanos, (1_000 + 3_600 + 120) * NANOS_PER_SEC);
    }

    // ── W1: fail-closed leaves ZERO residue on a simulated set failure ──────────

    #[test]
    fn fail_closed_on_set_failure_leaves_zero_residue() {
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        set.arm_error(AdmissionError::SetProgrammingFailed);
        let live = LiveAdmissions::new();
        let inputs = normal_inputs("example.test.", vec![pub_v4()]);

        let outcome = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0())
        };
        assert_eq!(outcome, AdmissionOutcome::FailClosed);

        // Zero residue: no map entry, no LIVE kernel element, no live admission.
        let key = AdmissionKey {
            session_uuid: "sess-uuid-1".into(),
            original_query_fqdn: "example.test.".into(),
        };
        assert!(
            map.lookup(&key).is_none(),
            "no map entry survives a failed admission"
        );
        assert!(
            set.committed().is_empty(),
            "no kernel element survives (first leg failed)"
        );
        assert!(
            live.is_empty(),
            "no live admission recorded on a failed admission"
        );
    }

    #[test]
    fn fail_closed_on_map_failure_rolls_back_kernel_elements() {
        // The set programs fine, then the map write fails — the kernel elements
        // already programmed MUST be withdrawn (zero residue), and no live record
        // is minted.
        let mut map = FailingMap {
            inner: InMemoryAdmissionMap::default(),
            next_error: Some(AdmissionError::Storage("map down".into())),
        };
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        // Two public IPs → two set elements programmed before the map write.
        let inputs = normal_inputs(
            "multi.test.",
            vec![pub_v4(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))],
        );

        let outcome = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0())
        };
        assert_eq!(outcome, AdmissionOutcome::FailClosed);

        // Both elements were programmed, then both withdrawn — zero live residue.
        assert_eq!(set.programmed().len(), 2, "both elements were attempted");
        assert_eq!(
            set.withdrawn().len(),
            2,
            "both were rolled back on the map failure"
        );
        assert!(
            set.committed().is_empty(),
            "no kernel element survives the rollback"
        );
        let key = AdmissionKey {
            session_uuid: "sess-uuid-1".into(),
            original_query_fqdn: "multi.test.".into(),
        };
        assert!(map.lookup(&key).is_none());
        assert!(live.is_empty());
    }

    // ── Caller-independent distinct-IP invariant: admit dedups its own input ────

    #[test]
    fn admit_dedups_duplicate_input_ip_to_one_element_and_one_membership() {
        // The handler is the SOLE producer that canonicalizes terminal_addrs today,
        // but the distinct-IP invariant the allow set + reverse index depend on must
        // hold REGARDLESS of producer. Feed a DUPLICATE plumbable IP directly
        // (bypassing the handler's dedup — the warm-restart-replay / phase-B-synthetic
        // / new-harness case) and assert the transaction collapses it: ONE allow-set
        // element programmed, ONE map membership, refcount == 1. Without the dedup
        // inside admit, the 1:1 fan-out would double-program the element and inflate
        // the membership.
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        // The SAME plumbable v4 appears twice in the resolved terminal set (a
        // malformed/duplicate answer, or a non-canonical caller).
        let dup = pub_v4();
        let inputs = normal_inputs("dup.test.", vec![dup, dup]);

        let outcome = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0())
        };
        assert!(
            matches!(outcome, AdmissionOutcome::Admitted { .. }),
            "the duplicate-fed admission still admits, got {outcome:?}"
        );

        // admitted_ips collapsed to the DISTINCT count (1), not the raw RR count (2).
        let key = AdmissionKey {
            session_uuid: "sess-uuid-1".into(),
            original_query_fqdn: "dup.test.".into(),
        };
        let entry = map.lookup(&key).expect("entry present");
        assert_eq!(
            entry.admitted_ips.len(),
            1,
            "admitted_ips collapses to the distinct count regardless of producer"
        );

        // The NFT-3 set was programmed EXACTLY once — no double SetInsert. (Both
        // `programmed()` — every attempt — and `committed()` — live residue — are the
        // distinct count, since nothing was withdrawn on this success path.)
        assert_eq!(
            set.programmed().len(),
            1,
            "no double SetInsert for a duplicate-fed admission"
        );
        assert_eq!(set.committed().len(), 1, "one live allow-set element");

        // The (session, ip) reverse-index refcount is 1, not 2 — the membership is
        // distinct-IP, so a later revoke frees it EXACTLY once (bias to under-delete).
        let dup_addr = to_admitted_addr(dup);
        assert_eq!(
            map.reverse_index().refcount("sess-uuid-1", &dup_addr),
            1,
            "duplicate-fed admit increfs the distinct IP exactly once"
        );

        // The §5.4 live record was minted once for the distinct IP, not twice.
        assert_eq!(
            live.len(),
            1,
            "one live admission record for the distinct IP"
        );
    }

    // ── W3: keyed on the ORIGINAL query name, never an intermediate CNAME ───────

    #[test]
    fn admission_is_keyed_on_original_query_name_not_cname_target() {
        // The guest asked `www.example.test.`; the upstream CNAME-chased to
        // `cdn.example.net.` and resolved a terminal A there. Admission keys on the
        // ORIGINAL name the guest asked (and that it will present in SNI), NEVER the
        // CNAME target.
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let original = "www.example.test.";
        let inputs = normal_inputs(original, vec![pub_v4()]);

        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            assert!(matches!(
                txn.admit(&inputs, t0()),
                AdmissionOutcome::Admitted { .. }
            ));
        }

        // The map key is the original name …
        assert!(map
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: original.into(),
            })
            .is_some());
        // … and the CNAME target is NOT a key.
        assert!(map
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: "cdn.example.net.".into(),
            })
            .is_none());
        // The live record carries the original name too.
        assert_eq!(live.snapshot()[0].fqdn, original);
    }

    // ── W4: refresh extends to max(existing,new), never shortens ────────────────

    #[test]
    fn refresh_extends_deadline_to_max_never_shortens() {
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let inputs = normal_inputs("refresh.test.", vec![pub_v4()]);

        // First admission at t=1000s → deadline 1000+300+60 = 1360s.
        let first = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0())
        };
        let first_deadline = match first {
            AdmissionOutcome::Admitted { deadline, .. } => deadline,
            other => panic!("expected Admitted, got {other:?}"),
        };

        // A LATER re-resolution at t=1100s → fresh deadline 1100+300+60 = 1460s.
        // refresh = max(1360, 1460) = 1460 → extended.
        let later = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, Instant::from_unix_nanos(1_100 * NANOS_PER_SEC))
        };
        let later_deadline = match later {
            AdmissionOutcome::Admitted { deadline, .. } => deadline,
            other => panic!("expected Admitted, got {other:?}"),
        };
        assert!(
            later_deadline > first_deadline,
            "a later re-resolution extends"
        );
        assert_eq!(
            later_deadline.unix_nanos,
            (1_100 + 300 + 60) * NANOS_PER_SEC
        );

        // An EARLIER re-resolution at t=1010s → fresh deadline 1010+300+60 = 1370s,
        // which is BELOW the live deadline 1460s. refresh = max(1460, 1370) = 1460:
        // the deadline is NEVER shortened.
        let earlier = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, Instant::from_unix_nanos(1_010 * NANOS_PER_SEC))
        };
        let earlier_deadline = match earlier {
            AdmissionOutcome::Admitted { deadline, .. } => deadline,
            other => panic!("expected Admitted, got {other:?}"),
        };
        assert_eq!(
            earlier_deadline, later_deadline,
            "an earlier re-resolution NEVER shortens the deadline (max rule, W4)"
        );

        // The map entry holds the max deadline, and both stores agree.
        let entry = map
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: "refresh.test.".into(),
            })
            .expect("entry present");
        assert_eq!(entry.expires_at, later_deadline);
        // The most recent committed element carries the same (non-shortened) deadline.
        let committed = set.committed();
        assert_eq!(committed.last().unwrap().deadline, later_deadline);
    }

    // ── F2: a refresh that DROPS an IP withdraws its kernel allow-set element ────
    //    (refcount-zero-gated, same transaction) — the map/kernel re-convergence the
    //    audit flagged. A sole-reference dropped IP's element IS withdrawn; a
    //    still-shared dropped IP (a live sibling fqdn vouches it) is RETAINED. ──────

    #[test]
    fn refresh_dropping_a_sole_reference_ip_withdraws_its_allow_set_element_in_the_same_txn() {
        // The F2 finding: on a DNS-rotation refresh the map decrefs a dropped IP but
        // its KERNEL allow-set element was never withdrawn (it lingered until its W2
        // timeout while the map said it was gone). This asserts the element for a
        // sole-reference dropped IP IS withdrawn in the SAME transaction, on the SAME
        // set, keyed byte-exact — and a still-shared dropped IP is RETAINED.
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();

        let ip_x = pub_v4(); // held across the refresh — no-op, retained
        let ip_y = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)); // sole-ref, DROPPED
        let ip_z = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)); // newly added
        let y = to_admitted_addr(ip_y);
        let z = to_admitted_addr(ip_z);

        // First admission resolves to {X, Y} → two elements programmed, both live.
        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&normal_inputs("rotate.test.", vec![ip_x, ip_y]), t0());
        }
        assert_eq!(
            set.committed().len(),
            2,
            "first admission programs both {{X, Y}} elements"
        );
        assert!(
            set.withdrawn().is_empty(),
            "nothing withdrawn on a first admission"
        );

        // A refresh re-resolves to {X, Z}: Y is dropped (sole-reference → refcount 0),
        // Z is newly added, X is held. Y's kernel element MUST be withdrawn in this
        // SAME txn; X is NOT (held); Z is a fresh insert, not a withdraw.
        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            let outcome = txn.admit(&normal_inputs("rotate.test.", vec![ip_x, ip_z]), t0());
            assert!(
                matches!(outcome, AdmissionOutcome::Admitted { .. }),
                "the refresh still admits the surviving + new IPs"
            );
        }

        // EXACTLY one element was withdrawn: the dropped sole-reference IP Y, on the
        // SAME `allow4` set the insert wrote, keyed byte-exact (`to_dst_key`).
        let withdrawn = set.withdrawn();
        assert_eq!(
            withdrawn.len(),
            1,
            "exactly the one dropped sole-reference IP is withdrawn (X held, Z added)"
        );
        assert_eq!(withdrawn[0].set_name, allow_set_name(AddressFamily::V4, 7));
        assert_eq!(
            withdrawn[0].element,
            y.to_dst_key().0,
            "the withdrawn element is the dropped IP Y, keyed byte-exact with its insert"
        );
        assert_eq!(
            withdrawn[0].value_mask_token(),
            SetInsert {
                set_name: allow_set_name(AddressFamily::V4, 7),
                mark_value: compose(Leg::AgentVm, 7),
                mark_mask: DS_MARK_MASK,
                element: y.to_dst_key().0,
                timeout_secs: 0,
                deadline: t0(),
            }
            .value_mask_token(),
            "the withdraw carries the SAME masked per-session mark the insert composed"
        );

        // The reverse-index count for the dropped IP is back to zero, and the LIVE
        // kernel model (programmed minus withdrawn) no longer holds Y but still holds
        // X and Z (one withdraw, no over-delete).
        let dropped_refcount = map.reverse_index().refcount("sess-uuid-1", &y);
        assert_eq!(dropped_refcount, 0, "the dropped IP's refcount is zero");
        let live_elements: std::collections::HashSet<String> =
            set.committed().into_iter().map(|s| s.element).collect();
        assert!(
            !live_elements.contains(&y.to_dst_key().0),
            "the dropped IP's element is gone from the live kernel model"
        );
        assert!(
            live_elements.contains(&z.to_dst_key().0),
            "the newly-added IP Z is live"
        );
    }

    #[test]
    fn refresh_dropping_a_still_shared_ip_does_not_withdraw_its_allow_set_element() {
        // The under-delete bias (W4): a refresh of name-A that drops a SHARED IP S —
        // one a live sibling name-B in the SAME session still holds — must NOT
        // withdraw S's kernel element (refcount stays > 0). Only a refcount-zero drop
        // withdraws. This pins that the withdraw is refcount-GATED, not drop-gated.
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();

        let ip_shared = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)); // held by A and B
        let ip_new = pub_v4(); // A rotates onto this
        let shared = to_admitted_addr(ip_shared);

        // name-B admits the shared IP (so it has a surviving reference).
        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&normal_inputs("b.cdn.test.", vec![ip_shared]), t0());
        }
        // name-A admits the SAME shared IP → refcount(S) == 2.
        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&normal_inputs("a.cdn.test.", vec![ip_shared]), t0());
        }
        assert_eq!(
            map.reverse_index().refcount("sess-uuid-1", &shared),
            2,
            "two distinct names hold the shared IP"
        );
        let withdrawn_before = set.withdrawn().len();

        // name-A refreshes onto a NEW IP, dropping the shared IP. S's refcount drops
        // to 1 (B still holds it) → S is NOT withdrawn (under-delete, W4).
        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&normal_inputs("a.cdn.test.", vec![ip_new]), t0());
        }
        assert_eq!(
            map.reverse_index().refcount("sess-uuid-1", &shared),
            1,
            "the shared IP's refcount drops to 1 — B still references it"
        );
        assert_eq!(
            set.withdrawn().len(),
            withdrawn_before,
            "a still-shared dropped IP is NOT withdrawn — only a refcount-zero drop is"
        );
    }

    // ── W4 re-admission refcount discipline: the DNS-2b reverse index counts
    //    DISTINCT-(session, fqdn) membership over an IP, so a re-admit (refresh) is a
    //    refcount NO-OP, a sole-reference IP frees EXACTLY once on revoke, and a
    //    shared-CDN IP survives a sibling name's revoke (bias to under-delete, W4).
    //    These drive the PRODUCTION `InMemoryAdmissionMap::admit`/`revoke` paths
    //    directly (no synthetic short-circuit of the counter logic). ───────────────

    /// Admit a `(session, original_query_fqdn)` over a single IP through the
    /// production map `admit` — the shape the W1/W2 transaction writes (the entry's
    /// `admitted_ips` is the membership of THIS name).
    fn admit_one_ip(map: &mut MemMap, session: &str, fqdn: &str, ip: IpAddr) {
        let entry = AdmissionEntry {
            admitted_ips: vec![to_admitted_addr(ip)],
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
            expires_at: t0(),
            admitted_at: t0(),
            provenance: provenance(),
        };
        map.admit(
            AdmissionKey {
                session_uuid: session.into(),
                original_query_fqdn: fqdn.into(),
            },
            entry,
        )
        .expect("admit succeeds");
    }

    #[test]
    fn k_refreshes_of_one_name_then_revoke_frees_the_sole_reference_ip_exactly_once() {
        // The W4 refresh case: a single logical admission re-admitted K times (each
        // refresh re-resolves the SAME (session, original-fqdn, ip)). The reverse
        // index counts DISTINCT-name membership, so after K refreshes the count for
        // (session, ip) is 1, NOT K. A single revoke then decrefs to ZERO and the
        // sole-reference IP is freed EXACTLY once — no residual K-1 leak (the IP that
        // would otherwise linger in the allow set until the W2 deadline expired), no
        // over-/double-free.
        let mut map = MemMap::default();
        let ip = pub_v4();
        let addr = to_admitted_addr(ip);
        let session = "sess-uuid-1";
        let fqdn = "refresh.test.";

        const K: u32 = 5;
        for _ in 0..K {
            admit_one_ip(&mut map, session, fqdn, ip);
        }

        // One distinct name references the IP → refcount is 1 after K refreshes
        // (a re-admit of an unchanged IP set is a refcount NO-OP).
        assert_eq!(
            map.reverse_index().refcount(session, &addr),
            1,
            "K refreshes of ONE name count as 1 distinct-name reference, not K"
        );

        // A single revoke frees the sole-reference IP exactly once (refcount → 0).
        let key = AdmissionKey {
            session_uuid: session.into(),
            original_query_fqdn: fqdn.into(),
        };
        let freed = map.revoke(&key).expect("revoke succeeds");
        assert_eq!(
            freed,
            vec![addr.clone()],
            "the sole-reference IP is freed exactly once on the single revoke"
        );
        assert_eq!(
            map.reverse_index().refcount(session, &addr),
            0,
            "no residual K-1 leak — the refcount is back to zero"
        );

        // The entry is gone, and a second revoke is an idempotent empty success that
        // does NOT over-free (saturating decref never underflows).
        assert!(map.lookup(&key).is_none(), "the map entry is revoked");
        assert!(
            map.revoke(&key).expect("idempotent revoke").is_empty(),
            "a second revoke frees nothing (no over-free / double-free)"
        );
        assert_eq!(map.reverse_index().refcount(session, &addr), 0);
    }

    #[test]
    fn shared_cdn_ip_survives_a_sibling_revoke_across_refreshes() {
        // A shared-CDN IP X is held by two DISTINCT names in one session: name-A
        // (refreshed K times) and name-B (admitted once). The reverse index counts
        // distinct-name membership, so X's refcount is 2 (A and B), unaffected by
        // A's K refreshes. Revoking A drops X's count to 1 — X is NOT freed (B still
        // holds it: bias to under-delete, W4). Revoking B then frees X exactly once.
        let mut map = MemMap::default();
        let shared = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let shared_addr = to_admitted_addr(shared);
        let session = "sess-uuid-1";
        let name_a = "a.cdn.test.";
        let name_b = "b.cdn.test.";

        // name-A refreshed K times over the shared IP; name-B once over the same IP.
        const K: u32 = 4;
        for _ in 0..K {
            admit_one_ip(&mut map, session, name_a, shared);
        }
        admit_one_ip(&mut map, session, name_b, shared);

        // Two DISTINCT names reference X → refcount 2 (A's K refreshes are no-ops).
        assert_eq!(
            map.reverse_index().refcount(session, &shared_addr),
            2,
            "two distinct names hold the shared IP — K refreshes of A do not inflate it"
        );

        // Revoke A: the shared IP is NOT freed (B still references it).
        let freed_a = map
            .revoke(&AdmissionKey {
                session_uuid: session.into(),
                original_query_fqdn: name_a.into(),
            })
            .expect("revoke A");
        assert!(
            freed_a.is_empty(),
            "the shared-CDN IP is NOT freed by A's revoke — B still holds it (under-delete, W4)"
        );
        assert_eq!(
            map.reverse_index().refcount(session, &shared_addr),
            1,
            "the shared IP's refcount drops to 1 (B) — exactly one decref for A"
        );

        // Revoke B: now the last reference drops, X is freed exactly once.
        let freed_b = map
            .revoke(&AdmissionKey {
                session_uuid: session.into(),
                original_query_fqdn: name_b.into(),
            })
            .expect("revoke B");
        assert_eq!(
            freed_b,
            vec![shared_addr.clone()],
            "the shared IP is freed exactly once, only after the LAST name revokes"
        );
        assert_eq!(map.reverse_index().refcount(session, &shared_addr), 0);
    }

    #[test]
    fn a_refresh_that_changes_the_ip_set_decrefs_dropped_and_increfs_added() {
        // A re-resolution can change the resolved address set (DNS rotation). The
        // refresh refcounts by the IP-SET MEMBERSHIP DELTA of the name: an IP the
        // name no longer references is decref'd (and frees if it was sole-reference),
        // an IP the name newly references is incref'd. An IP held across the change
        // is a NO-OP. This is the general case the sole-reference and shared-survivor
        // tests above specialize.
        let mut map = MemMap::default();
        let session = "sess-uuid-1";
        let fqdn = "rotate.test.";
        let ip_x = pub_v4();
        let ip_y = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let ip_z = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let x = to_admitted_addr(ip_x);
        let y = to_admitted_addr(ip_y);
        let z = to_admitted_addr(ip_z);

        // First admission resolves to {X, Y}.
        let admit_set = |map: &mut MemMap, ips: Vec<IpAddr>| {
            let entry = AdmissionEntry {
                admitted_ips: ips.iter().map(|a| to_admitted_addr(*a)).collect(),
                admission_type: AdmissionType::Normal,
                real_targets: vec![],
                expires_at: t0(),
                admitted_at: t0(),
                provenance: provenance(),
            };
            map.admit(
                AdmissionKey {
                    session_uuid: session.into(),
                    original_query_fqdn: fqdn.into(),
                },
                entry,
            )
            .expect("admit succeeds");
        };
        admit_set(&mut map, vec![ip_x, ip_y]);
        assert_eq!(map.reverse_index().refcount(session, &x), 1);
        assert_eq!(map.reverse_index().refcount(session, &y), 1);
        assert_eq!(map.reverse_index().refcount(session, &z), 0);

        // A refresh re-resolves to {X, Z}: Y is dropped (decref → 0), Z is added
        // (incref → 1), X is held across the change (NO-OP, stays 1).
        admit_set(&mut map, vec![ip_x, ip_z]);
        assert_eq!(
            map.reverse_index().refcount(session, &x),
            1,
            "X is held across the refresh — a refcount no-op"
        );
        assert_eq!(
            map.reverse_index().refcount(session, &y),
            0,
            "Y is dropped by the refresh — decref'd to zero"
        );
        assert_eq!(
            map.reverse_index().refcount(session, &z),
            1,
            "Z is newly referenced by the refresh — incref'd to one"
        );

        // Revoking the name now frees exactly its CURRENT membership {X, Z}, each
        // once — Y was already freed by the refresh's decref, so it is not double-freed.
        let mut freed = map
            .revoke(&AdmissionKey {
                session_uuid: session.into(),
                original_query_fqdn: fqdn.into(),
            })
            .expect("revoke succeeds");
        freed.sort_by(|a, b| a.octets.cmp(&b.octets));
        let mut expected = vec![x.clone(), z.clone()];
        expected.sort_by(|a, b| a.octets.cmp(&b.octets));
        assert_eq!(
            freed, expected,
            "revoke frees exactly the current membership {{X, Z}}, each once; Y is not double-freed"
        );
        assert_eq!(map.reverse_index().refcount(session, &x), 0);
        assert_eq!(map.reverse_index().refcount(session, &z), 0);
    }

    #[test]
    fn a_duplicate_ip_within_one_admission_counts_and_frees_as_one_distinct_reference() {
        // A malformed/duplicated answer can carry the SAME plumbable IP in two A RRs,
        // so one name's `admitted_ips` may hold the IP twice. The `(session, ip)`
        // refcount is DISTINCT-name membership, not a raw RR count, so admit increfs
        // the duplicated IP ONCE (the count is 1, not 2) and revoke decrefs it ONCE.
        // This pins the admit/revoke SYMMETRY: were revoke to decref per raw element,
        // a duplicate would over-free a shared-CDN IP a sibling still holds (a W4 /
        // bias-to-under-delete violation) and double-list it in `freed`.
        let mut map = MemMap::default();
        let dup_ip = pub_v4();
        let dup = to_admitted_addr(dup_ip);
        let session = "sess-uuid-1";

        // name-A admits the SAME IP twice in one entry; name-B (a sibling) admits it
        // once. Distinct-name membership over the IP is 2 (A and B), NOT 3.
        let dup_entry = AdmissionEntry {
            admitted_ips: vec![dup.clone(), dup.clone()],
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
            expires_at: t0(),
            admitted_at: t0(),
            provenance: provenance(),
        };
        map.admit(
            AdmissionKey {
                session_uuid: session.into(),
                original_query_fqdn: "dup.test.".into(),
            },
            dup_entry,
        )
        .expect("admit dup succeeds");
        admit_one_ip(&mut map, session, "sibling.test.", dup_ip);

        assert_eq!(
            map.reverse_index().refcount(session, &dup),
            2,
            "a duplicate IP within one name counts as ONE distinct reference (A), plus B = 2"
        );

        // Revoke A: the IP is NOT freed (B still holds it) and the count drops by
        // EXACTLY ONE — a raw per-element decref would have driven it 2 → 1 → 0 and
        // over-freed a sibling-held IP.
        let freed_a = map
            .revoke(&AdmissionKey {
                session_uuid: session.into(),
                original_query_fqdn: "dup.test.".into(),
            })
            .expect("revoke A");
        assert!(
            freed_a.is_empty(),
            "the duplicated IP is NOT freed by A's revoke — B still holds it (under-delete)"
        );
        assert_eq!(
            map.reverse_index().refcount(session, &dup),
            1,
            "A's revoke decrefs the duplicated IP exactly once — count drops 2 → 1, not to 0"
        );

        // Revoke B: now the last reference drops and the IP frees EXACTLY once (not
        // double-listed).
        let freed_b = map
            .revoke(&AdmissionKey {
                session_uuid: session.into(),
                original_query_fqdn: "sibling.test.".into(),
            })
            .expect("revoke B");
        assert_eq!(
            freed_b,
            vec![dup.clone()],
            "the IP frees exactly once on the last reference — never double-listed"
        );
        assert_eq!(map.reverse_index().refcount(session, &dup), 0);
    }

    #[test]
    fn expiry_predicate_gates_new_flows_only() {
        // is_expired_at is the NEW-flow gate; it is a predicate on the entry, not a
        // self-eviction. A lookup after the deadline still returns the entry (the
        // map never self-evicts) — TLS-1's check is what refuses a new flow; an
        // in-flight flow is never severed by this predicate (W4).
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let inputs = normal_inputs("gate.test.", vec![pub_v4()]);
        let deadline = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            match txn.admit(&inputs, t0()) {
                AdmissionOutcome::Admitted { deadline, .. } => deadline,
                other => panic!("expected Admitted, got {other:?}"),
            }
        };
        let entry = map
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: "gate.test.".into(),
            })
            .expect("entry present, never self-evicted");
        // Before the deadline: not expired (a new flow is gated through).
        assert!(!entry.is_expired_at(Instant::from_unix_nanos(deadline.unix_nanos - 1)));
        // At/after the deadline: expired — a NEW flow is refused; the entry is still
        // present (no self-eviction).
        assert!(entry.is_expired_at(deadline));
        assert!(map
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: "gate.test.".into(),
            })
            .is_some());
    }

    // ── W5 / DNS-4: martians are scrubbed; the cache path still admits ──────────

    #[test]
    fn dns4_filter_scrubs_martians_and_keeps_public() {
        // v4 martians.
        assert!(
            !is_plumbable(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            "loopback"
        );
        assert!(
            !is_plumbable(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            "rfc1918 10/8"
        );
        assert!(
            !is_plumbable(IpAddr::V4(Ipv4Addr::new(172, 16, 5, 5))),
            "rfc1918 172.16/12"
        );
        assert!(
            !is_plumbable(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            "rfc1918 192.168/16"
        );
        assert!(
            !is_plumbable(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))),
            "link-local"
        );
        assert!(
            !is_plumbable(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            "cgnat 100.64/10"
        );
        assert!(
            !is_plumbable(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))),
            "unspecified"
        );
        assert!(
            !is_plumbable(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))),
            "multicast"
        );
        assert!(
            !is_plumbable(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))),
            "reserved 240/4"
        );
        // public is plumbable.
        assert!(is_plumbable(pub_v4()), "a public address is plumbable");
        assert!(
            is_plumbable(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))),
            "198.18/15 (synthetic/benchmark pool) is NOT scrubbed by the v4 filter"
        );

        // v6 martians and the IPv4-mapped unwrap.
        assert!(
            !is_plumbable(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            "::1 loopback"
        );
        assert!(
            !is_plumbable(IpAddr::V6("fe80::1".parse().unwrap())),
            "fe80::/10 link-local"
        );
        assert!(
            !is_plumbable(IpAddr::V6("fc00::1".parse().unwrap())),
            "fc00::/7 ula"
        );
        assert!(
            !is_plumbable(IpAddr::V6("ff02::1".parse().unwrap())),
            "ff00::/8 multicast"
        );
        // ::ffff:127.0.0.1 must be unwrapped and rejected as a v4 loopback martian.
        assert!(
            !is_plumbable(IpAddr::V6("::ffff:127.0.0.1".parse().unwrap())),
            "IPv4-mapped loopback is unwrapped and scrubbed"
        );
        // ::ffff:93.184.216.34 unwraps to a public v4 → plumbable.
        assert!(is_plumbable(IpAddr::V6(
            "::ffff:93.184.216.34".parse().unwrap()
        )));
        // A global v6 is plumbable.
        assert!(is_plumbable(IpAddr::V6("2606:4700::1".parse().unwrap())));
    }

    #[test]
    fn an_all_martian_answer_is_refused_no_store_touched() {
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        // Every resolved address is a martian.
        let inputs = normal_inputs(
            "rebind.test.",
            vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            ],
        );
        let outcome = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0())
        };
        assert_eq!(outcome, AdmissionOutcome::NoPlumbableAddress);
        // No store touched — the filter runs ahead of any insert (W5).
        assert!(set.programmed().is_empty());
        assert!(live.is_empty());
        assert!(map
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: "rebind.test.".into(),
            })
            .is_none());
    }

    #[test]
    fn a_mixed_answer_admits_only_the_plumbable_addresses() {
        // A rebinding-style answer mixes a public IP with a private one; only the
        // public IP is admitted (the allow-set never silently widens to the
        // martian, doc 06 (c) row).
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let inputs = normal_inputs(
            "mixed.test.",
            vec![pub_v4(), IpAddr::V4(Ipv4Addr::new(192, 168, 0, 9))],
        );
        let outcome = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0())
        };
        assert!(matches!(outcome, AdmissionOutcome::Admitted { .. }));
        // Exactly ONE element (the public IP), one map IP, one live record.
        assert_eq!(set.committed().len(), 1, "only the public IP is plumbed");
        let entry = map
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: "mixed.test.".into(),
            })
            .expect("entry present");
        assert_eq!(entry.admitted_ips.len(), 1);
        assert_eq!(entry.admitted_ips[0], to_admitted_addr(pub_v4()));
        assert_eq!(live.len(), 1);
    }

    #[test]
    fn cache_path_still_admits_a_repeat_resolution_traverses_the_full_path() {
        // W3 full-path: a cached/repeat answer for an ALREADY-admitted name still
        // traverses the full admission path (filter + set insert + map write). The
        // second admit re-programs the set element and refreshes the map entry — it
        // does NOT bypass admission just because the name is live.
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let inputs = normal_inputs("cached.test.", vec![pub_v4()]);

        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            assert!(matches!(
                txn.admit(&inputs, t0()),
                AdmissionOutcome::Admitted { .. }
            ));
        }
        let programmed_after_first = set.programmed().len();
        assert_eq!(programmed_after_first, 1);

        // A second (cache-hit-shaped) answer for the same name at a later time:
        // the full path runs again — another set program, another map write.
        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            assert!(matches!(
                txn.admit(&inputs, Instant::from_unix_nanos(1_050 * NANOS_PER_SEC)),
                AdmissionOutcome::Admitted { .. }
            ));
        }
        assert_eq!(
            set.programmed().len(),
            2,
            "the cache path re-programs the set element — admission is NOT bypassed (W3)"
        );
        // Two live records now reference the IP (refcount raised) — the §5.4 sweep
        // reads the count of records holding an IP.
        assert_eq!(
            live.len(),
            2,
            "the repeat resolution raised the IP refcount"
        );
    }

    // ── Synthetic (phase B) admission: synthetic v4 → allow4, real v6 carried ───

    #[test]
    fn synthetic_admission_writes_allow4_and_carries_real_v6_targets() {
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let mut inputs = normal_inputs(
            "synthetic.test.",
            vec![IpAddr::V4(Ipv4Addr::new(198, 18, 0, 5))],
        );
        inputs.admission_type = AdmissionType::Synthetic;
        inputs.real_targets = vec![IpAddr::V6("2606:4700::1".parse().unwrap())];

        let outcome = {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0())
        };
        assert!(matches!(outcome, AdmissionOutcome::Admitted { .. }));
        // The synthetic v4 goes into the PER-SESSION allow4_<idx> (idx=7 — the
        // normal_inputs session_index), the single-source `allow_set_name`, NOT a
        // flat shared `allow4` (D3/D4).
        let committed = set.committed();
        assert_eq!(committed.len(), 1);
        assert_eq!(
            committed[0].set_name,
            allow_set_name(AddressFamily::V4, 7),
            "synthetic v4 fills the per-session allow4_7"
        );
        assert_eq!(committed[0].set_name, "allow4_7");
        // … and the entry carries the real v6 targets + the synthetic admission type.
        let entry = map
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: "synthetic.test.".into(),
            })
            .expect("entry present");
        assert_eq!(entry.admission_type, AdmissionType::Synthetic);
        assert_eq!(entry.real_targets.len(), 1);
        assert_eq!(entry.real_targets[0].family, AddressFamily::V6);
    }

    // ── D3/D4: the gate FILLS the PER-SESSION allow4_<idx> / allow6_<idx>, byte-
    //    exact with the single-source `ds_contracts::session::allow_set_name` ds-nft's
    //    `InstantiateSessionNFT` CREATES — NOT a flat shared `allow4` (the §2.5/D3
    //    set-name divergence that fails egress admission closed). ─────────────────

    #[test]
    fn insert_fills_the_per_session_allow4_idx_byte_exact_with_allow_set_name() {
        // A representative non-trivial host_session_index (NOT 0, NOT the test default
        // 7) so the `<idx>` token is load-bearing. The gate must FILL `allow4_<idx>` —
        // the exact name ds-nft's InstantiateSessionNFT creates for the same index.
        const IDX: u32 = 42;
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let mut inputs = normal_inputs("per-session.test.", vec![pub_v4()]);
        inputs.session_index = IDX;

        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            assert!(matches!(
                txn.admit(&inputs, t0()),
                AdmissionOutcome::Admitted { .. }
            ));
        }

        let committed = set.committed();
        assert_eq!(committed.len(), 1, "one v4 element filled");
        // Byte-exact with the single-source contract fn — the SECURITY-CRITICAL
        // agreement: the name the gate fills == the name ds-nft creates.
        assert_eq!(
            committed[0].set_name,
            allow_set_name(AddressFamily::V4, IDX),
            "the gate FILLS the per-session name `ds_contracts::session::allow_set_name` produces"
        );
        assert_eq!(
            committed[0].set_name, "allow4_42",
            "the per-session v4 set name is `allow4_<host_session_index>`"
        );
        // NO flat shared `allow4` survives — the set name carries the index suffix.
        assert_ne!(
            committed[0].set_name, "allow4",
            "no flat shared `allow4` fill survives (the D3 divergence is closed)"
        );
    }

    #[test]
    fn insert_fills_the_per_session_allow6_idx_for_a_v6_target() {
        // The v6 (dormant phase-C) path derives its name through the SAME single
        // source: a v6 terminal address fills `allow6_<idx>`, byte-exact with
        // `allow_set_name(V6, idx)`. (A normal admission can carry a global v6, doc 11
        // §3.5; the leg is shaped from the start so a dual-family admit is one txn.)
        const IDX: u32 = 42;
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let mut inputs = normal_inputs(
            "v6.test.",
            vec![IpAddr::V6("2606:4700::1".parse().unwrap())],
        );
        inputs.session_index = IDX;

        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            assert!(matches!(
                txn.admit(&inputs, t0()),
                AdmissionOutcome::Admitted { .. }
            ));
        }

        let committed = set.committed();
        assert_eq!(committed.len(), 1, "one v6 element filled");
        assert_eq!(
            committed[0].set_name,
            allow_set_name(AddressFamily::V6, IDX),
            "the v6 path fills the per-session `allow6_<idx>` via the SAME single source"
        );
        assert_eq!(committed[0].set_name, "allow6_42");
    }

    #[test]
    fn distinct_sessions_fill_distinct_per_session_sets() {
        // Per-session ISOLATION: two host_session_index values fill DISTINCT set names
        // (`allow4_1` vs `allow4_2`) — the property a flat shared `allow4` would
        // collapse (the §2.5/D4 isolation guarantee).
        let one = {
            let mut map = MemMap::default();
            let set = RecordingSetProgrammer::new();
            let live = LiveAdmissions::new();
            let mut inputs = normal_inputs("a.test.", vec![pub_v4()]);
            inputs.session_index = 1;
            {
                let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
                txn.admit(&inputs, t0());
            }
            set.committed()[0].set_name.clone()
        };
        let two = {
            let mut map = MemMap::default();
            let set = RecordingSetProgrammer::new();
            let live = LiveAdmissions::new();
            let mut inputs = normal_inputs("a.test.", vec![pub_v4()]);
            inputs.session_index = 2;
            {
                let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
                txn.admit(&inputs, t0());
            }
            set.committed()[0].set_name.clone()
        };
        assert_eq!(one, "allow4_1");
        assert_eq!(two, "allow4_2");
        assert_ne!(one, two, "distinct sessions never share an allow-set name");
    }

    // ── Provenance (POL-3) is preserved on the admission entry ──────────────────

    #[test]
    fn pol3_provenance_is_preserved_on_the_admission_entry() {
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let inputs = normal_inputs("prov.test.", vec![pub_v4()]);
        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0());
        }
        let entry = map
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: "prov.test.".into(),
            })
            .expect("entry present");
        assert_eq!(entry.provenance, provenance());
    }

    // ── The NFT-3 element carries the masked mark token, never a bare value ─────

    #[test]
    fn set_element_carries_the_masked_mark_token_not_a_bare_value() {
        let mut map = MemMap::default();
        let set = RecordingSetProgrammer::new();
        let live = LiveAdmissions::new();
        let inputs = normal_inputs("mark.test.", vec![pub_v4()]);
        {
            let mut txn = AdmissionTransaction::new(&mut map, &set, &live);
            txn.admit(&inputs, t0());
        }
        let committed = set.committed();
        let token = committed[0].value_mask_token();
        // The token always carries the frozen DS_MARK_MASK suffix — a bare-index
        // value can never reach the kernel.
        assert!(
            token.ends_with(&format!("/0x{:x}", DS_MARK_MASK)),
            "token={token}"
        );
        assert_eq!(committed[0].mark_mask, DS_MARK_MASK);
        // The element value is the canonical DstKey form of the IP (the same key
        // shape the reverse index and a later flush_session::DstFilter::Only count).
        assert_eq!(
            committed[0].element,
            to_admitted_addr(pub_v4()).to_dst_key().0
        );
    }

    // ── The PRODUCTION `impl NftSetProgrammer for ds_nft::NftWriter<B>`: the W1
    //    set-program → `ds_nft::refresh::refresh_batch` / `backend().apply_batch`
    //    map, asserted FIELD-FOR-FIELD against the ds-nft RECORDING backend (no live
    //    kernel — `cargo test --offline` never touches the kernel). The real
    //    `SpawnBackend` write is the `#[ignore]`/`DS_NFTGATE_LIVE`-gated test below. ──

    use ds_nft::backend::RecordingBackend;
    use ds_nft::NftWriter;

    /// One [`SetInsert`] for `pub_v4()` admitted at `t0()` — the SAME shape the
    /// transaction builds (masked mark over `compose(AgentVm, idx)`, `to_dst_key`
    /// element, the W2 deadline as both an absolute instant and a relative timeout).
    fn v4_insert(idx: u32, timeout_secs: u32) -> SetInsert {
        let addr = to_admitted_addr(pub_v4());
        SetInsert {
            set_name: allow_set_name(AddressFamily::V4, idx),
            mark_value: compose(Leg::AgentVm, idx),
            mark_mask: DS_MARK_MASK,
            element: addr.to_dst_key().0,
            timeout_secs,
            deadline: Instant::from_unix_nanos((1_000 + u64::from(timeout_secs)) * NANOS_PER_SEC),
        }
    }

    #[test]
    fn production_programmer_emits_the_add_element_timeout_batch_field_for_field() {
        // `program` renders the `add element … timeout Ns` batch via ds-nft's
        // `refresh_batch` and applies it through the backend — byte-exact with the
        // SetInsert: the SAME set name, the masked value/mask token (recovered from
        // mark_value, never re-derived), the `to_dst_key` element, and the W2 deadline
        // as the element's `timeout Ns`.
        let writer = NftWriter::new(RecordingBackend::new());
        let insert = v4_insert(7, 360);
        writer.program(&insert).expect("program applies");

        let batches = writer.backend().batches();
        assert_eq!(batches.len(), 1, "one add-element batch applied");
        let text = &batches[0].text;
        // The W2 deadline rides the element timeout (360s = clamp+grace from the txn).
        assert!(text.contains("timeout 360s"), "batch={text}");
        // The set name + the `to_dst_key` element are byte-exact with the SetInsert.
        // The set name is the PER-SESSION `allow4_<idx>` (idx=7 here), the single-
        // source `allow_set_name`, NOT a flat shared `allow4` (D3/D4).
        assert!(
            text.contains("add element inet ds_filter allow4_7"),
            "batch={text}"
        );
        assert_eq!(
            insert.set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, 7),
            "the insert names the per-session allow4_<idx>, byte-exact with ds-nft's creator"
        );
        assert!(
            text.contains(&ds_contracts::flush::DstKey(insert.element.clone()).address_literal()),
            "batch={text}"
        );
        // The masked value/mask token equals the SetInsert's — recovered, not re-derived.
        assert!(
            text.contains(&insert.value_mask_token()),
            "batch carries the SetInsert's masked token byte-exact: {text}"
        );
        // The token always carries the frozen DS_MARK_MASK suffix — never a bare value.
        assert!(
            text.contains(&format!("/0x{:x}", DS_MARK_MASK)),
            "batch={text}"
        );
        // The recovered ds-nft MarkMatch value equals the txn-composed mark_value (the
        // decompose → for_leg round-trip is the inverse of compose, byte-exact).
        let mark = mark_match_of(&insert).expect("mark recovers");
        assert_eq!(mark.value(), insert.mark_value);
        assert_eq!(mark.to_value_mask_token(), insert.value_mask_token());
    }

    #[test]
    fn production_programmer_fails_closed_on_a_backend_error() {
        // A backend `apply_batch` failure is the W1 fail-closed signal: `program`
        // returns `SetProgrammingFailed` (the transaction then withholds the answer
        // and rolls back), never an Ok with a half-written element.
        let writer = NftWriter::new(RecordingBackend::new());
        writer
            .backend()
            .arm_error(ds_nft::backend::BackendError::new("EPERM: CAP_NET_ADMIN"));
        let err = writer
            .program(&v4_insert(7, 360))
            .expect_err("must fail closed");
        assert_eq!(err, AdmissionError::SetProgrammingFailed);
    }

    #[test]
    fn production_programmer_withdraw_emits_the_delete_element_batch() {
        // `withdraw` (the W1 rollback compensation) applies a `delete element` batch in
        // the SAME shape ds-nft's DeleteAdd fallback embeds (same table, set, element),
        // so the compensating delete agrees byte-exact with the insert it undoes.
        let writer = NftWriter::new(RecordingBackend::new());
        let insert = v4_insert(7, 360);
        writer.withdraw(&insert).expect("withdraw applies");
        let batches = writer.backend().batches();
        assert_eq!(batches.len(), 1);
        let text = &batches[0].text;
        // The withdraw targets the SAME per-session `allow4_<idx>` the insert filled.
        assert!(
            text.contains("delete element inet ds_filter allow4_7"),
            "batch={text}"
        );
        assert!(
            text.contains(&ds_contracts::flush::DstKey(insert.element.clone()).address_literal()),
            "batch={text}"
        );
        // The delete names NO timeout (it removes the element, not refreshes it).
        assert!(
            !text.contains("timeout"),
            "a delete carries no timeout: {text}"
        );
    }

    #[test]
    fn production_writer_drives_the_w1_w2_lockstep_through_with_parts() {
        // The production `ds_nft::NftWriter` binds as the set programmer behind the
        // `AdmissionStores::with_parts` seam (the seam main would use behind
        // DS_NFTGATE_LIVE). Run the insert-then-answer transaction over it: the W2
        // deadline lands on BOTH the map entry's `expires_at` AND the kernel element's
        // `timeout Ns`, byte-exact element key, with no live kernel (recording backend).
        // The test mirrors the production `with_parts(Arc<S>)` seam; the recording
        // backend is intentionally not `Sync` (no live kernel), so the Arc is loop-shape
        // only, never crossed between threads here.
        #[allow(clippy::arc_with_non_send_sync)]
        let writer = Arc::new(NftWriter::new(RecordingBackend::new()));
        let live = LiveAdmissions::new();
        let stores = AdmissionStores::with_parts(writer.clone(), live);
        let inputs = normal_inputs("prod.test.", vec![pub_v4()]);

        let outcome = stores.run_admission(&inputs, t0());
        let deadline = match outcome {
            AdmissionOutcome::Admitted { deadline, .. } => deadline,
            other => panic!("expected Admitted, got {other:?}"),
        };

        // The map entry carries the SAME deadline (W2 lockstep).
        let entry = stores
            .lookup(&AdmissionKey {
                session_uuid: "sess-uuid-1".into(),
                original_query_fqdn: "prod.test.".into(),
            })
            .expect("entry present");
        assert_eq!(entry.expires_at, deadline);

        // The production writer programmed exactly one `add element … timeout Ns` batch,
        // and the timeout equals the relative whole-second form of that deadline
        // (deadline = t0 + clamp(300,60,900) + grace(60) = 1000+300+60 → timeout 360s).
        let batches = writer.backend().batches();
        assert_eq!(
            batches.len(),
            1,
            "one kernel-shaped batch from the txn lockstep"
        );
        assert!(
            batches[0].text.contains("timeout 360s"),
            "{}",
            batches[0].text
        );
        assert!(
            batches[0]
                .text
                .contains(&to_admitted_addr(pub_v4()).to_dst_key().address_literal()),
            "the rendered element is the nft-accepted address literal, not the to_dst_key hex"
        );
    }

    // The object-safe fingerprint→sessions resolver trait `FleetRevocationBook` implements — the
    // per-session fingerprint tests read the book's rows through it.
    use ds_policy_snapshot::SessionAdmissionBook;

    /// A NORMAL admission input on an explicit `(session_uuid, session_index)` — the per-session
    /// fingerprint tests admit two DISTINCT sessions to prove the book keys them apart.
    fn session_inputs(session_uuid: &str, index: u32, fqdn: &str) -> AdmissionInputs {
        AdmissionInputs {
            session_uuid: session_uuid.into(),
            session_index: index,
            original_query_fqdn: fqdn.into(),
            terminal_addrs: vec![pub_v4()],
            chain_min_ttl: 300,
            ttl_floor: FLOOR,
            ttl_ceil: CEIL,
            grace: GRACE,
            provenance: provenance(),
            admission_type: AdmissionType::Normal,
            real_targets: vec![],
        }
    }

    #[test]
    fn two_distinct_session_fingerprints_produce_distinct_book_keys() {
        // DELIVERABLE (2): the live PER-SESSION fingerprint feed replaces the single-session
        // stand-in — each admitting session is recorded under its OWN scoped-token fingerprint
        // resolved at admission time, so two sessions admitted under two distinct tokens key two
        // DISTINCT fleet-book rows (a per-token revocation then severs only its own sessions).
        let resolver: FleetFingerprintResolver =
            Arc::new(|session_uuid: &str| match session_uuid {
                "sess-a" => Some("fp-a".to_string()),
                "sess-b" => Some("fp-b".to_string()),
                // A session the live feed has no scoped token for records nothing (fail-open).
                _ => None,
            });
        let stores = AdmissionStores::new()
            .with_fleet_recording(Some("host-x".to_string()), None)
            .with_fleet_fingerprint_resolver(resolver);
        let book = stores.fleet_revocation_book();

        // Two distinct sessions admit under two distinct tokens.
        assert!(matches!(
            stores.run_admission(&session_inputs("sess-a", 3, "a.example.test."), t0()),
            AdmissionOutcome::Admitted { .. }
        ));
        assert!(matches!(
            stores.run_admission(&session_inputs("sess-b", 4, "b.example.test."), t0()),
            AdmissionOutcome::Admitted { .. }
        ));

        // Two DISTINCT book keys, each resolving to exactly its own session (not the other's).
        assert_eq!(book.len(), 2, "each session keyed its own fingerprint row");
        let a = book.sessions_for_fingerprint("fp-a");
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].session_uuid, "sess-a");
        assert_eq!(a[0].host_session_index, 3);
        assert_eq!(
            a[0].host_id, "host-x",
            "the host id from with_fleet_recording is retained"
        );
        let b = book.sessions_for_fingerprint("fp-b");
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].session_uuid, "sess-b");
        assert_eq!(b[0].host_session_index, 4);

        // A session the feed has no fingerprint for records NOTHING (fail-open, no cross-attribution).
        assert!(matches!(
            stores.run_admission(&session_inputs("sess-unmapped", 5, "c.example.test."), t0()),
            AdmissionOutcome::Admitted { .. }
        ));
        assert_eq!(book.len(), 2, "an unmapped session adds no book row");
    }

    #[test]
    fn fixed_fingerprint_still_records_every_session_under_one_key() {
        // Back-compat: the single-session `Fixed` stand-in (the pre-existing `with_fleet_recording`
        // fingerprint) still records EVERY admitted session under the ONE fingerprint — the
        // per-session resolver is additive, not a behavior change for the fixed path.
        let stores = AdmissionStores::new()
            .with_fleet_recording(Some("host-x".to_string()), Some("fp-fixed".to_string()));
        let book = stores.fleet_revocation_book();
        assert!(matches!(
            stores.run_admission(&session_inputs("sess-a", 1, "a.example.test."), t0()),
            AdmissionOutcome::Admitted { .. }
        ));
        assert!(matches!(
            stores.run_admission(&session_inputs("sess-b", 2, "b.example.test."), t0()),
            AdmissionOutcome::Admitted { .. }
        ));
        assert_eq!(book.len(), 1, "one fixed fingerprint keys both sessions");
        assert_eq!(book.sessions_for_fingerprint("fp-fixed").len(), 2);
    }

    #[test]
    fn no_fingerprint_source_records_nothing() {
        // The pre-token-plumbing default (`None` source) records NOTHING — byte-identical to today.
        let stores = AdmissionStores::new();
        let book = stores.fleet_revocation_book();
        assert!(matches!(
            stores.run_admission(&session_inputs("sess-a", 1, "a.example.test."), t0()),
            AdmissionOutcome::Admitted { .. }
        ));
        assert!(
            book.is_empty(),
            "no fingerprint wired → the fleet book stays empty"
        );
    }

    /// The REAL-KERNEL programmer proof — `#[ignore]`-and-`DS_NFTGATE_LIVE`-gated,
    /// CI/MANUAL-ONLY. The sandbox/CI kernel has no loadable nf_conntrack + restricted
    /// netlink, so this NEVER runs on `cargo test --offline`; an operator runs it on an
    /// M0 host (root / CAP_NET_ADMIN, the `inet ds_filter` table + `allow4` set
    /// present) with `DS_NFTGATE_LIVE=1 cargo test … -- --ignored
    /// production_writer_programs_a_real_allow4_element`. It programs a real allow4
    /// element carrying the W2 deadline as the kernel `timeout Ns`, then withdraws it,
    /// asserting both apply through the production `SpawnBackend` without error.
    #[test]
    #[ignore = "live-kernel: needs DS_NFTGATE_LIVE + root/CAP_NET_ADMIN + the inet ds_filter allow4 set (M0 host, CI/manual-only)"]
    fn production_writer_programs_a_real_allow4_element() {
        if std::env::var_os("DS_NFTGATE_LIVE").is_none() {
            eprintln!(
                "skipping live-kernel programmer test: DS_NFTGATE_LIVE unset (CI/manual-only)"
            );
            return;
        }
        let writer = NftWriter::new(ds_nft::backend::SpawnBackend::new());
        let insert = v4_insert(7, 360);
        // The W2 deadline rides the kernel element's `timeout Ns`; a real ≥6.12 host
        // takes the in-place update, a pre-6.12 host the delete+add fallback (probed).
        writer
            .program(&insert)
            .expect("real allow4 element programmed (timeout = W2 deadline)");
        writer
            .withdraw(&insert)
            .expect("real allow4 element withdrawn (zero residue)");
    }
}
