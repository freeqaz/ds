// SPDX-License-Identifier: Apache-2.0

//! NFT-5 per-session `ct mark` flow-tag stamping + the floor drop-observe shape
//! (doc 09 §3 NFT-5; doc 14 §5, D76).
//!
//! # What this module renders
//!
//! NFT-5 tags every agent-VM flow with the D76 composite `ct mark` derived from
//! the session, set on the rule for that VM's tap interface, so conntrack
//! accounting records and `nflog` drop events carry the session and `ds-flowlog`
//! can attribute every byte a VM sent (doc 09 §3/§7, D43). This module is the
//! `ds-nft` writer's side of that: it renders, from the frozen
//! [`ds_contracts::mark`] constants ALONE, the per-session stamping ruleset that
//! layers on the `ds_flowtag` table skeleton the versioned
//! `artifacts/nft/nft-5-flowtag.nft` ships.
//!
//! The per-session STATE is runtime (like the [`crate::session`] allow-sets, no
//! artifact holds it): on session create,
//! [`NftWriter::stamp_session`](crate::flush::NftWriter::stamp_session) adds a
//! per-session verdict-map element keying the session's `dstap-<idx>` tap to a
//! per-session stamp chain that sets the composite `ct mark`; teardown removes
//! both.
//!
//! # Mark-mask discipline (D76, the Tailscale PR-5606 lesson)
//!
//! The `ct mark` write is the ONLY sanctioned form: `ct mark set ct mark &
//! ~DS_MARK_MASK | <composed>` — a masked read-modify-write that overwrites only
//! the DS-owned bits (magic ∪ leg ∪ index) and preserves any foreign fwmark bits
//! coexisting in the permanently-unclaimed gap. The composed VALUE and both masks
//! come from [`ds_contracts::mark`] via [`crate::mark_match`] — NO raw mark
//! literal and NO mask/nibble/shift arithmetic is re-derived here.
//!
//! # The stamp runs BEFORE the floor's terminal drop
//!
//! The `ds_flowtag` forward chain is authored at `priority mangle` (-150),
//! strictly EARLIER than NFT-1's `priority filter` (0) forward chain that owns
//! the terminal `ct state new drop`. So the composite mark is stamped on a NEW
//! flow's conntrack entry BEFORE the floor decides its verdict — and a packet the
//! floor then drops still carries the session on the `nflog` drop event (the
//! composition-order property the `ds-contracts` `nft_composition_lint`
//! `nft5_ct_mark_dispatch_behind_an_earlier_drop_is_shadowed` guards). The stamp
//! chain issues NO verdict (it sets + counts and returns), so it never usurps the
//! floor's drop authority.
//!
//! # Conntrack accounting is a host-baseline precondition
//!
//! The byte/packet/duration fields those flow records carry come from
//! `nf_conntrack_acct=1` + `nf_conntrack_timestamp=1`, pinned in the versioned
//! host baseline (`artifacts/host-baseline/host-baseline.v0.json`, doc 14 §11) and
//! applied by the bootstrap unit before this ruleset loads — NFT-5 consumes it by
//! reference, it does not set sysctls.

use ds_contracts::mark::{Leg, DS_MARK_MASK};

use crate::backend::{BackendError, NftBackend, NftBatch};
use crate::flush::NftWriter;
use crate::mark_match::MarkMatch;

/// The table the NFT-5 flow-tag state lives under — `inet ds_flowtag`, its own
/// `inet` table (like NFT-4's `ds_resolver_closure`) so the accounting layer is
/// independently installable/removable and never edits the NFT-1 floor's frozen
/// default-deny scope. The versioned `nft-5-flowtag.nft` artifact ships its base
/// chain + the empty `session_tag` verdict map; this writer adds the per-session
/// elements + stamp chains.
pub const FLOWTAG_TABLE: &str = "inet ds_flowtag";

/// The per-session tap→stamp verdict map (keyed on the `dstap-*` ifname). Ships
/// empty in the artifact; this writer adds one element per live session.
pub const SESSION_TAG_MAP: &str = "session_tag";

/// The `nflog` group the NFT-5 floor drop-observe rule logs to (the Stage-1
/// VM-forward-leg drop stream `ds-flowlog` consumes). Distinct from NFT-3b's
/// group 2 (proxy-output leg) and NFT-4's group 4 (DNS bypass) so the three drop
/// streams stay separable on the wire.
pub const NFLOG_DROP_GROUP: u32 = 5;

/// The `log prefix` the NFT-5 floor drop-observe rule stamps — the marker the
/// `ds-telemetry` `flow::parse_nflog_drop_line` mapping keys on. Kept in ONE place
/// so the kernel rule and the userspace parser cannot drift.
pub const NFLOG_DROP_PREFIX: &str = "ds-nft5-drop ";

/// The complement mask `~DS_MARK_MASK`, rendered from the frozen constant (never a
/// typed-in literal). The masked read-modify-write ANDs the existing `ct mark`
/// with this to preserve the foreign unclaimed-gap bits before ORing the composed
/// DS value.
fn inv_mask_hex() -> String {
    format!("0x{:x}", !DS_MARK_MASK)
}

/// The per-session stamp chain name for a host session index — `tag_<idx>`.
pub fn stamp_chain_name(host_session_index: u32) -> String {
    format!("tag_{host_session_index}")
}

/// The never-recycled per-session tap interface name (`dstap-<idx>`, D66) the
/// stamp keys on — the unforgeable attachment point, never a source IP.
pub fn tap_ifname(host_session_index: u32) -> String {
    format!("dstap-{host_session_index}")
}

/// Render the masked `ct mark` stamping expression for the VM leg (`Leg::AgentVm`,
/// D76) and a host session index: `ct mark set ct mark & ~DS_MARK_MASK |
/// <composed>`. The composed value and both masks are sourced from
/// [`ds_contracts::mark`] through [`MarkMatch`] — no raw literal, no re-derived
/// arithmetic. The read-modify-write preserves any foreign fwmark bits in the
/// unclaimed gap and overwrites only the DS-owned bits.
pub fn ct_mark_stamp_expr(host_session_index: u32) -> String {
    let m = MarkMatch::for_leg(Leg::AgentVm, host_session_index);
    // `value()` is masked-by-construction (magic ∪ leg ∪ index, nothing else), so
    // `& ~DS_MARK_MASK | value` sets exactly the DS bits and preserves the rest.
    format!(
        "ct mark set ct mark & {inv} | 0x{val:x}",
        inv = inv_mask_hex(),
        val = m.value(),
    )
}

/// The canonical NFT-5 floor drop-observe rule shape: `iifname "dstap-*" ct state
/// new counter log prefix "ds-nft5-drop " group 5 drop`. This is the floor's
/// VM-forward-leg terminal drop, extended to `log`+`drop` (the `nflog` group-5
/// stream) so a dropped NEW flow is OBSERVED — and, because the `ds_flowtag` stamp
/// ran at an earlier priority, the drop's `nflog` line carries the stamped
/// composite `ct mark` (`ds-flowlog` attributes it to the session). Anchored on
/// the unforgeable `dstap-*` glob, NEVER source IP (doc 03 §3; doc 06 (c)). The
/// NFT-1 floor's terminal drop ADOPTS this shape at the NFT-6/Stage-1 integration
/// step (an env-gated deferred-manual arm, D50 — the shipped `nft-1-bootstrap.nft`
/// still carries the bare `ct state new drop`); this function is the single source
/// that floor adoption and the `ds-telemetry` drop-parser fixtures agree on.
pub fn floor_drop_observe_rule() -> String {
    format!(
        "iifname \"dstap-*\" ct state new counter log prefix \"{prefix}\" group {group} drop",
        prefix = NFLOG_DROP_PREFIX,
        group = NFLOG_DROP_GROUP,
    )
}

impl<B: NftBackend> NftWriter<B> {
    /// Build the `nft -f` batch [`NftWriter::stamp_session`] applies: ensure the
    /// `inet ds_flowtag` table + its `session_tag` verdict map exist (idempotent
    /// `add`s), create the per-session `tag_<idx>` stamp chain carrying the masked
    /// `ct mark` write + a `counter`, and add the `session_tag` element keying the
    /// session's `dstap-<idx>` tap to `jump tag_<idx>` — ONE atomic batch. Exposed
    /// so callers/tests can inspect the exact text without a backend touch.
    pub fn stamp_batch(host_session_index: u32) -> NftBatch {
        let chain = stamp_chain_name(host_session_index);
        let tap = tap_ifname(host_session_index);
        let stamp = ct_mark_stamp_expr(host_session_index);
        // The map declaration is idempotent; `add`ing an existing map is a
        // converged no-op that never clears its elements (concurrent sessions'
        // elements survive a re-stamp), mirroring `session::instantiate_batch`.
        let text = format!(
            "# nft5-stamp-session: per-session ct-mark flow tag (D76 VM leg)\n\
             add table {FLOWTAG_TABLE}\n\
             add map {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ type ifname : verdict; }}\n\
             add chain {FLOWTAG_TABLE} {chain}\n\
             flush chain {FLOWTAG_TABLE} {chain}\n\
             add rule {FLOWTAG_TABLE} {chain} {stamp} counter\n\
             add element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"{tap}\" : jump {chain} }}\n",
        );
        NftBatch::new(text)
    }

    /// Build the `nft -f` batch [`NftWriter::unstamp_session`] applies: remove the
    /// per-session `session_tag` element and delete the `tag_<idx>` stamp chain in
    /// ONE atomic batch — the NFT-5 half of the NFT-6 teardown. Idempotent for the
    /// doc 06 (b) round-trip-to-bootstrap invariant AND for a double-destroy: an
    /// `ensure-then-delete` shape (`add` the table/map/chain/element, then `delete`
    /// the element+chain) so a teardown of an already-removed session can never
    /// abort the atomic batch on a "No such file or directory".
    pub fn unstamp_batch(host_session_index: u32) -> NftBatch {
        let chain = stamp_chain_name(host_session_index);
        let tap = tap_ifname(host_session_index);
        // Ensure-then-delete (the shipped `nft-5-flowtag.nft` install idiom
        // `table inet ds_flowtag; delete table inet ds_flowtag`, applied per
        // object): `add` on a PRESENT object is a converged no-op that never
        // clears the map's OTHER sessions' elements; `add` on an ABSENT one
        // materialises an empty object the following `delete` removes in the same
        // transaction. So a double-destroy (the element+chain already gone) nets to
        // zero WITHOUT erroring. The `add element`'s `jump {chain}` needs the chain
        // to exist, so the chain ensure precedes it. The composed mark value is
        // NEVER re-rendered here — teardown is name-only, so no `ds-contracts` mark
        // is touched (the stamp VALUE lives solely in `stamp_batch`).
        let text = format!(
            "# nft5-unstamp-session: remove per-session ct-mark flow tag (idempotent)\n\
             add table {FLOWTAG_TABLE}\n\
             add map {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ type ifname : verdict; }}\n\
             add chain {FLOWTAG_TABLE} {chain}\n\
             add element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"{tap}\" : jump {chain} }}\n\
             delete element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"{tap}\" }}\n\
             delete chain {FLOWTAG_TABLE} {chain}\n",
        );
        NftBatch::new(text)
    }

    /// `StampSessionNFT` (NFT-5): install the per-session `ct mark` flow tag — the
    /// `dstap-<idx>` tap's NEW flows are stamped with the D76 composite mark for
    /// the VM leg. Mechanism only; the mark VALUE comes from `ds-contracts`, never
    /// authored here. Idempotent (`add table`/`add map`/`add chain` all converge;
    /// the `flush chain` makes the stamp-rule set converge on a re-stamp).
    pub fn stamp_session(&self, host_session_index: u32) -> Result<(), BackendError> {
        self.backend()
            .apply_batch(&Self::stamp_batch(host_session_index))
    }

    /// Remove the per-session `ct mark` flow tag (ensure-then-`delete` of the map
    /// element + stamp chain) in ONE atomic batch — the NFT-5 half of the NFT-6
    /// teardown. Idempotent: a double-destroy (a retried teardown, or the doc 06
    /// (b) round-trip on an already-clean session) is a converged no-op, never an
    /// error. The conntrack-by-mark destroy stays in [`NftWriter::flush_session`]
    /// (untouched); this removes the STAMPING rule so no new flow is tagged for a
    /// torn-down session.
    pub fn unstamp_session(&self, host_session_index: u32) -> Result<(), BackendError> {
        self.backend()
            .apply_batch(&Self::unstamp_batch(host_session_index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::RecordingBackend;
    use ds_contracts::mark::{compose, decompose};

    #[test]
    fn stamp_expr_is_a_masked_read_modify_write_from_the_constants() {
        let expr = ct_mark_stamp_expr(7);
        // The sanctioned form: read-modify-write under the complement mask, then OR
        // the composed value. Both masks/value come from ds-contracts.
        assert!(expr.starts_with("ct mark set ct mark & "));
        assert!(expr.contains('|'), "an OR of the composed value");
        // The complement mask is exactly ~DS_MARK_MASK, rendered from the constant.
        assert!(expr.contains(&format!("& 0x{:x} ", !DS_MARK_MASK)));
        // The composed value is the AgentVm-leg index-7 mark; leads with magic 0xd.
        let val = compose(Leg::AgentVm, 7);
        assert!(expr.contains(&format!("| 0x{val:x}")));
        assert!(expr.contains("0xd1000007"));
    }

    #[test]
    fn stamp_expr_never_touches_the_unclaimed_gap_and_round_trips() {
        // The composed value sets no bit outside DS_MARK_MASK (so the masked write
        // can never write the permanently-unclaimed bits 14–23).
        let val = compose(Leg::AgentVm, 12_345);
        assert_eq!(val & !DS_MARK_MASK, 0);
        let parts = decompose(val).expect("composed value decodes");
        assert_eq!(parts.leg, Leg::AgentVm);
        assert_eq!(parts.session_index, 12_345);
    }

    #[test]
    fn stamp_batch_is_one_atomic_batch_wiring_the_tap_to_the_stamp_chain() {
        let w = NftWriter::new(RecordingBackend::new());
        w.stamp_session(7).unwrap();
        let batches = w.backend().batches();
        assert_eq!(batches.len(), 1, "one atomic batch");
        let text = &batches[0].text;
        // Ensures the table + map exist (idempotent), creates the stamp chain, and
        // keys the tap to it — all in this one batch.
        assert!(text.contains(&format!("add table {FLOWTAG_TABLE}")));
        assert!(text.contains(&format!(
            "add map {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ type ifname : verdict; }}"
        )));
        assert!(text.contains(&format!("add chain {FLOWTAG_TABLE} tag_7")));
        assert!(text.contains("ct mark set ct mark &"));
        assert!(text.contains(&format!(
            "add element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"dstap-7\" : jump tag_7 }}"
        )));
        // The stamp chain issues NO verdict — it must not carry accept/drop/reject
        // (it sets + counts and returns; the floor keeps drop authority).
        assert!(!text.contains(" accept"));
        assert!(!text.contains(" drop"));
        assert!(!text.contains(" reject"));
    }

    #[test]
    fn unstamp_batch_removes_the_element_and_chain() {
        let w = NftWriter::new(RecordingBackend::new());
        w.unstamp_session(7).unwrap();
        let text = w.backend().batches()[0].text.clone();
        assert!(text.contains(&format!(
            "delete element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"dstap-7\" }}"
        )));
        assert!(text.contains(&format!("delete chain {FLOWTAG_TABLE} tag_7")));
        // Teardown is name-only: it never re-renders the composed mark value (that
        // lives solely in `stamp_batch`), so no `ct mark set` appears here.
        assert!(!text.contains("ct mark set"));
    }

    #[test]
    fn unstamp_batch_is_ensure_then_delete_so_a_double_destroy_cannot_error() {
        // The idempotency contract (no orphan on double-destroy): every object the
        // batch `delete`s is `add`ed first in the SAME atomic transaction, so a
        // teardown of an already-removed session nets to zero without a "No such
        // file or directory" abort. Assert the ensure precedes each delete.
        let text = NftWriter::<RecordingBackend>::unstamp_batch(7).text;
        for (add, del) in [
            (
                format!(
                    "add element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"dstap-7\" : jump tag_7 }}"
                ),
                format!("delete element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"dstap-7\" }}"),
            ),
            (
                format!("add chain {FLOWTAG_TABLE} tag_7"),
                format!("delete chain {FLOWTAG_TABLE} tag_7"),
            ),
        ] {
            let add_at = text
                .find(&add)
                .unwrap_or_else(|| panic!("ensure `{add}` present"));
            let del_at = text
                .find(&del)
                .unwrap_or_else(|| panic!("delete `{del}` present"));
            assert!(
                add_at < del_at,
                "the ensure `{add}` must precede its delete `{del}` (ensure-then-delete)"
            );
        }
        // The table + map are ensured too (a fresh/torn-down host may lack them),
        // so deleting the element out of the map can never fail on a missing map.
        assert!(text.contains(&format!("add table {FLOWTAG_TABLE}")));
        assert!(text.contains(&format!(
            "add map {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ type ifname : verdict; }}"
        )));
        // The `add element` jumps to the same per-session chain, so its re-add is a
        // converged no-op (never a value-conflict) when the element still exists.
        assert!(text.contains("jump tag_7"));
    }

    #[test]
    fn unstamp_batch_is_deterministic_a_double_destroy_renders_the_same_text() {
        // A repeated teardown renders byte-identical text — the offline witness that
        // unstamp is a pure function of the index and the second destroy carries no
        // extra state to trip on.
        let w = NftWriter::new(RecordingBackend::new());
        w.unstamp_session(42).unwrap();
        w.unstamp_session(42).unwrap();
        let batches = w.backend().batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].text, batches[1].text);
    }

    #[test]
    fn stamp_batch_is_deterministic_a_re_stamp_renders_the_same_text() {
        let w = NftWriter::new(RecordingBackend::new());
        w.stamp_session(42).unwrap();
        w.stamp_session(42).unwrap();
        let batches = w.backend().batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(
            batches[0].text, batches[1].text,
            "the rendered batch is a deterministic function of the index"
        );
    }

    #[test]
    fn distinct_sessions_get_distinct_marks_and_chains() {
        let a = ct_mark_stamp_expr(1);
        let b = ct_mark_stamp_expr(2);
        assert_ne!(a, b, "different indices compose different marks");
        assert_ne!(stamp_chain_name(1), stamp_chain_name(2));
        assert_ne!(tap_ifname(1), tap_ifname(2));
    }

    #[test]
    fn the_index_wraps_mod_two_to_the_fourteenth_in_the_stamp() {
        // A wrapped index composes the same mark as its 2^14 residue (the field is
        // a disambiguator, doc 14 §4) — the stamp VALUE agrees.
        assert_eq!(
            MarkMatch::for_leg(Leg::AgentVm, 16_384 + 5).value(),
            MarkMatch::for_leg(Leg::AgentVm, 5).value()
        );
    }

    #[test]
    fn floor_drop_observe_rule_is_dstap_anchored_logs_and_drops() {
        let rule = floor_drop_observe_rule();
        // Interface-anchored (never source IP), ct-state-new scoped, logs to the
        // NFT-5 nflog group with the parser's prefix, and drops.
        assert!(rule.contains("iifname \"dstap-*\""));
        assert!(
            !rule.contains("saddr"),
            "never anchors on a forgeable source IP"
        );
        assert!(rule.contains("ct state new"));
        assert!(rule.contains(&format!("log prefix \"{NFLOG_DROP_PREFIX}\"")));
        assert!(rule.contains(&format!("group {NFLOG_DROP_GROUP}")));
        assert!(rule.contains("counter"));
        assert!(rule.trim_end().ends_with("drop"));
        // The prefix is exactly the token the ds-telemetry drop parser keys on.
        assert!(NFLOG_DROP_PREFIX.contains("ds-nft5-drop"));
    }
}
