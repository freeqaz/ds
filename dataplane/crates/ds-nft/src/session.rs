//! Per-session `InstantiateSessionNFT` / teardown — the MODEL A admit surface
//! (session doc 11 §3 Model A, §5.1; D1/D3/D4/D75).
//!
//! [`NftWriter::instantiate_session`] mints, and [`NftWriter::teardown_session`]
//! removes, the per-session **admit surface ONLY**: the two named allow-sets the
//! host-wide `dstap-*` glob floor and ds-dnsgate are designed to fill. Those two
//! PRIMITIVES write NOTHING else (Model A, below). The FULL per-session
//! create/destroy lifecycle — admit surface PLUS the NFT-5 flow-tag stamp — is
//! [`NftWriter::create_session`] / [`NftWriter::destroy_session`] (see "NFT-5
//! flow-tag wiring" below), which compose the primitive with a SEPARATE atomic
//! batch on a SEPARATE table.
//!
//! # Model A discipline — what the admit-surface primitives do NOT write (ratified, §3/§6 D1)
//!
//! The host-wide boundary floor (`nft-1-bootstrap.nft` / `nft-4-resolver-closure
//! .nft`) already owns default-deny, the udp/tcp 53 → ds-dnsgate redirect, the
//! NFT-4 closure, and the IPv6 drop — all via the unforgeable `iifname "dstap-*"`
//! glob, written once. So per-session instantiate does **not** re-author any of
//! that. It writes:
//!
//! - **NO** default-deny / `ct state new drop` (the floor's `forward` policy +
//!   `:90` marker own it);
//! - **NO** redirect / DNAT (the floor's `prerouting` chain owns it);
//! - **NO** ct-mark verdict or mark copy (the NFT-5 stamp is a SEPARATE
//!   `inet ds_flowtag` batch, composed only by `create_session`, never mixed into
//!   the `ds_filter` admit surface);
//! - **NO** session enforcement chain — the NFT-3b `out_<session>` OUTPUT chain
//!   that READS these sets is Stage-3, out of scope here (session doc 11 §3
//!   Model C, deferred).
//!
//! `instantiate_session` writes EXACTLY the two empty sets. Re-authoring any floor
//! rule per session is the Model B anti-pattern (§3): a silent enforcement gap on
//! any drift.
//!
//! # NFT-5 flow-tag wiring (D76, doc 09 §3; the create/destroy lifecycle)
//!
//! The `dstap-<idx>` tap's flows must carry the D76 composite `ct mark` so
//! ds-flowlog can attribute every byte a VM sent back to its session. That STAMP
//! is [`crate::flowtag`] state on the SEPARATE `inet ds_flowtag` table, so the
//! lifecycle methods compose it around the admit surface WITHOUT touching the
//! Model-A primitives (or their frozen ffi contract):
//!
//! - [`NftWriter::create_session`] = [`NftWriter::instantiate_session`] (the
//!   `ds_filter` allow-sets) THEN [`NftWriter::stamp_session`] (the `ds_flowtag`
//!   per-session stamp chain + tap→chain map element) — two atomic batches, one
//!   per table, never mixed.
//! - [`NftWriter::destroy_session`] = [`NftWriter::teardown_session`] THEN
//!   [`NftWriter::unstamp_session`], which removes the stamp element+chain
//!   idempotently (ensure-then-delete — a double-destroy is a converged no-op).
//!
//! The mark VALUE is sourced ONLY from `ds-contracts` inside `flowtag` — never
//! authored here. The conntrack-by-mark destroy leg of NFT-6 stays in
//! [`crate::flush`] (`flush_session`), untouched by this module. (The C ABI
//! `ds_nft_instantiate_session` still wraps the admit-surface primitive; a
//! follow-up that owns `ffi.rs` re-points it at `create_session`.)
//!
//! # The sets
//!
//! `instantiate_session` first **ensures `table inet ds_filter` exists** (an
//! idempotent leading `add table` — a no-op that never clears existing sets when
//! the table is already present), then creates the two empty per-session sets in
//! it. No host bootstrap artifact owns `ds_filter` (the `nft-1-bootstrap` /
//! `nft-4-resolver-closure` floor builds `ds_boundary` / `ds_resolver_closure`,
//! never `ds_filter`), so instantiate is the first point the table is touched and
//! is self-sufficient — it cannot fail with "no such table" on a fresh host where
//! only ds-nft has run (Option B; the never-wipe-concurrent-sessions property is
//! a kernel `add table` guarantee, verified live in a rootless netns).
//!
//! The two sets live in this `table inet ds_filter` — the same table ds-dnsgate
//! writes element content into (`ds-dnsgate/src/txn.rs`); the same `const TABLE`
//! the refresh path names, [`crate::refresh`]:
//!
//! - `allow4_<idx>` — `type ipv4_addr` with the `timeout` flag (elements carry
//!   the W2 deadline ds-dnsgate stamps, doc 11 §8.3);
//! - `allow6_<idx>` — `type ipv6_addr` with the `timeout` flag, created DORMANT
//!   under D75 Phase-B (no v6 elements until v6 turns on end to end, but the set
//!   exists from instantiate so the dual-family path is reachable without a later
//!   rename).
//!
//! Both `<idx>` tokens are the `host_session_index` (D4) and the set NAME is the
//! SINGLE-SOURCE [`ds_contracts::session::allow_set_name`] — `ds-nft` (creates)
//! and `ds-dnsgate` (fills) both call it and never derive it independently
//! (this structurally kills the §2.5/D3 divergence).
//!
//! # Idempotency / teardown (doc 15 §5.1, the (b) round-trip invariant)
//!
//! `instantiate_session` renders `add set …` (idempotent at the kernel — a
//! re-`add` of an existing set with the same spec converges, never errors).
//! `teardown_session` renders `delete set …` for both sets; the conntrack leg of
//! the NFT-6 teardown stays in [`crate::flush`] (`flush_session`), so a full
//! teardown is `flush_session(legs=all)` THEN `teardown_session` — this module
//! owns only the named-set half. A create→destroy round-trip returns the ruleset
//! byte-identical to bootstrap (§5.1).
//!
//! # Mechanism is FREE (doc 11 §4)
//!
//! Like [`crate::refresh`], the batch text below is the spawned-`nft -f` shape an
//! `nftnl-rs` mechanism would emit equivalently behind [`crate::backend::NftBackend`];
//! unit tests assert the rendered text against a [`crate::backend::RecordingBackend`]
//! and never touch the kernel.

use ds_contracts::dns_admission::AddressFamily;
use ds_contracts::session::allow_set_name;

use crate::backend::{BackendError, NftBackend, NftBatch};
use crate::flush::NftWriter;

/// The table the per-session allow-sets live under — `inet ds_filter`, the
/// allow-set home (the NFT-3b OUTPUT chain reads it by name). No host bootstrap
/// artifact creates it, so instantiate idempotently ensures it (a leading
/// `add table`, a no-op that never clears existing sets) before creating the
/// per-session sets. Named once here so instantiate/teardown name the same table
/// the refresh path ([`crate::refresh`]) and ds-dnsgate already target.
const TABLE: &str = "inet ds_filter";

/// The error [`NftWriter::instantiate_session`] / [`NftWriter::teardown_session`]
/// surface: a backend (`nft -f`) failure. Mirrors [`crate::NftFlushError`] — a
/// thin newtype over the [`BackendError`], opaque to callers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NftSessionError {
    /// The underlying backend error.
    pub backend: BackendError,
}

impl From<BackendError> for NftSessionError {
    fn from(backend: BackendError) -> NftSessionError {
        NftSessionError { backend }
    }
}

impl std::fmt::Display for NftSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "nft session error: {}", self.backend.message)
    }
}

impl std::error::Error for NftSessionError {}

/// Render the `add set inet ds_filter <name> { type <addr_type>; flags timeout; }`
/// line for one family's per-session allow-set. The set NAME is the single-source
/// [`allow_set_name`]; `add set` is idempotent at the kernel (a converged
/// re-create).
fn add_set_line(family: AddressFamily, host_session_index: u32) -> String {
    let name = allow_set_name(family, host_session_index);
    // The element key type per family; the `timeout` flag lets elements carry the
    // W2 deadline ds-dnsgate stamps on admission (doc 11 §8.3). v6 is created
    // dormant (D75) — same shape, no elements until v6 turns on.
    let addr_type = match family {
        AddressFamily::V4 => "ipv4_addr",
        AddressFamily::V6 => "ipv6_addr",
    };
    format!("add set {TABLE} {name} {{ type {addr_type}; flags timeout; }}")
}

/// Render the `delete set inet ds_filter <name>` line for one family's
/// per-session allow-set, by the single-source [`allow_set_name`].
fn delete_set_line(family: AddressFamily, host_session_index: u32) -> String {
    let name = allow_set_name(family, host_session_index);
    format!("delete set {TABLE} {name}")
}

impl<B: NftBackend> NftWriter<B> {
    /// Build the `nft -f` batch [`NftWriter::instantiate_session`] applies: ensure
    /// `inet ds_filter` exists (idempotent `add table`, a no-op that never clears
    /// existing sets), then the two empty per-session allow-sets in it, and NOTHING
    /// else (Model A — the floor owns deny/redirect/closure). Exposed so
    /// callers/tests can inspect the exact text without a backend touch; the
    /// production path goes through [`NftWriter::instantiate_session`].
    pub fn instantiate_batch(host_session_index: u32) -> NftBatch {
        // ONE atomic batch (mirror `refresh::refresh_batch`): ensure the shared
        // host-infra table exists, then two `add set` lines — no chain, no rule,
        // no map, no element. v4 then v6 (v6 dormant, D75). The leading
        // `add table inet ds_filter` is the idempotent ensure: `add table` on an
        // already-present table is a converged no-op that NEVER clears its existing
        // contents, so concurrent sessions' filled sets survive a re-instantiate
        // (verified live in a rootless netns; the established repo preamble, also
        // used by `tests/dual_refresh_paths.rs::wrap_for_check`). This makes
        // instantiate self-sufficient: no bootstrap artifact owns `ds_filter`, so
        // the table is born here at the first point it is touched (Option B).
        let text = format!(
            "# instantiate-session:allow-sets (model A — admit surface only)\n\
             add table {TABLE}\n\
             {v4}\n{v6}\n",
            v4 = add_set_line(AddressFamily::V4, host_session_index),
            v6 = add_set_line(AddressFamily::V6, host_session_index),
        );
        NftBatch::new(text)
    }

    /// Build the `nft -f` batch [`NftWriter::teardown_session`] applies: delete
    /// both per-session allow-sets. The conntrack leg of the NFT-6 teardown stays
    /// in [`NftWriter::flush_session`]; this is the named-set half only.
    pub fn teardown_batch(host_session_index: u32) -> NftBatch {
        let text = format!(
            "# teardown-session:allow-sets (model A — admit surface only)\n\
             {v4}\n{v6}\n",
            v4 = delete_set_line(AddressFamily::V4, host_session_index),
            v6 = delete_set_line(AddressFamily::V6, host_session_index),
        );
        NftBatch::new(text)
    }

    /// `InstantiateSessionNFT` (Model A): ensure `inet ds_filter` exists (idempotent
    /// `add table`, a no-op that never clears existing sets), then create the EMPTY
    /// per-session `allow4_<idx>` / `allow6_<idx>` sets in it in ONE atomic batch.
    /// Mechanism only — NO deny/redirect/mark/chain (the floor owns those, session
    /// doc 11 §3). Idempotent (`add table` + `add set` re-create both converge).
    ///
    /// This is the admit-surface PRIMITIVE and stays Model-A pure. The full
    /// per-session create lifecycle — admit surface PLUS the NFT-5 flow-tag stamp —
    /// is [`NftWriter::create_session`], which composes this with
    /// [`NftWriter::stamp_session`].
    pub fn instantiate_session(&self, host_session_index: u32) -> Result<(), NftSessionError> {
        self.backend()
            .apply_batch(&Self::instantiate_batch(host_session_index))?;
        Ok(())
    }

    /// Remove the per-session allow-sets (`delete set` both families) in ONE
    /// atomic batch — the named-set half of the NFT-6 teardown. The conntrack-by-
    /// mark half is [`NftWriter::flush_session`]. Idempotent for the (b)
    /// round-trip-to-bootstrap invariant.
    ///
    /// This is the admit-surface PRIMITIVE and stays Model-A pure. The full
    /// per-session destroy lifecycle — admit-surface removal PLUS the NFT-5
    /// flow-tag unstamp — is [`NftWriter::destroy_session`], which composes this
    /// with [`NftWriter::unstamp_session`].
    pub fn teardown_session(&self, host_session_index: u32) -> Result<(), NftSessionError> {
        self.backend()
            .apply_batch(&Self::teardown_batch(host_session_index))?;
        Ok(())
    }

    /// The full per-session CREATE lifecycle (NFT-5 wiring, D76): the Model-A admit
    /// surface ([`NftWriter::instantiate_session`]) THEN the per-session `ct mark`
    /// flow-tag stamp ([`NftWriter::stamp_session`]) — two atomic batches, one on
    /// the `inet ds_filter` table (allow-sets) and one on the `inet ds_flowtag`
    /// table (stamp chain + tap→chain map element), NEVER mixed. This is the single
    /// call a session-create caller makes to get BOTH the admit surface and the
    /// attribution stamp; the mark VALUE is sourced from `ds-contracts` inside
    /// [`crate::flowtag`], never authored here. Both legs are idempotent, so a
    /// re-create converges byte-for-byte.
    ///
    /// The admit-surface leg runs first: the stamp is a best-effort accounting
    /// layer (a tap with no stamp is simply unmarked, never refused — doc 14 §5),
    /// so ordering it after the admit surface keeps the security-relevant sets
    /// first. A stamp-leg failure propagates (create fails) rather than leaving a
    /// half-tagged session silently.
    pub fn create_session(&self, host_session_index: u32) -> Result<(), NftSessionError> {
        self.instantiate_session(host_session_index)?;
        // NFT-5: stamp the per-session composite ct mark on the tap so this
        // session's flows are attributable (D76). BackendError converts into
        // NftSessionError via the `From` impl above.
        self.stamp_session(host_session_index)?;
        Ok(())
    }

    /// The full per-session DESTROY lifecycle (NFT-5 wiring, D76): the Model-A
    /// admit-surface removal ([`NftWriter::teardown_session`]) THEN the flow-tag
    /// unstamp ([`NftWriter::unstamp_session`], which removes the stamp element +
    /// chain idempotently — a double-destroy is a converged no-op, never an
    /// orphan). The conntrack-by-mark half of NFT-6 stays in
    /// [`NftWriter::flush_session`] (untouched). Idempotent for the doc 06 (b)
    /// round-trip-to-bootstrap invariant.
    pub fn destroy_session(&self, host_session_index: u32) -> Result<(), NftSessionError> {
        self.teardown_session(host_session_index)?;
        // NFT-5: remove the stamp so no NEW flow is tagged for a torn-down session.
        self.unstamp_session(host_session_index)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::RecordingBackend;

    fn writer() -> NftWriter<RecordingBackend> {
        NftWriter::new(RecordingBackend::new())
    }

    #[test]
    fn instantiate_creates_exactly_the_two_empty_named_sets() {
        let w = writer();
        w.instantiate_session(7).expect("instantiate");

        let batches = w.backend().batches();
        assert_eq!(batches.len(), 1, "one atomic batch");
        let text = &batches[0].text;

        // The two per-session sets, named by the single-source contract function,
        // in the ds_filter table, with the family-correct key type and the timeout
        // flag.
        assert!(text.contains("add set inet ds_filter allow4_7 { type ipv4_addr; flags timeout; }"));
        assert!(text.contains("add set inet ds_filter allow6_7 { type ipv6_addr; flags timeout; }"));
        // The admit-surface primitive stays pure Model A — the NFT-5 stamp is the
        // SEPARATE ds_flowtag batch, composed only by create_session.
        assert!(!text.contains("ds_flowtag"));
        assert!(!text.contains("ct mark"));
    }

    #[test]
    fn instantiate_ensures_the_ds_filter_table_exactly_once() {
        // No host bootstrap artifact owns `inet ds_filter`, so instantiate must
        // ensure it itself (Option B). The leading `add table inet ds_filter` is an
        // idempotent ensure — on an already-present table it is a converged no-op
        // that NEVER clears existing sets (a kernel property, exercised live by the
        // netns tests), so re-instantiate / concurrent sessions never wipe filled
        // sets. Assert it is rendered, and exactly ONCE (one ensure, not per-set).
        let w = writer();
        w.instantiate_session(7).expect("instantiate");
        let text = w.backend().batches()[0].text.clone();

        assert!(
            text.contains("add table inet ds_filter"),
            "instantiate must ensure the shared ds_filter table (no bootstrap owns it)"
        );
        assert_eq!(
            text.matches("add table").count(),
            1,
            "the table is ensured exactly once, before the per-session sets"
        );
        // The ensure precedes the sets it scopes (a batch where `add set` ran first
        // on a fresh host would fail; the ordering is load-bearing).
        let table_at = text.find("add table").expect("add table present");
        let set_at = text.find("add set").expect("add set present");
        assert!(
            table_at < set_at,
            "the table ensure must precede the per-session `add set` lines"
        );
        // Never a `delete table` here — the table is shared host infra, not
        // per-session, so instantiate only ever ensures (additive) it.
        assert!(
            !text.contains("delete table"),
            "instantiate never deletes the shared table"
        );
    }

    #[test]
    fn instantiate_writes_no_floor_rule_only_the_table_ensure_and_two_sets() {
        // Model A: the floor owns deny/redirect/mark/chain. The batch must carry
        // NONE of those — only the idempotent `add table` ensure, exactly two
        // `add set` lines, and a comment, nothing else.
        let w = writer();
        w.instantiate_session(42).expect("instantiate");
        let text = w.backend().batches()[0].text.clone();

        // No enforcement primitive of any kind.
        assert!(
            !text.contains("add chain"),
            "no session chain (floor/Stage-3 owns chains)"
        );
        assert!(!text.contains("add rule"), "no rule");
        assert!(!text.contains("add map"), "no verdict map");
        assert!(!text.contains("add element"), "sets are created EMPTY");
        assert!(!text.contains("drop"), "no default-deny (floor owns it)");
        assert!(!text.contains("redirect"), "no redirect (floor owns it)");
        assert!(!text.contains("dnat"), "no dnat (floor owns it)");
        assert!(!text.contains("mark"), "no ct-mark verdict (NFT-5 Stage-3)");
        assert!(!text.contains("4242"), "no :4242 allow here (out of scope)");

        // Exactly two `add set` statements, plus the single `add table` ensure:
        // three `add` verbs total, and NOTHING else additive. `add table` is none
        // of the enforcement primitives asserted-against above (it is additive,
        // never clears) — it is the only other `add` allowed.
        assert_eq!(text.matches("add set").count(), 2);
        assert_eq!(text.matches("add table").count(), 1);
        assert_eq!(
            text.matches("add ").count(),
            3,
            "exactly the table ensure + the two per-session sets"
        );
    }

    #[test]
    fn instantiate_uses_the_single_source_contract_name_not_a_local_derivation() {
        // The set name MUST be exactly what ds_contracts::session::allow_set_name
        // produces — both ds-nft (here) and ds-dnsgate call it, so they cannot
        // diverge (the §2.5/D3 fix). Assert against the contract directly.
        let w = writer();
        w.instantiate_session(13).expect("instantiate");
        let text = w.backend().batches()[0].text.clone();
        let v4 = allow_set_name(AddressFamily::V4, 13);
        let v6 = allow_set_name(AddressFamily::V6, 13);
        assert_eq!(v4, "allow4_13");
        assert_eq!(v6, "allow6_13");
        assert!(text.contains(&format!("add set inet ds_filter {v4} ")));
        assert!(text.contains(&format!("add set inet ds_filter {v6} ")));
    }

    #[test]
    fn instantiate_is_idempotent_a_re_instantiate_renders_the_same_batch() {
        // Both verbs are converged re-applies at the kernel: `add table` on an
        // existing table is a no-op that does NOT clear its sets, and `add set` is a
        // converged re-create. The rendered batch is deterministic, so two
        // instantiate calls produce byte-identical batches — the offline witness
        // that a re-instantiate ensures (never re-creates-and-wipes) the table; the
        // never-clear-existing-sets kernel property itself is pinned live by the
        // netns tests (`warm_restart_live_netns.rs`, `nft4_quic_reject.rs`).
        let w = writer();
        w.instantiate_session(9).expect("first");
        w.instantiate_session(9).expect("second");
        let batches = w.backend().batches();
        assert_eq!(batches.len(), 2);
        assert_eq!(
            batches[0].text, batches[1].text,
            "re-instantiate is byte-identical"
        );
    }

    #[test]
    fn teardown_deletes_exactly_those_two_sets() {
        let w = writer();
        w.teardown_session(7).expect("teardown");

        let batches = w.backend().batches();
        assert_eq!(batches.len(), 1, "one atomic batch");
        let text = &batches[0].text;

        assert!(text.contains("delete set inet ds_filter allow4_7"));
        assert!(text.contains("delete set inet ds_filter allow6_7"));
        // exactly two delete-set verbs; no conntrack/flush leg here (that is
        // flush_session's half of NFT-6).
        assert_eq!(text.matches("delete set").count(), 2);
        assert!(!text.contains("conntrack"));
        assert!(!text.contains("flush"));
        // The teardown primitive is pure ds_filter — the NFT-5 unstamp is composed
        // only by destroy_session, on the SEPARATE ds_flowtag table.
        assert!(!text.contains("ds_flowtag"));
        // The ds_filter table is SHARED host infra, not per-session — teardown must
        // NEVER touch the table itself (a `delete table` would wipe every other live
        // session's sets). It deletes only this session's two named sets.
        assert!(
            !text.contains("delete table"),
            "teardown never deletes the shared table"
        );
        assert!(
            !text.contains("add table"),
            "teardown never re-ensures the table either"
        );
    }

    #[test]
    fn teardown_uses_the_single_source_contract_name() {
        let w = writer();
        w.teardown_session(42).expect("teardown");
        let text = w.backend().batches()[0].text.clone();
        assert!(text.contains(&format!(
            "delete set inet ds_filter {}",
            allow_set_name(AddressFamily::V4, 42)
        )));
        assert!(text.contains(&format!(
            "delete set inet ds_filter {}",
            allow_set_name(AddressFamily::V6, 42)
        )));
    }

    #[test]
    fn instantiate_then_teardown_name_the_same_pair_of_sets() {
        // The create→destroy round-trip (the (b) invariant) must target the SAME
        // named sets — instantiate's `allow{4,6}_<idx>` are exactly the names
        // teardown deletes.
        let idx = 21;
        let create = NftWriter::<RecordingBackend>::instantiate_batch(idx).text;
        let destroy = NftWriter::<RecordingBackend>::teardown_batch(idx).text;
        for fam in [AddressFamily::V4, AddressFamily::V6] {
            let name = allow_set_name(fam, idx);
            assert!(create.contains(&format!("add set inet ds_filter {name} ")));
            assert!(destroy.contains(&format!("delete set inet ds_filter {name}")));
        }
    }

    #[test]
    fn a_backend_failure_propagates_as_the_session_error() {
        let w = writer();
        w.backend()
            .arm_error(BackendError::new("EPERM: CAP_NET_ADMIN missing"));
        let err = w
            .instantiate_session(1)
            .expect_err("backend failure must propagate");
        assert!(err.backend.message.contains("EPERM"));
        // surfaces through Display too.
        assert!(format!("{err}").contains("EPERM"));
    }

    #[test]
    fn create_session_stamps_the_flow_tag_and_destroy_session_unstamps_it() {
        // The NFT-5 lifecycle wiring (D76): create_session installs the per-session
        // ct-mark stamp on the tap AFTER the admit surface; destroy_session removes
        // it. Proven offline against the recording backend — the live-kernel bind is
        // `tests/nft5_flowtag_netns.rs` (D50 gate).
        use crate::flowtag::{FLOWTAG_TABLE, SESSION_TAG_MAP};

        let idx = 7u32;

        // ── create_session: [0] the ds_filter admit surface, [1] the NFT-5 stamp ──
        let w = writer();
        w.create_session(idx).expect("create_session");
        let create = w.backend().batches();
        assert_eq!(create.len(), 2, "admit surface + NFT-5 stamp");
        // The admit surface runs first and stays pure ds_filter (security sets
        // before the best-effort accounting stamp).
        let admit = &create[0].text;
        assert!(admit.contains(&format!("add set inet ds_filter allow4_{idx} ")));
        assert!(!admit.contains("ds_flowtag"));
        // The stamp keys the tap to its per-session stamp chain and writes the
        // masked ct mark — mechanism sourced from ds-contracts, never authored here.
        let stamp = &create[1].text;
        assert!(stamp.contains(&format!("add chain {FLOWTAG_TABLE} tag_{idx}")));
        assert!(stamp.contains(&format!(
            "add element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"dstap-{idx}\" : jump tag_{idx} }}"
        )));
        assert!(stamp.contains("ct mark set ct mark &"));
        // Interface-anchored, never a forgeable source IP.
        assert!(!stamp.contains("saddr"));

        // ── destroy_session: [0] the allow-set removal, [1] the NFT-5 unstamp ──
        let w2 = writer();
        w2.destroy_session(idx).expect("destroy_session");
        let destroy = w2.backend().batches();
        assert_eq!(destroy.len(), 2, "allow-set removal + NFT-5 unstamp");
        assert!(destroy[0]
            .text
            .contains(&format!("delete set inet ds_filter allow4_{idx}")));
        let unstamp = &destroy[1].text;
        assert!(unstamp.contains(&format!(
            "delete element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"dstap-{idx}\" }}"
        )));
        assert!(unstamp.contains(&format!("delete chain {FLOWTAG_TABLE} tag_{idx}")));
    }

    #[test]
    fn create_session_then_destroy_session_round_trips_the_same_named_objects() {
        // The (b) round-trip: the stamp chain + map element create_session installs
        // are EXACTLY the ones destroy_session removes (by name), for the same tap.
        use crate::flowtag::{stamp_chain_name, tap_ifname, FLOWTAG_TABLE, SESSION_TAG_MAP};

        let idx = 21u32;
        let chain = stamp_chain_name(idx);
        let tap = tap_ifname(idx);

        let wc = writer();
        wc.create_session(idx).expect("create_session");
        let create_stamp = wc.backend().batches()[1].text.clone();

        let wd = writer();
        wd.destroy_session(idx).expect("destroy_session");
        let destroy_unstamp = wd.backend().batches()[1].text.clone();

        assert!(create_stamp.contains(&format!("add chain {FLOWTAG_TABLE} {chain}")));
        assert!(destroy_unstamp.contains(&format!("delete chain {FLOWTAG_TABLE} {chain}")));
        assert!(create_stamp.contains(&format!(
            "add element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"{tap}\" : jump {chain} }}"
        )));
        assert!(destroy_unstamp.contains(&format!(
            "delete element {FLOWTAG_TABLE} {SESSION_TAG_MAP} {{ \"{tap}\" }}"
        )));
    }

    #[test]
    fn a_double_destroy_session_is_a_converged_no_op() {
        // No orphan on double-destroy: a repeated destroy_session renders
        // byte-identical batches on BOTH legs, and the NFT-5 unstamp is
        // ensure-then-delete so a real kernel would never abort the atomic batch on
        // an already-removed element/chain (the live proof is the D50-gated netns
        // arm). destroy_session is idempotent end to end.
        let idx = 42u32;
        let w = writer();
        w.destroy_session(idx).expect("first destroy_session");
        w.destroy_session(idx)
            .expect("second destroy_session converges");
        let b = w.backend().batches();
        assert_eq!(b.len(), 4);
        assert_eq!(b[0].text, b[2].text, "allow-set removal is deterministic");
        assert_eq!(b[1].text, b[3].text, "NFT-5 unstamp is deterministic");
        // The unstamp leg ensures each object before deleting it — the shape that
        // makes the second (already-clean) destroy a no-op rather than an error.
        let unstamp = &b[1].text;
        assert!(unstamp.contains(&format!("add chain inet ds_flowtag tag_{idx}")));
        assert!(unstamp.contains(&format!("delete chain inet ds_flowtag tag_{idx}")));
    }

    #[test]
    fn create_session_is_idempotent_a_recreate_renders_the_same_batches() {
        // Both legs converge on the kernel; the rendered batches are a deterministic
        // function of the index, so two create_session calls produce byte-identical
        // pairs — the offline witness that a re-create ensures rather than wipes.
        let w = writer();
        w.create_session(9).expect("first");
        w.create_session(9).expect("second");
        let b = w.backend().batches();
        assert_eq!(b.len(), 4);
        assert_eq!(
            b[0].text, b[2].text,
            "re-create admit surface is byte-identical"
        );
        assert_eq!(
            b[1].text, b[3].text,
            "re-create NFT-5 stamp is byte-identical"
        );
    }

    #[test]
    fn create_session_admit_surface_failure_aborts_before_the_stamp() {
        // If the admit-surface leg fails, create_session must NOT proceed to stamp —
        // the error propagates and no ds_flowtag batch is emitted (the security sets
        // failing is a hard create failure, not a half-tagged session).
        let w = writer();
        w.backend()
            .arm_error(BackendError::new("EPERM: CAP_NET_ADMIN missing"));
        let err = w
            .create_session(1)
            .expect_err("admit-surface failure propagates");
        assert!(err.backend.message.contains("EPERM"));
        // The armed error fires on the first apply; nothing further recorded.
        for batch in w.backend().batches() {
            assert!(
                !batch.text.contains("ds_flowtag"),
                "no stamp after an admit failure"
            );
        }
    }
}
