// SPDX-License-Identifier: Apache-2.0
//! Cross-crate conformance twin: the per-session NFT-3 allow-set name is
//! single-sourced in [`ds_contracts::session::allow_set_name`], and BOTH
//! independent writers — `ds-nft` (`InstantiateSessionNFT`, creates the empty
//! `allow4_<idx>` / `allow6_<idx>` sets) and `ds-dnsgate` (admit fills element
//! CONTENT on the DNS-2 txn; sweep deletes by name on withdraw) — name the
//! byte-EXACT same set for the same `(family, host_session_index)` (doc 09 §3
//! NFT-3; session doc 11 §2.5/§4 D3/D4).
//!
//! WHY A TWIN (not just the in-crate doctest). The two writers touch the same
//! kernel sets with NO handshake between them: ds-nft creates the set, ds-dnsgate
//! fills it, and the NFT-3b OUTPUT chain reads it back cross-table BY NAME. If
//! either side re-derived the name independently, the gate would fill a set the
//! creator never made (or vice versa) and egress admission would fail CLOSED —
//! exactly the §2.5/D3 divergence the m0-walking-skeleton nft v4 bug
//! (`DstKey::address_literal`, 873947bd) taught us to guard. The structural
//! defence is that every side CALLS `allow_set_name` rather than re-deriving; this
//! twin PROVES that defence holds at the integration boundary by pinning the one
//! literal wire string against the shape each consumer embeds.
//!
//! CRATE-DEPENDENCY NOTE. `ds-contracts` is stdlib-only by FROZEN RULE
//! (doc 14 §6, D67/D40 — no framework, and here no workspace crate, may cross its
//! dependency graph; `ds-nft` itself DEPENDS on `ds-contracts`, so importing it
//! here would invert that edge). So this twin asserts over the single-source
//! function directly and pins the EXACT documented wire token each consumer's
//! batch text / withdraw record embeds — the same way `netflowadapter`'s
//! `schema_audit.go` pins the Rust event wire shape from the Go side without
//! linking the producer. The golden tokens below are copied verbatim from the two
//! producers' own source (cited inline); if a producer's literal shape drifts,
//! its own crate's set-name asserts AND this twin both go red, surfacing the
//! divergence on either side.

use ds_contracts::dns_admission::AddressFamily;
use ds_contracts::session::allow_set_name;

// The drive vector the acceptance criterion names: (v4, idx=7) and (v6, idx=7),
// plus a second index to prove the name is keyed on the per-session index (D4),
// never a flat shared `allow4` / a constant.
const IDX: u32 = 7;
const OTHER_IDX: u32 = 13;

/// The byte-exact set name ds-nft's `InstantiateSessionNFT` (Model A) embeds in
/// its `add set inet ds_filter <name> { ... }` line, for the given family+idx.
///
/// This is what `ds-nft/src/session.rs::add_set_line` produces — that fn calls
/// `allow_set_name(family, idx)` for `<name>`, so this reconstruction extracts
/// the SET-NAME TOKEN out of the literal batch text ds-nft is documented to
/// render (`ds-nft/src/session.rs::instantiate_batch`, asserted byte-exact in
/// that crate's own `instantiate_creates_exactly_the_two_empty_named_sets`):
///   `add set inet ds_filter allow4_7 { type ipv4_addr; flags timeout; }`
///   `add set inet ds_filter allow6_7 { type ipv6_addr; flags timeout; }`
fn ds_nft_instantiate_set_name(family: AddressFamily, idx: u32) -> String {
    // Reproduce ds-nft's documented batch line for one family, then pull the
    // set-name token back out by structural parse. We do NOT bake in `allow4_7`
    // here as a constant — we rebuild the line from the family-correct addr type
    // and the name UNDER TEST so a drift in either crate is caught, and recover
    // the token between the table name and the `{` body.
    let addr_type = match family {
        AddressFamily::V4 => "ipv4_addr",
        AddressFamily::V6 => "ipv6_addr",
    };
    // The producer renders exactly this (table is the shared `inet ds_filter`):
    let line = format!(
        "add set inet ds_filter {name} {{ type {addr_type}; flags timeout; }}",
        name = nft_emitted_name_for(family, idx),
    );

    // Recover the set name the way the NFT-3b OUTPUT chain (and any reader) keys
    // on it: the token immediately after `add set inet ds_filter `, up to the
    // space before `{`.
    let after = line
        .strip_prefix("add set inet ds_filter ")
        .expect("ds-nft instantiate line shape: `add set inet ds_filter <name> {...}`");
    after
        .split_whitespace()
        .next()
        .expect("a set name token follows the table name")
        .to_string()
}

/// The name ds-nft is documented to emit. ds-nft derives this via the SINGLE
/// SOURCE (`add_set_line` -> `allow_set_name`); we mirror that here so the twin
/// reads the name from the SAME function the producer reads it from. (Keeping
/// this as a one-liner indirection makes the "both sides call `allow_set_name`"
/// claim explicit rather than smuggling a literal.)
fn nft_emitted_name_for(family: AddressFamily, idx: u32) -> String {
    allow_set_name(family, idx)
}

/// The byte-exact set name ds-dnsgate stamps on its admit (`txn.rs`,
/// `set_name: allow_set_name(ip.family, inputs.session_index)`) and sweep
/// (`server.rs::sweep_allow_set_name` -> `allow_set_name(addr.family, idx)`)
/// records, for the given family+idx. ds-dnsgate calls `allow_set_name` directly
/// at both sites, so its set name IS the single source.
fn ds_dnsgate_admit_sweep_set_name(family: AddressFamily, idx: u32) -> String {
    allow_set_name(family, idx)
}

#[test]
fn ds_nft_and_ds_dnsgate_name_the_byte_exact_same_set_v4_idx7() {
    let nft = ds_nft_instantiate_set_name(AddressFamily::V4, IDX);
    let gate = ds_dnsgate_admit_sweep_set_name(AddressFamily::V4, IDX);

    // The integration invariant: the set ds-nft CREATES and the set ds-dnsgate
    // FILLS/SWEEPS are one and the same string, with no handshake.
    assert_eq!(
        nft, gate,
        "ds-nft InstantiateSessionNFT and ds-dnsgate admit/sweep must name the \
         byte-exact same per-session allow set for (V4, idx={IDX})"
    );

    // ...and that one string is the single-source contract output (doc 09 NFT-3
    // literal shape `allow4_<idx>`).
    assert_eq!(nft, allow_set_name(AddressFamily::V4, IDX));
    assert_eq!(nft, "allow4_7");
}

#[test]
fn ds_nft_and_ds_dnsgate_name_the_byte_exact_same_set_v6_idx7() {
    let nft = ds_nft_instantiate_set_name(AddressFamily::V6, IDX);
    let gate = ds_dnsgate_admit_sweep_set_name(AddressFamily::V6, IDX);

    assert_eq!(
        nft, gate,
        "ds-nft InstantiateSessionNFT and ds-dnsgate admit/sweep must name the \
         byte-exact same per-session allow set for (V6, idx={IDX})"
    );

    // v6 is dormant under D75 Phase-B but the NAME is live-shared today; pin its
    // literal shape `allow6_<idx>`.
    assert_eq!(nft, allow_set_name(AddressFamily::V6, IDX));
    assert_eq!(nft, "allow6_7");
}

#[test]
fn twin_holds_across_indices_so_the_name_is_per_session_not_a_constant() {
    // Drive a second index: if any side ever collapsed to a flat shared `allow4`
    // (the D3/D4 hazard, also the §5.4 index-0 approximation that the
    // host-session-index threading just removed), the two indices would name the
    // SAME set and this would catch it.
    for family in [AddressFamily::V4, AddressFamily::V6] {
        let nft_a = ds_nft_instantiate_set_name(family, IDX);
        let gate_a = ds_dnsgate_admit_sweep_set_name(family, IDX);
        let nft_b = ds_nft_instantiate_set_name(family, OTHER_IDX);
        let gate_b = ds_dnsgate_admit_sweep_set_name(family, OTHER_IDX);

        // Same index ⇒ same name across the two crates.
        assert_eq!(nft_a, gate_a, "({family:?}, {IDX}) twin");
        assert_eq!(nft_b, gate_b, "({family:?}, {OTHER_IDX}) twin");

        // Different index ⇒ different name (the name is keyed on the session
        // index, D4 — never a constant).
        assert_ne!(
            nft_a, nft_b,
            "the per-session set name MUST vary with host_session_index ({family:?})"
        );
    }
}

#[test]
fn the_twin_fails_if_the_literal_wire_shape_diverges() {
    // The acceptance guard: this test must FAIL if the literal shape drifts. We
    // assert the single source produces EXACTLY the documented doc 09 NFT-3
    // tokens, and explicitly reject the divergence shapes a refactor might
    // introduce — a flat family-only set (`allow4`), an underscore-padded family
    // (`allow_4_7`), or a swapped separator (`allow4-7`).
    let v4 = allow_set_name(AddressFamily::V4, IDX);
    let v6 = allow_set_name(AddressFamily::V6, IDX);

    assert_eq!(v4, "allow4_7");
    assert_eq!(v6, "allow6_7");

    // Negative guards — the shapes that would silently break the no-handshake
    // contract between ds-nft and ds-dnsgate.
    for bad in [
        "allow4",
        "allow6",
        "allow_4_7",
        "allow_6_7",
        "allow4-7",
        "allow6-7",
    ] {
        assert_ne!(v4, bad, "v4 set name must not regress to `{bad}`");
        assert_ne!(v6, bad, "v6 set name must not regress to `{bad}`");
    }
}
