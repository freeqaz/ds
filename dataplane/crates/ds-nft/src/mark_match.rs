//! Masked conntrack-mark match composition (doc 14 §5, D76).
//!
//! Every conntrack match a flush issues is `<composed> & DS_MARK_MASK`, where
//! `<composed>` comes from [`ds_contracts::mark::compose`] and the mask is the
//! frozen [`ds_contracts::mark::DS_MARK_MASK`]. The mask is what makes a
//! **bare-index match never fire** against the composite layout: matching the
//! raw index alone (`0..=0x3FFF`) would also match foreign fwmark users that
//! happen to share those low bits, and would miss the magic+leg high bits a real
//! DS conntrack entry carries. By always pairing `value/mask` we match exactly
//! the magic ∪ leg ∪ index bits Dream Serpent owns and nothing else (the
//! Tailscale PR-5606 lesson).
//!
//! No raw DS-mark hex literal appears here or anywhere else in this crate: the
//! magic `0xD`, the leg nibbles, and the mask all come from `ds_contracts::mark`.

use ds_contracts::mark::{compose, is_ds_mark, Leg, DS_MARK_MASK};

/// A composed conntrack-mark match: a value paired with the frozen
/// [`DS_MARK_MASK`]. The contract is that the value's non-DS bits are zero (it
/// came from [`compose`]) and the match is always applied under the mask — a
/// bare value never reaches the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarkMatch {
    /// The composed value: magic ∪ leg ∪ index, every other bit zero.
    value: u32,
    /// The mask the match is applied under — always [`DS_MARK_MASK`].
    mask: u32,
}

impl MarkMatch {
    /// Compose the match for a `(leg, host_session_index)` pair. The index is
    /// reduced `mod 2^14` by [`compose`]; the result is masked-by-construction.
    pub fn for_leg(leg: Leg, host_session_index: u32) -> MarkMatch {
        let value = compose(leg, host_session_index);
        // Invariant the whole crate leans on: a composed value sets no bit
        // outside the owned mask, so `value & DS_MARK_MASK == value`.
        debug_assert_eq!(value & !DS_MARK_MASK, 0);
        debug_assert!(is_ds_mark(value));
        MarkMatch {
            value,
            mask: DS_MARK_MASK,
        }
    }

    /// The composed value (magic ∪ leg ∪ index).
    pub fn value(&self) -> u32 {
        self.value
    }

    /// The mask the match is applied under — always [`DS_MARK_MASK`]. Exposed so
    /// callers and tests can assert the match is never emitted bare.
    pub fn mask(&self) -> u32 {
        self.mask
    }

    /// Whether this match would fire on a kernel ct-mark register holding `raw`.
    /// The kernel semantics being modelled: `ct mark & mask == value`. A
    /// bare-index value (the high magic/leg bits cleared) will NOT match a real
    /// DS entry, which is the whole point of the mask.
    pub fn matches_register(&self, raw: u32) -> bool {
        raw & self.mask == self.value
    }

    /// Render the `value/mask` token an `nft` expression or a `conntrack -D`
    /// `--mark` argument consumes: the lower-case-hex composed value, a `/`, and
    /// the lower-case-hex mask (the magic+leg+index value over `DS_MARK_MASK`).
    /// Both fields are produced from the `ds_contracts::mark` constants — never a
    /// typed-in literal.
    pub fn to_value_mask_token(&self) -> String {
        format!("0x{:x}/0x{:x}", self.value, self.mask)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ds_contracts::mark::{decompose, DS_MARK_MAGIC};

    #[test]
    fn composed_value_is_masked_by_construction() {
        let m = MarkMatch::for_leg(Leg::AgentVm, 7);
        // The value never sets a bit outside the owned mask.
        assert_eq!(m.value() & !DS_MARK_MASK, 0);
        // And the mask is always the frozen constant — never a local literal.
        assert_eq!(m.mask(), DS_MARK_MASK);
    }

    #[test]
    fn a_bare_index_match_never_fires() {
        // The legitimate DS conntrack entry for (AgentVm, idx=7).
        let real = compose(Leg::AgentVm, 7);
        let m = MarkMatch::for_leg(Leg::AgentVm, 7);
        assert!(m.matches_register(real), "the real entry must match");

        // A *bare* index match — index 7 with the magic/leg high bits cleared —
        // is what a naive implementation would write. Under the mask it does NOT
        // match the real composite entry, proving the bare-index match is inert.
        let bare_index_value = 7u32; // no magic, no leg nibble.
        assert_ne!(
            real & DS_MARK_MASK,
            bare_index_value,
            "a bare index must never equal the masked composite value"
        );
    }

    #[test]
    fn match_distinguishes_legs_at_the_same_index() {
        let agent = MarkMatch::for_leg(Leg::AgentVm, 42);
        let tls = MarkMatch::for_leg(Leg::TlsproxyUpstream, 42);
        // Same index, different leg → different value, so one never fires on the
        // other's register.
        assert_ne!(agent.value(), tls.value());
        assert!(!agent.matches_register(tls.value()));
        assert!(!tls.matches_register(agent.value()));
    }

    #[test]
    fn match_ignores_foreign_bits_in_the_unclaimed_gap() {
        let m = MarkMatch::for_leg(Leg::AgentVm, 3);
        let real = compose(Leg::AgentVm, 3);
        // A coexisting WireGuard fwmark living only in the unclaimed gap must
        // not stop the DS match from firing (mask drops those bits).
        let coexist = real | (51_820u32 & !DS_MARK_MASK);
        assert!(m.matches_register(coexist));
    }

    #[test]
    fn value_mask_token_round_trips_through_decompose() {
        let m = MarkMatch::for_leg(Leg::TlsproxyUpstream, 9);
        let parts = decompose(m.value()).expect("composed value decodes");
        assert_eq!(parts.leg, Leg::TlsproxyUpstream);
        assert_eq!(parts.session_index, 9);
        // magic is present in the rendered token.
        let token = m.to_value_mask_token();
        assert!(token.ends_with(&format!("/0x{:x}", DS_MARK_MASK)));
        // the magic nibble 0xD leads the value field.
        let value_hex = token.split('/').next().unwrap();
        assert!(value_hex.starts_with(&format!("0x{:x}", DS_MARK_MAGIC)));
    }

    #[test]
    fn index_wraps_mod_two_to_the_fourteenth_in_the_match() {
        // composing a wrapped index is identical to composing the residue.
        let a = MarkMatch::for_leg(Leg::AgentVm, 16_384 + 5);
        let b = MarkMatch::for_leg(Leg::AgentVm, 5);
        assert_eq!(a.value(), b.value());
    }
}
