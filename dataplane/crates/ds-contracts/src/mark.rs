//! D76 mark-space layout — the one 32-bit layout shared by packet mark/fwmark
//! AND ct mark, both legs (doc 14 §5, ratified D76).
//!
//! ```text
//! | Bits  | Content                                                          |
//! |-------|------------------------------------------------------------------|
//! | 31–28 | magic 0xD                                                        |
//! | 27–24 | leg/type nibble (see `Leg`)                                      |
//! | 23–14 | PERMANENTLY UNCLAIMED — never set, never matched                 |
//! | 13–0  | host-local session index mod 2^14 (doc 14 §4)                    |
//! ```
//!
//! Bits 23–14 are left permanently unclaimed because other fwmark users live
//! there (kube-proxy 14–15, Weave 17–18, Tailscale claims bytes 16–23, UniFi
//! 17–22). Dream Serpent never sets and never matches them; the NFT-1 mark lint
//! ([`crate::nft_lint`] + `scripts/lint-nft-artifacts.sh`) fails the build on
//! any ruleset that touches them.
//!
//! Mask discipline (frozen, the Tailscale PR-5606 lesson): every nftables
//! set/match of a DS mark goes through an explicit mask. Compose/decompose here
//! are the only sanctioned way to turn a `(Leg, session_index)` pair into a raw
//! mark and back; raw mark literals never appear anywhere else (doc 14 §5).

/// Magic nibble in bits 31–28: marks a register value as Dream Serpent-owned.
pub const DS_MARK_MAGIC: u32 = 0xD;

/// Width of the magic field, in bits.
pub const MAGIC_BITS: u32 = 4;
/// Width of the leg/type nibble, in bits.
pub const LEG_BITS: u32 = 4;
/// Width of the permanently-unclaimed gap, in bits (23–14).
pub const UNCLAIMED_BITS: u32 = 10;
/// Width of the session-index field, in bits.
pub const INDEX_BITS: u32 = 14;

/// Least-significant bit position of the magic field (bit 28).
pub const MAGIC_SHIFT: u32 = 28;
/// Least-significant bit position of the leg/type nibble (bit 24).
pub const LEG_SHIFT: u32 = 24;
/// Least-significant bit position of the permanently-unclaimed gap (bit 14).
pub const UNCLAIMED_SHIFT: u32 = 14;
/// Least-significant bit position of the session-index field (bit 0).
pub const INDEX_SHIFT: u32 = 0;

/// Magic field mask, positioned (bits 31–28).
pub const MAGIC_MASK: u32 = ((1u32 << MAGIC_BITS) - 1) << MAGIC_SHIFT; // 0xF000_0000
/// Leg/type nibble mask, positioned (bits 27–24).
pub const LEG_MASK: u32 = ((1u32 << LEG_BITS) - 1) << LEG_SHIFT; // 0x0F00_0000
/// Permanently-unclaimed gap mask, positioned (bits 23–14).
///
/// This region is **never set and never matched**. It is exported only so the
/// NFT-1 lint and tests can assert that no DS mark write or match ever touches
/// it; `DS_MARK_MASK` deliberately excludes it.
pub const UNCLAIMED_MASK: u32 = ((1u32 << UNCLAIMED_BITS) - 1) << UNCLAIMED_SHIFT; // 0x00FF_C000
/// Session-index field mask, positioned (bits 13–0).
pub const INDEX_MASK: u32 = ((1u32 << INDEX_BITS) - 1) << INDEX_SHIFT; // 0x0000_3FFF

/// The DS mark mask: magic ∪ leg ∪ index — the bits Dream Serpent owns
/// (doc 14 §5, D76). The unclaimed gap (23–14) is **not** part of it.
///
/// Every nftables set/match of a DS mark uses this mask explicitly:
/// `meta mark set (meta mark & ~DS_MARK_MASK) | value`,
/// `meta mark & DS_MARK_MASK == value`. Full-register writes are forbidden.
pub const DS_MARK_MASK: u32 = MAGIC_MASK | LEG_MASK | INDEX_MASK; // 0xFF00_3FFF

/// Modulus of the session-index field: indices are carried `mod 2^14`
/// (doc 14 §4). The 14-bit field is a **disambiguator**, never the primary
/// join key — that is the never-recycled `dstap-<idx>` tap name.
pub const SESSION_INDEX_MODULUS: u32 = 1 << INDEX_BITS; // 16_384

/// The leg/type nibble (bits 27–24): which leg of the boundary a marked packet
/// or conntrack entry belongs to (doc 14 §5, D44/NFT-5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Leg {
    /// `0x1` — the agent-VM leg (D44/NFT-5).
    AgentVm,
    /// `0x2` — the ds-tlsproxy upstream leg.
    TlsproxyUpstream,
    /// `0x3` — the ds-dnsgate upstream-resolution leg.
    DnsgateUpstream,
    /// `0x4` — infrastructure egress.
    InfraEgress,
    /// `0xF` — reserved / diagnostic.
    Reserved,
}

impl Leg {
    /// The 4-bit nibble value (0x0–0xF) for this leg.
    pub const fn nibble(self) -> u32 {
        match self {
            Leg::AgentVm => 0x1,
            Leg::TlsproxyUpstream => 0x2,
            Leg::DnsgateUpstream => 0x3,
            Leg::InfraEgress => 0x4,
            Leg::Reserved => 0xF,
        }
    }

    /// Parse a leg from its 4-bit nibble value. Only the assigned values
    /// (0x1–0x4, 0xF) are recognised; all others — including 0x0 and the gap
    /// 0x5–0xE — return `None`.
    pub const fn from_nibble(nibble: u32) -> Option<Leg> {
        match nibble {
            0x1 => Some(Leg::AgentVm),
            0x2 => Some(Leg::TlsproxyUpstream),
            0x3 => Some(Leg::DnsgateUpstream),
            0x4 => Some(Leg::InfraEgress),
            0xF => Some(Leg::Reserved),
            _ => None,
        }
    }
}

/// The decoded contents of a DS mark (doc 14 §5). Carries the leg and the
/// session-index disambiguator; the magic nibble is validated on decode and not
/// re-surfaced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MarkParts {
    /// The leg/type nibble.
    pub leg: Leg,
    /// The host-local session index, already reduced `mod 2^14`.
    pub session_index: u16,
}

/// Why a raw value failed to decode as a DS mark (doc 14 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkError {
    /// Bits 31–28 were not the magic `0xD`.
    BadMagic(u32),
    /// The leg nibble (bits 27–24) was not an assigned `Leg` value.
    BadLeg(u32),
    /// Bits 23–14 — the permanently-unclaimed gap — were non-zero. A DS mark
    /// must never set them (doc 14 §5).
    UnclaimedBitsSet(u32),
}

/// Reduce a host-local session index to the 14-bit field, `mod 2^14`
/// (doc 14 §4). Wraparound is the documented contract: the field disambiguates,
/// it is not the primary key.
pub const fn session_index_field(host_session_index: u32) -> u16 {
    (host_session_index % SESSION_INDEX_MODULUS) as u16
}

/// Compose a DS mark from a leg and a host-local session index (doc 14 §5).
///
/// The index is reduced `mod 2^14`. The unclaimed gap is left zero. The result
/// is the value placed under `DS_MARK_MASK` on a packet/ct mark register:
/// `meta mark set (meta mark & ~DS_MARK_MASK) | compose(...)`.
pub const fn compose(leg: Leg, host_session_index: u32) -> u32 {
    (DS_MARK_MAGIC << MAGIC_SHIFT)
        | (leg.nibble() << LEG_SHIFT)
        | ((session_index_field(host_session_index) as u32) << INDEX_SHIFT)
}

/// Decompose a raw register value into its DS mark parts (doc 14 §5).
///
/// Validates the magic, the leg, and that the permanently-unclaimed gap is
/// zero. Callers that read a register holding foreign marks must first apply
/// [`DS_MARK_MASK`] (e.g. via [`is_ds_mark`]) — `decompose` is strict and will
/// reject any value with non-DS bits in the magic/leg/index span or any bit set
/// in the unclaimed gap.
pub const fn decompose(raw: u32) -> Result<MarkParts, MarkError> {
    let magic = (raw & MAGIC_MASK) >> MAGIC_SHIFT;
    if magic != DS_MARK_MAGIC {
        return Err(MarkError::BadMagic(magic));
    }
    if raw & UNCLAIMED_MASK != 0 {
        return Err(MarkError::UnclaimedBitsSet(raw & UNCLAIMED_MASK));
    }
    let leg_nibble = (raw & LEG_MASK) >> LEG_SHIFT;
    let leg = match Leg::from_nibble(leg_nibble) {
        Some(leg) => leg,
        None => return Err(MarkError::BadLeg(leg_nibble)),
    };
    let session_index = ((raw & INDEX_MASK) >> INDEX_SHIFT) as u16;
    Ok(MarkParts { leg, session_index })
}

/// Extract just the magic nibble (bits 31–28) from a raw register value.
pub const fn magic_of(raw: u32) -> u32 {
    (raw & MAGIC_MASK) >> MAGIC_SHIFT
}

/// Extract just the leg nibble (bits 27–24) from a raw register value, without
/// validating it against the assigned `Leg` set.
pub const fn leg_nibble_of(raw: u32) -> u32 {
    (raw & LEG_MASK) >> LEG_SHIFT
}

/// Extract just the 14-bit session-index field (bits 13–0) from a raw value.
pub const fn session_index_of(raw: u32) -> u16 {
    ((raw & INDEX_MASK) >> INDEX_SHIFT) as u16
}

/// Whether `raw`, reduced under [`DS_MARK_MASK`], carries the DS magic nibble —
/// a cheap "is this ours" check that ignores any foreign bits coexisting in the
/// same register (WireGuard `wg-quick` fwmark 51820, systemd-networkd, etc.).
pub const fn is_ds_mark(raw: u32) -> bool {
    magic_of(raw & DS_MARK_MASK) == DS_MARK_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_is_the_frozen_value() {
        // doc 14 §5: DS_MARK_MASK = 0xFF003FFF.
        assert_eq!(DS_MARK_MASK, 0xFF00_3FFF);
    }

    #[test]
    fn field_masks_partition_the_register() {
        // Magic, leg, unclaimed gap, and index are disjoint and cover the
        // whole 32-bit register exactly once.
        assert_eq!(MAGIC_MASK, 0xF000_0000);
        assert_eq!(LEG_MASK, 0x0F00_0000);
        assert_eq!(UNCLAIMED_MASK, 0x00FF_C000);
        assert_eq!(INDEX_MASK, 0x0000_3FFF);

        assert_eq!(MAGIC_MASK & LEG_MASK, 0);
        assert_eq!(LEG_MASK & UNCLAIMED_MASK, 0);
        assert_eq!(UNCLAIMED_MASK & INDEX_MASK, 0);
        assert_eq!(MAGIC_MASK & INDEX_MASK, 0);

        assert_eq!(
            MAGIC_MASK | LEG_MASK | UNCLAIMED_MASK | INDEX_MASK,
            0xFFFF_FFFF
        );
    }

    #[test]
    fn mask_excludes_the_unclaimed_gap() {
        // The owned mask must NOT include the permanently-unclaimed bits 23–14.
        assert_eq!(DS_MARK_MASK & UNCLAIMED_MASK, 0);
        // and it is exactly magic ∪ leg ∪ index.
        assert_eq!(DS_MARK_MASK, MAGIC_MASK | LEG_MASK | INDEX_MASK);
    }

    #[test]
    fn modulus_is_two_to_the_fourteenth() {
        assert_eq!(SESSION_INDEX_MODULUS, 16_384);
        assert_eq!(SESSION_INDEX_MODULUS, 1 << 14);
    }

    #[test]
    fn compose_then_decompose_round_trips_every_leg() {
        let legs = [
            Leg::AgentVm,
            Leg::TlsproxyUpstream,
            Leg::DnsgateUpstream,
            Leg::InfraEgress,
            Leg::Reserved,
        ];
        for leg in legs {
            for &idx in &[0u32, 1, 42, 16_383] {
                let raw = compose(leg, idx);
                // magic is always present.
                assert_eq!(magic_of(raw), DS_MARK_MAGIC);
                // composed marks never touch the unclaimed gap.
                assert_eq!(raw & UNCLAIMED_MASK, 0);
                let parts = decompose(raw).expect("round-trip");
                assert_eq!(parts.leg, leg);
                assert_eq!(parts.session_index as u32, idx);
                // the composed value is a subset of the owned mask.
                assert_eq!(raw & !DS_MARK_MASK, 0);
            }
        }
    }

    #[test]
    fn leg_nibble_values_match_doc14() {
        assert_eq!(Leg::AgentVm.nibble(), 0x1);
        assert_eq!(Leg::TlsproxyUpstream.nibble(), 0x2);
        assert_eq!(Leg::DnsgateUpstream.nibble(), 0x3);
        assert_eq!(Leg::InfraEgress.nibble(), 0x4);
        assert_eq!(Leg::Reserved.nibble(), 0xF);
    }

    #[test]
    fn leg_nibble_extraction_is_positional() {
        let raw = compose(Leg::DnsgateUpstream, 7);
        assert_eq!(leg_nibble_of(raw), 0x3);
        assert_eq!(magic_of(raw), 0xD);
        assert_eq!(session_index_of(raw), 7);
    }

    #[test]
    fn session_index_wraps_mod_two_to_the_fourteenth() {
        assert_eq!(session_index_field(0), 0);
        assert_eq!(session_index_field(16_383), 16_383);
        // 16_384 wraps to 0.
        assert_eq!(session_index_field(16_384), 0);
        // 16_385 wraps to 1.
        assert_eq!(session_index_field(16_385), 1);
        // a large host index folds into the field.
        assert_eq!(session_index_field(100_000), (100_000 % 16_384) as u16);
        // composing a wrapped index is the same as composing the residue.
        assert_eq!(compose(Leg::AgentVm, 16_384 + 5), compose(Leg::AgentVm, 5));
    }

    #[test]
    fn decompose_rejects_bad_magic() {
        // 0xC magic instead of 0xD.
        let raw = (0xCu32 << MAGIC_SHIFT) | (Leg::AgentVm.nibble() << LEG_SHIFT);
        assert_eq!(decompose(raw), Err(MarkError::BadMagic(0xC)));
    }

    #[test]
    fn decompose_rejects_unassigned_leg() {
        // 0x5 is in the leg gap (0x5–0xE), unassigned.
        let raw = (DS_MARK_MAGIC << MAGIC_SHIFT) | (0x5u32 << LEG_SHIFT);
        assert_eq!(decompose(raw), Err(MarkError::BadLeg(0x5)));
        // 0x0 is also not a valid leg.
        let raw0 = DS_MARK_MAGIC << MAGIC_SHIFT;
        assert_eq!(decompose(raw0), Err(MarkError::BadLeg(0x0)));
    }

    #[test]
    fn decompose_rejects_any_unclaimed_bit() {
        // A well-formed mark with a single unclaimed bit (bit 14) set must be
        // rejected — DS marks never touch 23–14.
        let raw = compose(Leg::TlsproxyUpstream, 9) | (1u32 << 14);
        match decompose(raw) {
            Err(MarkError::UnclaimedBitsSet(bits)) => assert_eq!(bits, 1u32 << 14),
            other => panic!("expected UnclaimedBitsSet, got {other:?}"),
        }
        // bit 23 (top of the gap) too.
        let raw_hi = compose(Leg::AgentVm, 0) | (1u32 << 23);
        match decompose(raw_hi) {
            Err(MarkError::UnclaimedBitsSet(bits)) => assert_eq!(bits, 1u32 << 23),
            other => panic!("expected UnclaimedBitsSet, got {other:?}"),
        }
    }

    #[test]
    fn is_ds_mark_ignores_foreign_register_bits() {
        // A DS mark coexisting with the WireGuard fwmark 51820 in the unclaimed
        // span is still recognised as ours under the mask.
        let ds = compose(Leg::AgentVm, 3);
        // simulate a foreign value living only in bits the mask drops.
        let coexist = ds | (51_820u32 & UNCLAIMED_MASK);
        assert!(is_ds_mark(coexist));
        // a non-DS magic is not ours.
        assert!(!is_ds_mark(0xC000_0000));
    }
}
