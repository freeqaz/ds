//! The monitored wrap/exhaustion alarm predicate (doc 14 §4, ships with NFT-5).
//!
//! The 14-bit mark field carries the host-local session index `mod 2^14` as a
//! **disambiguator, not a primary key** (doc 14 §4, D76). If a host's count of
//! *live retention-window* indices approaches `2^14` (16,384), two distinct
//! sessions can fold onto the same residue and joins ambiguate. Doc 14 §4
//! mandates a "monitored wrap/exhaustion alarm [that] pages before joins can
//! ambiguate."
//!
//! This module is the **predicate only**: given the live-index count and a
//! parameterized threshold, decide whether to page. Emission wiring (where the
//! page goes) is later NFT-5 integration — out of scope here, by the brief.
//! Allocator behavior AT exhaustion (block new sessions vs extend the layout)
//! is doc 14 OQ4 / Stage-5 work, also out of scope: this only pages.

use ds_contracts::mark::SESSION_INDEX_MODULUS;

/// The number of distinct residues the 14-bit field can hold before wrap:
/// `2^14 = 16_384` (doc 14 §4). Re-exported from the frozen constant so the
/// alarm's ceiling can never skew from the mark layout.
pub const INDEX_SPACE: u32 = SESSION_INDEX_MODULUS;

/// The default page threshold as a fraction of [`INDEX_SPACE`]: page when live
/// indices reach 90% of the space. Parameterized — ops can tune it via
/// [`WrapAlarm::with_threshold_fraction`] or an absolute count
/// ([`WrapAlarm::with_threshold_count`]) — but a default ships so NFT-5 has a
/// working alarm from day one.
pub const DEFAULT_THRESHOLD_FRACTION: f64 = 0.90;

/// The wrap/exhaustion alarm predicate (doc 14 §4). Holds the absolute live-index
/// count at which it pages; evaluation is a pure comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrapAlarm {
    /// Page when `live_indices >= threshold_count`.
    threshold_count: u32,
}

impl Default for WrapAlarm {
    fn default() -> WrapAlarm {
        WrapAlarm::with_threshold_fraction(DEFAULT_THRESHOLD_FRACTION)
    }
}

impl WrapAlarm {
    /// An alarm that pages at `fraction` of [`INDEX_SPACE`] (clamped to
    /// `0.0..=1.0`). `fraction = 0.9` → page at 14,745 of 16,384.
    pub fn with_threshold_fraction(fraction: f64) -> WrapAlarm {
        let frac = fraction.clamp(0.0, 1.0);
        // round to nearest; saturating into u32 is safe (space is 16_384).
        let threshold_count = (frac * INDEX_SPACE as f64).round() as u32;
        WrapAlarm { threshold_count }
    }

    /// An alarm that pages at an absolute live-index count (clamped to
    /// [`INDEX_SPACE`]).
    pub fn with_threshold_count(count: u32) -> WrapAlarm {
        WrapAlarm {
            threshold_count: count.min(INDEX_SPACE),
        }
    }

    /// The absolute count at which this alarm pages.
    pub fn threshold_count(&self) -> u32 {
        self.threshold_count
    }

    /// How many live retention-window indices remain before the page fires
    /// (saturating at 0).
    pub fn headroom(&self, live_indices: u32) -> u32 {
        self.threshold_count.saturating_sub(live_indices)
    }

    /// Whether `live_indices` (the count of distinct host-local indices live in
    /// the flow-log retention window) has reached the page threshold.
    pub fn should_page(&self, live_indices: u32) -> bool {
        live_indices >= self.threshold_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_space_tracks_the_frozen_modulus() {
        assert_eq!(INDEX_SPACE, 16_384);
    }

    #[test]
    fn default_pages_at_ninety_percent() {
        let alarm = WrapAlarm::default();
        // 0.9 * 16_384 = 14_745.6 → 14_746.
        assert_eq!(alarm.threshold_count(), 14_746);
        assert!(!alarm.should_page(14_745));
        assert!(alarm.should_page(14_746));
        assert!(alarm.should_page(16_384));
    }

    #[test]
    fn threshold_fraction_is_parameterized() {
        let half = WrapAlarm::with_threshold_fraction(0.5);
        assert_eq!(half.threshold_count(), 8_192);
        assert!(!half.should_page(8_191));
        assert!(half.should_page(8_192));
    }

    #[test]
    fn threshold_fraction_clamps_out_of_range() {
        assert_eq!(
            WrapAlarm::with_threshold_fraction(-1.0).threshold_count(),
            0
        );
        assert_eq!(
            WrapAlarm::with_threshold_fraction(2.0).threshold_count(),
            INDEX_SPACE
        );
        // fraction 0 pages immediately (count 0 means even 0 live trips it).
        assert!(WrapAlarm::with_threshold_fraction(0.0).should_page(0));
    }

    #[test]
    fn absolute_threshold_is_parameterized_and_clamped() {
        let alarm = WrapAlarm::with_threshold_count(1_000);
        assert_eq!(alarm.threshold_count(), 1_000);
        assert!(!alarm.should_page(999));
        assert!(alarm.should_page(1_000));
        // clamped to the index space.
        assert_eq!(
            WrapAlarm::with_threshold_count(100_000).threshold_count(),
            INDEX_SPACE
        );
    }

    #[test]
    fn headroom_counts_down_and_saturates() {
        let alarm = WrapAlarm::with_threshold_count(16_000);
        assert_eq!(alarm.headroom(15_000), 1_000);
        assert_eq!(alarm.headroom(16_000), 0);
        assert_eq!(alarm.headroom(16_384), 0);
    }
}
