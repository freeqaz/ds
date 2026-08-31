//! The richer internal flush outcome (doc 14 §5/§11; doc 11 §5.4).
//!
//! The frozen [`ds_contracts::flush::FlushOutcome`] carries only
//! `entries_flushed`. NFT-6 teardown needs MORE: per-entry destroy records with
//! byte counts, so the caller can emit final destroy events into ds-flowlog
//! (doc 14 §5: "emits final destroy events with byte counts"). That richer shape
//! lives HERE, internal to ds-nft; the frozen contract stays untouched, and the
//! caller maps [`FlushReport`] → `FlushOutcome` (and later → ds-flowlog) itself.
//!
//! Byte counts come from conntrack accounting output (`nf_conntrack_acct=1`, doc
//! 14 §11). With accounting on, `conntrack -D` prints one line per destroyed
//! entry carrying `bytes=<n>` in each direction; this module parses those lines.

use ds_contracts::flush::FlushOutcome;

/// One destroyed conntrack entry's accounting (doc 14 §11). Byte counts are the
/// last observed totals before destruction; `None` when accounting was off or
/// the field was absent from the line.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DestroyRecord {
    /// Original-direction byte count (`bytes=` in the first tuple), if present.
    pub orig_bytes: Option<u64>,
    /// Reply-direction byte count (`bytes=` in the reply tuple), if present.
    pub reply_bytes: Option<u64>,
    /// The destination address the entry was to, if the line carried `dst=`.
    pub dst: Option<String>,
}

impl DestroyRecord {
    /// Total bytes (orig + reply) for this entry, treating absent counts as 0.
    pub fn total_bytes(&self) -> u64 {
        self.orig_bytes.unwrap_or(0) + self.reply_bytes.unwrap_or(0)
    }
}

/// The richer internal flush report (ds-nft-internal; NOT the frozen contract).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FlushReport {
    /// One record per destroyed entry, in parse order.
    pub records: Vec<DestroyRecord>,
}

impl FlushReport {
    /// Number of entries destroyed — what the frozen contract surfaces.
    pub fn entries_flushed(&self) -> u64 {
        self.records.len() as u64
    }

    /// Sum of all entries' byte counts (for the ds-flowlog destroy event).
    pub fn total_bytes(&self) -> u64 {
        self.records.iter().map(DestroyRecord::total_bytes).sum()
    }

    /// Collapse to the frozen [`FlushOutcome`] the contract returns. The caller
    /// keeps the full [`FlushReport`] for ds-flowlog and hands this minimal
    /// shape back through the trait.
    pub fn to_outcome(&self) -> FlushOutcome {
        FlushOutcome {
            entries_flushed: self.entries_flushed(),
        }
    }
}

/// Parse conntrack `-D` accounting output into a [`FlushReport`].
///
/// `conntrack -D` with `nf_conntrack_acct=1` prints one line per destroyed
/// entry, with two `bytes=<n>` tokens (original then reply direction) and a
/// `dst=<addr>` in the original tuple, e.g.:
///
/// ```text
/// tcp 6 src=10.0.0.5 dst=203.0.113.10 sport=51514 dport=443 packets=12 bytes=1840 \
///     src=203.0.113.10 dst=10.0.0.5 sport=443 dport=51514 packets=10 bytes=5120 [ASSURED]
/// ```
///
/// Lines that are not per-entry accounting (a trailing
/// `conntrack v1.x.x (conntrack-tools): N flow entries have been deleted.`
/// summary, or blank lines) are skipped. Each kept line yields one
/// [`DestroyRecord`]; the FIRST `bytes=` is original, the SECOND is reply, the
/// FIRST `dst=` is the destination.
pub fn parse_destroy_output(lines: &[String]) -> FlushReport {
    let mut records = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() || !is_entry_line(line) {
            continue;
        }
        let bytes: Vec<u64> = line
            .split_whitespace()
            .filter_map(|tok| tok.strip_prefix("bytes="))
            .filter_map(|v| v.parse::<u64>().ok())
            .collect();
        let dst = line
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix("dst="))
            .map(|s| s.to_string());
        records.push(DestroyRecord {
            orig_bytes: bytes.first().copied(),
            reply_bytes: bytes.get(1).copied(),
            dst,
        });
    }
    FlushReport { records }
}

/// Whether a captured line is a per-entry accounting line (vs the deletion
/// summary or a usage line). A per-entry line carries an `src=`/`dst=` tuple;
/// the summary line carries "flow entries have been deleted".
fn is_entry_line(line: &str) -> bool {
    if line.contains("flow entries have been deleted") {
        return false;
    }
    line.contains("src=") || line.contains("dst=")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canned conntrack accounting output, inline (no fixtures/ dir → no D50
    // gate). Two destroyed TCP entries plus the deletion-summary line that
    // conntrack prints last.
    fn canned_two_entries() -> Vec<String> {
        vec![
            "tcp 6 110 src=10.0.0.5 dst=203.0.113.10 sport=51514 dport=443 \
             packets=12 bytes=1840 src=203.0.113.10 dst=10.0.0.5 sport=443 \
             dport=51514 packets=10 bytes=5120 [ASSURED] mark=3506962439"
                .to_string(),
            "tcp 6 95 src=10.0.0.5 dst=198.51.100.7 sport=51600 dport=443 \
             packets=3 bytes=400 src=198.51.100.7 dst=10.0.0.5 sport=443 \
             dport=51600 packets=2 bytes=900 [ASSURED] mark=3506962439"
                .to_string(),
            "conntrack v1.4.7 (conntrack-tools): 2 flow entries have been deleted.".to_string(),
        ]
    }

    #[test]
    fn parses_per_entry_byte_counts_skipping_the_summary() {
        let report = parse_destroy_output(&canned_two_entries());
        assert_eq!(report.entries_flushed(), 2);

        let first = &report.records[0];
        assert_eq!(first.orig_bytes, Some(1840));
        assert_eq!(first.reply_bytes, Some(5120));
        assert_eq!(first.dst.as_deref(), Some("203.0.113.10"));
        assert_eq!(first.total_bytes(), 1840 + 5120);

        let second = &report.records[1];
        assert_eq!(second.orig_bytes, Some(400));
        assert_eq!(second.reply_bytes, Some(900));
        assert_eq!(second.dst.as_deref(), Some("198.51.100.7"));

        assert_eq!(report.total_bytes(), 1840 + 5120 + 400 + 900);
    }

    #[test]
    fn empty_output_is_zero_entries() {
        let report = parse_destroy_output(&[]);
        assert_eq!(report.entries_flushed(), 0);
        assert_eq!(report.total_bytes(), 0);
    }

    #[test]
    fn output_with_only_summary_yields_no_records() {
        let lines =
            vec!["conntrack v1.4.7 (conntrack-tools): 0 flow entries have been deleted.".into()];
        let report = parse_destroy_output(&lines);
        assert_eq!(report.entries_flushed(), 0);
    }

    #[test]
    fn accounting_off_yields_records_with_no_byte_counts() {
        // Without nf_conntrack_acct=1 the line has no bytes= tokens.
        let lines = vec![
            "tcp 6 110 src=10.0.0.5 dst=203.0.113.10 sport=51514 dport=443 \
             src=203.0.113.10 dst=10.0.0.5 sport=443 dport=51514 [ASSURED]"
                .to_string(),
        ];
        let report = parse_destroy_output(&lines);
        assert_eq!(report.entries_flushed(), 1);
        assert_eq!(report.records[0].orig_bytes, None);
        assert_eq!(report.records[0].reply_bytes, None);
        assert_eq!(report.records[0].total_bytes(), 0);
        // dst is still recoverable for the ds-flowlog event keying.
        assert_eq!(report.records[0].dst.as_deref(), Some("203.0.113.10"));
    }

    #[test]
    fn report_collapses_to_the_frozen_outcome() {
        let report = parse_destroy_output(&canned_two_entries());
        let outcome = report.to_outcome();
        assert_eq!(outcome.entries_flushed, 2);
    }
}
