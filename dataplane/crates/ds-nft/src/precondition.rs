//! The `nf_conntrack_tcp_loose=0` effectiveness precondition (doc 14 §11; doc
//! 11 §5.4 host-baseline note).
//!
//! Without `net.netfilter.nf_conntrack_tcp_loose=0`, a flushed flow's
//! mid-stream packets are re-picked-up as ESTABLISHED and **the flush is a
//! no-op**. This is a host-baseline obligation owned by NFT-1 (doc 14 §11) and
//! merely *consumed* here — ds-nft does not set the sysctl. What ds-nft owns is
//! a probe so a caller can refuse to claim a flush succeeded on a misconfigured
//! host, and the doc-comment that records the no-op consequence.
//!
//! The probe reads the sysctl path, is injectable for tests, and returns
//! [`TcpLoose::Unknown`] when the path is absent (e.g. the sandbox kernel with
//! no loadable `nf_conntrack`, or a container without the procfs entry).

use std::path::{Path, PathBuf};

/// The procfs path the `nf_conntrack_tcp_loose` toggle is read from.
pub const TCP_LOOSE_SYSCTL_PATH: &str = "/proc/sys/net/netfilter/nf_conntrack_tcp_loose";

/// The state of the `nf_conntrack_tcp_loose` precondition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpLoose {
    /// `=0` — the required state; a flush can actually terminate flows.
    Disabled,
    /// `=1` (or any non-zero) — flushed flows are re-picked-up as ESTABLISHED,
    /// so the flush is a **no-op**. The caller should treat a flush as
    /// ineffective and surface the host-baseline drift (doc 14 §11).
    Enabled,
    /// The sysctl path is absent (no `nf_conntrack` loaded, or a restricted
    /// procfs). The effectiveness of a flush cannot be asserted.
    Unknown,
}

impl TcpLoose {
    /// Whether a flush issued on a host in this state can be relied on to
    /// actually terminate established flows. Only [`TcpLoose::Disabled`] is
    /// effective; both `Enabled` and `Unknown` are NOT relied upon.
    pub fn flush_is_effective(self) -> bool {
        matches!(self, TcpLoose::Disabled)
    }
}

/// Probes the `nf_conntrack_tcp_loose` precondition. Injectable for tests: the
/// reader is the only side effect.
#[derive(Clone, Debug)]
pub struct TcpLooseProbe {
    path: PathBuf,
}

impl TcpLooseProbe {
    /// A probe reading the real sysctl path ([`TCP_LOOSE_SYSCTL_PATH`]).
    pub fn live() -> TcpLooseProbe {
        TcpLooseProbe {
            path: PathBuf::from(TCP_LOOSE_SYSCTL_PATH),
        }
    }

    /// A probe reading an injected path (tests point this at a temp file; absent
    /// path → [`TcpLoose::Unknown`]).
    pub fn at_path(path: impl Into<PathBuf>) -> TcpLooseProbe {
        TcpLooseProbe { path: path.into() }
    }

    /// Read the current state. A missing/unreadable path is [`TcpLoose::Unknown`];
    /// a `0` is `Disabled`; anything else parseable as non-zero is `Enabled`;
    /// unparseable content is `Unknown` (fail-safe: never claim effectiveness on
    /// a value we can't read).
    pub fn probe(&self) -> TcpLoose {
        classify(read_path(&self.path).as_deref())
    }
}

/// Read a path to a string, or `None` if absent/unreadable. Split out so the
/// classification is unit-testable without touching the filesystem.
fn read_path(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

/// Classify the raw sysctl content into a [`TcpLoose`] state.
pub fn classify(content: Option<&str>) -> TcpLoose {
    match content {
        None => TcpLoose::Unknown,
        Some(raw) => match raw.trim().parse::<i64>() {
            Ok(0) => TcpLoose::Disabled,
            Ok(_) => TcpLoose::Enabled,
            Err(_) => TcpLoose::Unknown,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_values() {
        assert_eq!(classify(Some("0\n")), TcpLoose::Disabled);
        assert_eq!(classify(Some("0")), TcpLoose::Disabled);
        assert_eq!(classify(Some("1\n")), TcpLoose::Enabled);
        assert_eq!(classify(Some("2")), TcpLoose::Enabled);
        assert_eq!(classify(None), TcpLoose::Unknown);
        assert_eq!(classify(Some("garbage")), TcpLoose::Unknown);
        assert_eq!(classify(Some("")), TcpLoose::Unknown);
    }

    #[test]
    fn only_disabled_is_effective() {
        assert!(TcpLoose::Disabled.flush_is_effective());
        assert!(!TcpLoose::Enabled.flush_is_effective());
        assert!(!TcpLoose::Unknown.flush_is_effective());
    }

    #[test]
    fn absent_path_probes_unknown() {
        // The sandbox kernel has no loadable nf_conntrack; an absent path must
        // be Unknown, never falsely Disabled.
        let probe = TcpLooseProbe::at_path("/nonexistent/ds-nft/tcp_loose");
        assert_eq!(probe.probe(), TcpLoose::Unknown);
    }

    #[test]
    fn probe_reads_injected_path() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("ds_nft_tcp_loose_{}", std::process::id()));
        std::fs::write(&path, "0\n").unwrap();
        let probe = TcpLooseProbe::at_path(&path);
        assert_eq!(probe.probe(), TcpLoose::Disabled);
        std::fs::write(&path, "1\n").unwrap();
        assert_eq!(probe.probe(), TcpLoose::Enabled);
        let _ = std::fs::remove_file(&path);
    }
}
