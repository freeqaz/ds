//! ds-flowlog — the host flow-log collector (doc 09 §7, LOG-1..LOG-5).
//!
//! Skeleton stub: standard library only; compiles offline. The real service
//! joins conntrack/nflog kernel data with both proxies' event streams per
//! session, spools to disk-bounded local storage, ships off-box, and runs the
//! LOG-4 reconciliation: every byte that left a VM interface must be explained
//! by a proxy session or an explicit escape-hatch allowance — an unexplained
//! flow is an alarm, not a log line.

fn main() {
    eprintln!(
        "ds-flowlog: skeleton stub — no collector implemented yet \
         (see dataplane/services/ds-flowlog/README.md and docs/09-boundary-build-plan.md §7)"
    );
    std::process::exit(1);
}
