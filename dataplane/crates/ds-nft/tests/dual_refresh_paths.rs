//! "Both kernel refresh paths in CI" (D68; doc 14 §6/§11) — the always-run
//! dual-strategy assertions that gate BOTH refresh paths on ANY kernel.
//!
//! These run inside the existing `rust-dataplane.yml` cargo-test job (no
//! workflow edit). They assert the GENERATED batch text/ops for both the ≥6.12
//! in-place element-timeout update AND the pre-6.12 delete+add fallback, against
//! the recording fake — so the ≥6.12 path's batch is asserted even though
//! GitHub `ubuntu-latest` runs kernel 6.8 and cannot REALLY execute the in-place
//! update (that is M0-host work, capability-probed below).
//!
//! An optional `nft -c` syntax check of the generated batch is capability-probed
//! and skips cleanly when `nft` is absent or refuses (sandbox/restricted
//! netlink). Set-element ops need no `ct state` expression, so wave 1's
//! ct-module failure signature does not apply here.

use std::process::Command;

use ds_contracts::mark::Leg;
use ds_nft::backend::{NftBackend, NftBatch, RecordingBackend};
use ds_nft::mark_match::MarkMatch;
use ds_nft::refresh::{
    refresh_batch, KernelProbe, RefreshRequest, RefreshStrategy, INPLACE_MIN_KERNEL,
};

fn sample_req() -> RefreshRequest {
    RefreshRequest {
        set_name: "allow4".into(),
        mark: MarkMatch::for_leg(Leg::AgentVm, 7),
        element: "203.0.113.10".into(),
        timeout_secs: 900,
    }
}

/// CI assertion #1: the ≥6.12 in-place batch is a single in-place add with the
/// new timeout — generated and asserted on any kernel (its REAL execution is
/// M0-host work).
#[test]
fn inplace_batch_generated_on_any_kernel() {
    let batch = refresh_batch(RefreshStrategy::InPlace, &sample_req());
    assert!(batch.text.contains("refresh:inplace"));
    assert!(batch.text.contains("add element inet ds_filter allow4"));
    assert!(!batch.text.contains("delete element"));
    assert!(batch.text.contains("timeout 900s"));
    // carries the masked value/mask token, never a raw literal.
    assert!(batch.text.contains("/0xff003fff"));
}

/// CI assertion #2: the pre-6.12 fallback batch deletes then adds within ONE
/// batch (the OQ5 one-transaction invariant).
#[test]
fn delete_add_fallback_batch_is_one_batch_delete_then_add() {
    let batch = refresh_batch(RefreshStrategy::DeleteAdd, &sample_req());
    assert!(batch.text.contains("refresh:delete+add"));
    let del = batch.text.find("delete element").expect("delete present");
    let add = batch.text.find("add element").expect("add present");
    assert!(del < add, "delete must precede add inside the one batch");
    assert!(batch.text.contains("timeout 900s"));
}

/// CI assertion #3: the kernel probe with the explicit override drives BOTH
/// paths through one API — and a single applied backend exercises each.
#[test]
fn one_api_drives_both_paths_through_the_backend() {
    let backend = RecordingBackend::new();

    // Force in-place (override) and apply.
    let inplace = KernelProbe::Forced(RefreshStrategy::InPlace).resolve("6.8.0-ci");
    backend
        .apply_batch(&refresh_batch(inplace, &sample_req()))
        .unwrap();

    // Force delete+add (override) and apply.
    let fallback = KernelProbe::Forced(RefreshStrategy::DeleteAdd).resolve("7.0.0-ci");
    backend
        .apply_batch(&refresh_batch(fallback, &sample_req()))
        .unwrap();

    let batches = backend.batches();
    assert_eq!(batches.len(), 2);
    assert!(batches[0].text.contains("refresh:inplace"));
    assert!(batches[1].text.contains("refresh:delete+add"));
}

/// CI assertion #4: the live-probe boundary is exactly 6.12.
#[test]
fn live_probe_boundary_is_6_12() {
    assert_eq!(INPLACE_MIN_KERNEL, (6, 12));
    assert_eq!(
        KernelProbe::Live.resolve("6.12.0-x"),
        RefreshStrategy::InPlace
    );
    assert_eq!(
        KernelProbe::Live.resolve("6.11.9-x"),
        RefreshStrategy::DeleteAdd
    );
}

/// Capability-probed `nft -c` syntax check of BOTH generated batches. Skips
/// cleanly when `nft` is unavailable or refuses (no kernel tables / restricted
/// netlink). The batch is wrapped in a scratch table/set so `nft -c` has
/// context; `-c` is check-only and never commits.
#[test]
fn nft_check_accepts_both_batches_when_available() {
    if !nft_available() {
        eprintln!("skip: nft -c unavailable (sandbox/restricted netlink); batch text asserted by the unit tests above");
        return;
    }
    for strat in [RefreshStrategy::InPlace, RefreshStrategy::DeleteAdd] {
        let batch = refresh_batch(strat, &sample_req());
        let wrapped = wrap_for_check(&batch);
        match nft_check(&wrapped) {
            Ok(()) => {}
            Err(msg) => {
                // A restricted environment can reject the dynamic-set context
                // even when syntax is fine; treat a netlink/permission refusal
                // as a skip, not a failure (the brief's environment wall).
                if is_environment_refusal(&msg) {
                    eprintln!("skip nft -c for {strat:?}: environment refusal: {msg}");
                } else {
                    panic!(
                        "nft -c rejected the {strat:?} batch:\n{msg}\nbatch:\n{}",
                        wrapped.text
                    );
                }
            }
        }
    }
}

fn nft_available() -> bool {
    Command::new("nft")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Wrap a refresh batch in a scratch table + timeout-flagged set so `nft -c`
/// has the object context to syntax-check the element ops. The set carries a
/// `timeout` flag (set-element timeouts are nftables core, not conntrack).
fn wrap_for_check(batch: &NftBatch) -> NftBatch {
    let text = format!(
        "add table inet ds_filter\n\
         add set inet ds_filter allow4 {{ type ipv4_addr; flags timeout; }}\n\
         {body}",
        body = batch.text,
    );
    NftBatch::new(text)
}

fn nft_check(batch: &NftBatch) -> Result<(), String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("nft")
        .arg("-c")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nft -c: {e}"))?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(batch.text.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn is_environment_refusal(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("permission denied")
        || m.contains("operation not permitted")
        || m.contains("not supported")
        || m.contains("no such file")
        || m.contains("could not process rule")
}
