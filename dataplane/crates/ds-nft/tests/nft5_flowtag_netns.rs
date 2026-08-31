// SPDX-License-Identifier: Apache-2.0

//! NFT-5 live-kernel verification arm (deferred-manual, env-gated — D50).
//!
//! The offline half of NFT-5 is fully proven WITHOUT a kernel: the stamp-batch
//! rendering (`ds-nft::flowtag` unit tests), the mark-discipline lint over the
//! shipped `nft-5-flowtag.nft` artifact (`ds-contracts` mark lint), and the
//! conntrack/nflog → LOG-1 spool mapping (`ds-telemetry::flow` +
//! `tests/flow_spool.rs`). This test is the LIVE arm that a real kernel accepts
//! the masked per-session `ct mark` write and binds it — the thing only a kernel
//! can confirm.
//!
//! # Skip-by-default (D50): `DS_NFT5_LIVE=1` opts in
//!
//! Per the workspace D50 posture (loopback/synthetic only in default `cargo
//! test`; no live kernel/nft in the default run), this arm is GATED behind
//! `DS_NFT5_LIVE=1` AND a user+net-namespace probe (`unshare -rn`), so a default
//! `cargo test` NEVER touches nftables — it prints the committed host procedure
//! and returns. Enable it on a substrate that grants an unprivileged netns:
//!
//! ```sh
//! DS_NFT5_LIVE=1 cargo test -p ds-nft --test nft5_flowtag_netns -- --nocapture
//! ```
//!
//! The runnable-under-gate part loads the `ds_flowtag` skeleton + a per-session
//! stamp batch into a private netns and lists the stamp chain back, proving the
//! kernel accepts `ct mark set ct mark & ~DS_MARK_MASK | <composed>`. The
//! ct-mark-rides-a-REAL-FLOW proof (send traffic through a `dstap-*` veth, read
//! `conntrack -L` back, assert `mark=<composed>`) needs a wired data path and is
//! the committed [`HOST_TRAFFIC_PROCEDURE`] deferred to the nested v0 substrate
//! (substrate gap, not a design gap — the D34/D66 precedent).

use std::process::Command;

use ds_contracts::mark::{compose, Leg};
use ds_nft::backend::RecordingBackend;
use ds_nft::flowtag::FLOWTAG_TABLE;
use ds_nft::flush::NftWriter;

/// The committed host-only procedure that proves a REAL flow's conntrack entry
/// carries the stamped composite `ct mark` (deferred to the nested v0 substrate:
/// the dev sandbox has no loadable veth pair + conntrack in an unprivileged
/// netns). Kept verbatim so the deferred proof cannot rot into a vague TODO.
const HOST_TRAFFIC_PROCEDURE: &str = "\
HOST PROCEDURE — NFT-5 ct-mark rides a real flow (run as root on the v0 substrate):
  1. Bring up a per-session tap/veth named dstap-7 with a peer in the host netns.
  2. Ensure the host baseline conntrack sysctls are on:
       sysctl net.netfilter.nf_conntrack_acct=1 net.netfilter.nf_conntrack_timestamp=1
  3. Load the NFT-1 floor + the NFT-5 ds_flowtag skeleton, then apply the
     per-session stamp batch (flowtag::stamp_batch(7)) so dstap-7 -> tag_7.
  4. Originate one NEW tcp flow from behind dstap-7 to an admitted destination.
  5. conntrack -L -o extended | grep 'src=<vm>' MUST show mark=3506962439
       (0xd1000007 == compose(Leg::AgentVm, 7)) on the entry, with bytes=/packets=.
  6. Originate one NEW flow the floor DROPS; the group-5 nflog stream MUST carry a
       'ds-nft5-drop ' line with MARK=0xd1000007 (the stamp ran before the drop).
  7. Tear down: flowtag::unstamp_batch(7) removes tag_7 + the map element; assert
       the ct mark is no longer stamped on new flows (NFT-6 clean-teardown).
";

/// Run a script inside a fresh user+net namespace (`unshare -rn`). Returns the
/// combined stdout, or `None` when the sandbox cannot grant a private netns (CI
/// without user-namespace support) — in which case the caller skips.
fn nft_in_netns(script: &str) -> Option<String> {
    // Probe: can we get a namespaced nft at all?
    let probe = Command::new("unshare")
        .args(["-rn", "nft", "list", "ruleset"])
        .output();
    match probe {
        Ok(o) if o.status.success() => {}
        _ => return None,
    }
    let out = Command::new("unshare")
        .args(["-rn", "sh", "-c", script])
        .output()
        .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).to_string())
}

#[test]
fn ct_mark_stamp_binds_on_a_real_kernel_when_enabled() {
    if std::env::var_os("DS_NFT5_LIVE").is_none() {
        eprintln!(
            "SKIP (deferred-manual, D50): NFT-5 live-kernel arm is off by default. \
             Set DS_NFT5_LIVE=1 to run the netns nft-load proof. The stamp shape is \
             already pinned offline by ds-nft::flowtag unit tests, the mark lint over \
             nft-5-flowtag.nft, and the ds-telemetry flow_spool mapping test.\n{HOST_TRAFFIC_PROCEDURE}"
        );
        return;
    }

    // Render the exact runtime batch ds-nft would apply for host session index 7,
    // straight from the builder (no hand-authored ruleset — the shape under test IS
    // the shipped one). The RecordingBackend just captures the text.
    let w = NftWriter::new(RecordingBackend::new());
    w.stamp_session(7).expect("record the stamp batch");
    let stamp_batch = w.backend().batches()[0].text.clone();

    // Load the skeleton (base chain + map) then the per-session stamp batch, and
    // list the stamp chain back. The stamp batch is self-sufficient (its leading
    // `add table`/`add map`/`add chain` ensure the skeleton), so one load suffices.
    let script = format!(
        "nft -f - <<'EOF'\n{stamp_batch}\nEOF\nrc=$?\necho \"LOADRC=$rc\"\n\
         nft list chain {FLOWTAG_TABLE} tag_7 2>/dev/null\n\
         nft list map {FLOWTAG_TABLE} session_tag 2>/dev/null"
    );
    let combined = match nft_in_netns(&script) {
        Some(c) => c,
        None => {
            eprintln!(
                "SKIP: DS_NFT5_LIVE set but no usable user+net namespace here; the stamp \
                 shape is still pinned by the offline ds-nft::flowtag tests.\n{HOST_TRAFFIC_PROCEDURE}"
            );
            return;
        }
    };

    assert!(
        combined.contains("LOADRC=0"),
        "the kernel must accept the masked per-session ct-mark stamp batch. Output:\n{combined}"
    );
    // The stamp chain bound with a masked ct-mark write carrying the composed value.
    let composed = compose(Leg::AgentVm, 7);
    assert!(
        combined.contains("ct mark set ct mark") && combined.contains(&format!("0x{composed:x}")),
        "the bound stamp chain must carry the masked ct-mark write with the composed \
         value 0x{composed:x} (== compose(AgentVm, 7)). Output:\n{combined}"
    );
    // The tap is keyed to the stamp chain via the ifname verdict map (never saddr).
    assert!(
        combined.contains("dstap-7") && combined.contains("jump tag_7"),
        "the session_tag map must key dstap-7 -> jump tag_7. Output:\n{combined}"
    );
    assert!(
        !combined.contains("saddr"),
        "the stamp must never anchor on a forgeable source IP. Output:\n{combined}"
    );
}

#[test]
fn unstamp_is_idempotent_on_a_real_kernel_when_enabled() {
    // The LIVE proof of `unstamp_batch`'s ensure-then-delete idempotency contract
    // (the reviewer's manual `unshare -rn` probe, captured as a repeatable gated
    // test rather than offline-only evidence): a real kernel accepts a DOUBLE
    // unstamp load without a "No such file or directory" abort, because every
    // object the batch `delete`s is `add`ed first in the SAME atomic transaction.
    // A torn-down session's teardown is a converged no-op, never an orphan (doc 06
    // (b) round-trip-to-bootstrap; NFT-6 double-destroy safety).
    if std::env::var_os("DS_NFT5_LIVE").is_none() {
        eprintln!(
            "SKIP (deferred-manual, D50): NFT-5 unstamp-idempotency live arm is off by \
             default. Set DS_NFT5_LIVE=1 to run the netns double-unstamp proof. The \
             ensure-then-delete shape is already pinned offline by the ds-nft::flowtag \
             `unstamp_batch_is_ensure_then_delete_*` unit tests.\n{HOST_TRAFFIC_PROCEDURE}"
        );
        return;
    }

    // Render the exact runtime batches ds-nft would apply for host session index 7,
    // straight from the builders (no hand-authored ruleset — the shapes under test
    // ARE the shipped ones). The RecordingBackend just captures the text.
    let w = NftWriter::new(RecordingBackend::new());
    w.stamp_session(7).expect("record the stamp batch");
    w.unstamp_session(7).expect("record the unstamp batch");
    let batches = w.backend().batches();
    let stamp_batch = batches[0].text.clone();
    let unstamp_batch = batches[1].text.clone();

    // Load the stamp, then load the unstamp batch TWICE. Each load prints its own
    // rc; the unstamp batch is self-sufficient (its leading `add table`/`add
    // map`/`add chain` ensure the skeleton), so the second unstamp — with the
    // element+chain already gone — must STILL return rc 0 (ensure-then-delete nets
    // to zero). Distinct heredoc delimiters keep the three loads unambiguous.
    let script = format!(
        "nft -f - <<'EOF1'\n{stamp_batch}\nEOF1\necho \"STAMPRC=$?\"\n\
         nft -f - <<'EOF2'\n{unstamp_batch}\nEOF2\necho \"UNSTAMPRC1=$?\"\n\
         nft -f - <<'EOF3'\n{unstamp_batch}\nEOF3\necho \"UNSTAMPRC2=$?\"\n\
         nft list table {FLOWTAG_TABLE} 2>/dev/null"
    );
    let combined = match nft_in_netns(&script) {
        Some(c) => c,
        None => {
            eprintln!(
                "SKIP: DS_NFT5_LIVE set but no usable user+net namespace here; the \
                 ensure-then-delete idempotency is still pinned by the offline \
                 ds-nft::flowtag unit tests.\n{HOST_TRAFFIC_PROCEDURE}"
            );
            return;
        }
    };

    // The stamp loaded cleanly …
    assert!(
        combined.contains("STAMPRC=0"),
        "the kernel must accept the per-session stamp batch. Output:\n{combined}"
    );
    // … and BOTH unstamp loads returned rc 0 — the second is the idempotency proof:
    // an ensure-then-delete over an already-removed session never aborts.
    assert!(
        combined.contains("UNSTAMPRC1=0"),
        "the first unstamp load must succeed (LOADRC=0). Output:\n{combined}"
    );
    assert!(
        combined.contains("UNSTAMPRC2=0"),
        "the SECOND unstamp load must also succeed (LOADRC=0) — ensure-then-delete \
         makes a double-destroy a converged no-op, never a 'No such file' abort. \
         Output:\n{combined}"
    );
}

#[test]
fn floor_drop_observe_fires_on_nflog_group_5_when_enabled() {
    // The LIVE arm proving the NFT-1 floor's terminal drop, having ADOPTED the
    // canonical drop-observe shape (`iifname "dstap-*" ct state new counter log
    // prefix "ds-nft5-drop " group 5 drop` — the single source
    // `flowtag::floor_drop_observe_rule`), is accepted by a real kernel and its
    // `log ... group 5` binds an nflog group-5 emitter. The thing only a kernel can
    // confirm: the shipped floor rule loads and the group-5 nflog group is present
    // on the bound chain. The drop→nflog packet round-trip itself (originate a NEW
    // flow, read the `ds-nft5-drop ` line back off group 5 with MARK=) needs a wired
    // veth data path and is the committed [`HOST_TRAFFIC_PROCEDURE`] step 6, deferred
    // to the nested v0 substrate (substrate gap, not a design gap — D34/D66).
    if std::env::var_os("DS_NFT5_LIVE").is_none() {
        eprintln!(
            "SKIP (deferred-manual, D50): NFT-1 floor drop-observe live arm is off by \
             default. Set DS_NFT5_LIVE=1 to run the netns floor-load proof. The shape is \
             already pinned offline by the ds-nft::flowtag `floor_drop_observe_rule` unit \
             tests and stays byte-consistent with the shipped nft-1-bootstrap.nft.\n{HOST_TRAFFIC_PROCEDURE}"
        );
        return;
    }

    // The drop-observe rule under test is the single-source builder's output — the
    // exact text the shipped floor now carries (no hand-authored ruleset).
    let rule = ds_nft::flowtag::floor_drop_observe_rule();
    assert!(
        rule.contains("group 5")
            && rule.contains("log prefix \"ds-nft5-drop \"")
            && rule.ends_with("drop"),
        "the drop-observe rule must log to nflog group 5 before dropping; got: {rule}"
    );

    // Load a minimal floor `forward` chain carrying ONLY that terminal drop into a
    // private netns and list it back: a real kernel must accept the `log ... group 5`
    // extension and bind it (LOADRC=0 + the group-5 nflog directive survives the
    // parse). No packet is sent here — the drop→group-5 delivery round-trip is
    // HOST_TRAFFIC_PROCEDURE step 6 on the wired substrate.
    let script = format!(
        "nft -f - <<'EOF'\n\
         add table inet ds_boundary_probe\n\
         add chain inet ds_boundary_probe forward {{ type filter hook forward priority filter; policy drop; }}\n\
         add rule inet ds_boundary_probe forward {rule}\n\
         EOF\nrc=$?\necho \"LOADRC=$rc\"\n\
         nft list chain inet ds_boundary_probe forward 2>/dev/null"
    );
    let combined = match nft_in_netns(&script) {
        Some(c) => c,
        None => {
            eprintln!(
                "SKIP: DS_NFT5_LIVE set but no usable user+net namespace here; the \
                 drop-observe shape is still pinned by the offline ds-nft::flowtag tests.\n{HOST_TRAFFIC_PROCEDURE}"
            );
            return;
        }
    };

    assert!(
        combined.contains("LOADRC=0"),
        "the kernel must accept the floor drop-observe rule (log prefix + group 5 + drop). Output:\n{combined}"
    );
    // The bound chain carries the group-5 nflog directive and the terminal drop.
    assert!(
        combined.contains("group 5") && combined.contains("ds-nft5-drop"),
        "the bound floor chain must carry the group-5 nflog drop-observe on the ds-nft5-drop prefix. Output:\n{combined}"
    );
}

#[test]
fn host_traffic_procedure_is_recorded() {
    // The deferred host half is a committed, reproducible procedure (substrate gap,
    // not a design gap): assert it names the load-bearing checks so it cannot rot.
    assert!(HOST_TRAFFIC_PROCEDURE.contains("nf_conntrack_acct=1"));
    assert!(HOST_TRAFFIC_PROCEDURE.contains("mark=3506962439"));
    assert!(HOST_TRAFFIC_PROCEDURE.contains("ds-nft5-drop "));
    assert!(HOST_TRAFFIC_PROCEDURE.contains("unstamp_batch(7)"));
}
