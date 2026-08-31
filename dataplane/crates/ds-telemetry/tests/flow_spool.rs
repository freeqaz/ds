// SPDX-License-Identifier: Apache-2.0

//! NFT-5 end-to-end (offline): synthetic conntrack flow events + nflog drop
//! events → LOG-1 `FlowRecord`s → the disk-bounded spool (doc 09 §3 NFT-5; doc
//! 14 §2/§5/§12.4).
//!
//! This is the "done-when" proof, done offline (D50): flow events (start/stop,
//! bytes, packets, duration) AND nflog drop events, parsed from the SAME text a
//! `conntrack -E` / `nflog`-tail collector prints, carry the composed per-session
//! `ct mark` and LAND in the Stage-1 local event log (the on-disk spool). No live
//! kernel — the live-kernel arm is the env-gated `ds-nft` netns test
//! (deferred-manual).

use ds_telemetry::flow::{ct_mark_token, parse_conntrack_events, parse_nflog_drops, FlowLifecycle};
use ds_telemetry::provenance::Provenance;
use ds_telemetry::spool::{Spool, SpoolBounds};

use ds_contracts::mark::{compose, Leg};

/// The scratch root for test spool segments — honor `DS_WT_ROOT` (btrfs, off
/// tmpfs) then `TMPDIR`, matching the spool's own test convention.
fn scratch_root() -> std::path::PathBuf {
    std::env::var_os("DS_WT_ROOT")
        .or_else(|| std::env::var_os("TMPDIR"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
}

fn provenance() -> Provenance {
    Provenance::new("nft5/ct-mark-flowtag", "pol1-session", "2026-07-01").expect("valid triple")
}

/// A synthetic conntrack accounting stream for host session index 7 (VM leg): a
/// NEW start event and a DESTROY stop event carrying byte/packet totals + a
/// duration, both stamped with the composite `ct mark`.
fn synthetic_conntrack(idx: u32) -> Vec<String> {
    let mark = compose(Leg::AgentVm, idx).to_string();
    vec![
        format!(
            "[NEW] tcp 6 src=10.0.0.5 dst=203.0.113.10 sport=51514 dport=443 \
             [UNREPLIED] src=203.0.113.10 dst=10.0.0.5 sport=443 dport=51514 mark={mark}"
        ),
        format!(
            "[DESTROY] tcp 6 src=10.0.0.5 dst=203.0.113.10 sport=51514 dport=443 \
             packets=12 bytes=1840 src=203.0.113.10 dst=10.0.0.5 sport=443 \
             dport=51514 packets=10 bytes=5120 [ASSURED] mark={mark} delta-time=110"
        ),
        // A non-flow summary line that must be skipped.
        "conntrack v1.4.7 (conntrack-tools): 1 flow entries have been deleted.".to_string(),
    ]
}

/// A synthetic nflog drop stream: the floor dropped a NEW tcp/443 from the same
/// tap; the NFT-5 stamp set MARK before the drop, so the drop carries the session.
fn synthetic_nflog(idx: u32) -> Vec<String> {
    let mark_hex = format!("0x{:x}", compose(Leg::AgentVm, idx));
    vec![format!(
        "ds-nft5-drop IN=dstap-{idx} OUT= SRC=10.0.0.5 DST=185.199.108.153 \
         LEN=60 PROTO=TCP SPT=52000 DPT=8443 MARK={mark_hex}"
    )]
}

#[tokio::test]
async fn flow_and_drop_events_carry_the_ct_mark_and_land_in_the_spool() {
    let idx = 7u32;
    let dir = scratch_root().join(format!(
        "ds-telemetry-nft5-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("nft5.spool");

    // A roomy ring so the ONLY thing under test is that records land — no eviction.
    let bounds = SpoolBounds {
        max_records: 4096,
        batch_size: 4,
        channel_depth: 64,
        flush_interval: std::time::Duration::from_millis(10),
    };
    let spool = Spool::open(&path, bounds).await.unwrap();
    let sink = spool.sink();

    // Map the synthetic conntrack + nflog streams and emit each into the spool.
    let flows = parse_conntrack_events(&synthetic_conntrack(idx));
    let drops = parse_nflog_drops(&synthetic_nflog(idx));

    // Both a start and a stop conntrack event were parsed (the summary was skipped).
    assert_eq!(flows.len(), 2, "NEW + DESTROY parsed; summary skipped");
    assert!(flows.iter().any(|f| f.lifecycle == FlowLifecycle::New));
    assert!(flows.iter().any(|f| f.lifecycle == FlowLifecycle::Destroy));
    assert_eq!(drops.len(), 1, "one nflog drop parsed");
    assert_eq!(drops[0].lifecycle, FlowLifecycle::Drop);

    // Every record is attributed to session index 7 via the stamped ct mark, and
    // the DESTROY carries the accounting totals + duration.
    let expect_token = ct_mark_token(Leg::AgentVm, idx as u16);
    for f in flows.iter().chain(drops.iter()) {
        let parts = f.session.expect("flow/drop attributed to a session");
        assert_eq!(parts.session_index, idx as u16);
        assert_eq!(parts.leg, Leg::AgentVm);
        assert_eq!(f.ct_mark_token().as_deref(), Some(expect_token.as_str()));
    }
    let destroy = flows
        .iter()
        .find(|f| f.lifecycle == FlowLifecycle::Destroy)
        .unwrap();
    assert_eq!(destroy.bytes, 1840 + 5120);
    assert_eq!(destroy.packets, 12 + 10);
    assert_eq!(destroy.duration_ms, 110_000);

    // Feed the LOG-1 envelopes to the spool via the durable (visible-loss) path.
    for f in flows.iter().chain(drops.iter()) {
        sink.emit_async(f.to_envelope(provenance()))
            .await
            .expect("spool accepts the flow envelope");
    }
    spool.shutdown().await.unwrap();

    // The records landed on disk carrying the composed per-session ct mark — the
    // LOG-2 attribution key rides the Stage-1 local event log.
    let contents = std::fs::read(&path).unwrap();
    let text = String::from_utf8_lossy(&contents);
    let occurrences = text.matches(expect_token.as_str()).count();
    assert!(
        occurrences >= 3,
        "all three records (NEW flow, DESTROY flow, drop) must land carrying the \
         ct mark token {expect_token}; found {occurrences} in the spool segment"
    );
    // The drop record and the accounting totals are both present in the log.
    assert!(text.contains("nft5-flow|drop|"), "the drop event landed");
    assert!(text.contains("bytes=6960"), "the accounting total landed");

    std::fs::remove_dir_all(&dir).ok();
}
