//! D131 warm-restart *fallback* tier — the LIVE-gated harness for the production
//! [`ds_dnsgate::NftKernelDump`] kernel set-dump body (doc 11 §8.4 / §8.4.1).
//!
//! # What this proves, live, against a real kernel
//!
//! The synthetic [`ds_dnsgate::KernelSetDump`] fixtures prove the reconstructor's
//! invariants with no kernel. THIS harness proves the PRODUCTION kernel-read body
//! [`NftKernelDump`] against a real `nft` set in a rootless user+net namespace
//! (`unshare -rn`): it creates `table inet ds_filter` + an `allow4_<idx>` set with
//! a couple of `timeout` elements, runs [`NftKernelDump::dump`] against a session
//! roster, and asserts:
//!
//!  1. the dump recovers exactly the elements' IPs for the roster's `session_uuid`
//!     (the index↔uuid bridge worked: the kernel-side `allow4_<idx>` set was read
//!     for the roster's `host_session_index`, keyed back under the uuid);
//!  2. each rebuilt deadline is ADOPTED from the element's REMAINING timeout
//!     (`now + remaining_seconds`, W2 lockstep) — not recomputed;
//!  3. a full [`Reconstructor::rebuild`] round-trip over the LIVE kernel dump + a
//!     synthetic matching spool corpus rebuilds the `(session, fqdn)` entry with the
//!     kernel deadline.
//!
//! # How the netns is entered (self-reexec)
//!
//! A cargo test does not run inside a private netns, and a `unshare -rn` child's
//! netns vanishes when the child exits — so setup (`nft add ...`) and the
//! [`NftKernelDump`] read (which SPAWNS `nft`) must happen in the SAME netns. We do
//! that by RE-EXECing this very test binary under `unshare -rn` (with a marker env
//! var) and running the whole setup+dump+assert flow inside that single namespaced
//! process. The outer invocation only re-execs and relays the inner status.
//!
//! # Gating
//!
//! Off by default: requires BOTH `DS_WARM_RESTART_LIVE=1` AND `--ignored` (the test
//! is `#[ignore]`), so the offline `cargo test` path never touches a kernel. If the
//! sandbox cannot give a usable namespaced `nft`, the inner leg SKIPS (prints a
//! reason) rather than failing — the property stays pinned by the synthetic suite.

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;

use ds_contracts::dns_admission::{AdmissionKey, AdmissionMap, AdmissionType, Instant, Provenance};
use ds_contracts::session::SessionRef;
use ds_dnsgate::{KernelDumpSource, NftKernelDump, Reconstructor, SpoolRecord, SpoolReplayCorpus};

const LIVE_ENV: &str = "DS_WARM_RESTART_LIVE";
/// The marker that tells a re-exec'd inner invocation it is already inside the
/// freshly-unshared netns and should run the body directly (no second re-exec).
const INNER_ENV: &str = "DS_WARM_RESTART_LIVE_INNER";
const NANOS_PER_SEC: u64 = 1_000_000_000;

const TABLE: &str = "ds_filter";
const SESSION_INDEX: u32 = 7;
const SESSION_UUID: &str = "sess-d131-live-0001";
const FQDN: &str = "example.test.";
const IP_A: &str = "93.184.216.34";
const IP_B: &str = "198.51.100.9";
const REMAINING_A: u64 = 2000;
const REMAINING_B: u64 = 5000;

/// Whether a rootless namespaced `nft` is usable here (the same probe ds-nft's
/// netns tests use).
fn netns_nft_usable() -> bool {
    Command::new("unshare")
        .args(["-rn", "nft", "list", "ruleset"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
#[ignore = "live: requires DS_WARM_RESTART_LIVE=1 and a rootless-netns-capable kernel"]
fn nft_kernel_dump_round_trips_against_a_live_kernel() {
    if std::env::var(LIVE_ENV).ok().as_deref() != Some("1") {
        eprintln!("SKIP: set {LIVE_ENV}=1 to run the live warm-restart kernel-dump harness");
        return;
    }

    // INNER leg: already inside the unshared netns — run the body and assert.
    if std::env::var(INNER_ENV).is_ok() {
        run_inner_body();
        return;
    }

    // OUTER leg: re-exec this very test binary under `unshare -rn` so setup and the
    // NftKernelDump read share ONE netns.
    if !netns_nft_usable() {
        eprintln!(
            "SKIP: no usable rootless user+net namespace for the live kernel half; \
             the NftKernelDump parse + W2-deadline-adoption is still pinned by the \
             synthetic unit suite (src/warm_restart_live.rs)."
        );
        return;
    }

    let exe = std::env::current_exe().expect("test binary path");
    let status = Command::new("unshare")
        .args(["-rn"])
        .arg(&exe)
        // Run exactly this test, including ignored, single-threaded, with output.
        .args([
            "--exact",
            "nft_kernel_dump_round_trips_against_a_live_kernel",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(INNER_ENV, "1")
        .env(LIVE_ENV, "1")
        .status()
        .expect("re-exec the test under unshare -rn");
    assert!(
        status.success(),
        "the inner (namespaced) leg of the live warm-restart harness failed"
    );
}

/// The body that runs INSIDE the freshly-unshared netns: build the kernel allow-set,
/// dump it through the production [`NftKernelDump`], and assert the round-trip.
fn run_inner_body() {
    // 1) Build the live kernel state: table + allow4_<idx> with two timeout elements.
    let setup = format!(
        "nft add table inet {TABLE}\n\
         nft add set inet {TABLE} allow4_{idx} '{{ type ipv4_addr; flags timeout; }}'\n\
         nft add element inet {TABLE} allow4_{idx} '{{ {ip_a} timeout {ta}s, {ip_b} timeout {tb}s }}'\n",
        idx = SESSION_INDEX,
        ip_a = IP_A,
        ip_b = IP_B,
        ta = REMAINING_A,
        tb = REMAINING_B,
    );
    let setup_status = Command::new("sh")
        .args(["-c", &setup])
        .status()
        .expect("run nft setup inside the netns");
    assert!(
        setup_status.success(),
        "nft setup must succeed inside the netns"
    );

    // 2) The active-session roster: the index↔uuid bridge. The kernel knows only
    // host_session_index 7 (the allow4_7 set); the roster maps it to the uuid.
    let roster = vec![SessionRef::new(
        SESSION_UUID.to_string(),
        "host-live".to_string(),
        SESSION_INDEX,
        format!("dstap-{SESSION_INDEX}"),
    )];

    // Pin `now` so the adopted-deadline assertion is exact. The production path
    // reads the wall clock once; here we inject a fixed base.
    let now = Instant::from_unix_nanos(1_000 * NANOS_PER_SEC);
    let kernel = NftKernelDump::new(roster, TABLE).with_now(now);

    // 3) Run the LIVE kernel dump.
    let dump = kernel.dump();

    // The dump recovered both elements under the roster's session_uuid (the bridge
    // worked: allow4_7 was read for index 7 and keyed back to the uuid).
    let elems = dump.elements_for(SESSION_UUID);
    assert_eq!(
        elems.len(),
        2,
        "the live dump must recover both kernel elements for the session (got {elems:?})"
    );
    let ip_a: IpAddr = IP_A.parse().unwrap();
    let ip_b: IpAddr = IP_B.parse().unwrap();
    let got_ips: Vec<IpAddr> = elems.iter().map(|e| e.ip).collect();
    assert!(
        got_ips.contains(&ip_a) && got_ips.contains(&ip_b),
        "both IPs present: {got_ips:?}"
    );

    // W2 lockstep: each deadline is ADOPTED from the kernel's REMAINING timeout
    // (now + remaining_seconds). nft's `expires` is the remaining time and ticks
    // down by the (sub-second) setup latency, so it is `remaining` or `remaining-1`.
    for e in elems {
        let want = if e.ip == ip_a {
            REMAINING_A
        } else {
            REMAINING_B
        };
        let adopted_secs = (e.deadline.unix_nanos - now.unix_nanos) / NANOS_PER_SEC;
        assert!(
            adopted_secs == want || adopted_secs == want - 1,
            "deadline for {} must be adopted from the kernel remaining timeout \
             (~{want}s after `now`); got {adopted_secs}s",
            e.ip
        );
    }

    // 4) Full Reconstructor::rebuild round-trip: the LIVE kernel dump + a synthetic
    // matching spool corpus that supplies the (session, fqdn) provenance the spool
    // format does not itself carry from a DnsEvent record (see the audit-log
    // demotion note in warm_restart_live.rs). The rebuilt entry must adopt the
    // kernel deadline.
    let spool = SpoolReplayCorpus::new().with_record(SpoolRecord {
        session_uuid: SESSION_UUID.to_string(),
        original_query_fqdn: FQDN.to_string(),
        admitted_ips: vec![ip_a, ip_b],
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
        provenance: Provenance {
            rule_id: "core/example".into(),
            policy_layer: "pol2".into(),
            policy_version: "2026-06-16".into(),
        },
        admitted_at: Instant::from_unix_nanos(500 * NANOS_PER_SEC),
    });

    let (map, report) = Reconstructor::new().rebuild(&kernel, &spool);
    assert_eq!(
        report.entries_rebuilt, 1,
        "one (session, fqdn) entry rebuilt"
    );
    assert_eq!(report.ips_substantiated, 2, "both kernel IPs substantiated");
    assert!(
        report.is_fully_substantiated(),
        "no fail-closed gaps: {report:?}"
    );

    let entry = map
        .lookup(&AdmissionKey {
            session_uuid: SESSION_UUID.to_string(),
            original_query_fqdn: FQDN.to_string(),
        })
        .expect("the rebuilt entry is present");
    assert_eq!(entry.admitted_ips.len(), 2);
    // The entry's shared deadline is the LATER (max) of the two adopted kernel
    // deadlines — the longer-remaining element (B, ~5000s) wins, never shortened.
    let entry_secs = (entry.expires_at.unix_nanos - now.unix_nanos) / NANOS_PER_SEC;
    assert!(
        entry_secs == REMAINING_B || entry_secs == REMAINING_B - 1,
        "the rebuilt entry adopts the LATER kernel deadline (~{REMAINING_B}s); got {entry_secs}s"
    );

    // Sanity on the IP literal handling (no v6 leg here, but assert the v4 octets
    // round-tripped byte-exact through to_admitted_addr).
    let want_octets: Vec<u8> = match ip_a {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        _ => unreachable!(),
    };
    assert!(
        entry
            .admitted_ips
            .iter()
            .any(|a| a.octets == want_octets || a.octets == Ipv4Addr::new(198, 51, 100, 9).octets()),
        "the rebuilt entry carries the kernel IPs byte-exact"
    );

    eprintln!("LIVE OK: NftKernelDump dumped {} elements; rebuild substantiated {} IPs into {} entry with the adopted kernel deadline",
        elems.len(), report.ips_substantiated, report.entries_rebuilt);
}
