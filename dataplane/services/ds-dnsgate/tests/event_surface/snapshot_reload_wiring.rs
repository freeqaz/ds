// SPDX-License-Identifier: Apache-2.0
//! `event_surface` split (D75/D72/D53): WatchPolicies host-snapshot SUBSCRIBER wiring +
//! back-pressure legs — sections 13-15, extracted from the oversized `tests/event_surface.rs`
//! (test-only reorg, behavior-preserving). Included as a `#[path]` submodule of the
//! `event_surface` integration-test binary, so `crate::{query_bytes, tcp_query, udp_query}`
//! resolve to the shared helpers at that binary's root.

// ===========================================================================
// 13. The WatchPolicies host-snapshot SUBSCRIBER, end-to-end through `main`'s
//     PRODUCTION spawn / drop-feed-on-shutdown / await-subscriber wiring
//     (doc 11 §5.3 / §5.4 / D72 admitter-LAST / D53 severing rung).
//
//     The subscriber LOGIC is already covered by the four `server.rs` src-module
//     tests; what those do NOT exercise is `main.rs`'s wiring of it: the detached
//     `RunningGate::boundary_zone_reloader()` handle handed to a `tokio::spawn`ed
//     `watch_policies(subscription, &reloader)` task, fed by `boundary_snapshot_feed`,
//     and — on shutdown — `drop(feed)` followed by `subscriber.await`. This tests/-side
//     integration test reconstructs THAT production loop verbatim, binds a real gate on
//     127.0.0.1:0, publishes a committed synthetic `BoundarySnapshot` through the
//     host-LOCAL feed (NEVER a control-plane stream, §5.3), and asserts the admitter-LAST
//     reload re-sources the authored-SOA deny suffix ON THE WIRE, then that dropping the
//     feed cleanly awaits the subscriber to completion.
//
//     Synthetic + loopback only: an in-process `AlwaysDenyPolicy` so every query authors
//     the §3.2 NXDOMAIN + authored-SOA deny shape (the wire surface whose MNAME the
//     subscriber-driven reload changes), no live host agent, no policy stream, no network.
//
//     FROZEN DENY SHAPE: `policy_core::dns_gate::DnsVerdict::Deny` carries THREE fields
//     `{ rcode_policy, rung: Option<Rung>, provenance }` (doc 14 §6 / dns_gate.rs). Every
//     `Deny` literal this harness constructs includes `rung` — `None` for the plain hard
//     deny, and a `Some(Rung::BlockLog)` severing-rung variant proving the §5.4 / D53
//     `severs_established_flows` predicate rides the same frozen seam (folds the
//     rung-repair: a `Deny { rcode_policy, provenance }` two-field literal is an E0063).
// ===========================================================================

mod main_subscriber_wiring {
    //! A self-contained module so this integration test owns its imports without
    //! disturbing the shared top-level `use` block the sibling event tests bind.

    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use ds_contracts::pol1::Rung;
    use ds_dnsgate::policy::{DnsQueryCtx, PolicyHook, RcodePolicy, SeamProvenance, Verdict};
    use ds_dnsgate::server::{
        boundary_snapshot_feed, watch_policies, BoundarySnapshot, GateConfig,
    };
    use ds_dnsgate::spawn_gate;

    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::rdata::SOA as ProtoSoa;
    use hickory_proto::rr::{RData as ProtoRData, RecordType};

    use crate::{query_bytes, tcp_query, udp_query};

    /// The POL-3 provenance the harness deny attaches — a NON-EMPTY rule id / layer /
    /// version triple (doc 11 §6.7: missing provenance fails CI). It is the test's own
    /// `harness/deny-all` marker, NOT a real pack rule, so a LOG-1 join reads an honest
    /// "this was the integration harness deny", never a fabricated pack provenance.
    fn harness_deny_provenance() -> SeamProvenance {
        SeamProvenance {
            rule_id: "harness/deny-all".to_string(),
            policy_layer: "harness".to_string(),
            policy_version: "deny-all".to_string(),
        }
    }

    /// A `PolicyHook` that DENIES every query with the frozen §3.2 hard-deny verdict —
    /// `Verdict::Deny { rcode_policy: NxDomain, rung, provenance }`. The handler authors
    /// the NXDOMAIN + authored-SOA(MNAME=`denied.policy.<boundary_zone>.`) wire shape from
    /// it, so the SOA MNAME on the wire is the observable surface whose suffix the
    /// subscriber-driven D72 reload re-sources.
    ///
    /// FROZEN DENY SHAPE (folds rung-repair 01KV0DVMBA): the verdict carries the D53 `rung`
    /// as a THIRD field. The harness denies with a configurable rung so both the
    /// no-rung (`None`, gate-new-flows-only) and the severing (`Some(Rung::BlockLog)`,
    /// §5.4 `severs_established_flows`) constructions are exercised against the frozen seam.
    #[derive(Clone)]
    struct AlwaysDenyPolicy {
        /// The D53 rung the authored deny carries (`None` = no explicit rule rung). A
        /// block-or-higher rung makes the verdict's §5.4 `severs_established_flows` true.
        rung: Option<Rung>,
    }

    impl AlwaysDenyPolicy {
        /// A plain hard deny carrying NO explicit rung (`rung: None`) — gates new flows
        /// only, never severs established ones (doc 11 §5.4 / D53).
        fn no_rung() -> Self {
            Self { rung: None }
        }

        /// A deny reached at a block-or-higher D53 rung — the §5.4 severing predicate is
        /// true for this verdict (proves the third frozen field carries severing intent).
        fn severing() -> Self {
            Self {
                rung: Some(Rung::BlockLog),
            }
        }
    }

    impl PolicyHook for AlwaysDenyPolicy {
        fn evaluate(&self, _ctx: &DnsQueryCtx) -> Verdict {
            // The frozen 3-field Deny (doc 14 §6 / dns_gate.rs:150-158): a two-field literal
            // is an E0063 against the unified `DnsVerdict::Deny { rcode_policy, rung,
            // provenance }`. `rung` carries the D53 severing rung (folds rung-repair).
            Verdict::Deny {
                rcode_policy: RcodePolicy::NxDomain,
                rung: self.rung,
                provenance: harness_deny_provenance(),
            }
        }
    }

    /// The authored-SOA MNAME a deny over `addr` (TCP transport) signs with — the doc 11
    /// §3.2 signature whose `<boundary_zone>` suffix the D72 reload re-sources. Asserts the
    /// frozen deny SHAPE (NXDOMAIN + authored SOA in authority) and returns the live MNAME.
    async fn deny_mname_over_tcp(addr: SocketAddr, transport: &str) -> String {
        let query = query_bytes(0x7d01, "denied.example.test.", RecordType::A);
        let resp = tokio::time::timeout(Duration::from_secs(5), tcp_query(addr, &query))
            .await
            .expect("tcp deny round-trip timed out");
        let msg = Message::from_vec(&resp).expect("tcp deny response parses");
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::NXDomain,
            "the harness deny authors the §3.2 NXDOMAIN hard-deny ({transport})",
        );
        assert!(
            msg.answers.is_empty(),
            "a hard deny has an empty answer section ({transport})",
        );
        soa_mname(&msg)
            .unwrap_or_else(|| panic!("authored SOA present in authority ({transport}): {msg:?}"))
    }

    /// The authored-SOA MNAME a deny over `addr` (UDP transport) signs with — the §3.4
    /// parity twin of [`deny_mname_over_tcp`]. Both transports share one reload handle, so
    /// the suffix the subscriber commits holds identically across UDP and TCP.
    async fn deny_mname_over_udp(addr: SocketAddr, transport: &str) -> String {
        let query = query_bytes(0x7d02, "denied.example.test.", RecordType::A);
        let resp = tokio::time::timeout(Duration::from_secs(5), udp_query(addr, &query))
            .await
            .expect("udp deny round-trip timed out");
        let msg = Message::from_vec(&resp).expect("udp deny response parses");
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::NXDomain,
            "the harness deny authors the §3.2 NXDOMAIN hard-deny ({transport})",
        );
        soa_mname(&msg)
            .unwrap_or_else(|| panic!("authored SOA present in authority ({transport}): {msg:?}"))
    }

    /// Extract the authored signature SOA's MNAME from a parsed deny response, if present.
    fn soa_mname(msg: &Message) -> Option<String> {
        msg.authorities.iter().find_map(|r| match &r.data {
            ProtoRData::SOA(soa) => Some(soa_mname_ascii(soa)),
            _ => None,
        })
    }

    fn soa_mname_ascii(soa: &ProtoSoa) -> String {
        soa.mname.to_ascii()
    }

    #[tokio::test]
    async fn main_wiring_drives_admitter_last_reload_and_awaits_subscriber_on_feed_drop() {
        // ── Reconstruct `main.rs`'s PRODUCTION subscriber wiring, verbatim ──────────────
        //
        // main.rs:
        //   let mut gate = spawn_gate(policy, config).await?;
        //   let (feed, subscription) = boundary_snapshot_feed(SNAPSHOT_FEED_CAPACITY);
        //   let reloader = gate.boundary_zone_reloader();
        //   let subscriber = tokio::spawn(async move {
        //       watch_policies(subscription, &reloader).await
        //   });
        //   ... // host agent fans out committed snapshots onto `feed`
        //   drop(feed);                 // last publisher gone → subscriber loop returns
        //   let _ = subscriber.await;   // shutdown drains the subscriber
        //
        // This test stands up exactly that loop around a real loopback-bound gate, drives a
        // synthetic committed snapshot through it, and asserts the deny suffix re-sourced ON
        // THE WIRE (admitter-LAST) and the subscriber awaited cleanly on feed-drop.

        // A gate whose every query is a frozen 3-field hard deny, started with a known
        // startup boundary zone (the live host-snapshot value `main` threads into the
        // config in place of the DEFAULT_BOUNDARY_ZONE const).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(AlwaysDenyPolicy::no_rung(), config)
            .await
            .expect("gate binds on loopback");
        let udp_addr = gate.udp_local_addr();
        let tcp_addr = gate.tcp_local_addr();

        // Startup: the deny is signed with the LIVE startup-snapshot suffix on BOTH
        // transports (the gate sourced the boundary zone from the config, not the const).
        assert_eq!(
            deny_mname_over_tcp(tcp_addr, "tcp/startup").await,
            "denied.policy.startup.example.",
            "the startup deny signs with the live snapshot suffix, not the const default",
        );
        assert_eq!(
            deny_mname_over_udp(udp_addr, "udp/startup").await,
            "denied.policy.startup.example.",
            "§3.4 parity: the UDP transport signs with the same startup suffix",
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.startup.example.",
            "the gate's live authored MNAME reflects the startup snapshot",
        );

        // ── main.rs production wiring: detached reloader handle + spawned subscriber ──────
        // `main` hands the gate's detached `boundary_zone_reloader()` to a spawned
        // `watch_policies` task WHILE it keeps the gate to block on its listeners. The
        // reloader drives the SAME sole reload path `RunningGate::reload_boundary_zone`
        // drives (one reload path, two holders) — so committing through the subscriber is
        // byte-identical to a direct `reload_boundary_zone`, with no `P` type parameter on
        // the task.
        let (feed, subscription) = boundary_snapshot_feed(8);
        let reloader = gate.boundary_zone_reloader();
        let subscriber = tokio::spawn(async move { watch_policies(subscription, &reloader).await });

        // The host agent fans out committed snapshots host-locally (NEVER a control-plane
        // stream, §5.3). A duplicate/stale seq is dropped by the subscriber's D72
        // forward-only discipline; only forward seqs commit, admitter-LAST.
        feed.publish(BoundarySnapshot::new(7, "pushed.example."))
            .await
            .expect("subscriber alive for the first committed snapshot");
        // A duplicate seq (7) and a stale seq (3): the D72 forward-only commit drops both,
        // so neither re-sources the suffix backwards (single monotonic policy version).
        feed.publish(BoundarySnapshot::new(7, "dup.example."))
            .await
            .expect("subscriber alive for the duplicate fan-out");
        feed.publish(BoundarySnapshot::new(3, "stale.example."))
            .await
            .expect("subscriber alive for the stale fan-out");
        // A forward seq (8): committed admitter-LAST, re-sourcing the suffix once more.
        feed.publish(BoundarySnapshot::new(8, "final.example."))
            .await
            .expect("subscriber alive for the forward snapshot");

        // Drop every publisher so the subscriber loop's `recv()` returns `None` and the
        // loop completes — exactly `main`'s `drop(feed)` shutdown step.
        drop(feed);

        // The admitter committed LAST: the live gate now authors every deny with the
        // forward-seq pushed suffix, on BOTH transports (one reload handle, no skew). The
        // duplicate (`dup.example.`) and stale (`stale.example.`) fan-outs NEVER appear.
        let final_mname = "denied.policy.final.example.";
        await_authored_mname(tcp_addr, final_mname, "tcp/reloaded").await;
        assert_eq!(
            deny_mname_over_udp(udp_addr, "udp/reloaded").await,
            final_mname,
            "§3.4 parity: the subscriber-driven reload holds on the UDP transport too",
        );

        // ── Clean shutdown: `subscriber.await` drains the subscriber to completion ────────
        // The dropped feed closed the host-local channel, so `watch_policies` returned the
        // count of FORWARD-seq commits (the two — seq 7 then seq 8 — never the duplicate or
        // the stale fan-out). The task joins without panic: shutdown drained it cleanly.
        let commits = subscriber
            .await
            .expect("subscriber task joins cleanly on feed drop");
        assert_eq!(
            commits, 2,
            "only the two forward-seq snapshots (7, 8) committed; the duplicate (7) and \
             stale (3) host-local fan-outs were dropped by the D72 forward-only discipline",
        );

        gate.shutdown()
            .await
            .expect("gate shuts down after the subscriber drained");
    }

    /// Poll the bound gate over TCP until a deny signs with `expected_mname` (or fail after
    /// a bounded number of tries). The subscriber commits on its OWN task, so the wire may
    /// briefly lag the `feed` publish; this bounds the wait without a fixed sleep.
    async fn await_authored_mname(addr: SocketAddr, expected_mname: &str, transport: &str) {
        for _ in 0..50 {
            if deny_mname_over_tcp(addr, transport).await == expected_mname {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "the subscriber-driven admitter-LAST reload never re-sourced the deny suffix to \
             {expected_mname} on the wire ({transport})",
        );
    }

    #[tokio::test]
    async fn frozen_three_field_deny_carries_the_d53_severing_rung() {
        // The frozen `DnsVerdict::Deny` third field `rung` is load-bearing: a deny reached
        // at a block-or-higher D53 rung SEVERS established flows (doc 11 §5.4 / D53 rule 6),
        // while a no-rung deny gates new flows only. Both constructions go through the SAME
        // frozen 3-field literal — proving this harness folds the rung-repair (a two-field
        // `Deny { rcode_policy, provenance }` would be an E0063 against the unified type).
        let no_rung = AlwaysDenyPolicy::no_rung();
        let severing = AlwaysDenyPolicy::severing();

        let ctx = DnsQueryCtx {
            session: "harness-session".to_string(),
            qname: "denied.example.test.".to_string(),
            qtype: 1,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        };

        let plain = no_rung.evaluate(&ctx);
        let block = severing.evaluate(&ctx);

        // Both author the §3.2 hard deny (neither admits) with non-empty POL-3 provenance.
        assert!(!plain.admits(), "a no-rung deny never admits");
        assert!(!block.admits(), "a severing deny never admits");
        for v in [&plain, &block] {
            let prov = v.provenance();
            assert!(
                !prov.rule_id.is_empty()
                    && !prov.policy_layer.is_empty()
                    && !prov.policy_version.is_empty(),
                "§6.7: every verdict carries non-empty POL-3 provenance",
            );
        }

        // The D53 severing predicate reads the frozen `rung` third field: a no-rung deny
        // gates new flows only; a block-or-higher rung severs established flows.
        assert!(
            !plain.severs_established_flows(),
            "a Deny with rung=None gates new flows only — never severs (§5.4 / D53)",
        );
        assert!(
            block.severs_established_flows(),
            "a Deny at a block-or-higher rung severs established flows (§5.4 / D53 rule 6)",
        );
    }
}

// ===========================================================================
// 14. The WatchPolicies host-snapshot SUBSCRIBER bounded-feed BACK-PRESSURE path
//     under a publisher BURST EXCEEDING the feed capacity (doc 11 §1 bounded-mpsc
//     rationale / §5.3 one subscriber per host / D72 forward-only admitter-LAST).
//
//     The §13 main-wiring test publishes 4 snapshots into a capacity-8 feed, so
//     `publish()` never back-pressures and the doc 11 §1 rationale — a fan-out burst
//     back-pressures the host agent rather than spawning UNBOUNDED buffered snapshots
//     against the fleet's SINGLE resolver / DoS chokepoint — is asserted only by
//     construction (the `BoundarySnapshotFeed` is a bounded `mpsc`). This module DRIVES
//     a publisher burst LARGER than the capacity while the subscriber is NOT draining and
//     proves the bound is load-bearing:
//
//       * BACK-PRESSURE (not drop, not unbounded buffer): once the bounded feed is full,
//         a further `publish().await` BLOCKS (awaits) until the subscriber drains a slot —
//         it neither silently drops the snapshot nor grows the buffer past the capacity.
//         Observed by spawning the burst publisher on its own task, waiting until it has
//         WEDGED on `send().await` (its completed-publish counter stops short of the burst
//         length and stays there across a bounded settle window), then releasing the
//         subscriber and watching every remaining `publish()` complete.
//
//       * FORWARD-ONLY-SEQ + ADMITTER-LAST ORDERING PRESERVED THROUGH THE BURST: every
//         snapshot in the burst carries a strictly-forward seq, so after the drain the
//         subscriber commits ALL of them — none dropped — in monotonic seq order through
//         the SAME single reload sink (admitter-LAST, doc 11 §5.3 / D72). The committed
//         boundary-zone sequence equals the publish order exactly: the bounded feed
//         back-pressures the FAST publisher without REORDERING or LOSING the slow stream.
//
//     Synthetic + host-local only (§5.3): NO control-plane stream, NO live host agent, NO
//     network, NO bound gate — the test drives the bare `boundary_snapshot_feed` +
//     `watch_policies` seam against a synthetic `BoundaryZoneSink` recorder it controls
//     (the public trait the production `RunningGate` / `GateBoundaryReloader` also satisfy),
//     gating the subscriber's first commit on a barrier so the feed provably fills.
// ===========================================================================

mod subscriber_backpressure {
    //! A self-contained module: it owns its imports without disturbing the shared
    //! top-level `use` block (mirroring the sibling `main_subscriber_wiring` module).

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ds_dnsgate::server::{
        boundary_snapshot_feed, watch_policies, BoundarySnapshot, BoundaryZoneSink,
    };

    /// A synthetic admitter-LAST commit sink (the public [`BoundaryZoneSink`] trait the
    /// production `RunningGate` / `GateBoundaryReloader` also implement) that:
    ///   * RECORDS every committed boundary zone in commit order (proves no drop + ordering),
    ///   * GATES the FIRST commit on a one-shot release barrier so the subscriber wedges
    ///     mid-drain and the bounded feed provably fills behind it (drives back-pressure).
    ///
    /// `commit_boundary_zone` is the synchronous frozen seam signature. To pause the
    /// subscriber on its first commit WITHOUT a busy-wait, the first call parks on a
    /// `std::sync::mpsc::Receiver::recv()` until the test thread sends the release token; the
    /// subscriber runs on its own worker (multi-thread runtime) so this blocks only that
    /// worker, never the burst publisher.
    struct GatedRecordingSink {
        committed: Mutex<Vec<String>>,
        commits_started: AtomicUsize,
        /// The release barrier: the FIRST commit blocks on `recv()` until the test sends.
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl GatedRecordingSink {
        fn new(release: std::sync::mpsc::Receiver<()>) -> Self {
            Self {
                committed: Mutex::new(Vec::new()),
                commits_started: AtomicUsize::new(0),
                release: Mutex::new(Some(release)),
            }
        }

        /// The boundary zones the subscriber committed, in commit order.
        fn committed(&self) -> Vec<String> {
            self.committed.lock().expect("committed mutex").clone()
        }

        /// How many commits the subscriber has ENTERED (incremented before the first-commit
        /// gate blocks) — a probe the test uses to confirm the subscriber wedged on commit #1.
        fn commits_started(&self) -> usize {
            self.commits_started.load(Ordering::SeqCst)
        }
    }

    impl BoundaryZoneSink for GatedRecordingSink {
        fn commit_boundary_zone(&self, boundary_zone: &str) {
            let nth = self.commits_started.fetch_add(1, Ordering::SeqCst);
            // The FIRST commit parks until the test releases it — so the subscriber stops
            // draining after pulling exactly one snapshot and the bounded feed fills behind
            // it, forcing `publish()` to back-pressure. Take the receiver out (one-shot).
            if nth == 0 {
                if let Some(rx) = self.release.lock().expect("release mutex").take() {
                    // Block this subscriber worker until the test sends the release token (or
                    // the sender is dropped). Either way the subscriber resumes draining.
                    let _ = rx.recv();
                }
            }
            self.committed
                .lock()
                .expect("committed mutex")
                .push(boundary_zone.to_string());
        }
    }

    /// A burst > capacity back-pressures `publish()` (the bounded mpsc blocks the publisher
    /// rather than dropping or unboundedly buffering), and forward-only-seq + admitter-LAST
    /// ordering survives the burst (every snapshot commits, in monotonic order).
    ///
    /// Multi-thread runtime: the subscriber worker blocks (parked on the first-commit gate)
    /// while the burst publisher runs concurrently on another worker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn burst_exceeding_feed_capacity_back_pressures_publish_and_preserves_d72_order() {
        // A SMALL bounded feed so a modest burst exceeds it. The burst length is chosen
        // strictly larger than (capacity + the one snapshot the wedged subscriber pulls), so
        // at least one `publish()` MUST find the channel full and back-pressure.
        const CAPACITY: usize = 2;
        const BURST: usize = 12; // >> CAPACITY + 1 — many publishes must block on the bound.

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let sink = Arc::new(GatedRecordingSink::new(release_rx));
        let (feed, subscription) = boundary_snapshot_feed(CAPACITY);

        // Spawn the subscriber: it pulls snapshot #1, enters the FIRST commit, and parks on
        // the release gate — so it stops draining and the bounded feed fills behind it.
        let sub_sink = sink.clone();
        let subscriber =
            tokio::spawn(async move { watch_policies(subscription, sub_sink.as_ref()).await });

        // The burst publisher: publish BURST strictly-forward-seq snapshots (seq 1..=BURST,
        // each a distinct boundary zone encoding its publish order). It runs on its own task;
        // `completed` counts how many `publish().await` calls RETURNED — the probe that lets
        // the test observe the publisher WEDGING on the bounded feed once it is full.
        let completed = Arc::new(AtomicUsize::new(0));
        let pub_completed = completed.clone();
        let publisher = tokio::spawn(async move {
            for i in 1..=BURST {
                feed.publish(BoundarySnapshot::new(i as u64, format!("z{i}.example.")))
                    .await
                    .expect("subscriber alive for the whole burst");
                pub_completed.fetch_add(1, Ordering::SeqCst);
            }
            // Drop the feed (last publisher gone) so the subscriber loop returns after drain.
            drop(feed);
        });

        // ── Prove BACK-PRESSURE: the publisher WEDGES on the bounded feed ─────────────────
        // Wait until the subscriber has entered its (gated) first commit — it is now parked,
        // no longer draining, so the feed fills to CAPACITY and the publisher blocks.
        await_until(Duration::from_secs(5), || sink.commits_started() >= 1).await;

        // The publisher cannot have completed the whole burst: the bounded feed (CAPACITY
        // buffered + the one snapshot the wedged subscriber pulled) holds far fewer than
        // BURST, so the surplus `publish()` calls are blocked on `send().await`. Sample the
        // completed count, then confirm it is STUCK across a settle window (a dropped/unbounded
        // channel would let the publisher race to BURST; a bounded one pins it at the wall).
        let wedged = completed.load(Ordering::SeqCst);
        assert!(
            wedged < BURST,
            "a bounded feed must NOT let the publisher complete the whole burst while the \
             subscriber is wedged (got {wedged} of {BURST} — the channel buffered unboundedly \
             or dropped, violating the doc 11 §1 bounded-mpsc back-pressure invariant)"
        );
        // The wedge is STABLE: across a settle window with the subscriber still parked, the
        // publisher makes NO further progress — it is genuinely back-pressured (awaiting a
        // drained slot), not merely mid-flight. A channel that silently dropped or grew
        // unboundedly would advance `completed` here; the bounded feed pins it.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            completed.load(Ordering::SeqCst),
            wedged,
            "the back-pressured publisher made NO progress while the subscriber stayed wedged \
             — the bounded feed blocks `publish()`, it does not drop or unboundedly buffer"
        );
        assert!(
            !subscriber.is_finished(),
            "the subscriber is still draining the burst (parked on the first-commit gate), not \
             yet returned"
        );

        // ── Release the subscriber: it drains the rest, unblocking the back-pressured publish ─
        // Sending the release token lets the parked first commit return; the subscriber then
        // drains every buffered snapshot, freeing slots so each back-pressured `publish()`
        // completes and the publisher finishes the burst.
        release_tx
            .send(())
            .expect("subscriber parked on the release gate");

        let publisher_result = tokio::time::timeout(Duration::from_secs(10), publisher).await;
        publisher_result
            .expect("the back-pressured publisher completes once the subscriber drains")
            .expect("publisher task joins cleanly");

        // The whole burst published — the feed back-pressured the FAST publisher but NEVER
        // dropped a snapshot: all BURST `publish()` calls returned Ok.
        assert_eq!(
            completed.load(Ordering::SeqCst),
            BURST,
            "every burst publish completed once back-pressure released — none was dropped",
        );

        // ── Drain to completion: the subscriber commits the WHOLE burst, in order ──────────
        let commits = tokio::time::timeout(Duration::from_secs(10), subscriber)
            .await
            .expect("the subscriber returns after the dropped feed closes the channel")
            .expect("subscriber task joins cleanly");

        // FORWARD-ONLY-SEQ + ADMITTER-LAST ORDERING PRESERVED THROUGH THE BURST: every
        // snapshot carried a strictly-forward seq (1..=BURST), so the D72 forward-only commit
        // dropped NONE — all BURST committed, and the committed boundary-zone sequence equals
        // the publish order exactly (the bounded feed back-pressured the publisher WITHOUT
        // reordering or losing the slow stream, admitter-LAST through the single reload sink).
        assert_eq!(
            commits, BURST as u64,
            "every forward-seq snapshot in the burst committed — the bounded feed \
             back-pressures, it does not silently drop the back-pressured snapshots (D72)",
        );
        let expected: Vec<String> = (1..=BURST).map(|i| format!("z{i}.example.")).collect();
        assert_eq!(
            sink.committed(),
            expected,
            "the subscriber committed the whole burst in monotonic seq / publish order — \
             admitter-LAST ordering is preserved through the back-pressure (doc 11 §5.3 / D72)",
        );
    }

    /// Poll `cond` until it is true or the deadline elapses; panics on timeout. A bounded
    /// wait (no fixed sleep) for the subscriber to reach a state the test observes.
    async fn await_until(timeout: Duration, mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition not reached within {timeout:?}");
    }
}

// ===========================================================================
// 15. The PRODUCTION watch_snapshots / SnapshotCommitSink COMBINED-COMMIT path
//     under a publisher BURST EXCEEDING the production feed capacity (doc 11 §1
//     bounded-mpsc rationale / §5.3 one subscriber per host, admitter-LAST / D72
//     forward-only-seq).
//
//     The §14 `subscriber_backpressure` module drives the boundary-zone-ONLY
//     `watch_policies` adapter (a bare `BoundaryZoneSink` recorder). What it does NOT
//     exercise is the PRODUCTION combined-commit `main` actually runs: `watch_snapshots`
//     fed by a `SnapshotCommitSink` that re-sources BOTH the running `PolicyCorePolicy`
//     evaluator AND the authored-SOA boundary zone per snapshot — the
//     `BoundarySnapshot::with_policy` shape carrying a composed document + W2 clamp. Back-
//     pressure there rides the SAME bounded `mpsc` (`boundary_snapshot_feed` /
//     `SNAPSHOT_FEED_CAPACITY`), but the heavier COMBINED commit (evaluator re-source FIRST,
//     boundary-zone re-source LAST — `SnapshotCommitSink::commit_snapshot`) under a burst >
//     capacity is not separately asserted: a regression slowing the evaluator re-source under
//     burst (or one that let the production feed buffer unboundedly / drop committed snapshots)
//     would go uncaught. This module DRIVES that:
//
//       * BACK-PRESSURE ON THE PRODUCTION FEED (not drop, not unbounded buffer): a publisher
//         burst LARGER than the production-feed capacity, into the real `boundary_snapshot_feed`
//         consumed by `watch_snapshots(_, &SnapshotCommitSink)`, while the subscriber is wedged
//         mid-combined-commit. Once the bounded feed is full, a further `publish().await` BLOCKS
//         (awaits) until the SnapshotCommitSink drains a slot — it neither silently drops the
//         committed snapshot nor grows the buffer past the capacity. Observed by spawning the
//         burst publisher on its own task, waiting until it has WEDGED on `send().await` (its
//         completed-publish counter stops short of the burst length and stays there across a
//         bounded settle window), then releasing the subscriber and watching every remaining
//         `publish()` complete.
//
//       * EVERY COMMITTED SNAPSHOT RE-SOURCED BOTH THE EVALUATOR AND THE BOUNDARY ZONE: the
//         SnapshotCommitSink pairs a recording `PolicyEvaluatorSink` (re-sourcing a live
//         `PolicyCorePolicy`, so the evaluator's `policy_version` provably ADVANCES per commit)
//         with a recording `BoundaryZoneSink` (re-sourcing the authored suffix). After the drain,
//         both recorders hold the WHOLE burst, in monotonic seq / publish order — the heavier
//         combined commit back-pressured the FAST publisher without REORDERING or LOSING the
//         slow stream.
//
//       * FORWARD-ONLY-SEQ + ADMITTER-LAST ORDERING PRESERVED THROUGH THE BURST (D72): every
//         snapshot carries a strictly-forward seq AND a distinct evaluator policy version, so the
//         subscriber commits ALL of them — none dropped — in monotonic order through the SINGLE
//         SnapshotCommitSink (evaluator re-source FIRST, boundary-zone LAST). The committed
//         evaluator-version and boundary-zone sequences each equal the publish order exactly, and
//         the LIVE evaluator ends on the LAST burst version (admitter-LAST, doc 11 §5.3 / D72).
//
//     Synthetic + host-local only (§5.3): NO control-plane stream, NO live host agent, NO
//     network, NO bound gate — the test drives the bare `boundary_snapshot_feed` +
//     `watch_snapshots` seam against the PRODUCTION `SnapshotCommitSink` over synthetic recording
//     evaluator / boundary-zone sinks it controls (the SAME public `PolicyEvaluatorSink` /
//     `BoundaryZoneSink` traits the production `GatePolicyReloader` / `GateBoundaryReloader`
//     satisfy), gating the subscriber's first commit on a barrier so the production feed provably
//     fills. POL-3 provenance + the frozen D72 forward-only seq survive the burst.
// ===========================================================================

mod production_snapshot_backpressure {
    //! A self-contained module: it owns its imports without disturbing the shared
    //! top-level `use` block (mirroring the sibling `subscriber_backpressure` /
    //! `main_subscriber_wiring` modules).

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ds_contracts::pol1::parse_layer;
    use ds_dnsgate::policy::{PolicyCorePolicy, TtlClamp};
    use ds_dnsgate::server::{
        boundary_snapshot_feed, watch_snapshots, AdmissionReevaluator, BoundarySnapshot,
        BoundaryZoneSink, LiveAdmission, LiveAdmissions, PolicyEvaluatorSink, SnapshotCommitSink,
    };
    use policy_core::pol1_eval::{compose, ComposedPolicy};

    /// A POL-1 layer whose `schema_version` (and therefore composed `policy_version`) encodes
    /// `seq` — so each burst snapshot carries a DISTINCT, strictly-forward evaluator version the
    /// recording `PolicyEvaluatorSink` can confirm advanced per commit. `parse_layer` accepts a
    /// free-form `pol1/vN` schema-version scalar (the sibling src-module tests use `pol1/v1` /
    /// `pol1/v2`), and `compose` lifts it verbatim into `ComposedPolicy::policy_version`.
    fn composed_for_seq(seq: u64) -> ComposedPolicy {
        let layer_yaml = format!(
            "schema_version: pol1/v{seq}\n\
             layer: system-baseline\n\
             posture: standard\n\
             admission:\n\
            \x20 ttl_floor: 60\n\
            \x20 ttl_ceil: 900\n\
            \x20 grace: 60\n\
            \x20 max_ips_per_domain: 1000\n\
             dns:\n\
            \x20 negative_ttl: 5\n\
             baseline_pack:\n\
            \x20 pack_version: \"2026.06.12-v0\"\n\
            \x20 families:\n\
            \x20\x20 core: {{ tier: enabled }}\n\
            \x20 entries: []\n"
        );
        let layer = parse_layer(&layer_yaml).expect("the per-seq POL-1 layer parses");
        compose(&[layer], &[])
    }

    /// A recording `PolicyEvaluatorSink` (the public trait the production `GatePolicyReloader`
    /// satisfies) that:
    ///   * APPLIES every committed policy version to a LIVE `PolicyCorePolicy` (`reload`), so the
    ///     evaluator's `current_policy_version()` provably ADVANCES per commit — proof the
    ///     combined commit re-sourced the running evaluator, not just the boundary zone,
    ///   * RECORDS the committed `policy_version` in commit order (proves no drop + ordering on
    ///     the evaluator leg).
    ///
    /// It is the FIRST leg of `SnapshotCommitSink::commit_snapshot` (evaluator re-source FIRST,
    /// boundary-zone LAST), so when the boundary-zone leg parks on its barrier the evaluator has
    /// already committed — i.e. the wedge sits on the admitter-LAST boundary-zone step.
    struct RecordingEvaluatorSink {
        live: PolicyCorePolicy,
        versions: Mutex<Vec<String>>,
    }

    impl RecordingEvaluatorSink {
        fn new(live: PolicyCorePolicy) -> Self {
            Self {
                live,
                versions: Mutex::new(Vec::new()),
            }
        }

        /// The evaluator policy versions the subscriber re-sourced, in commit order.
        fn versions(&self) -> Vec<String> {
            self.versions.lock().expect("versions mutex").clone()
        }
    }

    impl PolicyEvaluatorSink for RecordingEvaluatorSink {
        fn commit_policy(&self, composed: &ComposedPolicy, ttl_clamp: TtlClamp) {
            // Re-source the LIVE evaluator from this committed policy version (the production
            // admitter-LAST evaluator hot-reload), then record the version it now decides against.
            self.live.reload(composed.clone(), ttl_clamp);
            self.versions
                .lock()
                .expect("versions mutex")
                .push(self.live.current_policy_version());
        }
    }

    /// A recording `BoundaryZoneSink` (the public trait the production `GateBoundaryReloader`
    /// satisfies) that:
    ///   * RECORDS every committed boundary zone in commit order (proves no drop + ordering on the
    ///     boundary-zone leg),
    ///   * GATES the FIRST commit on a one-shot release barrier so the subscriber wedges
    ///     mid-combined-commit and the bounded production feed provably fills behind it.
    ///
    /// `commit_boundary_zone` is the synchronous frozen seam signature; it runs LAST in
    /// `SnapshotCommitSink::commit_snapshot` (admitter-LAST), so parking here wedges the subscriber
    /// AFTER it has re-sourced the evaluator for snapshot #1 — the heavier combined commit is
    /// genuinely stalled mid-flight. The first call parks on a `std::sync::mpsc::Receiver::recv()`
    /// until the test thread sends the release token; the subscriber runs on its own worker
    /// (multi-thread runtime) so this blocks only that worker, never the burst publisher.
    struct GatedRecordingZoneSink {
        committed: Mutex<Vec<String>>,
        commits_started: AtomicUsize,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl GatedRecordingZoneSink {
        fn new(release: std::sync::mpsc::Receiver<()>) -> Self {
            Self {
                committed: Mutex::new(Vec::new()),
                commits_started: AtomicUsize::new(0),
                release: Mutex::new(Some(release)),
            }
        }

        /// The boundary zones the subscriber committed, in commit order.
        fn committed(&self) -> Vec<String> {
            self.committed.lock().expect("committed mutex").clone()
        }

        /// How many boundary-zone commits the subscriber has ENTERED (incremented before the
        /// first-commit gate blocks) — the probe the test uses to confirm the subscriber wedged.
        fn commits_started(&self) -> usize {
            self.commits_started.load(Ordering::SeqCst)
        }
    }

    impl BoundaryZoneSink for GatedRecordingZoneSink {
        fn commit_boundary_zone(&self, boundary_zone: &str) {
            let nth = self.commits_started.fetch_add(1, Ordering::SeqCst);
            // The FIRST commit parks until the test releases it — so the subscriber stops draining
            // after pulling exactly one snapshot (whose evaluator leg already committed) and the
            // bounded production feed fills behind it, forcing `publish()` to back-pressure. Take
            // the receiver out (one-shot).
            if nth == 0 {
                if let Some(rx) = self.release.lock().expect("release mutex").take() {
                    // Block this subscriber worker until the test sends the release token (or the
                    // sender is dropped). Either way the subscriber resumes draining.
                    let _ = rx.recv();
                }
            }
            self.committed
                .lock()
                .expect("committed mutex")
                .push(boundary_zone.to_string());
        }
    }

    /// A burst > the production feed capacity back-pressures `publish()` on the PRODUCTION
    /// `watch_snapshots` / `SnapshotCommitSink` combined-commit path (the bounded mpsc blocks the
    /// publisher rather than dropping or unboundedly buffering), every committed snapshot
    /// re-sourced BOTH the evaluator AND the boundary zone, and forward-only-seq + admitter-LAST
    /// ordering survives the burst (every snapshot commits, in monotonic order, evaluator-FIRST /
    /// boundary-zone-LAST).
    ///
    /// Multi-thread runtime: the subscriber worker blocks (parked on the first boundary-zone
    /// commit gate) while the burst publisher runs concurrently on another worker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn production_combined_commit_back_pressures_and_re_sources_both_under_burst() {
        // A SMALL bounded feed so a modest burst exceeds it. The burst length is chosen strictly
        // larger than (capacity + the one snapshot the wedged subscriber pulls), so at least one
        // `publish()` MUST find the channel full and back-pressure.
        const CAPACITY: usize = 2;
        const BURST: usize = 12; // >> CAPACITY + 1 — many publishes must block on the bound.

        // The LIVE evaluator the production combined commit re-sources. It starts on a baseline
        // version distinct from every burst version (pol1/v0 ≠ pol1/v{1..=BURST}), so the FIRST
        // commit provably advances it.
        let live = PolicyCorePolicy::new(composed_for_seq(0));
        assert_eq!(
            live.current_policy_version(),
            "pol1/v0",
            "the evaluator starts on the baseline version before any committed snapshot",
        );

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let evaluator_sink = RecordingEvaluatorSink::new(live.clone());
        let zone_sink = GatedRecordingZoneSink::new(release_rx);

        // The PRODUCTION combined-commit sink: the SAME `SnapshotCommitSink::new(zone, evaluator)`
        // `main` wires (evaluator re-source FIRST, boundary-zone re-source LAST per
        // `commit_snapshot`). Owned by `Arc`s so the test can read the recorders after the
        // subscriber returns; the sink borrows them by value through clones of the `Arc`-wrapped
        // sinks below.
        let evaluator_sink = Arc::new(evaluator_sink);
        let zone_sink = Arc::new(zone_sink);
        let (feed, subscription) = boundary_snapshot_feed(CAPACITY);

        // Spawn the subscriber on the PRODUCTION `watch_snapshots` loop driven by the
        // `SnapshotCommitSink`: it pulls snapshot #1, re-sources the evaluator (FIRST leg), enters
        // the FIRST boundary-zone commit (LAST leg), and parks on the release gate — so it stops
        // draining and the bounded production feed fills behind it.
        let sub_evaluator = evaluator_sink.clone();
        let sub_zone = zone_sink.clone();
        let subscriber = tokio::spawn(async move {
            // `SnapshotCommitSink` takes its sinks by value; the `Arc`-deref clones share the same
            // inner recorders the test reads. `(*sub_zone).clone()` is rejected (the sinks are not
            // `Clone`), so pass shared-handle wrappers: a thin `Arc`-backed forwarder.
            let commit_sink = SnapshotCommitSink::new(
                ArcZoneSink(sub_zone.clone()),
                ArcEvaluatorSink(sub_evaluator.clone()),
            );
            watch_snapshots(subscription, &commit_sink).await
        });

        // The burst publisher: publish BURST strictly-forward-seq `with_policy` snapshots
        // (seq 1..=BURST), each carrying a DISTINCT boundary zone AND a DISTINCT composed policy
        // version (pol1/v{seq}) so BOTH legs of the combined commit have something forward to
        // re-source. It runs on its own task; `completed` counts how many `publish().await` calls
        // RETURNED — the probe that lets the test observe the publisher WEDGING on the bounded feed
        // once it is full.
        let completed = Arc::new(AtomicUsize::new(0));
        let pub_completed = completed.clone();
        let publisher = tokio::spawn(async move {
            for i in 1..=BURST {
                let seq = i as u64;
                feed.publish(BoundarySnapshot::with_policy(
                    seq,
                    format!("z{i}.example."),
                    composed_for_seq(seq),
                    TtlClamp {
                        floor: 30,
                        ceil: 600,
                    },
                ))
                .await
                .expect("subscriber alive for the whole burst");
                pub_completed.fetch_add(1, Ordering::SeqCst);
            }
            // Drop the feed (last publisher gone) so the subscriber loop returns after drain.
            drop(feed);
        });

        // ── Prove BACK-PRESSURE: the publisher WEDGES on the bounded production feed ───────────
        // Wait until the subscriber has entered its (gated) first boundary-zone commit — by which
        // point it has ALREADY re-sourced the evaluator for snapshot #1 (evaluator-FIRST), so the
        // heavier combined commit is genuinely stalled mid-flight; it is now parked, no longer
        // draining, so the feed fills to CAPACITY and the publisher blocks.
        await_until(Duration::from_secs(5), || zone_sink.commits_started() >= 1).await;
        assert!(
            !evaluator_sink.versions().is_empty(),
            "the evaluator re-source (FIRST leg) ran before the boundary-zone commit wedged — \
             the combined commit re-sources the evaluator, not only the boundary zone",
        );

        // The publisher cannot have completed the whole burst: the bounded feed (CAPACITY buffered
        // + the one snapshot the wedged subscriber pulled) holds far fewer than BURST, so the
        // surplus `publish()` calls are blocked on `send().await`. Sample the completed count,
        // then confirm it is STUCK across a settle window (a dropped/unbounded channel would let
        // the publisher race to BURST; a bounded one pins it at the wall).
        let wedged = completed.load(Ordering::SeqCst);
        assert!(
            wedged < BURST,
            "a bounded production feed must NOT let the publisher complete the whole burst while \
             the SnapshotCommitSink is wedged (got {wedged} of {BURST} — the channel buffered \
             unboundedly or dropped, violating the doc 11 §1 bounded-mpsc back-pressure invariant)"
        );
        // The wedge is STABLE: across a settle window with the subscriber still parked, the
        // publisher makes NO further progress — it is genuinely back-pressured (awaiting a drained
        // slot), not merely mid-flight. A channel that silently dropped or grew unboundedly would
        // advance `completed` here; the bounded production feed pins it.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            completed.load(Ordering::SeqCst),
            wedged,
            "the back-pressured publisher made NO progress while the SnapshotCommitSink stayed \
             wedged — the bounded production feed blocks `publish()`, it does not drop or \
             unboundedly buffer the committed snapshots"
        );
        assert!(
            !subscriber.is_finished(),
            "the subscriber is still draining the burst (parked on the first boundary-zone commit \
             gate), not yet returned"
        );

        // ── Release the subscriber: it drains the rest, unblocking the back-pressured publish ──
        // Sending the release token lets the parked first boundary-zone commit return; the
        // subscriber then drains every buffered snapshot (each re-sourcing the evaluator FIRST then
        // the boundary zone LAST), freeing slots so each back-pressured `publish()` completes and
        // the publisher finishes the burst.
        release_tx
            .send(())
            .expect("subscriber parked on the release gate");

        let publisher_result = tokio::time::timeout(Duration::from_secs(10), publisher).await;
        publisher_result
            .expect("the back-pressured publisher completes once the SnapshotCommitSink drains")
            .expect("publisher task joins cleanly");

        // The whole burst published — the production feed back-pressured the FAST publisher but
        // NEVER dropped a snapshot: all BURST `publish()` calls returned Ok.
        assert_eq!(
            completed.load(Ordering::SeqCst),
            BURST,
            "every burst publish completed once back-pressure released — none was dropped",
        );

        // ── Drain to completion: the subscriber commits the WHOLE burst, in order, BOTH legs ───
        let commits = tokio::time::timeout(Duration::from_secs(10), subscriber)
            .await
            .expect("the subscriber returns after the dropped feed closes the channel")
            .expect("subscriber task joins cleanly");

        // FORWARD-ONLY-SEQ + ADMITTER-LAST ORDERING PRESERVED THROUGH THE BURST: every snapshot
        // carried a strictly-forward seq (1..=BURST), so the D72 forward-only commit dropped NONE —
        // all BURST committed through the single SnapshotCommitSink.
        assert_eq!(
            commits, BURST as u64,
            "every forward-seq snapshot in the burst committed through the production \
             SnapshotCommitSink — the bounded feed back-pressures, it does not silently drop the \
             back-pressured snapshots (D72)",
        );

        // BOTH legs re-sourced for EVERY committed snapshot, in monotonic seq / publish order:
        //   * the boundary-zone leg recorded z1..=zBURST,
        //   * the evaluator leg recorded pol1/v1..=pol1/vBURST (the live `policy_version` advanced
        //     per commit) — proof the combined commit re-sourced the evaluator too, not just the
        //     suffix, under the burst.
        let expected_zones: Vec<String> = (1..=BURST).map(|i| format!("z{i}.example.")).collect();
        assert_eq!(
            zone_sink.committed(),
            expected_zones,
            "the subscriber committed the whole burst's boundary zones in monotonic seq / publish \
             order — admitter-LAST ordering is preserved through the back-pressure (doc 11 §5.3 / \
             D72)",
        );
        let expected_versions: Vec<String> = (1..=BURST).map(|i| format!("pol1/v{i}")).collect();
        assert_eq!(
            evaluator_sink.versions(),
            expected_versions,
            "every committed snapshot ALSO re-sourced the running evaluator (the combined-commit \
             evaluator leg), in the same monotonic seq / publish order — the heavier production \
             commit back-pressures without reordering or losing the slow stream",
        );

        // The LIVE evaluator ends on the LAST burst version (admitter-LAST: the final committed
        // policy version is the one the running evaluator now decides against).
        assert_eq!(
            live.current_policy_version(),
            format!("pol1/v{BURST}"),
            "the running evaluator ends on the LAST burst version — admitter-LAST, one monotonic \
             policy version end to end (D72)",
        );

        // Counts agree across the legs and the loop: one commit per burst snapshot, no leg lagging.
        assert_eq!(
            zone_sink.committed().len(),
            BURST,
            "the boundary-zone leg committed exactly the burst count",
        );
        assert_eq!(
            evaluator_sink.versions().len(),
            BURST,
            "the evaluator leg committed exactly the burst count — both legs ran on every commit",
        );
    }

    /// A thin `Arc`-backed `BoundaryZoneSink` forwarder so the by-value `SnapshotCommitSink::new`
    /// can hold a SHARED-HANDLE to the recorder the test reads after the subscriber returns (the
    /// recorders are not `Clone` — they own `Mutex`/`AtomicUsize` state — so the `Arc` is the
    /// shared handle, mirroring how the production reloaders are `Clone` shared-handles).
    struct ArcZoneSink(Arc<GatedRecordingZoneSink>);

    impl BoundaryZoneSink for ArcZoneSink {
        fn commit_boundary_zone(&self, boundary_zone: &str) {
            self.0.commit_boundary_zone(boundary_zone);
        }
    }

    /// A thin `Arc`-backed `PolicyEvaluatorSink` forwarder — the evaluator-leg twin of
    /// [`ArcZoneSink`], so the test reads the recorded versions after the subscriber returns.
    struct ArcEvaluatorSink(Arc<RecordingEvaluatorSink>);

    impl PolicyEvaluatorSink for ArcEvaluatorSink {
        fn commit_policy(&self, composed: &ComposedPolicy, ttl_clamp: TtlClamp) {
            self.0.commit_policy(composed, ttl_clamp);
        }
    }

    /// Poll `cond` until it is true or the deadline elapses; panics on timeout. A bounded wait
    /// (no fixed sleep) for the subscriber to reach a state the test observes — the sibling
    /// `subscriber_backpressure` module's twin, owned here so this module is self-contained.
    async fn await_until(timeout: Duration, mut cond: impl FnMut() -> bool) {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition not reached within {timeout:?}");
    }

    // ── §5.4 revocation-sweep leg under burst back-pressure ────────────────────────────────────
    //
    // The combined-commit test above drives the NoSweep `SnapshotCommitSink::new` path (evaluator
    // FIRST, boundary-zone LAST). The doc 11 §5.4 `with_revocation_sweep` variant inserts a THIRD
    // commit leg between them: `commit_snapshot` runs evaluator re-source FIRST (`commit_policy`),
    // the §5.4 revocation sweep SECOND (`target.sweep(reevaluator)`, only on an evaluator re-source),
    // then the boundary-zone re-source LAST. The test below extends the SAME burst harness onto a
    // `with_revocation_sweep`-configured sink, asserting the sweep leg survives a burst > feed
    // capacity: it back-pressures (no drop, no unbounded buffer), runs admitter-LAST-then-sweep per
    // commit, and preserves D72 forward-only-seq ordering.

    /// A POL-1 layer whose `schema_version` encodes `seq` (so the committed `policy_version` is the
    /// distinct, strictly-forward `pol1/v{seq}` the recording evaluator confirms advanced) AND that
    /// BLOCKS exactly one name — `block{seq}.example` — at a SEVERING rung (`kill+snapshot`,
    /// block-or-higher → D53 conntrack flush), while ALLOWLISTING every burst name `block1..=blockN`.
    /// Deny-overrides (policy-core §1.2): the blocklist wins over the allowlist for `block{seq}`, so
    /// under version `pol1/v{seq}` exactly `block{seq}.example` DENIES (at a severing rung) and every
    /// other `block{j}.example` (j ≠ seq) still ADMITS. Re-sourcing the live evaluator to `pol1/v{seq}`
    /// and then sweeping the registry therefore revokes EXACTLY `block{seq}`'s admission — the
    /// per-commit signal that the sweep re-evaluated against THIS commit's version (admitter-LAST).
    fn composed_blocking_seq(seq: u64, total: u64) -> ComposedPolicy {
        let mut allow = String::new();
        for j in 1..=total {
            allow.push_str(&format!("  - domain: block{j}.example\n"));
        }
        let layer_yaml = format!(
            "schema_version: pol1/v{seq}\n\
             layer: system-baseline\n\
             posture: standard\n\
             admission:\n\
            \x20 ttl_floor: 60\n\
            \x20 ttl_ceil: 900\n\
            \x20 grace: 60\n\
            \x20 max_ips_per_domain: 1000\n\
             dns:\n\
            \x20 negative_ttl: 5\n\
             allowlist:\n\
             {allow}\
             blocklist:\n\
            \x20 - domain: block{seq}.example\n\
            \x20\x20\x20 reason: tightened-policy-push\n\
            \x20\x20\x20 rung: kill+snapshot\n\
             baseline_pack:\n\
            \x20 pack_version: \"2026.06.12-v0\"\n\
            \x20 families:\n\
            \x20\x20 core: {{ tier: enabled }}\n\
            \x20 entries: []\n"
        );
        let layer = parse_layer(&layer_yaml).expect("the per-seq blocking POL-1 layer parses");
        compose(&[layer], &[])
    }

    /// A burst > the production feed capacity back-pressures `publish()` on the PRODUCTION
    /// `watch_snapshots` / `SnapshotCommitSink::with_revocation_sweep` combined-commit-PLUS-sweep
    /// path (doc 11 §5.4 / §1 bounded-mpsc / §5.3 admitter-LAST / D72). This is the sibling of
    /// `production_combined_commit_back_pressures_and_re_sources_both_under_burst`, swapping the
    /// `SnapshotCommitSink::new` (NoSweep) sink for the `with_revocation_sweep` (LiveAdmissions) sink
    /// so the THIRD commit leg — the §5.4 revocation sweep, ordered evaluator-FIRST → sweep-SECOND →
    /// boundary-zone-LAST — is asserted under the burst. It proves:
    ///   * BACK-PRESSURE (not drop, not unbounded buffer): the bounded feed wedges the burst
    ///     publisher while the subscriber is parked mid-commit (on the first boundary-zone leg, i.e.
    ///     AFTER the evaluator re-source AND the sweep for snapshot #1 have already run), and the
    ///     publisher makes NO progress across a settle window — then drains to the whole burst on
    ///     release with NONE dropped.
    ///   * SWEEP ADMITTER-LAST-THEN-SWEEP, PER COMMIT: each burst version `pol1/v{seq}` blocks
    ///     EXACTLY `block{seq}.example` (and allows the rest), and the registry is seeded with one
    ///     live admission per burst name. The sweep re-evaluates against the version the evaluator
    ///     leg JUST re-sourced (admitter-LAST), so commit #seq revokes EXACTLY `block{seq}`'s
    ///     admission — observed at the wedge (only snapshot #1's `block1` admission is gone while
    ///     `block2..=blockN` survive: the sweep ran BEFORE the parked boundary-zone leg, AFTER the
    ///     evaluator leg) and at drain (all `block1..=blockN` revoked, one per commit's sweep — the
    ///     sweep re-evaluated per commit, never blocked or reordered ahead of the evaluator).
    ///   * D72 FORWARD-ONLY-SEQ ORDERING PRESERVED: every strictly-forward-seq snapshot commits, in
    ///     monotonic publish order, on BOTH the evaluator and boundary-zone legs — the heavier
    ///     three-leg commit back-pressures the FAST publisher without REORDERING or LOSING the slow
    ///     stream; the live evaluator ends on the LAST burst version.
    ///
    /// Loopback/synthetic only; no bound gate, no control-plane stream (§5.3). FROZEN DENY SHAPE:
    /// the revoked admissions ride the three-field `DnsVerdict::Deny {rcode_policy, rung, provenance}`
    /// through the sweep's re-evaluation; POL-3 provenance (rule-id/layer/policy-version) is preserved
    /// on the severing-rung deny each revocation reads.
    ///
    /// Multi-thread runtime: the subscriber worker blocks (parked on the first boundary-zone commit
    /// gate) while the burst publisher runs concurrently on another worker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn revocation_sweep_leg_back_pressures_and_sweeps_per_commit_under_burst() {
        // A SMALL bounded feed so a modest burst exceeds it. The burst length is chosen strictly
        // larger than (capacity + the one snapshot the wedged subscriber pulls), so at least one
        // `publish()` MUST find the channel full and back-pressure.
        const CAPACITY: usize = 2;
        const BURST: usize = 12; // >> CAPACITY + 1 — many publishes must block on the bound.

        // The LIVE evaluator the production combined commit re-sources AND the §5.4 sweep
        // re-evaluates against (the SAME shared inner `Arc` — `main` hands the policy reloader's
        // sibling as the re-evaluator, so the sweep decides against the version the evaluator leg
        // just committed). It starts on a baseline `pol1/v0` distinct from every burst version that
        // allowlists every burst name `block1..=blockN` and blocks only the never-seeded sentinel
        // `block0.example`, so every seeded admission ADMITS under it. Either way NOTHING is revoked
        // before the first committed snapshot: the sweep only runs on a commit, and no snapshot has
        // committed yet — the registry is untouched until snapshot #1's evaluator-leg-then-sweep.
        let live = PolicyCorePolicy::new(composed_blocking_seq(0, BURST as u64));
        assert_eq!(
            live.current_policy_version(),
            "pol1/v0",
            "the evaluator starts on the baseline version before any committed snapshot",
        );

        // Seed ONE live admission per burst name, `block1.example..=blockN.example`, all under the
        // (synthetic) baseline. Each gets a distinct sole-reference IP, so the reverse-index refcount
        // deletes its allow-set element on revocation (no shared-CDN survivor masks the removal).
        let admissions = LiveAdmissions::new();
        for i in 1..=BURST {
            let ip = format!("203.0.113.{i}")
                .parse()
                .expect("the test IP parses");
            admissions.admit(LiveAdmission::new(
                format!("sess-{i}"),
                format!("block{i}.example"),
                ip,
            ));
        }
        assert_eq!(
            admissions.len(),
            BURST,
            "one live admission seeded per burst name, all live under the baseline",
        );

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let evaluator_sink = Arc::new(RecordingEvaluatorSink::new(live.clone()));
        let zone_sink = Arc::new(GatedRecordingZoneSink::new(release_rx));
        let (feed, subscription) = boundary_snapshot_feed(CAPACITY);

        // The PRODUCTION commit-PLUS-sweep sink: the SAME
        // `SnapshotCommitSink::with_revocation_sweep(zone, evaluator, admissions, reevaluator)` `main`
        // wires (evaluator re-source FIRST, §5.4 sweep SECOND, boundary-zone re-source LAST per
        // `commit_snapshot`). The re-evaluator shares `live`'s inner `Arc`, so the sweep decides
        // against the version the evaluator leg just re-sourced (admitter-LAST). The `admissions`
        // clone is a shared-handle clone — the test reads the SAME registry the sweep mutates.
        let sub_evaluator = evaluator_sink.clone();
        let sub_zone = zone_sink.clone();
        let sweep_admissions = admissions.clone();
        let sweep_reevaluator = live.clone();
        let subscriber = tokio::spawn(async move {
            let commit_sink = SnapshotCommitSink::with_revocation_sweep(
                ArcZoneSink(sub_zone.clone()),
                ArcEvaluatorSink(sub_evaluator.clone()),
                sweep_admissions,
                sweep_reevaluator,
            );
            watch_snapshots(subscription, &commit_sink).await
        });

        // The burst publisher: publish BURST strictly-forward-seq `with_policy` snapshots
        // (seq 1..=BURST), each carrying a DISTINCT boundary zone AND a DISTINCT composed policy
        // version (`pol1/v{seq}`) that blocks EXACTLY `block{seq}.example`. It runs on its own task;
        // `completed` counts how many `publish().await` calls RETURNED — the probe that lets the test
        // observe the publisher WEDGING on the bounded feed once it is full.
        let completed = Arc::new(AtomicUsize::new(0));
        let pub_completed = completed.clone();
        let publisher = tokio::spawn(async move {
            for i in 1..=BURST {
                let seq = i as u64;
                feed.publish(BoundarySnapshot::with_policy(
                    seq,
                    format!("z{i}.example."),
                    composed_blocking_seq(seq, BURST as u64),
                    TtlClamp {
                        floor: 30,
                        ceil: 600,
                    },
                ))
                .await
                .expect("subscriber alive for the whole burst");
                pub_completed.fetch_add(1, Ordering::SeqCst);
            }
            // Drop the feed (last publisher gone) so the subscriber loop returns after drain.
            drop(feed);
        });

        // ── Prove BACK-PRESSURE: the publisher WEDGES on the bounded production feed ───────────
        // Wait until the subscriber has entered its (gated) first boundary-zone commit — by which
        // point, for snapshot #1, it has ALREADY re-sourced the evaluator (FIRST leg) AND run the
        // §5.4 sweep (SECOND leg); the wedge sits on the admitter-LAST boundary-zone step.
        await_until(Duration::from_secs(5), || zone_sink.commits_started() >= 1).await;
        assert!(
            !evaluator_sink.versions().is_empty(),
            "the evaluator re-source (FIRST leg) ran before the boundary-zone commit wedged — the \
             combined commit re-sources the evaluator, not only the boundary zone",
        );
        // SWEEP RAN AFTER THE EVALUATOR RE-SOURCE AND BEFORE THE PARKED BOUNDARY-ZONE LEG, for
        // snapshot #1: under `pol1/v1` exactly `block1.example` denies, so the sweep (admitter-LAST,
        // against the just-re-sourced version) has ALREADY revoked `block1`'s admission — while
        // `block2..=blockN` survive (their versions have not committed yet). This is the per-commit
        // ordering proof: the sweep is wedged-side of the boundary-zone leg, evaluator-side after it.
        let survivors_at_wedge = admissions.snapshot();
        assert_eq!(
            survivors_at_wedge.len(),
            BURST - 1,
            "exactly snapshot #1's admission was swept while the boundary-zone leg is parked — the \
             §5.4 sweep ran AFTER the evaluator re-source and BEFORE the (parked) boundary-zone \
             commit (admitter-LAST-then-sweep), per commit",
        );
        assert!(
            !survivors_at_wedge
                .iter()
                .any(|a| a.fqdn == "block1.example."),
            "`block1.example` — the name `pol1/v1` blocks — was revoked by snapshot #1's sweep",
        );
        assert!(
            survivors_at_wedge
                .iter()
                .any(|a| a.fqdn == "block2.example."),
            "`block2.example` survives the wedge — `pol1/v2` has not committed, so its sweep has \
             not run (the sweep re-evaluates PER COMMIT against that commit's version, not eagerly)",
        );

        // The publisher cannot have completed the whole burst: the bounded feed holds far fewer than
        // BURST, so the surplus `publish()` calls are blocked on `send().await`. Sample the completed
        // count, then confirm it is STUCK across a settle window (a dropped/unbounded channel would
        // let the publisher race to BURST; a bounded one pins it at the wall).
        let wedged = completed.load(Ordering::SeqCst);
        assert!(
            wedged < BURST,
            "a bounded production feed must NOT let the publisher complete the whole burst while \
             the sweep-configured SnapshotCommitSink is wedged (got {wedged} of {BURST} — the \
             channel buffered unboundedly or dropped, violating the doc 11 §1 bounded-mpsc \
             back-pressure invariant)"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            completed.load(Ordering::SeqCst),
            wedged,
            "the back-pressured publisher made NO progress while the sweep-configured \
             SnapshotCommitSink stayed wedged — the bounded production feed blocks `publish()`, it \
             does not drop or unboundedly buffer the committed snapshots"
        );
        assert!(
            !subscriber.is_finished(),
            "the subscriber is still draining the burst (parked on the first boundary-zone commit \
             gate), not yet returned"
        );

        // ── Release the subscriber: it drains the rest, unblocking the back-pressured publish ──
        // Sending the release token lets the parked first boundary-zone commit return; the
        // subscriber then drains every buffered snapshot (each re-sourcing the evaluator FIRST, then
        // running the §5.4 sweep against THAT version, then the boundary zone LAST), freeing slots so
        // each back-pressured `publish()` completes and the publisher finishes the burst.
        release_tx
            .send(())
            .expect("subscriber parked on the release gate");

        let publisher_result = tokio::time::timeout(Duration::from_secs(10), publisher).await;
        publisher_result
            .expect("the back-pressured publisher completes once the SnapshotCommitSink drains")
            .expect("publisher task joins cleanly");

        // The whole burst published — the production feed back-pressured the FAST publisher but
        // NEVER dropped a snapshot: all BURST `publish()` calls returned Ok.
        assert_eq!(
            completed.load(Ordering::SeqCst),
            BURST,
            "every burst publish completed once back-pressure released — none was dropped",
        );

        // ── Drain to completion: the subscriber commits the WHOLE burst, in order, ALL THREE legs ─
        let commits = tokio::time::timeout(Duration::from_secs(10), subscriber)
            .await
            .expect("the subscriber returns after the dropped feed closes the channel")
            .expect("subscriber task joins cleanly");

        // D72 FORWARD-ONLY-SEQ PRESERVED: every strictly-forward seq (1..=BURST) committed through
        // the single sweep-configured SnapshotCommitSink — none dropped under back-pressure.
        assert_eq!(
            commits, BURST as u64,
            "every forward-seq snapshot in the burst committed through the with_revocation_sweep \
             SnapshotCommitSink — the bounded feed back-pressures, it does not silently drop the \
             back-pressured snapshots (D72)",
        );

        // BOTH the evaluator and boundary-zone legs re-sourced for EVERY committed snapshot, in
        // monotonic seq / publish order — admitter-LAST ordering preserved through the back-pressure.
        let expected_zones: Vec<String> = (1..=BURST).map(|i| format!("z{i}.example.")).collect();
        assert_eq!(
            zone_sink.committed(),
            expected_zones,
            "the subscriber committed the whole burst's boundary zones in monotonic seq / publish \
             order — admitter-LAST ordering is preserved through the back-pressure (doc 11 §5.3 / \
             D72)",
        );
        let expected_versions: Vec<String> = (1..=BURST).map(|i| format!("pol1/v{i}")).collect();
        assert_eq!(
            evaluator_sink.versions(),
            expected_versions,
            "every committed snapshot ALSO re-sourced the running evaluator (the combined-commit \
             evaluator leg), in the same monotonic seq / publish order — the heavier three-leg \
             commit back-pressures without reordering or losing the slow stream",
        );

        // SWEEP RAN PER COMMIT, ADMITTER-LAST: every burst commit re-sourced `pol1/v{seq}` then
        // swept against it, revoking EXACTLY `block{seq}.example`. After the whole burst, ALL
        // `block1..=blockN` admissions are gone — each removed by its OWN commit's sweep (the sweep
        // re-evaluated per commit; it never blocked, ran eagerly, or reordered ahead of its
        // evaluator leg). A sweep that ran BEFORE the per-commit re-source would have decided
        // `block{seq}` against the PRIOR (allowing) version and left it live.
        assert!(
            admissions.is_empty(),
            "every seeded admission was revoked — one per commit's sweep, each against the version \
             that commit's evaluator leg just re-sourced (§5.4 admitter-LAST, per commit)",
        );

        // The LIVE evaluator ends on the LAST burst version (admitter-LAST: the final committed
        // policy version is the one the running evaluator — and so the sweep's last re-evaluation —
        // decides against). FROZEN DENY SHAPE + POL-3: re-evaluating the last-blocked name now
        // yields the three-field `Deny {rcode_policy, rung, provenance}` at a severing rung, with
        // non-empty POL-3 provenance (rule-id/layer/policy-version) preserved.
        assert_eq!(
            live.current_policy_version(),
            format!("pol1/v{BURST}"),
            "the running evaluator ends on the LAST burst version — admitter-LAST, one monotonic \
             policy version end to end (D72)",
        );
        let last_blocked =
            live.reevaluate(&format!("sess-{BURST}"), &format!("block{BURST}.example."));
        assert!(
            !last_blocked.admits(),
            "under the final version the last-blocked name is denied (the sweep revoked it)",
        );
        assert!(
            last_blocked.severs_established_flows(),
            "the revoking deny is at a block-or-higher (severing) rung — the frozen three-field \
             Deny carries the D53 rung (rung-conditional conntrack flush)",
        );
        let prov = last_blocked.provenance();
        assert!(
            !prov.rule_id.is_empty() && !prov.policy_version.is_empty(),
            "POL-3 provenance (rule-id + policy-version) is preserved on the revoking deny verdict",
        );

        // Counts agree across the legs and the loop: one commit per burst snapshot, no leg lagging.
        assert_eq!(
            zone_sink.committed().len(),
            BURST,
            "the boundary-zone leg committed exactly the burst count",
        );
        assert_eq!(
            evaluator_sink.versions().len(),
            BURST,
            "the evaluator leg committed exactly the burst count — every leg ran on every commit",
        );
    }
}
