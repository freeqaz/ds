// SPDX-License-Identifier: Apache-2.0
//! `event_surface` split (D72): the forward-only-seq DUPLICATE / OUT-OF-ORDER drop on the
//! PRODUCTION combined-commit wire + the over-capacity interleaved burst + the operationally-
//! observable stale-fan-out signal — sections 16-17, extracted from the oversized
//! `tests/event_surface.rs` (test-only reorg, behavior-preserving). `#[path]`-included into
//! the `event_surface` binary; `crate::{query_bytes, tcp_query}` resolve to its root helpers.

// ===========================================================================
// 16. The D72 forward-only-seq DUPLICATE / OUT-OF-ORDER drop on the PRODUCTION
//     COMBINED-COMMIT WIRE (a real loopback gate + the host-LOCAL
//     BoundarySnapshotFeed → `watch_snapshots` → `SnapshotCommitSink` pairing the
//     gate's `boundary_zone_reloader()` + `policy_reloader()`, exactly `main`'s
//     wiring) — doc 11 §5.3 admitter-LAST / D72 one monotonic policy version.
//
//     The src-module test `d72_forward_only_seq_drops_duplicate_and_stale_fan_outs`
//     proves the drop against a synthetic boundary-zone-ONLY `RecordingSink`. The
//     §13 `main_subscriber_wiring` integration test drives a duplicate/stale through
//     the boundary-zone-only `watch_policies` adapter and asserts the wire SOA MNAME.
//     What NEITHER exercises is the PRODUCTION COMBINED commit `main` actually runs —
//     `watch_snapshots(_, &SnapshotCommitSink)` re-sourcing BOTH the running
//     `PolicyCorePolicy` evaluator AND the authored-SOA boundary zone — under a
//     duplicate AND an out-of-order (seq < current) committed `with_policy` fan-out.
//     A regression that let a stale fan-out re-source the EVALUATOR backwards (even if
//     it kept the boundary-zone forward-only) would slip past both. This DRIVES that:
//
//       * A FORWARD `with_policy` snapshot (seq 5, policy `pol1/v5`, suffix
//         `v5.example.`) commits on the real running gate: the live evaluator
//         re-sources to `pol1/v5` AND the authored MNAME re-sources to
//         `denied.policy.v5.example.` — observed ON THE WIRE (a deny round-trip's SOA
//         MNAME) and through `gate.policy_version()` + a shared-handle `evaluate`.
//       * A DUPLICATE seq (5, policy `pol1/vDUP`, suffix `dup.example.`) and an
//         OUT-OF-ORDER seq (3, policy `pol1/vSTALE`, suffix `stale.example.`) are
//         DROPPED by the subscriber's D72 forward-only commit: NEITHER re-sources the
//         evaluator NOR the boundary zone — the running gate's evaluator stays on
//         `pol1/v5` and the wire MNAME stays at `denied.policy.v5.example.` (the stale
//         fan-out NEVER re-sources EITHER leg backwards).
//       * A strictly-FORWARD seq (8, policy `pol1/v8`, suffix `final.example.`)
//         commits once more, re-sourcing BOTH legs admitter-LAST — proving only a
//         strictly-forward seq advances after the drop.
//       * The subscriber's returned commit count is EXACTLY the forward count (2:
//         seq 5 then seq 8), never the duplicate or the stale.
//
//     Synthetic + loopback only (§5.3): a real `spawn_gate`-bound gate on 127.0.0.1:0,
//     the host-LOCAL `boundary_snapshot_feed` (NEVER a control-plane stream), and
//     `with_policy` snapshots whose composed documents are parsed from synthetic POL-1
//     layers. No live host agent, no policy stream, no network beyond loopback.
// ===========================================================================

mod production_wire_forward_only_drop {
    //! A self-contained module: it owns its imports without disturbing the shared
    //! top-level `use` block (mirroring the sibling subscriber-wiring modules).

    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use ds_contracts::pol1::parse_layer;
    use ds_dnsgate::policy::{DnsQueryCtx, PolicyCorePolicy, PolicyHook, TtlClamp};
    use ds_dnsgate::server::{
        boundary_snapshot_feed, watch_snapshots, BoundarySnapshot, GateConfig, SnapshotCommitSink,
    };
    use ds_dnsgate::spawn_gate;
    use policy_core::pol1_eval::{compose, ComposedPolicy};

    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::rdata::SOA as ProtoSoa;
    use hickory_proto::rr::{RData as ProtoRData, RecordType};

    use crate::{query_bytes, tcp_query};

    /// A POL-1 layer whose `schema_version` (and therefore composed `policy_version`) encodes
    /// `seq`, AND that hard-DENIES exactly `blocked.example` (every version blocks the SAME name
    /// at a severing rung) — so the running evaluator's verdict for `blocked.example` is a deny
    /// under EVERY version, but its `policy_version` string is the distinct, strictly-forward
    /// `pol1/v{seq}` the live gate confirms it re-sourced (or did NOT, for a dropped fan-out).
    /// `parse_layer` lifts a free-form `pol1/vN` schema-version scalar verbatim into the composed
    /// `policy_version` (the sibling src-module tests use `pol1/v1` / `pol1/v2`).
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
             blocklist:\n\
            \x20 - domain: blocked.example\n\
            \x20\x20\x20 reason: forward-only-seq-harness\n\
            \x20\x20\x20 rung: kill+snapshot\n\
             baseline_pack:\n\
            \x20 pack_version: \"2026.06.12-v0\"\n\
            \x20 families:\n\
            \x20\x20 core: {{ tier: enabled }}\n\
            \x20 entries: []\n"
        );
        let layer = parse_layer(&layer_yaml).expect("the per-seq POL-1 layer parses");
        compose(&[layer], &[])
    }

    fn ctx(qname: &str) -> DnsQueryCtx {
        DnsQueryCtx {
            session: "forward-only-seq-harness".to_string(),
            qname: qname.to_string(),
            qtype: 1,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        }
    }

    /// Extract the authored signature-SOA MNAME from a parsed deny response, if present.
    fn soa_mname(msg: &Message) -> Option<String> {
        msg.authorities.iter().find_map(|r| match &r.data {
            ProtoRData::SOA(soa) => Some(soa_mname_ascii(soa)),
            _ => None,
        })
    }

    fn soa_mname_ascii(soa: &ProtoSoa) -> String {
        soa.mname.to_ascii()
    }

    /// The authored-SOA MNAME the running gate signs a deny with ON THE WIRE (TCP) — the §3.2
    /// signature whose `<boundary_zone>` suffix the D72 reload re-sources. Asserts the frozen deny
    /// shape (NXDOMAIN + authored SOA in authority) and returns the live MNAME.
    async fn wire_authored_mname(addr: SocketAddr) -> String {
        let query = query_bytes(0x7e01, "blocked.example.", RecordType::A);
        let resp = tokio::time::timeout(Duration::from_secs(5), tcp_query(addr, &query))
            .await
            .expect("tcp deny round-trip timed out");
        let msg = Message::from_vec(&resp).expect("tcp deny response parses");
        assert_eq!(
            msg.metadata.response_code,
            ResponseCode::NXDomain,
            "the evaluator hard-denies blocked.example → §3.2 NXDOMAIN",
        );
        assert!(
            msg.answers.is_empty(),
            "a hard deny has an empty answer section",
        );
        soa_mname(&msg).unwrap_or_else(|| panic!("authored SOA present in authority: {msg:?}"))
    }

    #[tokio::test]
    async fn duplicate_and_out_of_order_committed_snapshots_re_source_neither_leg_on_the_wire() {
        // ── PRODUCTION combined-commit wiring (verbatim `main`'s) around a real loopback gate ──
        //
        //   let mut gate = spawn_gate(policy, config).await?;
        //   let (feed, subscription) = boundary_snapshot_feed(SNAPSHOT_FEED_CAPACITY);
        //   let commit_sink =
        //       SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader());
        //   let subscriber =
        //       tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });
        //   ... // host agent fans out committed snapshots onto `feed`
        //   drop(feed);                 // last publisher gone → subscriber loop returns
        //   let commits = subscriber.await?;
        //
        // This test stands up exactly that loop and drives a FORWARD snapshot, then a DUPLICATE
        // and an OUT-OF-ORDER (seq < current) fan-out, then a strictly-forward snapshot — and
        // asserts the stale fan-outs re-source NEITHER the evaluator NOR the boundary zone.

        // The running gate evaluates against `pol1/v5` (hard-denies `blocked.example`), with a
        // known startup boundary zone (the live host-snapshot value `main` threads into config).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        // A shared-handle clone of the installed evaluator held BEFORE spawn so the test can
        // observe the live verdict's policy version the gate's handlers decide with — it shares
        // the SAME inner `Arc`, so a subscriber-driven reload through the gate is visible here.
        let live_policy = PolicyCorePolicy::new(composed_for_seq(5));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        let tcp_addr = gate.tcp_local_addr();

        // Startup: the running evaluator decides against `pol1/v5`, and the wire MNAME is the
        // startup snapshot suffix (the gate sourced the boundary zone from config, not the const).
        assert_eq!(gate.policy_version(), "pol1/v5");
        assert!(
            !live_policy.evaluate(&ctx("blocked.example.")).admits(),
            "v5 hard-denies blocked.example on the live evaluator",
        );
        assert_eq!(
            wire_authored_mname(tcp_addr).await,
            "denied.policy.startup.example.",
            "the startup deny signs with the live snapshot suffix, not the const default",
        );

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);

        // The PRODUCTION combined-commit sink: boundary-zone reloader + evaluator reloader, paired
        // (the verbatim `main` wiring). Run it against the live gate on its own task.
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader());
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // ── 1. A FORWARD snapshot (seq 5) commits BOTH legs admitter-LAST ──────────────────────
        // The host agent fans out a committed `with_policy` snapshot (seq 5, `pol1/v5`,
        // suffix `v5.example.`) host-locally (NEVER a control-plane stream, §5.3).
        feed.publish(BoundarySnapshot::with_policy(
            5,
            "v5.example.",
            composed_for_seq(5),
            TtlClamp {
                floor: 30,
                ceil: 600,
            },
        ))
        .await
        .expect("subscriber alive for the first committed snapshot");

        // ── 2. A DUPLICATE seq (5) and an OUT-OF-ORDER seq (3): the D72 forward-only commit drops ─
        // ──    BOTH — neither re-sources the evaluator NOR the boundary zone backwards ──────────
        // Each carries a DISTINCT composed policy version AND a DISTINCT boundary zone, so if the
        // drop FAILED the regression would show on EITHER leg (the wire MNAME OR the policy
        // version flipping to the stale value).
        feed.publish(BoundarySnapshot::with_policy(
            5, // duplicate seq — dropped
            "dup.example.",
            composed_for_seq(105), // pol1/v105 — must NEVER become the live version
            TtlClamp {
                floor: 30,
                ceil: 600,
            },
        ))
        .await
        .expect("subscriber alive for the duplicate fan-out");
        feed.publish(BoundarySnapshot::with_policy(
            3, // out-of-order (stale, seq < current) — dropped
            "stale.example.",
            composed_for_seq(103), // pol1/v103 — must NEVER become the live version
            TtlClamp {
                floor: 30,
                ceil: 600,
            },
        ))
        .await
        .expect("subscriber alive for the stale fan-out");

        // ── 3. A strictly-FORWARD seq (8): committed admitter-LAST, re-sourcing BOTH legs once more ─
        feed.publish(BoundarySnapshot::with_policy(
            8,
            "final.example.",
            composed_for_seq(8),
            TtlClamp {
                floor: 30,
                ceil: 600,
            },
        ))
        .await
        .expect("subscriber alive for the forward snapshot");

        // Drop every publisher so the subscriber loop's `recv()` returns `None` and the loop
        // completes — exactly `main`'s `drop(feed)` shutdown step.
        drop(feed);
        let commits = subscriber.await.expect("subscriber task joins cleanly");

        // ── The forward-only-seq drop held on BOTH legs of the production combined commit ───────
        // Only the two FORWARD seqs (5 then 8) committed; the duplicate (5) and stale (3) fan-outs
        // were dropped by the D72 forward-only discipline — never re-sourcing either leg backwards.
        assert_eq!(
            commits, 2,
            "only the two forward-seq snapshots (5, 8) committed through the production \
             SnapshotCommitSink; the duplicate (5) and out-of-order (3) host-local fan-outs were \
             dropped by the D72 forward-only commit (one monotonic policy version)",
        );

        // EVALUATOR leg: the running evaluator ends on the LAST FORWARD version `pol1/v8` — it was
        // NEVER re-sourced backwards to the duplicate's `pol1/v105` or the stale's `pol1/v103`.
        assert_eq!(
            gate.policy_version(),
            "pol1/v8",
            "the running evaluator re-sourced ONLY on the forward seqs (5 → 8); the duplicate \
             (pol1/v105) and stale (pol1/v103) fan-outs never re-sourced the evaluator backwards",
        );
        // The shared-handle clone observes the SAME live re-source (same inner `Arc`): the live
        // verdict's policy version is the forward `pol1/v8`, not a stale fan-out version.
        let after = live_policy.evaluate(&ctx("blocked.example."));
        assert!(
            !after.admits(),
            "blocked.example stays a hard deny under the live (forward) version",
        );
        assert!(
            !after.provenance().rule_id.is_empty()
                && !after.provenance().policy_layer.is_empty()
                && !after.provenance().policy_version.is_empty(),
            "§6.7: POL-3 provenance preserved on the live (forward) evaluator's verdict",
        );

        // BOUNDARY-ZONE leg ON THE WIRE: the gate authors every deny with the forward-seq pushed
        // suffix `denied.policy.final.example.` — the duplicate (`dup.example.`) and stale
        // (`stale.example.`) suffixes NEVER appear, on the live wire OR the gate's authored state.
        assert_eq!(
            wire_authored_mname(tcp_addr).await,
            "denied.policy.final.example.",
            "the wire MNAME re-sourced ONLY on the forward seqs (v5 → final); the duplicate \
             (dup.example.) and stale (stale.example.) fan-outs never re-sourced the suffix \
             backwards (admitter-LAST, single monotonic policy version, D72)",
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.final.example.",
            "the gate's live authored MNAME reflects the last forward snapshot, never a stale \
             fan-out",
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down after the subscriber drained");
    }

    /// A per-seq POL-1 *layer text* (NOT a composed document) whose `schema_version` encodes
    /// `seq` AND whose `dns.boundary_zone` encodes `seq` (so the authored-SOA MNAME suffix is the
    /// distinct, strictly-forward `v{seq}.example.`), hard-DENYING `blocked.example` at a severing
    /// rung. Parsed through `parse_layer` and handed to the REAL loader-path constructor
    /// [`BoundarySnapshot::with_policy_layer`] (which threads `seq` through
    /// `ds_policy_snapshot::PolicySnapshot::from_policy_layer_with_seq` and lifts the composed
    /// document + W2 clamp + boundary zone + `content_hash` off ONE committed policy version) —
    /// the production startup/reload lift, NOT the synthetic `with_policy(seq, …)` shortcut the
    /// §16 sibling and the wave-1 tests use.
    fn layer_text_for_seq(seq: u64) -> String {
        format!(
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
            \x20 boundary_zone: v{seq}.example.\n\
             blocklist:\n\
            \x20 - domain: blocked.example\n\
            \x20\x20\x20 reason: loader-path-forward-only-seq-harness\n\
            \x20\x20\x20 rung: kill+snapshot\n\
             baseline_pack:\n\
            \x20 pack_version: \"2026.06.12-v0\"\n\
            \x20 families:\n\
            \x20\x20 core: {{ tier: enabled }}\n\
            \x20 entries: []\n"
        )
    }

    /// Build the production loader-path committed snapshot for `seq` (the REAL lift, not the
    /// `with_policy` shortcut): parse the per-seq layer, then drive
    /// [`BoundarySnapshot::with_policy_layer`] exactly as `server::run_policy_publisher` does.
    fn loader_snapshot_for_seq(seq: u64) -> BoundarySnapshot {
        let layer = parse_layer(&layer_text_for_seq(seq)).expect("the per-seq POL-1 layer parses");
        BoundarySnapshot::with_policy_layer(seq, &layer)
    }

    /// (1) The D72 forward-only-seq drop re-asserted over the REAL HOST-APPLIED LOADER PATH.
    ///
    /// §16 above (and the wave-1 §13 tests) publish via `BoundarySnapshot::with_policy(seq, …)`
    /// with HAND-AUTHORED seqs and an in-memory composed document — leaving the `(seq,
    /// content_hash)` identity synthetic. This DRIVES the identical forward-only-seq drop through
    /// the PRODUCTION lift [`BoundarySnapshot::with_policy_layer`] (which threads `seq` through
    /// `from_policy_layer_with_seq` and lifts the document + clamp + boundary zone + content_hash
    /// off ONE committed policy version, doc 13 §5), so the drop is proven on the SAME loader path
    /// `main`/`run_policy_publisher` runs, not a shortcut.
    ///
    ///   * A FORWARD loader-sourced snapshot (seq 5, `pol1/v5`, suffix `v5.example.`) commits:
    ///     the live evaluator re-sources to `pol1/v5` AND the wire MNAME to
    ///     `denied.policy.v5.example.` — each value coming off the REAL `with_policy_layer` lift.
    ///   * A DUPLICATE seq (5, `pol1/v105`, suffix `v105.example.`) and an OUT-OF-ORDER seq (3,
    ///     `pol1/v103`, suffix `v103.example.`), EACH loader-sourced, are DROPPED by the D72
    ///     forward-only commit: neither re-sources the evaluator NOR the boundary zone backwards.
    ///   * A strictly-FORWARD loader-sourced seq (8, `pol1/v8`, suffix `v8.example.`) commits once
    ///     more, re-sourcing BOTH legs admitter-LAST — only a strictly-forward seq advances.
    ///   * The subscriber's commit count is EXACTLY the forward count (2: seq 5 then seq 8), and
    ///     each committed snapshot's `(seq, content_hash)` self-identity came off the loader lift
    ///     (the snapshot carries the threaded seq + a non-default content_hash), never the synthetic
    ///     `with_policy` 0-default — closing gap (1): the drop is re-asserted over loader-sourced seqs.
    #[tokio::test]
    async fn loader_path_committed_snapshots_drop_non_advancing_seqs_on_the_wire() {
        // Sanity: the loader lift genuinely threads the seq + a real content_hash (NOT the
        // synthetic `with_policy` defaults), so this test exercises gap (1)'s loader-sourced
        // identity rather than a hand-authored one.
        let probe = loader_snapshot_for_seq(5);
        assert_eq!(
            probe.seq, 5,
            "with_policy_layer threads the supplied seq onto the snapshot"
        );
        assert_eq!(
            probe.content_hash(),
            Some(
                ds_policy_snapshot::PolicySnapshot::from_policy_layer_with_seq(
                    &parse_layer(&layer_text_for_seq(5)).unwrap(),
                    5,
                )
                .committed_policy()
                .expect("a layer-sourced snapshot carries a committed policy")
                .content_hash()
            ),
            "the loader-path snapshot's content_hash is lifted off the SAME committed policy \
             `from_policy_layer_with_seq` carries — the REAL loader identity, not the with_policy 0-default",
        );

        // The running gate starts on `pol1/v5` (hard-denies `blocked.example`), with a known
        // startup boundary zone threaded through config (the live host-snapshot value).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed_for_seq(5));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        let tcp_addr = gate.tcp_local_addr();

        assert_eq!(gate.policy_version(), "pol1/v5");
        assert_eq!(
            wire_authored_mname(tcp_addr).await,
            "denied.policy.startup.example.",
            "the startup deny signs with the live config suffix before any reload",
        );

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader());
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // ── 1. FORWARD loader-sourced seq 5 commits BOTH legs admitter-LAST ──────────────────
        feed.publish(loader_snapshot_for_seq(5))
            .await
            .expect("subscriber alive for the first loader-sourced snapshot");

        // ── 2. DUPLICATE seq 5 + OUT-OF-ORDER seq 3, each loader-sourced: both DROPPED ───────
        //       Each carries a DISTINCT loader-lifted policy version AND boundary zone, so a
        //       failed drop would surface on EITHER leg (wire MNAME or evaluator version flip).
        feed.publish(loader_snapshot_for_seq_with_version(5, 105))
            .await
            .expect("subscriber alive for the duplicate loader fan-out");
        feed.publish(loader_snapshot_for_seq_with_version(3, 103))
            .await
            .expect("subscriber alive for the out-of-order loader fan-out");

        // ── 3. strictly-FORWARD loader-sourced seq 8: committed admitter-LAST once more ──────
        feed.publish(loader_snapshot_for_seq(8))
            .await
            .expect("subscriber alive for the forward loader snapshot");

        drop(feed);
        let commits = subscriber.await.expect("subscriber task joins cleanly");

        // Only the two FORWARD loader-sourced seqs (5, 8) committed; the duplicate (5) and
        // out-of-order (3) loader fan-outs were dropped by the D72 forward-only discipline.
        assert_eq!(
            commits, 2,
            "only the two forward loader-sourced seqs (5, 8) committed through the production \
             SnapshotCommitSink; the duplicate (5) and out-of-order (3) loader fan-outs were \
             dropped by the D72 forward-only commit (one monotonic policy version)",
        );

        // EVALUATOR leg: ends on the last FORWARD loader version `pol1/v8`, never re-sourced
        // backwards to the duplicate's `pol1/v105` or the stale's `pol1/v103`.
        assert_eq!(
            gate.policy_version(),
            "pol1/v8",
            "the running evaluator re-sourced ONLY on the forward loader seqs (5 → 8); the \
             duplicate (pol1/v105) and stale (pol1/v103) loader fan-outs never re-sourced it backwards",
        );
        let after = live_policy.evaluate(&ctx("blocked.example."));
        assert!(
            !after.admits(),
            "blocked.example stays a hard deny under the live (forward) loader version",
        );
        assert!(
            !after.provenance().rule_id.is_empty()
                && !after.provenance().policy_layer.is_empty()
                && !after.provenance().policy_version.is_empty(),
            "§6.7: POL-3 provenance preserved on the live (forward) loader evaluator's verdict",
        );

        // BOUNDARY-ZONE leg ON THE WIRE: the gate authors every deny with the forward loader
        // suffix `denied.policy.v8.example.` — the duplicate (`v105.example.`) and stale
        // (`v103.example.`) loader suffixes NEVER appear on the live wire or the authored state.
        assert_eq!(
            wire_authored_mname(tcp_addr).await,
            "denied.policy.v8.example.",
            "the wire MNAME re-sourced ONLY on the forward loader seqs (v5 → v8); the duplicate \
             (v105.example.) and stale (v103.example.) loader fan-outs never re-sourced the suffix \
             backwards (admitter-LAST, single monotonic policy version, D72)",
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.v8.example.",
            "the gate's live authored MNAME reflects the last forward loader snapshot, never a \
             stale loader fan-out",
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down after the subscriber drained");
    }

    /// Build a loader-path committed snapshot whose `seq` and whose `schema_version` /
    /// `boundary_zone` *version label* differ — so a DUPLICATE / OUT-OF-ORDER fan-out can carry a
    /// DISTINCT loader-lifted policy version (`pol1/v{version}`, suffix `v{version}.example.`) at a
    /// non-advancing `seq`. If the D72 drop failed, that distinct version would flip the live
    /// evaluator or the wire MNAME — exactly what the test above asserts it never does.
    fn loader_snapshot_for_seq_with_version(seq: u64, version: u64) -> BoundarySnapshot {
        let layer =
            parse_layer(&layer_text_for_seq(version)).expect("the per-version POL-1 layer parses");
        BoundarySnapshot::with_policy_layer(seq, &layer)
    }

    /// (2-twin) The vSTALE evaluator/MNAME drop twin (D72 forward-only): the
    /// `production_wire_forward_only_drop` evaluator+MNAME assertion, named to MIRROR the
    /// policy_verdict.rs `vSTALE` EDE-15 wire twins. It pins that a DUPLICATE and an
    /// OUT-OF-ORDER fan-out — EACH carrying the DISTINCT `vSTALE` policy version (and a `vSTALE`
    /// MNAME suffix) — are dropped by `watch_snapshots`' forward-only commit, so the running
    /// evaluator's `policy_version` AND the authored-SOA MNAME both stay FORWARD (`v1`), never the
    /// stale fan-out's `vSTALE`. This is the event-surface (evaluator+MNAME) AXIS of the same
    /// guarantee policy_verdict.rs asserts on the EDE-15 wire AXIS — both axes, one invariant.
    #[tokio::test]
    async fn vstale_duplicate_and_out_of_order_fan_out_keeps_evaluator_and_mname_forward() {
        use ds_dnsgate::policy::TtlClamp;

        // Two composed documents that BOTH hard-deny `blocked.example` but carry DISTINCT version
        // labels + MNAME suffixes: the FORWARD `pol1/v1` and the stale-fan-out `pol1/vSTALE`.
        let forward = BoundarySnapshot::with_policy(
            50,
            "v1.example.",
            composed_for_label("1"),
            TtlClamp {
                floor: 60,
                ceil: 900,
            },
        );

        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed_for_label("1"));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        let tcp_addr = gate.tcp_local_addr();
        let gate = Arc::new(gate);

        let (feed, subscription) = boundary_snapshot_feed(8);
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader());
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // FORWARD seq 50 → v1 commits both legs.
        feed.publish(forward)
            .await
            .expect("subscriber alive for the forward fan-out");
        // DUPLICATE seq 50 → vSTALE: dropped — must NEVER become live on either leg.
        feed.publish(BoundarySnapshot::with_policy(
            50,
            "vSTALE.example.",
            composed_for_label("STALE"),
            TtlClamp {
                floor: 60,
                ceil: 900,
            },
        ))
        .await
        .expect("subscriber alive for the duplicate vSTALE fan-out");
        // OUT-OF-ORDER seq 40 (< committed 50) → vSTALE: dropped likewise.
        feed.publish(BoundarySnapshot::with_policy(
            40,
            "vSTALE.example.",
            composed_for_label("STALE"),
            TtlClamp {
                floor: 60,
                ceil: 900,
            },
        ))
        .await
        .expect("subscriber alive for the out-of-order vSTALE fan-out");

        drop(feed);
        let commits = subscriber.await.expect("subscriber task joins cleanly");

        assert_eq!(
            commits, 1,
            "only the single FORWARD seq committed; the duplicate (50) and out-of-order (40) \
             vSTALE fan-outs were dropped by the D72 forward-only commit",
        );
        // EVALUATOR axis: stays on the FORWARD v1, never re-sourced backwards to vSTALE.
        assert_eq!(
            gate.policy_version(),
            "pol1/v1",
            "the running evaluator stays at the FORWARD pol1/v1 — the pol1/vSTALE fan-outs never \
             re-sourced it backwards",
        );
        assert!(
            !live_policy.evaluate(&ctx("blocked.example.")).admits(),
            "blocked.example stays a hard deny under the live (forward) version",
        );
        // MNAME axis ON THE WIRE: stays on the FORWARD v1 suffix, never the vSTALE suffix.
        assert_eq!(
            wire_authored_mname(tcp_addr).await,
            "denied.policy.v1.example.",
            "the wire MNAME stays the FORWARD v1 suffix — the vSTALE fan-outs never re-sourced it",
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.v1.example.",
            "the gate's live authored MNAME reflects the forward snapshot, never the vSTALE fan-out",
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down after the subscriber drained");
    }

    /// A composed POL-1 document whose `schema_version` (→ `policy_version`) carries a free-form
    /// `label`, hard-DENYING `blocked.example` — the evaluator/MNAME-axis twin of
    /// `composed_for_seq`, parameterized on a string label so `v1` and `vSTALE` are distinct
    /// versions. `parse_layer` lifts `schema_version: pol1/v{label}` verbatim into `policy_version`.
    fn composed_for_label(label: &str) -> ComposedPolicy {
        let layer_yaml = format!(
            "schema_version: pol1/v{label}\n\
             layer: system-baseline\n\
             posture: standard\n\
             admission:\n\
            \x20 ttl_floor: 60\n\
            \x20 ttl_ceil: 900\n\
            \x20 grace: 60\n\
            \x20 max_ips_per_domain: 1000\n\
             dns:\n\
            \x20 negative_ttl: 5\n\
             blocklist:\n\
            \x20 - domain: blocked.example\n\
            \x20\x20\x20 reason: vstale-twin-harness\n\
            \x20\x20\x20 rung: kill+snapshot\n\
             baseline_pack:\n\
            \x20 pack_version: \"2026.06.12-v0\"\n\
            \x20 families:\n\
            \x20\x20 core: {{ tier: enabled }}\n\
            \x20 entries: []\n"
        );
        let layer = parse_layer(&layer_yaml).expect("the per-label POL-1 layer parses");
        compose(&[layer], &[])
    }
}

// ===========================================================================
// 17. The D72 forward-only-seq drop under a publisher BURST that BACK-PRESSURES the
//     bounded production feed WITH INTERLEAVED stale/duplicate seqs mixed into the
//     forward stream (doc 11 §1 bounded-mpsc / §5.3 admitter-LAST / D72 forward-only).
//
//     §15 `production_snapshot_backpressure` drives a STRICTLY-MONOTONIC burst through
//     the production `watch_snapshots` / `SnapshotCommitSink` (every snapshot commits,
//     so it proves back-pressure + ordering but NOT the complementary D72 guarantee).
//     §16 above drives the duplicate/out-of-order drop on the production wire but WITHOUT
//     back-pressure (a capacity-8 feed, 4 publishes — `publish()` never blocks). This
//     module DRIVES THE TWO TOGETHER: an over-capacity burst that ALSO carries
//     non-advancing seqs (duplicate / out-of-order host-local fan-out) interleaved into
//     the forward stream. The bounded feed must:
//
//       * BACK-PRESSURE on the FORWARD (and the interleaved stale) snapshots once full:
//         a further `publish().await` BLOCKS until the SnapshotCommitSink drains a slot —
//         it neither silently drops the snapshot off the channel nor grows the buffer past
//         the capacity. Observed by spawning the burst publisher on its own task, waiting
//         until it has WEDGED on `send().await` (its completed-publish counter stops short
//         of the burst length and stays there across a settle window), then releasing the
//         subscriber and watching every remaining `publish()` complete.
//       * DROP EXACTLY the stale ones (seq ≤ last committed, per `watch_snapshots`) at the
//         COMMIT stage while STILL committing every forward one: the forward-only drop
//         (D72) survives the burst. No stale snapshot ever wins (its evaluator version /
//         boundary zone never commits) and no forward snapshot is lost.
//       * PRESERVE admitter-LAST ordering THROUGH the burst: the committed evaluator-version
//         and boundary-zone sequences each equal the FORWARD sub-sequence's publish order
//         exactly, the live evaluator ends on the LAST forward version, and BOTH legs
//         re-sourced for every forward commit (evaluator FIRST, boundary-zone LAST).
//
//     Synthetic + host-local only (§5.3): NO control-plane stream, NO live host agent, NO
//     network, NO bound gate — the test drives the bare `boundary_snapshot_feed` +
//     `watch_snapshots` seam against the PRODUCTION `SnapshotCommitSink` over synthetic
//     recording evaluator / boundary-zone sinks it controls (the SAME public
//     `PolicyEvaluatorSink` / `BoundaryZoneSink` traits the production reloaders satisfy),
//     gating the subscriber's first commit on a barrier so the production feed provably
//     fills. POL-3 provenance + the frozen D72 forward-only seq survive the burst.
// ===========================================================================

mod interleaved_burst_forward_only_drop {
    //! A self-contained module: it owns its imports without disturbing the shared
    //! top-level `use` block (mirroring the sibling back-pressure modules).

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use ds_contracts::pol1::parse_layer;
    use ds_dnsgate::policy::{PolicyCorePolicy, TtlClamp};
    use ds_dnsgate::server::{
        boundary_snapshot_feed, watch_snapshots, BoundarySnapshot, BoundaryZoneSink,
        PolicyEvaluatorSink, SnapshotCommitSink,
    };
    use policy_core::pol1_eval::{compose, ComposedPolicy};

    /// A POL-1 layer whose `schema_version` (and therefore composed `policy_version`) encodes
    /// `tag` — so each published snapshot carries a DISTINCT evaluator version the recording
    /// `PolicyEvaluatorSink` can confirm advanced (for forward seqs) or NEVER appeared (for the
    /// interleaved stale/duplicate fan-outs, which must be dropped at the commit stage). `tag`
    /// is the snapshot's identity, distinct from its `seq`: a stale fan-out carries a NON-advancing
    /// seq but a UNIQUE tag, so a regression that committed it would surface its tag on the
    /// recorders.
    fn composed_for_tag(tag: u64) -> ComposedPolicy {
        let layer_yaml = format!(
            "schema_version: pol1/v{tag}\n\
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
        let layer = parse_layer(&layer_yaml).expect("the per-tag POL-1 layer parses");
        compose(&[layer], &[])
    }

    /// A recording `PolicyEvaluatorSink` (the public trait the production `GatePolicyReloader`
    /// satisfies) that applies every committed policy version to a LIVE `PolicyCorePolicy`
    /// (`reload`) and records the version it now decides against, in commit order — so the test
    /// confirms the evaluator re-sourced EXACTLY the forward sub-sequence's versions and NEVER a
    /// stale/duplicate fan-out's version. It is the FIRST leg of `SnapshotCommitSink`, so when the
    /// boundary-zone leg parks the evaluator has already committed.
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

        fn versions(&self) -> Vec<String> {
            self.versions.lock().expect("versions mutex").clone()
        }
    }

    impl PolicyEvaluatorSink for RecordingEvaluatorSink {
        fn commit_policy(&self, composed: &ComposedPolicy, ttl_clamp: TtlClamp) {
            self.live.reload(composed.clone(), ttl_clamp);
            self.versions
                .lock()
                .expect("versions mutex")
                .push(self.live.current_policy_version());
        }
    }

    /// A recording `BoundaryZoneSink` that records every committed boundary zone in commit order
    /// AND gates the FIRST commit on a one-shot release barrier so the subscriber wedges
    /// mid-combined-commit and the bounded production feed provably fills behind it (drives
    /// back-pressure). The first call parks on a `std::sync::mpsc::Receiver::recv()` until the test
    /// sends the release token; the subscriber runs on its own worker (multi-thread runtime) so
    /// this blocks only that worker, never the burst publisher.
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

        fn committed(&self) -> Vec<String> {
            self.committed.lock().expect("committed mutex").clone()
        }

        fn commits_started(&self) -> usize {
            self.commits_started.load(Ordering::SeqCst)
        }
    }

    impl BoundaryZoneSink for GatedRecordingZoneSink {
        fn commit_boundary_zone(&self, boundary_zone: &str) {
            let nth = self.commits_started.fetch_add(1, Ordering::SeqCst);
            if nth == 0 {
                if let Some(rx) = self.release.lock().expect("release mutex").take() {
                    let _ = rx.recv();
                }
            }
            self.committed
                .lock()
                .expect("committed mutex")
                .push(boundary_zone.to_string());
        }
    }

    /// A thin `Arc`-backed `BoundaryZoneSink` forwarder so the by-value `SnapshotCommitSink::new`
    /// can hold a SHARED-HANDLE to the recorder the test reads after the subscriber returns (the
    /// recorders are not `Clone` — they own `Mutex`/`AtomicUsize` state).
    struct ArcZoneSink(Arc<GatedRecordingZoneSink>);

    impl BoundaryZoneSink for ArcZoneSink {
        fn commit_boundary_zone(&self, boundary_zone: &str) {
            self.0.commit_boundary_zone(boundary_zone);
        }
    }

    /// A thin `Arc`-backed `PolicyEvaluatorSink` forwarder — the evaluator-leg twin of
    /// [`ArcZoneSink`].
    struct ArcEvaluatorSink(Arc<RecordingEvaluatorSink>);

    impl PolicyEvaluatorSink for ArcEvaluatorSink {
        fn commit_policy(&self, composed: &ComposedPolicy, ttl_clamp: TtlClamp) {
            self.0.commit_policy(composed, ttl_clamp);
        }
    }

    /// One scripted publish in the interleaved burst: its monotonic-or-not `seq`, its UNIQUE
    /// identity `tag` (the evaluator version + the boundary-zone suffix encode it), and whether
    /// the D72 forward-only commit MUST commit it (forward) or drop it (a non-advancing
    /// duplicate / out-of-order fan-out).
    struct Step {
        seq: u64,
        tag: u64,
        forward: bool,
    }

    /// An over-capacity burst of FORWARD seqs with DUPLICATE and OUT-OF-ORDER fan-outs INTERLEAVED
    /// into the stream, back-pressured on the bounded production feed while the subscriber is
    /// wedged. The forward-only drop (D72) survives the burst: ONLY the forward sub-sequence
    /// commits (in order, both legs), every interleaved stale/duplicate is dropped at the commit
    /// stage, no stale wins, no forward is lost, and admitter-LAST ordering holds end to end.
    ///
    /// Multi-thread runtime: the subscriber worker blocks (parked on the first boundary-zone
    /// commit gate) while the burst publisher runs concurrently on another worker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn interleaved_stale_seqs_in_an_over_capacity_burst_are_dropped_forward_only_survives() {
        // A SMALL bounded feed so the scripted burst exceeds it: every step (forward AND
        // interleaved-stale) rides the channel, so the back-pressure wall is hit regardless of
        // which steps will later be dropped at the COMMIT stage — the drop is a commit-stage
        // decision, not a channel-stage one.
        const CAPACITY: usize = 2;

        // The scripted interleaved burst. The FORWARD sub-sequence is the strictly-increasing
        // seqs 1,2,3,4,5,6,7,8 (tags 1..=8, suffixes z1..=z8). Mixed in are NON-advancing
        // fan-outs the D72 forward-only commit MUST drop:
        //   * a DUPLICATE of the just-committed seq (same seq, unique stale tag), and
        //   * an OUT-OF-ORDER (seq < last committed, unique stale tag).
        // Each stale step's tag (1xx) is unique, so a regression that committed one would surface
        // its `pol1/v1xx` version / `s1xx.example.` suffix on the recorders. Every step rides the
        // bounded feed (so they ALL count toward back-pressure); only the forward ones commit.
        let steps = [
            Step {
                seq: 1,
                tag: 1,
                forward: true,
            },
            Step {
                seq: 1,
                tag: 101,
                forward: false,
            }, // duplicate of seq 1 — dropped
            Step {
                seq: 2,
                tag: 2,
                forward: true,
            },
            Step {
                seq: 1,
                tag: 102,
                forward: false,
            }, // out-of-order (1 < 2) — dropped
            Step {
                seq: 3,
                tag: 3,
                forward: true,
            },
            Step {
                seq: 3,
                tag: 103,
                forward: false,
            }, // duplicate of seq 3 — dropped
            Step {
                seq: 4,
                tag: 4,
                forward: true,
            },
            Step {
                seq: 2,
                tag: 104,
                forward: false,
            }, // out-of-order (2 < 4) — dropped
            Step {
                seq: 5,
                tag: 5,
                forward: true,
            },
            Step {
                seq: 6,
                tag: 6,
                forward: true,
            },
            Step {
                seq: 6,
                tag: 106,
                forward: false,
            }, // duplicate of seq 6 — dropped
            Step {
                seq: 7,
                tag: 7,
                forward: true,
            },
            Step {
                seq: 4,
                tag: 107,
                forward: false,
            }, // out-of-order (4 < 7) — dropped
            Step {
                seq: 8,
                tag: 8,
                forward: true,
            },
        ];
        let burst_len = steps.len();
        let forward_count = steps.iter().filter(|s| s.forward).count();
        // The forward sub-sequence's identities, in publish order — what BOTH recorders must hold
        // after the drain (the stale fan-outs never appear).
        let expected_versions: Vec<String> = steps
            .iter()
            .filter(|s| s.forward)
            .map(|s| format!("pol1/v{}", s.tag))
            .collect();
        let expected_zones: Vec<String> = steps
            .iter()
            .filter(|s| s.forward)
            .map(|s| format!("z{}.example.", s.tag))
            .collect();
        let last_forward_tag = steps
            .iter()
            .filter(|s| s.forward)
            .map(|s| s.tag)
            .next_back()
            .expect("there is at least one forward step");

        // The LIVE evaluator the production combined commit re-sources. It starts on a baseline
        // version distinct from every published version (pol1/v0 ≠ any tag), so the FIRST forward
        // commit provably advances it.
        let live = PolicyCorePolicy::new(composed_for_tag(0));
        assert_eq!(
            live.current_policy_version(),
            "pol1/v0",
            "the evaluator starts on the baseline version before any committed snapshot",
        );

        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let evaluator_sink = Arc::new(RecordingEvaluatorSink::new(live.clone()));
        let zone_sink = Arc::new(GatedRecordingZoneSink::new(release_rx));
        let (feed, subscription) = boundary_snapshot_feed(CAPACITY);

        // Spawn the subscriber on the PRODUCTION `watch_snapshots` loop driven by the
        // `SnapshotCommitSink` (evaluator re-source FIRST, boundary-zone re-source LAST): it pulls
        // snapshot #1, re-sources the evaluator, enters the FIRST boundary-zone commit, and parks
        // on the release gate — so it stops draining and the bounded production feed fills behind it.
        let sub_evaluator = evaluator_sink.clone();
        let sub_zone = zone_sink.clone();
        let subscriber = tokio::spawn(async move {
            let commit_sink = SnapshotCommitSink::new(
                ArcZoneSink(sub_zone.clone()),
                ArcEvaluatorSink(sub_evaluator.clone()),
            );
            watch_snapshots(subscription, &commit_sink).await
        });

        // The burst publisher: publish every scripted step (forward + interleaved stale) onto the
        // bounded feed in order. `completed` counts how many `publish().await` calls RETURNED — the
        // probe that lets the test observe the publisher WEDGING on the bounded feed once it is full.
        let completed = Arc::new(AtomicUsize::new(0));
        let pub_completed = completed.clone();
        let publisher = tokio::spawn(async move {
            for s in steps {
                feed.publish(BoundarySnapshot::with_policy(
                    s.seq,
                    format!("z{}.example.", s.tag),
                    composed_for_tag(s.tag),
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

        // ── Prove BACK-PRESSURE: the publisher WEDGES on the bounded production feed ────────────
        // Wait until the subscriber has entered its (gated) first boundary-zone commit — by which
        // point it has ALREADY re-sourced the evaluator for snapshot #1; it is now parked, no
        // longer draining, so the feed fills to CAPACITY and the publisher blocks.
        await_until(Duration::from_secs(5), || zone_sink.commits_started() >= 1).await;
        assert!(
            !evaluator_sink.versions().is_empty(),
            "the evaluator re-source (FIRST leg) ran before the boundary-zone commit wedged",
        );

        // The publisher cannot have completed the whole burst: the bounded feed holds far fewer
        // than `burst_len`, so the surplus `publish()` calls are blocked on `send().await`. Every
        // step (forward AND interleaved-stale) rides the channel, so they ALL count toward the
        // wall — the drop is a COMMIT-stage decision, not a channel-stage one.
        let wedged = completed.load(Ordering::SeqCst);
        assert!(
            wedged < burst_len,
            "a bounded production feed must NOT let the publisher complete the whole interleaved \
             burst while the SnapshotCommitSink is wedged (got {wedged} of {burst_len} — the \
             channel buffered unboundedly or dropped off the channel, violating the doc 11 §1 \
             bounded-mpsc back-pressure invariant)"
        );
        // The wedge is STABLE: across a settle window with the subscriber still parked, the
        // publisher makes NO further progress — it is genuinely back-pressured, not mid-flight.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            completed.load(Ordering::SeqCst),
            wedged,
            "the back-pressured publisher made NO progress while the SnapshotCommitSink stayed \
             wedged — the bounded production feed blocks `publish()`, it does not drop off the \
             channel or unboundedly buffer (the interleaved stale seqs are dropped at COMMIT, not \
             silently off the channel)"
        );
        assert!(
            !subscriber.is_finished(),
            "the subscriber is still draining the burst (parked on the first boundary-zone commit \
             gate), not yet returned"
        );

        // ── Release the subscriber: it drains the rest, unblocking the back-pressured publish ──
        release_tx
            .send(())
            .expect("subscriber parked on the release gate");

        let publisher_result = tokio::time::timeout(Duration::from_secs(10), publisher).await;
        publisher_result
            .expect("the back-pressured publisher completes once the SnapshotCommitSink drains")
            .expect("publisher task joins cleanly");

        // EVERY publish completed — the bounded feed back-pressured the FAST publisher but NEVER
        // dropped a snapshot OFF THE CHANNEL: all `burst_len` `publish()` calls returned Ok. (The
        // stale/duplicate seqs are dropped at the COMMIT stage, not lost on the channel — a
        // back-pressured publisher is never silently shed.)
        assert_eq!(
            completed.load(Ordering::SeqCst),
            burst_len,
            "every burst publish (forward AND interleaved-stale) completed once back-pressure \
             released — none was dropped off the channel",
        );

        // ── Drain to completion: the subscriber commits ONLY the forward sub-sequence, in order ──
        let commits = tokio::time::timeout(Duration::from_secs(10), subscriber)
            .await
            .expect("the subscriber returns after the dropped feed closes the channel")
            .expect("subscriber task joins cleanly");

        // FORWARD-ONLY-SEQ DROP SURVIVED THE BURST (D72): exactly the forward sub-sequence
        // committed — every interleaved duplicate / out-of-order fan-out was dropped by the
        // forward-only commit, even under back-pressure. No stale won; no forward was lost.
        assert_eq!(
            commits, forward_count as u64,
            "exactly the forward sub-sequence committed through the production SnapshotCommitSink \
             under back-pressure; the interleaved duplicate / out-of-order fan-outs were dropped \
             by the D72 forward-only commit (one monotonic policy version, even under the burst)",
        );

        // ADMITTER-LAST ORDERING SURVIVED THE BURST: BOTH legs re-sourced for EVERY forward commit,
        // in the FORWARD sub-sequence's publish order — and NEVER a stale fan-out's tag (no stale
        // version / suffix ever appears on either recorder). The bounded feed back-pressured the
        // FAST publisher WITHOUT reordering, losing a forward snapshot, or letting a stale one win.
        assert_eq!(
            evaluator_sink.versions(),
            expected_versions,
            "the evaluator leg re-sourced EXACTLY the forward sub-sequence's versions, in order — \
             no interleaved stale/duplicate fan-out's version ever committed (D72 forward-only \
             under back-pressure)",
        );
        assert_eq!(
            zone_sink.committed(),
            expected_zones,
            "the boundary-zone leg committed EXACTLY the forward sub-sequence's suffixes, in order \
             — admitter-LAST ordering preserved through the back-pressure (doc 11 §5.3 / D72)",
        );

        // The LIVE evaluator ends on the LAST FORWARD version — admitter-LAST, one monotonic
        // policy version end to end: a stale fan-out NEVER re-sourced it backwards.
        assert_eq!(
            live.current_policy_version(),
            format!("pol1/v{last_forward_tag}"),
            "the running evaluator ends on the LAST forward version — no interleaved stale/duplicate \
             fan-out re-sourced it backwards (admitter-LAST, D72)",
        );

        // Counts agree across the legs and the loop: one commit per forward step, no leg lagging.
        assert_eq!(
            zone_sink.committed().len(),
            forward_count,
            "the boundary-zone leg committed exactly the forward count",
        );
        assert_eq!(
            evaluator_sink.versions().len(),
            forward_count,
            "the evaluator leg committed exactly the forward count — both legs ran on every \
             forward commit, none on a dropped fan-out",
        );
    }

    /// Poll `cond` until it is true or the deadline elapses; panics on timeout. A bounded wait
    /// (no fixed sleep) for the subscriber to reach a state the test observes — the sibling
    /// back-pressure modules' twin, owned here so this module is self-contained.
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
// 13. The D72 forward-only-seq DROP is OPERATIONALLY OBSERVABLE (doc 11 §5.3 / D72).
//
//     The subscriber drops a duplicate / out-of-order host-local fan-out (seq ≤ the last
//     committed seq) to keep ONE monotonic policy version — the drop BEHAVIOR is FROZEN by
//     the wave-1 burst test above (KEEP-GREEN). What this module adds is the OBSERVABILITY
//     leg: that benign dedup drop is no longer a SILENT `continue` — `watch_snapshots` emits a
//     DISTINCT stale-fan-out telemetry signal through the existing `SnapshotSink` seam
//     (`observe_snapshot_drop`), carrying the dropped seq, the live committed seq, and a
//     `SnapshotDropReason::StaleFanOut` reason.
//
//     Proven here (synthetic + host-local only, §5.3 — NO control-plane stream, NO live host
//     agent, NO network, NO bound gate; the bare `boundary_snapshot_feed` + `watch_snapshots`
//     seam against a recording `SnapshotSink` the test controls):
//       * A DUPLICATE and an OUT-OF-ORDER fan-out EACH surface exactly one stale-drop signal,
//         with the right dropped/committed seq identity and the StaleFanOut reason (count +
//         reason).
//       * A FORWARD commit emits NO stale-drop signal — the signal fires ONLY on the drop, so
//         a healthy commit stays distinguishable from a dedup drop.
//       * The stale-drop signal is DISTINCT from a content_hash NACK (D120): its reason is a
//         DIFFERENT `SnapshotDropReason` variant, and its convention-layer envelope encodes a
//         `PolicyDecision` whose payload leads with the `stale_fan_out` token — never the
//         `content_hash_mismatch` token. POL-3 provenance rides every drop (§6.7).
// ===========================================================================

mod forward_only_drop_is_observable {
    //! A self-contained module: it owns its imports without disturbing the shared top-level
    //! `use` block (mirroring the sibling forward-only-drop module).

    use std::sync::Mutex;
    use std::time::Duration;

    use ds_dnsgate::event::{
        CapturingDropSink, EventKind, SnapshotDropEvent, SnapshotDropReason, SnapshotDropSink,
    };
    use ds_dnsgate::server::{
        boundary_snapshot_feed, watch_snapshots, BoundarySnapshot, SnapshotSink,
    };

    /// A recording `SnapshotSink` that captures every COMMIT (by seq, in order) AND routes
    /// every reload-boundary DROP to a shared `CapturingDropSink` — so the test reads BOTH the
    /// committed forward sub-sequence AND the distinct stale-fan-out drop signals back after the
    /// subscriber returns. The drop leg overrides the `SnapshotSink::observe_snapshot_drop`
    /// default no-op (the production `SnapshotCommitSink` keeps the no-op; this recorder is the
    /// observability seam the new signal threads through).
    struct RecordingSnapshotSink {
        committed_seqs: Mutex<Vec<u64>>,
        drops: CapturingDropSink,
    }

    impl RecordingSnapshotSink {
        fn new() -> Self {
            Self {
                committed_seqs: Mutex::new(Vec::new()),
                drops: CapturingDropSink::new(),
            }
        }

        fn committed_seqs(&self) -> Vec<u64> {
            self.committed_seqs.lock().expect("committed mutex").clone()
        }

        fn drops(&self) -> Vec<SnapshotDropEvent> {
            self.drops.drops()
        }
    }

    impl SnapshotSink for RecordingSnapshotSink {
        fn commit_snapshot(&self, snapshot: &BoundarySnapshot) {
            self.committed_seqs
                .lock()
                .expect("committed mutex")
                .push(snapshot.seq);
        }

        fn observe_snapshot_drop(&self, drop: SnapshotDropEvent) {
            self.drops.observe_drop(drop);
        }
    }

    #[tokio::test]
    async fn duplicate_and_out_of_order_fan_outs_emit_the_distinct_stale_drop_signal() {
        // A scripted feed: forward commits 1,2,3, with a DUPLICATE of 3 and an OUT-OF-ORDER 2
        // interleaved — the two benign fan-outs the D72 forward-only commit drops.
        //   seq 1  forward  (commit)
        //   seq 2  forward  (commit)
        //   seq 3  forward  (commit)
        //   seq 3  DUPLICATE of the just-committed 3  -> dropped, stale-fan-out signal
        //   seq 2  OUT-OF-ORDER (2 < committed 3)     -> dropped, stale-fan-out signal
        let sink = RecordingSnapshotSink::new();
        let (feed, subscription) = boundary_snapshot_feed(16);

        // Publish, then drop the feed so the subscriber loop returns after drain. A small
        // capacity is fine here — this test is about the OBSERVABILITY of the drop, not
        // back-pressure (the frozen wave-1 burst test owns that).
        let publisher = tokio::spawn(async move {
            for seq in [1u64, 2, 3, 3, 2] {
                feed.publish(BoundarySnapshot::new(seq, "boundary."))
                    .await
                    .expect("subscriber alive for the whole feed");
            }
            drop(feed);
        });

        let commits =
            tokio::time::timeout(Duration::from_secs(5), watch_snapshots(subscription, &sink))
                .await
                .expect("the subscriber returns after the dropped feed closes the channel");

        publisher.await.expect("the publisher task joins cleanly");

        // Exactly the FORWARD sub-sequence committed (1,2,3) — drop behavior UNCHANGED.
        assert_eq!(
            commits, 3,
            "only the three forward seqs committed (the duplicate + out-of-order were dropped)"
        );
        assert_eq!(
            sink.committed_seqs(),
            vec![1, 2, 3],
            "exactly the forward sub-sequence committed, in order (one monotonic version, D72)"
        );

        // The drop is OBSERVABLE: exactly TWO stale-fan-out signals — one per dropped fan-out —
        // and NONE on the forward commits (the signal fires ONLY on the drop path).
        let drops = sink.drops();
        assert_eq!(
            drops.len(),
            2,
            "exactly the two dropped fan-outs (duplicate + out-of-order) surfaced a signal — a \
             forward commit emits NO stale-drop signal, so a healthy commit stays distinguishable"
        );
        assert_eq!(
            sink.drops
                .count_with_reason(SnapshotDropReason::StaleFanOut),
            2,
            "both drops carry the benign StaleFanOut reason (the D72 forward-only dedup)"
        );

        // The DUPLICATE of seq 3 (committed at 3): dropped_seq == committed_seq == 3.
        let dup = &drops[0];
        assert_eq!(dup.reason, SnapshotDropReason::StaleFanOut);
        assert!(dup.is_stale_fan_out());
        assert_eq!(dup.dropped_seq, 3);
        assert_eq!(
            dup.committed_seq, 3,
            "a duplicate is dropped at seq == committed"
        );

        // The OUT-OF-ORDER seq 2 (committed still at 3): dropped_seq 2 < committed_seq 3.
        let ooo = &drops[1];
        assert_eq!(ooo.reason, SnapshotDropReason::StaleFanOut);
        assert_eq!(ooo.dropped_seq, 2);
        assert_eq!(
            ooo.committed_seq, 3,
            "an out-of-order fan-out is dropped while the admitter stays on the last forward seq"
        );

        // POL-3 provenance rides every drop (§6.7, CI-fatal if missing).
        for d in &drops {
            assert!(
                !d.provenance.rule_id.is_empty()
                    && !d.provenance.policy_layer.is_empty()
                    && !d.provenance.policy_version.is_empty(),
                "every reload-boundary drop carries POL-3 provenance"
            );
        }

        // ── The signal is DISTINGUISHABLE from a content_hash NACK (D120) ──────────────────
        // 1) Structurally: the stale-fan-out reason is a DIFFERENT `SnapshotDropReason` variant
        //    from a hash-mismatch NACK — a consumer can match on it, never string-sniff.
        assert_ne!(
            SnapshotDropReason::StaleFanOut,
            SnapshotDropReason::ContentHashMismatch,
            "a benign stale-fan-out dedup is a DIFFERENT reason from a content_hash NACK"
        );
        assert!(drops.iter().all(|d| d.is_stale_fan_out()));
        assert_eq!(
            sink.drops
                .count_with_reason(SnapshotDropReason::ContentHashMismatch),
            0,
            "no content_hash NACK was raised on this benign-dedup path — they are distinct signals"
        );
        // 2) On the convention-layer carrier: the drop encodes a `PolicyDecision` envelope (a
        //    reload is a policy-version event — a DIFFERENT kind from a resolver DnsEvent), and
        //    its payload leads with the `stale_fan_out` token, NEVER the `content_hash_mismatch`
        //    token a hash-mismatch NACK would carry.
        let envelope = dup
            .to_envelope()
            .expect("a live reload-boundary POL-3 triple encodes");
        assert_eq!(envelope.kind(), EventKind::PolicyDecision);
        assert_ne!(envelope.kind(), EventKind::DnsEvent);
        let payload = String::from_utf8_lossy(envelope.payload());
        assert!(
            payload.contains("reason=stale_fan_out"),
            "the drop envelope carries the distinct stale-fan-out reason token (payload: {payload})"
        );
        assert!(
            !payload.contains("content_hash_mismatch"),
            "the benign dedup drop never carries the hash-mismatch token — the operator can tell \
             a stale fan-out apart from a content_hash NACK (D120)"
        );
    }

    #[tokio::test]
    async fn a_purely_forward_feed_emits_no_stale_drop_signal() {
        // A strictly-increasing feed: every seq advances, so NOTHING is dropped — the stale-drop
        // signal must stay silent. This is the negative control that proves the signal fires
        // ONLY on the forward-only drop, never on a healthy commit.
        let sink = RecordingSnapshotSink::new();
        let (feed, subscription) = boundary_snapshot_feed(16);

        let publisher = tokio::spawn(async move {
            for seq in [1u64, 2, 3, 4, 5] {
                feed.publish(BoundarySnapshot::new(seq, "boundary."))
                    .await
                    .expect("subscriber alive for the whole feed");
            }
            drop(feed);
        });

        let commits =
            tokio::time::timeout(Duration::from_secs(5), watch_snapshots(subscription, &sink))
                .await
                .expect("the subscriber returns after the dropped feed closes the channel");

        publisher.await.expect("the publisher task joins cleanly");

        assert_eq!(commits, 5, "every forward seq committed");
        assert_eq!(sink.committed_seqs(), vec![1, 2, 3, 4, 5]);
        assert!(
            sink.drops().is_empty(),
            "a purely-forward feed drops nothing — the stale-drop signal fires ONLY on the \
             forward-only drop, so a healthy commit is distinguishable from a dedup drop"
        );
    }
}
