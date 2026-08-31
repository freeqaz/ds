// SPDX-License-Identifier: Apache-2.0
//! `event_surface` split (D72/D120): the forward-only-seq drop re-asserted on the VERIFY-ONLY
//! (D120) LOADER PATH, plus the NACK-aborts-apply twin AND the SchemaFailure-aborts-apply twin
//! (the verify-only-PATH companion to the publisher-side
//! `publisher_schema_failure_is_a_distinct_reason_from_a_content_hash_mismatch`, server.rs).
//! Extracted from the oversized `tests/event_surface.rs` (test-only reorg, behavior-
//! preserving). `#[path]`-included into the `event_surface` binary; `crate::{query_bytes,
//! tcp_query}` resolve to its root helpers.

// ===========================================================================
// 18. The D72 forward-only-seq drop re-asserted on the VERIFY-ONLY (D120) LOADER
//     PATH, plus the NACK-aborts-apply twin (doc 11 §5.3 / §5.4 / §5.5 admitter-LAST
//     / D72 forward-only / D120 produce-once-verify-only; doc 13 §5.1).
//
//     §16 above re-asserts the forward-only-seq drop over the REAL host-applied
//     loader lift `BoundarySnapshot::with_policy_layer` — but that is the IN-MEMORY
//     loopback hand-off (`version.wire == None`, server.rs:2405), which carries NO
//     transported wire identity (`wire_content_hash == None`). It NEVER exercises the
//     PRODUCTION verify-only lift `BoundarySnapshot::with_verified_policy_layer`
//     (server.rs:2089) — the path that populates the VERIFIED 32-byte D120 wire
//     `content_hash` and is the path a stale fan-out carrying a transported wire
//     identity would actually leak through today. This module closes BOTH remaining
//     D72 verify-only surfaces, test-only, with no src change:
//
//       * VERIFY-ONLY DROP: a FORWARD verified snapshot (built off the verify-only
//         lift, carrying a populated `wire_content_hash`) commits BOTH legs; a
//         DUPLICATE and an OUT-OF-ORDER verified snapshot — each ALSO carrying a
//         populated (DISTINCT) wire identity and a DISTINCT evaluator version + MNAME
//         suffix — are DROPPED by `watch_snapshots`' forward-only commit (neither
//         re-sources the evaluator NOR the boundary zone backwards), and a final
//         strictly-FORWARD verified snapshot commits once more. The committed
//         snapshots self-identify on the §5 wire tuple (their `wire_content_hash` is
//         `Some`, NOT the `with_policy_layer` `None`), so this is the verify-only
//         identity, not the in-memory one. NON-VACUOUS: it asserts on DISTINCT
//         evaluator/MNAME VERSIONS (not a bare count), so it FAILS if the drop is
//         removed (a stale verified fan-out would flip the live version).
//       * NACK-ABORTS-APPLY: a version whose TRANSPORTED bytes do NOT hash to their
//         claimed wire `content_hash` fails the verify-only loader's hash-check
//         (`LoadVerdict::HashNack`, ds-policy-snapshot), so `run_policy_publisher`
//         ABORTS the apply (server.rs:2392 nack arm → `content_hash_nack_drop`,
//         server.rs:2431; never published, the host stays on vN). Driven through the
//         PRODUCTION publisher `run_policy_publisher_with_drop_sink` against a real
//         loopback gate + the production `SnapshotCommitSink`, the test asserts the
//         live evaluator AND the wire MNAME stay on the prior FORWARD version
//         (unchanged across the NACK), the publisher's published count excludes the
//         NACKed version, and the routed drop is the DISTINCT `content_hash_mismatch`
//         reason (`is_stale_fan_out() == false`) — NOT a benign stale fan-out (the
//         abort is a different non-commit reason from the D72 forward-only dedup,
//         exactly as `publisher_content_hash_nack_is_distinct_from_a_stale_fan_out`
//         establishes for the bare-publisher leg, here proven end to end ON THE WIRE).
//         NON-VACUOUS: it asserts the evaluator/MNAME stay the FORWARD version, so it
//         FAILS if the NACK ever applied the tampered version.
//
//     Synthetic + loopback only (§5.3): a real `spawn_gate`-bound gate on 127.0.0.1:0,
//     the host-LOCAL `boundary_snapshot_feed` / production publisher (NEVER a
//     control-plane stream), and verify-only snapshots whose transported bytes are
//     synthetic POL-1 layer text hashed through the SINGLE source of wire hashing
//     (`ds_contracts::snapshot_verify::sha256`). No live host agent, no policy stream,
//     no network beyond loopback.
// ===========================================================================

mod verify_only_and_nack_forward_only_drop {
    //! A self-contained module: it owns its imports without disturbing the shared
    //! top-level `use` block (mirroring the sibling production-wire modules).

    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use ds_contracts::pol1::{parse_layer, PolicyLayer};
    use ds_contracts::snapshot_verify::{sha256, ContentHash};
    use ds_dnsgate::event::{CapturingDropSink, SnapshotDropReason};
    use ds_dnsgate::policy::{DnsQueryCtx, PolicyCorePolicy, PolicyHook};
    use ds_dnsgate::server::{
        boundary_snapshot_feed, run_policy_publisher_with_drop_sink, watch_snapshots,
        BoundarySnapshot, CommittedPolicyVersion, GateConfig, PolicyVersionSource,
        SnapshotCommitSink,
    };
    use ds_dnsgate::spawn_gate;

    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::rdata::SOA as ProtoSoa;
    use hickory_proto::rr::{RData as ProtoRData, RecordType};

    use crate::{query_bytes, tcp_query};

    /// A per-version POL-1 layer *text* whose `schema_version` encodes `version` (so the composed
    /// `policy_version` is the distinct, forward `pol1/v{version}`) AND whose `dns.boundary_zone`
    /// encodes `version` (so the authored-SOA MNAME suffix is the distinct `v{version}.example.`),
    /// hard-DENYING `blocked.example` at a severing rung. These are the TRANSPORTED canonical bytes
    /// the verify-only loader hashes BEFORE parse — exactly the shape the produce-once Go host agent
    /// fans out (doc 13 §5.1). The label is a free-form scalar so `v8`, `v103`, `v105` are distinct.
    fn layer_text_for_version(version: u64) -> String {
        format!(
            "schema_version: pol1/v{version}\n\
             layer: system-baseline\n\
             posture: standard\n\
             admission:\n\
            \x20 ttl_floor: 60\n\
            \x20 ttl_ceil: 900\n\
            \x20 grace: 60\n\
            \x20 max_ips_per_domain: 1000\n\
             dns:\n\
            \x20 negative_ttl: 5\n\
            \x20 boundary_zone: v{version}.example.\n\
             blocklist:\n\
            \x20 - domain: blocked.example\n\
            \x20\x20\x20 reason: verify-only-forward-only-seq-harness\n\
            \x20\x20\x20 rung: kill+snapshot\n\
             baseline_pack:\n\
            \x20 pack_version: \"2026.06.12-v0\"\n\
            \x20 families:\n\
            \x20\x20 core: {{ tier: enabled }}\n\
            \x20 entries: []\n"
        )
    }

    /// Parse the per-version layer text (for the publisher's pre-parsed carrier view + the
    /// `with_verified_policy_layer` lift).
    fn layer_for_version(version: u64) -> PolicyLayer {
        parse_layer(&layer_text_for_version(version)).expect("the per-version POL-1 layer parses")
    }

    /// The composed evaluator the gate starts on for `version` — the SAME composed document the
    /// verify-only lift produces, so `gate.policy_version()` reports `pol1/v{version}` at startup.
    fn composed_for_version(version: u64) -> policy_core::pol1_eval::ComposedPolicy {
        policy_core::pol1_eval::compose(&[layer_for_version(version)], &[])
    }

    /// Build a VERIFY-ONLY committed snapshot for `(seq, version)` through the PRODUCTION verify-only
    /// lift [`BoundarySnapshot::with_verified_policy_layer`] (server.rs:2089) — the produce-once /
    /// D120 path that carries the VERIFIED wire `content_hash`. The transported canonical bytes are
    /// the per-version layer text; the wire hash is computed through the SINGLE source of wire
    /// hashing (`sha256`, the one the loader's NACK path checks). `seq` and `version` are
    /// independent: a stale/duplicate fan-out can carry a NON-advancing `seq` but a DISTINCT
    /// `version` (distinct evaluator version + boundary zone), so a failed forward-only drop would
    /// surface on EITHER leg.
    fn verified_snapshot(seq: u64, version: u64) -> BoundarySnapshot {
        let layer = layer_for_version(version);
        let transported = layer_text_for_version(version).into_bytes();
        let wire_content_hash: ContentHash = sha256(&transported);
        BoundarySnapshot::with_verified_policy_layer(seq, &layer, wire_content_hash)
    }

    fn ctx(qname: &str) -> DnsQueryCtx {
        DnsQueryCtx {
            session: "verify-only-forward-only-seq-harness".to_string(),
            qname: qname.to_string(),
            qtype: 1,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        }
    }

    fn soa_mname(msg: &Message) -> Option<String> {
        msg.authorities.iter().find_map(|r| match &r.data {
            ProtoRData::SOA(soa) => Some(soa_mname_ascii(soa)),
            _ => None,
        })
    }

    fn soa_mname_ascii(soa: &ProtoSoa) -> String {
        soa.mname.to_ascii()
    }

    /// The authored-SOA MNAME the running gate signs a deny with ON THE WIRE (TCP). Asserts the
    /// frozen deny shape (NXDOMAIN + authored SOA in authority) and returns the live MNAME.
    async fn wire_authored_mname(addr: SocketAddr) -> String {
        let query = query_bytes(0x7e02, "blocked.example.", RecordType::A);
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

    /// (1) The D72 forward-only-seq drop re-asserted over the VERIFY-ONLY (D120) LOADER PATH.
    ///
    /// §16's `loader_path_committed_snapshots_drop_non_advancing_seqs_on_the_wire` drives the drop
    /// over `BoundarySnapshot::with_policy_layer` — the IN-MEMORY loopback lift (`wire_content_hash
    /// == None`). This DRIVES the identical forward-only-seq drop through the PRODUCTION verify-only
    /// lift `BoundarySnapshot::with_verified_policy_layer` (server.rs:2089), so every committed
    /// snapshot carries the VERIFIED 32-byte D120 wire `content_hash` — the path that transports the
    /// §5 wire identity, where a stale fan-out leaking through today would go uncaught.
    ///
    ///   * Two strictly-FORWARD verified snapshots commit FIRST (seq 5 `pol1/v5`, then seq 8
    ///     `pol1/v8`): the live evaluator re-sources to `pol1/v8` AND the wire MNAME to
    ///     `denied.policy.v8.example.`.
    ///   * A DUPLICATE seq (8, `pol1/v105`, suffix `v105.example.`) and an OUT-OF-ORDER seq (3,
    ///     `pol1/v103`, suffix `v103.example.`) are then published LAST and DROPPED: neither
    ///     re-sources the evaluator NOR the boundary zone backwards. Publishing them AFTER the
    ///     highest forward commit makes the VERSION assertions themselves non-vacuous — were the
    ///     drop removed, the live evaluator/MNAME would flip to the LAST-committed stale `pol1/v103`,
    ///     not the forward `pol1/v8` (so the test FAILS on the version, not merely the count).
    ///   * The subscriber's commit count is EXACTLY the forward count (2: seq 5 then seq 8), and each
    ///     committed snapshot's identity is the VERIFY-ONLY one (`wire_content_hash` is `Some`, the
    ///     32 bytes `sha256` produced — NOT the `with_policy_layer` `None`), proving the drop is
    ///     re-asserted on the transported-wire-identity path, not only the in-memory one.
    #[tokio::test]
    async fn verify_only_committed_snapshots_drop_non_advancing_seqs_on_the_wire() {
        // Sanity: the verify-only lift genuinely populates the VERIFIED wire content_hash (the
        // produce-once §5 identity), distinct from the in-memory `with_policy_layer` `None` — so
        // this test exercises the verify-only path, not the in-memory one §16 already covers.
        let probe = verified_snapshot(5, 5);
        assert_eq!(probe.seq, 5, "with_verified_policy_layer threads the seq");
        assert_eq!(
            probe.wire_content_hash(),
            Some(sha256(&layer_text_for_version(5).into_bytes())),
            "the verify-only snapshot carries the VERIFIED 32-byte D120 wire content_hash \
             (sha256 over the transported bytes) on its identity — NOT the with_policy_layer None",
        );

        // The running gate starts on `pol1/v5` (hard-denies `blocked.example`), with a known startup
        // boundary zone threaded through config (the live host-snapshot value).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed_for_version(5));
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

        // ── 1. Two strictly-FORWARD verify-only seqs (5, then 8) commit BOTH legs admitter-LAST ──
        feed.publish(verified_snapshot(5, 5))
            .await
            .expect("subscriber alive for the first verify-only snapshot");
        feed.publish(verified_snapshot(8, 8))
            .await
            .expect("subscriber alive for the second forward verify-only snapshot");

        // ── 2. DUPLICATE seq 8 + OUT-OF-ORDER seq 3, each verify-only-sourced, published LAST: ──
        // ──    both DROPPED. Each carries a DISTINCT verified wire identity + policy version + ───
        // ──    boundary zone, so a failed drop would surface on EITHER leg (wire MNAME or ────────
        // ──    evaluator version flip). Publishing them AFTER the highest forward commit makes ───
        // ──    the VERSION assertions non-vacuous: the LAST-committed would be the stale v103. ───
        feed.publish(verified_snapshot(8, 105))
            .await
            .expect("subscriber alive for the duplicate verify-only fan-out");
        feed.publish(verified_snapshot(3, 103))
            .await
            .expect("subscriber alive for the out-of-order verify-only fan-out");

        drop(feed);
        let commits = subscriber.await.expect("subscriber task joins cleanly");

        // Only the two FORWARD verify-only seqs (5, 8) committed; the duplicate (8) and
        // out-of-order (3) verify-only fan-outs were dropped by the D72 forward-only discipline.
        assert_eq!(
            commits, 2,
            "only the two forward verify-only seqs (5, 8) committed through the production \
             SnapshotCommitSink; the duplicate (8) and out-of-order (3) verify-only fan-outs were \
             dropped by the D72 forward-only commit (one monotonic policy version)",
        );

        // EVALUATOR leg: ends on the last FORWARD verify-only version `pol1/v8`, never re-sourced
        // backwards to the duplicate's `pol1/v105` or the stale's `pol1/v103` (BOTH published LAST).
        assert_eq!(
            gate.policy_version(),
            "pol1/v8",
            "the running evaluator re-sourced ONLY on the forward verify-only seqs (5 → 8); the \
             duplicate (pol1/v105) and stale (pol1/v103) verify-only fan-outs never re-sourced it \
             backwards",
        );
        let after = live_policy.evaluate(&ctx("blocked.example."));
        assert!(
            !after.admits(),
            "blocked.example stays a hard deny under the live (forward) verify-only version",
        );
        assert!(
            !after.provenance().rule_id.is_empty()
                && !after.provenance().policy_layer.is_empty()
                && !after.provenance().policy_version.is_empty(),
            "§6.7: POL-3 provenance preserved on the live (forward) verify-only verdict",
        );

        // BOUNDARY-ZONE leg ON THE WIRE: the gate authors every deny with the forward verify-only
        // suffix `denied.policy.v8.example.` — the duplicate (`v105.example.`) and stale
        // (`v103.example.`) suffixes NEVER appear on the live wire or the authored state.
        assert_eq!(
            wire_authored_mname(tcp_addr).await,
            "denied.policy.v8.example.",
            "the wire MNAME re-sourced ONLY on the forward verify-only seqs (v5 → v8); the \
             duplicate (v105.example.) and stale (v103.example.) verify-only fan-outs never \
             re-sourced the suffix backwards (admitter-LAST, single monotonic policy version, D72)",
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.v8.example.",
            "the gate's live authored MNAME reflects the last forward verify-only snapshot, never \
             a stale verify-only fan-out",
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down after the subscriber drained");
    }

    /// A synthetic `PolicyVersionSource` (the host agent's `WatchPolicies(from_seq)` producer seam,
    /// §5.3 loopback/synthetic) delivering a scripted sequence of VERIFY-ONLY committed versions —
    /// each carrying its produce-once transported bytes + wire `content_hash` so the publisher takes
    /// the verify-only loader path (hash-check BEFORE parse, server.rs:2374). A version whose claimed
    /// wire hash does NOT match its transported bytes makes the loader NACK (HashNack), so the
    /// publisher ABORTS the apply for it.
    struct ScriptedVerifiedSource {
        versions: std::collections::VecDeque<CommittedPolicyVersion>,
    }

    impl ScriptedVerifiedSource {
        fn new(versions: Vec<CommittedPolicyVersion>) -> Self {
            Self {
                versions: versions.into(),
            }
        }
    }

    impl PolicyVersionSource for ScriptedVerifiedSource {
        async fn next_version(&mut self) -> Option<CommittedPolicyVersion> {
            self.versions.pop_front()
        }
    }

    /// Build a GOOD verify-only version for `(seq, version)`: the transported bytes are the per-
    /// version layer text and the claimed wire hash is their HONEST `sha256`, so the loader verifies
    /// and the publisher publishes it.
    fn good_verified_version(seq: u64, version: u64) -> CommittedPolicyVersion {
        let text = layer_text_for_version(version);
        let transported = text.clone().into_bytes();
        let content_hash: ContentHash = sha256(&transported);
        CommittedPolicyVersion::verified(seq, layer_for_version(version), transported, content_hash)
    }

    /// Build a TAMPERED verify-only version for `(seq, version)`: the transported bytes are MUTATED
    /// after the wire hash is computed over the UNMUTATED bytes, so the loader's hash-check FAILS
    /// (`LoadVerdict::HashNack`) and the publisher ABORTS the apply (never publishes it). The carried
    /// `layer` is the pre-parsed UNMUTATED view (irrelevant — the loader re-parses the transported
    /// bytes only AFTER verifying, which it never reaches).
    fn tampered_verified_version(seq: u64, version: u64) -> CommittedPolicyVersion {
        let mut transported = layer_text_for_version(version).into_bytes();
        let claimed_hash: ContentHash = sha256(&transported); // the UNMUTATED hash
        *transported.last_mut().expect("non-empty") ^= 0x20; // flip a transported byte AFTER hashing
        CommittedPolicyVersion::verified(seq, layer_for_version(version), transported, claimed_hash)
    }

    /// Build a VERIFIED-but-UNPARSEABLE verify-only version for `seq`: the transported bytes are
    /// arbitrary NON-POL-1 bytes whose claimed wire hash is their HONEST `sha256` — so the loader's
    /// D120 hash-check PASSES (`load_verified_snapshot` does NOT NACK on the hash), but the POL-1
    /// schema parse of the verified bytes FAILS, yielding a `LoadVerdict::ParseError`. The publisher
    /// ABORTS the apply for it exactly as a `HashNack` does (server.rs:2392 nack arm →
    /// `content_hash_nack_drop`), but the routed drop carries the DISTINCT
    /// `SnapshotDropReason::SchemaFailure` reason rather than `ContentHashMismatch` (server.rs:2442).
    /// The carried `layer` is the pre-parsed UNMUTATED carrier view (irrelevant on this path — the
    /// loader re-parses the TRANSPORTED bytes, which is exactly what fails). This is the verify-only-
    /// PATH companion to the bare-publisher
    /// `publisher_schema_failure_is_a_distinct_reason_from_a_content_hash_mismatch` (server.rs:6442).
    fn schema_failed_verified_version(seq: u64) -> CommittedPolicyVersion {
        // Arbitrary bytes that VERIFY (honest hash) but are NOT a valid POL-1 layer (the parse fails).
        let unparseable = b"this is not a pol1 layer { schema_version: nope".to_vec();
        debug_assert!(
            parse_layer(std::str::from_utf8(&unparseable).expect("utf-8 fixture")).is_err(),
            "the verified-but-unparseable fixture bytes must NOT be a valid POL-1 layer",
        );
        let honest_hash: ContentHash = sha256(&unparseable); // the hash check PASSES; only the parse fails
                                                             // A valid carrier layer (re-using v5) — the loader never consults it on the ParseError path.
        CommittedPolicyVersion::verified(seq, layer_for_version(5), unparseable, honest_hash)
    }

    /// (2) NACK-ABORTS-APPLY on the verify-only (D120) path — driven end to end ON THE WIRE.
    ///
    /// The verify-only loader hash-checks the transported bytes BEFORE parse (server.rs:2374). A
    /// version whose bytes do NOT hash to their claimed wire `content_hash` is a `HashNack`, so the
    /// production publisher `run_policy_publisher` ABORTS the apply (server.rs:2392 nack arm →
    /// `content_hash_nack_drop`, server.rs:2431; never published — the host stays on vN). This drives
    /// that through `run_policy_publisher_with_drop_sink` against a real loopback gate + the
    /// production `SnapshotCommitSink`:
    ///
    ///   * a FORWARD GOOD version (seq 5, `pol1/v5`) verifies + commits BOTH legs;
    ///   * a TAMPERED version at a strictly-FORWARD seq (7, `pol1/v107`) NACKs — the apply is
    ///     ABORTED (never published), so neither the evaluator NOR the wire MNAME advances to v107
    ///     even though its seq WOULD advance the forward-only discipline (distinguishing a NACK abort
    ///     from a stale-fan-out drop: the seq is forward, yet the version still never applies);
    ///   * a FINAL FORWARD GOOD version (seq 9, `pol1/v9`) verifies + commits, proving the publisher
    ///     keeps draining past the abort and the evaluator advances ONLY on verified forward versions.
    ///
    /// The publisher's published count is EXACTLY the verified-forward count (2: seq 5 then seq 9),
    /// the live evaluator + wire MNAME end on `pol1/v9` (never the NACKed `pol1/v107`), and the routed
    /// drop is the DISTINCT `content_hash_mismatch` reason (`is_stale_fan_out() == false`) — NOT a
    /// benign stale fan-out. NON-VACUOUS: it asserts the evaluator/MNAME never carry the NACKed
    /// version, so it FAILS if the abort ever applied the tampered version.
    #[tokio::test]
    async fn nack_aborts_apply_leaving_evaluator_and_mname_forward_on_the_wire() {
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed_for_version(5));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        let tcp_addr = gate.tcp_local_addr();

        assert_eq!(gate.policy_version(), "pol1/v5");

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader());
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // The reload-boundary drop sink: the publisher routes the verify-only NACK here as the
        // DISTINCT integrity-rejection drop, separable from a forward-only-seq stale fan-out.
        let drops = CapturingDropSink::new();

        // The scripted host-agent push: FORWARD GOOD seq 5, a TAMPERED seq 7 (NACK, aborts apply),
        // then FORWARD GOOD seq 9. The tampered version's seq IS forward — so a regression that let
        // the NACK apply would advance the evaluator to its `pol1/v107`, exactly what we assert it
        // never does.
        let source = ScriptedVerifiedSource::new(vec![
            good_verified_version(5, 5),
            tampered_verified_version(7, 107),
            good_verified_version(9, 9),
        ]);

        // Drive the PRODUCTION publisher to exhaustion, then drop the feed so the subscriber drains.
        let published = run_policy_publisher_with_drop_sink(&feed, source, 0, &drops).await;
        drop(feed);
        let commits = subscriber.await.expect("subscriber task joins cleanly");

        // The NACKed version was ABORTED at the publisher — never published. Only the two verified
        // forward versions (5, 9) reached the feed and committed.
        assert_eq!(
            published, 2,
            "only the two VERIFIED forward versions (seq 5, 9) published; the tampered seq 7 NACKed \
             host-wide and the apply was ABORTED (never published, the host stays on the prior version)",
        );
        assert_eq!(
            commits, 2,
            "the two published verify-only versions committed through the production \
             SnapshotCommitSink; the NACKed version never reached the subscriber",
        );

        // EVALUATOR leg: advanced 5 → 9 across the abort, NEVER to the NACKed `pol1/v107`.
        assert_eq!(
            gate.policy_version(),
            "pol1/v9",
            "the running evaluator advanced ONLY on the verified forward versions (5 → 9); the \
             tampered seq 7 NACK ABORTED the apply, so the evaluator never carried its pol1/v107",
        );
        let after = live_policy.evaluate(&ctx("blocked.example."));
        assert!(
            !after.admits(),
            "blocked.example stays a hard deny under the live (verified forward) version",
        );

        // BOUNDARY-ZONE leg ON THE WIRE: the wire MNAME advanced to the FINAL verified forward
        // suffix `denied.policy.v9.example.` — the NACKed version's `v107.example.` NEVER appears.
        assert_eq!(
            wire_authored_mname(tcp_addr).await,
            "denied.policy.v9.example.",
            "the wire MNAME advanced ONLY on the verified forward versions (v5 → v9); the NACKed \
             seq 7's v107.example. suffix never appeared (the apply was aborted)",
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.v9.example.",
            "the gate's live authored MNAME reflects the last VERIFIED forward version, never the \
             NACKed (aborted) one",
        );

        // The routed drop is the DISTINCT content_hash-mismatch NACK — NOT a benign stale fan-out.
        // Exactly one such drop (the tampered seq 7), naming its seq, with the greppable token.
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::ContentHashMismatch),
            1,
            "the tampered seq 7 raised exactly one content_hash-mismatch NACK (the apply aborted)",
        );
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::StaleFanOut),
            0,
            "no forward-only-seq stale fan-out occurred — the NACK abort is a DIFFERENT reason",
        );
        let nack = drops
            .drops()
            .into_iter()
            .find(|d| d.reason == SnapshotDropReason::ContentHashMismatch)
            .expect("a content_hash NACK drop");
        assert_eq!(
            nack.dropped_seq, 7,
            "the NACK drop names the NACKed (aborted) version's seq",
        );
        assert!(
            !nack.is_stale_fan_out(),
            "a content_hash NACK abort is NOT a benign D72 stale fan-out — distinct reason",
        );
        assert_eq!(nack.reason.as_str(), "content_hash_mismatch");

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down after the subscriber drained");
    }

    /// (3) SCHEMA-FAILURE-ABORTS-APPLY on the verify-only (D120) path — the symmetric companion to
    /// `nack_aborts_apply_leaving_evaluator_and_mname_forward_on_the_wire` above (and to the bare-
    /// publisher `publisher_schema_failure_is_a_distinct_reason_from_a_content_hash_mismatch`,
    /// server.rs:6442), driven end to end ON THE WIRE.
    ///
    /// The verify-only loader hash-checks the transported bytes BEFORE parse (server.rs:2374). A
    /// version whose bytes VERIFY against their claimed wire `content_hash` but FAIL the POL-1 schema
    /// parse is a `LoadVerdict::ParseError`, so the production publisher ABORTS the apply for it (the
    /// SAME non-commit decision a `HashNack` triggers — server.rs:2392 nack arm), but the routed drop
    /// carries the DISTINCT `SnapshotDropReason::SchemaFailure` reason, NOT `ContentHashMismatch`
    /// (server.rs:2442). This drives that through `run_policy_publisher_with_drop_sink` against a real
    /// loopback gate + the production `SnapshotCommitSink`:
    ///
    ///   * a FORWARD GOOD version (seq 5, `pol1/v5`) verifies + parses + commits BOTH legs;
    ///   * a VERIFIED-but-UNPARSEABLE version at a strictly-FORWARD seq (7) ParseErrors — the apply is
    ///     ABORTED (never published), so neither the evaluator NOR the wire MNAME advances even though
    ///     its seq WOULD advance the forward-only discipline (distinguishing a schema-failure abort
    ///     from a stale-fan-out drop: the seq is forward, yet the version still never applies);
    ///   * a FINAL FORWARD GOOD version (seq 9, `pol1/v9`) verifies + commits, proving the publisher
    ///     keeps draining past the abort and the evaluator advances ONLY on verified+parsed versions.
    ///
    /// The publisher's published count is EXACTLY the verified-parsed-forward count (2: seq 5 then
    /// seq 9), the live evaluator + wire MNAME end on `pol1/v9`, and the routed drop is the DISTINCT
    /// `schema_failure` reason (`is_stale_fan_out() == false`, AND not a `content_hash_mismatch`) —
    /// NOT a benign stale fan-out. NON-VACUOUS: it asserts the evaluator/MNAME never advance to the
    /// unparseable seq's version, so it FAILS if the abort ever applied the verified-but-unparseable
    /// bytes.
    #[tokio::test]
    async fn schema_failure_aborts_apply_leaving_evaluator_and_mname_forward_on_the_wire() {
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed_for_version(5));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        let tcp_addr = gate.tcp_local_addr();

        assert_eq!(gate.policy_version(), "pol1/v5");

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader());
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // The reload-boundary drop sink: the publisher routes the verify-only ParseError here as the
        // DISTINCT schema-failure integrity-rejection drop, separable from BOTH a content_hash NACK
        // and a forward-only-seq stale fan-out.
        let drops = CapturingDropSink::new();

        // The scripted host-agent push: FORWARD GOOD seq 5, a VERIFIED-but-UNPARSEABLE seq 7 (schema
        // failure, aborts apply), then FORWARD GOOD seq 9. The unparseable version's seq IS forward —
        // so a regression that let the ParseError apply would advance the evaluator past v5/v9's
        // discipline (it carries no parseable version at all), exactly what we assert it never does.
        let source = ScriptedVerifiedSource::new(vec![
            good_verified_version(5, 5),
            schema_failed_verified_version(7),
            good_verified_version(9, 9),
        ]);

        // Drive the PRODUCTION publisher to exhaustion, then drop the feed so the subscriber drains.
        let published = run_policy_publisher_with_drop_sink(&feed, source, 0, &drops).await;
        drop(feed);
        let commits = subscriber.await.expect("subscriber task joins cleanly");

        // The schema-failed version was ABORTED at the publisher — never published. Only the two
        // verified+parsed forward versions (5, 9) reached the feed and committed.
        assert_eq!(
            published, 2,
            "only the two VERIFIED+PARSED forward versions (seq 5, 9) published; the verified-but-\
             unparseable seq 7 ParseErrored host-wide and the apply was ABORTED (never published)",
        );
        assert_eq!(
            commits, 2,
            "the two published verify-only versions committed through the production \
             SnapshotCommitSink; the schema-failed version never reached the subscriber",
        );

        // EVALUATOR leg: advanced 5 → 9 across the abort, NEVER carrying the unparseable seq 7.
        assert_eq!(
            gate.policy_version(),
            "pol1/v9",
            "the running evaluator advanced ONLY on the verified+parsed forward versions (5 → 9); \
             the unparseable seq 7 ParseError ABORTED the apply, so the evaluator never carried it",
        );
        let after = live_policy.evaluate(&ctx("blocked.example."));
        assert!(
            !after.admits(),
            "blocked.example stays a hard deny under the live (verified+parsed forward) version",
        );

        // BOUNDARY-ZONE leg ON THE WIRE: the wire MNAME advanced to the FINAL verified forward
        // suffix `denied.policy.v9.example.` — the unparseable seq 7 NEVER changed it.
        assert_eq!(
            wire_authored_mname(tcp_addr).await,
            "denied.policy.v9.example.",
            "the wire MNAME advanced ONLY on the verified+parsed forward versions (v5 → v9); the \
             verified-but-unparseable seq 7 never moved the suffix (the apply was aborted)",
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.v9.example.",
            "the gate's live authored MNAME reflects the last VERIFIED+PARSED forward version, never \
             the schema-failed (aborted) one",
        );

        // The routed drop is the DISTINCT schema-failure reason — NOT a content_hash mismatch and NOT
        // a benign stale fan-out. Exactly one such drop (the unparseable seq 7), naming its seq.
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::SchemaFailure),
            1,
            "the verified-but-unparseable seq 7 raised exactly one schema-failure abort drop",
        );
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::ContentHashMismatch),
            0,
            "the bytes VERIFIED against their wire hash — this is a SCHEMA failure, NOT a content_hash \
             mismatch (the two integrity-rejection reasons are structurally distinct, server.rs:2442)",
        );
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::StaleFanOut),
            0,
            "no forward-only-seq stale fan-out occurred — the schema-failure abort is a DIFFERENT reason",
        );
        let schema_drop = drops
            .drops()
            .into_iter()
            .find(|d| d.reason == SnapshotDropReason::SchemaFailure)
            .expect("a schema-failure abort drop");
        assert_eq!(
            schema_drop.dropped_seq, 7,
            "the schema-failure drop names the aborted version's seq",
        );
        assert_eq!(
            schema_drop.committed_seq, 7,
            "the schema-failure drop is keyed by the version that failed to apply (no advance-past \
             relation, server.rs:2450)",
        );
        assert!(
            !schema_drop.is_stale_fan_out(),
            "a verify-only schema-failure abort is NOT a benign D72 stale fan-out — distinct reason",
        );
        assert_eq!(schema_drop.reason.as_str(), "schema_failure");

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down after the subscriber drained");
    }
}
