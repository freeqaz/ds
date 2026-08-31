// SPDX-License-Identifier: Apache-2.0
//! `event_surface` split (D53/§5.4): the severing-rung-reload REVOCATION-SWEEP WITNESS —
//! extracted from the oversized `tests/event_surface.rs` (test-only reorg, behavior-
//! preserving). `#[path]`-included into the `event_surface` binary; self-contained imports.

// ───────────────────────────────────────────────────────────────────────────────────────────────
// 18. The §5.4 / D53 REVOCATION-SWEEP WITNESS — a severing-rung policy RELOAD drives the sweep to
//     REVOKE + SEVER (doc 11 §5.3 admitter-LAST commit, §5.4 revocation sweep; D53 block-or-higher
//     rung; D72 admitter-LAST). This closes the gap the wave27b subscriber-inttest reviewer flagged:
//
//       * The wave-1 verdict-predicate test proves `severs_established_flows()` at the VERDICT
//         level (a frozen `DnsVerdict::Deny{rung}` whose rung severs), and the in-crate sweep tests
//         exercise the sweep core + the routing → enforcer in ISOLATION. But there was NO out-of-
//         crate WIRE-RELOAD witness proving the subscriber-driven reload of a SEVERING-rung policy
//         actually drives the §5.4 sweep all the way to the reportable enforcement surface.
//
//     This module IS that witness, against the PRODUCTION combined-commit wiring exactly as `main`
//     runs it (loopback gate + `boundary_snapshot_feed` → `watch_snapshots` →
//     `SnapshotCommitSink::with_revocation_sweep_enforced` against a SHARED `LiveAdmissions`
//     registry), driven end to end:
//
//       1. ADMIT under LOOSE — two live admissions are minted into the shared registry: a name that
//          the tightened version will sever (`tighten.example` at a sole-reference IP) and a
//          STILL-ALLOWED sibling (`kept.example` at its own IP). Both admit under LOOSE.
//       2. RELOAD a committed `BoundarySnapshot::with_policy` whose composed document DENIES the
//          admitted name at a SEVERING rung (`rung: kill+snapshot`, block-or-higher → D53) — the
//          SAME severing-rung POL-1 layer fixture pattern the in-crate sweep tests carry on
//          `BoundarySnapshot.policy` / `CommittedPolicy`.
//       3. The D72 admitter-LAST commit re-sources the evaluator FIRST, THEN runs the §5.4 sweep
//          against the NEW evaluator → the now-severing-denied admission is REVOKED (its DNS-2b
//          registry entry deleted) AND `flush_conntrack` is FLAGGED for the freed IP. We OBSERVE
//          that through the REPORTABLE path: a `RecordingSweepEnforcer` we own and read back, whose
//          `flushed()` records a `flush_session` over the freed IP spanning the `sever_pair`
//          (`AgentVm` 0x1 + `TlsproxyUpstream` 0x2) legs and whose `withdrawn()` records the
//          allow-set element delete — NO live kernel (no nft / no conntrack on `cargo test
//          --offline`).
//       4. The still-allowed sibling is NOT revoked, NOT withdrawn, NOT flushed (D53 / W4
//          UNDER-DELETE bias — a name the new version still admits keeps its admission).
//       5. A NON-SEVERING reload (the tightened version drops `tighten.example` to an unknown-domain
//          Ask, not a block-rung Deny) still REVOKES the admission but flags NO conntrack flush —
//          the rung-conditional guard (D53): expiry, not revocation, cleans the rest up.
//
//     Loopback / synthetic only (§5.3): a real `spawn_gate`-bound gate on 127.0.0.1:0, the host-
//     LOCAL `boundary_snapshot_feed` (NEVER a control-plane stream), `with_policy` snapshots whose
//     composed documents are parsed from synthetic POL-1 layers, and the reportable in-memory
//     enforcer (no kernel write). No new D-number; the FROZEN `DnsVerdict::Deny` keeps its three
//     fields {rcode_policy, rung, provenance}.
// ───────────────────────────────────────────────────────────────────────────────────────────────
mod d53_revocation_sweep_witness {
    use std::net::IpAddr;
    use std::sync::Arc;

    use ds_contracts::dns_admission::{AddressFamily, AdmittedAddr};
    use ds_contracts::flush::DstKey;
    use ds_contracts::mark::{Leg, DS_MARK_MASK};
    use ds_contracts::pol1::parse_layer;
    use ds_dnsgate::policy::{PolicyCorePolicy, TtlClamp};
    use ds_dnsgate::server::{
        boundary_snapshot_feed, spawn_gate, watch_snapshots, AdmissionReevaluator,
        BoundarySnapshot, GateConfig, LiveAdmission, LiveAdmissions, RecordingSweepEnforcer,
        SnapshotCommitSink, SweepEnforcer,
    };
    use policy_core::pol1_eval::{compose, ComposedPolicy};

    // ── Severing-rung POL-1 layer fixtures (the SAME shape the in-crate sweep tests carry; doc 11
    //    §5.4 / D53). LOOSE admits every name; TIGHT blocks `tighten.example` at a SEVERING rung
    //    (`kill+snapshot`, block-or-higher → the §5.4 conntrack flush fires); TIGHT_NONSEVERING
    //    simply drops it from the allowlist (an unknown-domain Ask under `standard` — revoked, but
    //    NOT a block-rung Deny, so NO flush). ──

    /// LOOSE (`pol1/v-loose`): allowlists `tighten.example` + `kept.example` — both ADMIT. The
    /// startup version every admission is minted under.
    const SWEEP_LAYER_LOOSE: &str = r#"
schema_version: pol1/v-loose
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: tighten.example
  - domain: kept.example
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// TIGHT (`pol1/v-tight`): `tighten.example` is now BLOCKED at a SEVERING rung
    /// (`rung: kill+snapshot`, block-or-higher → D53 conntrack flush fires); `kept.example` stays
    /// allowlisted (still admits). Re-sourcing LOOSE → TIGHT flips `tighten.example` Allow → a
    /// severing Deny, so the §5.4 sweep revokes its live admission AND flags the flush.
    const SWEEP_LAYER_TIGHT_SEVERING: &str = r#"
schema_version: pol1/v-tight
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: kept.example
blocklist:
  - domain: tighten.example
    reason: tightened-policy-push
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// TIGHT, NON-SEVERING (`pol1/v-tight-ask`): `tighten.example` is simply dropped from the
    /// allowlist (no blocklist entry), so under `standard` posture it becomes an unknown-domain
    /// `Ask` — which does NOT admit (the admission is REVOKED) but is NOT a `Deny` at a severing
    /// rung, so NO conntrack flush fires. The rung-conditional control (D53).
    const SWEEP_LAYER_TIGHT_NONSEVERING: &str = r#"
schema_version: pol1/v-tight-ask
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
allowlist:
  - domain: kept.example
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// Compose one synthetic POL-1 layer into the deny-wins document the running `PolicyCorePolicy`
    /// decides against — the SAME `parse_layer` → `compose` lift `main`'s startup + reload paths
    /// use (POL-3: no rule reimplemented here).
    fn composed(layer_yaml: &str) -> ComposedPolicy {
        let layer = parse_layer(layer_yaml).expect("the witness POL-1 layer parses");
        compose(&[layer], &[])
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("the witness IP parses")
    }

    /// The canonical `AdmittedAddr::to_dst_key` form for an IP — built through the SAME frozen
    /// `ds_contracts::dns_admission::AdmittedAddr` projection the §5.4 routing (and the admission
    /// insert) uses, so the witness asserts byte-exact agreement without re-deriving the hex.
    fn dst_key_of(addr: IpAddr) -> DstKey {
        let admitted = match addr {
            IpAddr::V4(v4) => AdmittedAddr {
                family: AddressFamily::V4,
                octets: v4.octets().to_vec(),
            },
            IpAddr::V6(v6) => AdmittedAddr {
                family: AddressFamily::V6,
                octets: v6.octets().to_vec(),
            },
        };
        admitted.to_dst_key()
    }

    #[tokio::test]
    async fn severing_rung_reload_drives_the_sweep_to_revoke_and_sever_via_the_reportable_enforcer()
    {
        // The WITNESS. PRODUCTION combined-commit wiring (exactly `main`'s): a real loopback gate
        // runs the LOOSE evaluator; the `SnapshotCommitSink::with_revocation_sweep_enforced` pairs
        // the gate's boundary-zone reloader, policy reloader, a SHARED live-admission registry, the
        // gate's re-evaluator, AND a `RecordingSweepEnforcer` WE OWN so we can read the reportable
        // §5.4 enforcement surface back. Admit `tighten.example` (sole-ref IP) + a still-allowed
        // sibling `kept.example` under LOOSE, then RELOAD a committed snapshot that DENIES
        // `tighten.example` at a SEVERING rung. The admitter-LAST commit re-sources the evaluator
        // FIRST and THEN runs the sweep → the now-denied admission is REVOKED and `flush_conntrack`
        // is FLAGGED (D53 sever) on the reportable enforcer; the sibling survives untouched.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        // A SHARED-HANDLE clone of the installed evaluator BEFORE spawn so the sweep re-evaluates
        // against the SAME inner `Arc` the gate's handlers (and the policy reloader) decide with.
        let live_policy = PolicyCorePolicy::new(composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v-loose");

        // ── 1. ADMIT under LOOSE. Two live admissions in ONE shared registry (the SAME registry
        //    the W1/W2 transaction mints into; fed synthetically here): the name the tightened
        //    version severs (a SOLE-reference IP, so the sweep frees it) and a STILL-ALLOWED
        //    sibling at its OWN IP. Both admit under LOOSE. ──
        let admissions = LiveAdmissions::new();
        let severed_ip = ip("203.0.113.7"); // tighten.example's sole-reference IP
        let kept_ip = ip("198.51.100.9"); // kept.example's own IP
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", severed_ip));
        admissions.admit(LiveAdmission::new("sess-b", "kept.example", kept_ip));
        assert_eq!(admissions.len(), 2, "two live admissions under LOOSE");
        // POL-3 sanity: under LOOSE both re-evaluate to an admitting verdict with provenance.
        assert!(
            live_policy
                .reevaluate("sess-a", "tighten.example.")
                .admits(),
            "tighten.example admits under LOOSE"
        );
        assert!(
            live_policy.reevaluate("sess-b", "kept.example.").admits(),
            "kept.example admits under LOOSE"
        );

        // The REPORTABLE enforcement surface: a `RecordingSweepEnforcer` WE keep a concrete handle
        // to (so we can read `flushed()` / `withdrawn()` after the commit), shared into the sink as
        // an `Arc<dyn SweepEnforcer>`. The DEFAULT `with_revocation_sweep` would bury its own
        // recorder; the `_enforced` seam is the one `main` uses to bind an explicit enforcer, and
        // it is what lets the witness observe the routed sever — no live kernel.
        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let enforcer_dyn: Arc<dyn SweepEnforcer> = enforcer.clone();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer_dyn,
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // ── 2. RELOAD the SEVERING-rung policy version (one policy version end to end). The host
        //    agent fans out the committed `with_policy` snapshot through the host-LOCAL feed. ──
        feed.publish(BoundarySnapshot::with_policy(
            7,
            "pushed.example.",
            composed(SWEEP_LAYER_TIGHT_SEVERING),
            TtlClamp::DEFAULT,
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(
            commits, 1,
            "the single committed severing-rung snapshot re-sourced + swept once"
        );

        // ── 3+4. ASSERT the admitter-LAST commit drove the §5.4 sweep to REVOKE + SEVER. ──
        // Admitter-LAST: the live evaluator now decides against the tightened (severing) version.
        assert_eq!(
            gate.policy_version(),
            "pol1/v-tight",
            "the running evaluator re-sourced its composed document admitter-LAST"
        );

        // The DNS-2b registry: tighten.example's admission was REVOKED; kept.example's survived.
        let survivors = admissions.snapshot();
        assert_eq!(
            survivors.len(),
            1,
            "the now-severing-denied admission was swept out of the live registry"
        );
        assert_eq!(
            survivors[0].fqdn, "kept.example.",
            "only the still-allowed sibling remains"
        );
        assert_eq!(survivors[0].ip, kept_ip);
        assert!(
            !survivors.iter().any(|a| a.ip == severed_ip),
            "the revoked admission's sole-reference IP is gone from the live set"
        );

        // The REPORTABLE allow-set delete (leg (a)): EXACTLY the freed sole-ref IP was withdrawn,
        // on the PER-SESSION `allow4_<idx>` (single-source `ds_contracts::session::allow_set_name`,
        // idx-0 reportable approximation; D3/D4 — never a flat shared `allow4`), keyed byte-exact
        // through the frozen `to_dst_key` projection.
        let withdrawn = enforcer.withdrawn();
        assert_eq!(
            withdrawn.len(),
            1,
            "exactly the freed sole-reference IP is withdrawn from the allow set"
        );
        assert_eq!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(
                ds_contracts::dns_admission::AddressFamily::V4,
                0
            )
        );
        assert_eq!(withdrawn[0].set_name, "allow4_0");
        assert_ne!(
            withdrawn[0].set_name, "allow4",
            "no flat shared `allow4` survives in the §5.4 sweep delete"
        );
        assert_eq!(withdrawn[0].dst_key, dst_key_of(severed_ip));
        // The mark is DS_MARK_MASK-composed, never bare (the mask discipline rides the routed
        // element verbatim).
        assert_eq!(withdrawn[0].mark_mask, DS_MARK_MASK);
        assert_eq!(
            withdrawn[0].mark_value & !DS_MARK_MASK,
            0,
            "the routed mark carries no bits outside the frozen mask"
        );
        // The still-allowed sibling's IP is NEVER withdrawn (D53 / W4 under-delete bias).
        assert!(
            !withdrawn.iter().any(|w| w.dst_key == dst_key_of(kept_ip)),
            "the still-allowed sibling's IP is NEITHER deleted (under-delete bias)"
        );

        // The REPORTABLE conntrack flush (leg (b)) — the D53 SEVER. The severing-rung deny fired
        // EXACTLY one `flush_session`, narrowed (`DstFilter::Only`) to the freed sole-ref IP,
        // spanning the block-rung sever pair (`AgentVm` 0x1 + `TlsproxyUpstream` 0x2).
        let flushed = enforcer.flushed();
        assert_eq!(
            flushed.len(),
            1,
            "a severing-rung reload fired the rung-conditional conntrack flush (D53)"
        );
        assert_eq!(
            flushed[0].dst_keys,
            vec![dst_key_of(severed_ip)],
            "the flush narrows to EXACTLY the freed sole-reference IP"
        );
        assert!(
            !flushed[0].dst_keys.contains(&dst_key_of(kept_ip)),
            "the still-allowed sibling's IP is NOT flushed (under-delete bias)"
        );
        assert_eq!(
            flushed[0].legs,
            [Leg::AgentVm, Leg::TlsproxyUpstream],
            "the flush spans the block-rung sever pair (0x1 + 0x2)"
        );
        assert_eq!(flushed[0].mark_mask, DS_MARK_MASK);

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn non_severing_reload_revokes_without_flagging_the_conntrack_flush() {
        // The rung-conditional NEGATIVE: a tightened reload that drops `tighten.example` to an
        // unknown-domain Ask (NOT a block-rung Deny) still REVOKES the admission through the wire
        // path — the freed allow-set element is withdrawn — but flags NO conntrack flush (D53:
        // expiry, not revocation, cleans the rest up). Same PRODUCTION combined-commit wiring +
        // reportable enforcer; only the rung of the reloaded version differs.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v-loose");

        let admissions = LiveAdmissions::new();
        let freed_ip = ip("203.0.113.7");
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", freed_ip));

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let enforcer_dyn: Arc<dyn SweepEnforcer> = enforcer.clone();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer_dyn,
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // Reload the NON-SEVERING tightened version (tighten.example → Ask, not a block-rung Deny).
        feed.publish(BoundarySnapshot::with_policy(
            9,
            "pushed-ask.example.",
            composed(SWEEP_LAYER_TIGHT_NONSEVERING),
            TtlClamp::DEFAULT,
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(
            commits, 1,
            "the non-severing snapshot committed + swept once"
        );

        assert_eq!(gate.policy_version(), "pol1/v-tight-ask");

        // The admission was still REVOKED (the DNS-2b registry entry is gone) …
        assert!(
            admissions.is_empty(),
            "the non-severing deny still revokes the now-unadmitted name"
        );
        // … and the freed allow-set element was still withdrawn (the allow-set state is revoked) …
        let withdrawn = enforcer.withdrawn();
        assert_eq!(
            withdrawn.len(),
            1,
            "a non-severing deny still withdraws the freed allow-set element"
        );
        assert_eq!(withdrawn[0].dst_key, dst_key_of(freed_ip));
        // … but NO conntrack flush fired — it gates new flows only (D53 rung-conditional; W4).
        assert!(
            enforcer.flushed().is_empty(),
            "a non-severing (gate-rung) reload flushes NO conntrack — the rung-conditional guard \
             (D53): expiry, not revocation, cleans the rest up"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn boundary_zone_only_reload_runs_no_sweep_and_flags_no_flush() {
        // The ordering guard, end to end: a `policy: None` snapshot re-sources only the authored
        // suffix (no evaluator change), so the §5.4 sweep is SKIPPED entirely — even a live
        // admission for a name the gate's CURRENT (tight, severing) evaluator already denies is
        // left untouched and NOTHING is routed to the enforcer. A boundary-zone-only commit must
        // never sever established flows.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        // Start on the SEVERING-tight version: if the sweep wrongly ran on a boundary-zone-only
        // commit, this live admission (a name TIGHT severs) would be revoked + flushed; it must not.
        let live_policy = PolicyCorePolicy::new(composed(SWEEP_LAYER_TIGHT_SEVERING));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v-tight");

        let admissions = LiveAdmissions::new();
        admissions.admit(LiveAdmission::new(
            "sess-a",
            "tighten.example",
            ip("203.0.113.7"),
        ));

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let enforcer_dyn: Arc<dyn SweepEnforcer> = enforcer.clone();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer_dyn,
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // A boundary-zone-only commit (`BoundarySnapshot::new`, `policy: None`).
        feed.publish(BoundarySnapshot::new(11, "zone-only.example."))
            .await
            .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1, "the boundary-zone-only snapshot committed once");

        assert_eq!(
            admissions.len(),
            1,
            "a boundary-zone-only commit re-sources no evaluator → runs no sweep"
        );
        assert!(
            enforcer.withdrawn().is_empty(),
            "no allow-set element is withdrawn on a boundary-zone-only commit"
        );
        assert!(
            enforcer.flushed().is_empty(),
            "no conntrack is flushed on a boundary-zone-only commit (the sweep never ran)"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }
}
