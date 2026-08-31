//! ds-dnsgate — the DNS gating proxy (doc 09 §4; component contract in doc 11).
//!
//! PRE-STAGE runner. This binary stands up the hickory 0.26.x framework on a plain
//! tokio runtime behind the REAL pack-backed admission evaluator (doc 11 §4 / doc 13
//! §1.1, POL-3) and serves on loopback high ports. The installed policy is
//! [`PolicyCorePolicy`] over the SHIPPED read-only POL-2 baseline pack — every query is
//! routed through `policy-core`'s public `dns_admission_decision`, the SAME evaluator
//! ds-tlsproxy and the NFT programming path embed (no rule reimplemented). The D71
//! authored-SOA boundary zone is now SOURCED FROM THE LIVE host policy snapshot's POL-1
//! `dns.boundary_zone` (the same value `ds-policy-snapshot::PolicySnapshot::boundary_zone_value`
//! materializes), threaded into `GateConfig.boundary_zone` in place of the handler-local
//! const default, and refreshed on the doc 13 §5.3 admitter-LAST D72 hot-reload by the
//! single-per-host `WatchPolicies` host-snapshot SUBSCRIBER loop (`server::watch_policies`,
//! driving the gate's sole reload path `RunningGate::reload_boundary_zone`). `ds-dnsgate`
//! NEVER opens a control-plane policy stream (§5.3): the subscriber consumes the host-LOCAL
//! committed-snapshot feed the host agent fans out, and — as the admitter — commits each
//! snapshot LAST. It is still a framework-validation skeleton, NOT the DNS-1 gate: the
//! verdict SHAPE is frozen, and the W1/W2 insert-then-answer admission transaction behind
//! `Allow{admit}` is now WIRED into the handler ([`ds_dnsgate::txn`]: the DNS-4 filter, the
//! single shared deadline from POL-1 floor/ceil/grace, the fail-closed two-store lockstep,
//! original-query-name keying, and the W4 `max()` refresh). It runs against the in-memory
//! DNS-2b map + the reportable in-memory NFT-3 set programmer (LOOPBACK/SYNTHETIC ONLY — no
//! live nft kernel write on the default/offline path). The production `ds-nft` `NftWriter`
//! binding NOW LANDS over the workspace-internal `ds-nft` path-dep: `impl SweepEnforcer for
//! ds_nft::NftWriter<B>` (the §5.4 allow-set delete-element batch + the D53 rung-conditional
//! `flush_session_report(DstFilter::Only, sever_pair)` conntrack flush) is WIRED behind
//! `DS_NFTGATE_LIVE` (default OFF → the reportable `RecordingSweepEnforcer`), and
//! `impl NftSetProgrammer for ds_nft::NftWriter<B>` (the W1 set-program →
//! `refresh::refresh_batch` / `backend().apply_batch`, the W2 deadline riding the element
//! timeout) is bindable via `AdmissionStores::with_parts`. The honest RESIDUAL seam: the txn
//! programmer's LIVE-PATH wiring through the handler is gated by `handler.rs`'s monomorphic
//! `admission: AdmissionStores<RecordingSetProgrammer>` field (a frozen, not-owned seam — the
//! handler must be made generic over the programmer before `spawn_gate` can thread the live
//! writer through), plus threading the live POL-1 `admission.grace` value off the snapshot
//! through `StubRequestHandler::with_admission`. The host agent's PRODUCTION publisher half of
//! the snapshot feed is now WIRED on the live path (`server::run_policy_publisher` drives the
//! host's single `WatchPolicies(from_seq)` subscription onto the host-local
//! `BoundarySnapshotFeed`, carrying the real `(seq, content_hash)` identity, admitter-LAST), and
//! the dataplane-side CONSUMER of the host-local feed is now bound behind
//! `DS_DNSGATE_HOST_AGENT_FEED` (default OFF → an idle source, no control-plane stream; SET → the
//! doc 13 §8.4 v0 file+atomic-rename `server::HostLocalFeedSource`, resuming from the persisted
//! `applied_seq`, D36). The one residual seam is the CROSS-PROCESS Go D35 host-agent fan-out half
//! (the host's sole control-plane `WatchPolicies` subscriber writing committed versions into that
//! host-local directory) — it lives OUTSIDE this dataplane workspace (a separate host-agent task).
//! Session attribution (D44) is LIVE-WIRED
//! into the handler (interface-anchored, fail-closed to SERVFAIL), but `main` still serves
//! with the pre-stage recorded-source fallback until the orchestrator per-session tap
//! registry is plumbed. See the crate docs and
//! `dataplane/services/ds-dnsgate/README.md` for the full not-yet-built list.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use ds_contracts::pol1::parse_layer;
use ds_dnsgate::server::{
    boundary_snapshot_feed, run_policy_publisher_with_drop_sink, spawn_gate_with_programmer,
    spawn_gate_with_stores, watch_snapshots, AppliedSeqHeartbeat, AppliedSeqIdentity,
    AppliedSeqStore, BookBackedFleetSweeper, FleetRedriveAlertSink, FleetRevocationBook,
    FleetRevocationSweeper, HostLocalFeedSource, LiveAdmissions, OperatorLogFleetRedriveAlertSink,
    PersistingAppliedSeqHeartbeat, PolicyVersionSource, RecordingSweepEnforcer, RunningGate,
    SnapshotCommitSink, SweepEnforcer, TeeAppliedSeqHeartbeat, WatchPoliciesCarrierSource,
};
use ds_dnsgate::txn::{AdmissionStores, NftSetProgrammer, RecordingSetProgrammer};
// The production §5.4 SweepEnforcer binding AND the W1/W2 admission NftSetProgrammer binding
// (both behind DS_NFTGATE_LIVE, default OFF): the ONE nft/netlink writer (doc 14 §6) over the
// spawned `nft -f` / `conntrack -D` backend. `impl SweepEnforcer for ds_nft::NftWriter<B>` and
// `impl NftSetProgrammer for ds_nft::NftWriter<B>` both live in the `ds_dnsgate` crate; `main`
// selects the `SpawnBackend` writer for BOTH the revocation sweep and the admission insert only
// when the env gate is set.
use ds_dnsgate::event::{SnapshotDropEvent, SnapshotDropReason, SnapshotDropSink};
use ds_dnsgate::{GateConfig, NullSink, PolicyCorePolicy, TtlClamp};
use ds_nft::backend::SpawnBackend;
use ds_nft::NftWriter;
use ds_policy_snapshot::{PolicySnapshot, W2TtlClamp};
use policy_core::pol1_eval::{compose, ComposedPolicy};

/// Repo-relative path from this crate to the SHIPPED read-only POL-2 baseline pack. The
/// binary's `CARGO_MANIFEST_DIR` is `.../dataplane/services/ds-dnsgate`; the pack lives
/// under `.../dataplane/artifacts/policy-packs/` (same resolution the seam tests use).
fn shipped_pack_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // ds-dnsgate
    p.pop(); // services
    p.push("artifacts");
    p.push("policy-packs");
    p.push("pol2-system-baseline.pol1.yaml");
    p
}

/// The host's ONE composed policy document PLUS the live boundary-zone the gate signs
/// its authored-SOA denials with (doc 11 §3.2 / D71) AND the W2 TTL clamp window each
/// `Allow` carries (doc 11 §4 / D68) — ALL lifted off the SAME committed snapshot THROUGH
/// `ds-policy-snapshot::PolicySnapshot::from_policy_layer` / `committed_policy()` (the one
/// place the parse → lift lives), so the admission evaluator, the authored-SOA suffix, and
/// the clamp can never disagree about which policy version is live (one snapshot → one
/// composed doc + one clamp + one boundary zone, D72). This is the gate-local carrier the
/// composed document + clamp + zone are materialized into off that shared accessor.
struct HostPolicy {
    /// The deny-wins composed document the [`PolicyCorePolicy`] evaluates against.
    composed: ComposedPolicy,
    /// The D71 authored-SOA boundary zone, sourced from the live snapshot's POL-1
    /// `dns.boundary_zone` (defaulted to the working name by the reader when a layer omits
    /// it) — the value `GateConfig.boundary_zone` carries in place of the handler-local
    /// const. On a D72 admitter-LAST hot-reload this is re-sourced from the NEW snapshot.
    boundary_zone: String,
    /// The W2 TTL clamp window (doc 11 §4 / D68), sourced from the SAME snapshot layer's
    /// POL-1 `admission.ttl_floor`/`ttl_ceil` (defaulted to 60s/900s by the reader). This
    /// is the clamp that rides each committed `CommittedPolicy` so the snapshot-sourced
    /// evaluator re-source carries the snapshot's OWN clamp — one snapshot, one clamp,
    /// never a `TtlClamp::DEFAULT` echo that drifts from the composed document's version.
    ///
    /// The reload PUBLISH path no longer reads this field off `HostPolicy`: it lifts the W2
    /// clamp THROUGH the shared `PolicySnapshot::from_policy_layer` / `committed_policy()`
    /// accessor inside the server.rs reload constructor
    /// [`BoundarySnapshot::with_policy_layer`] (one parse → compose → lift, shared with
    /// startup). The field stays the documented host-policy carrier of the snapshot's W2
    /// clamp and is asserted by the `committed_snapshot_tests` that pin
    /// `snapshot_host_policy`'s lift; it is read only there in the plain (non-test) build, so
    /// the non-test compile would flag it unread.
    #[cfg_attr(not(test), allow(dead_code))]
    ttl_clamp: TtlClamp,
    /// The live POL-1 `admission.grace` (seconds) — the W2 shared-deadline grace (doc 11 §3.1 /
    /// doc 13 §1.5 / D68), sourced from the SAME committed snapshot's PARSED layer
    /// (`layer.admission.grace`) the boundary zone + W2 clamp come from. The FROZEN
    /// `CommittedPolicy`/`W2TtlClamp` carry only floor/ceil, so grace is read off the parsed POL-1
    /// layer here (never re-mirroring the frozen snapshot crate) and threaded into
    /// `GateConfig.admission_grace_secs` → both handlers' admission transaction, REPLACING the
    /// `ds_contracts::pol1::DEFAULT_GRACE_SECS` (60s) default. FLOOR/CEIL ride the verdict's frozen
    /// `Admit`; this is the one tunable that does not, so the snapshot tunes it at runtime. A D72
    /// admitter-LAST hot-reload re-sources it from the new snapshot's layer alongside the clamp +
    /// zone (one snapshot → one composed doc + one clamp + one zone + one grace, D72).
    admission_grace_secs: u32,
}

/// Build the host's ONE composed policy document, its live boundary zone, AND its W2 TTL
/// clamp window, network-free, from the shipped POL-2 baseline: read + parse the read-only
/// pack (`ds-contracts` reader), lift the committed policy THROUGH the shared
/// `PolicySnapshot::from_policy_layer` accessor, and compose the committed layer it hands
/// back with `policy-core`'s `compose` over a fresh install (no capabilities present, so the
/// `requires:`-gated entries are INERT — the pre-TLS-6 state). The boundary zone + W2 clamp
/// ride that same committed snapshot, never re-derived inline. This is the SAME network-free
/// construction the seam tests use; no resolver / no upstream is contacted. The host agent's
/// PRODUCTION publisher (`server::run_policy_publisher`) fans out the same snapshot shape from
/// the host's `WatchPolicies(from_seq)` stream — this is the STARTUP source of the same lift.
fn default_host_policy() -> io::Result<HostPolicy> {
    let path = shipped_pack_path();
    let text = std::fs::read_to_string(&path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "reading shipped POL-2 baseline pack {}: {e}",
                path.display()
            ),
        )
    })?;
    snapshot_host_policy(&text)
}

/// Compose the host policy from ONE POL-1 snapshot document — the single network-free
/// construction `default_host_policy` (startup) AND the production WatchPolicies publisher (a
/// committed reload, via `server::run_policy_publisher` → `BoundarySnapshot::with_policy_layer`)
/// both build through, so a committed snapshot is sourced EXACTLY the way
/// the startup policy is: parse the layer ONCE, hand it to
/// `ds-policy-snapshot::PolicySnapshot::from_policy_layer`, and read the committed policy's
/// composed-layer material + W2 clamp + boundary zone off `committed_policy()`. The
/// parse → lift is now done THROUGH the shared accessor (no inline re-mirror): the snapshot
/// crate is the ONE place that lifts a `CommittedPolicy` off a parsed layer (doc 13 §5 /
/// D72: one snapshot → one composed doc + one clamp + one boundary zone), so the evaluator
/// re-source, the authored-SOA suffix, and the clamp can never disagree about which policy
/// version is live. `policy-core::compose` (the deny-wins composition) stays HERE — that is
/// the evaluator's job, run over the committed layer the snapshot hands back; the host
/// agent's production publisher fans the same committed shape out in production.
fn snapshot_host_policy(text: &str) -> io::Result<HostPolicy> {
    let layer = parse_layer(text).map_err(|errs| {
        io::Error::other(format!(
            "the POL-1 snapshot document must parse with zero PolicyErrors, got:\n{errs}"
        ))
    })?;
    // Lift the host's ONE committed policy THROUGH the shared snapshot accessor — the
    // boundary zone (POL-1 `dns.boundary_zone`, reader-defaulted to the working name) AND
    // the W2 clamp window (POL-1 `admission.ttl_floor`/`ttl_ceil`, reader-defaulted to
    // 60s/900s) are sourced off the SAME parsed layer, never re-derived inline. A
    // layer-sourced snapshot always carries a committed policy, so the accessor is present.
    let snapshot = PolicySnapshot::from_policy_layer(&layer);
    let committed = snapshot
        .committed_policy()
        .expect("a layer-sourced PolicySnapshot always carries a committed policy");
    let boundary_zone = committed.boundary_zone().to_string();
    // Map the snapshot's W2 clamp WINDOW onto the gate's `TtlClamp` (the gate owns the
    // `clamp()`/`to_admit()` projection; the snapshot carries only the floor/ceil VALUES).
    let ttl_clamp = ttl_clamp_from_window(committed.ttl_clamp());
    // The W2 shared-deadline GRACE (POL-1 `admission.grace`): the FROZEN `CommittedPolicy` /
    // `W2TtlClamp` carry ONLY floor/ceil, so grace is sourced off the SAME parsed POL-1 layer the
    // snapshot was lifted from (`layer.admission.grace`, reader-defaulted to 60s) — one snapshot,
    // one grace, alongside the clamp + zone (D72), without modifying the frozen snapshot crate.
    let admission_grace_secs = layer.admission.grace;
    // The deny-wins composition is the EVALUATOR's job (doc 13 §1 rule 1) — run it HERE over
    // the committed layer the snapshot hands back (the composition INPUT it carries), so a
    // committed snapshot is sourced exactly the way startup is, with no re-parse drift.
    let composed = compose(&[committed.composed_layer().clone()], &[]);
    Ok(HostPolicy {
        composed,
        boundary_zone,
        ttl_clamp,
        admission_grace_secs,
    })
}

/// Map the snapshot's W2 clamp WINDOW (`ds-policy-snapshot::W2TtlClamp`, the policy floor/ceil
/// VALUES lifted off the committed layer's `admission` block, doc 11 §4 / D68) onto the gate's
/// [`TtlClamp`] — the gate-local type that owns the `clamp()`/`to_admit()` projection onto each
/// `Allow`. The snapshot carries only the window so the evaluator re-source and the clamp come
/// from the SAME committed policy (D72); this is the field-for-field carry the gate applies.
fn ttl_clamp_from_window(window: W2TtlClamp) -> TtlClamp {
    TtlClamp {
        floor: window.floor,
        ceil: window.ceil,
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // D131 shm-rollout T1 (doc 13 §Rollout item 4): under the production profile
    // (DS_PRODUCTION) the shm WRITER gate (DS_ADMISSION_SHM_LIVE) is MANDATORY —
    // assert it BEFORE the gate spawns and EXIT FATALLY if missing, so a prod deploy
    // that forgets the gate refuses to boot rather than silently running the
    // in-process map a cross-process reader can never see (the M1 WithCAStore / D56
    // forget-the-gate footgun). Also warns if the writer-before-reader re-resolve
    // listen gate is unset. Off the profile this is a silent no-op; the default boot
    // is byte-identical to today.
    assert_production_profile_gates();

    eprintln!(
        "ds-dnsgate: PRE-STAGE — hickory 0.26.x framework-validation skeleton behind the \
         pack-backed PolicyCorePolicy (POL-3: policy-core's dns_admission_decision over the \
         shipped read-only POL-2 baseline). Serving on loopback high ports; the §5.3 D72 \
         admitter-LAST policy hot-reload runs via the host-local WatchPolicies feed (the host \
         agent's single WatchPolicies(from_seq) subscription is fanned onto the feed by the \
         production publisher carrying the real (seq, content_hash) identity; no control-plane \
         stream is opened here). The W1/W2 insert-then-answer admission \
         transaction is WIRED (DNS-4 filter, single shared deadline from POL-1 \
         floor/ceil/grace — the grace is now sourced LIVE off the committed snapshot, not the \
         60s schema default — fail-closed two-store lockstep, original-name keying, max() \
         refresh) and mints into the gate's SHARED §5.4 LiveAdmissions registry, so the \
         admitter-LAST revocation sweep re-decides the admissions the transaction actually \
         minted (the admission ↔ revocation loop is closed). It runs against the IN-MEMORY \
         DNS-2b map + reportable in-memory NFT-3 set programmer — LOOPBACK/SYNTHETIC ONLY, no \
         live nft kernel write. Residual seams: the production ds-nft NftWriter binding (the \
         services/ds-dnsgate Cargo.toml ds-nft path-dep + the impl NftSetProgrammer adapter, a \
         build-order dependency outside this listener shell), the host-agent gRPC \
         WatchPolicies(from_seq) feed binding behind DS_DNSGATE_HOST_AGENT_FEED (default OFF → \
         the idle source; the publisher mechanism itself is live), and session attribution in \
         main. See dataplane/services/ds-dnsgate/README.md and docs/11-ds-dnsgate-design.md."
    );

    // The OQ2 warm-restart REBUILD demonstration (OQ2 rebuild posture, maintainer ruling
    // 2026-06-14 — proposed D131, pending §6 ratification). Default-OFF, behind a single env
    // gate: with DS_DNSGATE_WARM_RESTART_DEMO set, the gate runs the warm_restart::Reconstructor
    // against a SYNTHETIC kernel NFT-3 set dump (TODO(seam: ds-nft kernel dump)) + a SYNTHETIC
    // §5.5 DnsEvent spool replay (TODO(seam: spool replay)) and prints the rebuild report, so an
    // operator can exercise the rebuild path end-to-end with NO live kernel and NO real spool I/O.
    // A real kernel-dump read / durable-spool replay are the deferred manual seams behind the two
    // trait hooks; this is the LOOPBACK/SYNTHETIC skeleton. It never gates startup — the gate goes
    // on to serve regardless.
    maybe_demo_warm_restart_rebuild().await;

    // The default installed evaluator: the REAL pack-backed PolicyCorePolicy, built
    // network-free from the shipped POL-2 baseline (the frozen `policy_core::dns_gate::evaluate`
    // is the PRODUCTION hot path — NOT the allow-all FixedStubPolicy harness default), AND the
    // live authored-SOA boundary zone sourced from the SAME snapshot's POL-1 `dns.boundary_zone`.
    // The composed document + W2 clamp window are the evaluator re-source the §5.3 D72
    // admitter-LAST hot-reload swaps on a committed snapshot (the subscriber below). The
    // production publisher does NOT echo this in-memory startup document: it re-SOURCES each
    // committed `CommittedPolicy` from the committed POL-1 layer the host agent fans out (the
    // same parse → compose → lift-clamp path), so a committed BoundarySnapshot carries that
    // version's ACTUAL composed doc + W2 clamp + (seq, content_hash) identity, not a startup echo.
    let host = default_host_policy()?;
    let policy = PolicyCorePolicy::new(host.composed);
    // A shared-handle clone of the running evaluator the §5.4 revocation sweep re-evaluates
    // through (the sweep's re-source twin of the gate's evaluator). `PolicyCorePolicy` shares one
    // inner `Arc`, so an admitter-LAST D72 commit through the gate's `policy_reloader` re-sources
    // THIS clone too — the sweep always decides against the version the commit just installed.
    let sweep_reevaluator = policy.clone();

    // Thread the live-snapshot boundary zone AND the live POL-1 `admission.grace` into the gate
    // (replacing the DEFAULT_BOUNDARY_ZONE / DEFAULT_GRACE_SECS const defaults): every authored-SOA
    // denial is signed with the policy-pushed suffix, and the W2 shared deadline carries the
    // snapshot's grace, not the schema 60s. A D72 admitter-LAST hot-reload re-sources the boundary
    // zone from the new snapshot via the WatchPolicies subscriber below; the grace rides the same
    // committed snapshot (one snapshot → one zone + one clamp + one grace, D72).
    let mut config = GateConfig {
        boundary_zone: host.boundary_zone,
        admission_grace_secs: host.admission_grace_secs,
        ..GateConfig::default()
    };
    // DS_DNSGATE_LISTEN (optional): pin BOTH the udp and tcp listeners to an explicit
    // address. The default (unset) keeps the loopback/OS-ephemeral bind — safe inside a
    // single-netns sandbox where the gate and its callers share localhost. But the nft
    // floor's `redirect to :15353` DNATs the VM's :53 flow to the inbound-iface address,
    // NOT loopback, so a routed-tap deployment (the nested-VM testbed) must bind the gate
    // on `0.0.0.0:15353` for the redirected flow to land. Parsed as a single SocketAddr
    // applied to both transports (one redirect port serves udp/53 and tcp/53 alike).
    if let Ok(listen) = std::env::var("DS_DNSGATE_LISTEN") {
        let addr: std::net::SocketAddr = listen.parse().unwrap_or_else(|e| {
            panic!("DS_DNSGATE_LISTEN={listen:?} is not a valid host:port SocketAddr: {e}")
        });
        config.udp_addr = addr;
        config.tcp_addr = addr;
        eprintln!("ds-dnsgate: DS_DNSGATE_LISTEN set — binding udp+tcp listeners on {addr}");
    }
    // DS_SESSION_UUID (optional, single-session): when set to a non-empty value, BOTH
    // transports stamp this exact `session_uuid` into every query — the W1/W2 DNS-2b
    // AdmissionKey is written under `{DS_SESSION_UUID, fqdn}` so a co-host ds-tlsproxy that
    // stamps the SAME uuid into its `SessionRef` gets a FORWARD admission HIT (doc 11 §5.1 /
    // D131-rollout). Unset (or empty) → the pre-stage `src:<addr>` token, byte-identical to
    // today. Single-session-honest only (one VM per gate); the multi-session path is the
    // interface-anchored attribution table, still deferred to the orchestrator tap-registry.
    if let Ok(uuid) = std::env::var(SESSION_UUID_ENV) {
        if !uuid.is_empty() {
            eprintln!(
                "ds-dnsgate: {SESSION_UUID_ENV} set — stamping the single-session session_uuid \
                 {uuid:?} into every query's DNS-2b AdmissionKey (cross-process key agreement \
                 with a co-host ds-tlsproxy; single-session/one-VM only)."
            );
            config.fixed_session_uuid = Some(uuid);
        }
    }
    // DS_DNSGATE_TAP_REGISTRY (optional, multi-session): when set to a non-empty SYNTHETIC SPEC,
    // thread the orchestrator's per-session TAP REGISTRY into the gate — the interface-anchored
    // §5.1 / W6 attribution table (doc 11 §5.1, D44). BOTH transports then resolve every query's
    // session through `AttributionTable::attribute_local` keyed on the listener's own post-NAT
    // LOCAL address (the never-recycled tap join), REPLACING the pre-stage `src:<addr>` fallback
    // and failing closed to SERVFAIL on an unregistered interface. This is the structurally-general
    // MULTI-session shape and takes PRECEDENCE over the single-session `DS_SESSION_UUID` above
    // (server.rs applies the precedence: tap registry > fixed uuid > pre-stage). Unset → `None`,
    // byte-identical to today. The live cross-process orchestrator session-record feed is a
    // DEFERRED seam outside this dataplane workspace; the spec is the loopback/synthetic stand-in.
    if let Some(table) = maybe_tap_registry_from_env() {
        config.tap_registry = Some(table);
    }
    // DS_TOKEN_FINGERPRINT (optional, single-session): the scoped-token chain FINGERPRINT / block
    // id (opaque hex; NEVER token bytes) the sessions this gate admits are recorded under in the
    // FLEET-revocation book (doc 19 §7; D102/P-R6). When set to a non-empty value, EVERY successful
    // admission records `(fingerprint → session)` so a pushed revocation of that token severs the
    // flows the W1/W2 mint path established (the post-commit fleet sweep resolves against this
    // book). Unset (or empty) → the mint path records NOTHING (byte-identical to today, the
    // pre-token-plumbing path). Single-session-honest only, mirroring `DS_SESSION_UUID`; a live
    // per-session fingerprint feed is a deferred seam outside this dataplane workspace. Paired with
    // DS_HOST_ID (below), which names the host the recorded `SessionRef` carries.
    if let Ok(fingerprint) = std::env::var(TOKEN_FINGERPRINT_ENV) {
        if !fingerprint.is_empty() {
            eprintln!(
                "ds-dnsgate: {TOKEN_FINGERPRINT_ENV} set — recording every admitted session under \
                 the scoped-token fingerprint {fingerprint:?} in the fleet-revocation book, so a \
                 pushed revocation of that token severs this gate's established flows \
                 (single-session/one-VM only)."
            );
            config.fixed_token_fingerprint = Some(fingerprint);
        }
    }
    // DS_HOST_ID (optional): the host id stamped into the fleet-revocation record's `SessionRef`
    // (doc 14 §4). Opaque to the sweep (`flush_session` joins on `tap_name`), so a stable per-gate
    // value suffices; unset → the loopback/synthetic `DEFAULT_FLEET_HOST_ID` stand-in.
    if let Ok(host_id) = std::env::var(HOST_ID_ENV) {
        if !host_id.is_empty() {
            config.host_id = Some(host_id);
        }
    }
    // DS_TOKEN_FINGERPRINT_MAP (optional, MULTI-session): a LIVE per-session scoped-token fingerprint
    // feed (doc 19 §7) — a synthetic `uuid=fingerprint` spec (comma-separated) the mint path consults
    // AT ADMISSION TIME so EACH session is recorded under its OWN token fingerprint, not the single
    // `DS_TOKEN_FINGERPRINT` stand-in. When set it TAKES PRECEDENCE over `DS_TOKEN_FINGERPRINT`: two
    // sessions admitted under two distinct tokens land two DISTINCT fleet-book rows, so a revocation
    // of one severs only its own sessions. This is the loopback/synthetic stand-in for the real
    // cross-process per-session feed (a deferred seam, D50); the spec carries fingerprint/block-id
    // only, NEVER token bytes. Unset → `None`, byte-identical to the single-session/none behavior.
    if let Some(map) = maybe_token_fingerprint_map_from_env() {
        eprintln!(
            "ds-dnsgate: {TOKEN_FINGERPRINT_MAP_ENV} set — resolving each admitted session's OWN \
             scoped-token fingerprint per-session at admission time ({} session(s) mapped), taking \
             precedence over {TOKEN_FINGERPRINT_ENV} so a per-token revocation severs only its own \
             sessions.",
            map.len(),
        );
        config.token_fingerprint_map = Some(map);
    }
    // Select the W1/W2 ADMISSION NFT-3 set programmer the SAME way the §5.4 revocation sweep
    // selects its enforcer ([`sweep_enforcer_from_env`]) — off the ONE `DS_NFTGATE_LIVE` gate, so
    // the admission insert and the revocation sweep program the SAME kernel surface in lockstep
    // (live writer when set, reportable recorder when not). Default OFF (unset) → the reportable
    // in-memory `RecordingSetProgrammer` (LOOPBACK/SYNTHETIC, no live nft kernel write — the
    // offline/CI path). SET → the production `ds_nft::NftWriter<SpawnBackend>` admission
    // programmer (`impl NftSetProgrammer for ds_nft::NftWriter<B>`, ds_dnsgate::txn) so the W1
    // set-program inserts the real kernel allow-set element carrying the W2 deadline. Because the
    // two branches spawn different `RunningGate<_, S>` types, the shared post-spawn wiring (the
    // §5.3/§5.4 subscriber, the production WatchPolicies publisher, and `block_until_done`) lives
    // in the generic [`run_gate`] helper — one body, both programmers.
    //
    // ORTHOGONAL second axis (D131 Candidate A): the DNS-2b MAP backing. Default-OFF
    // (`DS_ADMISSION_SHM_LIVE` unset) → the in-process `InMemoryAdmissionMap` (no shm; nothing for
    // a reader to attach; every existing test path unchanged). SET → the LIVE single-writer POSIX-
    // shm map over the host-wide named segment a co-host ds-tlsproxy attaches its read-only
    // `ShmAdmissionReader` to by the SAME name (single-sourced via
    // `ds_contracts::dns_admission::admission_shm_name`), so the W1/W2 transaction's admissions are
    // genuinely visible cross-process. The map axis and the programmer axis compose into the four
    // concrete `RunningGate<_, M, S>` types below; the shared post-spawn wiring (the §5.3/§5.4
    // subscriber, the WatchPolicies publisher, `block_until_done`) is the generic [`run_gate`] body.
    let nftgate_live = std::env::var_os(NFTGATE_LIVE_ENV).is_some();
    if nftgate_live {
        eprintln!(
            "ds-dnsgate: {NFTGATE_LIVE_ENV} set — binding the PRODUCTION ds_nft::NftWriter \
             admission NftSetProgrammer (W1 set-program → live kernel allow-set element carrying \
             the W2 deadline) over the spawned nft -f backend, in lockstep with the §5.4 sweep \
             enforcer. LIVE KERNEL WRITE: needs the inet ds_filter allow4 set + root/CAP_NET_ADMIN \
             (M0 host, doc 14 §11); leave this unset for the reportable offline path."
        );
    }
    if std::env::var_os(ADMISSION_SHM_LIVE_ENV).is_some() {
        // LIVE shm-backed DNS-2b map. Create-or-reattach the host-wide named segment (POSIX shm
        // persists across a ds-dnsgate restart → warm re-attach first, create on first boot); a
        // failure is FATAL — refuse the live path rather than silently fall back to an in-memory
        // map a reader cannot see (fail-closed). The shm map IS bound into the §5.4 sweep's
        // `LiveAdmissions` handle (inside `with_shm_writer`, via the now-generic
        // `bind_admission_map`), so a policy-revocation sweep tombstones the revoked `(session,
        // fqdn)` in the shm slot + decrefs the shm reverse index — a cross-process ds-tlsproxy
        // reader stops vouching a revoked domain immediately (doc 11 §5.4, D131). Host-agent
        // ownership of the segment for full warm-restart survivability is a later refinement.
        let shm_name = ds_contracts::dns_admission::admission_shm_name();
        eprintln!(
            "ds-dnsgate: {ADMISSION_SHM_LIVE_ENV} set — backing the DNS-2b admission map with the \
             D131 Candidate-A LIVE shm writer over segment {shm_name:?} (create-or-reattach); a \
             co-host ds-tlsproxy with DS_TLS1_LIVE attaches its read-only reader to the SAME name."
        );
        // The D68 re-admit-not-refuse re-resolve seam (T3): a co-host ds-tlsproxy whose
        // FORWARD gate hits a policy-allowed SNI with NO live shm admission asks ds-dnsgate
        // — the sole map writer — to re-admit it over the intra-Boundary UDS seam, and
        // PROCEEDS on the freshly admitted address (doc 12 §4.1 / doc 14 §3). The seam runs
        // the SAME W1/W2 transaction against the SAME shm-backed stores the reader reads, so
        // the fresh entry is genuinely visible cross-process. It is armed by the re-resolve
        // listen gate (a clone of `policy` shares the live evaluator's inner `Arc`, so a D72
        // reload applies to the re-admit too; a clone of `stores` is a shared-handle clone of
        // the SAME shm map). Spawned only on the shm-live path — without the shm map a
        // re-admit would write a store the reader cannot see.
        let reresolve_policy = policy.clone();
        if nftgate_live {
            let stores = AdmissionStores::with_shm_writer(
                &shm_name,
                Arc::new(NftWriter::new(SpawnBackend::new())),
                LiveAdmissions::new(),
            )
            .map_err(|e| io::Error::other(format!("admission shm writer: {e:?}")))?;
            maybe_spawn_reresolve_server(
                stores.clone(),
                reresolve_policy,
                host.admission_grace_secs,
            );
            let gate = spawn_gate_with_stores(policy, config, stores, Arc::new(NullSink)).await?;
            run_gate(gate, sweep_reevaluator).await
        } else {
            let stores = AdmissionStores::with_shm_writer(
                &shm_name,
                Arc::new(RecordingSetProgrammer::new()),
                LiveAdmissions::new(),
            )
            .map_err(|e| io::Error::other(format!("admission shm writer: {e:?}")))?;
            maybe_spawn_reresolve_server(
                stores.clone(),
                reresolve_policy,
                host.admission_grace_secs,
            );
            let gate = spawn_gate_with_stores(policy, config, stores, Arc::new(NullSink)).await?;
            run_gate(gate, sweep_reevaluator).await
        }
    } else if nftgate_live {
        let gate = spawn_gate_with_programmer(
            policy,
            config,
            Arc::new(NftWriter::new(SpawnBackend::new())),
            Arc::new(NullSink),
        )
        .await?;
        run_gate(gate, sweep_reevaluator).await
    } else {
        let gate = spawn_gate_with_programmer(
            policy,
            config,
            Arc::new(RecordingSetProgrammer::new()),
            Arc::new(NullSink),
        )
        .await?;
        run_gate(gate, sweep_reevaluator).await
    }
}

/// The shared post-spawn gate loop, GENERIC over the NFT-3 set programmer `S` the W1/W2
/// admission insert ran under (the reportable [`RecordingSetProgrammer`] on the default/offline
/// path, or the production `ds_nft::NftWriter<SpawnBackend>` behind `DS_NFTGATE_LIVE`). The
/// programmer choice is the gate's `S` type parameter; THIS body is byte-identical for both, so
/// the §5.3/§5.4 subscriber wiring and the listener block live here once. The §5.4 revocation
/// enforcer is still selected at runtime via [`sweep_enforcer_from_env`] (a `dyn` trait object),
/// off the SAME `DS_NFTGATE_LIVE` gate, so admission and revocation program one kernel surface in
/// lockstep.
async fn run_gate<
    M: ds_contracts::dns_admission::AdmissionMap + Send + Sync + 'static,
    S: NftSetProgrammer + Send + Sync + 'static,
>(
    mut gate: RunningGate<PolicyCorePolicy, M, S>,
    sweep_reevaluator: PolicyCorePolicy,
) -> io::Result<()> {
    eprintln!(
        "ds-dnsgate: listeners up — udp={} tcp={}",
        gate.udp_local_addr(),
        gate.tcp_local_addr()
    );

    // The single-per-host WatchPolicies host-snapshot SUBSCRIBER loop (doc 11 §5.3 / D72).
    // ds-dnsgate NEVER opens a control-plane policy stream (§5.3): the host agent — the
    // host's ONE WatchPolicies(from_seq) subscriber — fans the committed snapshot out
    // host-locally over this feed behind its prepare/commit barrier, and ds-dnsgate the
    // ADMITTER commits each one LAST. The PRODUCTION commit re-sources BOTH the running
    // PolicyCorePolicy evaluator (the composed document + W2 clamp window the snapshot
    // carries) AND the authored-SOA boundary zone, paired in one `SnapshotCommitSink`: a
    // committed BoundarySnapshot drives the frozen `evaluate` off that policy version, with no
    // listener re-bind and no per-transport skew. The subscriber runs on its own task, driving
    // detached reload handles, while `main` keeps the gate to block on its listeners.
    let (feed, subscription) = boundary_snapshot_feed(SNAPSHOT_FEED_CAPACITY);
    // The PRODUCTION commit sink WITH the doc 11 §5.4 revocation sweep: the gate's SHARED
    // `LiveAdmissions` registry — the SAME one the W1/W2 admission transaction mints into on every
    // `Allow` (both transports admit through it) — is handed here, alongside a `PolicyCorePolicy`
    // re-evaluator that shares the running evaluator's inner `Arc`. On a committed snapshot the
    // sink re-sources the evaluator admitter-LAST and THEN sweeps that registry, so a tightened
    // policy revokes the now-denied admissions the transaction ACTUALLY minted (the closed
    // admission ↔ revocation loop), not a fresh registry the sweep could never see.
    // The §5.4 SweepOutcome ENFORCEMENT surface the commit sink ROUTES the sweep to (the
    // refcount-zero freed allow-set element DELETES + the D53 rung-conditional conntrack FLUSH).
    // Default OFF (`DS_NFTGATE_LIVE` unset) → the reportable in-memory `RecordingSweepEnforcer`:
    // LOOPBACK/SYNTHETIC, no live nft/conntrack write. SET → the production
    // `impl SweepEnforcer for ds_nft::NftWriter<SpawnBackend>` (server.rs) over the spawned
    // `nft -f` / `conntrack -D` backend, bound over the workspace-internal `ds-nft` path-dep: leg
    // (a) the allow-set `delete element` batch via `backend().apply_batch`, leg (b) the
    // `flush_session_report(&SessionRef, &DstFilter::Only(keys), &LegSelector::sever_pair())`
    // conntrack flush. A real conntrack-flush EFFECTIVENESS assertion stays a deferred MANUAL step
    // (needs `nf_conntrack_tcp_loose=0` + CAP_NET_ADMIN, doc 14 §11); the binding is real and
    // field-for-field, and the default offline path leaves the gate UNSET so it never writes the kernel.
    let sweep_enforcer = sweep_enforcer_from_env();
    // Resolve the publisher source binding BEFORE the commit sink: on the gate-ON file-feed path it
    // carries the durable `applied_seq` cursor store the post-sweep heartbeat must persist to (so a
    // restart resumes `WatchPolicies(from_seq=applied_seq)`, D36), and that store has to be wired
    // into the heartbeat the commit sink owns. On the default-OFF idle path it carries no store.
    let publisher_binding = host_agent_policy_source();
    // The applied-seq host-agent HEARTBEAT (doc 13 §5 readiness row, D72/D36): the commit sink
    // reports each committed version's `(seq, content_hash, wire_content_hash)` identity here ONLY
    // AFTER the §5.4 revocation sweep completes, so a downstream consumer never reads an
    // `applied_seq` for a version whose now-denied admissions are not yet revoked. The production
    // carrier is the host agent's gRPC heartbeat (the shape that freezes at M0, doc 15 §5.2); the
    // operator-log heartbeat here is the LOOPBACK/SYNTHETIC stand-in — it prints the post-sweep
    // applied seq + the verified D120 wire-hash hex an operator joins the fleet `applied_seq` on.
    // On the gate-ON file-feed path the operator-log heartbeat is TEE'd with a
    // `PersistingAppliedSeqHeartbeat` that durably persists each post-sweep applied_seq to the
    // co-located cursor file (the §5 crash/restart-convergence (c) on-disk cursor), so a restart's
    // `host_agent_policy_source` reads it back as the resume `from_seq`. The persistence is reported
    // strictly after the sweep (the commit sink's fixed ordering), so the cursor never names a
    // version whose now-denied admissions are not yet revoked.
    let applied_seq_heartbeat: Arc<dyn AppliedSeqHeartbeat> =
        match &publisher_binding.applied_seq_store {
            Some(store) => Arc::new(TeeAppliedSeqHeartbeat::new(
                OperatorLogHeartbeat,
                PersistingAppliedSeqHeartbeat::new(store.clone()),
            )),
            None => Arc::new(OperatorLogHeartbeat),
        };
    // Build the SHARED reload-boundary DROP sink ONCE so both the subscriber commit sink
    // (the benign `StaleFanOut` leg) and the publisher (the integrity-rejection
    // `ContentHashMismatch` / `SchemaFailure` leg) route to the SAME observability surface.
    // Default offline/CI path → the LOOPBACK log-only `OperatorLogDropSink`; behind
    // `DS_DNSGATE_DROP_SPOOL_LIVE` → a `SpoolDropSink` over the REAL `ds_telemetry` spool
    // (D116), replacing the loopback stand-in. `_drop_spool` keeps the opened spool alive
    // for the run (dropping it would close the flush task); it is `None` on the log-only path.
    let (drop_sink, _drop_spool) = build_drop_sink().await;
    // The post-commit FLEET token-revocation sweeper (doc 19 §7; D102/P-R6, D72/D53): bind the
    // gate's shared `FleetRevocationBook` — the SAME one the W1/W2 admission mint path records a
    // session into as it admits it under a scoped token — to a concrete flusher (the offline no-op
    // by default; the production `ds_nft::NftWriter` conntrack flush behind `DS_NFTGATE_LIVE`), so
    // a pushed fleet-revocation artifact severs the flows this gate established under the revoked
    // token. `BookBackedFleetSweeper` carries the redrive buffer, so a transient flush error is
    // retried on the next commit cycle rather than dropped past an advanced `applied_seq`. Armed on
    // the commit sink below via `with_fleet_revocation_sweep`, run AFTER the §5.4 DNS-2b sweep and
    // BEFORE the applied-seq heartbeat (a fleet-sweep flush failure suppresses the heartbeat,
    // fail-closed). Until this the shipping binary never armed the sweeper — a pushed token
    // revocation severed NOTHING on the box.
    let fleet_sweeper = fleet_sweeper_from_env(gate.fleet_revocation_book());
    let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
        gate.boundary_zone_reloader(),
        gate.policy_reloader(),
        gate.live_admissions(),
        sweep_reevaluator,
        sweep_enforcer,
    )
    .with_applied_seq_heartbeat(applied_seq_heartbeat)
    .with_fleet_revocation_sweep(fleet_sweeper)
    // ROUTE the subscriber's forward-only-seq STALE-FAN-OUT drop (doc 11 §5.3 / §5.5, D72) to the
    // SAME operator-alert sink the publisher's content_hash / schema NACK drops route to
    // (`OperatorLogDropSink`, the LOOPBACK/SYNTHETIC stand-in for the production spool). Until this
    // wiring the production `SnapshotCommitSink` inherited the default no-op `observe_snapshot_drop`
    // and the subscriber's benign-dedup drop was DISCARDED; now both non-commit reasons ride one
    // observability surface, separable by their distinct `SnapshotDropReason` token (a benign
    // `StaleFanOut` here vs an integrity-rejection `ContentHashMismatch` / `SchemaFailure` from the
    // publisher leg). The drop BEHAVIOR is unchanged — the snapshot is dropped either way; this only
    // makes the dedup observable.
    .with_drop_sink(Arc::clone(&drop_sink));
    let subscriber = tokio::spawn(async move {
        let commits = watch_snapshots(subscription, &commit_sink).await;
        eprintln!("ds-dnsgate: WatchPolicies subscriber stopped after {commits} commit(s)");
    });

    // The PRODUCTION publisher half (doc 11 §5.3 / doc 13 §5, D72) — the host agent's host-local
    // committed-snapshot fan-out, driven by the host's ONE `WatchPolicies(from_seq)` subscription
    // (`ds-dnsgate` NEVER opens a control-plane stream, §5.3). `run_policy_publisher` lifts every
    // committed policy version the host agent delivers behind its prepare/commit barrier onto the
    // feed, carrying the real `(seq, content_hash)` identity; the subscriber above commits each
    // one LAST (the D35 admitter-LAST barrier). The publisher loop is the production mechanism and
    // runs on the live path; the SOURCE of committed versions is the host agent — gated EXACTLY
    // like the `DS_NFTGATE_LIVE` kernel writer. On the default offline/CI path
    // (`DS_DNSGATE_HOST_AGENT_FEED` unset) `host_agent_policy_source` resolves to an IDLE source
    // (the stream is closed → the publisher publishes nothing and the subscriber idles, ready for
    // the host agent), so NO control-plane stream is opened. SET, it binds the host-LOCAL
    // committed-snapshot feed (doc 13 §8.4 v0 file+atomic-rename): the host agent — the host's ONE
    // `WatchPolicies(from_seq)` subscriber, OUTSIDE this workspace — fans committed versions out
    // into a directory this consumer reads, resuming from the PERSISTED applied_seq (D36) the
    // post-sweep heartbeat durably writes. The publisher runs on its own task alongside the
    // subscriber + listeners; it owns the feed and drops it when its source is exhausted so the
    // subscriber drains.
    let publisher = {
        let PublisherBinding {
            source, from_seq, ..
        } = publisher_binding;
        // Decorate the publisher source with the NON-VACUOUS identity gate (POL-4 part 2;
        // D72/D120): each delivered version's PRODUCER-PINNED, SEPARATELY-transported
        // content_hash is threaded through the FROZEN Consumer::prepare_verified seam BEFORE the
        // publisher's lift. A transported-hash mismatch is NACKed host-wide at the seam and the
        // version is DROPPED (never published — the admission map is never re-sourced, the host
        // stays on vN). On the default-OFF idle path `source` delivers nothing, so the gate
        // wraps an exhausted stream and the default build / every offline test is byte-identical;
        // it only bites on the gate-ON host-local file feed (the live host-agent fan-out). The
        // publisher's own verify-only loader still runs behind it on the FORWARDED (verified)
        // versions, re-verifying the same hash idempotently and preserving its DISTINCT
        // ContentHashMismatch / SchemaFailure operator telemetry.
        let source = PrepareVerifiedGate::new(source, from_seq);
        // The publisher shares the SAME drop sink the subscriber uses (the loopback
        // `OperatorLogDropSink` by default, or the live `SpoolDropSink` over the real
        // `ds_telemetry` spool behind `DS_DNSGATE_DROP_SPOOL_LIVE`), so an
        // integrity-rejection NACK rides the identical observability surface as the
        // subscriber's benign `StaleFanOut` dedup.
        let drop_publisher = Arc::clone(&drop_sink);
        tokio::spawn(async move {
            // The publisher drives the produce-once / verify-only LOADER over any transported
            // wire bytes a delivered version carries (doc 13 §5.1): hash-check BEFORE parse, NACK
            // host-wide on a D120 content_hash mismatch (the version is never published, the host
            // stays on vN). A NACK routes to the shared drop sink as a DISTINCT
            // `ContentHashMismatch` signal — separable from the subscriber's benign forward-only-seq
            // `StaleFanOut`, so an operator never reads an integrity rejection as a routine dedup.
            let published = run_policy_publisher_with_drop_sink(
                &feed,
                source,
                from_seq,
                drop_publisher.as_ref(),
            )
            .await;
            // Dropping the feed (its last publisher) closes the host-local channel, so the
            // subscriber loop returns once it has drained the published versions.
            drop(feed);
            eprintln!("ds-dnsgate: WatchPolicies publisher stopped after {published} version(s)");
        })
    };

    let serve = gate.block_until_done().await;
    // The publisher owns the feed and drops it when its source is exhausted; await it (then the
    // subscriber) so a shutdown drains both halves of the host-local snapshot feed.
    let _ = publisher.await;
    let _ = subscriber.await;
    serve
}

/// The bound on buffered committed snapshots on the host-local feed (back-pressure on the
/// host agent's commit fan-out, never unbounded growth against the single resolver, doc 11
/// §1). Small: committed policy versions arrive at human/policy-push cadence, not per-query.
const SNAPSHOT_FEED_CAPACITY: usize = 8;

/// The env gate that binds the PRODUCTION host-LOCAL committed-snapshot feed as the publisher's
/// [`PolicyVersionSource`] — a LIVE step (the host agent is the host's ONE `WatchPolicies(from_seq)`
/// subscriber per §5.3, fanning committed versions out host-locally behind its prepare/commit
/// barrier; `ds-dnsgate` itself opens NO control-plane stream). Default-OFF: unset → the
/// [`IdlePolicySource`] (no live host agent reachable, so the publisher publishes nothing and the
/// subscriber idles, ready for the real feed — the offline/CI path). SET → the doc 13 §8.4 v0
/// file+atomic-rename [`HostLocalFeedSource`] over the feed directory (the env value when it
/// names a path, else [`DEFAULT_HOST_AGENT_FEED_DIR`]), resuming `WatchPolicies(from_seq)` from the
/// persisted [`AppliedSeqStore`] applied_seq (D36). The CROSS-PROCESS Go host-agent fan-out
/// half (the host's sole control-plane subscriber writing committed versions into that directory)
/// lives OUTSIDE this workspace (a separate host-agent task). NEVER a default-on live step.
const HOST_AGENT_FEED_ENV: &str = "DS_DNSGATE_HOST_AGENT_FEED";

/// The env gate that binds the production `ds_nft::NftWriter` enforcement surface for the §5.4
/// SweepOutcome routing (the allow-set element DELETES + the D53 rung-conditional conntrack FLUSH)
/// — a LIVE-KERNEL step. Default-OFF: unset → the reportable in-memory [`RecordingSweepEnforcer`]
/// (LOOPBACK/SYNTHETIC, no nft/conntrack write). SET → the production
/// `impl SweepEnforcer for ds_nft::NftWriter<SpawnBackend>` over the spawned `nft -f` /
/// `conntrack -D` backend (doc 11 §4). A real conntrack-flush effectiveness assertion is a
/// deferred MANUAL step (needs `nf_conntrack_tcp_loose=0` + CAP_NET_ADMIN, doc 14 §11); the
/// `cargo test --offline` path leaves this UNSET so it never writes the kernel.
const NFTGATE_LIVE_ENV: &str = "DS_NFTGATE_LIVE";

/// The env gate that backs the DNS-2b admission map with the D131 Candidate-A LIVE POSIX-shm
/// map (`ds_admission_shm::ShmAdmissionMap`) over the host-wide named segment ds-tlsproxy attaches
/// its read-only `ShmAdmissionReader` to by the SAME name — making the single-writer / many-reader
/// admission map genuinely live cross-process (doc 11 §8.4 / doc 14 §3 / OQ6). Default-OFF: unset →
/// the in-process [`ds_dnsgate::txn::InMemoryAdmissionMap`] (the offline/CI default — no shm,
/// nothing for a reader to attach, every existing test unchanged). SET → the gate creates-or-
/// reattaches the named segment ([`ds_dnsgate::txn::AdmissionStores::with_shm_writer`]) and the
/// W1/W2 insert-then-answer transaction writes through it, so a co-host ds-tlsproxy reads the live
/// admissions. The segment name is single-sourced via
/// [`ds_contracts::dns_admission::admission_shm_name`] (default `/ds-admission`, override
/// `DS_ADMISSION_SHM_NAME`). Orthogonal to `DS_NFTGATE_LIVE`: this swaps the MAP backing; that
/// swaps the NFT-3 set programmer. A shm-attach/create failure is FATAL (fail-closed: refuse to
/// serve the live path rather than silently fall back to an in-memory map a reader cannot see).
const ADMISSION_SHM_LIVE_ENV: &str = "DS_ADMISSION_SHM_LIVE";

/// The env gate that ARMS the D68 re-admit-not-refuse re-resolve seam server (T3, doc 12 §4.1 /
/// doc 14 §3) — the intra-Boundary UDS listener a co-host ds-tlsproxy dials when its FORWARD gate
/// hits a policy-allowed SNI with NO live shm admission. The env VALUE doubles as the listen path
/// (mirroring [`ds_contracts::dns_admission::admission_shm_name`]'s single-source convention via
/// `ds_dnsgate::reresolve::reresolve_endpoint`): a bare-set (`DS_DNSGATE_RERESOLVE_LISTEN=1`) or an
/// empty value falls back to the default endpoint, an explicit path pins the socket. Default-OFF:
/// unset → NO re-resolve server, so a ds-tlsproxy re-admit dial connect-fails → the gate refuses
/// fail-closed (byte-identical to today). The server is spawned ONLY on the shm-live path (it
/// re-admits into the SAME shm map the reader reads); the re-admit re-runs the SAME W1/W2 admission
/// transaction (policy re-eval + DNS-4 filter), never a parallel path.
const RERESOLVE_LISTEN_ENV: &str = ds_dnsgate::reresolve::RERESOLVE_ENDPOINT_ENV;

/// The env gate that runs the OQ2 warm-restart REBUILD demonstration against SYNTHETIC inputs
/// — a deferred manual step that exercises the rebuild path WITHOUT a live kernel set-dump or
/// real spool I/O (OQ2 rebuild posture, maintainer ruling 2026-06-14 — proposed D131, pending §6
/// ratification). Default-OFF: a production deployment leaves it unset; the real warm-restart
/// path drives the [`ds_dnsgate::warm_restart::Reconstructor`] from the live `ds-nft` kernel
/// dump + the durable §5.5 spool replay (the two `TODO(seam)` hooks). NEVER a default-on step.
const WARM_RESTART_DEMO_ENV: &str = "DS_DNSGATE_WARM_RESTART_DEMO";

/// The env gate that routes reload-boundary [`SnapshotDropEvent`]s (and the
/// [`WARM_RESTART_DEMO_ENV`] warm-restart completion event) onto the REAL shared
/// `ds_telemetry::SpoolSink` for `DnsEvent`s (doc 11 §5.5, D116) — the
/// snapshot-drop-observability / completion-telemetry LIVE leg. Its value is the path to
/// the on-disk spool SEGMENT FILE the drops + completions are spooled to.
///
/// DEFERRED MANUAL STEP / default-OFF: opening a real spool segment is live I/O, so the
/// default offline/CI path leaves it UNSET and keeps the LOOPBACK log-only
/// [`OperatorLogDropSink`] (and the warm-restart demo prints to stderr) — every existing
/// constructor/test stays byte-identical. SET to a writable path, the drop sink becomes a
/// [`SpoolDropSink`] over a `ds_telemetry::spool::Spool` opened at that path and the
/// completion demo additionally emits its envelope onto the same spool. The library-level
/// no-op default remains [`ds_dnsgate::event::NullDropSink`].
const DROP_SPOOL_LIVE_ENV: &str = "DS_DNSGATE_DROP_SPOOL_LIVE";

/// The env that selects the **production profile** (D131 shm-rollout T1, doc 13
/// §Rollout-ordering item 4: *"make the gate explicit and assert it at startup"*).
///
/// The shm admission map is "on by default IN PRODUCTION" NOT by a bare default-flip
/// of [`ADMISSION_SHM_LIVE_ENV`] (which would change the semantics of the gate-off
/// path and break every offline/CI test), but by an EXPLICIT production profile that
/// REQUIRES the WRITER gate (`DS_ADMISSION_SHM_LIVE`) and REFUSES TO BOOT without it —
/// the M1 `WithCAStore` / D56 forget-the-gate footgun guard. Presence (any value,
/// incl. empty) selects it; absence (the default) is the unchanged presence-only
/// posture (the in-process [`ds_dnsgate::txn::InMemoryAdmissionMap`] default, byte-
/// identical to today). The operator sets it on a real fleet deploy; CI/offline/the
/// test corpus never set it. Matched in ds-tlsproxy by the SAME `DS_PRODUCTION` name
/// (the reader side mandates its `DS_TLS1_LIVE` gate symmetrically).
const PRODUCTION_PROFILE_ENV: &str = "DS_PRODUCTION";

/// The OPTIONAL single-session FIXED `session_uuid` agreement (doc 11 §5.1 / D131-rollout).
///
/// The DNS-2b admission map is keyed `{session_uuid, fqdn}`. ds-dnsgate is the WRITE side; a
/// co-host ds-tlsproxy is the READ side. In the single-VM nested-KVM testbed neither process
/// can see the orchestrator's `sess-…` uuid yet (that join is a later seam, D44/D66), so the
/// two sides disagree on `session_uuid`: the gate's pre-stage token is `src:<addr>` while the
/// transparent proxy reads `""` — every FORWARD lookup misses, every served Allow falls into
/// D68 ReAdmit / `tls1-readmit-denied`. This env is the minimal cross-process key agreement:
/// when set (to e.g. `sess-2026…`), the gate stamps THIS string into every query's session, so
/// the W1/W2 AdmissionKey is written under `{DS_SESSION_UUID, fqdn}` — and a co-host
/// ds-tlsproxy stamps the SAME value into its `SessionRef::session_uuid`, so the lookup HITS.
///
/// Default-OFF: unset (the [`ds_dnsgate::GateConfig::fixed_session_uuid`] `None` default, and
/// every offline/CI/test path) keeps the pre-stage `src:<addr>` token — byte-identical to
/// today. Single-session-honest ONLY: one VM per gate (a second concurrent session would
/// cross-attribute to this one uuid); the structurally-general path is the interface-anchored
/// attribution table (`with_attribution_local` / `with_attribution_per_tap`), still deferred to
/// the orchestrator tap-registry seam. The VALUE is the uuid itself (a bare-set with an empty
/// value is treated as unset — an empty uuid would defeat the fail-closed forward miss).
const SESSION_UUID_ENV: &str = "DS_SESSION_UUID";

/// The env gate that names the scoped-token chain FINGERPRINT / block id (opaque hex; NEVER token
/// bytes) the sessions this gate admits are recorded under in the FLEET-revocation book (doc 19 §7;
/// D102/P-R6). When set to a non-empty value, every successful admission records
/// `(fingerprint → session)` so a pushed revocation of that token severs the mint path's established
/// flows; unset (or empty) records nothing (the pre-token-plumbing path, byte-identical to today).
/// Single-session-honest only, mirroring [`SESSION_UUID_ENV`].
const TOKEN_FINGERPRINT_ENV: &str = "DS_TOKEN_FINGERPRINT";

/// The env gate that names a LIVE per-session scoped-token fingerprint feed (doc 19 §7): a synthetic
/// `session_uuid=fingerprint` spec (comma-separated) the mint path consults at admission time so each
/// session is recorded under its OWN token fingerprint. Takes precedence over [`TOKEN_FINGERPRINT_ENV`]
/// (the single-session stand-in); unset → the fixed/none behavior. Loopback/synthetic stand-in for the
/// real cross-process feed (D50) — fingerprint/block-id only, never token bytes.
const TOKEN_FINGERPRINT_MAP_ENV: &str = "DS_TOKEN_FINGERPRINT_MAP";

/// The env gate that names the host id stamped into the fleet-revocation record's `SessionRef`
/// (doc 14 §4). Opaque to the sweep (`flush_session` joins on `tap_name`); unset → the
/// loopback/synthetic `DEFAULT_FLEET_HOST_ID` stand-in.
const HOST_ID_ENV: &str = "DS_HOST_ID";

/// The env gate that threads the orchestrator's per-session TAP REGISTRY into the gate — the
/// interface-anchored §5.1 / W6 attribution table (doc 11 §5.1, D44) that REPLACES the pre-stage
/// `src:<addr>` fallback with the never-recycled tap join. SOURCED FROM the orchestrator
/// session-record fan-out (the never-recycled tap registry); this side is the gate's READ VIEW.
///
/// Default-OFF: unset → no `AttributionTable` is wired
/// ([`ds_dnsgate::GateConfig::tap_registry`] `None`, and every offline/CI/test path), so the
/// handler keeps the pre-stage source token — byte-identical to today. SET to a non-empty
/// SYNTHETIC SPEC, the gate parses it into an [`ds_dnsgate::AttributionTable`] and threads it into
/// BOTH transports, which then resolve every query's session through
/// [`ds_dnsgate::AttributionTable::attribute_local`] keyed on the listener's own post-NAT LOCAL
/// address (the NFT-2 redirect target), failing closed to SERVFAIL on an unregistered interface.
///
/// The SPEC is a comma-separated list of `local_ip=tap_name[/mark_index]` entries (the mark index
/// defaults to 0 when omitted) — the LOOPBACK/SYNTHETIC stand-in for the orchestrator session
/// record, so an operator can exercise the interface-anchored join in the nested-KVM testbed
/// against a known bind address (pair it with `DS_DNSGATE_LISTEN` so the registered `local_ip`
/// matches the routed-tap redirect target). The CROSS-PROCESS orchestrator feed that populates
/// this table live (the never-recycled tap registry over the orchestrator↔dataplane seam) lives
/// OUTSIDE this dataplane workspace (D44/D66) — a DEFERRED MANUAL step; NEVER a default-on live
/// step. Takes precedence over [`SESSION_UUID_ENV`] when both are set (interface-anchored
/// attribution is the structurally-general multi-session shape).
const TAP_REGISTRY_ENV: &str = "DS_DNSGATE_TAP_REGISTRY";

/// Whether the production profile ([`PRODUCTION_PROFILE_ENV`]) is selected — presence
/// reads (any value, incl. empty), mirroring the other env-gate discipline.
fn production_profile_enabled() -> bool {
    std::env::var_os(PRODUCTION_PROFILE_ENV).is_some()
}

/// PURE, testable parse of the [`TAP_REGISTRY_ENV`] SYNTHETIC SPEC into the interface-anchored
/// [`ds_dnsgate::AttributionTable`] (doc 11 §5.1 / W6, D44) the gate threads into both transports.
///
/// The spec is a comma-separated list of `local_ip=tap_name[/mark_index]` entries: each registers
/// the never-recycled `tap_name` against the gate's own post-NAT LOCAL address `local_ip` (the
/// KEY `attribute_local` resolves on — never a guest source IP), with the 14-bit D76 mark index as
/// a disambiguator (defaulting to 0 when omitted). Whitespace around entries is trimmed and empty
/// entries (e.g. a trailing comma) are skipped. Side-effect-free (no env read, no I/O) so it is
/// unit-tested directly; the env read + `eprintln` live in [`maybe_tap_registry_from_env`].
///
/// Errors (a `String` banner the caller surfaces) on a malformed entry: a missing `=`, an empty
/// tap name, an unparseable IP, an unparseable mark index, or zero usable entries — fail-closed,
/// so a typo in the operator-supplied registry is REJECTED rather than silently producing an empty
/// table that fails every query closed.
fn parse_tap_registry(spec: &str) -> Result<ds_dnsgate::AttributionTable, String> {
    use ds_dnsgate::{AttributionTable, MarkIndex};

    let mut table = AttributionTable::new();
    let mut count = 0usize;
    for raw in spec.split(',') {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let (addr_part, rhs) = entry.split_once('=').ok_or_else(|| {
            format!("tap registry entry {entry:?} is missing '=' (want local_ip=tap_name[/idx])")
        })?;
        let local_addr: std::net::IpAddr = addr_part.trim().parse().map_err(|e| {
            format!(
                "tap registry entry {entry:?}: local_ip {:?} is not an IP: {e}",
                addr_part.trim()
            )
        })?;
        // The RHS is `tap_name` or `tap_name/mark_index`.
        let (tap_name, mark_index) = match rhs.trim().split_once('/') {
            Some((name, idx)) => {
                let counter: u32 = idx.trim().parse().map_err(|e| {
                    format!(
                        "tap registry entry {entry:?}: mark index {:?} is not a u32: {e}",
                        idx.trim()
                    )
                })?;
                (name.trim(), MarkIndex::from_counter(counter))
            }
            None => (rhs.trim(), MarkIndex::from_counter(0)),
        };
        if tap_name.is_empty() {
            return Err(format!(
                "tap registry entry {entry:?} has an empty tap name"
            ));
        }
        table.register(local_addr, tap_name, mark_index);
        count += 1;
    }
    if count == 0 {
        return Err(format!(
            "{TAP_REGISTRY_ENV} is set but parsed ZERO usable entries (want a comma-separated \
             list of local_ip=tap_name[/idx]); refusing an empty registry that would fail every \
             query closed"
        ));
    }
    Ok(table)
}

/// Resolve the optional interface-anchored tap registry from [`TAP_REGISTRY_ENV`] (doc 11 §5.1 /
/// W6, D44) — the SYNTHETIC/loopback stand-in for the orchestrator session-record fan-out, a
/// DEFERRED LIVE seam (the cross-process orchestrator feed lives outside this dataplane workspace).
///
/// Default-OFF: unset (or empty) → `None`, so [`ds_dnsgate::GateConfig::tap_registry`] stays
/// `None` and the handler keeps the pre-stage `src:<addr>` token (byte-identical to today). SET to
/// a non-empty spec → the parsed [`ds_dnsgate::AttributionTable`]. A malformed spec is FATAL
/// (`process::exit(1)`): a typo in the operator-supplied registry must refuse the boot rather than
/// silently wire a table that fails every query closed (fail-closed, mirroring the
/// `DS_DNSGATE_LISTEN` parse-panic discipline). Reads the env once; the parse itself is the pure
/// [`parse_tap_registry`].
fn maybe_tap_registry_from_env() -> Option<ds_dnsgate::AttributionTable> {
    let raw = std::env::var(TAP_REGISTRY_ENV).ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    match parse_tap_registry(&raw) {
        Ok(table) => {
            eprintln!(
                "ds-dnsgate: {TAP_REGISTRY_ENV} set — threading the orchestrator per-session TAP \
                 REGISTRY (interface-anchored §5.1/W6 attribution, D44) into both transports; the \
                 live `src:<addr>` fallback is REPLACED by the never-recycled tap join keyed on \
                 each listener's own post-NAT local address (unregistered interface → SERVFAIL \
                 fail-closed). SYNTHETIC SPEC stand-in for the orchestrator session-record fan-out \
                 (the cross-process feed is a deferred seam outside this dataplane workspace)."
            );
            Some(table)
        }
        Err(banner) => {
            eprintln!("ds-dnsgate: FATAL — {banner}");
            std::process::exit(1);
        }
    }
}

/// Parse the `DS_TOKEN_FINGERPRINT_MAP` synthetic per-session fingerprint feed (doc 19 §7) into a
/// `session_uuid → fingerprint` map — `None` when the env is unset/empty (the single-session/none
/// path). The spec is comma-separated `uuid=fingerprint` pairs; a malformed or empty pair is skipped
/// (an operator warning is logged), and an all-malformed spec yields `None` (nothing to install), so
/// a typo fails OPEN to the fixed/none behavior rather than silently mis-attributing sessions. The
/// values are OPAQUE fingerprint/block-id strings (D50) — never token bytes.
fn maybe_token_fingerprint_map_from_env() -> Option<std::collections::HashMap<String, String>> {
    let raw = std::env::var(TOKEN_FINGERPRINT_MAP_ENV).ok()?;
    if raw.trim().is_empty() {
        return None;
    }
    let mut map = std::collections::HashMap::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        match pair.split_once('=') {
            Some((uuid, fingerprint))
                if !uuid.trim().is_empty() && !fingerprint.trim().is_empty() =>
            {
                map.insert(uuid.trim().to_string(), fingerprint.trim().to_string());
            }
            _ => {
                eprintln!(
                    "ds-dnsgate: {TOKEN_FINGERPRINT_MAP_ENV} skipping malformed pair (want \
                     `uuid=fingerprint`); the affected session falls open to no fleet-book record."
                );
            }
        }
    }
    if map.is_empty() {
        None
    } else {
        Some(map)
    }
}

/// PURE, testable production-profile precondition: under the production profile the
/// shm WRITER gate (`DS_ADMISSION_SHM_LIVE`) is MANDATORY (ds-dnsgate is the SOLE
/// writer — without the live shm segment a co-host ds-tlsproxy reader has nothing to
/// attach, so the whole admission map stays in-process and invisible cross-process).
/// Off the profile this is a no-op `Ok(())`, so the bare-default path is unchanged.
///
/// `reresolve_listen` is reported back in the `Ok` arm as an operator WARNING signal
/// (the D68 re-admit re-resolve server should be up before the reader attaches so a
/// map miss re-admits instead of refusing); it never blocks startup — only the
/// writer gate is fatal. Returns `Err(banner)` (the caller emits the fatal banner +
/// non-zero exit) or `Ok(warn)` where `warn` is `Some(message)` when the re-resolve
/// listen gate is unset under the profile. Kept SIDE-EFFECT-FREE (no `process::exit`,
/// no env read) so the assertion logic is unit-tested directly.
fn requires_shm_gates(
    profile_on: bool,
    admission_shm_live: bool,
    reresolve_listen: bool,
) -> Result<Option<String>, String> {
    if !profile_on {
        // Bare default (no production profile): the gates stay opt-in/presence-only —
        // byte-identical to the pre-T1 posture. Nothing is required.
        return Ok(None);
    }
    if !admission_shm_live {
        return Err(format!(
            "ds-dnsgate: FATAL — {PRODUCTION_PROFILE_ENV} is set but the shm WRITER gate \
             {ADMISSION_SHM_LIVE_ENV} is UNSET. The production profile REQUIRES the live D131 \
             Candidate-A shm admission WRITER (ds-dnsgate is the sole map writer; without the \
             named shm segment a co-host ds-tlsproxy reader has nothing to attach and the \
             admission map stays in-process / invisible cross-process). Set \
             {ADMISSION_SHM_LIVE_ENV} (and pin DS_ADMISSION_SHM_NAME) BEFORE the reader's \
             DS_TLS1_LIVE — writer-before-reader. Refusing to boot rather than silently running \
             the in-process map (the forget-the-gate footgun). See SHM-ROLLOUT-RUNBOOK.md."
        ));
    }
    let warn = if !reresolve_listen {
        Some(format!(
            "ds-dnsgate: WARNING — {PRODUCTION_PROFILE_ENV} + {ADMISSION_SHM_LIVE_ENV} are set but \
             the D68 re-resolve listen gate ({RERESOLVE_LISTEN_ENV}) is UNSET, so a co-host \
             ds-tlsproxy re-admit (a map miss on a policy-allowed SNI) connect-fails → refuse \
             fail-closed instead of re-admitting (D68 re-admit-not-refuse). Set \
             {RERESOLVE_LISTEN_ENV} so map misses re-admit. (Non-fatal: the boundary stays \
             closed; this only narrows availability.)"
        ))
    } else {
        None
    };
    Ok(warn)
}

/// Assert the production-profile preconditions at startup and EXIT FATALLY if a
/// required gate is missing (the explicit-and-assert guard, doc 13 §Rollout item 4).
/// Reads the env ([`PRODUCTION_PROFILE_ENV`] / [`ADMISSION_SHM_LIVE_ENV`] /
/// [`RERESOLVE_LISTEN_ENV`]) and routes through the pure [`requires_shm_gates`]; on
/// `Err` it prints the fatal banner and `process::exit(1)`, on an `Ok(Some(warn))` it
/// prints the non-fatal operator warning. Off the production profile it is a silent
/// no-op, so the default boot is unchanged.
fn assert_production_profile_gates() {
    match requires_shm_gates(
        production_profile_enabled(),
        std::env::var_os(ADMISSION_SHM_LIVE_ENV).is_some(),
        std::env::var_os(RERESOLVE_LISTEN_ENV).is_some(),
    ) {
        Err(banner) => {
            eprintln!("{banner}");
            std::process::exit(1);
        }
        Ok(Some(warn)) => eprintln!("{warn}"),
        Ok(None) => {}
    }
}

/// Resolve the §5.4 SweepOutcome [`SweepEnforcer`] from the environment. Default path: the
/// reportable in-memory [`RecordingSweepEnforcer`] — no live nft/conntrack write (the
/// LOOPBACK/SYNTHETIC default the offline/CI path runs). With [`NFTGATE_LIVE_ENV`] set, this binds
/// the PRODUCTION `ds_nft::NftWriter<SpawnBackend>` adapter (the workspace-internal `ds-nft`
/// path-dep + the `impl SweepEnforcer for ds_nft::NftWriter<B>` in server.rs): the §5.4 sweep then
/// withdraws refcount-zero freed allow-set elements via a real `delete element` batch and fires the
/// D53 rung-conditional `flush_session_report(DstFilter::Only, sever_pair)` conntrack flush over the
/// freed IPs. HONEST STATUS: a real netns conntrack-flush EFFECTIVENESS assertion is a deferred
/// MANUAL step (needs `nf_conntrack_tcp_loose=0` + CAP_NET_ADMIN); the binding itself is real,
/// field-for-field, and `DS_NFTGATE_LIVE`-gated so the default offline path never touches the kernel.
fn sweep_enforcer_from_env() -> Arc<dyn SweepEnforcer> {
    if std::env::var_os(NFTGATE_LIVE_ENV).is_some() {
        eprintln!(
            "ds-dnsgate: {NFTGATE_LIVE_ENV} set — binding the PRODUCTION ds_nft::NftWriter \
             SweepEnforcer over the spawned nft -f / conntrack -D backend (the §5.4 allow-set \
             delete-element batch + the D53 rung-conditional flush_session(DstFilter::Only, \
             sever_pair)). LIVE KERNEL WRITE: effective conntrack flushing needs \
             nf_conntrack_tcp_loose=0 + CAP_NET_ADMIN (doc 14 §11); leave this unset for the \
             reportable offline path."
        );
        return Arc::new(NftWriter::new(SpawnBackend::new()));
    }
    Arc::new(RecordingSweepEnforcer::new())
}

/// The offline/CI FLEET-revocation flusher: a reportable no-op [`ds_contracts::flush::FlushSession`]
/// that touches NO kernel — the LOOPBACK/SYNTHETIC default, the fleet-sweep parallel to the §5.4
/// [`RecordingSweepEnforcer`]. It counts a sever as zero conntrack entries flushed and NEVER errors,
/// so the post-commit fleet sweep completes and `applied_seq` advances on the offline path exactly
/// as it would live — only the live `conntrack -D` write is elided. The production flush is
/// `ds_nft::NftWriter<SpawnBackend>`, bound behind [`NFTGATE_LIVE_ENV`].
#[derive(Clone, Copy, Default)]
struct OfflineFleetFlusher;

/// The (never-constructed) error surface of [`OfflineFleetFlusher`] — the offline flush never fails,
/// but `FlushSession` requires a `FlushError` associated type.
#[derive(Debug)]
struct OfflineFleetFlushError;
impl ds_contracts::flush::FlushError for OfflineFleetFlushError {}

impl ds_contracts::flush::FlushSession for OfflineFleetFlusher {
    type Error = OfflineFleetFlushError;
    fn flush_session(
        &self,
        _session: &ds_contracts::session::SessionRef,
        _dst_filter: &ds_contracts::flush::DstFilter,
        _legs: &ds_contracts::flush::LegSelector,
    ) -> Result<ds_contracts::flush::FlushOutcome, Self::Error> {
        // Reportable no-op: no kernel write, no failure (the offline path never fails closed).
        Ok(ds_contracts::flush::FlushOutcome { entries_flushed: 0 })
    }
}

/// Resolve the post-commit FLEET-revocation sweeper from the environment (doc 19 §7; D102/P-R6),
/// binding the gate's shared [`FleetRevocationBook`] (the SAME one the admission mint path records
/// into) to a concrete flusher — the fleet-sweep twin of [`sweep_enforcer_from_env`], off the SAME
/// [`NFTGATE_LIVE_ENV`] gate so the §5.4 DNS-2b sweep and the fleet-token sweep sever through ONE
/// kernel surface. Default path (unset): the reportable [`OfflineFleetFlusher`] (LOOPBACK/SYNTHETIC,
/// no live conntrack write). SET: the production `ds_nft::NftWriter<SpawnBackend>` over the spawned
/// `conntrack -D` backend — the D53 rung-conditional `flush_session(DstFilter::All, sever_pair)`
/// severing every destination a revoked token's session reached. Either way the returned
/// [`BookBackedFleetSweeper`] carries the redrive buffer, so a transient flush error is retried on
/// the next commit cycle rather than dropped past an advanced `applied_seq`, and its redrive buffer
/// is CAPPED with an [`OperatorLogFleetRedriveAlertSink`] so a SUSTAINED kernel/conntrack outage
/// alerts on the operator log (count-only, never token bytes) rather than growing without bound.
fn fleet_sweeper_from_env(book: FleetRevocationBook) -> Arc<dyn FleetRevocationSweeper> {
    // The operator-log redrive alert (the loopback stand-in for the production spool) fires when the
    // fleet flush has been unreachable for a sustained run of commits OR the redrive buffer overflows
    // its cap — the redrive twin of the `OperatorLogDropSink` reload-boundary alert.
    let alert_sink: Arc<dyn FleetRedriveAlertSink> = Arc::new(OperatorLogFleetRedriveAlertSink);
    if std::env::var_os(NFTGATE_LIVE_ENV).is_some() {
        eprintln!(
            "ds-dnsgate: {NFTGATE_LIVE_ENV} set — binding the PRODUCTION ds_nft::NftWriter \
             fleet-revocation flusher over the spawned conntrack -D backend (the D53 \
             rung-conditional flush_session(DstFilter::All, sever_pair) severing every destination \
             a revoked token's session reached). LIVE KERNEL WRITE: effective conntrack flushing \
             needs nf_conntrack_tcp_loose=0 + CAP_NET_ADMIN (doc 14 §11); leave this unset for the \
             reportable offline path."
        );
        return Arc::new(
            BookBackedFleetSweeper::new(book, NftWriter::new(SpawnBackend::new()))
                .with_redrive_alert_sink(alert_sink),
        );
    }
    Arc::new(
        BookBackedFleetSweeper::new(book, OfflineFleetFlusher).with_redrive_alert_sink(alert_sink),
    )
}

/// Spawn the D68 re-admit re-resolve seam server (T3) iff [`RERESOLVE_LISTEN_ENV`] is set —
/// the intra-Boundary UDS listener a co-host ds-tlsproxy dials to re-admit a policy-allowed SNI
/// whose live shm admission lapsed (doc 12 §4.1 / doc 14 §3). Called ONLY on the shm-live path so
/// the re-admit writes the SAME shm map the reader reads (`stores` is a shared-handle clone of the
/// gate's shm-backed stores; `policy` shares the live evaluator's inner `Arc`, so a D72 reload
/// applies to the re-admit too; `grace_secs` is the live POL-1 grace off the snapshot). The seam
/// runs the SAME W1/W2 admission transaction the forward path runs (policy re-eval + DNS-4 filter +
/// insert-then-answer), never a parallel path. Default-OFF (unset): no server is spawned, so a
/// ds-tlsproxy re-admit dial connect-fails and the gate refuses fail-closed — byte-identical to
/// today. A bind failure is logged and the server is simply not spawned (the dial then fails closed
/// at the reader); it never gates ds-dnsgate startup.
fn maybe_spawn_reresolve_server<S>(
    stores: AdmissionStores<ds_admission_shm::ShmAdmissionMap, S>,
    policy: PolicyCorePolicy,
    grace_secs: u32,
) where
    S: NftSetProgrammer + Send + Sync + 'static,
{
    if std::env::var_os(RERESOLVE_LISTEN_ENV).is_none() {
        return;
    }
    let endpoint = ds_dnsgate::reresolve::reresolve_endpoint();
    // A stale socket from a prior run blocks the bind; remove it first (the path is the
    // single-sourced endpoint, never a live FD).
    let _ = std::fs::remove_file(&endpoint);
    let listener = match tokio::net::UnixListener::bind(&endpoint) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "ds-dnsgate: {RERESOLVE_LISTEN_ENV} set but binding the re-resolve UDS at \
                 {endpoint:?} failed: {e}; the seam is NOT served (a ds-tlsproxy re-admit dial \
                 then fails closed at the reader). Ensure the parent directory exists and is writable."
            );
            return;
        }
    };
    eprintln!(
        "ds-dnsgate: {RERESOLVE_LISTEN_ENV} set — serving the D68 re-admit re-resolve seam on \
         {endpoint:?}; a co-host ds-tlsproxy with DS_TLS1_LIVE dials it to re-admit a policy-allowed \
         SNI whose shm admission lapsed (re-runs the SAME W1/W2 admission transaction into the SAME \
         shm map)."
    );
    // The PRODUCTION re-resolve body: the live hickory upstream forwarder (the ONLY hickory edge,
    // in handler.rs), the live policy evaluator, and the shm-backed admission stores. Built behind
    // the hickory-free `ReResolveSeam` so the transport stays framework-light.
    let resolver =
        ds_dnsgate::handler::LiveReResolver::new(&ds_dnsgate::handler::ForwarderConfig::default());
    let seam = Arc::new(ds_dnsgate::reresolve::AdmissionReResolver::new(
        resolver,
        Arc::new(policy),
        stores,
        grace_secs,
    ));
    tokio::spawn(async move {
        ds_dnsgate::reresolve::serve_reresolve(listener, seam).await;
        eprintln!("ds-dnsgate: re-resolve seam server stopped");
    });
}

/// Run the OQ2 warm-restart REBUILD demonstration iff [`WARM_RESTART_DEMO_ENV`] is set — the
/// deferred manual step that exercises the rebuild path against SYNTHETIC inputs (OQ2 rebuild
/// posture, maintainer ruling 2026-06-14 — proposed D131, pending §6 ratification). It stands up a
/// synthetic kernel NFT-3 set dump (`TODO(seam: ds-nft kernel dump)`: in production the live
/// `ds-nft` kernel set-dump read) and a synthetic §5.5 `DnsEvent` spool replay
/// (`TODO(seam: spool replay)`: in production a bounded durable-spool replay), runs the
/// [`Reconstructor`] over them, and prints the [`RebuildReport`]. NO live kernel, NO real spool
/// I/O — the two production inputs are the trait-seam hooks. The synthetic corpus exercises every
/// invariant: a fully-substantiated `(session, fqdn)` entry (adopts the kernel deadline, W2
/// lockstep), a shared-CDN IP across two names (refcount 2), and a kernel-resident IP the spool
/// could not substantiate (OMITTED fail-closed, never fabricated — TLS-1 re-admits it live). The
/// demonstration never gates startup.
async fn maybe_demo_warm_restart_rebuild() {
    use std::net::{IpAddr, Ipv4Addr};

    use ds_contracts::dns_admission::{AdmissionType, Instant, Provenance};
    use ds_dnsgate::warm_restart::{
        KernelElement, KernelSetDump, Reconstructor, SpoolRecord, SpoolReplayCorpus,
    };

    if std::env::var_os(WARM_RESTART_DEMO_ENV).is_none() {
        return;
    }

    eprintln!(
        "ds-dnsgate: {WARM_RESTART_DEMO_ENV} set — running the OQ2 warm-restart REBUILD \
         demonstration against SYNTHETIC inputs (a synthetic kernel NFT-3 set dump + a synthetic \
         §5.5 DnsEvent spool replay; the production ds-nft kernel-dump read and durable-spool \
         replay are the TODO(seam) hooks). NO live kernel, NO real spool I/O. OQ2 rebuild posture, \
         maintainer ruling 2026-06-14 (proposed D131, pending §6 ratification)."
    );

    let session = "warm-restart-demo-session";
    let nanos_per_sec: u64 = 1_000_000_000;
    let deadline = Instant::from_unix_nanos(2_000 * nanos_per_sec);
    let admitted_at = Instant::from_unix_nanos(1_000 * nanos_per_sec);
    let provenance = Provenance {
        rule_id: "demo-allow".to_string(),
        policy_layer: "org".to_string(),
        policy_version: "pol1/v0".to_string(),
    };

    let shared_cdn_ip = IpAddr::V4(Ipv4Addr::new(151, 101, 1, 1));
    let sole_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let unsubstantiated_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

    // The kernel dump persisted three IPs across the restart, each carrying the W2-authoritative
    // element deadline the rebuild ADOPTS (never recomputes). One IP (`unsubstantiated_ip`) has no
    // recoverable spool provenance and must be OMITTED fail-closed.
    let kernel = KernelSetDump::new()
        .with_element(
            session,
            KernelElement {
                ip: shared_cdn_ip,
                deadline,
            },
        )
        .with_element(
            session,
            KernelElement {
                ip: sole_ip,
                deadline,
            },
        )
        .with_element(
            session,
            KernelElement {
                ip: unsubstantiated_ip,
                deadline,
            },
        );

    // The spool replay recovered provenance for the shared CDN IP (under two names → refcount 2)
    // and the sole IP — but NOT the unsubstantiated IP (a lossy-spool gap).
    let record = |fqdn: &str, ips: Vec<IpAddr>| SpoolRecord {
        session_uuid: session.to_string(),
        original_query_fqdn: fqdn.to_string(),
        admitted_ips: ips,
        admission_type: AdmissionType::Normal,
        real_targets: vec![],
        provenance: provenance.clone(),
        admitted_at,
    };
    let spool = SpoolReplayCorpus::new()
        .with_record(record("a.cdn.demo.", vec![shared_cdn_ip]))
        .with_record(record("b.cdn.demo.", vec![shared_cdn_ip]))
        .with_record(record("sole.demo.", vec![sole_ip]));

    let (_map, report) = Reconstructor::new().rebuild(&kernel, &spool);

    eprintln!(
        "ds-dnsgate: warm-restart rebuild complete — {} entr{} rebuilt, {} kernel IP(s) \
         substantiated (per-name reference count), {} distinct kernel element(s) substantiated, \
         {} provenance gap(s) OMITTED fail-closed (TLS-1 re-admits those live), reconciles={}. \
         Gaps: {:?}",
        report.entries_rebuilt,
        if report.entries_rebuilt == 1 {
            "y"
        } else {
            "ies"
        },
        report.ips_substantiated,
        report.distinct_ips_substantiated,
        report.provenance_gaps.len(),
        report.reconciles_with(&kernel),
        report.provenance_gaps,
    );

    // The rebuild-distinct-count OBSERVABILITY leg: project the report onto the
    // convention-layer warm-restart COMPLETION event (carrying the
    // `distinct_ips_substantiated` scalar + the derived `reconciles` bit) and — behind the
    // SAME `DS_DNSGATE_DROP_SPOOL_LIVE` env gate the snapshot-drop leg uses — route it onto
    // the REAL `ds_telemetry` spool (D116), so an operator observes restart-substantiation
    // coverage live on the same spool the drops ride. DEFERRED MANUAL/LIVE leg: opens a real
    // spool segment; default-OFF the completion is the stderr line above only.
    let completion = report.completion_event(
        &kernel,
        ds_dnsgate::event::EventProvenance {
            rule_id: provenance.rule_id.clone(),
            policy_layer: provenance.policy_layer.clone(),
            policy_version: provenance.policy_version.clone(),
        },
    );
    if let Some(path) = std::env::var_os(DROP_SPOOL_LIVE_ENV) {
        let path = PathBuf::from(path);
        match ds_telemetry::spool::Spool::open(&path, ds_telemetry::spool::SpoolBounds::default())
            .await
        {
            Ok(spool) => {
                if let Ok(envelope) = completion.to_envelope() {
                    use ds_telemetry::event::EventSink as _;
                    spool.sink().emit(envelope);
                    eprintln!(
                        "ds-dnsgate: warm-restart completion event spooled to {} \
                         (distinct_ips_substantiated={}, reconciles={})",
                        path.display(),
                        completion.distinct_ips_substantiated,
                        completion.reconciles,
                    );
                }
                // Drain + close the flush task so the completion record is flushed to disk
                // before the demo returns (the demo is a one-shot, not a long-lived emitter).
                let _ = spool.shutdown().await;
            }
            Err(err) => {
                eprintln!(
                    "ds-dnsgate: WARNING — could not open the completion spool at {} ({err}); \
                     the warm-restart completion is the stderr line above only.",
                    path.display(),
                );
            }
        }
    }
}

/// The publisher's resolved [`PolicyVersionSource`] binding (doc 11 §5.3 / doc 13 §5, D72/D36): the
/// source itself, the `WatchPolicies(from_seq)` resume cursor it starts from, and — on the gate-ON
/// path — the [`AppliedSeqStore`] the post-sweep heartbeat persists each applied_seq to so a restart
/// resumes that cursor. Returned by [`host_agent_policy_source`] and consumed by the publisher
/// wiring in [`serve_until_shutdown`].
struct PublisherBinding {
    /// The source the publisher drives onto the host-local feed (gate-OFF idle / gate-ON file feed).
    source: PublisherSource,
    /// The `WatchPolicies(from_seq)` resume cursor — `0` on the idle/fresh path, the persisted
    /// applied_seq on a gate-ON restart (D36), so the publisher resumes rather than replays history.
    from_seq: u64,
    /// The durable applied_seq cursor store, present only on the gate-ON file-feed path. The
    /// post-sweep heartbeat persists each applied_seq here; `None` on the idle path (nothing to
    /// persist — the publisher fans nothing out).
    applied_seq_store: Option<AppliedSeqStore>,
}

/// The publisher [`PolicyVersionSource`] resolved from the environment — the default-OFF idle stream
/// or the gate-ON host-local file feed. An enum (not a boxed trait object) so the single publisher
/// task drives ONE concrete `impl PolicyVersionSource` whichever path is selected; the publisher
/// MECHANISM (`run_policy_publisher_with_drop_sink`) is identical on both.
enum PublisherSource {
    /// Default-OFF ([`HOST_AGENT_FEED_ENV`] unset): an EXHAUSTED stream — no live host agent, no
    /// control-plane stream, the publisher fans nothing out and the subscriber idles (§5.3).
    Idle(IdlePolicySource),
    /// Gate-ON, v0 transport: the host-local committed-snapshot FILE feed the host agent fans out
    /// (doc 13 §8.4 file+atomic-rename) — the default gate-ON path.
    File(HostLocalFeedSource),
    /// Gate-ON, PRODUCTION transport: the LIVE host-local UDS `WatchPolicies(from_seq)` carrier the
    /// host agent serves (doc 11 §5.3 / doc 13 §5, D72/D36/D120). Selected when the gate value names
    /// a `uds:<path>` endpoint; the directly-driven sibling of the v0 file feed.
    Carrier(WatchPoliciesCarrierSource),
}

impl PolicyVersionSource for PublisherSource {
    async fn next_version(&mut self) -> Option<ds_dnsgate::server::CommittedPolicyVersion> {
        match self {
            PublisherSource::Idle(s) => s.next_version().await,
            PublisherSource::File(s) => s.next_version().await,
            PublisherSource::Carrier(s) => s.next_version().await,
        }
    }
}

/// Resolve the publisher's [`PolicyVersionSource`] from the environment, paired with the
/// `WatchPolicies(from_seq)` resume cursor and the durable applied_seq store (doc 11 §5.3 / doc 13
/// §5, D72/D36).
///
/// Default path ([`HOST_AGENT_FEED_ENV`] unset): the [`IdlePolicySource`] — NO live host agent is
/// reachable, so the publisher publishes nothing and the subscriber idles, ready for the real
/// feed. This is the offline/CI path: `ds-dnsgate` opens NO control-plane stream (§5.3), and the
/// production publisher MECHANISM still runs on the live path (it just has nothing to fan out). The
/// resume cursor is `0` and there is no cursor store (nothing is fanned out to persist).
///
/// SET: the host agent's `WatchPolicies(from_seq)` feed, materialized host-locally as the doc 13
/// §8.4 v0 **file + atomic-rename** transport — the host agent (the host's ONE control-plane policy
/// subscriber, outside this workspace) fans committed versions out into a directory this consumer
/// reads (`ds-dnsgate` still opens NO control-plane stream itself, §5.3). The directory is
/// `$DS_DNSGATE_HOST_AGENT_FEED` when it names a path, else [`DEFAULT_HOST_AGENT_FEED_DIR`]. The
/// resume cursor is the PERSISTED applied_seq (the post-sweep `WatchPolicies(from_seq)` resume
/// point, D36) read from the co-located [`AppliedSeqStore`] — so a restart resumes rather than
/// replays committed history; the publisher's forward-only guard
/// (`version.seq < from_seq → continue`) then drops any re-delivered version at or below it. Gated
/// EXACTLY like the live `ds-nft` writer (`DS_NFTGATE_LIVE`): NEVER a default-on live step.
fn host_agent_policy_source() -> PublisherBinding {
    let Some(raw) = std::env::var_os(HOST_AGENT_FEED_ENV) else {
        // Default OFF: no host agent reachable — the idle stream, a fresh cursor, no persistence.
        return PublisherBinding {
            source: PublisherSource::Idle(IdlePolicySource),
            from_seq: 0,
            applied_seq_store: None,
        };
    };
    // Gate ON: select the transport off the env VALUE. A `uds:<path>` value selects the PRODUCTION
    // LIVE host-local UDS `WatchPolicies(from_seq)` carrier (doc 11 §5.3 / doc 13 §5) the host agent
    // serves; any other value (a bare-set `1`, an empty value, or a directory path) keeps the v0
    // file+atomic-rename feed (doc 13 §8.4) — so the existing gate-ON file-feed behavior + tests are
    // byte-identical and the carrier is purely additive. The carrier's resume cursor still rides the
    // co-located persisted applied_seq (D36): the carrier and the file feed both live under a
    // host-local directory the host agent owns, so the applied_seq the post-sweep heartbeat persists
    // is the restart resume point either way.
    let raw_str = raw.to_str();
    if let Some(endpoint) = raw_str.and_then(parse_carrier_endpoint) {
        // The carrier's resume cursor + applied_seq persistence are co-located in the PARENT
        // directory of the socket (the host-local feed directory the host agent owns), so a restart
        // resumes WatchPolicies(from_seq=applied_seq) exactly as the file feed does.
        let cursor_dir = std::path::Path::new(&endpoint)
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_HOST_AGENT_FEED_DIR));
        let applied_seq_store = AppliedSeqStore::in_dir(&cursor_dir);
        let from_seq = applied_seq_store.load();
        eprintln!(
            "ds-dnsgate: {HOST_AGENT_FEED_ENV}=uds:… set — consuming the LIVE host-local UDS \
             WatchPolicies(from_seq={from_seq}) carrier (doc 11 §5.3 / doc 13 §5) at {endpoint:?}, \
             resuming from the persisted applied_seq (D36) co-located in {}. ds-dnsgate DIALS the \
             host-agent feed; it opens NO control-plane stream of its own (§5.3) — the host agent is \
             the host's sole upstream WatchPolicies subscriber and SERVES this socket.",
            cursor_dir.display(),
        );
        return PublisherBinding {
            source: PublisherSource::Carrier(WatchPoliciesCarrierSource::connect_to(
                endpoint, from_seq,
            )),
            from_seq,
            applied_seq_store: Some(applied_seq_store),
        };
    }
    // The v0 file feed (doc 13 §8.4). The env value names the feed directory when it is a non-empty
    // path; bare-set (`DS_DNSGATE_HOST_AGENT_FEED=1`, the gate convention) falls back to the default
    // host-local path so an operator can flip the gate without a path.
    let dir = match raw_str {
        Some(s) if !s.is_empty() && s != "1" => PathBuf::from(s),
        _ => PathBuf::from(DEFAULT_HOST_AGENT_FEED_DIR),
    };
    // Resume from the persisted applied_seq (D36): a fresh host with no cursor reads `0`
    // (`WatchPolicies(from_seq=0)`, replay from the first committed version); a restart reads the
    // last post-sweep applied_seq so it resumes rather than replays.
    let applied_seq_store = AppliedSeqStore::in_dir(&dir);
    let from_seq = applied_seq_store.load();
    eprintln!(
        "ds-dnsgate: {HOST_AGENT_FEED_ENV} set — consuming the host-local committed-snapshot feed \
         (doc 13 §8.4 file+atomic-rename) at {} resuming WatchPolicies(from_seq={from_seq}) from \
         the persisted applied_seq (D36). ds-dnsgate opens NO control-plane stream (§5.3); the host \
         agent is the host's sole WatchPolicies subscriber and fans versions out into this directory.",
        dir.display(),
    );
    PublisherBinding {
        source: PublisherSource::File(HostLocalFeedSource::resume_from(dir, from_seq)),
        from_seq,
        applied_seq_store: Some(applied_seq_store),
    }
}

/// Parse a `DS_DNSGATE_HOST_AGENT_FEED` value as a LIVE UDS `WatchPolicies` carrier endpoint, or
/// `None` if it selects the v0 file feed instead (doc 11 §5.3 / doc 13 §8.4). The carrier is opted
/// into by a `uds:<path>` prefix — explicit so the default gate-ON path (a bare `1` or a directory)
/// stays the file feed and the carrier is purely additive. A `uds:` prefix with no path falls back
/// to the default endpoint ([`DEFAULT_HOST_AGENT_FEED_SOCK`]) so an operator can flip the carrier
/// without naming a socket, mirroring the file-feed bare-set convention.
fn parse_carrier_endpoint(value: &str) -> Option<String> {
    let path = value.strip_prefix("uds:")?;
    if path.is_empty() {
        Some(DEFAULT_HOST_AGENT_FEED_SOCK.to_string())
    } else {
        Some(path.to_string())
    }
}

/// The default host-local UDS endpoint the host agent serves the `WatchPolicies(from_seq)` carrier
/// on (doc 11 §5.3) when [`HOST_AGENT_FEED_ENV`] is set to a bare `uds:` with no explicit path. The
/// socket is co-located under the host-local feed directory the host agent owns (the same directory
/// the file feed + the persisted applied_seq cursor live in), so the §5 reload is one directory.
/// Both halves agree on this path out of band (the cross-process contract the host-agent task owns).
const DEFAULT_HOST_AGENT_FEED_SOCK: &str = "/run/ds-dnsgate/policy-feed/watch.sock";

/// The default host-local committed-snapshot feed directory (doc 13 §8.4) when
/// [`HOST_AGENT_FEED_ENV`] is set without an explicit path. The host agent atomic-renames committed
/// `<seq>.snapshot` files (and the `applied_seq` cursor) here; both halves agree on this path out of
/// band (the cross-process contract the separate host-agent task owns).
const DEFAULT_HOST_AGENT_FEED_DIR: &str = "/run/ds-dnsgate/policy-feed";

/// The default-path [`PolicyVersionSource`]: an EXHAUSTED `WatchPolicies(from_seq)` stream — no
/// live host agent is reachable, so it delivers no committed versions. The production publisher
/// still runs over it (the live mechanism is unconditional); it simply publishes nothing, and the
/// subscriber idles ready for the real host-agent feed. This is what keeps `ds-dnsgate` from
/// opening any control-plane stream on the offline/CI path (§5.3). The live host-agent binding
/// replaces this behind [`HOST_AGENT_FEED_ENV`].
struct IdlePolicySource;

impl PolicyVersionSource for IdlePolicySource {
    async fn next_version(&mut self) -> Option<ds_dnsgate::server::CommittedPolicyVersion> {
        // The stream is closed from the start: no host agent fans anything out.
        None
    }
}

/// The LIVE-INGEST NON-VACUOUS identity gate over the host-local committed-snapshot feed
/// (POL-4 part 2; D72/D120, doc 13 §5.1). It DECORATES the gate-ON
/// [`HostLocalFeedSource`] so every version the host agent fans out — carrying the
/// PRODUCER-PINNED, SEPARATELY-transported `content_hash` ALONGSIDE the bytes — is routed
/// through the frozen [`ds_contracts::consumer::Consumer::prepare_verified`] seam BEFORE it
/// reaches the publisher's lift.
///
/// # Why this exists (the gap this closes)
///
/// loop-2 made [`Consumer::prepare_verified`] the NON-VACUOUS identity gate
/// (verify-the-SEPARATELY-transported-hash-BEFORE-parse, NACK [`PrepareError::HashMismatch`]
/// fail-closed) in [`ds_dnsgate::apply::PolicyConsumer`]. But until now that gate was
/// reachable on the LIVE path only as the additive override exercised by per-file unit
/// tests: the live feed ingest entered via the publisher's own verify and never threaded the
/// transported `content_hash` through the FROZEN Consumer seam. This decorator threads it:
/// for each delivered version that carries its produce-once wire form
/// (`(seq, content_hash, transported bytes)`), it calls
/// `prepare_verified(transported, version, &content_hash)` on a gate-local
/// [`apply::PolicyConsumer`] as the identity gate (the SAME real gate ds-tlsproxy's
/// `snapshot_feed` dispatcher applies — its `SnapshotEnvelope::with_hash` carries the explicit
/// hash, its `dispatch` verifies before prepare). On a HashMismatch the version is DROPPED —
/// never forwarded to the publisher's lift, never published, so the admission map is NEVER
/// re-sourced and the gate STAYS ON `vN` (host-wide fail-closed, the host never advances). A
/// verified version forwards UNCHANGED, so the publisher's existing verify-only loader +
/// `(seq, content_hash)` lift runs byte-identically behind it (the two gates agree on verified
/// bytes — idempotent; this only short-circuits the tampered case at the frozen seam).
///
/// `prepare_verified` STAGES into the gate-local consumer; it never flips and the staged slot
/// is intentionally not consumed (the real evaluator re-source happens via the publisher's
/// `BoundarySnapshot` commit path, admitter-LAST, D72). The consumer here is the IDENTITY GATE
/// ONLY — its sole observable effect is the verify-before-parse verdict that gates publication.
///
/// Reachable ONLY on the gate-ON file-feed path ([`HOST_AGENT_FEED_ENV`] set) — the default
/// idle path is never decorated, so the default build + every offline/CI test is byte-identical.
/// A version with NO transported wire form (`wire: None`, the in-memory loopback hand-off)
/// passes through UNGATED: there is no separately-transported hash to verify, so the
/// non-vacuous gate does not apply (the bare in-process path keeps its existing semantics).
///
/// NEVER-LOG-THE-SECRET: nothing here logs the snapshot bytes; a drop logs only the structural
/// reason + the seq.
struct PrepareVerifiedGate<P: PolicyVersionSource> {
    inner: P,
    /// The gate-local [`Consumer`] whose `prepare_verified` IS the non-vacuous identity gate.
    /// Seeded once from a minimal valid POL-1 baseline at the resume seq; the verify-before-parse
    /// check is content-INDEPENDENT (it compares the transported bytes' hash to the producer's
    /// pinned hash before any parse), so the seed's content never feeds a decision — it only makes
    /// a well-formed consumer to host the frozen gate.
    gate: ds_dnsgate::apply::PolicyConsumer,
}

impl<P: PolicyVersionSource> PrepareVerifiedGate<P> {
    /// A minimal valid POL-1 session baseline used purely to seed the gate-local consumer (the
    /// identity gate is content-independent; see the field doc). Parses with zero PolicyErrors.
    const SEED_DOC: &'static str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n";

    /// Wrap `inner` with the non-vacuous identity gate, seeding the gate-local consumer at
    /// `from_seq` (the `WatchPolicies(from_seq)` resume cursor — its value never feeds the verify,
    /// which is keyed by the per-version transported `content_hash`).
    fn new(inner: P, from_seq: u64) -> Self {
        let layer = parse_layer(Self::SEED_DOC).expect("the POL-1 gate seed baseline parses");
        let gate = ds_dnsgate::apply::PolicyConsumer::new(
            ds_dnsgate::apply::Evaluator::from_layer(&layer),
            ds_contracts::consumer::PolicyVersion(from_seq),
        );
        Self { inner, gate }
    }
}

impl<P: PolicyVersionSource + Send> PolicyVersionSource for PrepareVerifiedGate<P> {
    async fn next_version(&mut self) -> Option<ds_dnsgate::server::CommittedPolicyVersion> {
        use ds_contracts::consumer::{Consumer, PolicyVersion, PrepareError};
        // Drain forward: a version DROPPED by the non-vacuous gate (a transported-hash mismatch)
        // is skipped and the NEXT version pulled, so a tampered snapshot never reaches the
        // publisher's lift — the host stays on vN and keeps draining (host-wide fail-closed; the
        // host agent attributes the abort off the absence of the version's ACK).
        loop {
            let version = self.inner.next_version().await?;
            let Some(wire) = version.wire.as_ref() else {
                // No separately-transported hash (the in-memory loopback hand-off): the
                // non-vacuous gate does not apply — pass through with the existing semantics.
                return Some(version);
            };
            // Thread the producer-pinned, SEPARATELY-transported content_hash into the FROZEN
            // Consumer::prepare_verified seam — the non-vacuous identity gate. A mismatch is
            // fail-closed HashMismatch BEFORE parse/stage; the admission map is never re-sourced.
            match self.gate.prepare_verified(
                &wire.transported,
                PolicyVersion(version.seq),
                &wire.content_hash,
            ) {
                // HashMismatch: the transported bytes do not hash to the producer's pinned
                // content_hash (a tampered/torn transport, D120). DROP — never publish; the gate
                // stays on vN. Content-free log line (NEVER-LOG-THE-SECRET): seq only.
                Err(PrepareError::HashMismatch { .. }) => {
                    eprintln!(
                        "ds-dnsgate: live-ingest prepare_verified NACK (HashMismatch) for seq {} — \
                         transported content_hash mismatch; version DROPPED, host stays on vN \
                         (non-vacuous identity gate, D72/D120 host-wide fail-closed)",
                        version.seq
                    );
                    continue;
                }
                // Verified (Ok), or a verified-but-unparseable / un-stageable version
                // (SchemaInvalid / StageFailed): forward UNCHANGED. The publisher's own
                // verify-only loader then re-verifies the same hash (idempotent on verified
                // bytes) and routes a schema failure to its DISTINCT ContentHashMismatch/
                // SchemaFailure drop sink — the existing operator telemetry is preserved
                // byte-identically. The non-vacuous gate's job is the transported-hash NACK,
                // which it has now applied at the frozen seam.
                Ok(_)
                | Err(PrepareError::SchemaInvalid { .. } | PrepareError::StageFailed { .. }) => {
                    return Some(version);
                }
            }
        }
    }
}

/// The operator-log applied-seq HEARTBEAT (doc 13 §5 readiness row, D72/D36) — the
/// LOOPBACK/SYNTHETIC stand-in for the host agent's gRPC heartbeat carrier (whose shape freezes at
/// M0, doc 15 §5.2). The [`SnapshotCommitSink`] reports each committed version's identity here
/// ONLY AFTER the §5.4 revocation sweep completes, so the printed `applied_seq` always reflects a
/// version whose now-denied admissions are already revoked. It prints the forward-only `seq`, the
/// per-version local fingerprint, and the verified D120 wire-hash hex an operator joins the fleet
/// `applied_seq` (min-over-three) on. A production deployment swaps in the host agent's heartbeat
/// carrier; this never gates anything (a printed line, no transport).
struct OperatorLogHeartbeat;

impl AppliedSeqHeartbeat for OperatorLogHeartbeat {
    fn report_applied_seq(&self, identity: AppliedSeqIdentity) {
        eprintln!(
            "ds-dnsgate: applied_seq={} (post-sweep) content_hash={:#018x} wire_content_hash={}",
            identity.seq,
            identity.content_hash,
            identity.wire_content_hash_hex(),
        );
    }
}

/// The operator-log reload-boundary DROP sink (doc 11 §5.5 / doc 13 §5.1) — the LOOPBACK/SYNTHETIC
/// stand-in for the spool the production wiring routes drops to. It makes the DISTINCT non-commit
/// reasons separable in operator logs: a [`SnapshotDropReason::ContentHashMismatch`] is a D120
/// integrity REJECTION (the transport's wire hash did not verify — a tampered/corrupt transport),
/// a [`SnapshotDropReason::SchemaFailure`] is the OTHER integrity rejection (verified bytes that
/// failed the POL-1 parse — a bad authored/composed document), and both NACK host-wide the SAME
/// way (the host stays on the prior version) — an operator must act on either. A
/// [`SnapshotDropReason::StaleFanOut`] is the benign forward-only-seq dedup (nothing to chase). The
/// greppable `reason=` token leads the line so a downstream consumer joins on it. Infallible (a
/// dropped log line never changes which snapshots commit).
struct OperatorLogDropSink;

/// Emit the operator-log line for one reload-boundary drop — the greppable
/// `reason=`-led line both [`OperatorLogDropSink`] and the spool-routing
/// [`SpoolDropSink`] write (so the operator log is identical whether or not the
/// drop ALSO rides the real spool). Factored out so the spool leg reuses it
/// verbatim, never forking the operator-facing text.
fn operator_log_drop_line(drop: &SnapshotDropEvent) {
    let class = match drop.reason {
        SnapshotDropReason::ContentHashMismatch => {
            "D120 content_hash NACK — host-wide rejection, host stays on prior version"
        }
        SnapshotDropReason::SchemaFailure => {
            "POL-1 schema failure — verified bytes failed to parse, host-wide rejection, \
             host stays on prior version"
        }
        SnapshotDropReason::StaleFanOut => "benign forward-only-seq dedup",
    };
    eprintln!(
        "ds-dnsgate: snapshot drop reason={} dropped_seq={} committed_seq={} ({class})",
        drop.reason.as_str(),
        drop.dropped_seq,
        drop.committed_seq,
    );
}

impl SnapshotDropSink for OperatorLogDropSink {
    fn observe_drop(&self, drop: SnapshotDropEvent) {
        operator_log_drop_line(&drop);
    }
}

/// The PRODUCTION reload-boundary DROP sink: route every [`SnapshotDropEvent`] —
/// `StaleFanOut` (the subscriber's benign D72 forward-only dedup) and the publisher's
/// integrity rejections `ContentHashMismatch` + `SchemaFailure` — through
/// [`SnapshotDropEvent::to_envelope`] onto the REAL shared `ds_telemetry::SpoolSink`
/// for `DnsEvent`s (doc 11 §5.5 / §5.3, D116), so the drop signals land in the genuine
/// disk-bounded, visible-loss spool rather than only the LOOPBACK [`OperatorLogDropSink`]
/// stand-in's stderr. THIS is the leg that replaces the loopback stand-in (the
/// snapshot-drop-observability leg): the drop BEHAVIOR is unchanged (the snapshot is
/// dropped either way), only the OBSERVABILITY routes to the production spool.
///
/// The operator-log line is STILL written ([`operator_log_drop_line`]) so the
/// human-readable surface is unchanged; the addition is the encoded
/// [`crate::event::EventEnvelope`] handed to the wrapped [`ds_telemetry::spool::SpoolSink`]
/// (a synchronous fire-and-forget `emit`, telemetry never fails the data path — doc 14
/// §12.4). On the unreachable blank-provenance case the envelope encode fails and the
/// drop is left log-only rather than shipping a blank-provenance envelope (the same
/// discipline `event::TelemetrySink` runs for `DnsEvent`s).
///
/// This sink is bound ONLY behind the [`DROP_SPOOL_LIVE_ENV`] env gate (a deferred
/// manual step — it opens a real on-disk spool segment); the default offline/CI path
/// keeps the log-only [`OperatorLogDropSink`], and the library-level no-op default is
/// [`ds_dnsgate::event::NullDropSink`].
///
/// The `spool_segment_round_trips_reload_and_warm_restart_envelopes` integration test
/// (`tests/event_surface.rs`) proves — over a REAL on-disk `ds_telemetry` segment opened
/// against a tmpdir, no kernel/network — that both this reload-boundary drop envelope
/// (all three drop reasons, DISTINCT on readback) AND the warm-restart completion envelope
/// round-trip through the same `SpoolSink` route this sink hands them to.
struct SpoolDropSink {
    spool: ds_telemetry::spool::SpoolSink,
}

impl SnapshotDropSink for SpoolDropSink {
    fn observe_drop(&self, drop: SnapshotDropEvent) {
        // The operator-log line is unchanged (greppable `reason=`-led), so the human
        // surface is identical whether or not the spool leg is live.
        operator_log_drop_line(&drop);
        // Route the encoded envelope onto the real disk-bounded spool. Telemetry never
        // fails the data path: a blank-provenance encode (unreachable on the subscriber /
        // publisher paths, where the live committed version's POL-3 triple is non-empty)
        // is left log-only rather than shipped blank.
        if let Ok(envelope) = drop.to_envelope() {
            use ds_telemetry::event::EventSink as _;
            self.spool.emit(envelope);
        }
    }
}

/// Build the reload-boundary DROP sink + (when live) the shared spool the warm-restart
/// completion event also rides. Returns the `Arc<dyn SnapshotDropSink>` BOTH the
/// subscriber commit sink (`with_drop_sink`) and the publisher
/// (`run_policy_publisher_with_drop_sink`) share, and the OPTIONAL owning
/// `ds_telemetry::spool::Spool` the caller must keep alive for the spool's lifetime
/// (dropping it would close the flush task) — `None` on the default log-only path.
///
/// DEFERRED MANUAL STEP: behind [`DROP_SPOOL_LIVE_ENV`] this opens a REAL on-disk spool
/// segment (`Spool::open`, live I/O on the current tokio runtime), so it is default-OFF;
/// the offline/CI path returns the LOOPBACK log-only [`OperatorLogDropSink`] and `None`,
/// byte-identical to the prior wiring. On an open failure it logs a loud banner and falls
/// back to the log-only sink (telemetry routing never blocks startup).
async fn build_drop_sink() -> (
    Arc<dyn SnapshotDropSink>,
    Option<ds_telemetry::spool::Spool>,
) {
    let Some(path) = std::env::var_os(DROP_SPOOL_LIVE_ENV) else {
        // Default offline/CI path: the log-only loopback stand-in, no spool I/O.
        return (Arc::new(OperatorLogDropSink), None);
    };
    let path = PathBuf::from(path);
    eprintln!(
        "ds-dnsgate: {DROP_SPOOL_LIVE_ENV}={} set — routing reload-boundary drops + the \
         warm-restart completion event onto the REAL ds_telemetry spool (D116). DEFERRED \
         MANUAL/LIVE leg: opens an on-disk spool segment.",
        path.display(),
    );
    match ds_telemetry::spool::Spool::open(&path, ds_telemetry::spool::SpoolBounds::default()).await
    {
        Ok(spool) => {
            let sink: Arc<dyn SnapshotDropSink> = Arc::new(SpoolDropSink {
                spool: spool.sink(),
            });
            (sink, Some(spool))
        }
        Err(err) => {
            eprintln!(
                "ds-dnsgate: WARNING — could not open the drop spool at {} ({err}); falling back \
                 to the log-only OperatorLogDropSink (drop OBSERVABILITY degraded, drop BEHAVIOR \
                 unchanged).",
                path.display(),
            );
            (Arc::new(OperatorLogDropSink), None)
        }
    }
}

#[cfg(test)]
mod committed_snapshot_tests {
    //! The committed policy a snapshot carries is SOURCED from a host policy snapshot (parse →
    //! compose → lift the boundary zone + W2 clamp), NOT an echo of the in-memory startup
    //! composed document. These assert, env-free, that a committed snapshot carrying a DIFFERENT
    //! POL-1 document yields a DIFFERENT composed version + W2 clamp than the shipped-pack startup
    //! snapshot — the version change vs the prior echo no-op. Synthetic / loopback only (§5.3): no
    //! live host agent, no policy stream, no I/O beyond the read-only shipped pack. The pure
    //! `snapshot_host_policy` is the same shared `PolicySnapshot::from_policy_layer` /
    //! `committed_policy()` lift the PRODUCTION publisher's reload path
    //! (`server::run_policy_publisher` → `BoundarySnapshot::with_policy_layer`) routes through, so
    //! this exercises the real source.

    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    use ds_dnsgate::server::BoundarySnapshot;
    use ds_dnsgate::{DnsQueryCtx, PolicyHook};

    /// A committed POL-1 snapshot document that is a NEW policy version (`pol1/v2`) vs the
    /// shipped baseline (`pol1/v0`), DENIES a name the baseline does not, and carries its OWN
    /// W2 clamp window (30s/600s) different from the W2 default — so a committed snapshot
    /// sourced from it carries a DIFFERENT composed doc + clamp, never a startup echo.
    const COMMITTED_SNAPSHOT_V2: &str = r#"
schema_version: pol1/v2
layer: system-baseline
posture: standard
admission:
  ttl_floor: 30
  ttl_ceil: 600
  grace: 60
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
  boundary_zone: pushed.example.
allowlist:
  - domain: kept.example
blocklist:
  - domain: blocked-in-v2.example
    reason: blocked-in-v2
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// A committed POL-1 snapshot that pushes a NON-default `admission.grace` (90s, not the 60s
    /// schema default) — so a `HostPolicy` sourced from it must carry 90, proving grace is lifted
    /// off the snapshot layer, not hardcoded to `DEFAULT_GRACE_SECS`.
    const COMMITTED_SNAPSHOT_GRACE_90: &str = r#"
schema_version: pol1/v-grace
layer: system-baseline
posture: standard
admission:
  ttl_floor: 60
  ttl_ceil: 900
  grace: 90
  max_ips_per_domain: 1000
dns:
  negative_ttl: 5
  boundary_zone: graced.example.
allowlist:
  - domain: kept.example
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    #[test]
    fn admission_grace_is_sourced_from_the_committed_snapshot_layer_not_hardcoded() {
        // POL-1 `admission.grace` is lifted off the SAME committed snapshot layer the boundary
        // zone + W2 clamp come from (the FROZEN CommittedPolicy/W2TtlClamp carry only floor/ceil,
        // so grace is read off the parsed layer). The shipped baseline pins 60s (the schema
        // default, but SOURCED from the layer); a pushed snapshot with grace: 90 yields 90 —
        // proving the value flows from the snapshot, never a `DEFAULT_GRACE_SECS` hardcode.
        let baseline = default_host_policy().expect("the shipped POL-2 baseline composes");
        assert_eq!(
            baseline.admission_grace_secs,
            ds_contracts::pol1::DEFAULT_GRACE_SECS,
            "the shipped baseline's grace is sourced from its admission block (60s)"
        );

        let pushed = snapshot_host_policy(COMMITTED_SNAPSHOT_GRACE_90)
            .expect("the grace-90 snapshot composes");
        assert_eq!(
            pushed.admission_grace_secs, 90,
            "a pushed admission.grace flows from the snapshot layer, not the default"
        );
        assert_ne!(
            pushed.admission_grace_secs, baseline.admission_grace_secs,
            "the pushed grace differs from the baseline — it is snapshot-sourced, not hardcoded"
        );
        // The grace rides the SAME snapshot as the boundary zone + clamp (one snapshot → one
        // composed doc + one clamp + one zone + one grace, D72).
        assert_eq!(pushed.boundary_zone, "graced.example.");
    }

    #[test]
    fn default_committed_policy_is_sourced_from_the_shipped_snapshot() {
        // The unset-env path re-sources from the shipped POL-2 baseline snapshot: the composed
        // version, boundary zone, AND W2 clamp all come from the parsed snapshot layer (the
        // 60s/900s admission timers the baseline pins), not a hardcoded `TtlClamp::DEFAULT`.
        let committed = default_host_policy().expect("the shipped POL-2 baseline composes");
        assert_eq!(
            committed.composed.policy_version, "pol1/v0",
            "the committed composed version is the shipped baseline's schema_version"
        );
        // The W2 clamp is LIFTED from the snapshot's `admission` block (here it equals the
        // pinned 60s/900s default, but it is SOURCED from the layer, not echoed as a const).
        assert_eq!(
            committed.ttl_clamp,
            TtlClamp {
                floor: 60,
                ceil: 900
            },
            "the W2 clamp is sourced from the snapshot's admission timers"
        );
    }

    #[test]
    fn committed_snapshot_carries_a_different_composed_doc_than_the_startup_echo() {
        // The version change vs the prior echo: a committed snapshot sourced from a NEW POL-1
        // document carries that document's composed version + W2 clamp + boundary zone — NOT
        // the in-memory startup document. Echoing `startup_composed` could NEVER produce these
        // values; only re-sourcing from the snapshot can.
        let startup = default_host_policy().expect("the shipped POL-2 baseline composes");
        let committed = snapshot_host_policy(COMMITTED_SNAPSHOT_V2)
            .expect("the committed v2 snapshot composes");

        // The composed POL-1 document is a DIFFERENT policy version than startup_composed.
        assert_eq!(committed.composed.policy_version, "pol1/v2");
        assert_ne!(
            committed.composed.policy_version, startup.composed.policy_version,
            "a committed snapshot carries a DIFFERENT composed document than the startup echo"
        );
        assert_ne!(
            committed.composed, startup.composed,
            "the whole composed document differs — not a startup_composed echo"
        );

        // The W2 clamp is the snapshot's OWN window (30s/600s), not a `TtlClamp::DEFAULT` echo.
        assert_eq!(
            committed.ttl_clamp,
            TtlClamp {
                floor: 30,
                ceil: 600
            }
        );
        assert_ne!(
            committed.ttl_clamp,
            TtlClamp::DEFAULT,
            "the committed W2 clamp is sourced from the snapshot, not the default echo"
        );

        // The boundary zone is lifted from the SAME snapshot layer (one snapshot → one version).
        assert_eq!(committed.boundary_zone, "pushed.example.");
        assert_ne!(committed.boundary_zone, startup.boundary_zone);

        // The committed snapshot the publisher fans out carries exactly these snapshot-sourced
        // fields: one seq → one composed doc + one clamp + one boundary zone (D72), end to end.
        let snapshot = BoundarySnapshot::with_policy(
            1,
            committed.boundary_zone.clone(),
            committed.composed.clone(),
            committed.ttl_clamp,
        );
        let policy = snapshot
            .policy
            .as_ref()
            .expect("a with_policy snapshot carries a committed CommittedPolicy");
        assert_eq!(policy.composed.policy_version, "pol1/v2");
        assert_eq!(
            policy.ttl_clamp,
            TtlClamp {
                floor: 30,
                ceil: 600
            }
        );
        assert_eq!(snapshot.boundary_zone, "pushed.example.");
    }

    #[test]
    fn snapshot_sourced_evaluator_flips_a_verdict_and_preserves_provenance() {
        // The committed composed document drives the frozen evaluator to a DIFFERENT verdict
        // than the shipped baseline for the v2-blocked name, and POL-3 provenance rides every
        // arm — the re-source is a real policy-version change, not an echo no-op.
        let committed = snapshot_host_policy(COMMITTED_SNAPSHOT_V2)
            .expect("the committed v2 snapshot composes");
        let policy = PolicyCorePolicy::new(committed.composed);
        let ctx = DnsQueryCtx {
            session: "committed-snapshot-test".to_string(),
            qname: "blocked-in-v2.example.".to_string(),
            qtype: 1,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        };
        let verdict = policy.evaluate(&ctx);
        assert!(
            !verdict.admits(),
            "the snapshot-sourced evaluator hard-denies the v2-blocked name"
        );
        // POL-3: the provenance triple is non-empty on the re-sourced verdict.
        let prov = verdict.provenance();
        assert!(
            !prov.rule_id.is_empty()
                && !prov.policy_layer.is_empty()
                && !prov.policy_version.is_empty(),
            "POL-3 provenance preserved on the snapshot-sourced verdict"
        );
        assert_eq!(prov.policy_version, "pol1/v2");
    }
}

#[cfg(test)]
mod production_profile_gate_tests {
    //! D131 shm-rollout T1 (doc 13 §Rollout item 4): the production-profile startup
    //! assertion the fatal guard routes through. These exercise the pure
    //! [`super::requires_shm_gates`] LOGIC directly (no `process::exit`, no listener
    //! bind, no env read) over the (profile × writer-gate × reresolve-gate) space,
    //! proving:
    //!   - off the profile NO gate is required (Ok(None)) — the bare-default path is
    //!     BYTE-IDENTICAL to today (the in-process map default is untouched);
    //!   - under the profile the WRITER gate (DS_ADMISSION_SHM_LIVE) is MANDATORY:
    //!     missing => Err (refuse to boot), present => Ok;
    //!   - under the profile a missing re-resolve listen gate is a NON-fatal warning
    //!     (Ok(Some(_))), never a boot block.

    use super::{requires_shm_gates, ADMISSION_SHM_LIVE_ENV, PRODUCTION_PROFILE_ENV};

    #[test]
    fn off_the_production_profile_no_gate_is_required() {
        // Bare default (DS_PRODUCTION unset): nothing is required, regardless of the
        // writer / re-resolve gates — the presence-only posture is unchanged.
        for shm in [false, true] {
            for rr in [false, true] {
                assert_eq!(
                    requires_shm_gates(false, shm, rr),
                    Ok(None),
                    "off the profile (shm={shm}, reresolve={rr}) requires nothing (unchanged default)"
                );
            }
        }
    }

    #[test]
    fn under_production_profile_the_writer_gate_is_mandatory() {
        // Profile ON + writer gate MISSING => refuse to boot (the forget-the-gate
        // footgun guard): the fatal banner names the missing writer gate + the profile.
        let err = requires_shm_gates(true, false, true)
            .expect_err("profile ON + DS_ADMISSION_SHM_LIVE UNSET must refuse startup (fatal)");
        assert!(
            err.contains(ADMISSION_SHM_LIVE_ENV),
            "the fatal banner names the missing writer gate: {err}"
        );
        assert!(
            err.contains(PRODUCTION_PROFILE_ENV),
            "the fatal banner names the production profile that mandates it: {err}"
        );
        // And it is fatal regardless of the re-resolve gate.
        assert!(
            requires_shm_gates(true, false, false).is_err(),
            "the writer-gate requirement is fatal even with the re-resolve gate unset"
        );
    }

    #[test]
    fn under_production_profile_writer_gate_present_proceeds_warning_only_on_reresolve() {
        // Profile ON + writer gate PRESENT + re-resolve PRESENT => clean proceed.
        assert_eq!(
            requires_shm_gates(true, true, true),
            Ok(None),
            "profile ON + both gates set proceeds with no warning"
        );
        // Profile ON + writer gate PRESENT + re-resolve MISSING => proceed WITH a
        // non-fatal operator warning (writer-before-reader / D68 availability), NEVER
        // a boot block.
        match requires_shm_gates(true, true, false) {
            Ok(Some(warn)) => {
                assert!(
                    warn.contains("WARNING"),
                    "a missing re-resolve gate is a non-fatal warning, not a fatal: {warn}"
                );
            }
            other => {
                panic!("expected Ok(Some(warning)) for a missing re-resolve gate, got {other:?}")
            }
        }
    }
}

#[cfg(test)]
mod prepare_verified_gate_tests {
    //! The live-ingest NON-VACUOUS identity gate (POL-4 part 2; D72/D120, doc 13 §5.1):
    //! [`super::PrepareVerifiedGate`] threads each delivered version's PRODUCER-PINNED,
    //! separately-transported `content_hash` through the FROZEN
    //! [`ds_contracts::consumer::Consumer::prepare_verified`] seam BEFORE the publisher's
    //! lift. These prove, over a scripted in-process [`PolicyVersionSource`]:
    //!   - a TAMPERED version (transported hash ≠ bytes) is NACKed at the seam and DROPPED
    //!     (never forwarded → never published → the admission map is never re-sourced, the
    //!     host stays on vN);
    //!   - a VERIFIED version forwards UNCHANGED (the publisher's verify-only loader + lift
    //!     run byte-identically behind the gate);
    //!   - a `wire: None` in-memory loopback version passes through UNGATED (no separately-
    //!     transported hash to verify — the non-vacuous gate does not apply).

    use super::{PolicyVersionSource, PrepareVerifiedGate};
    use ds_contracts::pol1::parse_layer;
    use ds_contracts::snapshot_verify::sha256;
    use ds_dnsgate::server::CommittedPolicyVersion;

    const DOC_A: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                         dns:\n  boundary_zone: a.example.\n";
    const DOC_B: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                         dns:\n  boundary_zone: b.example.\n";

    /// A scripted in-process source: hands out a queued set of versions in order, then closes.
    struct ScriptedSource {
        queue: std::collections::VecDeque<CommittedPolicyVersion>,
    }

    impl ScriptedSource {
        fn new(versions: impl IntoIterator<Item = CommittedPolicyVersion>) -> Self {
            Self {
                queue: versions.into_iter().collect(),
            }
        }
    }

    impl PolicyVersionSource for ScriptedSource {
        async fn next_version(&mut self) -> Option<CommittedPolicyVersion> {
            self.queue.pop_front()
        }
    }

    /// Build a VERIFIED version carrying its produce-once wire form with the CORRECT hash.
    fn verified_version(seq: u64, doc: &str) -> CommittedPolicyVersion {
        let layer = parse_layer(doc).expect("doc parses");
        let bytes = doc.as_bytes().to_vec();
        let hash = sha256(&bytes);
        CommittedPolicyVersion::verified(seq, layer, bytes, hash)
    }

    /// Build a TAMPERED version: the carried wire `content_hash` does NOT match the bytes.
    fn tampered_version(seq: u64, doc: &str) -> CommittedPolicyVersion {
        let layer = parse_layer(doc).expect("doc parses");
        let bytes = doc.as_bytes().to_vec();
        let mut hash = sha256(&bytes);
        hash[0] ^= 0xff; // a hash that does not match the bytes
        CommittedPolicyVersion::verified(seq, layer, bytes, hash)
    }

    #[tokio::test]
    async fn tampered_version_is_dropped_before_the_publisher_lift() {
        // A tampered middle version is NACKed at the prepare_verified seam and DROPPED; the
        // gate skips forward to the next VERIFIED version. The publisher never sees the
        // tampered one (the admission map is never re-sourced — host stays on vN).
        let source = ScriptedSource::new([
            verified_version(1, DOC_A),
            tampered_version(2, DOC_B),
            verified_version(3, DOC_A),
        ]);
        let mut gate = PrepareVerifiedGate::new(source, 0);

        let v1 = gate.next_version().await.expect("first verified version");
        assert_eq!(v1.seq, 1);
        // seq 2 (tampered) is dropped → the next yielded version is seq 3, not seq 2.
        let v3 = gate.next_version().await.expect("third verified version");
        assert_eq!(
            v3.seq, 3,
            "the tampered seq 2 was dropped at the identity gate"
        );
        assert!(gate.next_version().await.is_none(), "stream drained");
    }

    #[tokio::test]
    async fn verified_version_passes_through_unchanged() {
        // A verified version forwards UNCHANGED (same seq + same wire bytes/hash), so the
        // publisher's verify-only loader runs byte-identically behind the gate.
        let v = verified_version(7, DOC_A);
        let source = ScriptedSource::new([v.clone()]);
        let mut gate = PrepareVerifiedGate::new(source, 0);

        let got = gate
            .next_version()
            .await
            .expect("verified version forwards");
        assert_eq!(got, v, "the verified version is forwarded byte-for-byte");
    }

    #[tokio::test]
    async fn wire_none_loopback_version_passes_through_ungated() {
        // A `wire: None` in-memory loopback version carries no separately-transported hash:
        // the non-vacuous gate does not apply, so it passes through with existing semantics.
        let layer = parse_layer(DOC_A).expect("doc parses");
        let v = CommittedPolicyVersion::new(9, layer); // wire: None
        let source = ScriptedSource::new([v.clone()]);
        let mut gate = PrepareVerifiedGate::new(source, 0);

        let got = gate
            .next_version()
            .await
            .expect("loopback version forwards");
        assert_eq!(got, v, "a wire:None version is forwarded ungated");
    }
}

#[cfg(test)]
mod watch_policies_carrier_ingest_tests {
    //! The LIVE host-local UDS `WatchPolicies(from_seq)` carrier feeding the NON-VACUOUS identity
    //! gate end to end (POL-4 part 2; D72/D36/D120, doc 11 §5.3 / doc 13 §5.1): the production
    //! transport [`super::PublisherSource::Carrier`] selects behind `DS_DNSGATE_HOST_AGENT_FEED`.
    //!
    //! A SYNTHETIC in-process producer ([`ds_dnsgate::server::serve_watch_policies_connection`])
    //! over a real UDS socket stands in for the Go host-agent fan-out
    //! (`orchestrator/internal/hostagent/dnsfeed_carrier.go`) — the SAME wire shape, no live host
    //! agent (§5.3 loopback). The carrier surfaces each `(seq, content_hash, transported bytes)`
    //! version to [`super::PrepareVerifiedGate`] unchanged; a TAMPERED version (transported bytes ≠
    //! the producer-pinned `content_hash`) is DROPPED at the frozen `prepare_verified` seam and the
    //! host stays on vN (host-wide fail-closed). The default offline/CI run SKIPS the live-socket
    //! leg unless `DS_DNSGATE_HOST_AGENT_FEED` is set, so the default build is byte-identical; the
    //! gate-drop logic is also covered by `prepare_verified_gate_tests` over an in-process source.

    use super::{PolicyVersionSource, PrepareVerifiedGate, HOST_AGENT_FEED_ENV};
    use ds_contracts::snapshot_verify::sha256;
    use ds_dnsgate::server::{serve_watch_policies_connection, WatchPoliciesCarrierSource};

    const DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                       dns:\n  boundary_zone: carrier.example.\n";

    /// A VERIFIED `(seq, content_hash, document)` tuple — the producer-pinned hash matches the bytes.
    fn verified(seq: u64) -> (u64, ds_contracts::snapshot_verify::ContentHash, Vec<u8>) {
        let bytes = DOC.as_bytes().to_vec();
        (seq, sha256(&bytes), bytes)
    }

    /// A TAMPERED tuple — the producer-pinned hash does NOT match the transported bytes (a
    /// tampered/torn transport, D120). The carrier transports it verbatim; the gate must NACK it.
    fn tampered(seq: u64) -> (u64, ds_contracts::snapshot_verify::ContentHash, Vec<u8>) {
        let bytes = DOC.as_bytes().to_vec();
        let mut hash = sha256(&bytes);
        hash[0] ^= 0xff;
        (seq, hash, bytes)
    }

    #[tokio::test]
    async fn tampered_version_through_the_uds_carrier_is_dropped_host_stays_on_vn() {
        // The DELIVERABLE: a tampered version delivered over the LIVE UDS WatchPolicies carrier is
        // DROPPED at PrepareVerifiedGate (HashMismatch fail-closed), never forwarded to the
        // publisher's lift — so the admission map is never re-sourced and the host stays on vN. The
        // verified versions on either side of it are delivered, proving the carrier keeps draining.
        //
        // env-gated (DS_DNSGATE_HOST_AGENT_FEED): the live-socket leg runs only when the gate is
        // set, so the default offline/CI run is byte-identical. The in-process equivalent is always
        // covered by `prepare_verified_gate_tests::tampered_version_is_dropped_before_the_publisher_lift`.
        if std::env::var_os(HOST_AGENT_FEED_ENV).is_none() {
            eprintln!(
                "ds-dnsgate test: {HOST_AGENT_FEED_ENV} unset — skipping the LIVE UDS carrier leg \
                 (the in-process gate-drop is covered unconditionally by prepare_verified_gate_tests)."
            );
            return;
        }

        let dir = std::env::temp_dir().join(format!("ds-carrier-ingest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let sock = dir.join("watch.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind carrier UDS");

        // The producer fans out: verified seq 1, TAMPERED seq 2, verified seq 3.
        let versions = vec![verified(1), tampered(2), verified(3)];
        let producer = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.expect("accept");
            serve_watch_policies_connection(stream, &versions)
                .await
                .expect("producer streams")
        });

        // The PRODUCTION wiring: the carrier source DECORATED by the non-vacuous identity gate,
        // exactly as `run_gate` wires it in `main` (PrepareVerifiedGate::new(source, from_seq)).
        let carrier = WatchPoliciesCarrierSource::connect_to(&sock, 0);
        let mut gate = PrepareVerifiedGate::new(carrier, 0);

        // seq 1 (verified) is delivered; seq 2 (tampered) is DROPPED at the seam → the next yielded
        // version is seq 3, NOT seq 2 (the host never sees the tampered version → stays on vN).
        let v1 = gate.next_version().await.expect("first verified version");
        assert_eq!(v1.seq, 1, "the first verified version is delivered");
        let v3 = gate.next_version().await.expect("third verified version");
        assert_eq!(
            v3.seq, 3,
            "the tampered seq 2 was DROPPED at prepare_verified (HashMismatch); host stays on vN"
        );
        assert!(
            gate.next_version().await.is_none(),
            "the stream exhausts once the producer closes (no fabricated version)"
        );

        let streamed = producer.await.expect("producer task");
        assert_eq!(
            streamed, 3,
            "the producer streamed all three frames (it is a thin transport)"
        );

        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir(&dir);
    }
}

#[cfg(test)]
mod tap_registry_parse_tests {
    //! The pure `DS_DNSGATE_TAP_REGISTRY` SPEC parse (doc 11 §5.1 / W6, D44) — the SYNTHETIC
    //! loopback stand-in for the orchestrator session-record fan-out that builds the gate's
    //! interface-anchored [`ds_dnsgate::AttributionTable`]. Side-effect-free (no env, no I/O),
    //! so the registry construction `main` threads into `GateConfig.tap_registry` is asserted
    //! directly: a well-formed spec resolves the never-recycled tap by interface-anchored LOCAL
    //! address, and every malformed spec is REJECTED fail-closed (never a silent empty table).

    use super::parse_tap_registry;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parses_a_single_entry_and_resolves_the_tap_by_local_address() {
        let table = parse_tap_registry("127.0.0.1=dstap-7/7").expect("a well-formed spec parses");
        // The registered interface-anchored LOCAL address resolves to the never-recycled tap.
        let attribution = table
            .attribute_local(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .expect("the registered local address resolves");
        assert_eq!(attribution.tap_name, "dstap-7");
        assert_eq!(attribution.mark_index.value(), 7);
    }

    #[test]
    fn mark_index_defaults_to_zero_when_omitted() {
        let table = parse_tap_registry("10.0.0.2=dstap-3").expect("an index-less entry parses");
        let attribution = table
            .attribute_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .expect("the registered local address resolves");
        assert_eq!(attribution.tap_name, "dstap-3");
        assert_eq!(
            attribution.mark_index.value(),
            0,
            "an omitted mark index defaults to 0"
        );
    }

    #[test]
    fn parses_multiple_entries_and_skips_trailing_empty_segments() {
        // A comma-separated list with surrounding whitespace and a trailing comma (an empty
        // segment) — both registered addresses resolve, the empty segment is skipped.
        let table = parse_tap_registry(" 127.0.0.1=dstap-1/1 , 10.0.0.9=dstap-9/9 ,")
            .expect("a multi-entry spec parses");
        assert_eq!(
            table
                .attribute_local(IpAddr::V4(Ipv4Addr::LOCALHOST))
                .expect("first entry resolves")
                .tap_name,
            "dstap-1"
        );
        assert_eq!(
            table
                .attribute_local(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)))
                .expect("second entry resolves")
                .tap_name,
            "dstap-9"
        );
    }

    #[test]
    fn an_unregistered_address_fails_closed() {
        // The parse wires ONLY the registered anchors; an interface-anchored address with no
        // entry fails closed (UnknownInterface) — never a default/fabricated session.
        let table = parse_tap_registry("127.0.0.1=dstap-1").expect("parses");
        assert!(
            table
                .attribute_local(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)))
                .is_err(),
            "an unregistered interface-anchored address has no tap → fail closed"
        );
    }

    #[test]
    fn malformed_specs_are_rejected_fail_closed() {
        // A missing '=', an empty tap name, a non-IP local address, a non-u32 mark index, and a
        // spec with zero usable entries are ALL rejected — a typo refuses the boot rather than
        // silently producing an empty table that fails every query closed.
        assert!(
            parse_tap_registry("127.0.0.1").is_err(),
            "missing '=' is rejected"
        );
        assert!(
            parse_tap_registry("127.0.0.1=").is_err(),
            "an empty tap name is rejected"
        );
        assert!(
            parse_tap_registry("not-an-ip=dstap-1").is_err(),
            "an unparseable local IP is rejected"
        );
        assert!(
            parse_tap_registry("127.0.0.1=dstap-1/not-a-number").is_err(),
            "an unparseable mark index is rejected"
        );
        assert!(
            parse_tap_registry("   ,  ,").is_err(),
            "a spec with zero usable entries is rejected (never a silent empty table)"
        );
    }
}
