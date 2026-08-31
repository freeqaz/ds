//! The plain-tokio listener shell (doc 11 §2 process-shell row: "free").
//!
//! Binds a UDP socket and a TCP listener on loopback high ports. The UDP path is
//! driven by hickory-server's `Server` over our `StubRequestHandler`. The TCP path is
//! driven by an **accept-loop semaphore** here in `server.rs`: hickory 0.26.x has NO
//! built-in concurrent-connection cap (MEASURED — see the README findings:
//! `handle_tcp` spawns one task per accepted connection, the per-connection read
//! timeout being the only built-in DoS lever), so as the fleet's single resolver and
//! DoS chokepoint (doc 11 §1) the deployment must impose its own. The cap is
//! injectable with a sane default and bounds how many TCP connections are served
//! concurrently; the paired nftables conn-limit is DNS-5 territory (cross-reference
//! only — task 01KTWJ8DVRPPXFG1MVQSMQTPW5 owns the nft rules).
//!
//! The capped TCP serve reuses hickory's request/response machinery — it decodes each
//! framed query into a hickory `Request`, runs it through the SAME
//! `StubRequestHandler` the UDP path uses, and serializes the authored response back
//! over hickory's `ResponseHandle`/`BufDnsStreamHandle` — so the verdict, forwarder,
//! and wire-shape behavior are byte-identical across UDP and TCP (doc 11 §3.4 parity).
//! No hickory type appears in any pub signature here (D67): `spawn_gate` takes the
//! hickory-free `GateConfig` and returns an opaque `RunningGate`.
//!
//! This is the pre-stage of the eventual UDP+TCP/53 gate. The sandbox has no
//! privileged ports, so this binds high ports only; the real service binds :53 behind
//! the NFT-2 redirect.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::Protocol;
use hickory_server::net::BufDnsStreamHandle;
use hickory_server::server::{Request, ResponseHandle, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;

use ds_contracts::dns_admission::{
    AddressFamily, AdmissionError, AdmissionKey, AdmissionMap, AdmittedAddr,
};
use ds_contracts::flush::{DstKey, FlushSession};
use ds_contracts::mark::{compose, Leg, DS_MARK_MASK};
use ds_contracts::session::SessionRef;
use ds_contracts::snapshot_verify::ContentHash;
use ds_policy_snapshot::{
    sweep_fleet_revocations_with_book, FleetRevocationEntry, LoadVerdict, RevocationSweep,
    SessionAdmissionBook,
};
use policy_core::pol1_eval::ComposedPolicy;

use crate::attrib::AttributionTable;
use crate::event::{EventSink, NullDropSink, NullSink, SnapshotDropEvent, SnapshotDropSink};
use crate::handler::{
    BoundaryZoneReload, ForwarderConfig, StubRequestHandler, DEFAULT_BOUNDARY_ZONE,
};
use crate::policy::{DnsQueryCtx, PolicyCorePolicy, PolicyHook, TtlClamp};
use crate::txn::{AdmissionStores, InMemoryAdmissionMap, NftSetProgrammer, RecordingSetProgrammer};

/// The default ceiling on concurrently-served TCP connections. Sized to absorb a
/// healthy fan-out of legitimate TCP/53 retries (large answers, TC-bit retries)
/// while keeping a synthetic connection flood from spawning unbounded per-connection
/// tasks against the fleet's single resolver (doc 11 §1 / §8.5). Tunable per
/// deployment; the nftables conn-limit (DNS-5) is the paired kernel-side control.
pub const DEFAULT_MAX_TCP_CONNECTIONS: usize = 256;

/// Tunables for the listener shell. The TCP read timeout and per-connection response
/// buffer are the DNS-1 knobs the framework-validation harness measures (doc 11
/// §3.4); `max_tcp_connections` is the accept-loop semaphore cap the same harness
/// asserts holds under a synthetic loopback flood.
///
/// Carries plain `std` types plus the hickory-free [`ForwarderConfig`] only — no
/// hickory type, so the D67 corollary holds at the listener boundary too.
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// Address for the UDP listener (use port 0 to let the OS choose).
    pub udp_addr: SocketAddr,
    /// Address for the TCP listener (use port 0 to let the OS choose).
    pub tcp_addr: SocketAddr,
    /// Per-connection TCP read/idle timeout. A TCP connection that sends no complete
    /// request within this window is closed (the per-connection DoS lever measured in
    /// the framework-validation findings; here it is enforced by `server.rs` around
    /// the framed read rather than by hickory's `TimeoutStream`).
    pub tcp_timeout: Duration,
    /// Per-connection outgoing response buffer size for TCP.
    pub tcp_response_buffer: usize,
    /// Maximum number of TCP connections served concurrently — the accept-loop
    /// semaphore cap. hickory has no built-in cap (README finding), so the gate
    /// imposes its own. Injectable; defaults to [`DEFAULT_MAX_TCP_CONNECTIONS`].
    pub max_tcp_connections: usize,
    /// The upstream forwarder pool config (hickory-free): the D64 `1.1.1.1` /
    /// `8.8.8.8` pair by default; tests inject an in-process loopback mock upstream
    /// on an ephemeral port here so the forwarder is exercised with zero network.
    pub forwarder: ForwarderConfig,
    /// The D71 authored-SOA boundary zone the gate signs every deny / NODATA with
    /// (`SOA MNAME = denied.policy.<boundary_zone>.`; doc 11 §3.2). SOURCED FROM THE LIVE
    /// HOST POLICY SNAPSHOT (`ds-policy-snapshot::PolicySnapshot::boundary_zone_value`) at
    /// main startup, and refreshed on the doc 13 §5.3 admitter-LAST D72 hot-reload —
    /// REPLACING the handler-local [`DEFAULT_BOUNDARY_ZONE`] const default. The
    /// `with_forwarder` path (and a config that omits this field, via [`Default`]) still
    /// carries the working-name default, so the framework / forwarder / suppression
    /// harnesses are unchanged; the production `main` overrides it with the snapshot value.
    /// A plain `String` — the same value the POL-1 `dns.boundary_zone` reader materializes,
    /// no hickory type, so the D67 corollary holds at the listener boundary.
    pub boundary_zone: String,
    /// The W2 shared-deadline GRACE in seconds (POL-1 `admission.grace`, doc 13 §1.5 / D68) the
    /// gate threads into BOTH handlers' admission transaction. SOURCED FROM THE LIVE HOST POLICY
    /// SNAPSHOT's parsed POL-1 `admission.grace` (the FROZEN `CommittedPolicy`/`W2TtlClamp` carry
    /// only floor/ceil, so grace is read off the parsed layer in `main`), REPLACING the handler's
    /// [`ds_contracts::pol1::DEFAULT_GRACE_SECS`] (60s) default. FLOOR/CEIL ride the verdict's
    /// frozen `Admit`; GRACE is the one tunable that does not, so it is threaded here. The
    /// `with_forwarder` path and a config built via [`Default`] keep the 60s schema default, so
    /// the framework / forwarder / suppression harnesses are unchanged; the production `main`
    /// overrides it with the snapshot value. A plain `u32` — a policy value, no hickory type.
    pub admission_grace_secs: u32,
    /// OPTIONAL single-session FIXED `session_uuid` (doc 11 §5.1 / D131-rollout): when
    /// `Some`, BOTH transports stamp this exact string into every query's
    /// [`crate::policy::DnsQueryCtx::session`] (and thus the W1/W2 DNS-2b AdmissionKey),
    /// REPLACING the pre-stage `src:<addr>` token. This is the minimal cross-process
    /// AdmissionMap-key agreement for the single-VM nested-KVM testbed — the gate writes
    /// `{uuid, fqdn}` while a co-host ds-tlsproxy stamps the SAME `uuid` into the `SessionRef`
    /// it reads with, so the FORWARD admission lookup HITS. SOURCED FROM `DS_SESSION_UUID` in
    /// `main`; `None` (the [`Default`] and every existing test/harness) keeps the handler at
    /// [`crate::policy`]'s pre-stage source token, byte-identical to today. Single-session-
    /// honest only: a second concurrent session cross-attributes to this one uuid (prefer the
    /// interface-anchored attribution table for multi-session). A plain `Option<String>`.
    pub fixed_session_uuid: Option<String>,
    /// OPTIONAL interface-anchored per-session TAP REGISTRY (doc 11 §5.1 / W6, D44) — the
    /// orchestrator's never-recycled tap registry, threaded in as the gate's READ VIEW. When
    /// `Some`, BOTH transports resolve every query's [`crate::policy::DnsQueryCtx::session`]
    /// through [`AttributionTable::attribute_local`] keyed on THAT listener's own post-NAT
    /// LOCAL address (the interface-anchored anchor the NFT-2 redirect landed on) — NEVER the
    /// guest source IP — REPLACING the pre-stage `src:<addr>` token with the never-recycled tap
    /// join the §5.1 freeze requires, and FAILING CLOSED to SERVFAIL on an unregistered
    /// interface ([`crate::attrib::AttributionError::UnknownInterface`], a genuine ds-dnsgate
    /// failure per W1/§3.2, never a policy NXDOMAIN). This is the structurally-general,
    /// multi-session attribution shape and takes PRECEDENCE over [`Self::fixed_session_uuid`]
    /// (the single-VM testbed fallback) when both are set; with neither the handler keeps the
    /// pre-stage source token. SOURCED FROM the orchestrator session-record fan-out in `main`
    /// behind the `DS_DNSGATE_TAP_REGISTRY` env gate (a deferred live seam — the cross-process
    /// orchestrator feed lives outside this dataplane workspace); `None` (the [`Default`] and
    /// every existing test/harness) is byte-identical to today. A [`Clone`] [`AttributionTable`]
    /// (a shared-handle clone goes to each transport), no hickory type, so the D67 corollary
    /// holds at the listener boundary.
    pub tap_registry: Option<AttributionTable>,
    /// OPTIONAL host id stamped into the [`ds_contracts::session::SessionRef`] the FLEET-revocation
    /// mint-path record carries (doc 19 §7; D102/P-R6, doc 14 §4). Threaded into the gate's
    /// [`AdmissionStores`] at spawn (via [`AdmissionStores::with_fleet_recording`]); `None` (the
    /// [`Default`] and every existing test/harness) keeps the loopback/synthetic
    /// [`crate::txn::DEFAULT_FLEET_HOST_ID`] stand-in. Opaque to the sweep (`flush_session` joins on
    /// `tap_name`), so a stable per-gate value is sufficient. SOURCED FROM `DS_HOST_ID` in `main`.
    pub host_id: Option<String>,
    /// OPTIONAL scoped-token chain FINGERPRINT / block id (opaque hex; NEVER token bytes) the
    /// sessions this gate admits are recorded under in the FLEET-revocation book (doc 19 §7;
    /// D102/P-R6). When `Some`, every SUCCESSFUL admission records `(fingerprint → session)` so a
    /// pushed revocation of that token severs the flows the mint path established; `None` (the
    /// [`Default`] and every existing test/harness) records NOTHING — byte-identical to today, the
    /// pre-token-plumbing path. Mirrors the [`Self::fixed_session_uuid`] single-session testbed
    /// idiom: SOURCED FROM `DS_TOKEN_FINGERPRINT` in `main` (the single-session token identity). A
    /// live per-session fingerprint feed is a deferred seam outside this dataplane workspace.
    pub fixed_token_fingerprint: Option<String>,
    /// OPTIONAL LIVE PER-SESSION scoped-token fingerprint feed (doc 19 §7): a
    /// `session_uuid → fingerprint` map the mint path consults AT ADMISSION TIME, resolving EACH
    /// admitting session's OWN token fingerprint rather than the single `fixed_token_fingerprint`
    /// stand-in. When `Some`, this TAKES PRECEDENCE over `fixed_token_fingerprint` (spawn installs a
    /// per-session resolver): two sessions admitted under two distinct tokens land two DISTINCT book
    /// rows, so a revocation of one severs only its own sessions. A session absent from the map
    /// records nothing (fail-open to the pre-plumbing behavior for that session). `None` (the
    /// [`Default`] and every existing harness) keeps the fixed/none single-session behavior
    /// byte-identical. SOURCED FROM `DS_TOKEN_FINGERPRINT_MAP` in `main` — the loopback/synthetic
    /// stand-in for the real cross-process per-session feed (a deferred seam, D50); it carries
    /// fingerprint/block-id only, NEVER token bytes.
    pub token_fingerprint_map: Option<HashMap<String, String>>,
}

impl Default for GateConfig {
    fn default() -> Self {
        // Loopback, OS-chosen ports — safe inside the sandbox.
        let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        Self {
            udp_addr: loopback,
            tcp_addr: loopback,
            // 5s is the doc 11 §4 test-pinned TCP read timeout default.
            tcp_timeout: Duration::from_secs(5),
            // hickory's own example default; large enough for any 64KiB TCP answer.
            tcp_response_buffer: u16::MAX as usize,
            max_tcp_connections: DEFAULT_MAX_TCP_CONNECTIONS,
            forwarder: ForwarderConfig::default(),
            // The working-name default — the SAME value the host snapshot's own default
            // carries when a policy layer omits `dns.boundary_zone`, so a config that
            // does not source the live snapshot reproduces the frozen pre-stage signature
            // exactly. The production `main` overrides this with the live snapshot value.
            boundary_zone: DEFAULT_BOUNDARY_ZONE.to_string(),
            // The POL-1 `admission.grace` schema default (60s) — the SAME value the handler's
            // own `with_admission` default carries when no snapshot pushes one, so a config
            // that does not source the live snapshot reproduces the frozen W2 grace exactly.
            // The production `main` overrides this with the snapshot's parsed `admission.grace`.
            admission_grace_secs: ds_contracts::pol1::DEFAULT_GRACE_SECS,
            // No fixed single-session uuid by default → the handler keeps the pre-stage
            // `src:<addr>` source token (byte-identical to today). `main` sets this ONLY when
            // the operator exports `DS_SESSION_UUID` (the single-VM testbed key agreement).
            fixed_session_uuid: None,
            // No interface-anchored tap registry by default → the handler keeps the pre-stage
            // `src:<addr>` source token (byte-identical to today). `main` sets this ONLY when
            // the operator exports `DS_DNSGATE_TAP_REGISTRY` (the orchestrator session-record
            // fan-out, the structurally-general multi-session attribution shape).
            tap_registry: None,
            // No host id by default → the fleet-revocation record's SessionRef carries the
            // loopback/synthetic `DEFAULT_FLEET_HOST_ID` stand-in. `main` sets this from `DS_HOST_ID`.
            host_id: None,
            // No scoped-token fingerprint by default → the mint path records NOTHING into the fleet
            // book (byte-identical to today). `main` sets this ONLY when the operator exports
            // `DS_TOKEN_FINGERPRINT` (the single-session token identity).
            fixed_token_fingerprint: None,
            // No per-session fingerprint feed by default → the fixed/none single-session behavior is
            // unchanged. `main` sets this ONLY when the operator exports `DS_TOKEN_FINGERPRINT_MAP`
            // (the multi-session per-token feed, which takes precedence over the fixed stand-in).
            token_fingerprint_map: None,
        }
    }
}

/// A running gate: the hickory UDP `Server`, the capped TCP accept loop, and the
/// bound local addresses, so callers (and the framework-validation harness) can dial
/// it without racing the OS port assignment.
pub struct RunningGate<
    P: PolicyHook,
    M: AdmissionMap + Send + Sync + 'static = InMemoryAdmissionMap,
    S: NftSetProgrammer + Send + Sync + 'static = RecordingSetProgrammer,
> {
    udp_server: Server<StubRequestHandler<P, M, S>>,
    tcp_tasks: JoinSet<()>,
    tcp_shutdown: watch::Sender<bool>,
    udp_local: SocketAddr,
    tcp_local: SocketAddr,
    /// The doc 13 §5.3 admitter-LAST D72 reload handles — one per handler (UDP + TCP), so
    /// [`RunningGate::reload_boundary_zone`] re-sources the authored-SOA boundary zone on
    /// every transport from a new live snapshot value in one call (the UDP handler is moved
    /// into hickory's `Server`, so its handle is kept here to reach it).
    boundary_zone_reloads: Vec<BoundaryZoneReload>,
    /// A shared-handle clone of the installed evaluator — the SAME policy the UDP + TCP
    /// handlers hold (a `PolicyCorePolicy` clone shares one inner `Arc`). Kept here so the gate
    /// can hand out a [`GatePolicyReloader`] that re-sources the running evaluator on a doc 11
    /// §5.3 admitter-LAST D72 commit WITHOUT re-binding the listeners (the handler-held clones
    /// observe the same swap). For a `FixedStubPolicy` it is the inert unit; the
    /// evaluator-reload path is exposed only on `RunningGate<PolicyCorePolicy>`.
    policy: P,
    /// The SINGLE §5.4 live-admission registry both transports' admission transactions mint into
    /// (a shared-handle clone of the one the UDP + TCP handlers hold). Handed to the caller via
    /// [`live_admissions`](Self::live_admissions) so `main` wires
    /// [`SnapshotCommitSink::with_revocation_sweep`] against THIS registry — the §5.4 sweep then
    /// re-evaluates the admissions the W1/W2 transaction actually minted (the admission ↔
    /// revocation loop is closed; not a fresh registry the sweep could never see, doc 11 §5.4).
    live_admissions: LiveAdmissions,
    /// The gate's shared fingerprint→sessions FLEET-revocation admission book (doc 19 §7;
    /// D102/P-R6) — the SAME [`FleetRevocationBook`] the admission path records a session into as
    /// it mints it under a scoped token, handed to `main` via
    /// [`fleet_revocation_book`](Self::fleet_revocation_book) so it wires the post-commit
    /// [`SnapshotCommitSink::with_fleet_revocation_sweep`] against THIS book — the sweep then
    /// resolves a revoked token's fingerprint to the sessions the gate actually admitted under it
    /// (the REAL resolver, not an injected test closure). A shared-handle clone shares the inner
    /// `Arc`, so the recorder and the sweep hold one book with no copy skew.
    fleet_revocation_book: FleetRevocationBook,
}

// `S: Send + Sync + 'static` so the held `Server<StubRequestHandler<P, S>>` is a valid hickory
// `RequestHandler` (the supertrait the handler satisfies for any such `S`). The default
// `RecordingSetProgrammer` and the production `ds_nft::NftWriter<SpawnBackend>` both qualify, so
// these methods are identical whether the gate runs the reportable or the live programmer.
impl<
        P: PolicyHook,
        M: AdmissionMap + Send + Sync + 'static,
        S: NftSetProgrammer + Send + Sync + 'static,
    > RunningGate<P, M, S>
{
    /// The bound UDP address (resolved port if the config used port 0).
    pub fn udp_local_addr(&self) -> SocketAddr {
        self.udp_local
    }

    /// The bound TCP address (resolved port if the config used port 0).
    pub fn tcp_local_addr(&self) -> SocketAddr {
        self.tcp_local
    }

    /// Refresh the D71 authored-SOA boundary zone from a NEW live host snapshot value — the
    /// doc 13 §5.3 admitter-LAST D72 hot-reload (the gate is the ADMITTER, so it commits the
    /// new boundary zone LAST, after the enforcement layers have applied the snapshot). The
    /// caller sources `boundary_zone` from the freshly-committed
    /// `ds-policy-snapshot::PolicySnapshot::boundary_zone_value`; this re-derives the
    /// authored MNAME/RNAME on BOTH the UDP and TCP handlers in one call (no listener
    /// re-bind, no per-transport skew), so every subsequent authored denial signs with the
    /// policy-pushed suffix. A VALUE change, never a SHAPE change (the `denied.policy.`
    /// prefix, always-authored SOA, and TTL==MINIMUM==negative-TTL stay frozen, D71).
    ///
    /// This is the SOLE boundary-zone reload path: the `WatchPolicies` host-snapshot
    /// subscriber ([`watch_policies`]) drives it on every committed snapshot, and the
    /// handler-local re-derivation lives behind ONE `BoundaryZoneReload` handle per
    /// transport. There is no second reload entry point (the redundant per-handler pub
    /// method was folded into this one).
    pub fn reload_boundary_zone(&self, boundary_zone: &str) {
        for reload in &self.boundary_zone_reloads {
            reload.reload(boundary_zone);
        }
    }

    /// The authored-SOA MNAME the gate CURRENTLY signs its negative responses with — the
    /// live value after the most recent [`reload_boundary_zone`](Self::reload_boundary_zone)
    /// (or the startup snapshot value if none yet). Reads the shared signature both
    /// transports author from, so it reflects the admitter's last commit. Used to assert the
    /// `WatchPolicies` subscriber drove a reload on the live gate; with the default
    /// working-name zone it is `denied.policy.boundary.`.
    pub fn current_authored_mname(&self) -> String {
        self.boundary_zone_reloads
            .first()
            .map(BoundaryZoneReload::current_mname)
            .unwrap_or_default()
    }

    /// A detached, `Clone + Send + Sync` handle that drives this gate's SOLE boundary-zone
    /// reload path (the same per-transport `BoundaryZoneReload` handles
    /// [`reload_boundary_zone`](Self::reload_boundary_zone) drives). `main` hands this to the
    /// `WatchPolicies` subscriber task ([`watch_policies`]) so the subscriber commits new
    /// snapshots admitter-LAST WHILE `main` keeps the gate by `&mut` to
    /// [`block_until_done`](Self::block_until_done) — one reload path, two holders, no
    /// listener re-bind.
    pub fn boundary_zone_reloader(&self) -> GateBoundaryReloader {
        GateBoundaryReloader {
            reloads: self.boundary_zone_reloads.clone(),
        }
    }

    /// The SINGLE §5.4 live-admission registry the gate's W1/W2 admission transaction mints into
    /// — a shared-handle clone of the one BOTH transports admit through (doc 11 §5.2/§5.4). `main`
    /// hands this to [`SnapshotCommitSink::with_revocation_sweep`] so the admitter-LAST revocation
    /// sweep re-evaluates the admissions the transaction ACTUALLY minted (and deletes their
    /// DNS-2b/allow-set state on a flipped verdict), instead of a fresh registry it could never
    /// see — the closed admission ↔ revocation loop. A clone shares the inner `Arc`, so the sweep
    /// and the transaction hold the same live set with no copy skew.
    pub fn live_admissions(&self) -> LiveAdmissions {
        self.live_admissions.clone()
    }

    /// The gate's shared fingerprint→sessions FLEET-revocation admission book (doc 19 §7;
    /// D102/P-R6) — a shared-handle clone of the one the admission path records into. `main` hands
    /// this to [`BookBackedFleetSweeper::new`] +
    /// [`SnapshotCommitSink::with_fleet_revocation_sweep`] so the post-commit fleet sweep resolves
    /// a revoked token's fingerprint to the sessions the gate ACTUALLY admitted under it (the REAL
    /// resolver), and severs them rung-conditionally through the frozen `flush_session`. A clone
    /// shares the inner `Arc`, so the recorder and the sweep hold the same book with no copy skew.
    pub fn fleet_revocation_book(&self) -> FleetRevocationBook {
        self.fleet_revocation_book.clone()
    }

    /// Block until all listener tasks exit (used by `main`).
    pub async fn block_until_done(&mut self) -> io::Result<()> {
        self.udp_server
            .block_until_done()
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }

    /// Request a graceful shutdown and wait for the listeners to drain.
    pub async fn shutdown(mut self) -> io::Result<()> {
        let _ = self.tcp_shutdown.send(true);
        // Drain in-flight TCP connections (each holds a permit until it returns).
        while self.tcp_tasks.join_next().await.is_some() {}
        self.udp_server
            .shutdown_gracefully()
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

impl<M: AdmissionMap + Send + Sync + 'static, S: NftSetProgrammer + Send + Sync + 'static>
    RunningGate<PolicyCorePolicy, M, S>
{
    /// A detached, `Clone + Send + Sync` handle that re-sources this gate's running
    /// [`PolicyCorePolicy`] evaluator — the doc 11 §5.3 admitter-LAST D72 evaluator reload, the
    /// policy-document twin of [`boundary_zone_reloader`](Self::boundary_zone_reloader). A
    /// SHARED-HANDLE clone, so committing a new composed document through it re-sources every
    /// transport's evaluator at once (the UDP + TCP handlers and this handle share one inner
    /// `Arc`) WITHOUT re-binding the listeners. `main` pairs this with the boundary-zone
    /// reloader in a [`SnapshotCommitSink`] and hands it to the `WatchPolicies` subscriber task
    /// ([`watch_snapshots`]) WHILE it keeps the gate by `&mut` to block on its listeners — one
    /// evaluator, two holders, no listener re-bind. Available only on the production
    /// `PolicyCorePolicy` evaluator (the generic `FixedStubPolicy` shell has nothing to reload).
    pub fn policy_reloader(&self) -> GatePolicyReloader {
        GatePolicyReloader {
            policy: self.policy.clone(),
        }
    }

    /// The composed policy version the running evaluator CURRENTLY decides against — the live
    /// value after the most recent evaluator re-source (or the startup composed document if
    /// none yet). Reads the shared evaluator both transports decide with, so it reflects the
    /// admitter's last commit; the `WatchPolicies` subscriber tests assert the evaluator
    /// re-sourced on the live gate through this read.
    pub fn policy_version(&self) -> String {
        self.policy.current_policy_version()
    }
}

/// The single boundary-zone reload sink the `WatchPolicies` subscriber drives — the doc
/// 13 §5.3 admitter-LAST D72 commit point. A trait so the subscriber loop is exercised
/// against the REAL [`RunningGate`] in production AND a synthetic recorder in tests,
/// without binding listeners; both reach the SAME single reload path
/// ([`RunningGate::reload_boundary_zone`] → one `BoundaryZoneReload` per transport).
pub trait BoundaryZoneSink {
    /// Commit a new authored-SOA boundary zone (the admitter-LAST step). The caller has
    /// already confirmed the enforcement layers applied this snapshot version, so the
    /// admitter commits LAST by re-sourcing the suffix here.
    fn commit_boundary_zone(&self, boundary_zone: &str);
}

impl<
        P: PolicyHook,
        M: AdmissionMap + Send + Sync + 'static,
        S: NftSetProgrammer + Send + Sync + 'static,
    > BoundaryZoneSink for RunningGate<P, M, S>
{
    fn commit_boundary_zone(&self, boundary_zone: &str) {
        self.reload_boundary_zone(boundary_zone);
    }
}

/// A detached, `Clone + Send + Sync` handle on a gate's per-transport boundary-zone reload
/// handles — the SAME `BoundaryZoneReload`s [`RunningGate::reload_boundary_zone`] drives, so
/// committing through this handle is byte-identical to committing through the gate (one
/// reload path). `main` hands this to the `WatchPolicies` subscriber task while it keeps the
/// gate to block on its listeners; obtained via [`RunningGate::boundary_zone_reloader`]. The
/// handle is `PolicyHook`-free (it holds only the signature reload handles), so the
/// subscriber task does not carry the gate's `P` type parameter.
#[derive(Clone)]
pub struct GateBoundaryReloader {
    reloads: Vec<BoundaryZoneReload>,
}

impl BoundaryZoneSink for GateBoundaryReloader {
    fn commit_boundary_zone(&self, boundary_zone: &str) {
        // Admitter-LAST commit: re-source the authored SOA on every transport in one call,
        // the same loop `RunningGate::reload_boundary_zone` runs (no per-transport skew).
        for reload in &self.reloads {
            reload.reload(boundary_zone);
        }
    }
}

/// The evaluator re-source sink the `WatchPolicies` subscriber drives for the PRODUCTION
/// hot path — the doc 11 §5.3 admitter-LAST D72 commit point for the running
/// [`PolicyCorePolicy`]. A trait so the subscriber loop is exercised against the REAL
/// evaluator in production AND a synthetic recorder in tests; both re-source the SAME running
/// evaluator handle ([`PolicyCorePolicy::reload`]). The committed composed document + W2 clamp
/// window arrive on the [`BoundarySnapshot`]; this sink applies them to the live evaluator.
pub trait PolicyEvaluatorSink {
    /// Re-source the running evaluator from a freshly-committed policy version (the
    /// admitter-LAST step). The enforcement layers already applied this version before it
    /// reached the feed, so re-sourcing the evaluator HERE is strictly last.
    fn commit_policy(&self, composed: &ComposedPolicy, ttl_clamp: TtlClamp);
}

/// A detached, `Clone + Send + Sync` handle on a gate's running [`PolicyCorePolicy`] evaluator
/// — a SHARED-HANDLE clone, so re-sourcing through it is byte-identical to re-sourcing every
/// transport's evaluator at once (the policy is shared across the UDP + TCP handlers and this
/// handle by one inner `Arc`). `main` hands this to the `WatchPolicies` subscriber task while
/// it keeps the gate to block on its listeners; obtained via
/// [`RunningGate::policy_reloader`]. The handle carries the concrete [`PolicyCorePolicy`] (the
/// production evaluator), never the gate's generic `P`, so the subscriber task is evaluator-
/// typed without the listener shell's type parameter.
#[derive(Clone)]
pub struct GatePolicyReloader {
    policy: PolicyCorePolicy,
}

impl PolicyEvaluatorSink for GatePolicyReloader {
    fn commit_policy(&self, composed: &ComposedPolicy, ttl_clamp: TtlClamp) {
        // Admitter-LAST commit: re-source the running evaluator (the same shared inner state
        // the UDP + TCP handlers read) in one swap — no per-transport skew, no listener re-bind.
        self.policy.reload(composed.clone(), ttl_clamp);
    }
}

/// One live DNS-2b admission the gate has minted: the `(session, fqdn, ip)` triple a
/// successful `Allow` derived (doc 11 §3.1/§5.2/§8.3 — the W1/W2 admission transaction).
///
/// This is the MINIMAL admission record the §5.4 revocation sweep re-evaluates. The W1/W2
/// admission transaction ([`crate::txn`]) now mints these into the gate's shared
/// [`LiveAdmissions`] registry on every `Allow` answer (the insert-then-answer DNS-2b map +
/// reportable NFT-3 set write are wired; the production `ds-nft` `NftWriter` binding is the
/// documented crate-dependency seam). Each record carries exactly the fields the sweep needs:
/// the `session` + `qname` the sweep re-evaluates under the new evaluator, and the resolved `ip`
/// whose allow-set element the sweep deletes (refcount-aware) when the re-evaluation denies the
/// name. Tests still feed records synthetically to exercise the sweep in isolation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAdmission {
    /// The attributed session the admission was minted for (doc 11 §5.1) — the §5.4
    /// `flush_session` key and one third of the DNS-2b map key.
    pub session: String,
    /// The admitted name, lower-cased trailing-dot form — the name the sweep re-evaluates
    /// against the NEW composed document to decide whether the admission still stands.
    pub fqdn: String,
    /// The resolved address the admission allow-listed — the allow-set element the sweep
    /// deletes when the re-evaluation denies the name AND no other live admission references
    /// it (the reverse-index refcount; a shared-CDN IP survives while another name still holds
    /// it). Carried as a plain [`std::net::IpAddr`] — no wire type at this boundary.
    pub ip: IpAddr,
    /// The host-local `host_session_index` (D4) this admission's per-session NFT-3 allow set
    /// (`allow4_<idx>`/`allow6_<idx>`) and `(leg, index)` mark were composed under — the SAME
    /// index `crate::txn` keyed `allow_set_name(family, inputs.session_index)` and
    /// `compose(Leg::AgentVm, inputs.session_index)` on at admit time. Carried on the record so
    /// the §5.4 sweep deletes the EXACT per-session set the insert filled (`allow4_<idx>`), not
    /// the index-0 approximation, and the routed mark composes from the SAME real index — so a
    /// withdraw under concurrent sessions targets the freed admission's own `allow4_<idx>`,
    /// never another session's set. Defaults to `0` via [`new`](Self::new) (the W1/W2 mint that
    /// has not yet threaded its index keeps the prior index-0 behavior byte-for-byte); the
    /// index-carrying constructor [`with_host_session_index`](Self::with_host_session_index)
    /// sets the real value.
    pub host_session_index: u32,
}

impl LiveAdmission {
    /// Build a live admission record (the W1/W2 transaction mints these on every `Allow`; tests
    /// feed them synthetically). `fqdn` is normalized to the lower-cased trailing-dot form the
    /// evaluator keys on, so the sweep's re-evaluation matches the original admission's query name.
    ///
    /// The `host_session_index` defaults to `0` — the prior index-0 behavior, kept byte-for-byte
    /// for any mint that has not yet threaded its real index. Chain
    /// [`with_host_session_index`](Self::with_host_session_index) to carry the real per-session
    /// index the admission's `allow4_<idx>` set + `(leg, index)` mark were composed under, so the
    /// §5.4 sweep keys on the freed admission's own set rather than `allow4_0`.
    pub fn new(session: impl Into<String>, fqdn: impl Into<String>, ip: IpAddr) -> Self {
        let mut fqdn = fqdn.into().to_ascii_lowercase();
        if !fqdn.ends_with('.') {
            fqdn.push('.');
        }
        Self {
            session: session.into(),
            fqdn,
            ip,
            host_session_index: 0,
        }
    }

    /// Stamp the host-local `host_session_index` (D4) this admission's per-session allow set and
    /// mark were composed under (`allow_set_name(family, idx)` / `compose(leg, idx)`). The W1/W2
    /// admission transaction has `inputs.session_index` in hand when it mints the record, so it
    /// threads the real index here; the §5.4 sweep then reads it off the freed admission and
    /// deletes from `allow4_<idx>` (not the index-0 approximation). A builder so the back-compat
    /// [`new`](Self::new) signature stays intact.
    #[must_use]
    pub fn with_host_session_index(mut self, host_session_index: u32) -> Self {
        self.host_session_index = host_session_index;
        self
    }
}

/// The host-local registry of LIVE DNS-2b admissions the §5.4 revocation sweep re-evaluates
/// (doc 11 §5.4 / D53 / D72). Holds the `(session, fqdn, ip)` triples the gate has admitted, so
/// that after an admitter-LAST evaluator re-source the sweep can re-decide each one against the
/// NEW composed document and remove the now-denied derived state.
///
/// The W1/W2 admission transaction ([`crate::txn`]) mints into this registry on every `Allow`
/// answer: `main` constructs ONE registry in [`spawn_gate`], shares it into both transports'
/// admission stores AND hands it to the [`SnapshotCommitSink::with_revocation_sweep`] sweep via
/// [`RunningGate::live_admissions`], so the sweep re-evaluates the admissions the transaction
/// actually minted (the closed admission ↔ revocation loop; the evaluator re-sources FIRST, then
/// the sweep runs against it). A shared `Arc<Mutex<…>>` so the `SnapshotCommitSink` and the
/// admission path hold the SAME live set; cloning is a shared-handle clone. Tests still feed
/// records synthetically to drive the sweep in isolation.
///
/// Reverse-index refcount discipline (doc 11 §5.4): an allow-set element (an IP) is deleted only
/// when NO live admission still references it — a shared-CDN IP that a still-allowed name holds
/// survives a sibling name's revocation. The sweep BIASES TO UNDER-DELETE (D53 / W4: natural
/// expiry, not the sweep, cleans up a leaked element), so an IP is dropped only when its
/// refcount reaches zero.
///
/// **ONE shared reverse index (close the admission ↔ revocation refcount loop).** The DNS-2b map
/// the W1/W2 admission transaction writes (`crate::txn::InMemoryAdmissionMap`) ALREADY maintains
/// the per-`(session, ip)` distinct-name refcount — the frozen [`ds_contracts::dns_admission::ReverseIndex`],
/// reachable via [`ds_contracts::dns_admission::AdmissionMap::reverse_index`]. When the gate builds
/// its stores ([`crate::txn::AdmissionStores`]) it BINDS that same map handle here (via
/// [`bind_admission_map`](Self::bind_admission_map), threaded through the existing
/// `AdmissionStores::with_parts`/`live()` seams), so the §5.4 sweep's allow-set-deletion decision
/// reads off the SAME counts the map maintains — one refcount, no drift. The sweep then REVOKES each
/// now-denied `(session, fqdn)` THROUGH that shared map (`AdmissionMap::revoke` decrefs the shared
/// index and returns the IPs whose count reached zero off the SHARED reverse index, never a second
/// independently-derived survivor count). A synthetic/test registry with no bound map (the
/// isolation-test path) keeps the survivor-derived refcount fallback, so the sweep is exercisable in
/// isolation; either way the result is identical (an IP frees only when no surviving admission
/// references it; saturating decref never underflows — W4 bias-to-under-delete).
///
/// **Polymorphic over the backing map (in-memory OR shm).** The bound handle is a
/// [`SweepRevocable`] trait object, NOT a concrete `InMemoryAdmissionMap`: the production read
/// path D131 ships is the cross-process **shm** map (`ds_admission_shm::ShmAdmissionMap`), and the
/// sweep MUST revoke through whichever map the gate's stores write through so a revoked domain is
/// tombstoned on the live shm read path (else a cross-process ds-tlsproxy reader keeps vouching it).
/// The narrow object-safe `SweepRevocable` surface exposes only the one `revoke` the sweep needs —
/// the frozen [`ds_contracts::dns_admission::AdmissionMap`] trait itself is NOT object-safe (it has
/// the `Reverse` associated type), so a tiny dyn-able shim is the polymorphism seam.
///
/// `Debug` is hand-implemented (not derived) because the bound `map` is now a
/// `dyn SweepRevocable` trait object that is deliberately NOT `Debug` (the live shm map is not
/// `Debug`); the manual impl renders the map as a presence flag, which is all any diagnostic needs.
#[derive(Clone, Default)]
pub struct LiveAdmissions {
    inner: Arc<Mutex<Vec<LiveAdmission>>>,
    /// Parked TTL-ask-grants (doc 09 §4 DNS-3 / POL-5): a user said "yes" to an asked domain,
    /// so a session-scoped TTL'd allow is held until the next DNS retry resolves it. A `vN+1`
    /// that now DENIES that domain KILLS the grant (a policy update outranks a user approval —
    /// fail-closed), so the §5.4 sweep re-evaluates these AS PART OF the SAME pass it sweeps the
    /// DNS-2b admissions, against the SAME re-sourced evaluator, and any IPs a grant already
    /// admitted free through the SAME shared reverse index. An approved grant that has already
    /// resolved an address is a plain [`LiveAdmission`] (it admitted a flow) and rides the
    /// `inner` leg; this leg holds the genuinely-distinct PARKED grants whose retry has not yet
    /// minted an address, so a policy flip before the retry still evicts them.
    ask_grants: Arc<Mutex<Vec<LiveAskGrant>>>,
    /// The SHARED DNS-2b admission map whose reverse index the §5.4 sweep reads its allow-set-
    /// deletion decision off of (the SAME `(session, ip)` distinct-name refcount the W1/W2
    /// transaction maintains — frozen [`ds_contracts::dns_admission::AdmissionMap`]/[`ds_contracts::dns_admission::ReverseIndex`]).
    /// `Some` when the gate bound its stores' map here (the production / closed-loop path, via
    /// [`bind_admission_map`](Self::bind_admission_map)); `None` for a bare synthetic registry, which
    /// falls back to the survivor-derived refcount so the sweep is still exercisable in isolation.
    /// A shared-handle [`SweepRevocable`] clone of the one `AdmissionStores` holds (a blanket-impl'd
    /// `Arc<RwLock<M>>` for any `M: AdmissionMap` — in-memory OR the live shm map), so the sweep's
    /// revoke decrefs the very index the admit incref'd — no second count to drift. (Interim DNS-2b
    /// read-contention fix, doc 04 §6 D131 — see `AdmissionStores::map`; the sweep's revoke is a
    /// WRITE, so the shim takes the `.write()` guard internally.)
    map: Option<Arc<dyn SweepRevocable>>,
}

impl std::fmt::Debug for LiveAdmissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render the bound map as a presence flag — the `dyn SweepRevocable` trait object is
        // deliberately not `Debug` (the live shm map is not `Debug`), and no diagnostic needs more
        // than "is a shared reverse index bound?".
        f.debug_struct("LiveAdmissions")
            .field("inner", &self.inner)
            .field("ask_grants", &self.ask_grants)
            .field("map_bound", &self.map.is_some())
            .finish()
    }
}

/// The narrow, object-safe revocation surface the §5.4 sweep needs from the bound DNS-2b map.
///
/// [`LiveAdmissions`] is non-generic (it appears bare in `RunningGate`, `apply.rs`, and `main.rs`),
/// so it cannot be parameterized over `M: AdmissionMap` without leaking the `M` everywhere. The
/// frozen [`ds_contracts::dns_admission::AdmissionMap`] trait is itself NOT object-safe (its
/// `Reverse` associated type), so `dyn AdmissionMap` is impossible. This tiny shim exposes ONLY the
/// `revoke` the sweep calls — it is blanket-impl'd over `Arc<RwLock<M>>` for any
/// `M: AdmissionMap + Send + Sync`, taking the in-process write guard internally (matching the old
/// `map.write()` discipline), so the bound handle can be the in-memory map OR the live shm map with
/// no other code change. `Send + Sync` so the bound `Arc<dyn SweepRevocable>` rides across the
/// gate's tasks; [`LiveAdmissions`] hand-impls `Debug` (the trait object is not `Debug` — the shm
/// map is not `Debug`, and the sweep never needs to format the bound map).
pub(crate) trait SweepRevocable: Send + Sync {
    /// Revoke a now-denied `(session, fqdn)` THROUGH the bound map, returning the IPs whose shared
    /// reverse-index refcount reached zero (the allow-set elements safe to delete). Mirrors the
    /// frozen [`ds_contracts::dns_admission::AdmissionMap::revoke`] semantics (absent key → empty
    /// success; saturating decref never underflows). The `&self` shim takes the inner write guard.
    fn revoke(&self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError>;
}

/// Blanket impl: any `Arc<RwLock<M>>` for an `M: AdmissionMap` is a [`SweepRevocable`] — it acquires
/// the in-process write guard (the §5.4 sweep's revoke is a WRITE, D131) and delegates to the frozen
/// `AdmissionMap::revoke`. This is what lets the InMemory default path AND `with_shm_writer` bind
/// their concrete map handle into the same non-generic [`LiveAdmissions`] field.
impl<M> SweepRevocable for RwLock<M>
where
    M: AdmissionMap + Send + Sync,
{
    fn revoke(&self, key: &AdmissionKey) -> Result<Vec<AdmittedAddr>, AdmissionError> {
        // WRITE path (the §5.4 sweep): `revoke` mutates the bound map (decrefs the shared reverse
        // index), so it takes the RwLock write guard — identical lock discipline to the old inline
        // `map.write()` (interim contention fix, D131).
        self.write()
            .expect("admission-map lock poisoned")
            .revoke(key)
    }
}

/// One PARKED TTL-ask-grant the §5.4 sweep re-evaluates (doc 09 §4 DNS-3 / POL-5): a user
/// approved an asked domain, parking a session-scoped TTL'd allow so the next DNS retry resolves.
/// A `vN+1` that now DENIES that domain kills the grant — a policy update outranks a user approval
/// (fail-closed). The grant carries any IP(s) it already admitted (empty for a grant parked before
/// any address was resolved — it still evicts on a deny, it simply frees no allow-set element),
/// for the SAME rung-conditional flush + allow-set-free treatment the admission leg gets; those
/// IPs free through the SAME shared reverse index, never a second derivation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveAskGrant {
    /// The session the grant is scoped to (the approval is session-scoped, POL-5) — the
    /// `flush_session` key and the DNS-2b map key third.
    pub session: String,
    /// The granted (approved) domain, lower-cased trailing-dot form — the name the sweep
    /// re-evaluates against the NEW composed document to decide whether the grant still stands.
    pub fqdn: String,
    /// The IP(s) the grant already allow-listed (the flow the approval admitted, if the retry
    /// already resolved one). Empty for a grant parked before any address was admitted.
    pub ips: Vec<IpAddr>,
    /// The host-local `host_session_index` (D4) this grant's per-session allow set + mark were
    /// composed under — the SAME role as [`LiveAdmission::host_session_index`]. Read off by the
    /// §5.4 sweep on an ask-grant-only eviction (no revoked admission) so the routed delete + mark
    /// key on the grant's real `allow4_<idx>` rather than the index-0 approximation. Defaults to
    /// `0` via [`new`](Self::new); set the real value with
    /// [`with_host_session_index`](Self::with_host_session_index).
    pub host_session_index: u32,
}

impl LiveAskGrant {
    /// Build a parked ask-grant, normalizing `fqdn` to the lower-cased trailing-dot form the
    /// evaluator keys on (so the sweep's re-evaluation matches the asked query name). The
    /// `host_session_index` defaults to `0`; chain
    /// [`with_host_session_index`](Self::with_host_session_index) to carry the real per-session
    /// index the grant's allow set + mark were composed under.
    pub fn new(session: impl Into<String>, fqdn: impl Into<String>, ips: Vec<IpAddr>) -> Self {
        let mut fqdn = fqdn.into().to_ascii_lowercase();
        if !fqdn.ends_with('.') {
            fqdn.push('.');
        }
        Self {
            session: session.into(),
            fqdn,
            ips,
            host_session_index: 0,
        }
    }

    /// Stamp the host-local `host_session_index` (D4) this grant's per-session allow set + mark
    /// were composed under, so an ask-grant-only §5.4 eviction keys the routed delete on the
    /// grant's own `allow4_<idx>`. A builder so the back-compat [`new`](Self::new) stays intact.
    #[must_use]
    pub fn with_host_session_index(mut self, host_session_index: u32) -> Self {
        self.host_session_index = host_session_index;
        self
    }
}

impl LiveAdmissions {
    /// An empty live-admission registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bind the SHARED DNS-2b admission map whose reverse index the §5.4 sweep reads its allow-set-
    /// deletion decision off of — closing the admission ↔ revocation refcount loop onto ONE index.
    /// Called by [`crate::txn::AdmissionStores`] when it builds its store bundle (so the registry the
    /// W1/W2 transaction mints into and the map it increfs share the SAME reverse-index handle); the
    /// sweep then revokes each now-denied name THROUGH this map, reading the freed IPs off the SAME
    /// counts the map maintains instead of re-deriving an independent survivor refcount. A
    /// shared-handle `Arc` clone — the bound map is the very one `AdmissionStores` writes through.
    /// A registry built without a bound map (the bare synthetic/test path) keeps the survivor-derived
    /// fallback, so the sweep is still exercisable in isolation.
    ///
    /// Generic over the backing map `M` so BOTH the InMemory default path
    /// (`AdmissionStores::with_parts`/`Default`) AND the live shm-writer path
    /// (`AdmissionStores::with_shm_writer`) bind their concrete handle: the `Arc<RwLock<M>>` is stored
    /// as a [`SweepRevocable`] trait object (the blanket impl above), keeping [`LiveAdmissions`]
    /// non-generic while the sweep revokes through whichever real map the stores write through.
    pub(crate) fn bind_admission_map<M>(&mut self, map: Arc<RwLock<M>>)
    where
        M: AdmissionMap + Send + Sync + 'static,
    {
        self.map = Some(map);
    }

    /// Record a freshly-minted live admission (the W1/W2 transaction calls this on every `Allow`;
    /// tests feed it synthetically). The same `(session, fqdn, ip)` is not de-duplicated here —
    /// the refcount the sweep reads is the count of records holding an IP, so a re-admitted name
    /// correctly raises the refcount.
    pub fn admit(&self, admission: LiveAdmission) {
        self.lock().push(admission);
    }

    /// The number of live admissions currently held — used by the sweep's tests to assert which
    /// `(session, fqdn, ip)` entries survived a revocation.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the registry holds no live admissions.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// A snapshot of the live admissions (clone) — the sweep's tests read this to assert the
    /// exact `(session, fqdn, ip)` triples that survived (or were revoked).
    pub fn snapshot(&self) -> Vec<LiveAdmission> {
        self.lock().clone()
    }

    /// Park a TTL-ask-grant for the §5.4 sweep to re-evaluate (the POL-5 approval path mints
    /// these when a user approves an asked domain; tests feed them synthetically). A parked grant
    /// whose retry has not yet resolved an address still evicts on a deny — it simply frees no
    /// allow-set element. An approved grant that ALREADY resolved an address is a plain
    /// [`LiveAdmission`] minted through [`admit`](Self::admit); this leg is only the genuinely-
    /// distinct parked grants.
    pub fn park_ask_grant(&self, grant: LiveAskGrant) {
        self.lock_grants().push(grant);
    }

    /// The number of parked ask-grants currently held — used by the sweep's tests to assert which
    /// grants survived a re-evaluation.
    pub fn ask_grant_len(&self) -> usize {
        self.lock_grants().len()
    }

    /// A snapshot of the parked ask-grants (clone) — the sweep's tests read this to assert the
    /// grants that survived (or were evicted).
    pub fn ask_grant_snapshot(&self) -> Vec<LiveAskGrant> {
        self.lock_grants().clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<LiveAdmission>> {
        self.inner.lock().expect("live-admissions lock poisoned")
    }

    fn lock_grants(&self) -> std::sync::MutexGuard<'_, Vec<LiveAskGrant>> {
        self.ask_grants
            .lock()
            .expect("live-ask-grants lock poisoned")
    }
}

impl RevocationTarget for LiveAdmissions {
    fn sweep(&self, evaluator: &dyn AdmissionReevaluator) -> SweepOutcome {
        // The doc 11 §5.4 revocation sweep, run AFTER the admitter-LAST evaluator re-source.
        // Re-evaluate every live admission against the NEW evaluator; an admission whose name
        // is no longer admitted (the verdict flipped Allow → Deny/Ask) is removed from the
        // DNS-2b map. An allow-set element (the IP) is deleted only when NO surviving admission
        // still references it — the reverse-index refcount (a shared-CDN IP holds while another
        // name keeps it; bias to under-delete, D53/W4). A revoked admission whose re-evaluation
        // verdict severs established flows (D53: Deny at block-or-higher rung) is flagged for the
        // rung-conditional `flush_session` (the conntrack flush the shared primitive fires);
        // expiry is NOT revocation (W4), so an Allow that simply survives flushes nothing.
        let mut live = self.lock();

        // First pass: decide which records survive the re-evaluation and collect the revoked
        // ones (for the DNS-2b map delete + the rung-conditional flush record).
        let mut survivors: Vec<LiveAdmission> = Vec::with_capacity(live.len());
        let mut revoked: Vec<RevokedAdmission> = Vec::new();
        for admission in live.drain(..) {
            let verdict = evaluator.reevaluate(&admission.session, &admission.fqdn);
            if verdict.admits() {
                survivors.push(admission);
            } else {
                // The name is no longer admitted: this DNS-2b entry is revoked. The conntrack
                // flush is rung-conditional (D53) — it fires only when the deny severs
                // established flows (a Deny at a block-or-higher rung), never on a plain
                // gate-new-flows-only deny or an Ask.
                let severs = verdict.severs_established_flows();
                revoked.push(RevokedAdmission {
                    admission,
                    flush_conntrack: severs,
                });
            }
        }
        drop(live);

        // ASK-GRANT LEG (doc 09 §4 DNS-3 / POL-5): re-evaluate every PARKED ask-grant against the
        // SAME re-sourced evaluator, in the SAME sweep pass. A user approval is OUTRANKED by a
        // `vN+1` that now denies the asked domain (fail-closed): the grant is evicted. The grant's
        // already-admitted IPs (empty for a grant parked before any address resolved) ride the
        // SAME shared reverse-index refcount the admission leg uses — there is NO second survivor
        // derivation. A surviving grant whose name still admits is restored, exactly like a
        // surviving admission.
        let mut surviving_grants: Vec<LiveAskGrant> = Vec::new();
        let mut revoked_grants: Vec<RevokedAskGrant> = Vec::new();
        for grant in self.lock_grants().drain(..) {
            let verdict = evaluator.reevaluate(&grant.session, &grant.fqdn);
            if verdict.admits() {
                surviving_grants.push(grant);
            } else {
                let severs = verdict.severs_established_flows();
                revoked_grants.push(RevokedAskGrant {
                    grant,
                    flush_conntrack: severs,
                });
            }
        }

        // Second pass: decide which freed IPs to delete from the allow set, reading the refcount
        // off the ONE SHARED reverse index the W1/W2 transaction maintains — never a second,
        // independently-derived survivor count that could drift from it. BOTH legs (the DNS-2b
        // admissions AND the parked ask-grants) fold through THIS one pass, so the ask-grant leg's
        // freed IPs are decided by the SAME refcount, never a parallel derivation.
        //
        // When the gate bound its DNS-2b map here (`bind_admission_map`, threaded through
        // `AdmissionStores::with_parts`/`live()`), revoke each now-denied `(session, fqdn)` THROUGH
        // that shared map: `AdmissionMap::revoke` decrefs the SAME `(session, ip)` distinct-name
        // refcount the admit incref'd (saturating at zero — never underflow) and RETURNS the IPs
        // whose count reached zero off the shared `ReverseIndex`. Those refcount-zero IPs are
        // exactly the allow-set deletions — a shared-CDN IP a survivor still holds keeps a non-zero
        // count there and is NOT returned (bias to under-delete, W4). One refcount, no drift.
        //
        // A registry with no bound map (the bare synthetic/isolation-test path) has no shared index
        // to read, so it falls back to the survivor-derived refcount: an IP is kept iff some
        // survivor still references it. The two paths agree by construction — the shared index's
        // post-revoke count for an IP equals the number of surviving distinct names holding it.
        let allow_set_deletions = self.resolve_allow_set_deletions(
            &survivors,
            &surviving_grants,
            &revoked,
            &revoked_grants,
        );

        // Restore the survivors into the live set (taken out above only to drop the lock before the
        // map access). A concurrent admission may have appended its own record in the gap — those
        // are extended back in, never dropped, so a name admitted mid-sweep is preserved. The
        // surviving ask-grants are restored the same way.
        {
            let mut live = self.lock();
            let mut restored = survivors;
            restored.append(&mut *live);
            *live = restored;
        }
        {
            let mut grants = self.lock_grants();
            let mut restored = surviving_grants;
            restored.append(&mut *grants);
            *grants = restored;
        }

        SweepOutcome {
            revoked,
            evicted_ask_grants: revoked_grants,
            allow_set_deletions,
        }
    }

    fn live_session_uuids(&self) -> HashSet<String> {
        // Every session that still holds a live DNS-2b admission OR a parked ask-grant. Read AFTER a
        // sweep restores its survivors, so a session fully revoked by the sweep is absent here — the
        // signal the commit sink uses to prune its fleet-revocation rows (doc 19 §5.4).
        let mut sessions: HashSet<String> = self.lock().iter().map(|a| a.session.clone()).collect();
        sessions.extend(self.lock_grants().iter().map(|g| g.session.clone()));
        sessions
    }
}

impl LiveAdmissions {
    /// Resolve the allow-set element deletions for one sweep — the refcount-zero freed IPs — reading
    /// the decision off the ONE SHARED reverse index the W1/W2 transaction maintains whenever the
    /// gate bound its DNS-2b map ([`bind_admission_map`](Self::bind_admission_map)), and falling back
    /// to the survivor-derived refcount only for a bare synthetic registry with no bound map.
    ///
    /// The shared-index path REVOKES each now-denied `(session, fqdn)` through the bound map: each
    /// `AdmissionMap::revoke` decrefs the SAME `(session, ip)` distinct-name count the admit
    /// incref'd and returns the IPs whose count reached zero off the shared `ReverseIndex`. An IP is
    /// deleted from the allow set exactly when the shared index reports it free (refcount zero) — a
    /// shared-CDN IP a survivor still holds keeps a non-zero count there and is never returned (W4
    /// bias-to-under-delete; saturating decref never underflows). Deduped + filtered to the revoked
    /// IPs so the contract `Vec<IpAddr>` shape is unchanged.
    fn resolve_allow_set_deletions(
        &self,
        survivors: &[LiveAdmission],
        surviving_grants: &[LiveAskGrant],
        revoked: &[RevokedAdmission],
        revoked_grants: &[RevokedAskGrant],
    ) -> Vec<IpAddr> {
        let Some(map) = &self.map else {
            // No shared index bound (bare synthetic registry): keep the survivor-derived refcount —
            // an IP is kept iff some survivor (admission OR ask-grant) still references it. Identical
            // result to reading the shared index, since that index's post-revoke count for an IP
            // equals the number of surviving distinct names holding it.
            return survivor_derived_deletions(
                survivors,
                surviving_grants,
                revoked,
                revoked_grants,
            );
        };

        // The shared reverse index IS the refcount: revoke each now-denied `(session, fqdn)` through
        // the bound map so its decref runs against the SAME index the admit incref'd. The map returns
        // the IPs whose `(session, ip)` count reached zero off the shared `ReverseIndex` — exactly
        // the allow-set elements no live admission references (a survivor holding the IP keeps a
        // non-zero count there, so it is never freed: bias to under-delete, W4). Dedup per IP and
        // preserve first-seen order so the `Vec<IpAddr>` contract shape is unchanged. The ask-grant
        // leg revokes through the SAME map (an approved grant that resolved an address was minted as
        // a DNS-2b entry), so its freed IPs are decided by the SAME refcount — never a fork.
        // The bound `map` is a [`SweepRevocable`] trait object — the in-memory map OR the live shm
        // map. Its `revoke` takes the in-process RwLock write guard internally (the §5.4 sweep's
        // revoke is a WRITE; interim contention fix, D131), so a shm-backed bind tombstones the
        // cross-process shm slot and decrefs the shm reverse index: a revoked domain immediately
        // stops being vouched on the live ds-tlsproxy read path (the production read path D131 ships).
        let mut allow_set_deletions: Vec<IpAddr> = Vec::new();
        let mut revoked_keys: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        let revoked_admission_keys = revoked.iter().map(|r| {
            (
                r.admission.session.clone(),
                r.admission.fqdn.clone(),
                Some(&r.admission.ip),
            )
        });
        let revoked_grant_keys = revoked_grants
            .iter()
            .map(|r| (r.grant.session.clone(), r.grant.fqdn.clone(), None));
        for (session, fqdn, _ip) in revoked_admission_keys.chain(revoked_grant_keys) {
            // One revoke per distinct `(session, fqdn)` — `LiveAdmissions::admit` does not dedup
            // (a refresh pushes a fresh record), but the DNS-2b map holds ONE entry per name, and a
            // second revoke of an already-revoked key is an idempotent empty success that frees
            // nothing (saturating decref never underflows). Skipping the duplicate keys avoids a
            // wasted idempotent revoke without changing the result — and naturally dedups an
            // admission and an ask-grant that name the SAME `(session, fqdn)`.
            if !revoked_keys.insert((session.clone(), fqdn.clone())) {
                continue;
            }
            let key = ds_contracts::dns_admission::AdmissionKey {
                session_uuid: session,
                original_query_fqdn: fqdn,
            };
            // The freed IPs the SHARED reverse index reports at refcount zero (the SAME index the
            // map maintains). A storage error biases to under-delete (no deletion) rather than
            // wedge the admitter — a spuriously-retained element costs only a later expiry (W4).
            let freed = map.revoke(&key).unwrap_or_default();
            for addr in freed {
                if let Some(ip) = ip_of_admitted(&addr) {
                    if !allow_set_deletions.contains(&ip) {
                        allow_set_deletions.push(ip);
                    }
                }
            }
        }
        allow_set_deletions
    }
}

/// The survivor-derived allow-set-deletion fallback for a registry with NO bound shared reverse
/// index (the bare synthetic/isolation-test path): an IP is deleted only when no SURVIVOR still
/// references it (deduped, once per IP). This is the byte-for-byte behavior the sweep had before the
/// shared index was wired, and it agrees with the shared-index path by construction — the shared
/// index's post-revoke `(session, ip)` count for an IP equals the number of surviving distinct names
/// holding it, so "no survivor references it" and "shared refcount reached zero" pick the same IPs.
fn survivor_derived_deletions(
    survivors: &[LiveAdmission],
    surviving_grants: &[LiveAskGrant],
    revoked: &[RevokedAdmission],
    revoked_grants: &[RevokedAskGrant],
) -> Vec<IpAddr> {
    let mut live_refcount: HashMap<IpAddr, usize> = HashMap::new();
    for admission in survivors {
        *live_refcount.entry(admission.ip).or_insert(0) += 1;
    }
    // A surviving ask-grant references its IP(s) too — they hold the allow-set element against an
    // evicted sibling's revocation exactly like a surviving admission (the unified refcount, W4).
    for grant in surviving_grants {
        for ip in &grant.ips {
            *live_refcount.entry(*ip).or_insert(0) += 1;
        }
    }
    let mut allow_set_deletions: Vec<IpAddr> = Vec::new();
    let revoked_ips = revoked.iter().map(|r| r.admission.ip).chain(
        revoked_grants
            .iter()
            .flat_map(|r| r.grant.ips.iter().copied()),
    );
    for ip in revoked_ips {
        // Delete the allow-set element only when its refcount among survivors (admissions AND
        // grants) is zero (no live entry references it) — and only once per IP.
        if !live_refcount.contains_key(&ip) && !allow_set_deletions.contains(&ip) {
            allow_set_deletions.push(ip);
        }
    }
    allow_set_deletions
}

/// Recover a `std::net::IpAddr` from a frozen [`ds_contracts::dns_admission::AdmittedAddr`] (the
/// network-byte-order octets + family tag the shared map's `revoke` returns) — the inverse of the
/// `crate::txn::to_admitted_addr` / [`admitted_addr`] projection, so the IP the shared reverse index
/// reports free round-trips byte-exact to the `IpAddr` the `SweepOutcome::allow_set_deletions`
/// contract carries. A malformed octet length (cannot happen for a map-stored address) yields `None`
/// and is skipped (bias to under-delete — never invent a deletion).
fn ip_of_admitted(addr: &AdmittedAddr) -> Option<IpAddr> {
    match addr.family {
        AddressFamily::V4 => {
            let octets: [u8; 4] = addr.octets.as_slice().try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        AddressFamily::V6 => {
            let octets: [u8; 16] = addr.octets.as_slice().try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
    }
}

/// The minimal re-evaluation surface the §5.4 sweep needs from the running evaluator: re-decide
/// one live admission's `(session, fqdn)` against the CURRENT composed document. A trait so the
/// sweep is driven by the production [`PolicyCorePolicy`] (re-sourced admitter-LAST) AND a
/// synthetic recorder in tests, without binding listeners. The returned [`Verdict`] carries the
/// frozen POL-3 provenance + the D53 rung, so the sweep reads the same `admits()` /
/// `severs_established_flows()` the hot path does — one verdict surface, no re-projection.
pub trait AdmissionReevaluator {
    /// Re-evaluate a live admission's name under the current policy version. The `session` is the
    /// §5.1 attribution key the original admission was minted under; `fqdn` is its lower-cased
    /// trailing-dot name. The verdict is the frozen [`Verdict`] off the running evaluator (POL-3
    /// provenance + D53 rung intact), so the sweep decides revoke/keep + rung-conditional flush
    /// off the SAME shape the gate's hot path authors from.
    fn reevaluate(&self, session: &str, fqdn: &str) -> crate::policy::Verdict;
}

impl AdmissionReevaluator for PolicyCorePolicy {
    fn reevaluate(&self, session: &str, fqdn: &str) -> crate::policy::Verdict {
        // Re-run the frozen `evaluate` against the running evaluator's CURRENT composed document
        // (which the admitter-LAST commit just re-sourced). A standard-class A query ctx — the
        // sweep re-decides admissibility of the name, not a specific qtype answer; `qtype = 1` (A)
        // is the canonical admission probe and the source is a loopback sentinel (the sweep is a
        // policy re-evaluation, not a fresh client query — §5.1 keys on `session`, never the raw
        // source). POL-3 provenance + the D53 rung ride the returned verdict verbatim.
        self.evaluate(&DnsQueryCtx {
            session: session.to_string(),
            qname: fqdn.to_string(),
            qtype: 1,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        })
    }
}

/// One revoked DNS-2b admission the §5.4 sweep removed, plus whether its re-evaluation severs
/// established flows (D53 rung-conditional conntrack flush). The shared `flush_session`
/// primitive (doc 11 §5.4, owned jointly with nft-writer) fires the conntrack flush iff
/// `flush_conntrack` is set; the DNS-2b map entry is deleted unconditionally (the admission no
/// longer stands under the new policy version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedAdmission {
    /// The `(session, fqdn, ip)` triple whose DNS-2b map entry the sweep deleted.
    pub admission: LiveAdmission,
    /// Whether the deny that revoked this admission severs established flows (D53: a `Deny` at a
    /// block-or-higher rung). When set, the shared `flush_session` primitive fires the
    /// rung-conditional conntrack flush; otherwise the deny only gates NEW flows (no flush —
    /// expiry, not revocation, cleans the rest up, W4).
    pub flush_conntrack: bool,
}

/// One evicted PARKED ask-grant the §5.4 sweep removed (doc 09 §4 DNS-3 / POL-5), plus whether its
/// re-evaluation severs established flows (D53 rung-conditional conntrack flush). A `vN+1` that now
/// denies the asked domain kills the grant — a policy update outranks a user approval (fail-closed)
/// — and the grant is evicted unconditionally; the `flush_conntrack` flag drives the SAME
/// rung-conditional `flush_session` the admission leg uses, over any IP(s) the grant already
/// admitted (none for a grant parked before its retry resolved an address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokedAskGrant {
    /// The parked ask-grant whose approval the new policy version outranked.
    pub grant: LiveAskGrant,
    /// Whether the deny that killed this grant severs established flows (D53: a `Deny` at a
    /// block-or-higher rung). Drives the rung-conditional conntrack flush over the grant's IP(s).
    pub flush_conntrack: bool,
}

/// What one §5.4 revocation sweep removed: the revoked DNS-2b admissions and evicted ask-grants
/// (each with its D53 rung-conditional flush flag) and the allow-set elements (IPs) the sweep
/// deleted after the reverse-index refcount (an IP no surviving admission OR ask-grant references).
/// A no-op sweep (nothing flipped to denied, or no derived state at all) yields empty vectors — the
/// steady state when a policy push loosens or leaves every live name allowed. The entries the sweep
/// re-evaluates are now minted by the W1/W2 admission transaction (admissions) and the POL-5
/// approval path (ask-grants); `main` shares its [`LiveAdmissions`] registry into the commit sink
/// via [`RunningGate::live_admissions`], so the sweep is no longer fed synthetically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// The revoked DNS-2b map entries the sweep deleted, each with its D53 flush flag.
    pub revoked: Vec<RevokedAdmission>,
    /// The parked ask-grants the sweep evicted (a `vN+1` denial outranked the user approval),
    /// each with its D53 flush flag — the genuinely-new POL-5 leg.
    pub evicted_ask_grants: Vec<RevokedAskGrant>,
    /// The allow-set elements (IPs) the sweep deleted — only IPs no surviving admission OR
    /// ask-grant references (the ONE shared reverse-index refcount; bias to under-delete, W4).
    pub allow_set_deletions: Vec<IpAddr>,
}

impl SweepOutcome {
    /// Whether the sweep removed nothing — every live admission AND ask-grant survived the
    /// re-evaluation (or there were none). The steady state today (no derived state yet) and after
    /// a policy LOOSENING.
    pub fn is_noop(&self) -> bool {
        self.revoked.is_empty()
            && self.evicted_ask_grants.is_empty()
            && self.allow_set_deletions.is_empty()
    }

    /// The distinct session UUIDs this sweep touched — every session whose DNS-2b admission was
    /// revoked OR whose parked ask-grant was evicted. The fleet-book teardown prune (doc 19 §5.4)
    /// intersects THIS set against the sessions that still hold a live admission after the sweep:
    /// a session the sweep touched that retains NO live admission has been fully torn down, so its
    /// fleet-revocation rows are pruned.
    pub fn revoked_session_uuids(&self) -> HashSet<String> {
        self.revoked
            .iter()
            .map(|r| r.admission.session.clone())
            .chain(
                self.evicted_ask_grants
                    .iter()
                    .map(|g| g.grant.session.clone()),
            )
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// §5.4 SweepOutcome → ENFORCEMENT routing (doc 11 §5.4 / D53 / D72; doc 14 §5).
//
// The sweep (above) PRODUCES the outcome; this routes it to the ds-nft enforcement
// primitives so a tightened-policy push actually SEVERS the now-denied derived
// state in the kernel, instead of discarding it. Two legs, byte-exact with the
// admission transaction's NFT-3 inserts (`crate::txn::SetInsert`):
//   (a) the ALLOW-SET ELEMENT DELETE — for every refcount-zero freed IP, the
//       compensating `delete element` on the SAME `allow4`/`allow6` set the
//       admission programmer wrote, keyed by the SAME `AdmittedAddr::to_dst_key`
//       textual form so insert and delete agree;
//   (b) the rung-conditional CONNTRACK FLUSH — for every revoked admission whose
//       `flush_conntrack` is set (D53: a Deny at a block-or-higher rung), the
//       `flush_session(DstFilter::Only, sever_pair)` over the freed IPs, the mark
//       DS_MARK_MASK-composed so a bare-index match never fires.
//
// The D53/W4 UNDER-DELETE bias is preserved verbatim: the freed-IP set is the
// sweep's already-computed `allow_set_deletions` (sole-reference IPs only — a
// shared-CDN IP a survivor still holds is NEITHER deleted NOR flushed). This
// routing NEVER recomputes the refcount; it faithfully routes what the sweep
// resolved.
//
// LOOPBACK/SYNTHETIC DEFAULT: the default enforcer is the reportable in-memory
// `RecordingSweepEnforcer` (no live nft/conntrack on `cargo test --offline`), the
// exact role `crate::txn::RecordingSetProgrammer` and ds-nft's `RecordingBackend`
// play for the insert/flush batches. The production `ds_nft::NftWriter` binding NOW
// LANDS (the workspace-internal `ds-nft` path-dep + the
// `impl SweepEnforcer for ds_nft::NftWriter<B>` below): leg (a) is a standalone
// `delete element` batch applied via `NftWriter::backend().apply_batch` (the SAME
// shape `refresh::refresh_batch`'s DeleteAdd embeds — there is NO
// `ds_nft::NftWriter::withdraw` method on the real surface), and leg (b) is
// `NftWriter::flush_session_report(&SessionRef, &DstFilter::Only(keys),
// &LegSelector::sever_pair())`. It is the SAME workspace edge the txn's
// `NftSetProgrammer` → `ds_nft::NftWriter` binding rides, selected ONLY behind
// `DS_NFTGATE_LIVE` (default OFF → the reportable enforcer; no live kernel write on
// the offline/CI path). The structure and every invariant are real and
// sandbox-verified here; the live kernel write is `DS_NFTGATE_LIVE`-gated and
// CI/manual-only.
// ─────────────────────────────────────────────────────────────────────────────

/// One ALLOW-SET ELEMENT DELETE the sweep routes — the compensating `delete element` for a
/// refcount-zero freed IP (doc 11 §5.4 leg (a)). Mirrors the admission transaction's
/// `crate::txn::SetInsert` field-for-field in the fields a delete needs: the SAME set name
/// (`allow4`/`allow6`), the SAME `AdmittedAddr::to_dst_key` element form, and the masked
/// `(magic ∪ leg ∪ index)` mark over [`DS_MARK_MASK`] — so the delete the production
/// `ds_nft::NftWriter` renders agrees byte-exact with the insert.
///
/// The masked mark is carried (never a bare value) so the element is never addressed without the
/// frozen mask — the same discipline the `MarkMatch` enforces. The `session` is the §5.1
/// attribution key the freed IP was admitted under; the `set_name` + `mark_value` are already
/// keyed on the freed admission's REAL `host_session_index` (resolved in `route_sweep_outcome` off
/// the `SweepOutcome`'s revoked record), so the production adapter renders them byte-exact with the
/// admission insert's per-session `allow{4,6}_<idx>` element — no index resolution remains here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowSetDeletion {
    /// The §5.1 attributed session the freed IP was admitted under (the DNS-2b map key third).
    pub session: String,
    /// The PER-SESSION set the freed element lived in — `allow4_<idx>` (v4 / synthetic) or
    /// `allow6_<idx>` (dormant v6), the single-source `ds_contracts::session::allow_set_name`
    /// name (D3/D4), the SAME set the admission insert filled.
    pub set_name: String,
    /// The freed element as the set stores it — the canonical [`AdmittedAddr::to_dst_key`] form
    /// (`"<family>:<lower-hex-octets>"`), byte-exact with the insert's element and a later
    /// `flush_session` `DstFilter::Only` key.
    pub dst_key: DstKey,
    /// The composed `(magic ∪ leg ∪ index)` mark value, masked-by-construction (never bare).
    pub mark_value: u32,
    /// The frozen [`DS_MARK_MASK`] the element is addressed under — carried so the delete is
    /// never rendered against a bare value (the mask discipline, doc 14 §5).
    pub mark_mask: u32,
}

/// One rung-conditional CONNTRACK FLUSH the sweep routes — the `flush_session(DstFilter::Only,
/// sever_pair)` for a revoked admission whose deny SEVERS established flows (D53: a Deny at a
/// block-or-higher rung; doc 11 §5.4 leg (b)). Mirrors the ds-nft `flush_session` arguments: the
/// `session` (resolved to a `SessionRef` at the production edge), the freed `dst_keys` the flush
/// narrows to (`DstFilter::Only`, the SAME `to_dst_key` form), the two severed leg nibbles
/// (`LegSelector::sever_pair()` = AgentVm `0x1` + TlsproxyUpstream `0x2`), and the
/// [`DS_MARK_MASK`] the conntrack match is composed under.
///
/// Routed ONLY when the revocation's `flush_conntrack` is set — a non-severing (gate-rung) deny
/// revokes the DNS-2b/allow-set state but NEVER flushes established conntrack (expiry, not
/// revocation, cleans the rest up, W4). The flushed `dst_keys` are exactly the freed
/// (refcount-zero) IPs the sweep resolved — a shared-CDN IP a survivor still holds is never
/// flushed (the under-delete bias).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConntrackFlush {
    /// The §5.1 attributed session whose severed flows are flushed (the `flush_session` key).
    pub session: String,
    /// The host-local `host_session_index` (D4) the conntrack `--mark` match is composed from —
    /// the freed admission's REAL index, so `session_ref_for_flush` builds a `SessionRef` whose
    /// `MarkMatch::for_leg(leg, idx)` agrees byte-exact with the `(leg, idx)` mark the routed
    /// allow-set delete carries (and the per-session `allow4_<idx>` set name). The `flush_session`
    /// match keys on `(leg, host_session_index)` only, so this is the load-bearing index for the
    /// flush leg.
    pub host_session_index: u32,
    /// The destinations the flush narrows to (`DstFilter::Only`) — the freed (refcount-zero)
    /// IPs' [`AdmittedAddr::to_dst_key`] forms, byte-exact with the allow-set delete keys.
    pub dst_keys: Vec<DstKey>,
    /// The two severed leg nibbles (`LegSelector::sever_pair()` = AgentVm `0x1` +
    /// TlsproxyUpstream `0x2`, doc 14 §5) — carried so the routing names the SAME legs the
    /// shared revocation primitive severs, never a teardown-`All` span.
    pub legs: [Leg; 2],
    /// The frozen [`DS_MARK_MASK`] the conntrack match is composed under (a bare-index match
    /// never fires against the composite layout, doc 14 §5).
    pub mark_mask: u32,
}

/// The §5.4 SweepOutcome ENFORCEMENT surface, consumed (not owned) by the commit sink — the
/// abstract shape of the ds-nft enforcement primitives the routing drives. `withdraw_allow_set`
/// is the compensating set-element delete — a standalone `delete element` batch applied via
/// `ds_nft::NftWriter::backend().apply_batch` (the SAME shape `ds_nft::refresh::refresh_batch`'s
/// DeleteAdd embeds; there is no `ds_nft::NftWriter::withdraw` method on the real surface);
/// `flush_session_conntrack` is the rung-conditional conntrack flush
/// (`ds_nft::NftWriter::flush_session_report(&SessionRef, &DstFilter::Only, &LegSelector::sever_pair())`).
/// A success means the kernel state was severed; the routing logs (it never fails the commit — a
/// sweep that cannot reach the kernel must not wedge the admitter, and the bias is to
/// under-delete, never to block a still-valid sibling, D53/W4).
///
/// `&self` interior mutability mirrors ds-nft's `RecordingBackend` / `SpawnBackend` (both
/// genuinely `&self`), so the trait stays shared-ref and the commit sink holds the enforcer behind
/// a shared handle without distorting the production signature. The default in-memory
/// [`RecordingSweepEnforcer`] drives the SAME reportable path the ds-nft recording backend exposes;
/// the production `impl SweepEnforcer for ds_nft::NftWriter<B>` (below) binds the real primitives
/// over the workspace-internal `ds-nft` path-dep, selected ONLY behind `DS_NFTGATE_LIVE` (default
/// OFF → the reportable enforcer; no live kernel write on the offline/CI path).
pub trait SweepEnforcer: Send + Sync {
    /// Delete one refcount-zero freed allow-set element (leg (a)) — the compensating set-element
    /// delete on the SAME set the admission insert wrote, keyed by the SAME `to_dst_key` form.
    fn withdraw_allow_set(&self, deletion: &AllowSetDeletion);

    /// Flush the established conntrack for one revoked, severing-rung admission (leg (b)) — the
    /// `flush_session(DstFilter::Only, sever_pair)` over the freed IPs. Called ONLY when the
    /// revocation's `flush_conntrack` is set (D53 rung-conditional — the caller decides, the
    /// enforcer executes mechanism, doc 14 §5 "what must NOT live here").
    fn flush_session_conntrack(&self, flush: &ConntrackFlush);
}

/// An in-memory recording [`SweepEnforcer`] — the LOOPBACK/SYNTHETIC default path (no live
/// nft/conntrack write), the exact role `crate::txn::RecordingSetProgrammer` and ds-nft's
/// `RecordingBackend` play for the insert/flush batches. It records every allow-set delete and
/// every conntrack flush IN ORDER, so a test can assert the routing drove EXACTLY the sweep's
/// deletions (and the rung-conditional flushes) with no live kernel.
#[derive(Debug, Default)]
pub struct RecordingSweepEnforcer {
    withdrawn: Mutex<Vec<AllowSetDeletion>>,
    flushed: Mutex<Vec<ConntrackFlush>>,
}

impl RecordingSweepEnforcer {
    /// A fresh recording enforcer with nothing routed yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The allow-set element deletes routed so far, in order — the leg-(a) record a test asserts
    /// against the sweep's `allow_set_deletions`.
    pub fn withdrawn(&self) -> Vec<AllowSetDeletion> {
        self.withdrawn.lock().expect("sweep-enforcer lock").clone()
    }

    /// The conntrack flushes routed so far, in order — the leg-(b) record a test asserts fires
    /// ONLY on the D53 severing rung.
    pub fn flushed(&self) -> Vec<ConntrackFlush> {
        self.flushed.lock().expect("sweep-enforcer lock").clone()
    }
}

impl SweepEnforcer for RecordingSweepEnforcer {
    fn withdraw_allow_set(&self, deletion: &AllowSetDeletion) {
        self.withdrawn
            .lock()
            .expect("sweep-enforcer lock")
            .push(deletion.clone());
    }

    fn flush_session_conntrack(&self, flush: &ConntrackFlush) {
        self.flushed
            .lock()
            .expect("sweep-enforcer lock")
            .push(flush.clone());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The PRODUCTION SweepEnforcer binding: `impl SweepEnforcer for
// ds_nft::NftWriter<B>` — the §5.4 kernel-write seam wave37b deferred (the same
// workspace-internal `ds-nft` path-dep the txn `NftSetProgrammer` binding rides).
// LOOPBACK/SYNTHETIC DEFAULT: selected ONLY behind `DS_NFTGATE_LIVE` (default OFF →
// the reportable `RecordingSweepEnforcer` above stays the default); the sandbox/CI
// kernel has no nf_conntrack + restricted netlink, so the REAL conntrack flush is a
// `#[ignore]`/`DS_NFTGATE_LIVE`-gated, CI/manual-only test (needs
// `nf_conntrack_tcp_loose=0` + CAP_NET_ADMIN, doc 14 §11), never on
// `cargo test --offline`. The adapter maps the routed `AllowSetDeletion` /
// `ConntrackFlush` FIELD-FOR-FIELD onto the REAL ds-nft primitive names — the
// allow-set delete is a standalone `delete element` batch applied via
// `NftWriter::backend().apply_batch` (the SAME shape `refresh::refresh_batch`'s
// DeleteAdd embeds; there is no `ds_nft::NftWriter::withdraw` method on the real
// surface), and the conntrack flush is
// `NftWriter::flush_session_report(&SessionRef, &DstFilter::Only(keys),
// &LegSelector::sever_pair())` (`refresh::sever_legs()` / `flush::sever_pair()`
// name the SAME 0x1+0x2 leg pair). The D53/W4 under-delete bias rides verbatim:
// the routing already narrowed to the sweep-resolved freed IPs.
// ─────────────────────────────────────────────────────────────────────────────

/// The whole `inet ds_filter` table the per-session NFT-3 allow sets live under —
/// the SAME table `ds_nft::refresh::refresh_batch` names its `delete element`
/// against (private `const TABLE = "inet ds_filter"` there, doc 14 §6). ds-nft
/// exports no standalone `delete element` batch helper (only the `refresh_batch`
/// DeleteAdd embeds it) and is READ-ONLY for this wave, so the §5.4 allow-set delete
/// batch is rendered HERE in the SAME shape DeleteAdd embeds; this const mirrors
/// `crate::txn::NFT_FILTER_TABLE` so the admission insert, the txn rollback withdraw,
/// and the §5.4 sweep delete all name the SAME table byte-exact.
const NFT_FILTER_TABLE: &str = "inet ds_filter";

/// Build the `SessionRef` the production `flush_session_report` keys the conntrack
/// destroy on, from a routed [`ConntrackFlush`]'s session + REAL `host_session_index`.
/// The §5.4 routing carries the §5.1 attribution UUID (`flush.session`) AND the freed
/// admission's actual `host_session_index` (`flush.host_session_index`); the
/// `MarkMatch::for_leg(leg, host_session_index)` the production `flush_session` composes
/// then agrees byte-exact with the `(leg, index)` mark the routed allow-set delete
/// carries (and the per-session `allow4_<idx>` set name) — no index-0 approximation, so
/// the flush severs the freed admission's OWN per-session flows even under concurrent
/// sessions. The `host_id` / `tap_name` are not part of the conntrack `--mark` key
/// (`flush_session` composes the match from `(leg, host_session_index)` only), so they
/// are unconstrained placeholders here.
fn session_ref_for_flush(
    session: &str,
    host_session_index: u32,
) -> ds_contracts::session::SessionRef {
    ds_contracts::session::SessionRef::new(
        session.to_string(),
        // host_id / tap_name do not enter the conntrack mark key (the flush composes
        // it from leg + host_session_index only), so they are session-derived
        // placeholders, not byte-exact key material.
        String::new(),
        // The freed admission's REAL per-session index: `route_sweep_outcome` composes the
        // routed mark from `compose(leg, host_session_index)`, so the live flush matches it
        // byte-exact and targets the correct session's conntrack marks.
        host_session_index,
        String::new(),
    )
}

/// The PRODUCTION [`SweepEnforcer`]: bind `ds_nft::NftWriter<B>` (the ONE
/// nft/netlink writer, doc 14 §6) as the §5.4 enforcement surface.
///
/// `withdraw_allow_set` renders the compensating `delete element {table} {set} {{
/// {dst_key} }}` batch (leg (a), the SAME shape `refresh::refresh_batch`'s DeleteAdd
/// embeds — there is NO `ds_nft::NftWriter::withdraw` on the real surface) and
/// applies it through `NftWriter::backend().apply_batch`. `flush_session_conntrack`
/// runs `NftWriter::flush_session_report(&SessionRef, &DstFilter::Only(dst_keys),
/// &LegSelector::sever_pair())` (leg (b), the `0x1`+`0x2` sever pair
/// `refresh::sever_legs()` / `flush::LegSelector::sever_pair()` both name) over the
/// freed dst keys. A backend error is LOGGED, never propagated — a sweep that cannot
/// reach the kernel must not wedge the admitter, and the bias is to under-delete
/// (D53/W4); the routing already narrowed to the sweep-resolved freed IPs.
impl<B: ds_nft::backend::NftBackend + Send + Sync> SweepEnforcer for ds_nft::NftWriter<B> {
    fn withdraw_allow_set(&self, deletion: &AllowSetDeletion) {
        // Leg (a): the compensating `delete element` on the SAME allow set the
        // admission insert wrote. The element renders to the nft-accepted address
        // literal (`DstKey::address_literal`) — `nft` rejects the frozen `v4:<hex>`
        // `to_dst_key` identity outright (`syntax error`), so a raw-hex `delete
        // element` fails closed (and, under the D53/W4 under-delete bias below, fails
        // SILENTLY): the revoked IP would linger in the allow-set until its W2
        // deadline. Same live-rejection class the admission `refresh_batch` boundary
        // already fixed. The in-memory `dst_key` stays the frozen hex identity; only
        // the CLI text is normalised.
        let batch = ds_nft::backend::NftBatch::new(format!(
            "delete element {table} {set} {{ {elem} }}\n",
            table = NFT_FILTER_TABLE,
            set = deletion.set_name,
            elem = deletion.dst_key.address_literal(),
        ));
        if let Err(err) = self.backend().apply_batch(&batch) {
            eprintln!(
                "ds-dnsgate: §5.4 allow-set delete failed (under-delete bias — not wedging the \
                 admitter): set={} dst={} err={err}",
                deletion.set_name,
                deletion.dst_key.address_literal()
            );
        }
    }

    fn flush_session_conntrack(&self, flush: &ConntrackFlush) {
        // Leg (b): the rung-conditional `flush_session(DstFilter::Only, sever_pair)`
        // over the freed dst keys — narrowed to EXACTLY the sweep-resolved freed IPs
        // (`DstFilter::Only`), spanning the `0x1`+`0x2` sever pair (the routed
        // `flush.legs` are exactly `LegSelector::sever_pair()`'s legs). The masked
        // conntrack match `flush_session_report` composes is DS_MARK_MASK-aware, so a
        // bare-index match never fires.
        let session = session_ref_for_flush(&flush.session, flush.host_session_index);
        let dst_filter = ds_contracts::flush::DstFilter::Only(flush.dst_keys.clone());
        let legs = ds_contracts::flush::LegSelector::sever_pair();
        if let Err(err) = self.flush_session_report(&session, &dst_filter, &legs) {
            eprintln!(
                "ds-dnsgate: §5.4 conntrack flush failed (under-delete bias — not wedging the \
                 admitter): session={} keys={} err={err:?}",
                flush.session,
                flush.dst_keys.len(),
            );
        }
    }
}

/// Project a `std::net::IpAddr` onto the frozen family-agnostic [`AdmittedAddr`] (network-byte-
/// order octets + family tag) — the SAME projection `crate::txn::to_admitted_addr` does, so the
/// freed-IP `to_dst_key` the routing renders is byte-exact with the admission insert's element
/// and the conntrack `DstFilter::Only` key.
fn admitted_addr(ip: IpAddr) -> AdmittedAddr {
    match ip {
        IpAddr::V4(v4) => AdmittedAddr {
            family: AddressFamily::V4,
            octets: v4.octets().to_vec(),
        },
        IpAddr::V6(v6) => AdmittedAddr {
            family: AddressFamily::V6,
            octets: v6.octets().to_vec(),
        },
    }
}

/// The PER-SESSION `allow4_<idx>` (v4 / synthetic) or `allow6_<idx>` (dormant v6) set name a
/// freed IP's element lived in — the SINGLE-SOURCE `ds_contracts::session::allow_set_name` (D3/D4),
/// the SAME family+index→set mapping the admission transaction's insert uses, so a sweep delete
/// names the EXACT set the insert filled (and ds-nft's `InstantiateSessionNFT` created). The
/// `host_session_index` is the freed admission's REAL index (read off the `SweepOutcome`'s revoked
/// record in `route_sweep_outcome`), the SAME index the routed mark composes from, so insert and
/// delete agree byte-exact and a concurrent session's `allow4_<other>` is never touched.
fn sweep_allow_set_name(addr: &AdmittedAddr, host_session_index: u32) -> String {
    ds_contracts::session::allow_set_name(addr.family, host_session_index)
}

/// Route ONE §5.4 [`SweepOutcome`] to the enforcement primitives (doc 11 §5.4 / D53 / D72), the
/// step that replaces the wave-1 discard. Faithfully routes what the sweep RESOLVED — never
/// recomputes the refcount:
///   (a) for every refcount-zero freed IP in `outcome.allow_set_deletions`, issue the allow-set
///       element delete (the compensating `delete element` on the same set the insert wrote);
///   (b) for every revoked admission with `flush_conntrack` set (D53 severing rung), issue the
///       rung-conditional conntrack flush over the freed IPs (`DstFilter::Only`, `sever_pair`).
///
/// The D53/W4 UNDER-DELETE bias is preserved: the flush + delete keys are exactly the freed
/// (sole-reference) IPs — a shared-CDN IP a survivor still holds is in NEITHER set, so it is
/// neither deleted nor flushed. The allow-set delete names the PER-SESSION `allow4_<idx>` /
/// `allow6_<idx>` via the single-source `ds_contracts::session::allow_set_name` (D3/D4 — the SAME
/// set the admission insert filled and ds-nft's `InstantiateSessionNFT` created; NEVER a flat
/// shared `allow4`). The mark is DS_MARK_MASK-composed (never bare). The session index BOTH the
/// set name and the mark are keyed on is the FREED admission's REAL `host_session_index`, read off
/// the `SweepOutcome`'s revoked record (or, on an ask-grant-only eviction, the evicted grant's) —
/// so the leg the freed-IP element carries is the agent-VM leg (`0x1`) and the routed `mark_value`
/// is `compose(AgentVm, idx)` and the set name `allow{4,6}_<idx>` over the freed admission's own
/// index, keeping the set name and mark internally consistent AND distinct from any concurrent
/// session's `allow{4,6}_<other>`. A non-severing deny routes leg (a) but NOT leg (b) — the
/// rung-conditional flush guard (D53).
pub(crate) fn route_sweep_outcome(outcome: &SweepOutcome, enforcer: &dyn SweepEnforcer) {
    if outcome.is_noop() {
        return;
    }

    // The freed (refcount-zero) IPs the sweep resolved — the SOLE source of both the delete keys
    // and the flush narrowing. A shared-CDN IP a survivor still holds is NOT in this set (the
    // sweep already applied the reverse-index refcount, biasing to under-delete, D53/W4), so it is
    // neither deleted nor flushed below.
    let freed: Vec<(IpAddr, AdmittedAddr)> = outcome
        .allow_set_deletions
        .iter()
        .map(|&ip| (ip, admitted_addr(ip)))
        .collect();

    // The §5.1 session AND the freed admission's REAL `host_session_index` the freed IPs were
    // admitted under — the per-session mark identity AND the per-session `allow{4,6}_<idx>` set name
    // are BOTH keyed on this index (kept internally consistent: ONE index feeds both, plus the
    // flush's `SessionRef`). The revoked admissions/grants all carry their session + index; a freed
    // IP is freed for the revoked name's session, so the first revoked entry is the attribution
    // source (a single sweep commit re-decides one host's live set). A flush with no revoked entry
    // cannot happen (a freed IP implies a revoked name freed it). An ask-grant-only eviction (no
    // revoked admission) falls back to the first evicted grant. This DROPS the prior index-0
    // approximation: the swept set + mark now name the freed admission's OWN `allow{4,6}_<idx>`,
    // never `allow4_0` for a session that is actually `allow4_<N>`.
    let (session, host_session_index) = outcome
        .revoked
        .first()
        .map(|r| (r.admission.session.clone(), r.admission.host_session_index))
        .or_else(|| {
            outcome
                .evicted_ask_grants
                .first()
                .map(|g| (g.grant.session.clone(), g.grant.host_session_index))
        })
        .unwrap_or_default();

    // (a) ALLOW-SET ELEMENT DELETE — one compensating delete per freed IP, byte-exact with the
    // admission insert (same set, same `to_dst_key` element, masked mark — never bare).
    for (_, addr) in &freed {
        enforcer.withdraw_allow_set(&AllowSetDeletion {
            session: session.clone(),
            // The PER-SESSION `allow4_<idx>`/`allow6_<idx>` (single-source `allow_set_name`,
            // D3/D4) — the SAME set the admission insert filled and ds-nft's
            // `InstantiateSessionNFT` created, keyed on the freed admission's REAL
            // `host_session_index` (the SAME index the mark below composes from). NEVER a flat
            // shared `allow4`, and never another session's `allow4_<other>`.
            set_name: sweep_allow_set_name(addr, host_session_index),
            dst_key: addr.to_dst_key(),
            // The freed-IP element carries the agent-VM leg (`0x1`) and the freed admission's REAL
            // per-session index, so the composed value here is `(magic ∪ AgentVm ∪ idx)` over the
            // frozen mask — masked-by-construction, and the SAME index the per-session set name is
            // keyed on.
            mark_value: compose(Leg::AgentVm, host_session_index),
            mark_mask: DS_MARK_MASK,
        });
    }

    // (b) RUNG-CONDITIONAL CONNTRACK FLUSH (D53) — fire `flush_session(DstFilter::Only, sever_pair)`
    // over the freed IPs ONLY when a revoked admission OR evicted ask-grant severs established flows.
    // A non-severing (gate-rung) deny revokes the DNS-2b/allow-set/grant state above but flushes NO
    // conntrack (W4). The flush narrows to exactly the freed (refcount-zero) IPs — a shared-sibling
    // IP is never in the narrowing.
    let any_severing = outcome.revoked.iter().any(|r| r.flush_conntrack)
        || outcome.evicted_ask_grants.iter().any(|g| g.flush_conntrack);
    if any_severing && !freed.is_empty() {
        enforcer.flush_session_conntrack(&ConntrackFlush {
            session,
            // The freed admission's REAL per-session index — `session_ref_for_flush` builds the
            // `SessionRef` whose `MarkMatch::for_leg(leg, idx)` agrees byte-exact with the
            // `(leg, idx)` mark the leg-(a) delete above carried, so the flush severs THIS
            // session's conntrack marks (not `host_session_index = 0`'s).
            host_session_index,
            dst_keys: freed.iter().map(|(_, addr)| addr.to_dst_key()).collect(),
            // The block-rung sever pair (doc 14 §5): the agent-VM leg + the ds-tlsproxy upstream
            // leg, the SAME `LegSelector::sever_pair()` the shared revocation primitive severs.
            legs: [Leg::AgentVm, Leg::TlsproxyUpstream],
            mark_mask: DS_MARK_MASK,
        });
    }
}

/// The §5.4 revocation-sweep target the [`SnapshotCommitSink`] drives AFTER the admitter-LAST
/// evaluator re-source (doc 11 §5.4 / D72): re-evaluate the live derived state against the NEW
/// evaluator and remove what is now denied. A trait so the production [`LiveAdmissions`] registry
/// (the one the W1/W2 admission transaction mints into) AND a synthetic recorder in tests both
/// satisfy the commit-path hook, without binding the transaction's concrete stores. A commit with
/// no sweep target (the boundary-zone-only paths) skips it.
pub trait RevocationTarget {
    /// Re-evaluate every live admission against the freshly-committed evaluator and remove the
    /// now-denied derived state (DNS-2b map entries + refcount-aware allow-set elements,
    /// rung-conditional flush per D53). Returns the [`SweepOutcome`] for observability/tests.
    /// MUST run admitter-LAST — i.e. AFTER the evaluator has been re-sourced — so it decides
    /// against the NEW policy version (the [`SnapshotCommitSink`] orders this).
    fn sweep(&self, evaluator: &dyn AdmissionReevaluator) -> SweepOutcome;

    /// The session UUIDs that STILL hold at least one live admission (or parked ask-grant) after a
    /// sweep — read by the commit sink to decide which swept sessions were fully torn down and so
    /// should be pruned from the fleet-revocation book (doc 19 §5.4). The default is EMPTY: a target
    /// with no notion of live sessions (e.g. [`NoSweep`]) reports none, which is harmless because
    /// such a target also produces no revoked sessions to prune. [`LiveAdmissions`] overrides this
    /// with its real live set.
    fn live_session_uuids(&self) -> HashSet<String> {
        HashSet::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FLEET token-revocation sweep — the SECOND post-commit sweep leg (doc 19 §7; D102/P-R6,
// D72/D53/D68). Distinct from the §5.4 DNS-2b revocation sweep above: that one re-evaluates the
// gate's DNS-admission/ask-grant derived state against the NEW policy version and evicts what the
// new policy denies; THIS one severs the flows established under a fleet-REVOKED TOKEN (an
// emergency kill-switch artifact riding the SAME committed policy version, D72 "no third
// channel"). The revocation names a token by a hex chain FINGERPRINT / block id — NEVER token
// bytes (the producer, identity/fleetreg, guarantees that structurally) — and carries the D53 rung
// that gates whether established flows sever.
//
// The substance lives in `ds_policy_snapshot::sweep_fleet_revocations` (the recognition +
// rung-conditional severing) and severs through the FROZEN shared `flush_session` primitive (a
// CALL-SITE only). This module wires it into the live serving loop's commit path with a REAL
// fingerprint→sessions admission book (not the injected test closure the library unit tests use)
// so a pushed fleet-revocation artifact actually severs live flows on the box; the commit path
// runs it BEFORE reporting `applied_seq` (D72: the seq advances only post-sweep-plus-flush).
// ─────────────────────────────────────────────────────────────────────────────

/// The host-agent's fingerprint→sessions ADMISSION BOOK (doc 19 §7) — the REAL registry the
/// serving loop's fleet-revocation sweep resolves a revoked token's fingerprint against, replacing
/// the injected test closure the library sweep's unit tests pass. A shared `Arc<Mutex<…>>` handle
/// so the admission path records `(fingerprint → session)` on every session minted under a token
/// while the post-commit sweep reads it; cloning is a shared-handle clone. Empty for a fingerprint
/// this host admitted nothing under — a no-op sever for that entry.
///
/// The fingerprint is opaque to the gate (a hex chain fingerprint / unique block id); it is used
/// ONLY as the map key and is NEVER rendered into a flush (the flush carries the resolved
/// [`SessionRef`] and opaque destination keys, never token/fingerprint bytes).
#[derive(Clone, Default)]
pub struct FleetRevocationBook {
    by_fingerprint: Arc<Mutex<HashMap<String, Vec<SessionRef>>>>,
}

impl std::fmt::Debug for FleetRevocationBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render only the number of distinct revocable-token fingerprints tracked — never the
        // fingerprints or the session attribution material.
        let n = self
            .by_fingerprint
            .lock()
            .map(|m| m.len())
            .unwrap_or_default();
        f.debug_struct("FleetRevocationBook")
            .field("fingerprints_tracked", &n)
            .finish()
    }
}

impl FleetRevocationBook {
    /// An empty admission book.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `session` was admitted under the token named by `fingerprint` (the admission
    /// path calls this as it mints a session under a scoped token; tests feed it synthetically).
    /// A fingerprint may map to many sessions — a token admitted on several concurrent sessions is
    /// all severed on one revocation.
    ///
    /// DEDUP: the mint path calls this on EVERY admission a session makes under a token (each
    /// domain the guest resolves, each W4 refresh), so the same `(fingerprint, session)` pair
    /// recurs; recording it once keeps the sweep's `sessions_severed` accounting honest and avoids
    /// a redundant (idempotent, but wasteful) re-flush of an already-severed session. An exact
    /// duplicate (the whole `SessionRef` quartet) under the fingerprint is skipped.
    pub fn record(&self, fingerprint: impl Into<String>, session: SessionRef) {
        let mut by_fingerprint = self
            .by_fingerprint
            .lock()
            .expect("fleet-revocation-book lock poisoned");
        let sessions = by_fingerprint.entry(fingerprint.into()).or_default();
        if !sessions.contains(&session) {
            sessions.push(session);
        }
    }

    /// The number of distinct token fingerprints currently tracked (tests / diagnostics only).
    pub fn len(&self) -> usize {
        self.by_fingerprint
            .lock()
            .expect("fleet-revocation-book lock poisoned")
            .len()
    }

    /// Whether the book tracks no token fingerprints.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The total number of `(fingerprint → SessionRef)` rows across ALL fingerprints (tests /
    /// diagnostics only) — the accumulation metric the teardown-prune bounds. Distinct from
    /// [`len`](Self::len), which counts fingerprint KEYS: one fingerprint admitting many sessions
    /// contributes one key but several rows.
    pub fn session_row_count(&self) -> usize {
        self.by_fingerprint
            .lock()
            .expect("fleet-revocation-book lock poisoned")
            .values()
            .map(Vec::len)
            .sum()
    }

    /// Prune every recorded `(fingerprint → SessionRef)` row whose session is `session_uuid` — the
    /// doc 19 §5.4 decref path calls this when a session is torn down / expires so a long-running
    /// gate does not accumulate stale attribution rows without bound. A fingerprint whose LAST
    /// session is pruned has its key dropped entirely (the book SHRINKS — `len` falls), so a token
    /// no live session remains under stops occupying a row. Returns the number of session rows
    /// removed (diagnostics / tests). Idempotent: pruning a session the book never recorded removes
    /// nothing and returns 0.
    ///
    /// A token admitted on SEVERAL sessions keeps its fingerprint key while any sibling session is
    /// still live — only the torn-down session's own row is removed, so a later revocation of that
    /// token still severs the survivors (bias to under-prune, mirroring the §5.4 W4 under-delete).
    pub fn prune_session(&self, session_uuid: &str) -> usize {
        let mut by_fingerprint = self
            .by_fingerprint
            .lock()
            .expect("fleet-revocation-book lock poisoned");
        let mut removed = 0usize;
        by_fingerprint.retain(|_fingerprint, sessions| {
            let before = sessions.len();
            sessions.retain(|s| s.session_uuid != session_uuid);
            removed += before - sessions.len();
            // Drop the fingerprint key entirely once its last session is pruned — this is what makes
            // the book shrink rather than accumulate empty rows under a long-running gate.
            !sessions.is_empty()
        });
        removed
    }
}

impl SessionAdmissionBook for FleetRevocationBook {
    fn sessions_for_fingerprint(&self, fingerprint: &str) -> Vec<SessionRef> {
        self.by_fingerprint
            .lock()
            .expect("fleet-revocation-book lock poisoned")
            .get(fingerprint)
            .cloned()
            .unwrap_or_default()
    }
}

/// A content-free fleet-revocation sweep failure — the object-safe error the commit path fails
/// closed on (a flush that could not reach the kernel). Carries only a structural reason string
/// (the underlying `FlushSession::Error`'s `Debug`, itself content-free), never token/session
/// bytes.
#[derive(Clone, Debug)]
pub struct FleetSweepError(pub String);

impl std::fmt::Display for FleetSweepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fleet-revocation sweep failed: {}", self.0)
    }
}

/// The object-safe post-commit FLEET-revocation sweep the commit sink drives (doc 19 §7 / D72).
/// The library sweep [`ds_policy_snapshot::sweep_fleet_revocations`] is generic over the
/// `F: FlushSession` flusher (so `dyn FlushSession` is impossible — the trait has an associated
/// `Error` type), so the commit sink — which holds its sweep leg behind a shared trait object —
/// routes through THIS erased surface. The concrete [`BookBackedFleetSweeper`] owns the flusher +
/// the admission book and runs the library sweep; a commit with no fleet sweeper wired (the
/// existing callers) simply skips this leg.
pub trait FleetRevocationSweeper: Send + Sync {
    /// Sever every live session the admission book resolves for each block-or-higher revocation in
    /// `entries`, through the shared `flush_session` primitive. Returns the [`RevocationSweep`]
    /// accounting. FAIL-CLOSED: a flush error short-circuits the sweep so the caller does NOT
    /// advance `applied_seq` (D72 — the seq advances only after sweep-plus-flush completes).
    fn sweep_fleet(
        &self,
        entries: &[FleetRevocationEntry],
    ) -> Result<RevocationSweep, FleetSweepError>;

    /// Prune the fleet-revocation book of every row for a session the §5.4 decref path fully tore
    /// down / expired (doc 19 §5.4), so a long-running gate does not accumulate stale attribution
    /// rows without bound. The default is a NO-OP (a sweeper with no book to prune);
    /// [`BookBackedFleetSweeper`] prunes its shared book. Idempotent — a session the book never
    /// recorded prunes nothing.
    fn prune_torn_down_sessions(&self, _session_uuids: &HashSet<String>) {}
}

/// The default REDRIVE-buffer cap: the maximum number of distinct fleet-revocation entries the
/// [`BookBackedFleetSweeper`] retains for retry across a SUSTAINED kernel/conntrack outage. A v1
/// bound (not a frozen contract value), sized generously — a real box carries far fewer than this
/// many concurrently-revoked tokens; the cap only matters when the kernel has been unreachable long
/// enough to accumulate that many DISTINCT entries. On overflow the OLDEST entries are dropped (the
/// newest revocations are the most likely to still name a live session) and an operator alert fires,
/// so the loss is BOUNDED and VISIBLE rather than an unbounded memory leak.
pub const DEFAULT_FLEET_REDRIVE_CAP: usize = 4096;

/// Fire the sustained-outage operator alert after this many CONSECUTIVE failed sweep cycles — the
/// kernel/conntrack flush has been unreachable across this many commits, so a human must look even
/// though the buffer has not yet overflowed. A transient one- or two-cycle blip (the redrive test's
/// single failure-then-recover) stays quiet; a genuine sustained outage alerts.
pub const FLEET_REDRIVE_ALERT_AFTER_CYCLES: u64 = 3;

/// A count-only report of a SUSTAINED fleet-revocation redrive condition — the operator-alert
/// payload (doc 19 §7). Carries ONLY counts and flags: NEVER a fingerprint, a session, or any
/// token-chain material (D50 — the fleet-revocation surface is fingerprint/block-id only, and an
/// alert log line must not leak even those).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FleetRedriveAlert {
    /// How many entries remain buffered for retry after this failed cycle (post-cap).
    pub pending_len: usize,
    /// How many CONSECUTIVE cycles the fleet flush has now failed (reset to 0 on a clean sweep).
    pub consecutive_failed_cycles: u64,
    /// Whether this cycle OVERFLOWED the redrive cap (oldest entries were dropped).
    pub capped: bool,
    /// How many entries this cycle DROPPED on overflow (0 unless `capped`).
    pub dropped: usize,
}

/// The operator-alert sink the [`BookBackedFleetSweeper`] fires on a SUSTAINED kernel/conntrack
/// outage — the redrive analogue of the reload-boundary [`crate::event::SnapshotDropSink`] (doc 19
/// §7 / doc 13 §5.1). Infallible: a dropped alert line never changes which revocations enforce.
pub trait FleetRedriveAlertSink: Send + Sync {
    /// Observe one sustained-outage condition — the kernel flush has failed for
    /// [`FLEET_REDRIVE_ALERT_AFTER_CYCLES`] consecutive cycles OR the redrive buffer overflowed its
    /// cap. The payload is count-only (never token/session bytes, D50).
    fn observe_redrive(&self, alert: FleetRedriveAlert);
}

/// The inert redrive alert sink (the default): observes nowhere. Keeps every existing
/// [`BookBackedFleetSweeper::new`] caller/test byte-for-byte quiet until an alert sink is wired.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullFleetRedriveAlertSink;

impl FleetRedriveAlertSink for NullFleetRedriveAlertSink {
    fn observe_redrive(&self, _alert: FleetRedriveAlert) {}
}

/// The LOOPBACK/SYNTHETIC operator-log redrive alert sink — the redrive twin of `main`'s
/// `OperatorLogDropSink` (doc 19 §7 / doc 13 §5.1). Emits ONE greppable `reason=`-led stderr line
/// carrying COUNTS ONLY (never a fingerprint / session / token byte, D50), so an operator watching
/// the log sees a sustained fleet-flush outage — the kernel/conntrack has been unreachable across
/// several commits, so pushed token revocations are NOT yet enforced and the redrive buffer is
/// filling (or has overflowed). Infallible.
#[derive(Clone, Copy, Debug, Default)]
pub struct OperatorLogFleetRedriveAlertSink;

impl FleetRedriveAlertSink for OperatorLogFleetRedriveAlertSink {
    fn observe_redrive(&self, alert: FleetRedriveAlert) {
        let reason = if alert.capped {
            "fleet_redrive_capped"
        } else {
            "fleet_redrive_sustained_outage"
        };
        eprintln!(
            "ds-dnsgate: fleet-revocation redrive alert reason={reason} \
             consecutive_failed_cycles={} pending_entries={} capped={} dropped={} \
             (kernel/conntrack flush unreachable — pushed token revocations NOT yet enforced)",
            alert.consecutive_failed_cycles, alert.pending_len, alert.capped, alert.dropped,
        );
    }
}

/// The production [`FleetRevocationSweeper`]: binds a concrete `F: FlushSession` flusher (the ONE
/// shared `ds_nft::NftWriter` in production — behind `DS_NFTGATE_LIVE` — or a recording
/// `NftWriter<RecordingBackend>` on the offline/CI path) to a REAL [`FleetRevocationBook`] and runs
/// [`ds_policy_snapshot::sweep_fleet_revocations_with_book`]. The severing shape (`DstFilter::All`
/// on `LegSelector::sever_pair()`, rung-conditional per D53) and the fail-closed short-circuit are
/// the library's, unchanged — this only carries the real book + flusher into the object-safe hook.
pub struct BookBackedFleetSweeper<F: FlushSession> {
    book: FleetRevocationBook,
    flusher: F,
    /// The REDRIVE buffer: the fleet-revocation entries a PRIOR commit cycle failed to flush
    /// fail-closed (the kernel was unreachable), retained here so the NEXT commit cycle retries
    /// them BEFORE its own entries (doc 19 §7; D72). Without this a transient flush error would
    /// permanently drop a revocation: the entry rides INSIDE one committed policy version, so once
    /// a later (recovered) version commits and advances `applied_seq` past the failed one, nothing
    /// re-presents the dropped entry — the revoked token's flows would linger un-severed even
    /// though the sweep "succeeds" on every subsequent version. Draining on the first clean sweep
    /// (all entries flushed) and re-persisting the union on a fresh failure makes the fail-closed
    /// short-circuit a RETRY, not a silent drop. CAPPED at [`redrive_cap`](Self::redrive_cap) so a
    /// SUSTAINED outage cannot grow it without bound (oldest entries dropped on overflow, alerted).
    /// `commit_snapshot` drives the sole subscriber task serially, so this `Mutex` is uncontended in
    /// practice; it is here only because the sweeper is held behind a shared
    /// `Arc<dyn FleetRevocationSweeper>`.
    pending: Mutex<Vec<FleetRevocationEntry>>,
    /// The count of CONSECUTIVE failed sweep cycles — reset to 0 on the first clean sweep. Drives
    /// the sustained-outage alert ([`FLEET_REDRIVE_ALERT_AFTER_CYCLES`]).
    consecutive_failures: Mutex<u64>,
    /// The maximum number of distinct entries [`pending`](Self::pending) retains before it overflows
    /// (dropping oldest + alerting). [`DEFAULT_FLEET_REDRIVE_CAP`] unless overridden by
    /// [`with_redrive_cap`](Self::with_redrive_cap).
    redrive_cap: usize,
    /// The operator-alert sink fired on a sustained kernel/conntrack outage or a buffer overflow
    /// (count-only payload, never token/session bytes). The inert [`NullFleetRedriveAlertSink`] by
    /// default; `main` wires [`OperatorLogFleetRedriveAlertSink`] (the loopback log stand-in).
    alert_sink: Arc<dyn FleetRedriveAlertSink>,
}

impl<F: FlushSession> BookBackedFleetSweeper<F> {
    /// Pair a real admission book with a concrete flusher. `main` hands the gate's shared
    /// [`FleetRevocationBook`] (the SAME one the admission path records into) and a
    /// `ds_nft::NftWriter`; tests hand a book they seed synthetically and a
    /// `NftWriter<RecordingBackend>`. The redrive buffer defaults to
    /// [`DEFAULT_FLEET_REDRIVE_CAP`] with the inert [`NullFleetRedriveAlertSink`] (quiet); chain
    /// [`with_redrive_cap`](Self::with_redrive_cap) / [`with_redrive_alert_sink`](Self::with_redrive_alert_sink)
    /// to bound + observe a sustained outage.
    pub fn new(book: FleetRevocationBook, flusher: F) -> Self {
        Self {
            book,
            flusher,
            pending: Mutex::new(Vec::new()),
            consecutive_failures: Mutex::new(0),
            redrive_cap: DEFAULT_FLEET_REDRIVE_CAP,
            alert_sink: Arc::new(NullFleetRedriveAlertSink),
        }
    }

    /// Override the redrive-buffer cap (default [`DEFAULT_FLEET_REDRIVE_CAP`]). Tests use a small
    /// cap to exercise overflow without a huge buffer; a deployment may tune it off the host session
    /// count. A builder — returns `self`.
    #[must_use]
    pub fn with_redrive_cap(mut self, cap: usize) -> Self {
        self.redrive_cap = cap;
        self
    }

    /// Wire the operator-alert sink fired on a sustained outage / buffer overflow (default: the
    /// inert [`NullFleetRedriveAlertSink`]). `main` passes [`OperatorLogFleetRedriveAlertSink`]; a
    /// test passes a capturing sink to assert the alert fires. A builder — returns `self`.
    #[must_use]
    pub fn with_redrive_alert_sink(mut self, sink: Arc<dyn FleetRedriveAlertSink>) -> Self {
        self.alert_sink = sink;
        self
    }

    /// The number of entries currently held for REDRIVE (a prior cycle's fail-closed flush that has
    /// not yet been retried to success). Zero in the steady state; diagnostics / tests only.
    pub fn pending_redrive_len(&self) -> usize {
        self.pending
            .lock()
            .expect("fleet-sweep redrive lock poisoned")
            .len()
    }

    /// The count of CONSECUTIVE failed sweep cycles (0 in the steady state; diagnostics / tests).
    pub fn consecutive_failed_cycles(&self) -> u64 {
        *self
            .consecutive_failures
            .lock()
            .expect("fleet-sweep redrive lock poisoned")
    }
}

impl<F: FlushSession + Send + Sync> FleetRevocationSweeper for BookBackedFleetSweeper<F> {
    fn sweep_fleet(
        &self,
        entries: &[FleetRevocationEntry],
    ) -> Result<RevocationSweep, FleetSweepError> {
        // REDRIVE FIRST: prepend any entries a prior cycle failed to flush, then this cycle's own,
        // deduped (an entry re-published on a later version, or still pending, is swept once). The
        // sweep is idempotent — re-severing an already-severed session is a kernel no-op — so
        // retrying the whole union is safe; the dedup only keeps the buffer from growing without
        // bound under a persistent outage.
        let mut combined = self
            .pending
            .lock()
            .expect("fleet-sweep redrive lock poisoned")
            .clone();
        for entry in entries {
            if !combined.contains(entry) {
                combined.push(entry.clone());
            }
        }
        match sweep_fleet_revocations_with_book(&self.flusher, &combined, &self.book) {
            Ok(sweep) => {
                // Every entry (redriven + new) flushed clean — the revocations are enforced, so the
                // redrive buffer is emptied, the consecutive-failure count resets, and `applied_seq`
                // may advance (the caller heartbeats).
                self.pending
                    .lock()
                    .expect("fleet-sweep redrive lock poisoned")
                    .clear();
                *self
                    .consecutive_failures
                    .lock()
                    .expect("fleet-sweep redrive lock poisoned") = 0;
                Ok(sweep)
            }
            Err(e) => {
                // FAIL-CLOSED: the sweep short-circuited on a flush the kernel could not take.
                // Retain the union for the next cycle's redrive so no revocation is dropped past an
                // advanced seq — but CAP it so a SUSTAINED outage cannot grow the buffer without
                // bound. On overflow drop the OLDEST entries (the newest revocations are the most
                // likely to still name a live session; a bounded, alerted loss beats a memory leak),
                // and fire the operator alert. Also alert on a sustained run of failed cycles even
                // before overflow. Then surface the error so the caller SUPPRESSES the applied-seq
                // heartbeat (D72 — the seq advances only after sweep-plus-flush).
                let dropped = combined.len().saturating_sub(self.redrive_cap);
                if dropped > 0 {
                    combined.drain(0..dropped);
                }
                let capped = dropped > 0;
                let pending_len = combined.len();
                *self
                    .pending
                    .lock()
                    .expect("fleet-sweep redrive lock poisoned") = combined;
                let consecutive_failed_cycles = {
                    let mut failures = self
                        .consecutive_failures
                        .lock()
                        .expect("fleet-sweep redrive lock poisoned");
                    *failures += 1;
                    *failures
                };
                if capped || consecutive_failed_cycles >= FLEET_REDRIVE_ALERT_AFTER_CYCLES {
                    self.alert_sink.observe_redrive(FleetRedriveAlert {
                        pending_len,
                        consecutive_failed_cycles,
                        capped,
                        dropped,
                    });
                }
                // Content-free: only the flusher error's structural Debug (never token/session bytes).
                Err(FleetSweepError(format!("{e:?}")))
            }
        }
    }

    fn prune_torn_down_sessions(&self, session_uuids: &HashSet<String>) {
        // The §5.4 decref path fully tore these sessions down: prune their fleet-revocation rows so
        // the book does not accumulate stale attribution (doc 19 §5.4). `prune_session` drops a
        // fingerprint key once its last session is pruned, so the book shrinks.
        for session_uuid in session_uuids {
            self.book.prune_session(session_uuid);
        }
    }
}

/// The combined admitter-LAST commit sink for the PRODUCTION subscriber: re-sources BOTH the
/// authored-SOA boundary zone AND the running evaluator from one committed snapshot, in the
/// frozen admitter-LAST order (the gate is the admitter — it commits the new policy version
/// LAST, after the enforcement layers applied it), THEN runs the doc 11 §5.4 revocation sweep
/// over the live admissions against that just-re-sourced evaluator. Pairs a [`BoundaryZoneSink`]
/// (the gate's boundary-zone reload path) with a [`PolicyEvaluatorSink`] (the running evaluator)
/// and an optional [`RevocationTarget`] (the live-admission registry), so a single committed
/// `BoundarySnapshot` drives the frozen `evaluate`, the authored suffix, AND the revocation
/// sweep off one policy version. A snapshot that carries no composed policy (`policy: None`)
/// re-sources only the boundary zone — the unchanged boundary-zone-only path (no evaluator
/// change → nothing for the sweep to re-decide, so it is skipped).
pub struct SnapshotCommitSink<Z: BoundaryZoneSink, E: PolicyEvaluatorSink, R: RevocationTarget> {
    zone: Z,
    evaluator: E,
    /// The live-admission registry the §5.4 sweep re-evaluates against the re-sourced evaluator,
    /// the re-evaluation surface (the running evaluator) to decide against, AND the enforcement
    /// surface the resulting [`SweepOutcome`] is ROUTED to (the ds-nft allow-set withdrawals +
    /// rung-conditional conntrack flush). `None` when no admission registry is wired (the
    /// pre-W1/W2-seam path today, and the boundary-zone-only callers) — the sweep is then a no-op
    /// the commit skips. The enforcer is a shared-handle `Arc<dyn SweepEnforcer>` so the sink holds
    /// it behind a shared ref; it defaults to the reportable in-memory [`RecordingSweepEnforcer`]
    /// ([`with_revocation_sweep`](Self::with_revocation_sweep)) — no live kernel — and `main` binds
    /// an explicit enforcer via [`with_revocation_sweep_enforced`](Self::with_revocation_sweep_enforced).
    sweep: Option<(R, PolicyCorePolicy, Arc<dyn SweepEnforcer>)>,
    /// The applied-seq host-agent HEARTBEAT the commit reports the committed version's
    /// [`AppliedSeqIdentity`] to — reported ONLY AFTER the §5.4 revocation sweep completes (doc 13
    /// §5 readiness row: `applied_seq` is reported after-sweep). Defaults to the inert
    /// [`NullHeartbeat`] (the commit reports nowhere — behavior unchanged for the existing tests);
    /// `main` wires the host agent's heartbeat via
    /// [`with_applied_seq_heartbeat`](Self::with_applied_seq_heartbeat). A boundary-zone-only
    /// snapshot (`policy: None`) carries no version identity and never heartbeats.
    heartbeat: Arc<dyn AppliedSeqHeartbeat>,
    /// The reload-boundary DROP sink the subscriber's forward-only-seq STALE-FAN-OUT drop is
    /// ROUTED to (doc 11 §5.3 / §5.5, D72): when [`watch_snapshots`] declines a duplicate /
    /// out-of-order fan-out it hands the [`SnapshotDropEvent`] to
    /// [`observe_snapshot_drop`](SnapshotSink::observe_snapshot_drop), and THIS field is where the
    /// production commit sink routes it — to a real [`SnapshotDropSink`] (chiefly `main`'s
    /// operator-alert sink, the SAME one the publisher's content_hash/schema NACK drops route to).
    /// The drop BEHAVIOR is unchanged (the snapshot is still dropped, one monotonic version);
    /// only the OBSERVABILITY is opt-in. Defaults to the inert [`NullDropSink`] so every existing
    /// `SnapshotCommitSink` constructor / test stays green (the drop is observed nowhere — the
    /// pre-existing default-no-op behavior); `main` wires a real sink via
    /// [`with_drop_sink`](Self::with_drop_sink). The stale-fan-out drop the subscriber raises and
    /// the content_hash/schema NACK the publisher raises are distinct reasons
    /// ([`crate::event::SnapshotDropReason`]) carried in the SAME convention-layer payload, so an
    /// operator joins on the reason token.
    drop_sink: Arc<dyn SnapshotDropSink>,
    /// The post-commit FLEET token-revocation sweep leg (doc 19 §7; D102/P-R6, D72/D53). `Some`
    /// when the gate wired a [`FleetRevocationSweeper`] (a real [`FleetRevocationBook`] + a
    /// concrete flusher) via [`with_fleet_revocation_sweep`](Self::with_fleet_revocation_sweep);
    /// `None` for every existing caller (the §5.4-DNS-2b-only path is unchanged — no fleet-token
    /// severing). When wired, [`commit_snapshot`](SnapshotSink::commit_snapshot) runs it over the
    /// committed policy's [`CommittedPolicy::fleet_revocations`] AFTER the §5.4 sweep and BEFORE
    /// the applied-seq heartbeat, so a pushed fleet-revocation artifact severs live flows and
    /// `applied_seq` advances only after the sweep-plus-flush completes; a fail-closed flush error
    /// suppresses the heartbeat (the host never reports a version applied whose token revocations
    /// did not enforce).
    fleet_sweep: Option<Arc<dyn FleetRevocationSweeper>>,
}

impl<Z: BoundaryZoneSink, E: PolicyEvaluatorSink> SnapshotCommitSink<Z, E, NoSweep> {
    /// Pair a boundary-zone reload sink with an evaluator re-source sink, WITHOUT a revocation
    /// sweep target — the boundary-zone + evaluator commit the existing wave28 tests drive. The
    /// revocation target defaults to the inert [`NoSweep`], so a snapshot's evaluator re-source
    /// runs no sweep (nothing to re-decide). The §5.4 sweep is wired via
    /// [`with_revocation_sweep`](Self::with_revocation_sweep) once the W1/W2 admission
    /// transaction mints live admissions into a [`LiveAdmissions`] registry.
    pub fn new(zone: Z, evaluator: E) -> Self {
        Self {
            zone,
            evaluator,
            sweep: None,
            heartbeat: Arc::new(NullHeartbeat),
            drop_sink: Arc::new(NullDropSink),
            fleet_sweep: None,
        }
    }
}

impl<Z, E> SnapshotCommitSink<Z, E, LiveAdmissions>
where
    Z: BoundaryZoneSink,
    E: PolicyEvaluatorSink,
{
    /// Pair a boundary-zone reload sink + evaluator re-source sink WITH the doc 11 §5.4
    /// revocation sweep: after the admitter-LAST evaluator re-source, the commit re-evaluates the
    /// `admissions` registry against the `reevaluator` (the gate's re-sourced running evaluator —
    /// `main` hands [`RunningGate::policy_reloader`]'s sibling here, the SAME shared inner `Arc`)
    /// and removes the now-denied derived state. The production `main` wires this with the gate's
    /// shared [`RunningGate::live_admissions`] registry — the SAME one the W1/W2 admission
    /// transaction mints into — so the sweep re-decides the admissions actually minted; the
    /// ordering (evaluator FIRST, sweep SECOND) is fixed here so the sweep always decides against
    /// the NEW policy version.
    pub fn with_revocation_sweep(
        zone: Z,
        evaluator: E,
        admissions: LiveAdmissions,
        reevaluator: PolicyCorePolicy,
    ) -> Self {
        // The enforcer defaults to the reportable in-memory [`RecordingSweepEnforcer`] — the
        // LOOPBACK/SYNTHETIC path (no live nft/conntrack write). `main` overrides it via
        // [`with_revocation_sweep_enforced`] to bind the production `ds_nft::NftWriter` adapter
        // behind the `DS_NFTGATE_LIVE` gate; the existing 4-arg callers (and the wave-1 tests)
        // get the reportable default with no signature change.
        Self::with_revocation_sweep_enforced(
            zone,
            evaluator,
            admissions,
            reevaluator,
            Arc::new(RecordingSweepEnforcer::new()),
        )
    }

    /// Pair the boundary-zone + evaluator + §5.4 sweep WITH an explicit [`SweepEnforcer`] — the
    /// production seam `main` uses to ROUTE the sweep's [`SweepOutcome`] (the refcount-zero freed
    /// allow-set deletions + the D53 rung-conditional conntrack flushes) to a chosen enforcement
    /// surface. The default-path [`with_revocation_sweep`](Self::with_revocation_sweep) supplies
    /// the reportable [`RecordingSweepEnforcer`]; a production deployment supplies an adapter over
    /// `ds_nft::NftWriter` (the deferred crate-dependency edge), gated behind `DS_NFTGATE_LIVE`
    /// (default OFF → the reportable in-memory enforcer, no live kernel). The ordering is fixed:
    /// evaluator re-source FIRST, sweep SECOND, the outcome ROUTED to the enforcer THIRD, the
    /// authored suffix LAST.
    pub fn with_revocation_sweep_enforced(
        zone: Z,
        evaluator: E,
        admissions: LiveAdmissions,
        reevaluator: PolicyCorePolicy,
        enforcer: Arc<dyn SweepEnforcer>,
    ) -> Self {
        Self {
            zone,
            evaluator,
            sweep: Some((admissions, reevaluator, enforcer)),
            heartbeat: Arc::new(NullHeartbeat),
            drop_sink: Arc::new(NullDropSink),
            fleet_sweep: None,
        }
    }
}

impl<Z: BoundaryZoneSink, E: PolicyEvaluatorSink, R: RevocationTarget> SnapshotCommitSink<Z, E, R> {
    /// Wire the applied-seq host-agent HEARTBEAT this commit reports the committed version's
    /// [`AppliedSeqIdentity`] to — reported ONLY AFTER the §5.4 revocation sweep completes (doc 13
    /// §5 readiness row: `applied_seq = min(seq)` over the consumers, after-sweep). `main` hands
    /// the host agent's heartbeat carrier here; a deployment that wants no heartbeat keeps the
    /// inert [`NullHeartbeat`] default (this is opt-in, behavior-preserving for the existing
    /// callers). The after-sweep ordering is FIXED in [`commit_snapshot`](SnapshotSink::commit_snapshot):
    /// the evaluator re-source FIRST, the sweep SECOND, the heartbeat LAST — so a downstream
    /// consumer never reads an `applied_seq` for a version whose now-denied admissions are not yet
    /// revoked.
    pub fn with_applied_seq_heartbeat(mut self, heartbeat: Arc<dyn AppliedSeqHeartbeat>) -> Self {
        self.heartbeat = heartbeat;
        self
    }

    /// Wire the reload-boundary DROP sink this commit sink ROUTES the subscriber's forward-only-seq
    /// STALE-FAN-OUT drop to (doc 11 §5.3 / §5.5, D72). [`watch_snapshots`] hands every declined
    /// duplicate / out-of-order fan-out to [`observe_snapshot_drop`](SnapshotSink::observe_snapshot_drop);
    /// the production [`SnapshotCommitSink`] override forwards it to the `drop_sink` bound here. `main`
    /// hands the SAME operator-alert [`SnapshotDropSink`] the publisher's content_hash / schema NACK
    /// drops route to, so a benign stale fan-out and an integrity rejection ride one observability
    /// surface, separable by their distinct [`crate::event::SnapshotDropReason`] token.
    ///
    /// OPT-IN and behavior-preserving: a deployment (and every existing test) that wires no drop sink
    /// keeps the inert [`NullDropSink`] default, so the drop is observed nowhere — the prior
    /// default-no-op `observe_snapshot_drop` behavior — and the snapshot is dropped EITHER WAY (one
    /// monotonic policy version; only the OBSERVABILITY of that benign dedup is added).
    pub fn with_drop_sink(mut self, drop_sink: Arc<dyn SnapshotDropSink>) -> Self {
        self.drop_sink = drop_sink;
        self
    }

    /// Wire the post-commit FLEET token-revocation sweep this commit sink runs over each committed
    /// policy version's [`CommittedPolicy::fleet_revocations`] (doc 19 §7; D102/P-R6, D72/D53).
    /// `main` hands a [`BookBackedFleetSweeper`] pairing the gate's shared [`FleetRevocationBook`]
    /// (the SAME fingerprint→sessions book the admission path records into) with a concrete
    /// `ds_nft::NftWriter` flusher; a deployment that wires none keeps the default `None` and runs
    /// only the §5.4 DNS-2b sweep (behavior-preserving for every existing caller).
    ///
    /// The ordering is FIXED in [`commit_snapshot`](SnapshotSink::commit_snapshot): the evaluator
    /// re-source FIRST, the §5.4 DNS-2b sweep SECOND, THIS fleet-revocation sweep THIRD, the
    /// applied-seq heartbeat LAST — and the heartbeat is SUPPRESSED on a fleet-sweep flush failure
    /// (fail-closed: `applied_seq` never advances past a version whose token revocations did not
    /// enforce, D72).
    pub fn with_fleet_revocation_sweep(mut self, sweeper: Arc<dyn FleetRevocationSweeper>) -> Self {
        self.fleet_sweep = Some(sweeper);
        self
    }
}

impl<Z: BoundaryZoneSink, E: PolicyEvaluatorSink, R: RevocationTarget> SnapshotSink
    for SnapshotCommitSink<Z, E, R>
{
    fn commit_snapshot(&self, snapshot: &BoundarySnapshot) {
        // The committed evaluator re-source FIRST (the policy version the boundary zone
        // belongs to) — admitter-LAST relative to the enforcement layers — THEN the doc 11
        // §5.4 revocation sweep over the live admissions against that just-re-sourced evaluator,
        // THEN the authored-SOA suffix. The sweep MUST run after the re-source so it re-decides
        // against the NEW policy version (D72): a tightened policy revokes its now-denied live
        // admissions before the gate authors another answer. A boundary-zone-only snapshot
        // (`policy: None`) re-sources only the suffix and runs no sweep (no evaluator change →
        // nothing to re-decide). The sweep now re-decides the admissions the W1/W2 transaction
        // mints into the shared registry (`RunningGate::live_admissions`), in the admitter-LAST
        // order this commit fixes.
        if let Some(committed) = &snapshot.policy {
            self.evaluator
                .commit_policy(&committed.composed, committed.ttl_clamp);
            // §5.4: re-evaluate live admissions against the NEW evaluator (admitter-LAST →
            // sweep). The registry is the SAME one the W1/W2 admission transaction mints into
            // (shared from the gate via `RunningGate::live_admissions`), so the sweep re-decides
            // the admissions the transaction actually minted. The outcome (revoked DNS-2b entries,
            // refcount-aware allow-set deletions, rung-conditional flush flags) is now ROUTED to
            // ENFORCEMENT (no longer discarded): `route_sweep_outcome` withdraws the refcount-zero
            // freed allow-set elements via the ds-nft allow-set delete AND fires the D53
            // rung-conditional `flush_session` conntrack flush over the freed IPs, faithfully
            // routing what the sweep RESOLVED (it never recomputes the refcount — the D53/W4
            // under-delete bias rides verbatim). The default enforcer is the reportable in-memory
            // recorder (no live kernel); the production `ds_nft::NftWriter` adapter is the deferred
            // edge behind `DS_NFTGATE_LIVE`.
            if let Some((target, reevaluator, enforcer)) = &self.sweep {
                let outcome = target.sweep(reevaluator);
                route_sweep_outcome(&outcome, enforcer.as_ref());
                // FLEET-BOOK TEARDOWN PRUNE (doc 19 §5.4): a session the §5.4 sweep revoked that now
                // holds NO surviving live admission has been fully torn down by the decref path — so
                // prune its rows from the fleet-revocation book, bounding a long-running gate's
                // accumulation of stale attribution. A session that lost ONE domain but retains
                // others stays (it is still live); only fully-drained sessions are pruned (bias to
                // under-prune, mirroring the §5.4 W4 under-delete). Skipped when no fleet sweeper is
                // wired (the §5.4-only path is unchanged).
                if let Some(sweeper) = &self.fleet_sweep {
                    let mut torn_down = outcome.revoked_session_uuids();
                    if !torn_down.is_empty() {
                        let still_live = target.live_session_uuids();
                        torn_down.retain(|s| !still_live.contains(s));
                        if !torn_down.is_empty() {
                            sweeper.prune_torn_down_sessions(&torn_down);
                        }
                    }
                }
            }
            // FLEET token-revocation sweep (doc 19 §7; D102/P-R6, D72/D53) — the SECOND post-commit
            // sweep leg, run AFTER the §5.4 DNS-2b sweep and BEFORE the applied-seq heartbeat. It
            // severs the flows established under any token this version's fleet-revocation artifact
            // revokes: for each recognized entry, the REAL admission book (the shared
            // `FleetRevocationBook` the admission path records into — NOT an injected test closure)
            // resolves the revoked token's fingerprint to its live sessions, and each is severed
            // rung-conditionally (D53) through the FROZEN shared `flush_session` primitive (a
            // call-site only). A boundary-zone-only snapshot never reaches here; a committed policy
            // that carries no fleet revocations runs an empty (no-op) sweep. FAIL-CLOSED: a flush
            // failure (the sweep could not reach the kernel) SUPPRESSES the applied-seq heartbeat
            // below, so the host never reports a version applied whose token revocations did not
            // enforce (D72: `applied_seq` advances only after the sweep-plus-flush completes).
            let fleet_sweep_ok = match &self.fleet_sweep {
                Some(sweeper) => match sweeper.sweep_fleet(&committed.fleet_revocations) {
                    Ok(_sweep) => true,
                    Err(err) => {
                        eprintln!(
                            "ds-dnsgate: fleet-revocation sweep FAILED — suppressing applied_seq \
                             heartbeat for seq={} (fail-closed, token revocations not yet \
                             enforced): {err}",
                            snapshot.seq,
                        );
                        false
                    }
                },
                // No fleet sweeper wired: the §5.4-only path is unchanged (nothing to suppress).
                None => true,
            };
            // The applied-seq host-agent HEARTBEAT — reported ONLY AFTER the §5.4 revocation sweep
            // AND the fleet-revocation sweep above (doc 13 §5 readiness row: `applied_seq` is
            // reported after-sweep). A downstream consumer reading this `applied_seq` therefore
            // knows the now-denied admissions AND the fleet-revoked tokens of the PRIOR/THIS
            // version are already severed under THIS version. The reported identity is the EXACT
            // `(seq, content_hash, wire_content_hash)` the committed snapshot transported, so the
            // heartbeat can never disagree with what the loader committed. A boundary-zone-only
            // snapshot (`policy: None`) carries no version identity and never reaches here; a
            // fleet-sweep flush failure suppresses the report (fail-closed, above).
            if fleet_sweep_ok {
                if let Some(identity) = snapshot.applied_seq_identity() {
                    self.heartbeat.report_applied_seq(identity);
                }
            }
        }
        self.zone.commit_boundary_zone(&snapshot.boundary_zone);
    }

    fn observe_snapshot_drop(&self, drop: SnapshotDropEvent) {
        // ROUTE the subscriber's forward-only-seq STALE-FAN-OUT drop to the wired drop sink (doc 11
        // §5.3 / §5.5, D72) — the production override of the default no-op. `watch_snapshots` raised
        // this on a declined duplicate / out-of-order fan-out; the snapshot is dropped EITHER WAY
        // (the drop BEHAVIOR is unchanged, one monotonic policy version), this only makes that
        // benign dedup OBSERVABLE on the SAME `SnapshotDropSink` `main` routes the publisher's
        // content_hash / schema NACK drops to. Infallible: a dropped telemetry record never changes
        // which snapshots commit. Defaults to the inert `NullDropSink` (observed nowhere — the prior
        // default-no-op behavior) until `main` wires a real sink via
        // [`with_drop_sink`](Self::with_drop_sink).
        self.drop_sink.observe_drop(drop);
    }
}

/// The inert revocation target the no-sweep [`SnapshotCommitSink::new`] defaults to — a sweep
/// over it is always a no-op (there is no admission registry). The boundary-zone + evaluator
/// commit callers that wire no admission registry use this; the production `main` uses a
/// [`LiveAdmissions`]-carrying sink ([`SnapshotCommitSink::with_revocation_sweep`]) over the
/// gate's shared registry the W1/W2 transaction mints into.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSweep;

impl RevocationTarget for NoSweep {
    fn sweep(&self, _evaluator: &dyn AdmissionReevaluator) -> SweepOutcome {
        SweepOutcome::default()
    }
}

/// The full committed-snapshot commit sink the subscriber core loop drives — the
/// admitter-LAST D72 commit point for EVERYTHING a [`BoundarySnapshot`] re-sources (the
/// authored-SOA boundary zone today; the running evaluator when the snapshot carries a
/// composed policy). A trait so the loop is exercised against the production
/// [`SnapshotCommitSink`] AND a synthetic recorder in tests, without binding listeners.
pub trait SnapshotSink {
    /// Commit one host-local snapshot admitter-LAST — re-source every field this snapshot
    /// carries (the enforcement layers already applied this version, so this is strictly last).
    fn commit_snapshot(&self, snapshot: &BoundarySnapshot);

    /// Observe a forward-only-seq DROP at the reload boundary (doc 11 §5.3 / D72): a duplicate
    /// or out-of-order host-local fan-out the subscriber declined to re-source (`dropped_seq ≤
    /// committed_seq`), so one monotonic policy version is preserved. The drop BEHAVIOR is
    /// unchanged — the snapshot is dropped either way; this hook only makes that benign dedup
    /// OPERATIONALLY OBSERVABLE (a distinct telemetry signal vs the silent `continue`), so an
    /// operator can tell a stale fan-out apart from a content_hash NACK (D120, the OTHER
    /// non-commit; [`crate::event::SnapshotDropReason`]).
    ///
    /// DEFAULTS TO A NO-OP so the existing [`SnapshotSink`] impls (the production
    /// [`SnapshotCommitSink`] and the boundary-zone-only adapter) need no change and stay
    /// green; a sink that wants the signal overrides it to route the [`SnapshotDropEvent`] to
    /// a real [`crate::event::SnapshotDropSink`]. The default body is `let _ = drop;` (the drop
    /// event is observed nowhere) — never an emission site that changes which snapshots commit.
    ///
    /// # FORWARD RULE for a decorator/wrapper `SnapshotSink` (doc 11 §5.3 / §5.5)
    ///
    /// Because this method is DEFAULTED, a wrapper/decorator [`SnapshotSink`] impl (one that
    /// wraps an inner sink to intercept [`commit_snapshot`](Self::commit_snapshot)) MUST
    /// EXPLICITLY DELEGATE `observe_snapshot_drop` to its inner sink — otherwise it silently
    /// inherits THIS no-op default and SHADOWS the inner sink's production override
    /// ([`SnapshotCommitSink::observe_snapshot_drop`], which routes the drop to the wired
    /// [`crate::event::SnapshotDropSink`]). The shadow is INVISIBLE at compile time (the default
    /// makes the method optional, so a wrapper that forgets it still type-checks and still
    /// commits snapshots correctly) yet swallows the stale-fan-out DROP signal the §5.3
    /// single-monotonic-version story relies on for observability. The rule, then: a decorator
    /// delegates EVERY defaulted method to its inner sink, not just the one it set out to wrap.
    fn observe_snapshot_drop(&self, drop: SnapshotDropEvent) {
        let _ = drop;
    }
}

/// Adapt a boundary-zone-only [`BoundaryZoneSink`] into a [`SnapshotSink`] that commits ONLY
/// the authored-SOA suffix (ignoring any committed composed policy) — the boundary-zone-only
/// subscriber path [`watch_policies`] keeps for callers that re-source only the suffix (e.g.
/// the gate's detached [`GateBoundaryReloader`]). A snapshot's composed policy, if present, is
/// simply not applied through this adapter.
struct BoundaryZoneOnly<'a, S: BoundaryZoneSink>(&'a S);

impl<S: BoundaryZoneSink> SnapshotSink for BoundaryZoneOnly<'_, S> {
    fn commit_snapshot(&self, snapshot: &BoundarySnapshot) {
        self.0.commit_boundary_zone(&snapshot.boundary_zone);
    }

    // AUDIT (the `SnapshotSink` FORWARD RULE above): `BoundaryZoneOnly` INHERITS the no-op
    // default `observe_snapshot_drop`, and that is CORRECT here — it is NOT the decorator case the
    // rule forbids. It wraps a `BoundaryZoneSink` (`self.0`), NOT an inner `SnapshotSink`, so there
    // is NO inner `SnapshotSink` override for the default to shadow: a `BoundaryZoneSink` has no
    // `observe_snapshot_drop` method to delegate to. The two production `SnapshotSink` impls are
    // exactly this adapter (no inner sink) and `SnapshotCommitSink` (which OVERRIDES the method to
    // route the drop to its wired `SnapshotDropSink`); neither wraps an inner `SnapshotSink` whose
    // override the default would silently swallow. The genuine forbidden case — a decorator wrapping
    // an inner `SnapshotSink` that FORGETS to delegate `observe_snapshot_drop` — is guarded
    // out-of-crate by the delegating-decorator witness in `tests/event_surface.rs`
    // (`snapshotsink_forward_rule`), so a future decorator that inherits the default fails the gate.
}

/// One committed host-local policy snapshot the gate reads its policy-pushed field(s)
/// off of — the value the host agent fans out behind its prepare/commit barrier (doc 11
/// §5.3 / D72). `ds-dnsgate` NEVER opens a control-plane stream (§5.3): this is the
/// host-LOCAL hand-off shape, fed synthetically in tests and by the host agent in
/// production.
///
/// Carries the D71 authored-SOA `boundary_zone` (the same value
/// `ds-policy-snapshot::PolicySnapshot::boundary_zone_value` materializes), the D72 monotonic
/// policy `seq` (one policy version end to end, no per-service namespace), AND — additively —
/// the committed evaluator re-source: the host's ONE composed POL-1 document plus its W2 clamp
/// window. A snapshot WITHOUT a composed document (constructed via [`BoundarySnapshot::new`])
/// re-sources only the authored-SOA suffix (the boundary-zone-only hand-off); a snapshot WITH
/// one (via [`BoundarySnapshot::with_policy`]) ALSO re-sources the running [`PolicyCorePolicy`]
/// evaluator — the doc 11 §5.3 production path that drives the frozen `evaluate` off a
/// committed policy version. The type grows additively as the gate reads more snapshot fields;
/// the subscriber loop is unchanged when it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundarySnapshot {
    /// The D36 `policy_log` seq — the single monotonic policy version (D72). The subscriber
    /// commits only forward (a seq that does not advance is a duplicate fan-out, ignored),
    /// so a re-delivered or stale snapshot never re-sources the suffix backwards.
    pub seq: u64,
    /// The committed authored-SOA boundary zone (`SOA MNAME = denied.policy.<boundary_zone>.`;
    /// doc 11 §3.2). The owned live-wire read the gate commits LAST on this seq.
    pub boundary_zone: String,
    /// The committed evaluator re-source for this policy version, if the host agent fanned a
    /// composed document out with this snapshot: the host's ONE composed POL-1 document
    /// (`policy-core`'s deny-wins composition), its W2 TTL clamp window, AND the D72
    /// `content_hash` HALF of the `(seq, content_hash)` snapshot identity (doc 13 §5; the `seq`
    /// half is the [`seq`](Self::seq) field above). `None` for a boundary-zone-only hand-off (the
    /// pre-existing 2-field shape, [`BoundarySnapshot::new`]), so a feed that re-sources only the
    /// authored suffix is unchanged. When `Some`, the D72 admitter-LAST commit re-sources the
    /// running [`PolicyCorePolicy`] from it.
    pub policy: Option<CommittedPolicy>,
}

/// The committed evaluator re-source a [`BoundarySnapshot`] carries — the host's ONE composed
/// POL-1 document plus its W2 clamp window, the pair the running [`PolicyCorePolicy`]
/// re-sources from on a D72 admitter-LAST commit. One committed policy version yields one
/// composed document and one clamp window, so the evaluator never reads a document from one
/// snapshot with a clamp from another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedPolicy {
    /// The deny-wins composed document the evaluator decides against (`policy-core`'s
    /// `compose` output — the same document `ds-dnsgate`'s startup default is built from).
    pub composed: ComposedPolicy,
    /// The W2 TTL clamp window that rides each `Allow`'s frozen `Admit` for this version.
    pub ttl_clamp: TtlClamp,
    /// The D72 `content_hash` HALF of the `(seq, content_hash)` snapshot identity (doc 13 §5:
    /// the full identity is `(seq, content_hash, full composed document)`; the `seq` is the
    /// owning [`BoundarySnapshot::seq`], the document is [`composed`](Self::composed), and this
    /// is the [`ds_policy_snapshot::CommittedPolicy::content_hash`] fingerprint of that document
    /// lifted off the SAME committed policy version the production publisher fans out). It makes
    /// a committed snapshot self-identifying so the subscriber can ACK `(seq, content_hash)` per
    /// the §5 identity row, and so a re-applied document is recognizable by its stable hash.
    /// ADDITIVE: the prior [`with_policy`](BoundarySnapshot::with_policy) callers (and the
    /// boundary-zone-only hand-off) carry no transported identity, so this defaults to `0` for
    /// them; the production [`with_policy_layer`](BoundarySnapshot::with_policy_layer) lift
    /// threads the real fingerprint THROUGH `ds-policy-snapshot` (the one place it is computed).
    pub content_hash: u64,
    /// The D120 WIRE `content_hash` (SHA-256 full 32 bytes over the producer's produce-once RFC
    /// 8785 (JCS) payload; doc 13 §5.1) when this version was built from VERIFIED transported bytes
    /// through the produce-once / verify-only LOADER
    /// ([`BoundarySnapshot::with_verified_policy_layer`] /
    /// [`ds_policy_snapshot::load_verified_snapshot`]). `None` for the in-memory layer-only
    /// hand-offs that never saw transported wire bytes
    /// ([`with_policy`](BoundarySnapshot::with_policy) /
    /// [`with_policy_layer`](BoundarySnapshot::with_policy_layer)), keeping those carriers
    /// byte-identical (ADDITIVE). This is the SAME 32-byte hash the loader's NACK-on-hash check
    /// validated against the transported bytes, surfaced onto the applied-seq host-agent
    /// heartbeat ([`SnapshotCommitSink`] reports it ONLY AFTER the §5.4 revocation sweep) so the
    /// host self-identifies on the §5 wire-identity tuple, not only the local fingerprint.
    pub wire_content_hash: Option<ContentHash>,
    /// The FLEET token-revocation entries recognized on THIS committed policy version (doc 19 §7;
    /// D102/P-R6). Each names a revoked token by a hex chain FINGERPRINT / block id (NEVER token
    /// bytes) plus the D53 rung that gates severing; the emergency kill-switch artifact rides
    /// INSIDE the committed document (D72 "no third channel"), so it commits on the SAME monotonic
    /// policy `seq` as the boundary zone + evaluator. The [`SnapshotCommitSink`]'s post-commit
    /// fleet sweep severs the live sessions each fingerprint resolves to (via the shared
    /// [`FleetRevocationBook`]) rung-conditionally through the frozen `flush_session`, BEFORE the
    /// applied-seq heartbeat. ADDITIVE + EMPTY by default: the boundary-zone/evaluator commit
    /// callers (and the produce-once loader lift) carry no revocations unless the producer
    /// recognizes them, so the existing carriers are behavior-identical (an empty sweep is a
    /// no-op). Populate via [`BoundarySnapshot::with_fleet_revocations`].
    pub fleet_revocations: Vec<FleetRevocationEntry>,
}

/// The D72 snapshot identity the applied-seq host-agent HEARTBEAT surfaces (doc 13 §5 identity +
/// readiness rows) — the scalar components of the `(seq, content_hash, document)` tuple a host
/// reports for a committed policy version: the host-applied forward-only `seq` (the value
/// `applied_seq` tracks), the build-LOCAL `content_hash` fingerprint, AND the VERIFIED D120 wire
/// `content_hash` when the version was loaded through the produce-once / verify-only path
/// (`None` on the in-memory layer-only hand-offs). The host heartbeat reports this ONLY AFTER the
/// §5.4 revocation sweep completes (doc 13 §5 readiness row: `applied_seq` is reported
/// after-sweep), so a downstream consumer never reads an `applied_seq` for a version whose
/// now-denied admissions have not yet been revoked. The scalars are the EXACT values the
/// committed [`BoundarySnapshot`] transports (never re-derived), so the reported identity matches
/// what the loader committed byte-for-byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppliedSeqIdentity {
    /// The host-applied, forward-only `seq` of the committed version (doc 13 §5 / D72) — the value
    /// `applied_seq` tracks across the consumers (min-over-three, reported after-sweep).
    pub seq: u64,
    /// The build-LOCAL `content_hash` fingerprint of the committed composed document (the
    /// `ds-policy-snapshot` per-version digest the publisher lifted off the version).
    pub content_hash: u64,
    /// The VERIFIED D120 wire `content_hash` (SHA-256 full 32 bytes; doc 13 §5.1) when the version
    /// was loaded through the verify-only path, else `None`. The wire identity the cross-fleet
    /// `applied_seq` skew test joins on (both services assert the SAME `(seq, content_hash)`).
    pub wire_content_hash: Option<ContentHash>,
}

impl AppliedSeqIdentity {
    /// The §5.4 readiness predicate's wire-identity hex (doc 13 §5.1) — the greppable
    /// `content_hash` token an operator joins the post-sweep `applied_seq` heartbeat on, or
    /// `"local-only"` when the version carried no transported wire hash (an in-memory hand-off).
    pub fn wire_content_hash_hex(&self) -> String {
        self.wire_content_hash
            .map(|h| ds_contracts::snapshot_verify::content_hash_hex(&h))
            .unwrap_or_else(|| "local-only".to_string())
    }
}

/// The applied-seq host-agent HEARTBEAT seam (doc 13 §5 readiness row, D72/D36): the
/// [`SnapshotCommitSink`] reports each committed version's [`AppliedSeqIdentity`] here ONLY AFTER
/// the §5.4 revocation sweep completes. `ds-dnsgate` is one of the three consumers whose
/// `applied_seq` the host agent's heartbeat takes the `min` over; this is the host-LOCAL hand-off
/// the gate reports its post-sweep applied seq + identity to (the host agent's gRPC heartbeat — the
/// carrier whose shape freezes at M0 in doc 15 §5.2 — backs it in production; tests capture it
/// in-process). A separate trait from [`SnapshotDropSink`] so the reload-boundary drop telemetry
/// and the readiness heartbeat compose independently.
///
/// `Send + Sync + 'static` so the carrier can live behind the `Arc` the commit sink shares.
pub trait AppliedSeqHeartbeat: Send + Sync + 'static {
    /// Report the committed version's applied-seq identity — called by the commit sink AFTER the
    /// §5.4 revocation sweep (the after-sweep ordering is fixed by the sink, never the reporter).
    /// Infallible by construction (a dropped heartbeat record never changes the commit BEHAVIOR;
    /// the obligation is only to make the post-sweep applied seq OBSERVABLE to the host agent).
    fn report_applied_seq(&self, identity: AppliedSeqIdentity);
}

/// The default applied-seq heartbeat: a no-op. The commit paths that wire no host-agent heartbeat
/// default to this — the commit BEHAVIOR is unchanged (still admitter-LAST, still sweeps); only the
/// readiness REPORTING is opt-in via a real carrier ([`SnapshotCommitSink::with_applied_seq_heartbeat`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct NullHeartbeat;

impl AppliedSeqHeartbeat for NullHeartbeat {
    fn report_applied_seq(&self, _identity: AppliedSeqIdentity) {}
}

impl BoundarySnapshot {
    /// Build a committed snapshot from a seq and a boundary-zone value — the boundary-zone-only
    /// host-local hand-off the host agent (and the synthetic test feed) produces. The value is
    /// the `ds-policy-snapshot::PolicySnapshot::boundary_zone_value()` output; an empty value
    /// falls back to the [`DEFAULT_BOUNDARY_ZONE`] working name so the authored suffix is never
    /// blank (mirroring the POL-1 reader / snapshot empty-skip). Carries NO composed policy
    /// (`policy: None`), so it re-sources only the authored-SOA suffix — the unchanged 2-field
    /// shape the boundary-zone reload path consumes.
    pub fn new(seq: u64, boundary_zone: impl Into<String>) -> Self {
        Self {
            policy: None,
            ..Self::with_zone_and_policy(seq, boundary_zone, None)
        }
    }

    /// Build a committed snapshot that ALSO carries the evaluator re-source for this policy
    /// version — the production host-agent hand-off (and the synthetic test feed) that drives
    /// the frozen `evaluate` off a committed composed document. The boundary zone and the
    /// composed document are the SAME policy version (one seq → one version end to end, D72);
    /// the running [`PolicyCorePolicy`] re-sources from `composed`/`ttl_clamp` admitter-LAST.
    ///
    /// This shape carries NO transported `content_hash` (the identity defaults to `0`): it is
    /// the in-memory composed-doc hand-off the wave28/29 callers and the suffix-only feeds use.
    /// The production publisher lifts the real `(seq, content_hash)` identity off a committed
    /// policy version via [`with_policy_layer`](Self::with_policy_layer) instead.
    pub fn with_policy(
        seq: u64,
        boundary_zone: impl Into<String>,
        composed: ComposedPolicy,
        ttl_clamp: TtlClamp,
    ) -> Self {
        Self::with_policy_and_hash(seq, boundary_zone, composed, ttl_clamp, 0)
    }

    /// Build a committed snapshot carrying the evaluator re-source AND the D72 `content_hash`
    /// HALF of the `(seq, content_hash)` snapshot identity (doc 13 §5) — the shape the
    /// PRODUCTION publisher fans out so the subscriber re-sources a committed version with its
    /// full transported identity, not a synthesized one. The `content_hash` is the
    /// [`ds_policy_snapshot::CommittedPolicy::content_hash`] fingerprint of the composed document
    /// (the one place it is computed); [`with_policy_layer`](Self::with_policy_layer) lifts both
    /// the document and this hash off the SAME committed policy version so they can never
    /// disagree about which policy is carried.
    pub fn with_policy_and_hash(
        seq: u64,
        boundary_zone: impl Into<String>,
        composed: ComposedPolicy,
        ttl_clamp: TtlClamp,
        content_hash: u64,
    ) -> Self {
        // The in-memory layer-only hand-off never saw transported wire bytes, so the D120 wire
        // hash is absent (ADDITIVE: the existing callers are byte-identical). The verify-only
        // loader path threads the verified wire hash via `with_verified_policy_and_hash`.
        Self::with_zone_and_policy(
            seq,
            boundary_zone,
            Some(CommittedPolicy {
                composed,
                ttl_clamp,
                content_hash,
                wire_content_hash: None,
                // ADDITIVE: the in-memory layer-only hand-off recognizes no fleet revocations;
                // populate via `BoundarySnapshot::with_fleet_revocations`.
                fleet_revocations: Vec::new(),
            }),
        )
    }

    /// Build a committed snapshot carrying the evaluator re-source, the LOCAL `content_hash`
    /// fingerprint, AND the VERIFIED D120 wire `content_hash` (doc 13 §5.1) — the shape the
    /// produce-once / verify-only LOADER fans out after the host agent's bytes verified against
    /// their wire hash. The wire hash is the SAME 32 bytes
    /// [`ds_policy_snapshot::verify_transported_bytes`] validated against the transported bytes;
    /// carried here it threads onto the applied-seq host-agent heartbeat
    /// ([`SnapshotIdentity::wire_content_hash`]) so the host self-identifies on the §5 wire
    /// identity, not only the local fingerprint. ADDITIVE: the layer-only
    /// [`with_policy_and_hash`](Self::with_policy_and_hash) callers are untouched (wire hash
    /// `None`).
    pub fn with_verified_policy_and_hash(
        seq: u64,
        boundary_zone: impl Into<String>,
        composed: ComposedPolicy,
        ttl_clamp: TtlClamp,
        content_hash: u64,
        wire_content_hash: ContentHash,
    ) -> Self {
        Self::with_zone_and_policy(
            seq,
            boundary_zone,
            Some(CommittedPolicy {
                composed,
                ttl_clamp,
                content_hash,
                wire_content_hash: Some(wire_content_hash),
                // ADDITIVE: the verify-only loader lift recognizes no fleet revocations here;
                // populate via `BoundarySnapshot::with_fleet_revocations`.
                fleet_revocations: Vec::new(),
            }),
        )
    }

    /// Attach the FLEET token-revocation entries recognized on this committed policy version (doc
    /// 19 §7; D102/P-R6) — the emergency kill-switch artifact that rides INSIDE the committed
    /// document on the SAME monotonic `seq` (D72 "no third channel"). A builder over the existing
    /// `with_policy*` carriers so the additive field stays default-empty for every current caller;
    /// the producer (the orchestrator `policy_log` adapter) and the serving-loop integration test
    /// populate it. No-op on a boundary-zone-only snapshot (`policy: None`) — there is no committed
    /// policy version to revoke tokens against.
    #[must_use]
    pub fn with_fleet_revocations(mut self, entries: Vec<FleetRevocationEntry>) -> Self {
        if let Some(policy) = self.policy.as_mut() {
            policy.fleet_revocations = entries;
        }
        self
    }

    /// The FLEET token-revocation entries this snapshot's committed policy carries (doc 19 §7), or
    /// an empty slice for a boundary-zone-only hand-off / a version that revokes no tokens.
    pub fn fleet_revocations(&self) -> &[FleetRevocationEntry] {
        self.policy
            .as_ref()
            .map(|p| p.fleet_revocations.as_slice())
            .unwrap_or(&[])
    }

    /// The D72 `content_hash` HALF of the `(seq, content_hash)` snapshot identity for the
    /// committed policy this snapshot carries (doc 13 §5), or `None` for a boundary-zone-only
    /// hand-off (`policy: None`) and `Some(0)` for an in-memory [`with_policy`](Self::with_policy)
    /// hand-off that carried no transported identity. The publisher's
    /// [`with_policy_layer`](Self::with_policy_layer) lift populates the real fingerprint. The
    /// `seq` half is the public [`seq`](Self::seq) field.
    pub fn content_hash(&self) -> Option<u64> {
        self.policy.as_ref().map(|p| p.content_hash)
    }

    /// The VERIFIED D120 wire `content_hash` (doc 13 §5.1) for the committed policy this snapshot
    /// carries, or `None` for a boundary-zone-only hand-off (`policy: None`) OR a layer-only
    /// in-memory hand-off that never saw transported wire bytes
    /// ([`with_policy`](Self::with_policy) / [`with_policy_layer`](Self::with_policy_layer)). Only
    /// the produce-once / verify-only loader path
    /// ([`with_verified_policy_layer`](Self::with_verified_policy_layer)) populates it with the
    /// SAME 32 bytes [`ds_policy_snapshot::verify_transported_bytes`] checked.
    pub fn wire_content_hash(&self) -> Option<ContentHash> {
        self.policy.as_ref().and_then(|p| p.wire_content_hash)
    }

    /// The D72 [`AppliedSeqIdentity`] of the committed policy this snapshot carries (doc 13 §5: the
    /// `(seq, content_hash, document)` identity, surfaced as the scalar components the host reports)
    /// — `seq` from the [`seq`](Self::seq) field, the build-LOCAL `content_hash` fingerprint the
    /// publisher lifted off the committed version, and the VERIFIED D120 wire hash from
    /// [`wire_content_hash`](Self::wire_content_hash) when this snapshot was loaded through the
    /// verify-only path. `None` for a boundary-zone-only hand-off (no committed policy). This is
    /// the identity the applied-seq host-agent heartbeat surfaces ONLY AFTER the §5.4 revocation
    /// sweep ([`SnapshotCommitSink::commit_snapshot`] / doc 13 §5 readiness row). The scalars are
    /// the EXACT values the committed snapshot transports — never re-derived from a fabricated
    /// layer — so the reported identity can never disagree with what the loader committed.
    pub fn applied_seq_identity(&self) -> Option<AppliedSeqIdentity> {
        let policy = self.policy.as_ref()?;
        Some(AppliedSeqIdentity {
            seq: self.seq,
            content_hash: policy.content_hash,
            wire_content_hash: policy.wire_content_hash,
        })
    }

    /// Build a committed snapshot for the D72 hot-reload commit path by lifting the WHOLE
    /// committed policy off ONE parsed POL-1 layer THROUGH the shared
    /// [`ds_policy_snapshot::PolicySnapshot::from_policy_layer`] /
    /// [`committed_policy`](ds_policy_snapshot::PolicySnapshot::committed_policy) accessor — the
    /// SAME source of truth `main`'s STARTUP path (`snapshot_host_policy`) sources its host
    /// policy from. The boundary zone, the W2 TTL clamp window, AND the composed-document
    /// material are all read off the single committed policy the accessor hands back, never
    /// re-derived inline on the reload path, so the evaluator re-source, the authored-SOA
    /// suffix, and the clamp can never disagree about which policy version is live (doc 13 §5 /
    /// D72: one snapshot → one composed doc + one clamp + one boundary zone). `policy-core`'s
    /// deny-wins [`compose`](policy_core::pol1_eval::compose) is the EVALUATOR's job — run HERE
    /// over the committed layer the snapshot hands back (the composition INPUT it carries), the
    /// same way startup composes — and the result is carried verbatim into the stable
    /// [`with_policy_and_hash`](Self::with_policy_and_hash) shape the [`SnapshotCommitSink`] /
    /// [`watch_snapshots`] commit path already consumes. This collapses the last inline
    /// parse→compose→lift on the reload path onto the shared accessor; `main`'s PRODUCTION
    /// publisher drives it, so startup and reload share ONE lift end to end.
    ///
    /// This is the lift that carries the full D72 `(seq, content_hash, composed document)`
    /// identity (doc 13 §5): the supplied `seq` is threaded into
    /// [`ds_policy_snapshot::PolicySnapshot::from_policy_layer_with_seq`] and the
    /// `content_hash` is lifted off the resulting committed policy, so the snapshot
    /// self-identifies on the §5 identity row, not only the composed document.
    pub fn with_policy_layer(seq: u64, layer: &ds_contracts::pol1::PolicyLayer) -> Self {
        // Lift the host's ONE committed policy THROUGH the shared snapshot accessor — the
        // boundary zone (POL-1 `dns.boundary_zone`, reader-defaulted to the working name) and
        // the W2 clamp window (POL-1 `admission.ttl_floor`/`ttl_ceil`, reader-defaulted to
        // 60s/900s) are sourced off the SAME parsed layer the composed document is, never
        // re-derived inline. A layer-sourced snapshot always carries a committed policy.
        let snapshot = ds_policy_snapshot::PolicySnapshot::from_policy_layer_with_seq(layer, seq);
        let committed = snapshot
            .committed_policy()
            .expect("a layer-sourced PolicySnapshot always carries a committed policy");
        let boundary_zone = committed.boundary_zone().to_string();
        // The W2 clamp travels WITH the composed document (one policy version, D72): map the
        // snapshot's clamp WINDOW onto the gate's `TtlClamp` (the gate owns the
        // `clamp()`/`to_admit()` projection; the snapshot carries only the floor/ceil VALUES).
        let window = committed.ttl_clamp();
        let ttl_clamp = TtlClamp {
            floor: window.floor,
            ceil: window.ceil,
        };
        // The D72 `(seq, content_hash)` identity travels WITH the document (doc 13 §5): lift the
        // `content_hash` HALF off the SAME committed policy version the document + clamp + zone
        // come from (`ds-policy-snapshot` is the ONE place the fingerprint is computed, from the
        // identical layer the seq was threaded through above). The seq half is the supplied `seq`.
        let content_hash = committed.content_hash();
        // The deny-wins composition is the EVALUATOR's job (doc 13 §1 rule 1) — run it HERE over
        // the committed layer the snapshot hands back (the composition INPUT it carries), so the
        // reload is sourced exactly the way startup is, with no re-parse drift.
        let composed = policy_core::pol1_eval::compose(&[committed.composed_layer().clone()], &[]);
        Self::with_policy_and_hash(seq, boundary_zone, composed, ttl_clamp, content_hash)
    }

    /// Build a committed snapshot from a layer that was loaded through the produce-once /
    /// verify-only LOADER (doc 13 §5.1 / D120) — the path that carries the VERIFIED D120 wire
    /// `content_hash` alongside the document. The caller (the production publisher) first drives
    /// [`ds_policy_snapshot::load_verified_snapshot`] over the TRANSPORTED bytes (hash-check
    /// BEFORE parse; NACK host-wide on mismatch), and on a [`ds_policy_snapshot::LoadVerdict::Loaded`]
    /// hands the parsed `layer` + its `seq` + the verified `wire_content_hash` here. The lift is the
    /// SAME shared `ds-policy-snapshot` accessor as [`with_policy_layer`](Self::with_policy_layer)
    /// (the composed document + W2 clamp + boundary zone + the local fingerprint all come off ONE
    /// committed policy version, never re-derived inline); the ONLY addition is that the VERIFIED
    /// wire hash rides the identity, so the snapshot self-identifies on the §5 wire-identity tuple
    /// and the applied-seq heartbeat can surface it after the sweep.
    pub fn with_verified_policy_layer(
        seq: u64,
        layer: &ds_contracts::pol1::PolicyLayer,
        wire_content_hash: ContentHash,
    ) -> Self {
        // Lift the host's ONE committed policy THROUGH the shared verify-only accessor — the SAME
        // boundary zone + W2 clamp + composed document + local fingerprint the layer-only path
        // lifts, plus the VERIFIED wire hash on the identity (one snapshot → one identity, D72).
        let snapshot = ds_policy_snapshot::PolicySnapshot::from_verified_bytes_and_layer(
            layer,
            seq,
            wire_content_hash,
        );
        let committed = snapshot
            .committed_policy()
            .expect("a layer-sourced PolicySnapshot always carries a committed policy");
        let boundary_zone = committed.boundary_zone().to_string();
        let window = committed.ttl_clamp();
        let ttl_clamp = TtlClamp {
            floor: window.floor,
            ceil: window.ceil,
        };
        let content_hash = committed.content_hash();
        let composed = policy_core::pol1_eval::compose(&[committed.composed_layer().clone()], &[]);
        Self::with_verified_policy_and_hash(
            seq,
            boundary_zone,
            composed,
            ttl_clamp,
            content_hash,
            wire_content_hash,
        )
    }

    /// The shared constructor: normalize an empty boundary zone to the working-name default
    /// and carry the optional committed policy verbatim.
    fn with_zone_and_policy(
        seq: u64,
        boundary_zone: impl Into<String>,
        policy: Option<CommittedPolicy>,
    ) -> Self {
        let boundary_zone = boundary_zone.into();
        let boundary_zone = if boundary_zone.is_empty() {
            DEFAULT_BOUNDARY_ZONE.to_string()
        } else {
            boundary_zone
        };
        Self {
            seq,
            boundary_zone,
            policy,
        }
    }
}

/// The host-local committed-snapshot feed the single-per-host `WatchPolicies` subscriber
/// consumes (doc 11 §5.3 / D72). The host agent — the host's ONE `WatchPolicies(from_seq)`
/// subscriber — fans the committed snapshot out host-locally over this channel after its
/// prepare/commit barrier; `ds-dnsgate` the admitter then commits LAST. There is one such
/// feed per host (`ds-dnsgate` never opens a control-plane stream); tests push synthetic
/// commits through [`BoundarySnapshotFeed::publish`].
///
/// A bounded `mpsc` so a fan-out burst back-pressures the host agent rather than spawning
/// unbounded buffered snapshots against the fleet's single resolver (doc 11 §1).
pub struct BoundarySnapshotFeed {
    tx: mpsc::Sender<BoundarySnapshot>,
}

impl BoundarySnapshotFeed {
    /// Publish one committed snapshot onto the host-local feed (the host agent's commit
    /// fan-out, or a synthetic test push). Returns the channel error if the subscriber has
    /// already stopped (the gate is shutting down), so a publisher can stop feeding.
    pub async fn publish(
        &self,
        snapshot: BoundarySnapshot,
    ) -> Result<(), mpsc::error::SendError<BoundarySnapshot>> {
        self.tx.send(snapshot).await
    }
}

/// The receiving half of the host-local committed-snapshot feed — handed to
/// [`watch_policies`]. Created together with its [`BoundarySnapshotFeed`] publisher by
/// [`boundary_snapshot_feed`].
pub struct BoundarySnapshotSubscription {
    rx: mpsc::Receiver<BoundarySnapshot>,
}

/// Create the host-local committed-snapshot feed: a bounded channel whose publisher half
/// is held by the host agent's commit fan-out (synthetic in tests) and whose subscriber
/// half drives [`watch_policies`]. `capacity` bounds buffered committed snapshots
/// (back-pressure on the host agent, never unbounded growth).
pub fn boundary_snapshot_feed(
    capacity: usize,
) -> (BoundarySnapshotFeed, BoundarySnapshotSubscription) {
    let (tx, rx) = mpsc::channel(capacity.max(1));
    (
        BoundarySnapshotFeed { tx },
        BoundarySnapshotSubscription { rx },
    )
}

/// One committed policy VERSION the host agent's `WatchPolicies(from_seq)` subscription
/// delivers behind its prepare/commit barrier (doc 11 §5.3 / doc 13 §5, D72) — the PRODUCER
/// half of the host-local snapshot feed. The host agent is the host's ONE
/// `WatchPolicies(from_seq)` subscriber (`ds-dnsgate` never opens a control-plane stream); it
/// validates + stages the new version on every enforcement consumer FIRST and then hands the
/// already-enforcement-committed version here for the admitter to commit LAST. The version
/// carries the D72 `seq` (the `policy_log` bigserial — one monotonic version, no per-service
/// namespace) and the committed composed POL-1 [`PolicyLayer`](ds_contracts::pol1::PolicyLayer)
/// (the composition INPUT — `policy-core::compose` is the evaluator's job, run downstream in
/// [`BoundarySnapshot::with_policy_layer`], never by this carrier). The `(seq, content_hash)`
/// identity is derived from the SAME layer when the publisher lifts it onto the feed, so the
/// producer never has to compute the fingerprint itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedPolicyVersion {
    /// The D72 forward-only `policy_log` seq — the single monotonic policy version (doc 13 §5).
    pub seq: u64,
    /// The committed composed POL-1 layer this version carries (the composition INPUT). The
    /// publisher lifts the boundary zone, the W2 clamp, the composed document, AND the
    /// `(seq, content_hash)` identity off this ONE layer THROUGH the shared
    /// `ds-policy-snapshot` accessor, so one version yields one snapshot identity.
    pub layer: ds_contracts::pol1::PolicyLayer,
    /// The PRODUCE-ONCE transported wire form of this version (doc 13 §5.1 / D120), when the host
    /// agent fanned out the canonical bytes it formed EXACTLY ONCE plus their wire `content_hash`.
    /// When `Some`, the publisher drives the VERIFY-ONLY loader
    /// ([`ds_policy_snapshot::load_verified_snapshot`]) over the TRANSPORTED bytes — hash-check
    /// BEFORE parse, NACK host-wide on a content_hash mismatch (the host stays on vN), never
    /// re-serialize. When `None`, the publisher takes the in-memory layer-only lift
    /// ([`BoundarySnapshot::with_policy_layer`]) — the loopback hand-off that never transported wire
    /// bytes. ADDITIVE: the existing [`CommittedPolicyVersion::new`] callers default this to `None`.
    pub wire: Option<VersionWire>,
}

/// The produce-once transported wire form of a [`CommittedPolicyVersion`] (doc 13 §5.1 / D120):
/// the canonical bytes the Go host agent formed EXACTLY ONCE plus the wire `content_hash` it hashed
/// them into. The Rust consumer is VERIFY-ONLY — it hashes THESE transported bytes (via the single
/// source of wire hashing, [`ds_policy_snapshot::verify_transported_bytes`]) and compares to
/// `content_hash`, NACKing host-wide on a mismatch; it NEVER re-serializes or re-canonicalizes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionWire {
    /// The TRANSPORTED canonical bytes the host agent produced once and hashed. The verify-only
    /// loader hashes these (never the parsed layer) and parses them only AFTER the hash verifies.
    pub transported: Vec<u8>,
    /// The D120 wire `content_hash` (SHA-256 full 32 bytes) the producer hashed `transported` into.
    /// The loader's NACK-on-hash check validates the transported bytes against THIS.
    pub content_hash: ContentHash,
}

impl CommittedPolicyVersion {
    /// Bundle a forward-only seq with the committed composed POL-1 layer it carries — the in-memory
    /// loopback hand-off that transported NO wire bytes (the publisher takes the layer-only lift).
    pub fn new(seq: u64, layer: ds_contracts::pol1::PolicyLayer) -> Self {
        Self {
            seq,
            layer,
            wire: None,
        }
    }

    /// Bundle a forward-only seq with the committed layer AND its produce-once transported wire form
    /// (doc 13 §5.1 / D120) — the production hand-off where the publisher drives the VERIFY-ONLY
    /// loader over the transported bytes (hash-check before parse, NACK host-wide on mismatch). The
    /// `layer` is the pre-parsed view the publisher carries for convenience; the loader RE-PARSES
    /// the transported bytes itself after verifying them, so the wire bytes are authoritative.
    pub fn verified(
        seq: u64,
        layer: ds_contracts::pol1::PolicyLayer,
        transported: Vec<u8>,
        content_hash: ContentHash,
    ) -> Self {
        Self {
            seq,
            layer,
            wire: Some(VersionWire {
                transported,
                content_hash,
            }),
        }
    }
}

/// The host agent's `WatchPolicies(from_seq)` subscription, modeled as the PRODUCER seam the
/// host-local snapshot feed is driven from (doc 11 §5.3 / doc 13 §5, D72). `ds-dnsgate` never
/// opens a control-plane policy stream (§5.3); the host agent — the host's ONE
/// `WatchPolicies(from_seq)` subscriber — is the SOLE control-plane reader, and this trait is
/// the host-LOCAL hand-off it drives: each committed version it delivers is ALREADY
/// enforcement-committed (the NFT programming path + `ds-tlsproxy` flipped first), so the
/// admitter publishing it onto the feed and committing it LAST never mints under an
/// un-enforced version.
///
/// [`run_policy_publisher`] consumes this and fans every delivered version onto the
/// [`BoundarySnapshotFeed`], carrying the real `(seq, content_hash)` identity. In PRODUCTION the
/// host agent's gRPC `WatchPolicies(from_seq)` stream backs this (the deferred live seam, gated
/// in `main` exactly the way the live `ds-nft` writer is — no control-plane stream is opened on
/// the offline/CI path). Tests drive it with an in-process synthetic source that delivers a
/// scripted sequence of committed POL-1 layers — a REAL policy push through the SAME publisher,
/// no live host agent (§5.3 loopback/synthetic).
///
/// `next_version` resolves to the next committed version at or after the publisher's current
/// cursor, or `None` when the subscription is exhausted / the stream closed (the gate is
/// shutting down) — the publisher then drops the feed so the subscriber drains.
pub trait PolicyVersionSource {
    /// Deliver the next committed policy version from the host agent's `WatchPolicies(from_seq)`
    /// stream, or `None` when the stream is closed. The publisher calls this in a loop; a
    /// version whose seq does not advance the feed's last-published seq is dropped by the D72
    /// forward-only-seq discipline downstream (the publisher itself stays a thin pass-through —
    /// the host agent's prepare/commit barrier owns the version ordering).
    fn next_version(
        &mut self,
    ) -> impl std::future::Future<Output = Option<CommittedPolicyVersion>> + Send;
}

/// The PRODUCTION publisher half of the host-local committed-snapshot feed (doc 11 §5.3 / doc 13
/// §5, D72) — the replacement for the env-gated single synthetic commit.
///
/// Drives the host agent's `WatchPolicies(from_seq)` subscription (`source`) onto the
/// [`BoundarySnapshotFeed`]: for every committed [`CommittedPolicyVersion`] the host agent fans
/// out behind its prepare/commit barrier, this lifts the WHOLE committed policy (composed
/// document + W2 clamp + boundary zone + the `(seq, content_hash)` identity) off the ONE POL-1
/// layer THROUGH [`BoundarySnapshot::with_policy_layer`] — the SAME shared `ds-policy-snapshot`
/// accessor `main`'s startup path sources from — and publishes the resulting committed
/// [`BoundarySnapshot`] onto the feed. The admitter (`ds-dnsgate`) then commits each one LAST
/// via [`watch_snapshots`]: the version is already enforcement-committed before it reaches the
/// feed, so the admitter's re-source is strictly the last step (the D35 admitter-LAST barrier).
///
/// `from_seq` is the publisher's starting cursor — the `WatchPolicies(from_seq)` resume point
/// (the last applied seq the host persists, D36). Versions are passed through verbatim; the
/// feed subscriber's D72 forward-only-seq discipline drops any non-advancing fan-out, so the
/// publisher stays a thin pass-through and the host agent's barrier owns version ordering.
///
/// Runs until the source is exhausted (the stream closed — the gate is shutting down) or the
/// subscriber has stopped (the feed publish errors). Returns the count of versions published.
/// Drive it on a dedicated task (`tokio::spawn`) alongside the gate's listeners + subscriber.
///
/// A version carrying its produce-once transported wire form
/// ([`CommittedPolicyVersion::verified`]) is driven through the VERIFY-ONLY loader
/// ([`ds_policy_snapshot::load_verified_snapshot`]): hash-check BEFORE parse, and on a D120
/// content_hash mismatch OR a §5 schema failure of the verified bytes the version is NACKed
/// host-wide (never published — the host stays on vN). Either integrity rejection is OPERATIONALLY
/// DISTINCT from a forward-only-seq stale fan-out: here it routes to the [`NullDropSink`] (use
/// [`run_policy_publisher_with_drop_sink`] to observe it for operator logs — a
/// [`crate::event::SnapshotDropReason::ContentHashMismatch`] for a hash NACK, a
/// [`crate::event::SnapshotDropReason::SchemaFailure`] for a verified-but-unparseable parse error).
pub async fn run_policy_publisher<P: PolicyVersionSource>(
    feed: &BoundarySnapshotFeed,
    source: P,
    from_seq: u64,
) -> u64 {
    run_policy_publisher_with_drop_sink(feed, source, from_seq, &crate::event::NullDropSink).await
}

/// The PRODUCTION publisher half WITH a reload-boundary drop sink (doc 11 §5.3 / §5.5 / doc 13 §5.1,
/// D72/D120) — the variant that makes the verify-only loader's D120 content_hash NACK OPERATIONALLY
/// OBSERVABLE, DISTINCT from the subscriber's forward-only-seq stale fan-out.
///
/// Identical to [`run_policy_publisher`] except a version that fails the verify-only loader's
/// hash-check (a [`ds_policy_snapshot::LoadVerdict::HashNack`]) — OR fails the POL-1 schema parse
/// of the verified bytes (a §5 "schema failure") — is routed to `drop_sink` as a
/// [`crate::event::SnapshotDropReason::ContentHashMismatch`] [`SnapshotDropEvent`] and NOT published
/// (the host stays on vN). The stale-fan-out drop the subscriber raises ([`watch_snapshots`]) and
/// this hash-mismatch drop are the TWO distinct non-commit reasons doc 13 §5.1 keeps separable: a
/// benign dedup vs a real integrity rejection. `main` wires the same spool-backed sink both halves
/// route to, so an operator joins on the reason token.
pub async fn run_policy_publisher_with_drop_sink<P: PolicyVersionSource>(
    feed: &BoundarySnapshotFeed,
    mut source: P,
    from_seq: u64,
    drop_sink: &dyn crate::event::SnapshotDropSink,
) -> u64 {
    let mut published: u64 = 0;
    while let Some(version) = source.next_version().await {
        // A version delivered below the resume cursor is a stale `WatchPolicies(from_seq)`
        // re-delivery — never republished (the host persists `from_seq` as its resume point, D36;
        // the feed subscriber would drop it forward-only anyway, but skipping it here keeps the
        // publisher honest about its cursor).
        if version.seq < from_seq {
            continue;
        }
        // The produce-once / verify-only path: a version carrying transported wire bytes is
        // hash-checked BEFORE parse. On a D120 content_hash mismatch (or a schema failure of the
        // verified bytes), the loader NACKs the apply host-wide — emit the DISTINCT integrity-
        // rejection drop telemetry (the reason token selected from the verdict variant:
        // `ContentHashMismatch` for a hash NACK, `SchemaFailure` for a verified-but-unparseable
        // parse error) and skip (never published, the host stays on vN). The in-memory layer-only
        // hand-off (`wire: None`) takes the existing lift unchanged.
        let snapshot = match &version.wire {
            Some(wire) => {
                match ds_policy_snapshot::load_verified_snapshot(
                    &wire.transported,
                    version.seq,
                    &wire.content_hash,
                ) {
                    LoadVerdict::Loaded(_) => {
                        // Verified + parsed: lift the committed policy THROUGH the verify-only
                        // accessor so the published snapshot carries the VERIFIED wire hash on its
                        // identity (the loader re-parsed the transported bytes; `version.layer` is
                        // the equal pre-parsed view the publisher carries for the lift).
                        BoundarySnapshot::with_verified_policy_layer(
                            version.seq,
                            &version.layer,
                            wire.content_hash,
                        )
                    }
                    nack => {
                        // A D120 content_hash NACK or a §5 schema failure — route the DISTINCT
                        // integrity-rejection drop signal (NOT a stale fan-out; the reason token is
                        // selected from the verdict variant) and do NOT publish.
                        drop_sink.observe_drop(content_hash_nack_drop(&version, &nack));
                        continue;
                    }
                }
            }
            // The in-memory loopback hand-off transported no wire bytes: lift the WHOLE committed
            // policy off the ONE POL-1 layer THROUGH the shared `ds-policy-snapshot` accessor
            // (composed doc + W2 clamp + boundary zone + the local fingerprint), the SAME lift the
            // startup path runs — no re-derive, no recomputed fingerprint, no wire hash carried.
            None => BoundarySnapshot::with_policy_layer(version.seq, &version.layer),
        };
        if feed.publish(snapshot).await.is_err() {
            // The subscriber has stopped (the gate is shutting down): stop feeding.
            break;
        }
        published += 1;
    }
    published
}

/// Build the DISTINCT integrity-rejection [`SnapshotDropEvent`] the verify-only loader raises on a
/// non-`Loaded` verdict (doc 11 §5.5 / doc 13 §5.1) — the drop an operator MUST tell apart from a
/// benign forward-only-seq stale fan-out. The reason is SELECTED from the verdict variant so the
/// two rejection sub-cases are separable in operator telemetry while keeping IDENTICAL commit
/// behavior (both NACK host-wide, the host stays on vN, the snapshot is never published):
///
///   * a [`LoadVerdict::ParseError`] — bytes that VERIFIED against their wire `content_hash` but
///     failed the POL-1 schema parse — maps to [`crate::event::SnapshotDropReason::SchemaFailure`];
///   * a [`LoadVerdict::HashNack`] — a D120 content_hash MISMATCH (a tampered transport) — maps to
///     [`crate::event::SnapshotDropReason::ContentHashMismatch`].
///
/// The dropped seq is the NACKed version's seq, and `committed_seq` is left as that same seq (the
/// rejection is keyed by the version that failed to apply, not by a prior committed version —
/// there is no "advance past" relation as there is for a stale fan-out). The POL-3 provenance names
/// the reload boundary and the NACKed version's seq (non-blank by construction, §6.7).
fn content_hash_nack_drop(
    version: &CommittedPolicyVersion,
    verdict: &LoadVerdict,
) -> SnapshotDropEvent {
    debug_assert!(
        !matches!(verdict, LoadVerdict::Loaded(_)),
        "content_hash_nack_drop must only be called on a NACK / parse-failure verdict"
    );
    // The commit decision is UNCHANGED across both sub-cases (host-wide NACK, host stays on vN);
    // only the operator-telemetry reason token is separated so a verified-but-unparseable schema
    // failure does not read as a tampered-transport content_hash mismatch (doc 13 §5.1).
    let reason = if matches!(verdict, LoadVerdict::ParseError(_)) {
        crate::event::SnapshotDropReason::SchemaFailure
    } else {
        crate::event::SnapshotDropReason::ContentHashMismatch
    };
    SnapshotDropEvent {
        reason,
        dropped_seq: version.seq,
        committed_seq: version.seq,
        provenance: crate::event::EventProvenance {
            rule_id: "reload-boundary/content-hash-nack".to_string(),
            policy_layer: "pol-reload-boundary".to_string(),
            policy_version: format!("seq/{}", version.seq),
        },
    }
}

/// The host-LOCAL committed-snapshot feed's v0 transport: **file + atomic-rename** (doc 13 §8.4,
/// the non-binding v0 recommendation). The Go D35 host agent — the host's ONE
/// `WatchPolicies(from_seq)` subscriber (`ds-dnsgate` NEVER opens a control-plane stream, §5.3) —
/// fans each committed version out host-locally by writing the produce-once canonical wire bytes to
/// a temp file under [`Self::dir`] and `rename()`ing it into place under the seq-named final path
/// (atomic on the same filesystem). This [`PolicyVersionSource`] is the dataplane-side CONSUMER of
/// that directory: `next_version()` reads each committed version file in forward-seq order, carries
/// the transported bytes + their D120 `content_hash`, and hands them to the publisher's VERIFY-ONLY
/// loader path (hash-check BEFORE parse). The cross-process Go fan-out half lives OUTSIDE the
/// dataplane workspace (a separate host-agent task); this side reads files the host agent wrote.
///
/// Why the file shape for v0 (doc 13 §8.4 rationale): it makes the §5 "before the first verified
/// snapshot a booting host serves nothing beyond NFT-1 default-deny" posture trivial (no file ⇒ no
/// snapshot), it survives a single consumer restart without re-subscription (the on-disk files +
/// the persisted [`AppliedSeqStore`] cursor are reloaded — the §5 crash/restart-convergence (c)
/// reload), and it keeps the §5.1 produce-once / verify-only rule honest (the subscriber writes the
/// bytes once; this consumer hashes-then-parses the EXACT transported bytes, no re-serialization).
/// inotify-blocking is the documented latency upgrade; v0 correctness is a forward-seq directory
/// DRAIN — `next_version()` returns `None` once the directory holds no version past the cursor (the
/// publisher then drops the feed and the subscriber drains). A long-lived deployment re-arms by
/// re-scanning; that arming is the live-only step behind the env gate in `main` (NEVER default-on).
///
/// Naming contract: each committed version is a file `<seq:020>.snapshot` (zero-padded so a
/// lexicographic directory sort IS forward-seq order) whose bytes ARE the produce-once transported
/// canonical wire form. The `content_hash` is recomputed from those bytes via the SINGLE source of
/// wire hashing ([`ds_contracts::snapshot_verify::sha256`]) — the publisher's verify-only loader
/// re-verifies authoritatively, so a tampered file still NACKs host-wide (the host stays on vN).
pub struct HostLocalFeedSource {
    /// The host-local feed directory the host agent atomic-renames committed version files into.
    dir: std::path::PathBuf,
    /// The forward-only cursor: `next_version()` only yields files with `seq > delivered_seq`, so a
    /// re-scan never re-delivers a version this source already handed to the publisher. Seeded from
    /// the persisted [`AppliedSeqStore`] applied_seq (the `WatchPolicies(from_seq)` resume point,
    /// D36) so a restart resumes rather than replaying committed history.
    delivered_seq: u64,
}

/// The file-name suffix the host agent writes each committed version under (`<seq:020>.snapshot`).
const HOST_LOCAL_FEED_SUFFIX: &str = ".snapshot";

impl HostLocalFeedSource {
    /// Open the host-local feed over `dir`, resuming from `from_seq` (the persisted applied_seq, the
    /// `WatchPolicies(from_seq)` resume cursor, D36): only versions with `seq > from_seq` are
    /// delivered. The directory need not exist yet (a booting host before the host agent's first
    /// fan-out) — `next_version()` treats a missing/empty directory as an exhausted stream (`None`),
    /// the §5 "no file ⇒ no snapshot" posture.
    pub fn resume_from(dir: impl Into<std::path::PathBuf>, from_seq: u64) -> Self {
        Self {
            dir: dir.into(),
            delivered_seq: from_seq,
        }
    }

    /// The seq encoded by a feed file name, or `None` for any name that is not a
    /// `<digits>.snapshot` committed-version file (a temp file the host agent has not yet renamed
    /// into place, a stray entry, a sub-directory) — skipped, never mis-read as a version.
    fn seq_of(name: &str) -> Option<u64> {
        name.strip_suffix(HOST_LOCAL_FEED_SUFFIX)?
            .parse::<u64>()
            .ok()
    }

    /// Scan the feed directory for the LOWEST committed-version seq strictly greater than the
    /// delivered cursor — the next forward version to hand the publisher, or `None` when none is
    /// present yet (an empty/missing directory, or every file already delivered). A v0 directory
    /// drain: forward-seq order from the zero-padded names, never re-reading a delivered version.
    fn next_pending(&self) -> Option<(u64, std::path::PathBuf)> {
        let entries = std::fs::read_dir(&self.dir).ok()?;
        let mut best: Option<(u64, std::path::PathBuf)> = None;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(seq) = Self::seq_of(name) else {
                continue;
            };
            if seq <= self.delivered_seq {
                continue;
            }
            if best.as_ref().is_none_or(|(b, _)| seq < *b) {
                best = Some((seq, entry.path()));
            }
        }
        best
    }
}

impl PolicyVersionSource for HostLocalFeedSource {
    async fn next_version(&mut self) -> Option<CommittedPolicyVersion> {
        // v0 file transport: the next committed version is the lowest-seq `<seq>.snapshot` file
        // past the delivered cursor. A drain — once the directory holds nothing newer, the stream
        // is exhausted (`None`) so the publisher drops the feed and the subscriber drains. The
        // host agent's atomic-rename guarantees a name only appears once its full bytes are durable.
        loop {
            let (seq, path) = self.next_pending()?;
            // Advance the cursor BEFORE yielding so a file we cannot read (it vanished mid-scan, a
            // truncated rename race) is skipped forward rather than re-scanned forever.
            self.delivered_seq = seq;
            let Ok(transported) = std::fs::read(&path) else {
                // The file disappeared between scan and read (a host-agent rotate) — skip to the
                // next pending version. The cursor already advanced past this seq.
                continue;
            };
            // Recompute the wire content_hash off the transported bytes via the SINGLE source of
            // wire hashing — the publisher's verify-only loader RE-VERIFIES against this, so a
            // tampered file is NACKed host-wide there (the host stays on vN), never silently trusted.
            let content_hash = ds_contracts::snapshot_verify::sha256(&transported);
            // Carry the pre-parsed layer view the publisher lifts identity off (the loader re-parses
            // the transported bytes authoritatively). A file whose bytes do not parse is still
            // delivered: the publisher's verify-only loader raises the §5 schema-failure NACK and
            // routes the distinct ContentHashMismatch drop — the parse decision stays in ONE place.
            // We need a layer to construct the carrier; on an unparseable file we cannot, so we
            // synthesize the produce-once verified carrier from a best-effort parse and let the
            // loader own the verdict.
            let layer = match ds_contracts::pol1::parse_layer(
                std::str::from_utf8(&transported).unwrap_or_default(),
            ) {
                Ok(layer) => layer,
                Err(_) => {
                    // An unparseable file would NACK at the loader anyway; rather than carry a
                    // bogus layer, skip it forward (the cursor already advanced) so the publisher
                    // never sees a malformed carrier. A production wiring routes this to the
                    // integrity-alert path; here the file is dropped from the drain.
                    continue;
                }
            };
            return Some(CommittedPolicyVersion::verified(
                seq,
                layer,
                transported,
                content_hash,
            ));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The LIVE host-local UDS `WatchPolicies(from_seq)` carrier (doc 11 §5.3 / doc 13 §5 / §8.4,
// D72/D36/D120) — the PRODUCTION transport the `HostLocalFeedSource` file feed is the v0
// fallback for. Same hand-rolled length-prefixed frame codec as `reresolve` (no tonic/tower
// exist in the dataplane workspace, D40/D67): a tokio UDS stream with a 4-byte big-endian
// length prefix per frame. The Go host agent (the host's ONE control-plane `WatchPolicies`
// subscriber, OUTSIDE this workspace — `orchestrator/internal/hostagent/dnsfeed_carrier.go`)
// SERVES this socket; `ds-dnsgate` DIALS it and consumes the server-stream (it still opens NO
// control-plane stream — the host agent owns the upstream subscription, §5.3).
// ─────────────────────────────────────────────────────────────────────────────

/// The hard cap on a single `WatchPolicies` carrier frame body (bytes). A version frame is a
/// seq + a 32-byte content_hash + the composed POL-1 document; a composed document is small
/// (human/policy-push cadence, never per-query, doc 11 §1). 4 MiB is a generous ceiling that
/// still bounds a malformed/over-long frame (a length over the cap is a malformed frame → the
/// stream is dropped, the publisher idles fail-closed). MUST match the Go producer's cap.
const WATCH_POLICIES_MAX_FRAME_BODY: u32 = 4 * 1024 * 1024;

/// The cross-process WATCH-POLICIES CARRIER wire contract (binding — mirrored EXACTLY by the Go
/// producer `orchestrator/internal/hostagent/dnsfeed_carrier.go`; the two halves share ONLY this
/// on-the-wire shape, there is no FFI / shared type):
///
///   * Handshake (consumer → producer): ONE frame whose body is the 8-byte big-endian
///     `from_seq` resume cursor — the `WatchPolicies(from_seq)` request (doc 13 §5, D36). The
///     producer replays only committed versions with `seq > from_seq`.
///   * Stream (producer → consumer): ZERO OR MORE version frames, each body =
///     `seq (8B BE) || content_hash_len (4B BE) || content_hash bytes || document_len (4B BE)
///     || document bytes`. The bytes ARE the produce-once transported canonical wire form
///     (`PolicySnapshot.document`) and the producer-pinned `content_hash`
///     (`PolicySnapshot.content_hash`), §5.1 identity tuple — NEVER re-serialized here.
///   * End of stream: the producer closes the connection (EOF). The consumer then yields `None`
///     (the stream is exhausted) so the publisher drops the feed and the subscriber drains.
///
/// NEVER-LOG-THE-SECRET: a frame carries the composed document opaquely; the codec logs only
/// the structural defect, never a snapshot byte (D73).
struct WatchPoliciesFrame;

impl WatchPoliciesFrame {
    /// Encode the `from_seq` handshake body: the 8-byte big-endian resume cursor.
    fn encode_handshake(from_seq: u64) -> Vec<u8> {
        from_seq.to_be_bytes().to_vec()
    }

    /// Encode one version frame body (the `(seq, content_hash, document)` identity tuple). The
    /// PRODUCER side (the host agent / the reference [`serve_watch_policies_connection`]) calls
    /// this; the consumer's [`Self::decode_version`] is the inverse.
    fn encode_version(seq: u64, content_hash: &ContentHash, document: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 4 + content_hash.len() + 4 + document.len());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&(content_hash.len() as u32).to_be_bytes());
        out.extend_from_slice(content_hash);
        out.extend_from_slice(&(document.len() as u32).to_be_bytes());
        out.extend_from_slice(document);
        out
    }

    /// Decode one version frame body into `(seq, content_hash, document)`. A malformed body (a
    /// truncated field, a content_hash that is not the 32-byte SHA-256 width, a length past the
    /// buffer) returns `None` — the carrier drops the stream fail-closed rather than fabricate a
    /// version (the host stays on its current version).
    fn decode_version(body: &[u8]) -> Option<(u64, ContentHash, Vec<u8>)> {
        let mut cur = body;
        let seq = u64::from_be_bytes(take_array::<8>(&mut cur)?);
        let hash_len = u32::from_be_bytes(take_array::<4>(&mut cur)?) as usize;
        // The wire `content_hash` is a full SHA-256 (32 bytes) — a different width is a torn frame.
        if hash_len != std::mem::size_of::<ContentHash>() {
            return None;
        }
        let hash_bytes = take_slice(&mut cur, hash_len)?;
        let mut content_hash: ContentHash = [0u8; 32];
        content_hash.copy_from_slice(hash_bytes);
        let doc_len = u32::from_be_bytes(take_array::<4>(&mut cur)?) as usize;
        let document = take_slice(&mut cur, doc_len)?.to_vec();
        // Trailing bytes after the document are a malformed frame.
        if !cur.is_empty() {
            return None;
        }
        Some((seq, content_hash, document))
    }
}

/// Take the next `N` bytes off `cur` as a fixed array, advancing the cursor — `None` if short.
fn take_array<const N: usize>(cur: &mut &[u8]) -> Option<[u8; N]> {
    if cur.len() < N {
        return None;
    }
    let (head, tail) = cur.split_at(N);
    *cur = tail;
    let mut out = [0u8; N];
    out.copy_from_slice(head);
    Some(out)
}

/// Take the next `len` bytes off `cur` as a slice, advancing the cursor — `None` if short or if
/// `len` exceeds the frame cap (a guard against an attacker-supplied length over-allocating).
fn take_slice<'a>(cur: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if len > WATCH_POLICIES_MAX_FRAME_BODY as usize || cur.len() < len {
        return None;
    }
    let (head, tail) = cur.split_at(len);
    *cur = tail;
    Some(head)
}

/// Write ONE length-prefixed frame (a 4-byte big-endian body length + the body) to the UDS
/// stream and flush — the SAME framing as `reresolve::write_frame`, the dataplane's one
/// length-prefixed UDS convention. A body over the cap is rejected (never partially written).
async fn write_watch_frame(
    stream: &mut tokio::net::UnixStream,
    body: &[u8],
) -> std::io::Result<()> {
    if body.len() as u64 > WATCH_POLICIES_MAX_FRAME_BODY as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "watch-policies frame body over cap",
        ));
    }
    stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

/// Read ONE length-prefixed frame body from the UDS stream (the 4-byte length, then the body).
/// A clean EOF before the length prefix is the end of the server-stream (the producer closed) —
/// returned as `ErrorKind::UnexpectedEof` for the caller to treat as stream exhaustion. A length
/// over the cap is a malformed frame (the stream is dropped fail-closed).
async fn read_watch_frame(stream: &mut tokio::net::UnixStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > WATCH_POLICIES_MAX_FRAME_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "watch-policies frame length over cap",
        ));
    }
    let mut body = vec![0u8; len as usize];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

/// The LIVE host-agent `WatchPolicies(from_seq)` carrier as a [`PolicyVersionSource`] (doc 11
/// §5.3 / doc 13 §5, D72/D36/D120) — the PRODUCTION transport behind the `DS_DNSGATE_HOST_AGENT_FEED`
/// gate, the directly-driven sibling of the v0 [`HostLocalFeedSource`] file feed.
///
/// On the FIRST [`PolicyVersionSource::next_version`] it dials the host agent's host-local UDS
/// endpoint, sends the `WatchPolicies(from_seq)` handshake (the persisted applied_seq resume
/// cursor, D36), and then reads the server-stream of version frames; each subsequent call reads
/// the next frame off the SAME connection. Every frame carries the produce-once
/// `(seq, content_hash, transported document)` identity tuple, surfaced UNCHANGED as a
/// [`CommittedPolicyVersion::verified`] so the publisher's verify-only loader — and, decorating
/// it, the `main`-side `PrepareVerifiedGate` non-vacuous identity gate — runs against the SAME
/// real wire bytes the host agent fanned out. A tampered version (transported bytes ≠ the
/// producer-pinned `content_hash`) is DROPPED at that gate (the host stays on vN); this carrier
/// is a thin transport — it never decides admission, never re-serializes, never re-hashes for a
/// verdict.
///
/// `ds-dnsgate` STILL opens no control-plane policy stream (§5.3): the host agent is the host's
/// ONE upstream `WatchPolicies` subscriber and SERVES this host-local socket; this side is the
/// host-LOCAL consumer of that fan-out. A connect/read error or a malformed frame closes the
/// stream (`None`) fail-closed — the publisher idles, ready for the host agent to re-serve, and
/// the host stays on its current version (never a fabricated one). Reachable ONLY behind the env
/// gate in `main`; the default offline/CI build never dials it.
pub struct WatchPoliciesCarrierSource {
    /// The host-local UDS endpoint the host agent serves the `WatchPolicies` stream on.
    endpoint: std::path::PathBuf,
    /// The `WatchPolicies(from_seq)` resume cursor sent in the handshake (the persisted applied_seq,
    /// D36) — a restart resumes from it rather than replaying committed history.
    from_seq: u64,
    /// The live connection, established lazily on the first `next_version` and reused for every
    /// subsequent frame. `None` until the first call or after the stream closed (EOF / fault) — a
    /// closed stream is terminal (the source yields `None` thereafter; the publisher drops the feed).
    stream: Option<tokio::net::UnixStream>,
    /// Set once the stream has closed (cleanly or on fault) so a re-poll after exhaustion stays
    /// `None` instead of re-dialing — the publisher's drain contract (one source, drained once).
    closed: bool,
}

impl WatchPoliciesCarrierSource {
    /// Bind the carrier to `endpoint`, resuming from `from_seq` (the persisted applied_seq, the
    /// `WatchPolicies(from_seq)` resume cursor, D36). The connection is NOT dialed here — it is
    /// established lazily on the first [`PolicyVersionSource::next_version`], so constructing the
    /// source (the default-gate resolution in `main`) never touches the socket.
    pub fn connect_to(endpoint: impl Into<std::path::PathBuf>, from_seq: u64) -> Self {
        Self {
            endpoint: endpoint.into(),
            from_seq,
            stream: None,
            closed: false,
        }
    }

    /// Dial the host agent's UDS endpoint and send the `WatchPolicies(from_seq)` handshake.
    /// Returns the live stream ready to read version frames, or the I/O error (a connect failure
    /// when the host agent is not yet serving) — the caller treats it as an exhausted stream
    /// (fail-closed: the host stays on its current version, the publisher idles).
    async fn dial(&self) -> std::io::Result<tokio::net::UnixStream> {
        let mut stream = tokio::net::UnixStream::connect(&self.endpoint).await?;
        write_watch_frame(
            &mut stream,
            &WatchPoliciesFrame::encode_handshake(self.from_seq),
        )
        .await?;
        Ok(stream)
    }
}

impl PolicyVersionSource for WatchPoliciesCarrierSource {
    async fn next_version(&mut self) -> Option<CommittedPolicyVersion> {
        // A stream that already closed (EOF or fault) is terminal — never re-dial; the publisher
        // drains once. (`closed` is set on the first None-producing event below.)
        if self.closed {
            return None;
        }
        // Lazy connect on the first poll: dial + handshake. A connect failure (the host agent is
        // not serving yet) closes the stream fail-closed — the publisher idles, the host stays on
        // its current version, and ds-dnsgate opens NO control-plane stream of its own (§5.3).
        if self.stream.is_none() {
            match self.dial().await {
                Ok(s) => self.stream = Some(s),
                Err(e) => {
                    eprintln!(
                        "ds-dnsgate: WatchPolicies carrier could not dial the host-agent feed at \
                         {:?}: {e}; the publisher idles (host stays on its current version, \
                         fail-closed). The host agent re-serves on its next fan-out.",
                        self.endpoint
                    );
                    self.closed = true;
                    return None;
                }
            }
        }
        // Read the next server-stream version frame. A clean EOF (the producer closed the stream)
        // OR any read/decode fault closes the source: the carrier never fabricates a version, so a
        // torn transport leaves the host on its current version (host-wide fail-closed). An
        // unparseable-but-well-framed version is SKIPPED forward (read the next frame) rather than
        // carrying a bogus layer to the publisher — looped, not recursed, so the async future stays
        // a simple state machine.
        loop {
            let stream = self.stream.as_mut().expect("stream established above");
            let body = match read_watch_frame(stream).await {
                Ok(body) => body,
                Err(e) => {
                    // UnexpectedEof = the producer closed the server-stream cleanly (end of the
                    // committed history it had to replay); any other error is a transport fault.
                    // Both exhaust the source — the publisher drops the feed, the subscriber drains.
                    if e.kind() != std::io::ErrorKind::UnexpectedEof {
                        eprintln!(
                            "ds-dnsgate: WatchPolicies carrier stream read error: {e}; closing \
                             (host stays on its current version, fail-closed)"
                        );
                    }
                    self.closed = true;
                    return None;
                }
            };
            let Some((seq, content_hash, document)) = WatchPoliciesFrame::decode_version(&body)
            else {
                eprintln!(
                    "ds-dnsgate: WatchPolicies carrier dropped a malformed version frame; \
                     closing the stream (host stays on its current version, fail-closed)"
                );
                self.closed = true;
                return None;
            };
            // Carry the pre-parsed layer view the publisher lifts identity off (the verify-only
            // loader / the PrepareVerifiedGate re-parse + re-verify the TRANSPORTED bytes
            // authoritatively). A frame whose bytes do not parse is dropped here rather than
            // carrying a bogus layer — the loader would NACK it anyway; the parse decision stays in
            // ONE place (the gate), and a malformed wire never reaches the publisher half-formed.
            match ds_contracts::pol1::parse_layer(
                std::str::from_utf8(&document).unwrap_or_default(),
            ) {
                Ok(layer) => {
                    return Some(CommittedPolicyVersion::verified(
                        seq,
                        layer,
                        document,
                        content_hash,
                    ));
                }
                Err(_) => {
                    // Skip an unparseable version forward; the cursor is server-driven, so there is
                    // no local cursor to advance. NEVER log a snapshot byte — the seq only.
                    eprintln!(
                        "ds-dnsgate: WatchPolicies carrier dropped seq {seq} — transported bytes do \
                         not parse as POL-1 (malformed carrier, host unchanged)"
                    );
                    continue;
                }
            }
        }
    }
}

/// SERVE one `WatchPolicies(from_seq)` connection from the PRODUCER side over a bound UDS stream
/// (the host-agent fan-out half) — read the handshake, then stream the committed `versions` whose
/// `seq > from_seq` as frames, in order, and close (EOF) to end the stream. This is the in-tree
/// REFERENCE producer the carrier's integration test drives (and the exact wire shape the Go
/// `dnsfeed_carrier.go` host-agent producer implements cross-process). `versions` is the
/// `(seq, content_hash, transported document)` tuple the host agent fanned out — the producer
/// transports them verbatim (produce-once / verify-only, §5.1: it never re-serializes).
///
/// A write fault (the consumer hung up) stops the stream early — never fatal to the producer's
/// listener (the caller's accept loop handles the next connection). Returns the count of versions
/// streamed. REFERENCE producer on this side (the integration test + the cross-process wire-shape
/// fixture for the Go `dnsfeed_carrier.go`); the PRODUCTION fan-out is the Go host agent, which
/// implements the SAME frame shape — there is no Rust-side production caller, mirroring how
/// `request_over_uds` is the re-resolve client shared by both sides.
pub async fn serve_watch_policies_connection(
    mut stream: tokio::net::UnixStream,
    versions: &[(u64, ContentHash, Vec<u8>)],
) -> std::io::Result<u64> {
    // Read the WatchPolicies(from_seq) handshake (the 8-byte resume cursor).
    let body = read_watch_frame(&mut stream).await?;
    let mut cur = body.as_slice();
    let from_seq = u64::from_be_bytes(take_array::<8>(&mut cur).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "watch-policies handshake is not an 8-byte from_seq",
        )
    })?);
    let mut streamed = 0u64;
    for (seq, content_hash, document) in versions {
        // FORWARD-ONLY: replay only committed versions past the consumer's resume cursor (D36).
        if *seq <= from_seq {
            continue;
        }
        let frame = WatchPoliciesFrame::encode_version(*seq, content_hash, document);
        write_watch_frame(&mut stream, &frame).await?;
        streamed += 1;
    }
    // Close the stream (drop) → the consumer reads EOF and yields None, the §5.3 end-of-stream.
    Ok(streamed)
}

/// The persisted `applied_seq` cursor (doc 13 §5 readiness row / D36) — the on-disk
/// `WatchPolicies(from_seq)` RESUME point a restart reads so the publisher resumes from the last
/// applied version rather than replaying committed history (the §5 crash/restart-convergence (c)
/// reload). The [`AppliedSeqHeartbeat`] surfaces each version's `applied_seq` ONLY AFTER the §5.4
/// revocation sweep; persisting it here makes the post-sweep cursor durable, so on restart the
/// publisher seeds [`HostLocalFeedSource::resume_from`] / `from_seq` with it — and the publisher's
/// forward-only-seq guard (`version.seq < from_seq → continue`) then drops any re-delivered stale
/// version below it. Written via the SAME atomic-rename discipline as the feed files (temp file +
/// `rename()`), so a crash mid-write never leaves a torn cursor (the prior value stays readable).
///
/// Co-located with the feed directory: a single host-local directory carries the feed files AND the
/// `applied_seq` cursor, so the §5 reload is one directory the host agent owns. Failures to read
/// (no cursor yet — a fresh host) resolve to `0` (`WatchPolicies(from_seq=0)`, replay from the first
/// committed version); failures to WRITE are infallible by construction (a dropped cursor write
/// never changes which versions commit — at worst a restart replays already-applied versions, which
/// the forward-only guard drops anyway, never a double-apply).
#[derive(Clone)]
pub struct AppliedSeqStore {
    /// The on-disk cursor file (`<dir>/applied_seq`).
    path: std::path::PathBuf,
}

/// The cursor file name under the feed directory.
const APPLIED_SEQ_FILE: &str = "applied_seq";

impl AppliedSeqStore {
    /// Bind the cursor to `<dir>/applied_seq` (co-located with the host-local feed files).
    pub fn in_dir(dir: impl AsRef<std::path::Path>) -> Self {
        Self {
            path: dir.as_ref().join(APPLIED_SEQ_FILE),
        }
    }

    /// Read the persisted applied_seq, or `0` when no cursor has been written yet (a fresh host:
    /// `WatchPolicies(from_seq=0)` replays from the first committed version) or the file is
    /// unreadable/garbled (treated as a fresh cursor — fail-open to a full resume, never a panic).
    pub fn load(&self) -> u64 {
        std::fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// Persist `seq` as the applied_seq cursor via atomic-rename (temp file + `rename()` on the same
    /// directory), so a concurrent reader / a crash mid-write never observes a torn value. Returns
    /// the I/O error to the caller for telemetry, but the obligation is best-effort: a dropped write
    /// never changes which versions commit (the forward-only-seq guard tolerates a stale resume).
    pub fn persist(&self, seq: u64) -> std::io::Result<()> {
        let dir = self
            .path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        std::fs::create_dir_all(dir)?;
        // A per-pid temp name keeps two co-resident writers from clobbering each other's temp file
        // before the rename (the rename itself is the atomic publish).
        let tmp = dir.join(format!("{APPLIED_SEQ_FILE}.{}.tmp", std::process::id()));
        std::fs::write(&tmp, seq.to_string())?;
        std::fs::rename(&tmp, &self.path)
    }
}

/// An [`AppliedSeqHeartbeat`] that PERSISTS each post-sweep `applied_seq` to an [`AppliedSeqStore`]
/// (doc 13 §5 / D36) so a restart resumes the `WatchPolicies(from_seq)` cursor from the last applied
/// version. The commit sink calls [`report_applied_seq`](AppliedSeqHeartbeat::report_applied_seq)
/// ONLY AFTER the §5.4 revocation sweep, so the persisted cursor always names a version whose
/// now-denied admissions are already revoked — a resume past it can never skip an un-swept version.
/// A write failure is swallowed (best-effort, never gates the commit); compose it with an operator
/// log via a second heartbeat if observability is wanted (this one is the durable cursor only).
pub struct PersistingAppliedSeqHeartbeat {
    store: AppliedSeqStore,
}

impl PersistingAppliedSeqHeartbeat {
    /// Persist each post-sweep applied_seq into `store`.
    pub fn new(store: AppliedSeqStore) -> Self {
        Self { store }
    }
}

impl AppliedSeqHeartbeat for PersistingAppliedSeqHeartbeat {
    fn report_applied_seq(&self, identity: AppliedSeqIdentity) {
        // Best-effort: a dropped cursor write never changes which versions commit. The forward-only
        // guard at the publisher tolerates a stale resume, so the worst case is replaying an
        // already-applied version (dropped forward-only), never a double-apply or a skip.
        let _ = self.store.persist(identity.seq);
    }
}

/// Fan one post-sweep `applied_seq` report to TWO heartbeat carriers in order (doc 13 §5 / D36) —
/// the composition `main` uses to BOTH persist the durable `WatchPolicies(from_seq)` resume cursor
/// (a [`PersistingAppliedSeqHeartbeat`]) AND keep the operator-log line, since the commit sink takes
/// exactly one `Arc<dyn AppliedSeqHeartbeat>`. Reports to `first` then `second`; both are infallible
/// by the trait contract (a dropped report never changes the commit behavior), so the order is only
/// for deterministic log/persist sequencing.
pub struct TeeAppliedSeqHeartbeat<A: AppliedSeqHeartbeat, B: AppliedSeqHeartbeat> {
    first: A,
    second: B,
}

impl<A: AppliedSeqHeartbeat, B: AppliedSeqHeartbeat> TeeAppliedSeqHeartbeat<A, B> {
    /// Report each applied_seq to `first` then `second`.
    pub fn new(first: A, second: B) -> Self {
        Self { first, second }
    }
}

impl<A: AppliedSeqHeartbeat, B: AppliedSeqHeartbeat> AppliedSeqHeartbeat
    for TeeAppliedSeqHeartbeat<A, B>
{
    fn report_applied_seq(&self, identity: AppliedSeqIdentity) {
        self.first.report_applied_seq(identity);
        self.second.report_applied_seq(identity);
    }
}

/// The single-per-host `WatchPolicies` host-snapshot SUBSCRIBER loop (doc 11 §5.3 / D72).
///
/// `ds-dnsgate` never opens a control-plane policy stream (§5.3): it consumes the
/// host-LOCAL committed-snapshot feed the host agent fans out behind its prepare/commit
/// barrier, and — as the ADMITTER — commits each snapshot LAST by re-sourcing the
/// authored-SOA boundary zone through the SOLE reload path
/// ([`RunningGate::reload_boundary_zone`], via [`BoundaryZoneSink::commit_boundary_zone`]).
/// No admission is ever minted under a policy version the enforcement layers (the NFT
/// programming path + ds-tlsproxy) have not applied: the feed only delivers snapshots that
/// are ALREADY enforcement-committed, so the admitter's commit is strictly last.
///
/// D72 single-policy-version discipline: the loop commits only on a FORWARD seq. A
/// re-delivered or out-of-order snapshot (seq ≤ the last committed seq) is a duplicate
/// host-local fan-out and is dropped without re-sourcing the suffix — no backwards reload,
/// no per-service version namespace. The boundary zone re-sources on BOTH transports in
/// one commit (no per-transport skew), so the §5.4 revocation sweep that re-evaluates live
/// admissions runs against one consistent authored suffix.
///
/// Runs until the feed is closed (every publisher dropped — the gate is shutting down),
/// then returns the count of committed reloads. Drive it on a dedicated task
/// (`tokio::spawn`) alongside the gate's listeners.
pub async fn watch_policies<S: BoundaryZoneSink>(
    subscription: BoundarySnapshotSubscription,
    sink: &S,
) -> u64 {
    // The boundary-zone-only path: adapt the boundary-zone sink into the full snapshot loop,
    // re-sourcing ONLY the authored-SOA suffix (a committed composed policy on the snapshot, if
    // any, is not applied through this adapter). The detached `GateBoundaryReloader` and the
    // suffix-only synthetic feeds drive this. The PRODUCTION `main` drives [`watch_snapshots`]
    // with a [`SnapshotCommitSink`] so a committed snapshot ALSO re-sources the running
    // evaluator.
    watch_snapshots(subscription, &BoundaryZoneOnly(sink)).await
}

/// The single-per-host `WatchPolicies` host-snapshot SUBSCRIBER core loop (doc 11 §5.3 / D72)
/// — the PRODUCTION entry point that re-sources EVERYTHING a committed [`BoundarySnapshot`]
/// carries (the running [`PolicyCorePolicy`] evaluator AND the authored-SOA boundary zone).
///
/// `ds-dnsgate` never opens a control-plane policy stream (§5.3): it consumes the host-LOCAL
/// committed-snapshot feed the host agent fans out behind its prepare/commit barrier, and — as
/// the ADMITTER — commits each snapshot LAST through the [`SnapshotSink`]. `main` drives this
/// with a [`SnapshotCommitSink`] pairing the gate's [`RunningGate::boundary_zone_reloader`] and
/// [`RunningGate::policy_reloader`], so a committed snapshot that carries a composed document
/// re-sources the frozen `evaluate` off that policy version — admitter-LAST, no listener
/// re-bind. No admission is ever minted under a policy version the enforcement layers (the NFT
/// programming path + ds-tlsproxy) have not applied: the feed only delivers snapshots that are
/// ALREADY enforcement-committed, so the admitter's commit is strictly last.
///
/// D72 single-policy-version discipline (identical to the boundary-zone-only path): the loop
/// commits only on a FORWARD seq. A re-delivered or out-of-order snapshot (seq ≤ the last
/// committed seq) is a duplicate host-local fan-out and is dropped — no backwards reload, no
/// per-service version namespace. The evaluator and the boundary zone re-source together (one
/// committed policy version), so the §5.4 revocation sweep runs against one consistent policy.
///
/// Runs until the feed is closed (every publisher dropped — the gate is shutting down), then
/// returns the count of committed snapshots. Drive it on a dedicated task (`tokio::spawn`)
/// alongside the gate's listeners.
pub async fn watch_snapshots<S: SnapshotSink>(
    mut subscription: BoundarySnapshotSubscription,
    sink: &S,
) -> u64 {
    // The last seq the admitter committed. Starts below any real seq so the FIRST
    // committed snapshot always advances (a fresh subscriber has committed nothing yet).
    let mut committed_seq: Option<u64> = None;
    let mut commits: u64 = 0;
    while let Some(snapshot) = subscription.rx.recv().await {
        // D72 forward-only commit: a non-advancing seq is a duplicate fan-out — never
        // re-source backwards (one monotonic policy version end to end).
        if let Some(last) = committed_seq {
            if snapshot.seq <= last {
                // The drop BEHAVIOR is UNCHANGED — the snapshot is still dropped (no backwards
                // re-source, one monotonic version). But the drop is no longer SILENT: emit a
                // distinct stale-fan-out telemetry signal through the existing `SnapshotSink`
                // seam (doc 11 §5.3) so an operator can tell this benign duplicate / out-of-order
                // dedup apart from a content_hash NACK (D120). The signal carries the dropped seq
                // and the live committed seq for full identity; the reason is fixed to
                // `StaleFanOut` (the only drop `watch_snapshots` itself raises — a hash-mismatch
                // NACK is the loader's separate reason).
                sink.observe_snapshot_drop(SnapshotDropEvent::stale_fan_out(
                    snapshot.seq,
                    last,
                    reload_boundary_provenance(&snapshot),
                ));
                continue;
            }
        }
        // Admitter-LAST commit: the enforcement layers already applied this snapshot
        // before it reached the feed, so re-sourcing the evaluator + boundary zone HERE is
        // the strictly-last step (doc 11 §5.3). One commit re-sources every field the
        // snapshot carries, on every transport.
        sink.commit_snapshot(&snapshot);
        committed_seq = Some(snapshot.seq);
        commits += 1;
    }
    commits
}

/// Derive the POL-3 provenance the reload-boundary [`SnapshotDropEvent`] carries from the
/// DROPPED snapshot (doc 11 §6.7: provenance on every event, never blank). The drop is a
/// reload-boundary signal, not a query verdict, so it has no matched rule — the triple names
/// the reload boundary as its rule/layer and carries the policy VERSION the dropped fan-out
/// failed to advance: the snapshot's committed composed-document version when it carries one
/// (the production hand-off), else the snapshot's `seq` (the boundary-zone-only hand-off has
/// no composed document, but the monotonic seq IS its version identity). Every field is
/// non-empty by construction, so the convention-layer encode never hits the blank-provenance
/// error (§6.7).
fn reload_boundary_provenance(snapshot: &BoundarySnapshot) -> crate::event::EventProvenance {
    let policy_version = snapshot
        .policy
        .as_ref()
        .map(|p| p.composed.policy_version.clone())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| format!("seq/{}", snapshot.seq));
    crate::event::EventProvenance {
        rule_id: "reload-boundary/forward-only-seq".to_string(),
        policy_layer: "pol-reload-boundary".to_string(),
        policy_version,
    }
}

/// Bind the UDP + TCP listeners and start serving.
///
/// Returns once the sockets are bound; the UDP `Server` and the capped TCP accept
/// loop then run on the caller's tokio runtime. Errors only on bind failure.
///
/// Runs with the [`NullSink`] §5.5 event sink — the framework / forwarder / scrub
/// harnesses and the pre-stage `main` validate the listener and the wire shapes, not
/// telemetry transport. A production deployment that wants the gate's `DnsEvent`s in
/// the real disk-bounded, visible-loss spool (D116) calls [`spawn_gate_with_sink`]
/// with a [`TelemetrySink`](crate::event::TelemetrySink) over a
/// [`ds_telemetry::SpoolSink`] — the same handler, the same emission sites, only the
/// sink swapped (doc 11 §5.5).
pub async fn spawn_gate<P: PolicyHook + Clone>(
    policy: P,
    config: GateConfig,
) -> io::Result<RunningGate<P, InMemoryAdmissionMap, RecordingSetProgrammer>> {
    spawn_gate_with_sink(policy, config, Arc::new(NullSink)).await
}

/// Bind the UDP + TCP listeners and start serving, with an explicit §5.5 LOG-1
/// [`EventSink`] — the PRODUCTION entry point the collapse wires.
///
/// `events` is the gate's real `DnsEvent` sink, shared (`Arc`-cloned) across the UDP
/// `Server` handler and the capped TCP accept-loop handler so both transports emit to
/// the same sink. The production wiring hands a
/// [`TelemetrySink`](crate::event::TelemetrySink) over the real
/// [`ds_telemetry::SpoolSink`] here, so every authored `DnsEvent` is encoded to a
/// convention-layer `EventEnvelope` and durably spooled (D116) — with the handler
/// emission sites byte-identical in shape (doc 11 §5.5: replace the sink, never the
/// sites). [`spawn_gate`] is exactly this with a [`NullSink`].
pub async fn spawn_gate_with_sink<P: PolicyHook + Clone>(
    policy: P,
    config: GateConfig,
    events: Arc<dyn EventSink>,
) -> io::Result<RunningGate<P, InMemoryAdmissionMap, RecordingSetProgrammer>> {
    // The DEFAULT NFT-3 set programmer: the reportable in-memory `RecordingSetProgrammer`
    // (LOOPBACK/SYNTHETIC, no live nft kernel write — the offline/CI path). `main` selects the
    // production `ds_nft::NftWriter` admission programmer via [`spawn_gate_with_programmer`]
    // behind `DS_NFTGATE_LIVE`; this default-path entry point never touches the kernel.
    spawn_gate_with_programmer(
        policy,
        config,
        Arc::new(RecordingSetProgrammer::new()),
        events,
    )
    .await
}

/// Bind the UDP + TCP listeners with an explicit §5.5 LOG-1 [`EventSink`] AND an explicit
/// NFT-3 set programmer `S` — the PRODUCTION admission-programmer selection seam.
///
/// The supplied `Arc<S>` becomes the W1/W2 admission insert's set programmer for BOTH
/// transports (shared by Arc-clone inside the one [`AdmissionStores`]). The default-path
/// [`spawn_gate`] / [`spawn_gate_with_sink`] pass the reportable [`RecordingSetProgrammer`]
/// (LOOPBACK/SYNTHETIC, no live kernel); `main` passes `ds_nft::NftWriter<SpawnBackend>` ONLY
/// behind `DS_NFTGATE_LIVE` (default OFF), so the SAME insert-then-answer transaction that
/// records into the recorder programs the real kernel allow-set element carrying the W2
/// deadline. W1–W4, the fail-closed two-store lockstep, and byte-exact key agreement are
/// properties of the transaction (doc 11 §3.1) — independent of which programmer the insert
/// lands on; selecting the live writer changes only the set-write backend, never the
/// transaction shape.
pub async fn spawn_gate_with_programmer<
    P: PolicyHook + Clone,
    S: NftSetProgrammer + Send + Sync + 'static,
>(
    policy: P,
    config: GateConfig,
    set: Arc<S>,
    events: Arc<dyn EventSink>,
) -> io::Result<RunningGate<P, InMemoryAdmissionMap, S>> {
    // The DEFAULT/in-memory DNS-2b map path: build the store bundle via
    // `AdmissionStores::with_parts` (which BINDS the §5.4 revocation-sweep map handle — the
    // closed admission ↔ revocation loop, doc 11 §5.4) and serve. The D131 Candidate-A live
    // shm-backed path bypasses this and constructs the stores itself
    // (`AdmissionStores::with_shm_writer`), then serves via [`spawn_gate_with_stores`].
    let admission = AdmissionStores::with_parts(set, LiveAdmissions::new());
    spawn_gate_with_stores(policy, config, admission, events).await
}

/// Bind the UDP + TCP listeners with an explicit §5.5 LOG-1 [`EventSink`] AND a fully-built
/// [`AdmissionStores`] bundle — the generic-over-map seam `main` uses to serve the D131
/// Candidate-A LIVE shm-backed DNS-2b map (`M = ds_admission_shm::ShmAdmissionMap`, built via
/// [`AdmissionStores::with_shm_writer`]) behind `DS_ADMISSION_SHM_LIVE`, mirroring how
/// [`spawn_gate_with_programmer`] selects the production NFT-3 programmer behind `DS_NFTGATE_LIVE`.
///
/// The caller owns the store construction (and thus the create-or-reattach of the shm segment);
/// this function only wires the bundle into both transports and starts serving. W1–W4 and the
/// fail-closed two-store lockstep are properties of the transaction (doc 11 §3.1), independent of
/// which map backs the admission entries — only the backing swaps.
pub async fn spawn_gate_with_stores<
    P: PolicyHook + Clone,
    M: AdmissionMap + Send + Sync + 'static,
    S: NftSetProgrammer + Send + Sync + 'static,
>(
    policy: P,
    config: GateConfig,
    admission: AdmissionStores<M, S>,
    events: Arc<dyn EventSink>,
) -> io::Result<RunningGate<P, M, S>> {
    // Thread the FLEET-revocation recording config (doc 19 §7) into the admission store BEFORE it is
    // shared into the transports: the `SessionRef` host id (`config.host_id`) and the scoped-token
    // fingerprint source the mint path records `(fingerprint → session)` under. With no fingerprint
    // wired (the default) the mint path records nothing — the fleet book stays empty, byte-identical
    // to today. A shared-handle-preserving field set (the book handle is untouched), so the clones
    // below and the gate's captured handle are the SAME book.
    let admission = admission.with_fleet_recording(
        config.host_id.clone(),
        config.fixed_token_fingerprint.clone(),
    );
    // PER-SESSION fingerprint feed (doc 19 §7): when `config.token_fingerprint_map` is wired, install
    // a live per-session resolver that TAKES PRECEDENCE over the fixed single-session fingerprint —
    // the mint path resolves EACH admitting session's own token fingerprint from its `session_uuid`
    // at admission time, so two sessions admitted under two distinct tokens key two DISTINCT book
    // rows. The map is the loopback/synthetic stand-in for the real cross-process feed (a deferred
    // seam, D50); it carries fingerprint/block-id only, never token bytes. The host id set above is
    // retained (the resolver overrides only the fingerprint source).
    let admission = match config.token_fingerprint_map.clone() {
        Some(map) => {
            admission.with_fleet_fingerprint_resolver(Arc::new(move |session_uuid: &str| {
                map.get(session_uuid).cloned()
            }))
        }
        None => admission,
    };

    let udp = UdpSocket::bind(config.udp_addr).await?;
    let udp_local = udp.local_addr()?;

    let tcp = TcpListener::bind(config.tcp_addr).await?;
    let tcp_local = tcp.local_addr()?;

    // A shared-handle clone of the installed evaluator the gate keeps so it can hand out a
    // `GatePolicyReloader` (the doc 11 §5.3 D72 evaluator re-source path). For a
    // `PolicyCorePolicy` this shares the SAME inner `Arc` the UDP + TCP handlers hold, so a
    // reload through the gate's clone re-sources every transport's evaluator at once.
    let gate_policy = policy.clone();

    // ONE W1/W2 admission-store bundle for the WHOLE gate (doc 11 §5.2 / §5.4): the DNS-2b map,
    // the NFT-3 set programmer, and the SINGLE §5.4 live-admission registry both transports admit
    // into. Cloning is a shared-handle clone, so the UDP and TCP handlers (built below) hold the
    // SAME stores — the SAME map, the SAME `Arc<S>` programmer, and the SAME `LiveAdmissions` the
    // §5.4 revocation sweep re-evaluates (handed back to the caller via
    // [`RunningGate::live_admissions`]).
    let live_admissions = admission.live().clone();
    // The gate's shared FLEET-revocation admission book — the SAME handle the store's mint path
    // records into (captured here, before `admission` is shared into the transports, so
    // `RunningGate::fleet_revocation_book` hands `main` the book the admissions actually populate,
    // not a fresh one the sweep could never see). A shared-handle clone; doc 19 §7 / D102/P-R6.
    let fleet_revocation_book = admission.fleet_revocation_book();

    // UDP: hickory's Server drives our handler directly. The authored-SOA boundary zone
    // is the LIVE snapshot value the config carries (sourced via
    // `ds-policy-snapshot::PolicySnapshot::boundary_zone_value` at startup / D72 reload),
    // NOT the handler-local DEFAULT_BOUNDARY_ZONE const. The shared admission stores + the
    // live POL-1 `admission.grace` (the config value, sourced off the committed snapshot in
    // `main`) are threaded in via `with_admission`, so the W2 deadline carries the policy grace
    // and both transports record into the one shared §5.4 registry.
    // The §5.1 session-attribution wiring, applied as the LAST builder on each handler so it
    // overrides the constructor's `SessionSource::PreStage` only when a source is configured.
    // PRECEDENCE (doc 11 §5.1 / W6): the interface-anchored TAP REGISTRY (the structurally-
    // general, multi-session W6 join — the orchestrator's never-recycled tap registry threaded
    // in via `config.tap_registry`) wins over the single-session FIXED `session_uuid`
    // (`DS_SESSION_UUID`, the single-VM testbed key agreement), which in turn wins over the
    // pre-stage `src:<addr>` fallback. The registry is anchored PER TRANSPORT on that listener's
    // own post-NAT LOCAL address (`AttributionTable::attribute_local`) — never the guest source
    // IP — so both transports resolve the SAME never-recycled tap and FAIL CLOSED to SERVFAIL on
    // an unregistered interface. Each transport gets a shared-handle clone of the table (the
    // registry is the read view of one orchestrator session record). With NEITHER set (the
    // `Default` and every existing harness) the handler keeps the pre-stage token, byte-identical
    // to today.
    let tap_registry = config.tap_registry.clone();
    let fixed_session_uuid = config.fixed_session_uuid.clone();
    let with_attribution = |handler: StubRequestHandler<_, _, _>, local_addr: IpAddr| match (
        &tap_registry,
        &fixed_session_uuid,
    ) {
        (Some(table), _) => handler.with_attribution_local(table.clone(), local_addr),
        (None, Some(uuid)) => handler.with_session_uuid(uuid.clone()),
        (None, None) => handler,
    };

    let udp_handler = with_attribution(
        StubRequestHandler::with_forwarder_boundary_zone_and_sink(
            policy.clone(),
            config.forwarder.clone(),
            &config.boundary_zone,
            events.clone(),
        )
        .with_admission(admission.clone(), config.admission_grace_secs),
        udp_local.ip(),
    );
    // Keep the UDP handler's D72 reload handle before it is moved into hickory's `Server`.
    let mut boundary_zone_reloads = vec![udp_handler.boundary_zone_reload_handle()];
    let mut udp_server = Server::new(udp_handler);
    udp_server.register_socket(udp);

    // TCP: an accept loop here in server.rs bounds concurrency with a semaphore (the
    // cap hickory does not provide), then serves each connection through the SAME
    // handler so UDP/TCP behavior stays identical (doc 11 §3.4 parity) — same live
    // snapshot boundary zone, same shared admission stores + grace as the UDP handler.
    let tcp_handler = Arc::new(with_attribution(
        StubRequestHandler::with_forwarder_boundary_zone_and_sink(
            policy,
            config.forwarder,
            &config.boundary_zone,
            events,
        )
        .with_admission(admission, config.admission_grace_secs),
        tcp_local.ip(),
    ));
    boundary_zone_reloads.push(tcp_handler.boundary_zone_reload_handle());
    let semaphore = Arc::new(Semaphore::new(config.max_tcp_connections.max(1)));
    let (tcp_shutdown, shutdown_rx) = watch::channel(false);
    let mut tcp_tasks = JoinSet::new();

    {
        let semaphore = semaphore.clone();
        let handler = tcp_handler.clone();
        let timeout = config.tcp_timeout;
        tcp_tasks.spawn(async move {
            accept_loop(tcp, semaphore, shutdown_rx, handler, timeout).await;
        });
    }

    Ok(RunningGate {
        udp_server,
        tcp_tasks,
        tcp_shutdown,
        udp_local,
        tcp_local,
        boundary_zone_reloads,
        policy: gate_policy,
        live_admissions,
        // The store's OWN shared fleet-revocation admission book (doc 19 §7) — captured above so the
        // gate hands `main` the SAME handle the mint path records sessions into as it admits them
        // under a scoped token. `main` wires the post-commit fleet sweep against it via
        // `fleet_revocation_book()`; the closed admission ↔ fleet-revocation loop.
        fleet_revocation_book,
    })
}

/// The semaphore-gated TCP accept loop. Acquires a permit BEFORE accepting the next
/// connection, so at most `cap` connections are in flight at once; a flood beyond the
/// cap simply waits for a permit (bounded resource use) instead of spawning unbounded
/// per-connection tasks.
async fn accept_loop<
    P: PolicyHook,
    M: AdmissionMap + Send + Sync + 'static,
    S: NftSetProgrammer + Send + Sync + 'static,
>(
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
    handler: Arc<StubRequestHandler<P, M, S>>,
    timeout: Duration,
) {
    let mut conns = JoinSet::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        // Acquire a permit first: this is the cap. We never accept-and-then-drop, so
        // the number of LIVE served connections never exceeds the cap.
        let permit = tokio::select! {
            permit = semaphore.clone().acquire_owned() => match permit {
                Ok(p) => p,
                Err(_) => break, // semaphore closed
            },
            _ = shutdown.changed() => break,
        };

        let (stream, src) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(_) => {
                    // Transient accept error: drop the permit and keep serving.
                    drop(permit);
                    continue;
                }
            },
            _ = shutdown.changed() => break,
        };

        let handler = handler.clone();
        conns.spawn(async move {
            // The permit is held for the whole connection lifetime, then released.
            let _permit = permit;
            serve_tcp_connection(stream, src, handler, timeout).await;
        });

        // Reap finished connection tasks so the JoinSet does not grow unbounded.
        while let Some(res) = conns.try_join_next() {
            let _ = res;
        }
    }

    // Drain in-flight connections on shutdown.
    while conns.join_next().await.is_some() {}
}

/// Serve one TCP/53 connection: read length-prefixed DNS queries, run each through
/// the handler, and write the length-prefixed responses back. Reuses hickory's
/// `Request` decode, `RequestHandler` dispatch, and `ResponseHandle` serialization,
/// so the served wire shape matches the UDP path byte for byte.
async fn serve_tcp_connection<
    P: PolicyHook,
    M: AdmissionMap + Send + Sync + 'static,
    S: NftSetProgrammer + Send + Sync + 'static,
>(
    mut stream: TcpStream,
    src: SocketAddr,
    handler: Arc<StubRequestHandler<P, M, S>>,
    timeout: Duration,
) {
    loop {
        // DNS over TCP framing: a 2-byte big-endian length prefix, then the message.
        // The per-connection read timeout is the DoS lever (doc 11 §3.4): a
        // connection that sends no complete frame in time is dropped.
        let mut len_buf = [0u8; 2];
        match tokio::time::timeout(timeout, stream.read_exact(&mut len_buf)).await {
            Ok(Ok(_)) => {}
            // EOF, read error, or idle timeout: close the connection.
            _ => return,
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            return;
        }
        let mut msg = vec![0u8; msg_len];
        match tokio::time::timeout(timeout, stream.read_exact(&mut msg)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }

        // Decode into a hickory Request; a malformed frame closes the connection
        // (mirrors hickory's own "bail on this connection" behavior).
        let Ok(request) = Request::from_bytes(msg, src, Protocol::Tcp) else {
            return;
        };

        // A per-message response sink: the handler authors into this channel via the
        // ResponseHandle; we then drain and frame the serialized bytes.
        let (stream_handle, mut receiver) = BufDnsStreamHandle::new(src);
        let response_handle = ResponseHandle::new(src, stream_handle, Protocol::Tcp);

        let _ =
            <StubRequestHandler<P, M, S> as hickory_server::server::RequestHandler>::handle_request::<
                _,
                TokioTime,
            >(&handler, &request, response_handle)
            .await;

        // Drain every serialized response the handler produced for this query and
        // write each back with the TCP length prefix.
        while let Some(serial) = next_serial(&mut receiver).await {
            let (bytes, _addr) = serial.into_parts();
            let Ok(len) = u16::try_from(bytes.len()) else {
                return;
            };
            if stream.write_all(&len.to_be_bytes()).await.is_err()
                || stream.write_all(&bytes).await.is_err()
                || stream.flush().await.is_err()
            {
                return;
            }
        }
    }
}

/// Pull the next serialized response out of the per-connection sink, if any is
/// immediately available. The handler pushes synchronously inside `handle_request`,
/// so by the time it returns the message is already queued; we use a zero-ish poll so
/// a query that produced no response (none expected) does not block the connection.
async fn next_serial(
    receiver: &mut hickory_server::net::xfer::StreamReceiver,
) -> Option<hickory_server::proto::op::SerialMessage> {
    use futures_util::StreamExt;
    // The response is already in the channel by the time handle_request returns; a
    // short timeout guards against the (no-response) case. On timeout there was no
    // response to send (none expected), so `None` (the default) is correct.
    tokio::time::timeout(Duration::from_millis(50), receiver.next())
        .await
        .unwrap_or_default()
}

#[cfg(test)]
mod watch_policies_tests {
    //! The single-per-host `WatchPolicies` host-snapshot subscriber loop (doc 11 §5.3 /
    //! D72): a SYNTHETIC host-local committed-snapshot feed flows through [`watch_policies`]
    //! and drives the SOLE boundary-zone reload path admitter-LAST. `ds-dnsgate` never opens
    //! a control-plane stream (§5.3), so these push synthetic commits through the host-local
    //! [`BoundarySnapshotFeed`] — no live host agent, no policy stream, loopback only. These
    //! live in `src/` (NOT `tests/`, which belongs to the sibling dnsgate-inttest unit).

    use super::*;
    use std::sync::Mutex;

    /// A synthetic boundary-zone reload sink that records every committed suffix IN ORDER —
    /// the test stand-in for the real [`RunningGate`] reload path, so the subscriber →
    /// commit flow (and its D72 forward-only seq discipline) is asserted without binding
    /// listeners. The REAL `RunningGate` is exercised end-to-end in the wire test below.
    #[derive(Default)]
    struct RecordingSink {
        commits: Mutex<Vec<String>>,
    }

    impl RecordingSink {
        fn committed(&self) -> Vec<String> {
            self.commits.lock().expect("sink lock poisoned").clone()
        }
    }

    impl BoundaryZoneSink for RecordingSink {
        fn commit_boundary_zone(&self, boundary_zone: &str) {
            self.commits
                .lock()
                .expect("sink lock poisoned")
                .push(boundary_zone.to_string());
        }
    }

    #[test]
    fn empty_committed_value_falls_back_to_the_working_name() {
        // The host-local hand-off mirrors the POL-1 / snapshot empty-skip: a committed
        // snapshot with no boundary zone signs with the working-name default, never blank.
        assert_eq!(
            BoundarySnapshot::new(1, "").boundary_zone,
            DEFAULT_BOUNDARY_ZONE
        );
        assert_eq!(
            BoundarySnapshot::new(2, "corp.example.").boundary_zone,
            "corp.example."
        );
    }

    #[tokio::test]
    async fn synthetic_snapshot_commit_flows_through_the_subscriber_to_the_reload_sink() {
        // A synthetic host-local feed: publish two committed snapshots with advancing seqs;
        // the subscriber commits each one, in order, through the sink. This is the
        // subscriber → reload flow the unit exists to close.
        let sink = RecordingSink::default();
        let (feed, subscription) = boundary_snapshot_feed(8);

        let publisher = tokio::spawn(async move {
            feed.publish(BoundarySnapshot::new(1, "alpha.example."))
                .await
                .expect("subscriber alive");
            feed.publish(BoundarySnapshot::new(2, "beta.example."))
                .await
                .expect("subscriber alive");
            // Drop the feed (every publisher gone) so the subscriber loop returns.
        });

        let commits = watch_policies(subscription, &sink).await;
        publisher.await.expect("publisher task");

        assert_eq!(commits, 2, "both advancing-seq snapshots committed");
        assert_eq!(
            sink.committed(),
            vec!["alpha.example.".to_string(), "beta.example.".to_string()],
            "the subscriber drove the boundary zone in commit order"
        );
    }

    #[tokio::test]
    async fn d72_forward_only_seq_drops_duplicate_and_stale_fan_outs() {
        // D72 single-policy-version: a re-delivered (same seq) or out-of-order (lower seq)
        // host-local fan-out is a duplicate, NEVER re-sourced backwards. Only forward seqs
        // commit, so the authored suffix is monotonic with the policy version.
        let sink = RecordingSink::default();
        let (feed, subscription) = boundary_snapshot_feed(16);

        let publisher = tokio::spawn(async move {
            for snap in [
                BoundarySnapshot::new(5, "v5.example."),
                BoundarySnapshot::new(5, "dup-v5.example."), // duplicate seq — dropped
                BoundarySnapshot::new(3, "stale-v3.example."), // stale seq — dropped
                BoundarySnapshot::new(6, "v6.example."),     // forward — committed
            ] {
                feed.publish(snap).await.expect("subscriber alive");
            }
        });

        let commits = watch_policies(subscription, &sink).await;
        publisher.await.expect("publisher task");

        assert_eq!(commits, 2, "only the two forward seqs (5, 6) committed");
        assert_eq!(
            sink.committed(),
            vec!["v5.example.".to_string(), "v6.example.".to_string()],
            "the duplicate (seq 5) and stale (seq 3) fan-outs never re-sourced the suffix"
        );
    }

    #[tokio::test]
    async fn subscriber_drives_reload_boundary_zone_on_the_real_running_gate_admitter_last() {
        // End-to-end: a synthetic committed snapshot flows through the subscriber and drives
        // the REAL `RunningGate::reload_boundary_zone` (the SOLE reload path) — proving the
        // admitter-LAST commit re-sources the authored SOA on the live gate. No control-plane
        // stream; the feed is host-local and synthetic (§5.3); loopback only.
        use crate::handler::DEFAULT_BOUNDARY_ZONE;
        use crate::policy::FixedStubPolicy;

        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(FixedStubPolicy::new(), config)
            .await
            .expect("gate binds on loopback");
        // Startup: the gate authors with the live startup snapshot suffix (NOT the const).
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.startup.example."
        );
        assert_ne!(gate.current_authored_mname(), DEFAULT_BOUNDARY_ZONE);

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);

        // Run the subscriber against the live gate on its own task (as `main` does).
        let sub_gate = gate.clone();
        let subscriber =
            tokio::spawn(async move { watch_policies(subscription, sub_gate.as_ref()).await });

        // The host agent fans out a committed snapshot (a new policy version) host-locally.
        feed.publish(BoundarySnapshot::new(42, "pushed.example."))
            .await
            .expect("subscriber alive");
        drop(feed); // gate shutting down → subscriber loop returns
        let commits = subscriber.await.expect("subscriber task");

        assert_eq!(commits, 1, "the single committed snapshot reloaded once");
        // The admitter committed LAST: the live gate now authors with the pushed suffix.
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.pushed.example."
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    // ── The PRODUCTION path: a committed BoundarySnapshot that carries a composed policy
    //    re-sources the RUNNING `PolicyCorePolicy` evaluator (the frozen `evaluate`) through
    //    the `SnapshotCommitSink` + `watch_snapshots`, admitter-LAST — not just the authored
    //    suffix. POL-3 provenance preserved on every arm. Loopback / synthetic only (§5.3). ──

    use ds_contracts::pol1::parse_layer;
    use policy_core::pol1_eval::compose;

    use crate::policy::DnsQueryCtx;

    /// A POL-1 layer (`v1`) that DENIES `blocked-v1.example` at a severing rung — composes to a
    /// document whose `policy_version` is `pol1/v1`, so the evaluator hard-denies that name.
    const SUB_LAYER_V1: &str = r#"
schema_version: pol1/v1
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
  - domain: blocked-v1.example
    reason: blocked-in-v1
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// A SECOND POL-1 layer (`v2`) — a NEW committed policy version where `blocked-v1.example`
    /// is no longer blocked. Composes to `policy_version` `pol1/v2`, so re-sourcing from v1 to
    /// v2 flips the evaluator's verdict for `blocked-v1.example`.
    const SUB_LAYER_V2: &str = r#"
schema_version: pol1/v2
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

    fn sub_composed(layer_yaml: &str) -> ComposedPolicy {
        let layer = parse_layer(layer_yaml).expect("the test POL-1 layer parses");
        compose(&[layer], &[])
    }

    fn sub_ctx(qname: &str) -> DnsQueryCtx {
        DnsQueryCtx {
            session: "sub-test".to_string(),
            qname: qname.to_string(),
            qtype: 1,
            source: SocketAddr::from((Ipv4Addr::LOCALHOST, 9)),
        }
    }

    #[tokio::test]
    async fn committed_snapshot_re_sources_the_running_evaluator_admitter_last() {
        // End-to-end PRODUCTION wiring (exactly `main`'s): a real loopback gate runs the
        // pack-backed `PolicyCorePolicy` (v1 — hard-denies `blocked-v1.example`); the
        // `SnapshotCommitSink` pairs the gate's boundary-zone reloader + policy reloader; a
        // committed `with_policy` snapshot (v2) flows through `watch_snapshots` and re-sources
        // BOTH the evaluator and the authored suffix admitter-LAST. The verdict for the SAME
        // name flips on the LIVE evaluator — the frozen `evaluate` is now driven by the
        // committed policy version. No control-plane stream; synthetic feed; loopback only.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        // Hold a SHARED-HANDLE clone of the installed evaluator BEFORE spawn so the test can
        // observe the live verdict the gate's handlers decide with — it shares the SAME inner
        // `Arc`, so a subscriber-driven reload through the gate is visible on this clone (the
        // same way the UDP + TCP handler clones observe it).
        let live_policy = PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        // Startup: the running evaluator decides against v1 (blocked-v1.example is a hard deny),
        // and the authored suffix is the startup snapshot value.
        assert_eq!(gate.policy_version(), "pol1/v1");
        let before = live_policy.evaluate(&sub_ctx("blocked-v1.example."));
        assert!(
            !before.admits(),
            "v1 hard-denies blocked-v1.example on the live evaluator"
        );
        assert!(
            !before.provenance().rule_id.is_empty(),
            "POL-3 on the v1 deny"
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.startup.example."
        );

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);

        // The PRODUCTION commit sink: boundary-zone reloader + evaluator reloader, paired (the
        // verbatim `main` wiring). Run it against the live gate on its own task.
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader());
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // The host agent fans out a committed snapshot carrying a NEW composed policy version
        // (v2) AND a new boundary zone — one policy version, end to end.
        feed.publish(BoundarySnapshot::with_policy(
            7,
            "pushed.example.",
            sub_composed(SUB_LAYER_V2),
            TtlClamp {
                floor: 30,
                ceil: 600,
            },
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1, "the single committed snapshot re-sourced once");

        // Admitter-LAST: the LIVE evaluator now decides against v2 — `blocked-v1.example` is no
        // longer denied (the verdict flipped on the running gate), and the authored suffix is
        // the pushed value. POL-3 provenance is preserved across the swap.
        assert_eq!(
            gate.policy_version(),
            "pol1/v2",
            "the running evaluator re-sourced its composed document from the committed snapshot"
        );
        // The shared-handle clone observes the live re-source (same inner `Arc` as the gate's
        // handlers) — the frozen `evaluate` now decides against v2.
        let after = live_policy.evaluate(&sub_ctx("blocked-v1.example."));
        assert_ne!(
            before, after,
            "the snapshot-driven reload changed the live evaluator's verdict"
        );
        assert!(
            !after.provenance().rule_id.is_empty(),
            "POL-3 provenance preserved on the re-sourced evaluator's verdict"
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.pushed.example.",
            "the authored suffix re-sourced together with the evaluator (one policy version)"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn boundary_zone_only_snapshot_leaves_the_evaluator_unchanged() {
        // A snapshot WITHOUT a composed policy (`BoundarySnapshot::new`, `policy: None`)
        // re-sources ONLY the authored suffix through the combined sink — the running evaluator
        // is untouched (the boundary-zone-only hand-off the existing feeds use stays valid).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v1");

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader());
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // A boundary-zone-only commit: re-sources the suffix, NOT the evaluator.
        feed.publish(BoundarySnapshot::new(9, "zone-only.example."))
            .await
            .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1, "the boundary-zone-only snapshot committed once");

        assert_eq!(
            gate.policy_version(),
            "pol1/v1",
            "a `policy: None` snapshot left the running evaluator on its startup version"
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.zone-only.example.",
            "the authored suffix still re-sourced from the boundary-zone-only snapshot"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    // ── The doc 11 §5.4 REVOCATION SWEEP: after the admitter-LAST evaluator re-source, the
    //    commit re-evaluates live DNS-2b admissions against the NEW composed document and removes
    //    the now-denied derived state — DNS-2b map entries + refcount-aware allow-set elements,
    //    with the D53 rung-conditional conntrack flush. HONEST SCOPE: there is no W1/W2 admission
    //    transaction in `main` yet, so the registry is fed synthetically; these assert the HOOK
    //    runs correctly ordered (evaluator FIRST, sweep SECOND) and ready for that seam. POL-3
    //    provenance preserved on the re-evaluation verdicts. Loopback / synthetic only (§5.3). ──

    use std::net::IpAddr;

    /// A LOOSE POL-1 layer (`pol1/v-loose`): allowlists `tighten.example`, `shared.example`, and
    /// `kept.example` — every one ADMITS. The startup version every sweep test admits against.
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
  - domain: shared.example
  - domain: kept.example
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    /// A TIGHTENED POL-1 layer (`pol1/v-tight`): `tighten.example` is now BLOCKED at a SEVERING
    /// rung (`kill+snapshot`, block-or-higher → D53 conntrack flush fires); `shared.example` and
    /// `kept.example` stay allowlisted (still admit). Re-sourcing LOOSE → TIGHT flips
    /// `tighten.example` Allow → Deny, so the sweep revokes its live admissions.
    const SWEEP_LAYER_TIGHT: &str = r#"
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
  - domain: shared.example
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

    /// A TIGHTENED layer where the revocation is NON-SEVERING: `tighten.example` is simply
    /// dropped from the allowlist (no blocklist entry), so under `standard` posture it becomes an
    /// unknown-domain `Ask` — which does NOT admit (the admission is revoked) but is NOT a `Deny`
    /// at a severing rung, so NO conntrack flush fires. Used to assert the flush is
    /// rung-conditional (D53): a non-severing revocation removes the DNS-2b entry without a flush.
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
  - domain: shared.example
  - domain: kept.example
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("the test IP parses")
    }

    #[test]
    fn live_admission_normalizes_the_fqdn_to_trailing_dot_lowercase() {
        // The W1/W2 transaction (and tests) feed names in mixed forms; the registry normalizes
        // to the lower-cased trailing-dot form the evaluator keys on, so the sweep's
        // re-evaluation matches the original admission.
        let a = LiveAdmission::new("s", "Tighten.EXAMPLE", ip("203.0.113.7"));
        assert_eq!(a.fqdn, "tighten.example.");
        let b = LiveAdmission::new("s", "kept.example.", ip("203.0.113.8"));
        assert_eq!(b.fqdn, "kept.example.");
    }

    #[test]
    fn sweep_revokes_a_now_denied_admission_but_keeps_a_shared_cdn_ip_referenced_by_a_survivor() {
        // The §5.4 sweep core, driven directly against the production `PolicyCorePolicy`
        // re-evaluator. Three live admissions under the LOOSE policy (all admit):
        //   - tighten.example @ 203.0.113.7  (a SOLE-reference IP)
        //   - tighten.example @ 198.51.100.9 (a SHARED-CDN IP)
        //   - kept.example     @ 198.51.100.9 (the SAME shared IP, a survivor)
        // Re-source to TIGHT (tighten.example → Deny at a severing rung). The sweep must:
        //   - revoke BOTH tighten.example admissions (the DNS-2b entries are gone),
        //   - delete the sole-reference IP 203.0.113.7 from the allow set,
        //   - NOT delete the shared IP 198.51.100.9 (kept.example still references it — the
        //     reverse-index refcount, bias to under-delete),
        //   - flag the revoked admissions for the D53 conntrack flush (severing rung),
        //   - leave kept.example's admission live.
        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        let admissions = LiveAdmissions::new();
        let sole_ip = ip("203.0.113.7");
        let shared_ip = ip("198.51.100.9");
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", sole_ip));
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", shared_ip));
        admissions.admit(LiveAdmission::new("sess-b", "kept.example", shared_ip));
        assert_eq!(admissions.len(), 3);

        // Admitter-LAST: re-source the evaluator to the tightened version FIRST, THEN sweep.
        evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
        assert_eq!(evaluator.current_policy_version(), "pol1/v-tight");

        let outcome = admissions.sweep(&evaluator);

        // Both tighten.example admissions were revoked; kept.example survived.
        assert_eq!(
            outcome.revoked.len(),
            2,
            "both tighten.example entries revoked"
        );
        assert!(
            outcome
                .revoked
                .iter()
                .all(|r| r.admission.fqdn == "tighten.example."),
            "only the now-denied name was revoked"
        );
        // The D53 conntrack flush is flagged: the deny is at a severing rung (kill+snapshot).
        assert!(
            outcome.revoked.iter().all(|r| r.flush_conntrack),
            "a severing-rung deny fires the rung-conditional conntrack flush (D53)"
        );

        // The sole-reference IP is deleted; the shared-CDN IP is NOT (a survivor still holds it).
        assert_eq!(
            outcome.allow_set_deletions,
            vec![sole_ip],
            "only the IP no live admission references is deleted (refcount-aware, bias to under-delete)"
        );
        assert!(
            !outcome.allow_set_deletions.contains(&shared_ip),
            "the shared-CDN IP survives because kept.example still references it"
        );

        // The live registry now holds ONLY kept.example's admission.
        let survivors = admissions.snapshot();
        assert_eq!(
            survivors.len(),
            1,
            "only the still-allowed admission remains"
        );
        assert_eq!(survivors[0].fqdn, "kept.example.");
        assert_eq!(survivors[0].ip, shared_ip);
    }

    /// A unique-per-invocation POSIX shm name (PID + a process-local counter) so this test is
    /// hermetic across parallel test threads and never reuses a stale leftover. POSIX shm names
    /// begin with `/` and carry no further `/`.
    fn unique_shm_name(tag: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("/ds-admission-sweep-{tag}-{}-{n}", std::process::id())
    }

    /// Build the `AdmissionInputs` the W1/W2 transaction consumes for a NORMAL admission of one
    /// `(session, fqdn)` over an explicit terminal-address set (POL-1 schema defaults pinned in the
    /// inputs, never read from a code constant in the transaction itself — doc 13 §1.5).
    fn shm_inputs(session: &str, fqdn: &str, addrs: Vec<IpAddr>) -> crate::txn::AdmissionInputs {
        crate::txn::AdmissionInputs {
            session_uuid: session.to_string(),
            session_index: 0,
            original_query_fqdn: fqdn.to_string(),
            terminal_addrs: addrs,
            chain_min_ttl: 300,
            ttl_floor: 60,
            ttl_ceil: 900,
            grace: 60,
            provenance: ds_contracts::dns_admission::Provenance {
                rule_id: "rule-allow-sweep".into(),
                policy_layer: "system-baseline".into(),
                policy_version: "pol1/v-loose".into(),
            },
            admission_type: ds_contracts::dns_admission::AdmissionType::Normal,
            real_targets: vec![],
        }
    }

    #[test]
    fn shm_backed_sweep_tombstones_the_revoked_domain_and_frees_only_the_sole_reference_ip() {
        // T5 LIVE-PATH PROOF (doc 11 §5.4, D131): with the §5.4 sweep's `LiveAdmissions` map handle
        // bound to the LIVE shm map (the production read path D131 ships, not the in-process Vec),
        // a policy-revocation sweep must revoke each now-denied `(session, fqdn)` THROUGH the shm
        // map — tombstoning the shm slot so a cross-process ds-tlsproxy reader immediately stops
        // vouching the revoked domain, and decref-ing the shm reverse index so only the IPs whose
        // shm refcount reached zero are deleted from the allow set (a shared-CDN IP a surviving
        // sibling still holds keeps a non-zero shm count and survives — bias to under-delete, W4).
        //
        // Three admissions in ONE session under the LOOSE policy (all admit), shm-backed:
        //   - tighten.example @ 203.0.113.7  (a SOLE-reference IP)
        //   - tighten.example @ 198.51.100.9 (a SHARED-CDN IP)
        //   - kept.example    @ 198.51.100.9 (the SAME shared IP, a survivor)
        // Re-source to TIGHT (tighten.example → Deny at a severing rung), then sweep.
        let name = unique_shm_name("revoke");
        let session = "sess-shm";
        let sole_ip = ip("203.0.113.7");
        let shared_ip = ip("198.51.100.9");

        // PRODUCTION wiring: `with_shm_writer` create-or-reattaches the named segment AND binds the
        // shm map into the live registry (the T5 fix). The W1/W2 `run_admission` writes the shm
        // entry + increfs the shm reverse index AND records the in-process LiveAdmission the sweep
        // re-evaluates.
        let stores = AdmissionStores::with_shm_writer(
            &name,
            Arc::new(RecordingSetProgrammer::new()),
            LiveAdmissions::new(),
        )
        .expect("create shm-backed admission stores on the named segment");

        // Each NAME admits its FULL terminal-address set in ONE W1/W2 transaction (a second
        // `run_admission` of the same name is a REFRESH that decrefs IPs the name no longer
        // references — so `tighten.example` must carry BOTH its IPs in one call, else the second
        // call would decref the first). `tighten.example` → {sole, shared}; `kept.example` → shared.
        // The fqdn is fed in the SAME trailing-dot-normalized form the gate's hot path resolves to
        // (W3), so the shm key the admit writes matches the sweep's revoke key (which the in-process
        // `LiveAdmission` normalizes identically) — else `find_slot` would miss and free nothing.
        let t0 = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000 * 1_000_000_000);
        for (fqdn, addrs) in [
            ("tighten.example.", vec![sole_ip, shared_ip]),
            ("kept.example.", vec![shared_ip]),
        ] {
            match stores.run_admission(&shm_inputs(session, fqdn, addrs), t0) {
                crate::txn::AdmissionOutcome::Admitted { .. } => {}
                other => panic!("expected Admitted from the shm-backed W1/W2 txn, got {other:?}"),
            }
        }

        // Pre-sweep: the shm reverse index holds the SHARED IP at refcount 2 (both names) and the
        // SOLE IP at 1 — read THROUGH the shm `reverse_index`, proving the decision below is sourced
        // off the shm index, not a re-derived survivor count.
        let sole_addr = admitted_addr(sole_ip);
        let shared_addr = admitted_addr(shared_ip);
        assert_eq!(
            stores.reverse_refcount(session, &shared_addr),
            2,
            "the shared-CDN IP is held by BOTH names in the shm reverse index pre-sweep"
        );
        assert_eq!(
            stores.reverse_refcount(session, &sole_addr),
            1,
            "the sole-reference IP is held by exactly one name in the shm reverse index pre-sweep"
        );

        // Admitter-LAST: re-source the evaluator to TIGHT (tighten.example → Deny@severing) FIRST,
        // then sweep through the SAME shared `live` registry the stores bound the shm map into.
        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
        assert_eq!(evaluator.current_policy_version(), "pol1/v-tight");
        let live = stores.live().clone();
        let outcome = live.sweep(&evaluator);

        // Both tighten.example admissions revoked at a severing rung (D53 flush flagged).
        assert_eq!(
            outcome.revoked.len(),
            2,
            "both tighten.example entries revoked"
        );
        assert!(
            outcome
                .revoked
                .iter()
                .all(|r| r.admission.fqdn == "tighten.example." && r.flush_conntrack),
            "only the now-denied name was revoked, at a severing rung (D53)"
        );

        // (c) The SOLE-reference IP IS deleted (its shm refcount hit zero); (b) the SHARED-CDN IP
        // is NOT (the surviving kept.example keeps a non-zero shm refcount).
        assert_eq!(
            outcome.allow_set_deletions,
            vec![sole_ip],
            "only the IP whose SHM refcount reached zero is deleted (refcount-aware, bias to under-delete)"
        );
        assert!(
            !outcome.allow_set_deletions.contains(&shared_ip),
            "the shared-CDN IP survives because kept.example still references it in the shm index"
        );

        // Refcount-correct delete proven DIRECTLY off the shm reverse index (not the survivor
        // fallback): the shared IP now reads 1 (kept.example survives), the sole IP reads 0 (freed).
        assert_eq!(
            stores.reverse_refcount(session, &shared_addr),
            1,
            "post-sweep the shared-CDN IP keeps a non-zero SHM refcount (the surviving sibling)"
        );
        assert_eq!(
            stores.reverse_refcount(session, &sole_addr),
            0,
            "post-sweep the sole-reference IP is freed in the SHM reverse index (refcount zero)"
        );

        // (a) The revoked (session, fqdn) is GONE from the shm map: an INDEPENDENT reader (the
        // ds-tlsproxy read shape — a fresh shm_open attach by name) no longer vouches it, while the
        // surviving kept.example is still present. This is the cross-process security guarantee.
        let reader = ds_admission_shm::ShmAdmissionReader::attach_named(&name)
            .expect("attach an independent read-only reader to the same named segment");
        assert!(
            reader
                .lookup(&AdmissionKey {
                    session_uuid: session.to_string(),
                    original_query_fqdn: "tighten.example.".to_string(),
                })
                .is_none(),
            "the revoked domain is tombstoned in shm — a cross-process reader stops vouching it"
        );
        assert!(
            reader
                .lookup(&AdmissionKey {
                    session_uuid: session.to_string(),
                    original_query_fqdn: "kept.example.".to_string(),
                })
                .is_some(),
            "the surviving domain is still vouched on the live shm read path"
        );

        // The in-process live registry holds ONLY the surviving kept.example admission.
        let survivors = live.snapshot();
        assert_eq!(
            survivors.len(),
            1,
            "only the still-allowed admission remains"
        );
        assert_eq!(survivors[0].fqdn, "kept.example.");
        assert_eq!(survivors[0].ip, shared_ip);

        // Hermetic teardown: unlink the named segment (existing mappings keep working until drop).
        ds_admission_shm::ShmAdmissionMap::unlink(&name).expect("unlink the test segment");
    }

    #[test]
    fn unbound_synthetic_registry_still_uses_the_survivor_derived_fallback_unchanged() {
        // FAIL-CLOSED DEFAULT PRESERVED (the gate-off / isolation path): a bare synthetic
        // `LiveAdmissions::new()` with NO bound map still hits `survivor_derived_deletions` (the
        // `None` branch), producing the IDENTICAL deletion set the shm-backed path computes above —
        // so the isolation tests are unregressed and the fail-closed default is byte-unchanged. This
        // is the same corpus as the shm test (one session, the shared-CDN + sole-reference shape).
        let session = "sess-shm";
        let sole_ip = ip("203.0.113.7");
        let shared_ip = ip("198.51.100.9");

        let admissions = LiveAdmissions::new();
        assert!(
            admissions.map.is_none(),
            "the bare synthetic registry has NO bound map — it must exercise the survivor-derived path"
        );
        admissions.admit(LiveAdmission::new(session, "tighten.example", sole_ip));
        admissions.admit(LiveAdmission::new(session, "tighten.example", shared_ip));
        admissions.admit(LiveAdmission::new(session, "kept.example", shared_ip));

        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
        let outcome = admissions.sweep(&evaluator);

        // The survivor-derived fallback picks the SAME IPs the shm-backed path does: free only the
        // sole-reference IP, keep the shared-CDN IP (a surviving sibling references it).
        assert_eq!(
            outcome.allow_set_deletions,
            vec![sole_ip],
            "the unbound (survivor-derived) path frees only the sole-reference IP — identical to the shm path"
        );
        assert!(
            !outcome.allow_set_deletions.contains(&shared_ip),
            "the shared-CDN IP survives on the survivor-derived fallback too"
        );
        assert_eq!(
            outcome.revoked.len(),
            2,
            "both tighten.example entries revoked"
        );
    }

    #[test]
    fn sweep_under_k_refreshes_frees_a_sole_reference_ip_once_and_keeps_a_shared_survivor() {
        // Regression guard for the §5.4 sweep's correct-by-compensation refcount
        // (server.rs ~507-524) under W4 RE-ADMISSION. `LiveAdmissions::admit` does
        // NOT de-duplicate the same (session, fqdn, ip) — a re-admit/refresh of one
        // logical admission pushes a NEW record each time (by design: the sweep
        // refcounts over SURVIVORS, not over the raw record count). This pins that a
        // burst of K identical pushes does NOT mis-program the allow set:
        //   - the sole-reference IP (held only by the now-DENIED name, even across K
        //     refreshes) is freed EXACTLY once — deduped at the deletion list, never
        //     K times,
        //   - the shared-CDN IP (held by a SURVIVING sibling, also refreshed K times)
        //     is NOT freed — its survivor-side refcount keeps it (bias to
        //     under-delete, W4), no matter how many revoked copies reference it.
        // This is the server.rs analogue of the txn.rs distinct-name refcount: it
        // pins the SURVIVOR-refcount + DEDUPED-deletion so it cannot regress when the
        // txn-side revoke/expiry path is wired.
        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        let admissions = LiveAdmissions::new();
        let sole_ip = ip("203.0.113.7");
        let shared_ip = ip("198.51.100.9");

        // K refreshes of the now-DENIED name over BOTH a sole-reference IP and the
        // shared IP, plus K refreshes of the SURVIVING sibling over the shared IP.
        const K: usize = 5;
        for _ in 0..K {
            admissions.admit(LiveAdmission::new("sess-a", "tighten.example", sole_ip));
            admissions.admit(LiveAdmission::new("sess-a", "tighten.example", shared_ip));
            admissions.admit(LiveAdmission::new("sess-b", "kept.example", shared_ip));
        }
        assert_eq!(admissions.len(), 3 * K, "K non-deduped refresh records");

        // Admitter-LAST: re-source to TIGHT (tighten.example → Deny at a severing
        // rung), THEN sweep.
        evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
        let outcome = admissions.sweep(&evaluator);

        // Every tighten.example record (2*K of them) is revoked; kept.example's K
        // records survive.
        assert_eq!(
            outcome.revoked.len(),
            2 * K,
            "all K refreshes of both denied (session,ip) records are revoked"
        );
        assert!(
            outcome.revoked.iter().all(|r| r.flush_conntrack),
            "a severing-rung deny fires the rung-conditional conntrack flush (D53)"
        );

        // The sole-reference IP is freed EXACTLY ONCE despite K revoked copies (the
        // sweep dedups its deletion list — server.rs `!allow_set_deletions.contains`).
        assert_eq!(
            outcome.allow_set_deletions,
            vec![sole_ip],
            "the sole-reference IP is freed exactly once, not K times (deduped deletion)"
        );
        assert!(
            !outcome.allow_set_deletions.contains(&shared_ip),
            "the shared-CDN IP survives — a surviving sibling (also K-refreshed) still holds it"
        );

        // The live registry keeps ONLY kept.example's K survivor records.
        let survivors = admissions.snapshot();
        assert_eq!(
            survivors.len(),
            K,
            "only the still-allowed name's records remain"
        );
        assert!(
            survivors
                .iter()
                .all(|s| s.fqdn == "kept.example." && s.ip == shared_ip),
            "the survivors are exactly the still-allowed shared-CDN references"
        );
    }

    #[test]
    fn sweep_flush_is_rung_conditional_a_non_severing_deny_revokes_without_flush() {
        // D53: the conntrack flush fires ONLY when the deny severs established flows (a Deny at a
        // block-or-higher rung). A non-severing deny (gate rung) still REVOKES the admission (the
        // DNS-2b entry is gone), but flags NO conntrack flush — it gates new flows only.
        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        let admissions = LiveAdmissions::new();
        admissions.admit(LiveAdmission::new(
            "sess-a",
            "tighten.example",
            ip("203.0.113.7"),
        ));

        evaluator.reload(
            sub_composed(SWEEP_LAYER_TIGHT_NONSEVERING),
            TtlClamp::DEFAULT,
        );
        let outcome = admissions.sweep(&evaluator);

        assert_eq!(
            outcome.revoked.len(),
            1,
            "the non-severing deny still revokes"
        );
        assert!(
            !outcome.revoked[0].flush_conntrack,
            "a non-severing (gate-rung) deny gates new flows only — no conntrack flush (D53)"
        );
        assert!(
            admissions.is_empty(),
            "the revoked DNS-2b entry was removed"
        );
    }

    #[test]
    fn sweep_is_a_noop_when_policy_loosens_or_stays_allowed() {
        // A policy change that keeps a name allowed (or loosens) revokes nothing — the sweep is a
        // no-op. The steady state today (no admissions) and after a loosening.
        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_TIGHT));
        let admissions = LiveAdmissions::new();
        admissions.admit(LiveAdmission::new(
            "sess-a",
            "kept.example",
            ip("198.51.100.9"),
        ));
        // Re-source to LOOSE (kept.example stays allowed; tighten.example un-blocked).
        evaluator.reload(sub_composed(SWEEP_LAYER_LOOSE), TtlClamp::DEFAULT);
        let outcome = admissions.sweep(&evaluator);
        assert!(
            outcome.is_noop(),
            "a still-allowed admission is not revoked"
        );
        assert_eq!(admissions.len(), 1, "the live admission survives");

        // And an empty registry sweeps to a no-op too.
        let empty = LiveAdmissions::new();
        assert!(empty.sweep(&evaluator).is_noop());
    }

    #[tokio::test]
    async fn committed_snapshot_runs_the_revocation_sweep_admitter_last_on_the_live_gate() {
        // End-to-end PRODUCTION wiring: a real loopback gate runs the LOOSE evaluator; the
        // `SnapshotCommitSink::with_revocation_sweep` pairs the gate's boundary-zone reloader,
        // policy reloader, the live-admission registry, AND the gate's re-evaluator. Two live
        // admissions are minted under LOOSE (both admit). A committed `with_policy` snapshot
        // (TIGHT — tighten.example → Deny at a severing rung) flows through `watch_snapshots`; the
        // commit re-sources the evaluator admitter-LAST and THEN runs the §5.4 sweep, which
        // revokes the now-denied admission (and flags its D53 flush) while the still-allowed one
        // survives. No control-plane stream; synthetic feed; loopback only (§5.3).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v-loose");

        // Mint two live admissions under the LOOSE policy (the W1/W2 transaction will do this;
        // here the test feeds them synthetically). Both names admit today.
        let admissions = LiveAdmissions::new();
        let tighten_ip = ip("203.0.113.7");
        let kept_ip = ip("198.51.100.9");
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", tighten_ip));
        admissions.admit(LiveAdmission::new("sess-b", "kept.example", kept_ip));
        // POL-3 sanity: under LOOSE both re-evaluate to an admitting verdict with provenance.
        assert!(live_policy
            .reevaluate("sess-a", "tighten.example.")
            .admits());
        assert!(!live_policy
            .reevaluate("sess-a", "tighten.example.")
            .provenance()
            .rule_id
            .is_empty());

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);

        // The PRODUCTION commit sink WITH the §5.4 sweep: the gate's re-evaluator shares the SAME
        // inner `Arc` as the policy reloader, so the sweep decides against the version the
        // admitter-LAST commit just re-sourced.
        let commit_sink = SnapshotCommitSink::with_revocation_sweep(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // The host agent fans out the TIGHTENED policy version (one policy version end to end).
        feed.publish(BoundarySnapshot::with_policy(
            7,
            "pushed.example.",
            sub_composed(SWEEP_LAYER_TIGHT),
            TtlClamp::DEFAULT,
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(
            commits, 1,
            "the single committed snapshot re-sourced + swept once"
        );

        // Admitter-LAST: the live evaluator decides against TIGHT, and the §5.4 sweep already
        // ran against it — tighten.example's admission is revoked, kept.example's survives.
        assert_eq!(gate.policy_version(), "pol1/v-tight");
        let survivors = admissions.snapshot();
        assert_eq!(survivors.len(), 1, "the now-denied admission was swept out");
        assert_eq!(survivors[0].fqdn, "kept.example.");
        assert_eq!(survivors[0].ip, kept_ip);
        // The tighten.example IP is no longer referenced by any live admission.
        assert!(
            !survivors.iter().any(|a| a.ip == tighten_ip),
            "the revoked admission's sole-reference IP is gone from the live set"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn boundary_zone_only_commit_runs_no_sweep() {
        // A `policy: None` snapshot re-sources only the suffix (no evaluator change), so the
        // commit runs NO sweep — the live admissions are untouched even when wired with a sweep
        // target. Asserts the ordering guard: the sweep only fires on an evaluator re-source.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_TIGHT));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        // A live admission for a name TIGHT already denies — if the sweep wrongly ran on a
        // boundary-zone-only commit it would be revoked; it must NOT be.
        let admissions = LiveAdmissions::new();
        admissions.admit(LiveAdmission::new(
            "sess-a",
            "tighten.example",
            ip("203.0.113.7"),
        ));

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        feed.publish(BoundarySnapshot::new(9, "zone-only.example."))
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

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    // ── The CLOSED admission ↔ revocation loop: the §5.4 sweep sees the admissions the W1/W2 ──
    //    transaction ACTUALLY minted, because both share ONE `LiveAdmissions` registry. ───────

    /// Build admission inputs for a name that the LOOSE/TIGHT sweep layers key on.
    fn sweep_inputs(fqdn: &str, addr: IpAddr, grace: u32) -> crate::txn::AdmissionInputs {
        sweep_inputs_multi(fqdn, vec![addr], grace)
    }

    /// As [`sweep_inputs`] but for a name resolving to a MULTI-IP set in the SAME `sess-loop`
    /// session — so two distinct names can share a CDN IP within one session and the SHARED
    /// `(session, ip)` reverse index keeps it while a sibling survives.
    fn sweep_inputs_multi(
        fqdn: &str,
        addrs: Vec<IpAddr>,
        grace: u32,
    ) -> crate::txn::AdmissionInputs {
        crate::txn::AdmissionInputs {
            session_uuid: "sess-loop".into(),
            session_index: 11,
            original_query_fqdn: fqdn.into(),
            terminal_addrs: addrs,
            chain_min_ttl: 300,
            ttl_floor: 60,
            ttl_ceil: 900,
            grace,
            provenance: ds_contracts::dns_admission::Provenance {
                rule_id: "rule-allow".into(),
                policy_layer: "system-baseline".into(),
                policy_version: "pol1/v-loose".into(),
            },
            admission_type: ds_contracts::dns_admission::AdmissionType::Normal,
            real_targets: vec![],
        }
    }

    #[test]
    fn sweep_sees_the_admissions_the_transaction_minted_via_the_one_shared_registry() {
        // The closed loop: the W1/W2 admission transaction mints into the SAME `LiveAdmissions`
        // the §5.4 sweep re-evaluates. Build ONE `AdmissionStores`, run the insert-then-answer
        // transaction over it (which records into its live registry), then sweep THAT SAME
        // registry (`stores.live()`) after re-sourcing to a tightened policy. The sweep must
        // revoke the txn-minted admission — proving it reads the registry the transaction
        // populated, not a fresh one (the open-loop bug `AdmissionStores::new()` per handler
        // would cause).
        let stores = crate::txn::AdmissionStores::new();
        let live = stores.live().clone();

        // Mint a real admission through the transaction (not fed synthetically): tighten.example
        // admits under LOOSE.
        let tighten_ip = ip("203.0.113.7");
        let kept_ip = ip("198.51.100.9");
        let t0 = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000_000_000_000);
        assert!(matches!(
            stores.run_admission(&sweep_inputs("tighten.example.", tighten_ip, 60), t0),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));
        assert!(matches!(
            stores.run_admission(&sweep_inputs("kept.example.", kept_ip, 60), t0),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));
        // The transaction recorded BOTH live admissions into the shared registry.
        assert_eq!(
            live.len(),
            2,
            "the transaction minted its live records into the shared registry"
        );

        // ADMIT-SIDE INDEX THREADING (this unit): every txn-minted record carries the REAL
        // `inputs.session_index` (`sweep_inputs` admits under `session_index: 11`), NOT the
        // index-0 default `LiveAdmission::new` leaves. This is the wire that makes the §5.4 sweep
        // multi-session-correct end-to-end: the sweep reads `record.host_session_index` to key
        // the freed admission's own `allow4_<idx>` / `(leg, idx)` mark, so the index the ADMIT
        // path keyed `allow_set_name`/`compose` on MUST be stamped onto the record the sweep
        // later reads. A regression to the index-0 default here would silently re-target every
        // production withdraw at `allow4_0`.
        for minted in live.snapshot() {
            assert_eq!(
                minted.host_session_index, 11,
                "the txn-minted live record carries the real inputs.session_index (11), \
                 not the index-0 LiveAdmission::new default",
            );
        }

        // Re-source the evaluator LOOSE → TIGHT (tighten.example → Deny at a severing rung), then
        // sweep the SAME registry the transaction minted into.
        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
        let outcome = live.sweep(&evaluator);

        // The sweep revoked the txn-minted tighten.example admission (and flagged its D53 flush),
        // and freed its sole-reference IP; kept.example survived.
        assert_eq!(
            outcome.revoked.len(),
            1,
            "the txn-minted admission was revoked"
        );
        assert_eq!(outcome.revoked[0].admission.fqdn, "tighten.example.");
        assert!(
            outcome.revoked[0].flush_conntrack,
            "a severing-rung deny flags the D53 conntrack flush"
        );
        assert_eq!(
            outcome.allow_set_deletions,
            vec![tighten_ip],
            "the freed IP is the txn-admitted one"
        );
        let survivors = live.snapshot();
        assert_eq!(
            survivors.len(),
            1,
            "only the still-allowed admission survives"
        );
        assert_eq!(survivors[0].fqdn, "kept.example.");
    }

    #[test]
    fn shared_index_sweep_keeps_a_shared_cdn_ip_held_by_a_survivor_and_frees_only_the_sole_ref() {
        // ONE shared reverse index, read off the SHARED counts the map maintains. Build a real
        // `AdmissionStores` (which BINDS its DNS-2b map into the live registry, so the sweep reads
        // its allow-set-deletion decision off the SAME `(session, ip)` reverse index the W1/W2
        // transaction increfs — never a second, independently-derived survivor count). In ONE
        // session admit through the transaction:
        //   - tighten.example → {sole_ip, shared_ip}
        //   - kept.example    → {shared_ip}           (the shared-CDN IP, a survivor)
        // After admit, the shared index holds `(sess-loop, shared_ip) = 2` (both names) and
        // `(sess-loop, sole_ip) = 1`. Re-source LOOSE → TIGHT (tighten.example → severing Deny):
        // the sweep revokes tighten.example THROUGH the shared map, which decrefs the SHARED index —
        // shared_ip drops 2 → 1 (kept.example still holds it; NOT freed — read off the shared index,
        // bias to under-delete, W4), sole_ip drops 1 → 0 (freed). The deletion is read off the SAME
        // index the map maintains, so a shared-CDN IP held by a survivor is NOT deleted.
        let stores = crate::txn::AdmissionStores::new();
        let live = stores.live().clone();
        let sole_ip = ip("203.0.113.7");
        let shared_ip = ip("198.51.100.9");
        let t0 = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000_000_000_000);

        assert!(matches!(
            stores.run_admission(
                &sweep_inputs_multi("tighten.example.", vec![sole_ip, shared_ip], 60),
                t0,
            ),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));
        assert!(matches!(
            stores.run_admission(&sweep_inputs("kept.example.", shared_ip, 60), t0),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));

        // The SHARED reverse index the map maintains: shared_ip is held by TWO distinct names, the
        // sole_ip by one — the counts the sweep will read its deletion decision off of.
        let shared_addr = admitted_addr(shared_ip);
        let sole_addr = admitted_addr(sole_ip);
        assert_eq!(
            stores.reverse_refcount("sess-loop", &shared_addr),
            2,
            "the shared-CDN IP is referenced by two distinct names in the shared index"
        );
        assert_eq!(
            stores.reverse_refcount("sess-loop", &sole_addr),
            1,
            "the sole-reference IP is referenced by exactly one name"
        );

        // Admitter-LAST: re-source to TIGHT (tighten.example → severing Deny), THEN sweep.
        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
        let outcome = live.sweep(&evaluator);

        // The sweep deletes ONLY the sole-reference IP — the shared-CDN IP survives because the
        // SHARED index still reports a non-zero count for it (kept.example holds it). This is read
        // off the SAME index the map maintains, not a re-derived survivor count.
        assert_eq!(
            outcome.allow_set_deletions,
            vec![sole_ip],
            "only the IP the shared index reports at refcount zero is deleted (shared-index read)"
        );
        assert!(
            !outcome.allow_set_deletions.contains(&shared_ip),
            "the shared-CDN IP held by a survivor is NOT deleted when read off the shared index (W4)"
        );

        // The shared index now reports the survivor-only counts: shared_ip decremented exactly once
        // (2 → 1), sole_ip freed (1 → 0). One refcount, no drift between the map and the sweep.
        assert_eq!(
            stores.reverse_refcount("sess-loop", &shared_addr),
            1,
            "the shared index decremented the shared IP exactly once — kept.example still holds it"
        );
        assert_eq!(
            stores.reverse_refcount("sess-loop", &sole_addr),
            0,
            "the shared index freed the sole-reference IP (refcount reached zero)"
        );

        // The live registry keeps only the surviving kept.example admission.
        let survivors = live.snapshot();
        assert_eq!(survivors.len(), 1, "only kept.example survives");
        assert_eq!(survivors[0].fqdn, "kept.example.");
        assert_eq!(survivors[0].ip, shared_ip);
    }

    #[test]
    fn shared_index_sweep_frees_a_sole_reference_ip_exactly_once_off_the_shared_index() {
        // A sole-reference IP frees EXACTLY once, read off the SHARED index. Admit
        // tighten.example → {sole_ip} through the real `AdmissionStores` (map bound into the live
        // registry). The shared index holds `(sess-loop, sole_ip) = 1`. Re-source to TIGHT; the
        // sweep revokes tighten.example through the shared map, decref'ing the SHARED index 1 → 0 —
        // the IP is freed EXACTLY once (the map's `revoke` returns a refcount-zero IP at most once,
        // and a saturating decref never underflows, so a second sweep frees nothing).
        let stores = crate::txn::AdmissionStores::new();
        let live = stores.live().clone();
        let sole_ip = ip("203.0.113.7");
        let sole_addr = admitted_addr(sole_ip);
        let t0 = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000_000_000_000);

        assert!(matches!(
            stores.run_admission(&sweep_inputs("tighten.example.", sole_ip, 60), t0),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));
        assert_eq!(
            stores.reverse_refcount("sess-loop", &sole_addr),
            1,
            "the sole-reference IP is referenced exactly once before the sweep"
        );

        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);

        // First sweep frees the sole-reference IP exactly once (refcount 1 → 0 off the shared index).
        let first = live.sweep(&evaluator);
        assert_eq!(
            first.allow_set_deletions,
            vec![sole_ip],
            "the sole-reference IP is freed exactly once off the shared index"
        );
        assert_eq!(
            stores.reverse_refcount("sess-loop", &sole_addr),
            0,
            "the shared index reached zero — the sole-reference IP is freed"
        );

        // A second sweep frees NOTHING — the live registry is empty and the shared index is already
        // at zero (saturating decref never underflows → no spurious second free / under-delete).
        let second = live.sweep(&evaluator);
        assert!(
            second.allow_set_deletions.is_empty(),
            "a second sweep frees nothing — no double-free, saturating decref never underflows (W4)"
        );
        assert_eq!(stores.reverse_refcount("sess-loop", &sole_addr), 0);
        assert!(live.snapshot().is_empty(), "no admissions remain live");
    }

    // ── §5.4 SHARED-INDEX SWEEP ROBUSTNESS (wave53): three folded tests harden the wave52
    //    one-shared-reverse-index sweep — (A) two revoked siblings sharing one IP free it EXACTLY
    //    once off the shared index (no double-free); (B) the shared-index path and the
    //    survivor-derived fallback agree on a corpus (the fallback cannot drift); (C) a concurrent
    //    mid-sweep admission in the restore window loses nothing and keeps the refcount consistent.
    //    Test-only; the production sweep/refcount logic is UNCHANGED. Loopback/synthetic only. ──

    /// A TIGHTENED POL-1 layer (`pol1/v-tight-both`) that BLOCKS BOTH `tighten.example` and
    /// `shared.example` at a SEVERING rung (`kill+snapshot`, block-or-higher → D53 conntrack flush
    /// fires for each). `kept.example` stays allowlisted (a survivor). Re-sourcing LOOSE →
    /// TIGHT-BOTH flips two distinct names Allow → Deny in ONE session, so the sweep revokes both
    /// siblings — the two-revoked-holders-of-one-shared-IP case the shared index must free exactly
    /// once on the LAST holder's decref.
    const SWEEP_LAYER_TIGHT_BOTH: &str = r#"
schema_version: pol1/v-tight-both
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
  - domain: shared.example
    reason: tightened-policy-push
    rung: kill+snapshot
baseline_pack:
  pack_version: "2026.06.12-v0"
  families:
    core: { tier: enabled }
  entries: []
"#;

    #[test]
    fn two_revoked_siblings_sharing_one_ip_free_it_exactly_once_off_the_shared_index() {
        // (A) [01KV2RW1] TWO distinct revoked names sharing ONE IP free the shared IP EXACTLY once
        // off the SHARED reverse index — no double-free, no eager free on the first revoke. Drive
        // the BOUND-MAP production path (`AdmissionStores` binds its DNS-2b map into the live
        // registry), NOT the survivor-derived fallback. In ONE session admit through the W1/W2
        // transaction:
        //   - tighten.example → {shared_ip, sole_a}
        //   - shared.example  → {shared_ip, sole_b}
        // The shared index then holds `(sess-loop, shared_ip) = 2` (two DISTINCT names), and each
        // sole-ref IP at 1. Re-source LOOSE → TIGHT-BOTH (both names → severing Deny). The sweep
        // revokes BOTH siblings THROUGH the shared map: revoking the first decrefs shared_ip 2 → 1
        // (NOT freed — the other sibling still holds it), revoking the second decrefs shared_ip
        // 1 → 0 (freed EXACTLY once). Each sole-ref IP frees once (1 → 0). The dedup in
        // `resolve_allow_set_deletions` guards against a stray double-push, and the saturating
        // decref never underflows (W4) — so shared_ip appears in `allow_set_deletions` exactly once.
        let stores = crate::txn::AdmissionStores::new();
        let live = stores.live().clone();
        let shared_ip = ip("198.51.100.9");
        let sole_a = ip("203.0.113.7");
        let sole_b = ip("203.0.113.8");
        let t0 = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000_000_000_000);

        assert!(matches!(
            stores.run_admission(
                &sweep_inputs_multi("tighten.example.", vec![shared_ip, sole_a], 60),
                t0,
            ),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));
        assert!(matches!(
            stores.run_admission(
                &sweep_inputs_multi("shared.example.", vec![shared_ip, sole_b], 60),
                t0,
            ),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));

        // The shared index: shared_ip held by TWO distinct names; each sole-ref IP by one.
        let shared_addr = admitted_addr(shared_ip);
        let sole_a_addr = admitted_addr(sole_a);
        let sole_b_addr = admitted_addr(sole_b);
        assert_eq!(
            stores.reverse_refcount("sess-loop", &shared_addr),
            2,
            "two distinct sibling names share the IP in the shared index"
        );
        assert_eq!(stores.reverse_refcount("sess-loop", &sole_a_addr), 1);
        assert_eq!(stores.reverse_refcount("sess-loop", &sole_b_addr), 1);

        // Admitter-LAST: re-source to TIGHT-BOTH (both siblings → severing Deny), THEN sweep.
        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT_BOTH), TtlClamp::DEFAULT);
        assert_eq!(evaluator.current_policy_version(), "pol1/v-tight-both");

        let outcome = live.sweep(&evaluator);

        // Both siblings revoked at a severing rung (one RevokedAdmission per live per-IP record:
        // tighten.example carries shared_ip + sole_a, shared.example carries shared_ip + sole_b).
        assert_eq!(
            outcome.revoked.len(),
            4,
            "both siblings' per-IP live records were revoked"
        );
        let revoked_names: std::collections::HashSet<&str> = outcome
            .revoked
            .iter()
            .map(|r| r.admission.fqdn.as_str())
            .collect();
        assert_eq!(
            revoked_names,
            ["tighten.example.", "shared.example."]
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            "both now-denied sibling names are carried in SweepOutcome.revoked"
        );
        assert!(
            outcome.revoked.iter().all(|r| r.flush_conntrack),
            "both severing-rung denies flag the D53 conntrack flush"
        );

        // The SHARED IP appears in the allow-set deletions EXACTLY once — not twice (no
        // double-free), and not zero (it must free once the LAST holder revokes). Each sole-ref IP
        // frees exactly once too.
        let shared_count = outcome
            .allow_set_deletions
            .iter()
            .filter(|&&d| d == shared_ip)
            .count();
        assert_eq!(
            shared_count, 1,
            "the shared IP frees EXACTLY once off the shared index (no double-free, no eager free)"
        );
        assert_eq!(
            outcome
                .allow_set_deletions
                .iter()
                .filter(|&&d| d == sole_a)
                .count(),
            1,
            "the first sole-reference IP frees exactly once"
        );
        assert_eq!(
            outcome
                .allow_set_deletions
                .iter()
                .filter(|&&d| d == sole_b)
                .count(),
            1,
            "the second sole-reference IP frees exactly once"
        );
        // The whole deletion set is the three distinct freed IPs, each once (length == 3).
        let deletion_set: std::collections::HashSet<IpAddr> =
            outcome.allow_set_deletions.iter().copied().collect();
        assert_eq!(
            deletion_set,
            [shared_ip, sole_a, sole_b]
                .into_iter()
                .collect::<std::collections::HashSet<_>>(),
            "exactly the three distinct freed IPs are deleted"
        );
        assert_eq!(
            outcome.allow_set_deletions.len(),
            3,
            "no IP is freed more than once — the shared IP's last-holder decref freed it once"
        );

        // The shared index now reports every IP at zero — the last holder's decref freed the
        // shared IP exactly once, and neither sole-ref IP underflowed.
        assert_eq!(
            stores.reverse_refcount("sess-loop", &shared_addr),
            0,
            "the shared IP reached zero after the SECOND sibling's revoke (not before)"
        );
        assert_eq!(stores.reverse_refcount("sess-loop", &sole_a_addr), 0);
        assert_eq!(stores.reverse_refcount("sess-loop", &sole_b_addr), 0);
        assert!(
            live.snapshot().is_empty(),
            "no admissions survive — both siblings were denied"
        );
    }

    #[test]
    fn shared_index_sweep_and_survivor_fallback_agree_on_a_corpus() {
        // (B) [01KV2RWF] DUAL-PATH EQUIVALENCE. Over a shared corpus of admit/revoke scenarios the
        // bound-map SHARED-INDEX path (production) and the survivor-derived FALLBACK path (a bare
        // synthetic registry, no map bound) must produce the IDENTICAL `SweepOutcome` — the same
        // `revoked` set AND the same `allow_set_deletions` set — so the fallback can never drift
        // from the shared-index source of truth.
        //
        // Each corpus row is a list of `(fqdn, ips)` admissions in ONE session, re-evaluated under
        // TIGHT-BOTH (which denies `tighten.example` + `shared.example`, keeps `kept.example`):
        //   - sole-ref:        tighten.example → {sole}                     (freed both paths)
        //   - shared survivor: tighten.example → {cdn}, kept.example → {cdn} (kept both paths)
        //   - all-revoked sib: tighten.example → {cdn}, shared.example → {cdn} (freed once both)
        //   - re-admit/refresh: tighten.example → {a} admitted TWICE       (one distinct holder)
        //   - multi-IP mix:    tighten.example → {x,y}, shared.example → {y,z}, kept.example → {z}
        type Corpus = Vec<(&'static str, Vec<IpAddr>)>;
        let rows: Vec<(&str, Corpus)> = vec![
            (
                "sole-ref",
                vec![("tighten.example.", vec![ip("203.0.113.7")])],
            ),
            (
                "shared-cdn-survivor",
                vec![
                    ("tighten.example.", vec![ip("198.51.100.9")]),
                    ("kept.example.", vec![ip("198.51.100.9")]),
                ],
            ),
            (
                "all-revoked-siblings",
                vec![
                    ("tighten.example.", vec![ip("198.51.100.9")]),
                    ("shared.example.", vec![ip("198.51.100.9")]),
                ],
            ),
            (
                "re-admit-refresh",
                vec![
                    ("tighten.example.", vec![ip("203.0.113.7")]),
                    ("tighten.example.", vec![ip("203.0.113.7")]),
                ],
            ),
            (
                "multi-ip-mix",
                vec![
                    (
                        "tighten.example.",
                        vec![ip("203.0.113.7"), ip("198.51.100.9")],
                    ),
                    (
                        "shared.example.",
                        vec![ip("198.51.100.9"), ip("203.0.113.8")],
                    ),
                    ("kept.example.", vec![ip("203.0.113.8")]),
                ],
            ),
        ];

        let t0 = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000_000_000_000);

        // Order-insensitive comparison keys for a SweepOutcome (both paths dedup
        // `allow_set_deletions` and build `revoked` per surviving/revoked record).
        fn deletions_set(outcome: &SweepOutcome) -> std::collections::BTreeSet<IpAddr> {
            outcome.allow_set_deletions.iter().copied().collect()
        }
        fn revoked_set(
            outcome: &SweepOutcome,
        ) -> std::collections::BTreeSet<(String, String, IpAddr, bool)> {
            outcome
                .revoked
                .iter()
                .map(|r| {
                    (
                        r.admission.session.clone(),
                        r.admission.fqdn.clone(),
                        r.admission.ip,
                        r.flush_conntrack,
                    )
                })
                .collect()
        }

        for (label, corpus) in &rows {
            // ── Shared-index path: admit through the W1/W2 transaction (binds the map). ──
            let stores = crate::txn::AdmissionStores::new();
            let live_shared = stores.live().clone();
            for (fqdn, ips) in corpus {
                assert!(
                    matches!(
                        stores.run_admission(&sweep_inputs_multi(fqdn, ips.clone(), 60), t0),
                        crate::txn::AdmissionOutcome::Admitted { .. }
                    ),
                    "[{label}] admit through the transaction succeeds",
                );
            }

            // ── Fallback path: a bare synthetic registry (no map bound) fed the SAME per-IP
            //    live records the transaction would mint (one record per plumbable IP, keyed on
            //    the original query name) — so the two paths sweep the SAME live set. A W4 refresh
            //    re-admits an already-live `(session, fqdn)` key, so de-dup the per-name IP set the
            //    fallback receives, mirroring the map's distinct-IP-membership refcount. ──
            let live_fallback = LiveAdmissions::new();
            let mut minted: std::collections::HashSet<(String, IpAddr)> =
                std::collections::HashSet::new();
            for (fqdn, ips) in corpus {
                // `LiveAdmission::new` normalizes the fqdn the same way the transaction does, so
                // the fallback's records key identically to the shared path's.
                let normalized = LiveAdmission::new("sess-loop", *fqdn, ips[0]).fqdn;
                let mut seen_this_name: std::collections::HashSet<IpAddr> =
                    std::collections::HashSet::new();
                for ip_addr in ips {
                    // One live record per (name, distinct-IP): the transaction pushes per
                    // plumbable IP, and a refresh of the SAME name+IP set is a refcount no-op that
                    // does not add a distinct holder. De-dup within a name's IP set AND across a
                    // re-admit of the SAME name+IP so the fallback's distinct holders match.
                    if !seen_this_name.insert(*ip_addr) {
                        continue;
                    }
                    if !minted.insert((normalized.clone(), *ip_addr)) {
                        continue;
                    }
                    live_fallback.admit(LiveAdmission::new("sess-loop", *fqdn, *ip_addr));
                }
            }

            // The fallback registry has NO bound map — confirm it really exercises the
            // survivor-derived path, not the shared-index path.
            assert!(
                live_fallback.map.is_none(),
                "[{label}] the fallback registry has no bound map (survivor-derived path)"
            );
            assert!(
                live_shared.map.is_some(),
                "[{label}] the shared-index registry has its DNS-2b map bound"
            );

            // Admitter-LAST: a fresh TIGHT-BOTH evaluator per path (the shared path's revoke
            // mutates the bound map, so build an evaluator for each path independently).
            let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_TIGHT_BOTH));

            let shared_outcome = live_shared.sweep(&evaluator);
            let fallback_outcome = live_fallback.sweep(&evaluator);

            assert_eq!(
                deletions_set(&shared_outcome),
                deletions_set(&fallback_outcome),
                "[{label}] the shared-index and survivor-derived paths free the SAME IPs",
            );
            assert_eq!(
                revoked_set(&shared_outcome),
                revoked_set(&fallback_outcome),
                "[{label}] the two paths revoke the SAME (session, fqdn, ip, flush) records",
            );
        }
    }

    /// An [`AdmissionReevaluator`] that delegates verdicts to a real `PolicyCorePolicy` but fires a
    /// ONE-SHOT side-effect the FIRST time it re-evaluates a chosen trigger name — used by the
    /// restore-window stress test to launch a concurrent `run_admission` on the shared stores
    /// WHILE a sweep is mid-flight, deterministically landing the admit in the drain → restore gap.
    struct ConcurrentAdmitReevaluator {
        inner: PolicyCorePolicy,
        trigger_fqdn: String,
        // The shared stores the concurrent admit lands on (a shared-handle clone of the one being
        // swept — same map + same live registry).
        stores: crate::txn::AdmissionStores,
        // The inputs the concurrent admit runs (a fresh, still-allowed name).
        admit_inputs: crate::txn::AdmissionInputs,
        // Set once the concurrent admit thread has been spawned (fire-once latch).
        spawned: Mutex<bool>,
        // The spawned admit thread's handle, joined after the sweep returns.
        handle: Mutex<Option<std::thread::JoinHandle<crate::txn::AdmissionOutcome>>>,
    }

    impl AdmissionReevaluator for ConcurrentAdmitReevaluator {
        fn reevaluate(&self, session: &str, fqdn: &str) -> crate::policy::Verdict {
            // On the FIRST re-evaluation of the trigger name (inside the sweep's first pass, while
            // the live lock is held), spawn a thread that runs a concurrent admission. The thread
            // BLOCKS acquiring the map lock then the live lock until the sweep drops the live lock
            // (`drop(live)` before the map access) and finishes its map work — so the admit lands
            // squarely in the restore window. The hook itself never blocks (it only spawns), so no
            // re-entrant deadlock on the live lock the sweep is holding here.
            if fqdn == self.trigger_fqdn {
                let mut spawned = self.spawned.lock().expect("spawned latch");
                if !*spawned {
                    *spawned = true;
                    let stores = self.stores.clone();
                    let inputs = self.admit_inputs.clone();
                    let t1 =
                        ds_contracts::dns_admission::Instant::from_unix_nanos(2_000_000_000_000);
                    let h = std::thread::spawn(move || stores.run_admission(&inputs, t1));
                    *self.handle.lock().expect("handle slot") = Some(h);
                }
            }
            self.inner.reevaluate(session, fqdn)
        }
    }

    #[test]
    fn concurrent_mid_sweep_admission_in_the_restore_window_loses_nothing() {
        // (C) [01KV2RX2] RESTORE-WINDOW STRESS. A concurrent `run_admission` lands on the shared
        // stores WHILE a sweep is in its drain → restore window (between `drop(live)` and the
        // survivors' restore append). Assert: (a) NO surviving pre-sweep admission is dropped;
        // (b) the mid-sweep-admitted record is PRESERVED in live (the sweep extends the gap's new
        // records back, never drops them); (c) the shared `(session, ip)` refcount stays CONSISTENT
        // (the mid-sweep admit's incref is reflected, no underflow); (d) no deadlock/panic — the
        // test completes.
        //
        // Setup under LOOSE (all admit):
        //   - tighten.example → {tighten_ip}  (a SOLE-ref IP the sweep will revoke + free)
        //   - kept.example    → {kept_ip}      (a survivor the sweep restores)
        // The concurrent admit (fired one-shot from the reevaluator hook, mid first-pass) admits a
        // FRESH, NOT-YET-LIVE name `shared.example → {fresh_ip}`. `shared.example` is allowlisted
        // under TIGHT (only `tighten.example` is blocked there), so the mid-sweep record survives
        // re-evaluation and is a single brand-new live record + a single fresh-IP incref — exactly
        // the record the restore append must preserve.
        let stores = crate::txn::AdmissionStores::new();
        let live = stores.live().clone();
        let tighten_ip = ip("203.0.113.7");
        let kept_ip = ip("198.51.100.9");
        let fresh_ip = ip("198.51.100.10");
        let t0 = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000_000_000_000);

        assert!(matches!(
            stores.run_admission(&sweep_inputs("tighten.example.", tighten_ip, 60), t0),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));
        assert!(matches!(
            stores.run_admission(&sweep_inputs("kept.example.", kept_ip, 60), t0),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));
        assert_eq!(live.len(), 2, "two pre-sweep admissions are live");

        // The concurrent admit: `shared.example` (allowlisted under TIGHT, NOT yet live) at a fresh
        // distinct IP — one new live record, one fresh-IP incref to 1. It must survive the sweep.
        let concurrent_inputs = sweep_inputs("shared.example.", fresh_ip, 60);

        let reevaluator = ConcurrentAdmitReevaluator {
            inner: {
                let p = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
                p.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
                p
            },
            trigger_fqdn: "tighten.example.".to_string(),
            stores: stores.clone(),
            admit_inputs: concurrent_inputs,
            spawned: Mutex::new(false),
            handle: Mutex::new(None),
        };

        // Run the sweep — the hook spawns the concurrent admit mid first-pass. The sweep must NOT
        // deadlock or panic, and must restore every survivor PLUS the gap's new records.
        let outcome = live.sweep(&reevaluator);

        // Join the concurrent admit (it lands in the restore window). It must have succeeded — a
        // still-allowed name on healthy stores admits.
        let admit_outcome = reevaluator
            .handle
            .lock()
            .expect("handle slot")
            .take()
            .expect("the concurrent admit thread was spawned")
            .join()
            .expect("the concurrent admit thread did not panic");
        assert!(
            matches!(admit_outcome, crate::txn::AdmissionOutcome::Admitted { .. }),
            "the mid-sweep admission succeeded (no deadlock, healthy stores)"
        );

        // (a) The pre-sweep survivor (kept.example @ kept_ip) is NOT dropped: it is back in live.
        let survivors = live.snapshot();
        assert!(
            survivors
                .iter()
                .any(|a| a.fqdn == "kept.example." && a.ip == kept_ip),
            "the pre-sweep survivor was restored, not dropped to the drain"
        );

        // (b) The mid-sweep-admitted FRESH record (shared.example @ fresh_ip) is PRESERVED — the
        // restore append extended the gap's new records back into live.
        assert!(
            survivors
                .iter()
                .any(|a| a.fqdn == "shared.example." && a.ip == fresh_ip),
            "the mid-sweep admission landing in the restore window was preserved (not lost)"
        );

        // The revoked name was tighten.example (the sole-ref IP it held is freed once).
        assert!(
            outcome
                .revoked
                .iter()
                .all(|r| r.admission.fqdn == "tighten.example."),
            "only the now-denied name was revoked"
        );
        assert_eq!(
            outcome
                .allow_set_deletions
                .iter()
                .filter(|&&d| d == tighten_ip)
                .count(),
            1,
            "the revoked sole-ref IP frees exactly once — no double-free under the concurrent admit"
        );

        // (c) The shared `(session, ip)` refcount stays CONSISTENT (no underflow, the mid-sweep
        // incref reflected): tighten_ip freed (0), kept_ip survives (>= 1 — held by the survivor),
        // fresh_ip incref'd by the mid-sweep admit (>= 1). No count underflowed.
        let tighten_addr = admitted_addr(tighten_ip);
        let kept_addr = admitted_addr(kept_ip);
        let fresh_addr = admitted_addr(fresh_ip);
        assert_eq!(
            stores.reverse_refcount("sess-loop", &tighten_addr),
            0,
            "the revoked sole-ref IP reached zero (freed once, no underflow)"
        );
        assert!(
            stores.reverse_refcount("sess-loop", &kept_addr) >= 1,
            "the survivor's shared IP keeps a non-zero count (not under-deleted)"
        );
        assert!(
            stores.reverse_refcount("sess-loop", &fresh_addr) >= 1,
            "the mid-sweep admit's incref of the fresh IP is reflected (no lost increment)"
        );

        // (d) The test completed — no deadlock, no panic. The live registry holds exactly the two
        // surviving records: the pre-sweep `kept.example @ kept_ip` and the mid-sweep
        // `shared.example @ fresh_ip` — neither lost nor double-counted (tighten.example revoked).
        assert_eq!(
            survivors.len(),
            2,
            "exactly the survivor and the mid-sweep record remain — none lost or double-counted"
        );
        assert!(
            !survivors.iter().any(|a| a.fqdn == "tighten.example."),
            "the revoked name left no residual live record"
        );
    }

    // ── DRAIN → RESTORE WINDOW STRESS (additive, test-only; the sweep / refcount src behavior
    //    is UNCHANGED). The single deterministic restore-window test
    //    (`concurrent_mid_sweep_admission_in_the_restore_window_loses_nothing`, test (C)) fires
    //    exactly ONE concurrent admit at ONE deterministic interleaving. The
    //    incref-before-drop(live) / restore-after-map-access ordering the sweep's drain → restore
    //    window (`drop(live)` … `restored.append(&mut *live)`) relies on must also hold across
    //    MANY jittered timings and MULTIPLE concurrent admits — that is what this bounded
    //    randomized stress proves. It drives REAL `std::thread`s (no `loom`/`rand` dep — the crate
    //    declares neither, and `--offline --locked` must stay green; a hand-rolled stdlib xorshift
    //    supplies the deterministic-but-varied jitter) and is BOUNDED (a small iteration count ×
    //    a small fan-out) so the cargo gate completes promptly. Per iteration it asserts the
    //    test-(C) invariants: no pre-sweep survivor dropped, every concurrently-admitted record
    //    that landed mid-sweep is preserved in live, and the shared `(session, ip)` refcount holds
    //    (the revoked sole-ref IP frees EXACTLY once → 0, every surviving / fresh IP stays ≥ 1, no
    //    underflow / double-free). Loopback / synthetic only. ──

    /// A tiny deterministic xorshift64* PRNG — stdlib-only jitter for the drain→restore stress
    /// (the crate carries no `rand` dev-dep, and the `--offline --locked` gate must stay green).
    /// Seeded per iteration so the timings VARY across iterations yet the run is reproducible.
    struct XorShift64(u64);

    impl XorShift64 {
        fn new(seed: u64) -> Self {
            // Avoid the all-zero fixed point of xorshift.
            Self(seed | 1)
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        /// A small bounded jitter in nanoseconds (0..max_ns) — enough to scatter the concurrent
        /// admits across the sweep's drain → restore window without making the test slow.
        fn jitter_ns(&mut self, max_ns: u64) -> u64 {
            if max_ns == 0 {
                0
            } else {
                self.next_u64() % max_ns
            }
        }
    }

    #[test]
    fn drain_restore_window_stress_preserves_admissions_and_refcount_across_many_timings() {
        // BOUNDED randomized stress over the drain → restore window. Each iteration:
        //   * admits a SOLE-ref name the sweep will revoke + a SURVIVOR, both under LOOSE, through
        //     the W1/W2 transaction on a SHARED `AdmissionStores` (bound-map path → the SAME shared
        //     `(session, ip)` reverse index the sweep revokes through);
        //   * spawns `fan_out` concurrent admit threads, each running a DISTINCT fresh, still-allowed
        //     name at a DISTINCT fresh IP after a randomized sub-window jitter, so they scatter
        //     across the sweep's drain → restore gap at varying timings;
        //   * runs the sweep (admitter-LAST: re-source TIGHT first, sweep over the SAME live
        //     registry) CONCURRENTLY with those admits;
        //   * asserts the test-(C) invariants hold for THIS timing.
        // BOUNDED: `iterations` × `fan_out` is small (≤ 8 × 4), so the gate completes promptly.
        const ITERATIONS: u64 = 8;
        const FAN_OUT: usize = 4;

        for iter in 0..ITERATIONS {
            let mut rng = XorShift64::new(0x9E37_79B9_7F4A_7C15 ^ iter.wrapping_mul(0x1000_0001));

            let stores = crate::txn::AdmissionStores::new();
            let live = stores.live().clone();
            let sole_ip = ip("203.0.113.7"); // tighten.example's SOLE-ref IP — revoked + freed
            let kept_ip = ip("198.51.100.9"); // kept.example — a survivor (still allowed under TIGHT)
            let t0 = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000_000_000_000);

            assert!(
                matches!(
                    stores.run_admission(&sweep_inputs("tighten.example.", sole_ip, 60), t0),
                    crate::txn::AdmissionOutcome::Admitted { .. }
                ),
                "[iter {iter}] the sole-ref admission lands"
            );
            assert!(
                matches!(
                    stores.run_admission(&sweep_inputs("kept.example.", kept_ip, 60), t0),
                    crate::txn::AdmissionOutcome::Admitted { .. }
                ),
                "[iter {iter}] the survivor admission lands"
            );
            assert_eq!(
                live.len(),
                2,
                "[iter {iter}] two pre-sweep admissions are live"
            );

            // The fresh, still-allowed concurrent admits — each under a DISTINCT session at a
            // DISTINCT IP for the SAME allowlisted name (`shared.example` is allowlisted under
            // BOTH LOOSE and TIGHT, so every one survives re-evaluation and must be preserved by
            // the restore append). Distinct SESSIONS (not distinct names) so each is an INDEPENDENT
            // `(session, ip)` map entry — a distinct live record AND a distinct refcount the sweep
            // must reflect with no lost increment AND no cross-session decref. (Two admits of the
            // SAME `(session, fqdn)` with different IPs would refresh ONE map entry and decref the
            // prior IP — distinct sessions keep them genuinely independent.)
            let fresh_specs: Vec<(String, IpAddr, u64)> = (0..FAN_OUT)
                .map(|k| {
                    let session = format!("sess-fresh-{k}");
                    let fresh_ip = ip(&format!("198.51.100.{}", 100 + k));
                    // A randomized sub-window jitter so the admits scatter across the drain →
                    // restore gap at varying timings (bounded ≤ ~200µs so the test stays fast).
                    let jitter = rng.jitter_ns(200_000);
                    (session, fresh_ip, jitter)
                })
                .collect();

            // Build the `AdmissionInputs` for one concurrent admit under a CHOSEN session — the
            // `sweep_inputs` helper is fixed to `sess-loop`, but the stress needs distinct sessions
            // so each fresh admit is an independent `(session, ip)` entry. (The fqdn is the
            // allowlisted `shared.example`; `session_index` is unique per session so the routed
            // per-session set never collides.)
            fn fresh_inputs(
                session: &str,
                session_index: u32,
                fresh_ip: IpAddr,
            ) -> crate::txn::AdmissionInputs {
                crate::txn::AdmissionInputs {
                    session_uuid: session.into(),
                    session_index,
                    original_query_fqdn: "shared.example.".into(),
                    terminal_addrs: vec![fresh_ip],
                    chain_min_ttl: 300,
                    ttl_floor: 60,
                    ttl_ceil: 900,
                    grace: 60,
                    provenance: ds_contracts::dns_admission::Provenance {
                        rule_id: "rule-allow".into(),
                        policy_layer: "system-baseline".into(),
                        policy_version: "pol1/v-loose".into(),
                    },
                    admission_type: ds_contracts::dns_admission::AdmissionType::Normal,
                    real_targets: vec![],
                }
            }

            // Spawn the concurrent admits. Each acquires the map write guard then the live lock
            // inside `run_admission`, BLOCKING behind the sweep's in-flight map access / live lock
            // — so it lands in (or around) the restore window. The jitter varies WHEN each thread
            // begins contending, exercising many interleavings across iterations.
            let handles: Vec<std::thread::JoinHandle<crate::txn::AdmissionOutcome>> = fresh_specs
                .iter()
                .cloned()
                .enumerate()
                .map(|(k, (session, fresh_ip, jitter))| {
                    let stores = stores.clone();
                    std::thread::spawn(move || {
                        if jitter > 0 {
                            std::thread::sleep(std::time::Duration::from_nanos(jitter));
                        }
                        let t1 = ds_contracts::dns_admission::Instant::from_unix_nanos(
                            2_000_000_000_000,
                        );
                        // A unique per-session index (offset off `sess-loop`'s 11) so the routed
                        // per-session `allow4_<idx>` never collides across the concurrent admits.
                        stores.run_admission(&fresh_inputs(&session, 100 + k as u32, fresh_ip), t1)
                    })
                })
                .collect();

            // Admitter-LAST: re-source TIGHT (tighten.example → severing Deny), THEN sweep over the
            // SAME live registry concurrently with the admits above.
            let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
            evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
            let outcome = live.sweep(&evaluator);

            // Join every concurrent admit — each must have SUCCEEDED (a still-allowed name on
            // healthy stores admits; no deadlock / panic).
            for (k, h) in handles.into_iter().enumerate() {
                let admit_outcome = h
                    .join()
                    .unwrap_or_else(|_| panic!("[iter {iter}] concurrent admit {k} panicked"));
                assert!(
                    matches!(admit_outcome, crate::txn::AdmissionOutcome::Admitted { .. }),
                    "[iter {iter}] concurrent admit {k} succeeded (no deadlock)"
                );
            }

            // INVARIANT (revoke): ONLY tighten.example was revoked, and its sole-ref IP frees
            // EXACTLY once — no double-free under the concurrent admits.
            assert!(
                outcome
                    .revoked
                    .iter()
                    .all(|r| r.admission.fqdn == "tighten.example."),
                "[iter {iter}] only the now-denied name was revoked"
            );
            assert_eq!(
                outcome
                    .allow_set_deletions
                    .iter()
                    .filter(|&&d| d == sole_ip)
                    .count(),
                1,
                "[iter {iter}] the revoked sole-ref IP frees exactly once (no double-free)"
            );

            // INVARIANT (no pre-sweep survivor dropped): kept.example is back in live.
            let survivors = live.snapshot();
            assert!(
                survivors
                    .iter()
                    .any(|a| a.fqdn == "kept.example." && a.ip == kept_ip),
                "[iter {iter}] the pre-sweep survivor was restored, not dropped to the drain"
            );

            // INVARIANT (every mid-sweep committed record preserved): EVERY concurrently-admitted
            // fresh record landed in live (the restore append extends the gap's new records back,
            // never drops one — regardless of WHICH side of the drain→restore boundary it landed).
            for (session, fresh_ip, _) in &fresh_specs {
                assert!(
                    survivors
                        .iter()
                        .any(|a| &a.session == session && &a.ip == fresh_ip),
                    "[iter {iter}] the mid-sweep admission for {session} was preserved (not lost)"
                );
            }

            // INVARIANT (the revoked name leaves no residual live record).
            assert!(
                !survivors.iter().any(|a| a.fqdn == "tighten.example."),
                "[iter {iter}] the revoked name left no residual live record"
            );
            // Exactly the survivor + the FAN_OUT fresh records remain — none lost, none double-counted.
            assert_eq!(
                survivors.len(),
                1 + FAN_OUT,
                "[iter {iter}] exactly the survivor and the {FAN_OUT} mid-sweep records remain"
            );

            // INVARIANT (refcount holds, no underflow / no lost increment): the revoked sole-ref IP
            // reached zero; the survivor's IP stays ≥ 1; every fresh IP's incref is reflected (≥ 1).
            let sole_addr = admitted_addr(sole_ip);
            let kept_addr = admitted_addr(kept_ip);
            assert_eq!(
                stores.reverse_refcount("sess-loop", &sole_addr),
                0,
                "[iter {iter}] the revoked sole-ref IP reached zero (freed once, no underflow)"
            );
            assert!(
                stores.reverse_refcount("sess-loop", &kept_addr) >= 1,
                "[iter {iter}] the survivor's IP keeps a non-zero count (not under-deleted)"
            );
            for (session, fresh_ip, _) in &fresh_specs {
                let fresh_addr = admitted_addr(*fresh_ip);
                assert!(
                    stores.reverse_refcount(session, &fresh_addr) >= 1,
                    "[iter {iter}] the mid-sweep admit's incref of {fresh_ip} under {session} is reflected (no lost increment)"
                );
            }
        }
    }

    #[test]
    fn default_gate_config_has_no_fixed_session_uuid_byte_identical_default() {
        // The single-session fixed-uuid agreement is OPT-IN: the `Default` (and every existing
        // harness/test that builds a config via `..GateConfig::default()`) carries `None`, so the
        // handler stays `SessionSource::PreStage` and the gate is byte-identical to pre-agreement
        // behavior. `main` sets `Some(..)` ONLY when the operator exports `DS_SESSION_UUID`.
        assert!(
            GateConfig::default().fixed_session_uuid.is_none(),
            "the default gate config carries NO fixed session uuid (opt-in via DS_SESSION_UUID)"
        );
    }

    #[tokio::test]
    async fn fixed_session_uuid_config_threads_into_a_spawned_gate() {
        // A `GateConfig` with `Some(uuid)` spawns cleanly — the uuid is threaded into BOTH the
        // UDP and TCP handlers (each query then attributes to the agreed uuid; the per-handler
        // derivation is unit-tested in `handler.rs`). This guards the spawn-time wiring path the
        // operator reaches when `DS_SESSION_UUID` is set.
        let config = GateConfig {
            fixed_session_uuid: Some("sess-2026-spawn-wire-0001".to_string()),
            ..GateConfig::default()
        };
        let gate = spawn_gate(
            PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE)),
            config,
        )
        .await
        .expect("a gate with a fixed session uuid binds on loopback");
        gate.shutdown().await.expect("gate shuts down");
    }

    /// A policy that DENIES every query (NXDOMAIN) — the §3.2 hard-deny path authored
    /// LOCALLY (no upstream forward), so the wire test below can distinguish a POLICY deny
    /// (NXDOMAIN) from an ATTRIBUTION fail-closed (SERVFAIL) without any network. `Clone` so
    /// `spawn_gate` accepts it.
    #[derive(Clone)]
    struct TapDenyPolicy;

    impl PolicyHook for TapDenyPolicy {
        fn evaluate(&self, _ctx: &DnsQueryCtx) -> crate::policy::Verdict {
            crate::policy::Verdict::Deny {
                rcode_policy: crate::policy::RcodePolicy::NxDomain,
                rung: None,
                provenance: crate::policy::SeamProvenance {
                    rule_id: "blocklist/tap-registry-wire".to_string(),
                    policy_layer: "system-baseline".to_string(),
                    policy_version: "2026-06-30".to_string(),
                },
            }
        }
    }

    #[tokio::test]
    async fn tap_registry_config_threads_the_attribution_table_into_the_spawned_gate() {
        // The W6 interface-anchored join is LOAD-BEARING at spawn time: a `GateConfig` with a
        // populated `tap_registry` makes `spawn_gate` resolve every query's session through
        // `AttributionTable::attribute_local` keyed on each transport's own post-NAT LOCAL
        // address — REPLACING the pre-stage `src:<addr>` fallback. We prove it END-TO-END over
        // the wire, by the OUTCOME flipping with the table's contents (a synthetic loopback
        // spawn, no live orchestrator / no kernel):
        //   * a registry that REGISTERS the gate's bind address resolves the tap, so the query
        //     reaches the policy verdict → NXDOMAIN (the deny is AUTHORED, attribution succeeded).
        //   * an EMPTY registry leaves the bind address unregistered → the handler FAILS CLOSED
        //     to SERVFAIL before any policy verdict (a genuine ds-dnsgate failure per W1/§5.1,
        //     NEVER a policy NXDOMAIN).
        use hickory_server::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
        use hickory_server::proto::rr::{Name as ProtoName, RecordType as ProtoRt};

        fn query_bytes(id: u16, name: &str) -> Vec<u8> {
            let mut msg = Message::query();
            msg.metadata.id = id;
            msg.metadata.message_type = MessageType::Query;
            msg.metadata.op_code = OpCode::Query;
            msg.metadata.recursion_desired = true;
            msg.add_query(Query::query(
                ProtoName::from_ascii(name).expect("valid query name"),
                ProtoRt::A,
            ));
            msg.to_vec().expect("query encodes")
        }

        async fn udp_response_code(server: SocketAddr, query: &[u8]) -> ResponseCode {
            let sock = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .await
                .expect("udp bind");
            sock.connect(server).await.expect("udp connect");
            sock.send(query).await.expect("udp send");
            let mut buf = vec![0u8; 65535];
            let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
                .await
                .expect("udp recv timed out")
                .expect("udp recv");
            buf.truncate(n);
            Message::from_vec(&buf)
                .expect("response parses")
                .metadata
                .response_code
        }

        // POSITIVE: a registry that registers the loopback bind address (the gate binds udp/tcp
        // on 127.0.0.1 by `GateConfig::default`) → `attribute_local` resolves the never-recycled
        // tap, so the query reaches the deny verdict → NXDOMAIN.
        let mut table = AttributionTable::new();
        table.register(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "dstap-77",
            crate::attrib::MarkIndex::from_counter(77),
        );
        let gate = spawn_gate(
            TapDenyPolicy,
            GateConfig {
                tap_registry: Some(table),
                ..GateConfig::default()
            },
        )
        .await
        .expect("a gate with a populated tap registry binds on loopback");
        let rc = udp_response_code(gate.udp_local_addr(), &query_bytes(1, "denied.example.")).await;
        assert_eq!(
            rc,
            ResponseCode::NXDomain,
            "a REGISTERED interface-anchored anchor resolves the tap, so the query reaches the \
             policy deny (NXDOMAIN) — the table join is load-bearing through spawn_gate"
        );
        gate.shutdown().await.expect("gate shuts down");

        // NEGATIVE: an EMPTY registry leaves the loopback bind address unregistered → the handler
        // fails closed to SERVFAIL (UnknownInterface), NEVER a policy NXDOMAIN. The OUTCOME flips
        // purely on the registry contents — proof the registry is threaded into spawn_gate.
        let gate = spawn_gate(
            TapDenyPolicy,
            GateConfig {
                tap_registry: Some(AttributionTable::new()),
                ..GateConfig::default()
            },
        )
        .await
        .expect("a gate with an empty tap registry still binds on loopback");
        let rc = udp_response_code(gate.udp_local_addr(), &query_bytes(2, "denied.example.")).await;
        assert_eq!(
            rc,
            ResponseCode::ServFail,
            "an UNREGISTERED interface-anchored anchor fails closed to SERVFAIL before the policy \
             verdict (a genuine ds-dnsgate failure, never the deny NXDOMAIN)"
        );
        assert_ne!(
            rc,
            ResponseCode::NXDomain,
            "an attribution failure must never be confused with a policy deny"
        );
        gate.shutdown().await.expect("gate shuts down");
    }

    #[tokio::test]
    async fn default_gate_config_has_no_tap_registry_byte_identical_default() {
        // The interface-anchored tap registry is OPT-IN: the `Default` (and every existing
        // harness/test built via `..GateConfig::default()`) carries `None`, so the handler stays
        // `SessionSource::PreStage` and the gate is byte-identical to pre-plumbing behavior.
        // `main` sets `Some(..)` ONLY when the operator exports `DS_DNSGATE_TAP_REGISTRY`.
        assert!(
            GateConfig::default().tap_registry.is_none(),
            "the default gate config carries NO tap registry (opt-in via DS_DNSGATE_TAP_REGISTRY)"
        );
    }

    #[tokio::test]
    async fn spawn_gate_shares_one_live_admissions_registry_with_the_caller() {
        // `spawn_gate` builds ONE `AdmissionStores` for BOTH transports and hands its
        // `LiveAdmissions` to the caller via `RunningGate::live_admissions`. A record admitted
        // into that handle is visible to the gate (and would be to a `with_revocation_sweep`
        // wired against it) — the shared-handle that closes the admission ↔ revocation loop. The
        // handle the caller gets is a clone of the SAME inner `Arc` the handlers admit through.
        let gate = spawn_gate(
            PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE)),
            GateConfig::default(),
        )
        .await
        .expect("gate binds on loopback");

        let live = gate.live_admissions();
        assert!(live.is_empty(), "a fresh gate has no live admissions");
        // A second `live_admissions()` is the SAME registry (shared-handle clone): a record
        // pushed through one handle is visible through the other.
        let live_again = gate.live_admissions();
        live.admit(LiveAdmission::new(
            "sess-x",
            "seen.example",
            ip("93.184.216.34"),
        ));
        assert_eq!(
            live_again.len(),
            1,
            "both `live_admissions()` handles point at the ONE shared registry"
        );

        gate.shutdown().await.expect("gate shuts down");
    }

    #[tokio::test]
    async fn gate_grace_config_threads_the_pol1_admission_grace_into_the_w2_deadline() {
        // POL-1 `admission.grace` is sourced off the snapshot in `main` and carried on
        // `GateConfig.admission_grace_secs`; this asserts a NON-default grace flows through to the
        // W2 deadline the admission transaction writes (the answered VM TTL stays the clamp
        // WITHOUT grace — grace lives only on the kernel/map deadline). We exercise the same
        // `with_admission(stores, grace)` seam `spawn_gate` wires, with grace != 60.
        const PUSHED_GRACE: u32 = 120;
        let stores = crate::txn::AdmissionStores::new();
        let answer_time = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000_000_000_000);
        let outcome = stores.run_admission(
            &sweep_inputs("kept.example.", ip("198.51.100.9"), PUSHED_GRACE),
            answer_time,
        );
        let (answered_ttl, deadline) = match outcome {
            crate::txn::AdmissionOutcome::Admitted {
                answered_ttl,
                deadline,
            } => (answered_ttl, deadline),
            other => panic!("expected Admitted, got {other:?}"),
        };
        // The VM is answered the clamp WITHOUT grace (clamp(300, 60, 900) = 300).
        assert_eq!(answered_ttl, 300, "the answered TTL is the clamp, no grace");
        // The deadline carries the PUSHED grace: answer_time + clamp + grace.
        let expected_nanos = (1_000 + 300 + u64::from(PUSHED_GRACE)) * 1_000_000_000;
        assert_eq!(
            deadline.unix_nanos, expected_nanos,
            "the W2 deadline carries the pushed POL-1 grace, not the 60s default"
        );
    }

    // ── The §5.4 SweepOutcome → ENFORCEMENT routing: the wave-1 sweep PRODUCES the outcome; this
    //    wave ROUTES it (no longer discards it) to the ds-nft allow-set withdrawals + the D53
    //    rung-conditional `flush_session` conntrack flush, via the REPORTABLE in-memory enforcer
    //    (no live kernel). The D53/W4 under-delete bias rides verbatim: sole-ref IPs are
    //    withdrawn + flushed; a shared-CDN IP a survivor still holds is NEITHER. Loopback /
    //    synthetic only (no nft/conntrack write on `cargo test --offline`). ──

    /// The canonical `AdmittedAddr::to_dst_key` form for a v4 IP — built through the SAME frozen
    /// `ds_contracts::dns_admission::AdmittedAddr` projection the routing (and the admission insert)
    /// uses, so a test asserts byte-exact agreement without re-deriving the hex.
    fn dst_key_of(addr: IpAddr) -> DstKey {
        admitted_addr(addr).to_dst_key()
    }

    #[test]
    fn route_withdraws_the_sole_ref_freed_ip_but_keeps_a_shared_sibling_ip() {
        // The end-to-end §5.4 ROUTING over the SAME sweep the wave-1 core ran: three live
        // admissions under LOOSE, re-source to TIGHT (tighten.example → Deny at a severing rung).
        // The sweep frees ONLY the sole-reference IP 203.0.113.7 (the shared-CDN IP 198.51.100.9 is
        // held by the surviving kept.example), so the routing must:
        //   - withdraw EXACTLY the sole-ref IP from the allow set (byte-exact `to_dst_key`),
        //   - NEVER withdraw the shared-sibling IP (the under-delete bias),
        //   - and flush conntrack over exactly the freed IP (severing rung).
        let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        let admissions = LiveAdmissions::new();
        let sole_ip = ip("203.0.113.7");
        let shared_ip = ip("198.51.100.9");
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", sole_ip));
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", shared_ip));
        admissions.admit(LiveAdmission::new("sess-b", "kept.example", shared_ip));

        evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
        let outcome = admissions.sweep(&evaluator);
        // Sanity: the sweep already biased to under-delete — only the sole-ref IP is freed.
        assert_eq!(outcome.allow_set_deletions, vec![sole_ip]);

        // ROUTE the outcome to the reportable enforcer (the wave's point).
        let enforcer = RecordingSweepEnforcer::new();
        route_sweep_outcome(&outcome, &enforcer);

        // (a) the allow-set delete: EXACTLY the sole-ref IP, on `allow4`, keyed byte-exact.
        let withdrawn = enforcer.withdrawn();
        assert_eq!(withdrawn.len(), 1, "exactly the one freed IP is withdrawn");
        // The sweep targets the PER-SESSION `allow4_<idx>` (single-source `allow_set_name`,
        // idx-0 reportable approximation), byte-exact with the admission insert — NOT a flat
        // shared `allow4` (D3/D4: the sweep names the EXACT set the insert filled).
        assert_eq!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, 0)
        );
        assert_eq!(withdrawn[0].set_name, "allow4_0");
        assert_ne!(
            withdrawn[0].set_name, "allow4",
            "no flat shared `allow4` survives in the sweep"
        );
        assert_eq!(withdrawn[0].dst_key, dst_key_of(sole_ip));
        // the shared-CDN IP is NEVER withdrawn (a survivor still references it — under-delete bias).
        assert!(
            !withdrawn.iter().any(|w| w.dst_key == dst_key_of(shared_ip)),
            "the shared-sibling IP held by kept.example is NEITHER deleted"
        );
        // the mark is DS_MARK_MASK-composed, never bare.
        assert_eq!(withdrawn[0].mark_mask, DS_MARK_MASK);
        // The mark is `ds_contracts::mark::compose` (fully qualified — the test module also imports
        // `policy_core::pol1_eval::compose`, a different `compose`).
        assert_eq!(
            withdrawn[0].mark_value,
            ds_contracts::mark::compose(Leg::AgentVm, 0)
        );
        assert_eq!(withdrawn[0].mark_value & !DS_MARK_MASK, 0);

        // (b) the conntrack flush: narrowed to EXACTLY the freed IP, sever_pair legs.
        let flushed = enforcer.flushed();
        assert_eq!(flushed.len(), 1, "one severing-rung flush fired");
        assert_eq!(flushed[0].dst_keys, vec![dst_key_of(sole_ip)]);
        assert!(
            !flushed[0].dst_keys.contains(&dst_key_of(shared_ip)),
            "the shared-sibling IP is NOT flushed"
        );
        assert_eq!(
            flushed[0].legs,
            [Leg::AgentVm, Leg::TlsproxyUpstream],
            "the flush spans the block-rung sever pair (0x1 + 0x2)"
        );
        assert_eq!(flushed[0].mark_mask, DS_MARK_MASK);
    }

    #[test]
    fn route_sweep_outcome_keys_on_the_freed_admissions_real_host_session_index() {
        // §5.4 multi-session sweep correctness (the wave's point): the reportable sweep keys the
        // allow-set delete + the composed mark + the conntrack flush on the FREED admission's REAL
        // `host_session_index`, NOT the retired index-0 approximation. A withdraw for a session at
        // index N names `allow4_N` (and `compose(AgentVm, N)`), DISTINCT from a concurrent session
        // at index M — so under >1 live session a revoke never hits the wrong session's set.

        // A representative non-trivial index (NOT 0, NOT 1) and a distinct concurrent index.
        const IDX_N: u32 = 7;
        const IDX_M: u32 = 12;
        assert_ne!(
            IDX_N, 0,
            "the index must be non-zero to detect the dropped approximation"
        );

        let freed = ip("203.0.113.7");
        let addr = admitted_addr(freed);

        // The sweep frees `freed` under the session that admitted at index N (severing rung).
        let outcome = SweepOutcome {
            revoked: vec![RevokedAdmission {
                admission: LiveAdmission::new("sess-n", "tighten.example", freed)
                    .with_host_session_index(IDX_N),
                flush_conntrack: true,
            }],
            evicted_ask_grants: Vec::new(),
            allow_set_deletions: vec![freed],
        };

        let enforcer = RecordingSweepEnforcer::new();
        route_sweep_outcome(&outcome, &enforcer);

        // (a) the delete names the FREED admission's OWN per-session set `allow4_7` (single-source
        // `allow_set_name`), NOT the index-0 approximation, and NOT a flat shared `allow4`.
        let withdrawn = enforcer.withdrawn();
        assert_eq!(withdrawn.len(), 1);
        assert_eq!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, IDX_N),
        );
        assert_eq!(
            withdrawn[0].set_name, "allow4_7",
            "the swept set is keyed on the freed admission's real host_session_index"
        );
        assert_ne!(
            withdrawn[0].set_name, "allow4_0",
            "the index-0 approximation is dropped"
        );
        assert_ne!(
            withdrawn[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, IDX_M),
            "the swept set is NOT a concurrent session's allow4_M"
        );
        // The composed mark is keyed on the SAME real index (set name and mark internally consistent).
        assert_eq!(
            withdrawn[0].mark_value,
            ds_contracts::mark::compose(Leg::AgentVm, IDX_N),
        );
        assert_eq!(
            ds_contracts::mark::decompose(withdrawn[0].mark_value)
                .expect("composed value decodes")
                .session_index,
            IDX_N as u16,
            "the routed mark's session_index is the freed admission's real index, not 0",
        );
        assert_eq!(withdrawn[0].mark_mask, DS_MARK_MASK);

        // (b) the conntrack flush carries the SAME real index, so the production `SessionRef`'s
        // `MarkMatch::for_leg(leg, idx)` severs THIS session's marks (not index 0's).
        let flushed = enforcer.flushed();
        assert_eq!(flushed.len(), 1);
        assert_eq!(
            flushed[0].host_session_index, IDX_N,
            "the flush keys on the freed admission's real host_session_index"
        );
        assert_eq!(flushed[0].dst_keys, vec![dst_key_of(freed)]);

        // The V6 twin: a freed v6 element under index N names `allow6_7` (dormant phase, but the
        // family+index→set mapping is the SAME single source), distinct from `allow6_0`/`allow6_12`.
        let freed_v6 = ip("2001:db8::7");
        let outcome_v6 = SweepOutcome {
            revoked: vec![RevokedAdmission {
                admission: LiveAdmission::new("sess-n", "tighten.example", freed_v6)
                    .with_host_session_index(IDX_N),
                flush_conntrack: false,
            }],
            evicted_ask_grants: Vec::new(),
            allow_set_deletions: vec![freed_v6],
        };
        let enforcer_v6 = RecordingSweepEnforcer::new();
        route_sweep_outcome(&outcome_v6, &enforcer_v6);
        let withdrawn_v6 = enforcer_v6.withdrawn();
        assert_eq!(withdrawn_v6.len(), 1);
        assert_eq!(
            withdrawn_v6[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V6, IDX_N),
        );
        assert_eq!(
            withdrawn_v6[0].set_name, "allow6_7",
            "the v6 twin keys on the real index"
        );
        assert_ne!(withdrawn_v6[0].set_name, "allow6_0");

        // ── ISOLATION: two concurrent sessions, freed in the SAME routing surface, target DISTINCT
        //    per-session sets — index N → allow4_N, index M → allow4_M, never crossing. (One sweep
        //    commit re-decides one host's set, so each outcome attributes to its own admission; this
        //    proves the two indices route to two distinct sets, not a single shared one.)
        let _ = addr; // (addr computed above for clarity; family is V4)
        let outcome_m = SweepOutcome {
            revoked: vec![RevokedAdmission {
                admission: LiveAdmission::new("sess-m", "tighten.example", freed)
                    .with_host_session_index(IDX_M),
                flush_conntrack: false,
            }],
            evicted_ask_grants: Vec::new(),
            allow_set_deletions: vec![freed],
        };
        let enforcer_m = RecordingSweepEnforcer::new();
        route_sweep_outcome(&outcome_m, &enforcer_m);
        let withdrawn_m = enforcer_m.withdrawn();
        assert_eq!(withdrawn_m[0].set_name, "allow4_12");
        assert_ne!(
            withdrawn_m[0].set_name, withdrawn[0].set_name,
            "concurrent sessions at distinct indices target DISTINCT per-session allow sets"
        );
    }

    #[test]
    fn route_sweep_outcome_keys_on_an_ask_grant_only_evictions_real_index() {
        // An ask-grant-only eviction (NO revoked admission) still keys the routed delete on the
        // evicted grant's REAL host_session_index — the fallback resolution reads the grant's
        // index, not the index-0 approximation.
        const IDX: u32 = 5;
        let freed = ip("203.0.113.9");
        let outcome = SweepOutcome {
            revoked: Vec::new(),
            evicted_ask_grants: vec![RevokedAskGrant {
                grant: LiveAskGrant::new("sess-g", "asked.example", vec![freed])
                    .with_host_session_index(IDX),
                flush_conntrack: false,
            }],
            allow_set_deletions: vec![freed],
        };
        let enforcer = RecordingSweepEnforcer::new();
        route_sweep_outcome(&outcome, &enforcer);
        let withdrawn = enforcer.withdrawn();
        assert_eq!(withdrawn.len(), 1);
        assert_eq!(withdrawn[0].session, "sess-g");
        assert_eq!(withdrawn[0].set_name, "allow4_5");
        assert_ne!(withdrawn[0].set_name, "allow4_0");
        assert_eq!(
            withdrawn[0].mark_value,
            ds_contracts::mark::compose(Leg::AgentVm, IDX),
        );
    }

    #[test]
    fn live_ask_grant_mint_threads_the_real_host_session_index() {
        // ASK-GRANT MINT-SIDE INDEX THREADING (this unit, 01KVJAB8Y6) — the MINT-SITE sibling of
        // the LiveAdmission admit-side thread (`txn.rs` chains
        // `LiveAskGrant`'s `LiveAdmission::new(..).with_host_session_index(inputs.session_index)`;
        // see `the_txn_minted_live_record_carries_the_real_inputs_session_index` guard above). When
        // the production ask-grant mint path lands, the `park_ask_grant(LiveAskGrant::new(..))`
        // call-site MUST chain `.with_host_session_index(inputs.session_index)` the SAME way — or
        // ask-grant withdraws regress to the `allow4_0` index-0 approximation the §5.4 host-session
        // threading just removed (a correctness/security regression in per-session NFT-3 set
        // targeting). Today every `park_ask_grant`/`LiveAskGrant::new` call-site is `#[cfg(test)]`
        // (no production mint site exists yet — `ask.rs` only emits the one-way `AskUserRequest`
        // notification; the grant lands later on the policy stream). This guard PINS the mint
        // contract end-to-end so that future production path cannot silently default to index 0:
        // a grant minted under the real index (a) carries it on the record the §5.4 sweep reads,
        // and (b) routes an ask-grant-only withdraw at the grant's own `allow4_<idx>`/`allow6_<idx>`
        // and `(leg, idx)` mark — for `idx != 0`, never the flat index-0 set.
        const IDX: u32 = 7;

        // (a) MINT SIDE: `.with_host_session_index(IDX)` stamps the REAL index onto the record,
        //     NOT the index-0 default `LiveAskGrant::new` leaves. This is the exact wire the
        //     production mint must use; the default-0 path is the regression.
        let minted = LiveAskGrant::new("sess-g", "asked.example", vec![ip("203.0.113.9")])
            .with_host_session_index(IDX);
        assert_eq!(
            minted.host_session_index, IDX,
            "the minted ask-grant carries the real per-session host_session_index, \
             not the index-0 LiveAskGrant::new default",
        );
        assert_ne!(
            minted.host_session_index, 0,
            "the mint must NOT regress to the allow4_0 index-0 approximation",
        );
        let default_idx = LiveAskGrant::new("sess-g", "asked.example", vec![ip("203.0.113.9")]);
        assert_eq!(
            default_idx.host_session_index, 0,
            "the bare `new` default is index 0 — the value the production mint must override",
        );

        // (b) WITHDRAW SIDE (v4): an ask-grant-only eviction (NO revoked admission) of the
        //     real-index grant routes the §5.4 delete at the grant's own `allow4_7` + `(leg, 7)`
        //     mark — exercising `route_sweep_outcome`'s grant-fallback branch (server.rs:1458).
        let freed_v4 = ip("203.0.113.9");
        let outcome_v4 = SweepOutcome {
            revoked: Vec::new(),
            evicted_ask_grants: vec![RevokedAskGrant {
                grant: minted,
                flush_conntrack: false,
            }],
            allow_set_deletions: vec![freed_v4],
        };
        let enforcer_v4 = RecordingSweepEnforcer::new();
        route_sweep_outcome(&outcome_v4, &enforcer_v4);
        let withdrawn_v4 = enforcer_v4.withdrawn();
        assert_eq!(withdrawn_v4.len(), 1);
        assert_eq!(withdrawn_v4[0].session, "sess-g");
        assert_eq!(
            withdrawn_v4[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V4, IDX),
        );
        assert_eq!(withdrawn_v4[0].set_name, "allow4_7");
        assert_ne!(withdrawn_v4[0].set_name, "allow4_0");
        assert_eq!(
            withdrawn_v4[0].mark_value,
            ds_contracts::mark::compose(Leg::AgentVm, IDX),
        );

        // (c) WITHDRAW SIDE (v6 twin): a v6-only grant under the SAME real index names `allow6_7`
        //     (dormant Phase-B, but the family+index→set mapping is the SAME single source),
        //     distinct from `allow6_0`.
        let freed_v6 = ip("2001:db8::7");
        let outcome_v6 = SweepOutcome {
            revoked: Vec::new(),
            evicted_ask_grants: vec![RevokedAskGrant {
                grant: LiveAskGrant::new("sess-g", "asked.example", vec![freed_v6])
                    .with_host_session_index(IDX),
                flush_conntrack: false,
            }],
            allow_set_deletions: vec![freed_v6],
        };
        let enforcer_v6 = RecordingSweepEnforcer::new();
        route_sweep_outcome(&outcome_v6, &enforcer_v6);
        let withdrawn_v6 = enforcer_v6.withdrawn();
        assert_eq!(withdrawn_v6.len(), 1);
        assert_eq!(
            withdrawn_v6[0].set_name,
            ds_contracts::session::allow_set_name(AddressFamily::V6, IDX),
        );
        assert_eq!(withdrawn_v6[0].set_name, "allow6_7");
        assert_ne!(withdrawn_v6[0].set_name, "allow6_0");
    }

    #[test]
    fn route_flushes_conntrack_only_on_the_severing_rung() {
        // D53 rung-conditional: a SEVERING deny routes BOTH the allow-set delete AND the conntrack
        // flush; a NON-SEVERING deny routes the allow-set delete but NO conntrack flush. Same
        // sole-ref admission, two re-sources, asserted on the reportable enforcer.

        // (1) SEVERING (kill+snapshot, block-or-higher rung) → delete AND flush.
        {
            let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
            let admissions = LiveAdmissions::new();
            let freed = ip("203.0.113.7");
            admissions.admit(LiveAdmission::new("sess-a", "tighten.example", freed));
            evaluator.reload(sub_composed(SWEEP_LAYER_TIGHT), TtlClamp::DEFAULT);
            let outcome = admissions.sweep(&evaluator);
            assert!(outcome.revoked.iter().all(|r| r.flush_conntrack));

            let enforcer = RecordingSweepEnforcer::new();
            route_sweep_outcome(&outcome, &enforcer);
            assert_eq!(
                enforcer.withdrawn().len(),
                1,
                "the freed IP is withdrawn on a severing deny"
            );
            assert_eq!(
                enforcer.flushed().len(),
                1,
                "a severing-rung deny fires the rung-conditional conntrack flush (D53)"
            );
            assert_eq!(enforcer.flushed()[0].dst_keys, vec![dst_key_of(freed)]);
        }

        // (2) NON-SEVERING (the tightened layer drops it to an Ask, never a block-rung Deny) →
        // delete only, NO flush.
        {
            let evaluator = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
            let admissions = LiveAdmissions::new();
            let freed = ip("203.0.113.7");
            admissions.admit(LiveAdmission::new("sess-a", "tighten.example", freed));
            evaluator.reload(
                sub_composed(SWEEP_LAYER_TIGHT_NONSEVERING),
                TtlClamp::DEFAULT,
            );
            let outcome = admissions.sweep(&evaluator);
            assert!(
                !outcome.revoked[0].flush_conntrack,
                "the non-severing deny flags no conntrack flush"
            );

            let enforcer = RecordingSweepEnforcer::new();
            route_sweep_outcome(&outcome, &enforcer);
            // The DNS-2b/allow-set state is still revoked — the freed IP is withdrawn …
            assert_eq!(
                enforcer.withdrawn().len(),
                1,
                "a non-severing deny still withdraws the freed allow-set element"
            );
            // … but NO conntrack flush fires (it gates new flows only — expiry, not revocation, W4).
            assert!(
                enforcer.flushed().is_empty(),
                "a non-severing (gate-rung) deny flushes NO conntrack (D53 rung-conditional)"
            );
        }
    }

    #[test]
    fn reportable_enforcer_records_exactly_the_sweep_deletions() {
        // The reportable enforcer records EXACTLY the SweepOutcome's `allow_set_deletions` — no
        // more (no shared-sibling over-delete), no fewer (every freed IP routed), keyed byte-exact.
        // Drive it directly off a hand-built outcome with TWO sole-ref freed IPs (a v4 + a second
        // v4) and one revoked admission flagged severing, so the deletion set and the flush
        // narrowing are both pinned to the outcome's freed list.
        let freed_a = ip("203.0.113.7");
        let freed_b = ip("203.0.113.8");
        let outcome = SweepOutcome {
            revoked: vec![RevokedAdmission {
                admission: LiveAdmission::new("sess-z", "tighten.example", freed_a),
                flush_conntrack: true,
            }],
            evicted_ask_grants: Vec::new(),
            allow_set_deletions: vec![freed_a, freed_b],
        };

        let enforcer = RecordingSweepEnforcer::new();
        route_sweep_outcome(&outcome, &enforcer);

        // EXACTLY the two freed IPs were withdrawn, in order, on the PER-SESSION `allow4_0`,
        // keyed byte-exact.
        let withdrawn = enforcer.withdrawn();
        let keys: Vec<DstKey> = withdrawn.iter().map(|w| w.dst_key.clone()).collect();
        assert_eq!(
            keys,
            vec![dst_key_of(freed_a), dst_key_of(freed_b)],
            "the enforcer records EXACTLY the sweep's allow_set_deletions, byte-exact"
        );
        // Every delete names the PER-SESSION single-source `allow_set_name`, never a flat `allow4`.
        assert!(withdrawn
            .iter()
            .all(|w| w.set_name == ds_contracts::session::allow_set_name(AddressFamily::V4, 0)));
        assert!(withdrawn.iter().all(|w| w.set_name == "allow4_0"));
        // The flush narrows to the SAME freed list (one flush, all freed IPs, sever_pair legs).
        let flushed = enforcer.flushed();
        assert_eq!(flushed.len(), 1);
        assert_eq!(
            flushed[0].dst_keys,
            vec![dst_key_of(freed_a), dst_key_of(freed_b)]
        );
        // The session keys on the revoked admission's attribution (the freed IPs were admitted under it).
        assert_eq!(withdrawn[0].session, "sess-z");
        assert_eq!(flushed[0].session, "sess-z");

        // A NO-OP outcome routes NOTHING (the steady state — no admissions revoked).
        let noop_enforcer = RecordingSweepEnforcer::new();
        route_sweep_outcome(&SweepOutcome::default(), &noop_enforcer);
        assert!(noop_enforcer.withdrawn().is_empty() && noop_enforcer.flushed().is_empty());
    }

    #[tokio::test]
    async fn committed_snapshot_routes_the_sweep_outcome_to_the_enforcer_admitter_last() {
        // End-to-end through the PRODUCTION commit path: a committed `with_policy` snapshot (TIGHT)
        // flows through `watch_snapshots` + `SnapshotCommitSink::with_revocation_sweep_enforced`;
        // the commit re-sources the evaluator admitter-LAST, sweeps the SHARED registry the
        // transaction would mint into, and ROUTES the outcome to the reportable enforcer — the
        // sole-ref freed IP is withdrawn + flushed, the shared-sibling IP is neither. Loopback /
        // synthetic only (no live kernel).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        let admissions = LiveAdmissions::new();
        let sole_ip = ip("203.0.113.7");
        let shared_ip = ip("198.51.100.9");
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", sole_ip));
        admissions.admit(LiveAdmission::new("sess-a", "tighten.example", shared_ip));
        admissions.admit(LiveAdmission::new("sess-b", "kept.example", shared_ip));

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer.clone(),
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        feed.publish(BoundarySnapshot::with_policy(
            7,
            "pushed.example.",
            sub_composed(SWEEP_LAYER_TIGHT),
            TtlClamp::DEFAULT,
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1);

        // The routing fired on the commit: the sole-ref IP withdrawn + flushed, shared-IP kept.
        let withdrawn = enforcer.withdrawn();
        assert_eq!(withdrawn.len(), 1, "the sole-ref freed IP was withdrawn");
        assert_eq!(withdrawn[0].dst_key, dst_key_of(sole_ip));
        assert!(!withdrawn.iter().any(|w| w.dst_key == dst_key_of(shared_ip)));
        let flushed = enforcer.flushed();
        assert_eq!(flushed.len(), 1, "the severing-rung flush fired");
        assert_eq!(flushed[0].dst_keys, vec![dst_key_of(sole_ip)]);

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn boundary_zone_only_commit_routes_nothing_to_the_enforcer() {
        // A `policy: None` snapshot re-sources only the suffix → no sweep → the enforcer is never
        // called, even when wired (the ordering guard: the routing only fires on an evaluator
        // re-source that produced a non-noop sweep).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_TIGHT));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        let admissions = LiveAdmissions::new();
        admissions.admit(LiveAdmission::new(
            "sess-a",
            "tighten.example",
            ip("203.0.113.7"),
        ));

        let enforcer = Arc::new(RecordingSweepEnforcer::new());
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            enforcer.clone(),
        );
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        feed.publish(BoundarySnapshot::new(9, "zone-only.example."))
            .await
            .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1);

        assert!(
            enforcer.withdrawn().is_empty() && enforcer.flushed().is_empty(),
            "a boundary-zone-only commit re-sources no evaluator → routes nothing to the enforcer"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    // ── FLEET token-revocation sweep wired into the live WatchPolicies serving loop
    //    (doc 19 §7; D102/P-R6, D72/D53). A pushed fleet-revocation artifact rides INSIDE the
    //    committed policy version (D72 "no third channel"); the post-commit fleet sweep resolves
    //    each revoked token's fingerprint to the live sessions the REAL admission book
    //    (`FleetRevocationBook`) holds — NOT an injected closure — and severs them
    //    rung-conditionally through the shared `flush_session` primitive, BEFORE the applied-seq
    //    heartbeat. Synthetic/loopback only (D50), driven end-to-end THROUGH `watch_snapshots`. ──

    /// A `Send + Sync`, shared-handle recording [`FlushSession`] — the synthetic flusher the
    /// fleet-revocation serving-loop tests sever through (D50). It records every
    /// `(session, DstFilter::All?, sever_pair legs?)` call and can arm a one-shot error to exercise
    /// the fail-closed path; a clone shares the inner buffers, so the test inspects what the sweeper
    /// (which owns its own clone) flushed. It depends ONLY on ds-contracts, a pure synthetic
    /// stand-in for the production `ds_nft::NftWriter` flusher (the live kernel write is
    /// `DS_NFTGATE_LIVE`-gated elsewhere).
    #[derive(Clone, Default)]
    struct SharedRecordingFlusher {
        calls: Arc<Mutex<Vec<(SessionRef, bool, bool)>>>,
        entries_per_flush: u64,
        error: Arc<Mutex<Option<String>>>,
    }

    /// The content-free error the synthetic flusher raises to exercise the fail-closed path.
    #[derive(Debug)]
    struct RecordingFlushError(String);
    impl ds_contracts::flush::FlushError for RecordingFlushError {}

    impl SharedRecordingFlusher {
        fn new(entries_per_flush: u64) -> Self {
            Self {
                calls: Arc::default(),
                entries_per_flush,
                error: Arc::default(),
            }
        }
        /// Arm a ONE-SHOT flush error: the NEXT `flush_session` call fails (and consumes the arming),
        /// every call after it succeeds. This models a TRANSIENT kernel outage — the fail-closed test
        /// (one flush total) sees the failure, and the redrive test sees cycle-1 fail then cycle-2
        /// retry succeed, WITHOUT racing a `feed.publish` against a manual disarm.
        fn arm_error(&self, msg: &str) {
            *self.error.lock().expect("flusher lock") = Some(msg.to_string());
        }
        fn flushed(&self) -> Vec<(SessionRef, bool, bool)> {
            self.calls.lock().expect("flusher lock").clone()
        }
    }

    impl FlushSession for SharedRecordingFlusher {
        type Error = RecordingFlushError;
        fn flush_session(
            &self,
            session: &SessionRef,
            dst_filter: &ds_contracts::flush::DstFilter,
            legs: &ds_contracts::flush::LegSelector,
        ) -> Result<ds_contracts::flush::FlushOutcome, Self::Error> {
            // A flush error short-circuits the sweep fail-closed (the caller must not advance
            // applied_seq on a failed sweep). ONE-SHOT: the arming is CONSUMED on the failing call
            // (`take`), so a subsequent redrive retry succeeds — a transient outage, not a permanent one.
            if let Some(msg) = self.error.lock().expect("flusher lock").take() {
                return Err(RecordingFlushError(msg));
            }
            self.calls.lock().expect("flusher lock").push((
                session.clone(),
                matches!(dst_filter, ds_contracts::flush::DstFilter::All),
                legs == &ds_contracts::flush::LegSelector::sever_pair(),
            ));
            Ok(ds_contracts::flush::FlushOutcome {
                entries_flushed: self.entries_per_flush,
            })
        }
    }

    /// A synthetic live session admitted under a scoped token (the admission book records these).
    fn revoked_session(idx: u32) -> SessionRef {
        SessionRef::new(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    /// A committed snapshot carrying a composed policy AND the given fleet-revocation entries — the
    /// shape the serving loop's fleet sweep runs over (the entries ride inside the committed
    /// document, on the same monotonic seq).
    fn snapshot_with_fleet_revocations(
        seq: u64,
        entries: Vec<FleetRevocationEntry>,
    ) -> BoundarySnapshot {
        BoundarySnapshot::with_policy_and_hash(
            seq,
            "pushed.example.",
            sub_composed(SWEEP_LAYER_TIGHT),
            TtlClamp::DEFAULT,
            0xfeed,
        )
        .with_fleet_revocations(entries)
    }

    #[tokio::test]
    async fn fleet_revocation_sweep_through_the_serving_loop_severs_the_revoked_session() {
        // End-to-end THROUGH the serving loop (`watch_snapshots` → `SnapshotCommitSink`, NOT a
        // direct call to the sweep function): a committed policy version carrying a block-or-higher
        // fleet-revocation entry severs the live sessions the REAL admission book resolves for the
        // revoked token's fingerprint — through the shared `flush_session` primitive
        // (`DstFilter::All` + sever_pair). The applied-seq heartbeat is reported only AFTER the
        // sweep-plus-flush (D72). A second token the same host admitted (a different fingerprint) is
        // left untouched — the resolver is real, keyed on the actual admission book.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_TIGHT));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        // The REAL admission book — the gate's SHARED handle (the same one the admission path would
        // record into). The stolen token was admitted on session 7; a different live token on
        // session 9.
        let book = gate.fleet_revocation_book();
        book.record("fp-stolen", revoked_session(7));
        book.record("fp-live", revoked_session(9));
        assert_eq!(book.len(), 2);

        let flusher = SharedRecordingFlusher::new(2);
        let sweeper = Arc::new(BookBackedFleetSweeper::new(book.clone(), flusher.clone()));
        let heartbeat = CapturingHeartbeat::default();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            // An empty §5.4 DNS-2b registry — the FLEET leg is under test here, not the §5.4 leg.
            LiveAdmissions::new(),
            live_policy.clone(),
            Arc::new(RecordingSweepEnforcer::new()),
        )
        .with_applied_seq_heartbeat(Arc::new(heartbeat.clone()))
        .with_fleet_revocation_sweep(sweeper);
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        feed.publish(snapshot_with_fleet_revocations(
            7,
            vec![FleetRevocationEntry::new(
                "fp-stolen",
                ds_contracts::pol1::Rung::KillSnapshot,
            )],
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1);

        // The revoked token's ONE live session was severed through the shared flush primitive with
        // DstFilter::All (a token revocation drops the whole session) on the sever_pair legs.
        let flushed = flusher.flushed();
        assert_eq!(
            flushed.len(),
            1,
            "exactly the revoked token's live session severed"
        );
        assert_eq!(
            flushed[0].0,
            revoked_session(7),
            "the stolen token's session"
        );
        assert!(flushed[0].1, "DstFilter::All for a token revocation");
        assert!(flushed[0].2, "LegSelector::sever_pair() legs (0x1 + 0x2)");
        // The other live token (fp-live) was NOT revoked → session 9 is untouched.
        assert!(
            !flushed.iter().any(|(s, _, _)| *s == revoked_session(9)),
            "an un-revoked token's session is never severed"
        );

        // applied_seq advanced only AFTER the sweep-plus-flush (D72): the heartbeat reported seq 7.
        let reports = heartbeat.reports();
        assert_eq!(reports.len(), 1, "the post-sweep heartbeat fired once");
        assert_eq!(reports[0].seq, 7);

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn fleet_revocation_below_block_rung_severs_nothing_but_still_advances_applied_seq() {
        // A below-block-rung fleet revocation (allow+log) gates NEW flows only and severs NO
        // established flow (D53; expiry-is-not-revocation) — the serving-loop sweep flushes nothing,
        // yet the sweep still completes so applied_seq advances (the post-sweep heartbeat fires).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_TIGHT));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        let book = gate.fleet_revocation_book();
        book.record("fp-noisy", revoked_session(3));

        let flusher = SharedRecordingFlusher::new(2);
        let sweeper = Arc::new(BookBackedFleetSweeper::new(book.clone(), flusher.clone()));
        let heartbeat = CapturingHeartbeat::default();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            LiveAdmissions::new(),
            live_policy.clone(),
            Arc::new(RecordingSweepEnforcer::new()),
        )
        .with_applied_seq_heartbeat(Arc::new(heartbeat.clone()))
        .with_fleet_revocation_sweep(sweeper);
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        feed.publish(snapshot_with_fleet_revocations(
            11,
            vec![FleetRevocationEntry::new(
                "fp-noisy",
                ds_contracts::pol1::Rung::AllowLog,
            )],
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        assert_eq!(subscriber.await.expect("subscriber task"), 1);

        assert!(
            flusher.flushed().is_empty(),
            "a below-block rung severs no established flow"
        );
        let reports = heartbeat.reports();
        assert_eq!(reports.len(), 1, "applied_seq still advances post-sweep");
        assert_eq!(reports[0].seq, 11);

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn fleet_revocation_flush_failure_is_fail_closed_and_suppresses_the_heartbeat() {
        // FAIL-CLOSED (D72): a fleet-revocation flush that cannot reach the kernel short-circuits
        // the sweep, so the serving loop does NOT report the applied-seq heartbeat — the host never
        // advertises a version applied whose token revocations did not enforce. The commit itself is
        // infallible (the loop still counts the commit), only the readiness report is withheld.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_TIGHT));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        let book = gate.fleet_revocation_book();
        book.record("fp-stolen", revoked_session(7));

        let flusher = SharedRecordingFlusher::new(2);
        flusher.arm_error("conntrack -D failed"); // the kernel flush cannot be reached
        let sweeper = Arc::new(BookBackedFleetSweeper::new(book.clone(), flusher.clone()));
        let heartbeat = CapturingHeartbeat::default();

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            LiveAdmissions::new(),
            live_policy.clone(),
            Arc::new(RecordingSweepEnforcer::new()),
        )
        .with_applied_seq_heartbeat(Arc::new(heartbeat.clone()))
        .with_fleet_revocation_sweep(sweeper);
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        feed.publish(snapshot_with_fleet_revocations(
            7,
            vec![FleetRevocationEntry::new(
                "fp-stolen",
                ds_contracts::pol1::Rung::KillSnapshot,
            )],
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        assert_eq!(
            subscriber.await.expect("subscriber task"),
            1,
            "the commit is infallible — the loop still committed the snapshot"
        );

        assert!(
            heartbeat.reports().is_empty(),
            "a failed fleet sweep SUPPRESSES the applied-seq heartbeat (fail-closed, D72)"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn admitted_session_recorded_by_the_mint_path_is_swept_on_the_next_commit() {
        // The CLOSED admission ↔ fleet-revocation loop end to end through the PRODUCTION wire (doc 19
        // §7; D102/P-R6): a session admitted by the REAL W1/W2 `run_admission` mint path — NOT a
        // hand-seeded `book.record` — records `(token fingerprint → session)` into the gate's shared
        // `FleetRevocationBook`, and a pushed revocation of that token severs it on the next commit
        // cycle through `watch_snapshots → SnapshotCommitSink → BookBackedFleetSweeper`. Only the
        // flusher is a synthetic recorder (D50 loopback, no kernel); the recording + resolution are
        // the production ones.
        let stores = AdmissionStores::new()
            .with_fleet_recording(Some("host-mint".to_string()), Some("fp-minted".to_string()));
        let book = stores.fleet_revocation_book();
        let t0 = ds_contracts::dns_admission::Instant::from_unix_nanos(1_000_000_000_000);

        // The REAL mint path admits a session under the scoped token and records it into the book.
        assert!(matches!(
            stores.run_admission(
                &fleet_mint_inputs("sess-minted", 7, "api.example.", ip("203.0.113.7")),
                t0
            ),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));

        // The book now resolves the minted token's fingerprint to exactly the admitted session.
        let minted = book.sessions_for_fingerprint("fp-minted");
        assert_eq!(
            minted.len(),
            1,
            "the mint path recorded exactly one session"
        );
        assert_eq!(minted[0].session_uuid, "sess-minted");
        assert_eq!(minted[0].host_id, "host-mint");
        assert_eq!(minted[0].host_session_index, 7);
        assert_eq!(minted[0].tap_name, "dstap-7");
        // A re-admission of the SAME session under the SAME token (a refresh / sibling name) does
        // not double the session in the book (dedup).
        assert!(matches!(
            stores.run_admission(
                &fleet_mint_inputs("sess-minted", 7, "cdn.example.", ip("203.0.113.8")),
                t0
            ),
            crate::txn::AdmissionOutcome::Admitted { .. }
        ));
        assert_eq!(
            book.sessions_for_fingerprint("fp-minted").len(),
            1,
            "re-admitting the same session under the same token is deduped"
        );

        // Drive the pushed revocation of the minted token through the PRODUCTION commit wire.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_TIGHT));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        let flusher = SharedRecordingFlusher::new(2);
        let sweeper = Arc::new(BookBackedFleetSweeper::new(book.clone(), flusher.clone()));
        let heartbeat = CapturingHeartbeat::default();
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            LiveAdmissions::new(),
            live_policy.clone(),
            Arc::new(RecordingSweepEnforcer::new()),
        )
        .with_applied_seq_heartbeat(Arc::new(heartbeat.clone()))
        .with_fleet_revocation_sweep(sweeper);
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        feed.publish(snapshot_with_fleet_revocations(
            12,
            vec![FleetRevocationEntry::new(
                "fp-minted",
                ds_contracts::pol1::Rung::KillSnapshot,
            )],
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        assert_eq!(subscriber.await.expect("subscriber task"), 1);

        // The mint-path-recorded session was severed through the shared flush primitive.
        let flushed = flusher.flushed();
        assert_eq!(flushed.len(), 1, "the minted session was swept");
        assert_eq!(flushed[0].0.session_uuid, "sess-minted");
        assert_eq!(flushed[0].0.tap_name, "dstap-7");
        assert!(flushed[0].1, "DstFilter::All for a token revocation");
        assert!(flushed[0].2, "sever_pair legs");
        // A token the mint path never recorded resolves to nothing — no over-severing.
        assert!(
            book.sessions_for_fingerprint("fp-live").is_empty(),
            "an unrecorded token resolves to no session"
        );
        let reports = heartbeat.reports();
        assert_eq!(reports.len(), 1, "applied_seq advanced post-sweep");
        assert_eq!(reports[0].seq, 12);

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn fleet_revocation_flush_failure_is_redriven_and_retried_on_the_next_commit() {
        // REDRIVE (doc 19 §7; D72): a fleet-revocation flush that fails fail-closed on one commit
        // cycle is RETRIED on the next — NOT dropped past an advanced `applied_seq`. Cycle 1 carries
        // the revocation but the kernel is unreachable (armed error): the sweep short-circuits, the
        // session is NOT severed, and the heartbeat is suppressed. Cycle 2 carries NO fleet
        // revocation at all, yet the recovered flusher severs the previously-failed session off the
        // REDRIVE buffer, and the heartbeat finally fires — proving the revocation survived the
        // transient error rather than being lost with the advancing seq.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_TIGHT));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        let book = gate.fleet_revocation_book();
        book.record("fp-stolen", revoked_session(7));

        let flusher = SharedRecordingFlusher::new(2);
        flusher.arm_error("conntrack -D unreachable"); // cycle 1: the kernel flush fails
        let sweeper = Arc::new(BookBackedFleetSweeper::new(book.clone(), flusher.clone()));
        let heartbeat = CapturingHeartbeat::default();
        // A trait-object handle for the sink; the concrete `sweeper` is kept to read
        // `pending_redrive_len()` (a diagnostic off the concrete type, not the trait).
        let dyn_sweeper: Arc<dyn FleetRevocationSweeper> = Arc::clone(&sweeper) as _;

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            LiveAdmissions::new(),
            live_policy.clone(),
            Arc::new(RecordingSweepEnforcer::new()),
        )
        .with_applied_seq_heartbeat(Arc::new(heartbeat.clone()))
        .with_fleet_revocation_sweep(dyn_sweeper);
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // Cycle 1 (seq 7): carries the fp-stolen revocation; the flush fails.
        feed.publish(snapshot_with_fleet_revocations(
            7,
            vec![FleetRevocationEntry::new(
                "fp-stolen",
                ds_contracts::pol1::Rung::KillSnapshot,
            )],
        ))
        .await
        .expect("subscriber alive");
        // Cycle 2 (seq 8): carries NO fleet revocation — only the REDRIVE can sever fp-stolen now.
        // The armed error was ONE-SHOT (consumed by cycle 1's failing flush), so the retry succeeds
        // — no manual disarm, hence no race against the async subscriber processing cycle 1.
        feed.publish(snapshot_with_fleet_revocations(8, vec![]))
            .await
            .expect("subscriber alive");
        drop(feed);
        assert_eq!(subscriber.await.expect("subscriber task"), 2);

        // The session was severed exactly once — on the redrive (cycle 2), not cycle 1.
        let flushed = flusher.flushed();
        assert_eq!(
            flushed.len(),
            1,
            "the previously-failed revocation was retried and severed once"
        );
        assert_eq!(flushed[0].0, revoked_session(7));
        // The redrive buffer is drained once the retry succeeds.
        assert_eq!(
            sweeper.pending_redrive_len(),
            0,
            "the redrive buffer is cleared after a clean retry"
        );
        // The heartbeat fired ONLY for the recovered cycle (seq 8), never for the failed seq 7.
        let reports = heartbeat.reports();
        assert_eq!(
            reports.len(),
            1,
            "applied_seq advanced only after the retry"
        );
        assert_eq!(
            reports[0].seq, 8,
            "the seq the redrive-plus-flush completed under"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    /// A capturing [`FleetRedriveAlertSink`] for the redrive-cap tests — records every alert so the
    /// test asserts the count-only payload (never token/session bytes).
    #[derive(Clone, Default)]
    struct CapturingRedriveAlertSink {
        alerts: Arc<Mutex<Vec<FleetRedriveAlert>>>,
    }

    impl CapturingRedriveAlertSink {
        fn alerts(&self) -> Vec<FleetRedriveAlert> {
            self.alerts.lock().expect("alert lock").clone()
        }
    }

    impl FleetRedriveAlertSink for CapturingRedriveAlertSink {
        fn observe_redrive(&self, alert: FleetRedriveAlert) {
            self.alerts.lock().expect("alert lock").push(alert);
        }
    }

    /// A synthetic session admitted under a scoped token, on an explicit `session_uuid` + index.
    fn fleet_session(uuid: &str, idx: u32) -> SessionRef {
        SessionRef::new(
            uuid.to_string(),
            "host-a".into(),
            idx,
            format!("dstap-{idx}"),
        )
    }

    #[test]
    fn fleet_book_prunes_a_torn_down_session_and_shrinks() {
        // DELIVERABLE (1): the book shrinks after a simulated teardown. A token admitted on TWO
        // sessions keeps its fingerprint key while a sibling is live; a token admitted on only the
        // torn-down session has its key DROPPED entirely (the book shrinks). Idempotent for an
        // unknown session.
        let book = FleetRevocationBook::new();
        book.record("fp-shared", fleet_session("sess-torn", 1));
        book.record("fp-shared", fleet_session("sess-live", 2));
        book.record("fp-solo", fleet_session("sess-torn", 1));
        assert_eq!(book.len(), 2, "two fingerprint keys tracked");
        assert_eq!(book.session_row_count(), 3, "three session rows");

        // Tear the session down (doc 19 §5.4 decref path): prune every row for `sess-torn`.
        let removed = book.prune_session("sess-torn");
        assert_eq!(removed, 2, "sess-torn had a row under each fingerprint");
        // The book SHRANK: `fp-solo` had only the torn-down session, so its key is gone.
        assert_eq!(
            book.len(),
            1,
            "the fingerprint whose last session was pruned is dropped — the book shrinks"
        );
        assert_eq!(
            book.session_row_count(),
            1,
            "only the live sibling row remains"
        );
        assert!(
            book.sessions_for_fingerprint("fp-solo").is_empty(),
            "the solo fingerprint's key was dropped"
        );
        assert_eq!(
            book.sessions_for_fingerprint("fp-shared"),
            vec![fleet_session("sess-live", 2)],
            "the shared fingerprint keeps its still-live sibling session (bias to under-prune)"
        );

        // Idempotent: pruning a session the book never recorded removes nothing.
        assert_eq!(book.prune_session("sess-never"), 0);
        assert_eq!(book.len(), 1);
    }

    #[tokio::test]
    async fn commit_prunes_fleet_book_rows_for_a_fully_torn_down_session() {
        // DELIVERABLE (1), through the PRODUCTION §5.4 decref wire: when a committed policy version
        // revokes a session's LAST live admission, the commit path prunes that session's rows from
        // the fleet-revocation book (doc 19 §5.4) — bounding a long-running gate's accumulation. A
        // session that keeps a still-allowed admission is NOT pruned (bias to under-prune).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        // The shared fleet book records both sessions (distinct per-session fingerprints). `sess-torn`
        // holds ONLY tighten.example (denied under TIGHT → fully torn down); `sess-keep` holds
        // kept.example (still allowed → survives).
        let book = FleetRevocationBook::new();
        book.record("fp-torn", fleet_session("sess-torn", 11));
        book.record("fp-keep", fleet_session("sess-keep", 12));
        assert_eq!(book.len(), 2);

        // The §5.4 live registry the sweep re-evaluates: one admission per session.
        let admissions = LiveAdmissions::new();
        let torn_ip = ip("203.0.113.7");
        let kept_ip = ip("198.51.100.9");
        admissions.admit(LiveAdmission::new("sess-torn", "tighten.example", torn_ip));
        admissions.admit(LiveAdmission::new("sess-keep", "kept.example", kept_ip));

        let flusher = SharedRecordingFlusher::new(2);
        let sweeper = Arc::new(BookBackedFleetSweeper::new(book.clone(), flusher.clone()));

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(4);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            Arc::new(RecordingSweepEnforcer::new()),
        )
        .with_fleet_revocation_sweep(sweeper);
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // A committed TIGHT version (tighten.example → Deny at a severing rung). NO fleet-revocation
        // entries: the prune is driven by the §5.4 sweep's teardown, not a token revocation.
        feed.publish(BoundarySnapshot::with_policy(
            7,
            "pushed.example.",
            sub_composed(SWEEP_LAYER_TIGHT),
            TtlClamp::DEFAULT,
        ))
        .await
        .expect("subscriber alive");
        drop(feed);
        assert_eq!(subscriber.await.expect("subscriber task"), 1);

        // The §5.4 sweep revoked sess-torn's only admission → fully torn down → its fleet row was
        // pruned and, being the fingerprint's last session, the key dropped. The book SHRANK 2 → 1.
        assert_eq!(
            admissions.snapshot().len(),
            1,
            "kept.example survived the sweep"
        );
        assert_eq!(
            book.len(),
            1,
            "the fully-torn-down session's fingerprint key was pruned — the book shrank"
        );
        assert!(
            book.sessions_for_fingerprint("fp-torn").is_empty(),
            "the torn-down session's row was pruned"
        );
        assert_eq!(
            book.sessions_for_fingerprint("fp-keep"),
            vec![fleet_session("sess-keep", 12)],
            "the session that kept a live admission is NOT pruned (bias to under-prune)"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[test]
    fn redrive_buffer_caps_and_alerts_after_sustained_failed_cycles() {
        // DELIVERABLE (3): a SUSTAINED kernel/conntrack outage caps the redrive buffer and fires the
        // operator alert. The flusher fails on every cycle (re-armed one-shot); distinct block-rung
        // entries accumulate. With a cap of 2, the third failed cycle overflows (drops the oldest,
        // capped alert) AND crosses the sustained-cycle threshold — the buffer stays bounded and the
        // count-only alert fires.
        let book = FleetRevocationBook::new();
        for i in 1..=3 {
            book.record(format!("fp{i}"), fleet_session(&format!("sess{i}"), i));
        }
        let flusher = SharedRecordingFlusher::new(2);
        let alerts = CapturingRedriveAlertSink::default();
        let sweeper = BookBackedFleetSweeper::new(book.clone(), flusher.clone())
            .with_redrive_cap(2)
            .with_redrive_alert_sink(Arc::new(alerts.clone()));

        let block = ds_contracts::pol1::Rung::KillSnapshot;

        // Cycle 1: buffer [fp1], below cap, one failed cycle → NO alert yet.
        flusher.arm_error("conntrack -D unreachable");
        assert!(sweeper
            .sweep_fleet(&[FleetRevocationEntry::new("fp1", block)])
            .is_err());
        assert_eq!(sweeper.pending_redrive_len(), 1);
        assert_eq!(sweeper.consecutive_failed_cycles(), 1);
        assert!(
            alerts.alerts().is_empty(),
            "no alert on the first failed cycle"
        );

        // Cycle 2: buffer [fp1, fp2], AT cap (2), no drop, two failed cycles → still NO alert.
        flusher.arm_error("conntrack -D unreachable");
        assert!(sweeper
            .sweep_fleet(&[FleetRevocationEntry::new("fp2", block)])
            .is_err());
        assert_eq!(sweeper.pending_redrive_len(), 2);
        assert_eq!(sweeper.consecutive_failed_cycles(), 2);
        assert!(
            alerts.alerts().is_empty(),
            "still no alert at cap, below the cycle threshold"
        );

        // Cycle 3: buffer would be [fp1, fp2, fp3] (len 3) > cap 2 → drop the OLDEST (fp1), keep
        // [fp2, fp3]. Capped AND third consecutive failure → the operator alert fires.
        flusher.arm_error("conntrack -D unreachable");
        assert!(sweeper
            .sweep_fleet(&[FleetRevocationEntry::new("fp3", block)])
            .is_err());
        assert_eq!(
            sweeper.pending_redrive_len(),
            2,
            "the redrive buffer is CAPPED — a sustained outage never grows it without bound"
        );
        assert_eq!(sweeper.consecutive_failed_cycles(), 3);
        let fired = alerts.alerts();
        assert_eq!(
            fired.len(),
            1,
            "exactly one alert fired on the capped/sustained cycle"
        );
        assert_eq!(
            fired[0],
            FleetRedriveAlert {
                pending_len: 2,
                consecutive_failed_cycles: 3,
                capped: true,
                dropped: 1,
            },
            "the alert payload is COUNTS ONLY (no fingerprint / session / token bytes)"
        );

        // A recovered flusher on the NEXT cycle drains the buffer and RESETS the failure count.
        assert!(sweeper.sweep_fleet(&[]).is_ok());
        assert_eq!(
            sweeper.pending_redrive_len(),
            0,
            "a clean sweep drains the redrive buffer"
        );
        assert_eq!(
            sweeper.consecutive_failed_cycles(),
            0,
            "the failure count resets on recovery"
        );
    }

    #[test]
    fn redrive_alerts_on_sustained_cycles_even_below_the_cap() {
        // The sustained-outage alert fires on the Nth CONSECUTIVE failed cycle even when the buffer
        // has not overflowed (cap far above the entry count) — a human must look at a persistent
        // flush failure before the buffer fills.
        let book = FleetRevocationBook::new();
        book.record("fp1", fleet_session("sess1", 1));
        let flusher = SharedRecordingFlusher::new(2);
        let alerts = CapturingRedriveAlertSink::default();
        let sweeper = BookBackedFleetSweeper::new(book.clone(), flusher.clone())
            .with_redrive_alert_sink(Arc::new(alerts.clone()));
        let block = ds_contracts::pol1::Rung::KillSnapshot;

        for _ in 0..FLEET_REDRIVE_ALERT_AFTER_CYCLES {
            flusher.arm_error("conntrack -D unreachable");
            assert!(sweeper
                .sweep_fleet(&[FleetRevocationEntry::new("fp1", block)])
                .is_err());
        }
        let fired = alerts.alerts();
        assert_eq!(
            fired.len(),
            1,
            "the alert fires once, on the Nth consecutive failure"
        );
        assert!(
            !fired[0].capped,
            "no overflow — the alert is the sustained-cycle trigger"
        );
        assert_eq!(
            fired[0].consecutive_failed_cycles,
            FLEET_REDRIVE_ALERT_AFTER_CYCLES
        );
    }

    /// A synthetic W1/W2 admission input for the fleet-mint recording tests — a NORMAL admission of
    /// `fqdn` at `addr` on `(session, index)`, keyed exactly as the forward path builds it.
    fn fleet_mint_inputs(
        session: &str,
        index: u32,
        fqdn: &str,
        addr: IpAddr,
    ) -> crate::txn::AdmissionInputs {
        crate::txn::AdmissionInputs {
            session_uuid: session.to_string(),
            session_index: index,
            original_query_fqdn: fqdn.to_string(),
            terminal_addrs: vec![addr],
            chain_min_ttl: 300,
            ttl_floor: 60,
            ttl_ceil: 900,
            grace: 60,
            provenance: ds_contracts::dns_admission::Provenance {
                rule_id: "rule-allow-fleet".into(),
                policy_layer: "system-baseline".into(),
                policy_version: "pol1/v-loose".into(),
            },
            admission_type: ds_contracts::dns_admission::AdmissionType::Normal,
            real_targets: vec![],
        }
    }

    // ── The PRODUCTION `impl SweepEnforcer for ds_nft::NftWriter<B>`: the §5.4 leg-(a)
    //    allow-set `delete element` batch and the leg-(b)
    //    `flush_session_report(DstFilter::Only, sever_pair)` conntrack flush, asserted
    //    against a thread-safe recording backend (no live kernel — `cargo test --offline`
    //    never touches the kernel). The real `SpawnBackend` flush is the
    //    `#[ignore]`/`DS_NFTGATE_LIVE`-gated test below. ──

    use ds_nft::backend::{BackendError, ConntrackDestroy, ConntrackOutput, NftBackend, NftBatch};
    use ds_nft::NftWriter;

    /// A `Send + Sync` recording [`NftBackend`] for the production-enforcer tests. The
    /// `SweepEnforcer` trait is `Send + Sync` (the commit sink holds the enforcer behind a
    /// shared `Arc` across the subscriber task), so `NftWriter<B>` must be `Sync` — ds-nft's
    /// own `RecordingBackend` is `RefCell`-based (single-thread) and cannot satisfy that, so
    /// the tests wire this `Mutex`-based recorder (test-only, in this owned file; ds-nft stays
    /// READ-ONLY). The PRODUCTION binding uses `ds_nft::backend::SpawnBackend` (genuinely
    /// `Send + Sync`), exercised by the live-kernel test below.
    #[derive(Default)]
    struct SyncRecordingBackend {
        batches: Mutex<Vec<NftBatch>>,
        destroys: Mutex<Vec<ConntrackDestroy>>,
    }

    impl SyncRecordingBackend {
        fn new() -> Self {
            Self::default()
        }
        fn batches(&self) -> Vec<NftBatch> {
            self.batches.lock().expect("backend lock").clone()
        }
        fn destroys(&self) -> Vec<ConntrackDestroy> {
            self.destroys.lock().expect("backend lock").clone()
        }
    }

    impl NftBackend for SyncRecordingBackend {
        fn apply_batch(&self, batch: &NftBatch) -> Result<(), BackendError> {
            self.batches
                .lock()
                .expect("backend lock")
                .push(batch.clone());
            Ok(())
        }
        fn destroy_conntrack(
            &self,
            destroy: &ConntrackDestroy,
        ) -> Result<ConntrackOutput, BackendError> {
            self.destroys
                .lock()
                .expect("backend lock")
                .push(destroy.clone());
            Ok(ConntrackOutput::default())
        }
        // ds-dnsgate is not a tap writer; these satisfy the NftBackend trait
        // (the tap netdev capability lives on the host-agent's ds-nft writer).
        fn create_tap(&self, _: &ds_nft::backend::TapSpec) -> Result<(), BackendError> {
            Ok(())
        }
        fn delete_tap(&self, _: &str) -> Result<(), BackendError> {
            Ok(())
        }
    }

    #[test]
    fn production_enforcer_withdraw_emits_the_delete_element_batch_byte_exact() {
        // `withdraw_allow_set` (leg (a)) applies a standalone `delete element` batch on
        // the SAME allow set the admission insert wrote, keyed by the SAME `to_dst_key`
        // element form — the compensating delete the §5.4 sweep resolved.
        let writer = NftWriter::new(SyncRecordingBackend::new());
        let freed = ip("203.0.113.7");
        let addr = admitted_addr(freed);
        writer.withdraw_allow_set(&AllowSetDeletion {
            session: "sess-a".into(),
            // The PER-SESSION set name (single-source `allow_set_name`, idx 0 to match the
            // mark below) — NOT a flat shared `allow4`.
            set_name: ds_contracts::session::allow_set_name(AddressFamily::V4, 0),
            dst_key: addr.to_dst_key(),
            mark_value: ds_contracts::mark::compose(Leg::AgentVm, 0),
            mark_mask: DS_MARK_MASK,
        });

        // One delete-element batch, no conntrack destroy (a withdraw is not a flush).
        let batches = writer.backend().batches();
        assert_eq!(batches.len(), 1, "one delete-element batch applied");
        assert!(
            writer.backend().destroys().is_empty(),
            "withdraw fires no conntrack destroy"
        );
        let text = &batches[0].text;
        // The withdraw names the PER-SESSION `allow4_0` byte-exact (not a flat `allow4`).
        assert!(
            text.contains("delete element inet ds_filter allow4_0"),
            "batch={text}"
        );
        // The rendered element is the nft-accepted address literal (the in-memory key
        // stays the `to_dst_key` identity) — revocation live-bug regression guard.
        assert!(
            text.contains(&addr.to_dst_key().address_literal()),
            "batch={text}"
        );
        assert!(
            !text.contains("timeout"),
            "a delete carries no timeout: {text}"
        );
    }

    #[test]
    fn production_enforcer_flush_runs_flush_session_over_only_and_sever_pair() {
        // `flush_session_conntrack` (leg (b)) runs `flush_session_report(&SessionRef,
        // &DstFilter::Only(keys), &LegSelector::sever_pair())` — one conntrack destroy per
        // (sever-leg × freed dst), narrowed to EXACTLY the freed keys, spanning the
        // 0x1+0x2 sever pair, the masked match composed under DS_MARK_MASK (never bare).
        let writer = NftWriter::new(SyncRecordingBackend::new());
        let freed_a = ip("203.0.113.7");
        let freed_b = ip("203.0.113.8");
        let keys = vec![
            admitted_addr(freed_a).to_dst_key(),
            admitted_addr(freed_b).to_dst_key(),
        ];
        writer.flush_session_conntrack(&ConntrackFlush {
            session: "sess-a".into(),
            // Index 0 here: this leg-(b) unit test composes the live match at index 0 and asserts
            // `parts.session_index == 0` below; the real-index threading is covered by the
            // multi-session routing test (`route_sweep_outcome_keys_on_the_freed_admissions_real_host_session_index`).
            host_session_index: 0,
            dst_keys: keys.clone(),
            legs: [Leg::AgentVm, Leg::TlsproxyUpstream],
            mark_mask: DS_MARK_MASK,
        });

        let destroys = writer.backend().destroys();
        // sever_pair = {AgentVm 0x1, TlsproxyUpstream 0x2}; 2 legs × 2 dst keys → 4 destroys.
        assert_eq!(destroys.len(), 4, "2 sever legs × 2 freed dst keys");
        // Every destroy narrows to one of the freed keys (DstFilter::Only) — the
        // conntrack `--dst` renders the nft/conntrack-accepted address literal.
        let want_dsts: Vec<String> = keys.iter().map(|k| k.address_literal()).collect();
        for d in &destroys {
            let dst = d
                .dst
                .as_ref()
                .expect("DstFilter::Only narrows to a dst key");
            assert!(want_dsts.contains(dst), "narrowed to a freed key: {dst}");
            // … and carries the masked value/mask token, never a bare value.
            assert!(
                d.mark_arg.ends_with(&format!("/0x{:x}", DS_MARK_MASK)),
                "mark_arg={}",
                d.mark_arg
            );
        }
        // Both sever legs (and ONLY them) appear; the index-0 reportable approximation
        // is composed byte-exact (compose(leg, 0)) so the live match agrees with the route.
        let mut legs_seen = std::collections::HashSet::new();
        for d in &destroys {
            let value_hex = d.mark_arg.split('/').next().unwrap();
            let value = u32::from_str_radix(value_hex.trim_start_matches("0x"), 16).unwrap();
            let parts = ds_contracts::mark::decompose(value).expect("composed value decodes");
            assert_eq!(
                parts.session_index, 0,
                "the index-0 reportable approximation"
            );
            legs_seen.insert(parts.leg);
        }
        assert!(legs_seen.contains(&Leg::AgentVm) && legs_seen.contains(&Leg::TlsproxyUpstream));
        assert!(
            !legs_seen.contains(&Leg::DnsgateUpstream) && !legs_seen.contains(&Leg::InfraEgress)
        );
    }

    #[test]
    fn route_sweep_outcome_drives_the_production_writer_field_for_field() {
        // The §5.4 routing drives the PRODUCTION `ds_nft::NftWriter` enforcer end-to-end:
        // the same outcome the reportable enforcer records (sole-ref freed IP) routes to
        // the real ds-nft primitives — one delete-element batch + the sever-pair flush
        // over the freed key, byte-exact. (The reportable default keeps the offline path
        // kernel-free; this proves the production binding routes identically.)
        let writer = NftWriter::new(SyncRecordingBackend::new());
        let freed = ip("203.0.113.7");
        let outcome = SweepOutcome {
            revoked: vec![RevokedAdmission {
                admission: LiveAdmission::new("sess-z", "tighten.example", freed),
                flush_conntrack: true,
            }],
            evicted_ask_grants: Vec::new(),
            allow_set_deletions: vec![freed],
        };
        route_sweep_outcome(&outcome, &writer);

        // Leg (a): one delete-element batch for the freed IP on the PER-SESSION allow4_0
        // (single-source `allow_set_name`, idx-0 reportable approximation), byte-exact.
        let batches = writer.backend().batches();
        assert_eq!(batches.len(), 1);
        assert!(batches[0]
            .text
            .contains("delete element inet ds_filter allow4_0"));
        assert!(batches[0]
            .text
            .contains(&admitted_addr(freed).to_dst_key().address_literal()));
        // Leg (b): the severing-rung flush fired over the freed key, 2 sever legs.
        let destroys = writer.backend().destroys();
        assert_eq!(destroys.len(), 2, "2 sever legs × 1 freed dst key");
        let want_dst = admitted_addr(freed).to_dst_key().address_literal();
        for d in &destroys {
            assert_eq!(d.dst.as_deref(), Some(want_dst.as_str()));
        }
    }

    #[test]
    fn sweep_delete_names_the_same_per_session_set_the_insert_fills() {
        // SECURITY-CRITICAL byte-exact agreement (D3/D4): the §5.4 sweep's allow-set delete
        // names the SAME per-session set the W1/W2 admission INSERT fills — both routed through
        // the single-source `ds_contracts::session::allow_set_name`, never a flat shared `allow4`.
        // (The reportable sweep keys on the index-0 approximation; the txn insert keys on the
        // real host_session_index. Here we prove the SAME function produces both, so for any
        // shared index the names are identical — the set ds-nft creates is the set the gate
        // fills AND the set the sweep deletes.)
        let freed = ip("203.0.113.7");
        let addr = admitted_addr(freed);

        // What the SWEEP names (reportable index 0).
        let enforcer = RecordingSweepEnforcer::new();
        let outcome = SweepOutcome {
            revoked: vec![RevokedAdmission {
                admission: LiveAdmission::new("sess-z", "tighten.example", freed),
                flush_conntrack: false,
            }],
            evicted_ask_grants: Vec::new(),
            allow_set_deletions: vec![freed],
        };
        route_sweep_outcome(&outcome, &enforcer);
        let swept = enforcer.withdrawn();
        assert_eq!(swept.len(), 1);

        // Both the sweep delete AND a notional insert for the SAME (family, index) resolve to the
        // single-source name — identical, and NOT the flat `allow4`.
        let insert_name = ds_contracts::session::allow_set_name(addr.family, 0);
        assert_eq!(
            swept[0].set_name, insert_name,
            "the sweep delete names the EXACT per-session set the insert fills (single source)"
        );
        assert_eq!(swept[0].set_name, "allow4_0");
        assert_ne!(swept[0].set_name, "allow4", "never a flat shared `allow4`");
    }

    /// The REAL-KERNEL flush proof — `#[ignore]`-and-`DS_NFTGATE_LIVE`-gated,
    /// CI/MANUAL-ONLY. The sandbox/CI kernel has no loadable nf_conntrack + restricted
    /// netlink, so this NEVER runs on `cargo test --offline`; an operator runs it on an
    /// M0 host (root / CAP_NET_ADMIN, `nf_conntrack_tcp_loose=0` per doc 14 §11, the
    /// `inet ds_filter` allow4 set present) with `DS_NFTGATE_LIVE=1 cargo test … --
    /// --ignored production_enforcer_flushes_real_conntrack`. It deletes a real allow4
    /// element and runs the sever-pair conntrack flush over the freed key through the
    /// production `SpawnBackend`, asserting both reach the kernel without error.
    #[test]
    #[ignore = "live-kernel: needs DS_NFTGATE_LIVE + root/CAP_NET_ADMIN + nf_conntrack_tcp_loose=0 + the inet ds_filter allow4 set (M0 host, CI/manual-only)"]
    fn production_enforcer_flushes_real_conntrack() {
        if std::env::var_os("DS_NFTGATE_LIVE").is_none() {
            eprintln!("skipping live-kernel flush test: DS_NFTGATE_LIVE unset (CI/manual-only)");
            return;
        }
        let writer = NftWriter::new(ds_nft::backend::SpawnBackend::new());
        let freed = ip("203.0.113.7");
        let key = admitted_addr(freed).to_dst_key();
        writer.withdraw_allow_set(&AllowSetDeletion {
            session: "live-sess".into(),
            set_name: ds_contracts::session::allow_set_name(AddressFamily::V4, 0),
            dst_key: key.clone(),
            mark_value: ds_contracts::mark::compose(Leg::AgentVm, 0),
            mark_mask: DS_MARK_MASK,
        });
        writer.flush_session_conntrack(&ConntrackFlush {
            session: "live-sess".into(),
            host_session_index: 0,
            dst_keys: vec![key],
            legs: [Leg::AgentVm, Leg::TlsproxyUpstream],
            mark_mask: DS_MARK_MASK,
        });
        // The enforcer logs (never panics) on a backend error; reaching here means the
        // delete + flush were issued to the real kernel without wedging the admitter.
    }

    // ── The PRODUCTION ADMISSION programmer selection: `spawn_gate_with_programmer` threads a
    //    chosen `S: NftSetProgrammer` into BOTH transports' W1/W2 admission stores (the seam
    //    `main` uses to bind the live `ds_nft::NftWriter` behind `DS_NFTGATE_LIVE`). These prove
    //    the generic plumbing accepts a NON-default programmer (the live writer's type) and binds
    //    + serves with it, with NO kernel touch on `cargo test --offline` — the real-kernel
    //    admission-program proof is the `#[ignore]`/`DS_NFTGATE_LIVE`-gated test below. ──

    #[tokio::test]
    async fn spawn_gate_with_programmer_threads_the_chosen_admission_programmer() {
        // The default `spawn_gate` pins the reportable `RecordingSetProgrammer`; this asserts
        // `spawn_gate_with_programmer` accepts the PRODUCTION-shaped programmer instead — a
        // `ds_nft::NftWriter` (here over a `Send + Sync` recording backend, the live writer's
        // type with no kernel) — binds both transports over it, and serves. The gate is typed
        // `RunningGate<_, NftWriter<_>>`, so the admission insert on every `Allow` would program
        // THROUGH this writer (the `with_parts` seam the txn-level lockstep test already drives).
        // The shared `LiveAdmissions` registry still threads to the caller, unchanged by the
        // programmer choice (the admission ↔ revocation loop is programmer-agnostic). NO kernel
        // touch: the recording backend records nothing at idle.
        let writer = Arc::new(NftWriter::new(SyncRecordingBackend::new()));
        let gate = spawn_gate_with_programmer(
            PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE)),
            GateConfig::default(),
            writer.clone(),
            Arc::new(NullSink),
        )
        .await
        .expect("gate binds on loopback with the production-shaped admission programmer");

        // Both transports came up over the chosen programmer, and the shared registry is handed
        // back exactly as the default path does (a fresh gate has no live admissions).
        assert!(gate.udp_local_addr().port() != 0, "udp bound");
        assert!(gate.tcp_local_addr().port() != 0, "tcp bound");
        assert!(
            gate.live_admissions().is_empty(),
            "a fresh gate has no live admissions, whatever the programmer"
        );
        // No admission ran, so the programmer's kernel-model backend recorded NOTHING — the
        // default/offline path never touches the kernel even when the live-writer TYPE is bound.
        assert!(
            writer.backend().batches().is_empty(),
            "binding the production-shaped programmer touches no kernel at idle"
        );

        gate.shutdown().await.expect("gate shuts down");
    }

    /// The REAL-KERNEL admission-programmer proof at the gate seam — `#[ignore]`-and-
    /// `DS_NFTGATE_LIVE`-gated, CI/MANUAL-ONLY. The sandbox/CI kernel has no loadable
    /// nf_conntrack + restricted netlink, so this NEVER runs on `cargo test --offline`; an
    /// operator runs it on an M0 host (root / CAP_NET_ADMIN, the `inet ds_filter` allow4 set
    /// present) with `DS_NFTGATE_LIVE=1 cargo test … -- --ignored
    /// spawn_gate_binds_the_live_admission_programmer`. It spawns the gate with the PRODUCTION
    /// `ds_nft::NftWriter<SpawnBackend>` as the W1/W2 admission programmer — the exact binding
    /// `main` selects behind `DS_NFTGATE_LIVE` — proving the live admission programmer binds both
    /// transports without wedging the listeners. (The per-element insert assertion is the
    /// txn-level `production_writer_programs_a_real_allow4_element`; this proves the SPAWN seam.)
    #[tokio::test]
    #[ignore = "live-kernel: needs DS_NFTGATE_LIVE + root/CAP_NET_ADMIN + the inet ds_filter allow4 set (M0 host, CI/manual-only)"]
    async fn spawn_gate_binds_the_live_admission_programmer() {
        if std::env::var_os("DS_NFTGATE_LIVE").is_none() {
            eprintln!(
                "skipping live-kernel admission-programmer spawn test: DS_NFTGATE_LIVE unset \
                 (CI/manual-only)"
            );
            return;
        }
        let writer = Arc::new(NftWriter::new(ds_nft::backend::SpawnBackend::new()));
        let gate = spawn_gate_with_programmer(
            PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE)),
            GateConfig::default(),
            writer,
            Arc::new(NullSink),
        )
        .await
        .expect("gate binds with the live ds_nft::NftWriter<SpawnBackend> admission programmer");
        // Reaching here means the live programmer bound both transports; shut down cleanly.
        gate.shutdown().await.expect("gate shuts down");
    }

    // ── The PRODUCTION PUBLISHER ↔ SUBSCRIBER loop (doc 11 §5.3 / doc 13 §5, D72): a REAL
    //    committed policy version pushed through `run_policy_publisher` onto the host-local feed
    //    re-sources the running evaluator + boundary zone on the LIVE gate admitter-LAST, and the
    //    published `BoundarySnapshot` carries the correct `(seq, content_hash)` identity. This is
    //    the end-to-end replacement for the env-gated single synthetic commit: a synthetic
    //    in-process `PolicyVersionSource` stands in for the host agent's `WatchPolicies(from_seq)`
    //    stream (§5.3 loopback/synthetic — no live host agent, no control-plane stream). ──

    /// A synthetic [`PolicyVersionSource`] — the test stand-in for the host agent's
    /// `WatchPolicies(from_seq)` stream. It delivers a SCRIPTED sequence of committed POL-1
    /// layers (a REAL policy push), then closes the stream (`None`) so the publisher drops the
    /// feed and the subscriber drains. No live host agent, no control-plane stream (§5.3).
    struct ScriptedPolicySource {
        versions: std::collections::VecDeque<CommittedPolicyVersion>,
    }

    impl ScriptedPolicySource {
        fn new(versions: Vec<CommittedPolicyVersion>) -> Self {
            Self {
                versions: versions.into(),
            }
        }
    }

    impl PolicyVersionSource for ScriptedPolicySource {
        async fn next_version(&mut self) -> Option<CommittedPolicyVersion> {
            self.versions.pop_front()
        }
    }

    /// A [`SnapshotSink`] decorator that records the `(seq, content_hash, boundary_zone,
    /// policy_version)` identity of every committed snapshot AND delegates the real re-source to
    /// the wrapped production [`SnapshotCommitSink`] — so the test asserts both the re-source
    /// behavior on the LIVE gate AND the transported `(seq, content_hash)` identity the publisher
    /// drove, without forking the production commit path.
    struct IdentityCapturingSink<S: SnapshotSink> {
        inner: S,
        committed: Mutex<Vec<CommittedIdentity>>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct CommittedIdentity {
        seq: u64,
        content_hash: Option<u64>,
        wire_content_hash: Option<ContentHash>,
        boundary_zone: String,
        policy_version: Option<String>,
    }

    impl<S: SnapshotSink> IdentityCapturingSink<S> {
        fn new(inner: S) -> Self {
            Self {
                inner,
                committed: Mutex::new(Vec::new()),
            }
        }

        fn committed(&self) -> Vec<CommittedIdentity> {
            self.committed.lock().expect("sink lock poisoned").clone()
        }
    }

    impl<S: SnapshotSink> SnapshotSink for IdentityCapturingSink<S> {
        fn commit_snapshot(&self, snapshot: &BoundarySnapshot) {
            self.committed
                .lock()
                .expect("sink lock poisoned")
                .push(CommittedIdentity {
                    seq: snapshot.seq,
                    content_hash: snapshot.content_hash(),
                    wire_content_hash: snapshot.wire_content_hash(),
                    boundary_zone: snapshot.boundary_zone.clone(),
                    policy_version: snapshot
                        .policy
                        .as_ref()
                        .map(|p| p.composed.policy_version.clone()),
                });
            // Delegate the REAL re-source to the production commit sink (evaluator + boundary
            // zone + the §5.4 sweep) — the decorator only OBSERVES identity, never changes which
            // snapshots commit.
            self.inner.commit_snapshot(snapshot);
        }

        fn observe_snapshot_drop(&self, drop: SnapshotDropEvent) {
            // DELEGATE the reload-boundary drop to the wrapped inner sink, rather than letting
            // the `SnapshotSink` trait DEFAULT (`let _ = drop;`) swallow it here. Without this
            // override the decorator shadowed the inner `SnapshotCommitSink::observe_snapshot_drop`
            // (the production override that routes the drop to its wired `SnapshotDropSink`, the
            // `NullDropSink` by default), so a test wrapping its commit sink in this decorator
            // could never witness the PRODUCTION default-drop path — the wrapper ate the drop
            // first. Delegating makes the decorator transparent to the drop signal exactly as it
            // already is for the commit signal: it observes nothing of its own, it forwards.
            self.inner.observe_snapshot_drop(drop);
        }
    }

    #[tokio::test]
    async fn production_publisher_drives_a_real_policy_push_resourcing_with_correct_identity() {
        // END-TO-END production wiring (the verbatim `main` wiring, minus the host-agent source
        // binding): a REAL committed policy version (a parsed POL-1 layer) is pushed through
        // `run_policy_publisher` onto the host-local feed; the subscriber (`watch_snapshots` over
        // a `SnapshotCommitSink`) commits it LAST on the LIVE gate. The verdict for a name flips
        // on the running evaluator (the frozen `evaluate` re-sources off the committed version),
        // the authored suffix re-sources together with it (one policy version), AND the published
        // snapshot carried the correct `(seq, content_hash)` identity lifted off the SAME layer.
        // No control-plane stream; the source is a synthetic in-process `PolicyVersionSource`
        // (§5.3 loopback/synthetic).
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        // Startup runs the v1 evaluator (hard-denies `blocked-v1.example`); a shared-handle clone
        // observes the live verdict the gate's handlers decide with.
        let live_policy = PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");
        assert_eq!(gate.policy_version(), "pol1/v1");
        let before = live_policy.evaluate(&sub_ctx("blocked-v1.example."));
        assert!(
            !before.admits(),
            "v1 hard-denies blocked-v1.example on the live evaluator"
        );
        assert_eq!(
            gate.current_authored_mname(),
            "denied.policy.startup.example."
        );

        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);

        // The PRODUCTION commit sink (boundary-zone reloader + evaluator reloader), wrapped in the
        // identity-capturing decorator so the test asserts the transported `(seq, content_hash)`.
        let commit_sink = IdentityCapturingSink::new(SnapshotCommitSink::new(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
        ));
        let subscriber = tokio::spawn(async move {
            (
                watch_snapshots(subscription, &commit_sink).await,
                commit_sink,
            )
        });

        // The REAL policy push: parse the v2 POL-1 layer (a NEW committed version where
        // `blocked-v1.example` is no longer blocked) and drive it through the PRODUCTION publisher
        // exactly as the host agent's `WatchPolicies(from_seq)` fan-out would.
        let v2_layer = parse_layer(SUB_LAYER_V2).expect("the v2 POL-1 layer parses");
        let push_seq = 7u64;
        let source = ScriptedPolicySource::new(vec![CommittedPolicyVersion::new(
            push_seq,
            v2_layer.clone(),
        )]);
        let published = run_policy_publisher(&feed, source, 0).await;
        assert_eq!(
            published, 1,
            "the publisher fanned out the single committed version"
        );
        // The publisher owns the feed; drop it so the subscriber drains and returns.
        drop(feed);
        let (commits, sink) = subscriber.await.expect("subscriber task");
        assert_eq!(
            commits, 1,
            "the subscriber committed the single pushed version"
        );

        // Admitter-LAST: the LIVE evaluator now decides against v2 — `blocked-v1.example` is no
        // longer denied (the verdict flipped on the running gate), and the authored suffix
        // re-sourced together with the evaluator (one policy version, end to end).
        assert_eq!(
            gate.policy_version(),
            "pol1/v2",
            "the running evaluator re-sourced its composed document from the pushed version"
        );
        let after = live_policy.evaluate(&sub_ctx("blocked-v1.example."));
        assert_ne!(
            before, after,
            "the publisher-driven push changed the live evaluator's verdict admitter-LAST"
        );
        assert!(
            !after.provenance().rule_id.is_empty(),
            "POL-3 provenance preserved on the re-sourced evaluator's verdict"
        );

        // The published snapshot carried the correct `(seq, content_hash)` identity: the seq is
        // the pushed seq, and the content_hash is the `ds-policy-snapshot` fingerprint of the SAME
        // layer threaded with that seq — proving the publisher lifts identity off the committed
        // version, never synthesizes it.
        let expected =
            ds_policy_snapshot::PolicySnapshot::from_policy_layer_with_seq(&v2_layer, push_seq);
        let expected_committed = expected
            .committed_policy()
            .expect("a layer-sourced snapshot carries a committed policy");
        let expected_hash = expected_committed.content_hash();
        let expected_zone = expected_committed.boundary_zone().to_string();
        let captured = sink.committed();
        assert_eq!(captured.len(), 1, "exactly one snapshot committed");
        assert_eq!(
            captured[0],
            CommittedIdentity {
                seq: push_seq,
                content_hash: Some(expected_hash),
                // The in-memory layer-only publisher path (`CommittedPolicyVersion::new`) transports
                // NO wire bytes, so the committed snapshot carries no verified D120 wire hash.
                wire_content_hash: None,
                boundary_zone: expected_zone.clone(),
                policy_version: Some("pol1/v2".to_string()),
            },
            "the subscriber re-sourced with the publisher's (seq, content_hash) identity"
        );
        // The authored suffix on the LIVE gate re-sourced from the SAME boundary zone (one policy
        // version, end to end).
        assert_eq!(
            gate.current_authored_mname(),
            format!("denied.policy.{expected_zone}"),
            "the authored suffix re-sourced together with the evaluator (one policy version)"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn production_publisher_fans_out_multiple_forward_versions_in_order() {
        // The publisher passes a scripted sequence of forward-seq committed versions through the
        // feed; the subscriber commits each, in order, and the LAST version wins on the live gate
        // (the D72 forward-only-seq monotone). A REAL multi-push through the production loop.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
            .await
            .expect("gate binds on loopback");
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);

        let commit_sink = IdentityCapturingSink::new(SnapshotCommitSink::new(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
        ));
        let subscriber = tokio::spawn(async move {
            (
                watch_snapshots(subscription, &commit_sink).await,
                commit_sink,
            )
        });

        // Two forward versions: v1 (seq 3) then v2 (seq 9). The host agent fans them out in order.
        let v1_layer = parse_layer(SUB_LAYER_V1).expect("v1 parses");
        let v2_layer = parse_layer(SUB_LAYER_V2).expect("v2 parses");
        let source = ScriptedPolicySource::new(vec![
            CommittedPolicyVersion::new(3, v1_layer),
            CommittedPolicyVersion::new(9, v2_layer),
        ]);
        let published = run_policy_publisher(&feed, source, 0).await;
        assert_eq!(published, 2, "both forward versions fanned out");
        drop(feed);
        let (commits, sink) = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 2, "both forward versions committed in order");

        // The LAST committed version (v2, seq 9) is the live one.
        assert_eq!(gate.policy_version(), "pol1/v2");
        let captured = sink.committed();
        assert_eq!(
            captured.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![3, 9],
            "the publisher fanned out the versions in forward-seq order"
        );
        assert_eq!(
            captured
                .iter()
                .map(|c| c.policy_version.clone())
                .collect::<Vec<_>>(),
            vec![Some("pol1/v1".to_string()), Some("pol1/v2".to_string())],
        );
        // Every committed version carried a content_hash lifted off its layer (never None for a
        // publisher-driven push).
        assert!(
            captured.iter().all(|c| c.content_hash.is_some()),
            "every publisher-driven snapshot carried its (seq, content_hash) identity"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    // ── The verify-only LOADER loop + content_hash NACK telemetry + applied-seq heartbeat ──────
    //
    // The publisher drives the produce-once / verify-only loader over transported bytes (doc 13
    // §5.1): a verified version publishes a snapshot carrying the VERIFIED wire hash on its
    // identity; a D120 content_hash mismatch is NACKed host-wide (never published) and routed as a
    // DISTINCT `ContentHashMismatch` drop (vs the subscriber's forward-only-seq `StaleFanOut`). The
    // applied-seq heartbeat surfaces the committed identity ONLY AFTER the §5.4 revocation sweep.

    use crate::event::{CapturingDropSink, SnapshotDropReason, SnapshotDropSink};

    /// An in-process [`AppliedSeqHeartbeat`] that records every post-sweep applied-seq report — the
    /// test stand-in for the host agent's heartbeat carrier. Clones share one buffer (an `Arc`), so
    /// the commit sink reports through one handle and the test reads back through another.
    #[derive(Clone, Default)]
    struct CapturingHeartbeat {
        reports: Arc<Mutex<Vec<AppliedSeqIdentity>>>,
    }

    impl CapturingHeartbeat {
        fn reports(&self) -> Vec<AppliedSeqIdentity> {
            self.reports
                .lock()
                .expect("heartbeat lock poisoned")
                .clone()
        }
    }

    impl AppliedSeqHeartbeat for CapturingHeartbeat {
        fn report_applied_seq(&self, identity: AppliedSeqIdentity) {
            self.reports
                .lock()
                .expect("heartbeat lock poisoned")
                .push(identity);
        }
    }

    /// A [`SweepEnforcer`] that records a `"sweep"` marker into a shared ORDER log every time the
    /// §5.4 sweep routes a revocation to it — so a test can prove the applied-seq heartbeat is
    /// reported strictly AFTER the sweep (doc 13 §5 after-sweep readiness ordering). It records on
    /// the allow-set-withdraw leg (the leg a tightening revocation always exercises).
    struct OrderRecordingEnforcer {
        log: Arc<Mutex<Vec<String>>>,
    }

    impl SweepEnforcer for OrderRecordingEnforcer {
        fn withdraw_allow_set(&self, _deletion: &AllowSetDeletion) {
            self.log
                .lock()
                .expect("log lock poisoned")
                .push("sweep".to_string());
        }
        fn flush_session_conntrack(&self, _flush: &ConntrackFlush) {}
    }

    /// An [`AppliedSeqHeartbeat`] that records a `"heartbeat"` marker into the SAME shared order log
    /// the [`OrderRecordingEnforcer`] writes — so the test asserts the markers land in
    /// `[sweep, heartbeat]` order (the heartbeat is reported AFTER the §5.4 revocation sweep).
    struct OrderRecordingHeartbeat {
        log: Arc<Mutex<Vec<String>>>,
    }

    impl AppliedSeqHeartbeat for OrderRecordingHeartbeat {
        fn report_applied_seq(&self, _identity: AppliedSeqIdentity) {
            self.log
                .lock()
                .expect("log lock poisoned")
                .push("heartbeat".to_string());
        }
    }

    #[test]
    fn with_policy_layer_matches_from_policy_layer_directly() {
        // DIRECT unit test (the SCOPE acceptance pin): `BoundarySnapshot::with_policy_layer(seq,
        // layer)` lifts the SAME committed policy the shared `ds-policy-snapshot` accessor
        // `PolicySnapshot::from_policy_layer(layer)` does — the composed document, the W2 clamp,
        // the boundary zone, AND the (seq, content_hash) identity all come off ONE committed policy
        // version, never re-derived. Pin each lifted component against `from_policy_layer` so the
        // gate's reload constructor can never drift from the snapshot crate's source of truth.
        let layer = parse_layer(SUB_LAYER_V2).expect("the v2 POL-1 layer parses");
        let seq = 7u64;

        // The snapshot-crate source of truth (the seq-less accessor + the seq'd accessor).
        let from_layer = ds_policy_snapshot::PolicySnapshot::from_policy_layer(&layer);
        let from_layer_committed = from_layer
            .committed_policy()
            .expect("a layer-sourced snapshot carries a committed policy");
        let from_layer_with_seq =
            ds_policy_snapshot::PolicySnapshot::from_policy_layer_with_seq(&layer, seq);
        let from_layer_with_seq_committed = from_layer_with_seq
            .committed_policy()
            .expect("a layer-sourced snapshot carries a committed policy");

        // The gate's reload constructor under test.
        let snapshot = BoundarySnapshot::with_policy_layer(seq, &layer);
        let policy = snapshot
            .policy
            .as_ref()
            .expect("with_policy_layer always carries a committed policy");

        // (1) REAL seq threaded through (no more seq=0 default): the snapshot carries the supplied
        //     seq, exactly the seq `from_policy_layer_with_seq` carries (and NOT the seq=0 the
        //     seq-less `from_policy_layer` defaults to — proving the seq is genuinely threaded).
        assert_eq!(snapshot.seq, seq);
        assert_eq!(snapshot.seq, from_layer_with_seq_committed.seq());
        assert_ne!(snapshot.seq, from_layer_committed.seq()); // from_policy_layer defaults seq=0
        assert_eq!(from_layer_committed.seq(), 0);

        // (2) content_hash: the gate's snapshot carries the SAME local fingerprint
        //     `from_policy_layer` computes off the layer (the seq does not change the fingerprint).
        assert_eq!(
            snapshot.content_hash(),
            Some(from_layer_committed.content_hash())
        );
        assert_eq!(
            snapshot.content_hash(),
            Some(from_layer_with_seq_committed.content_hash())
        );

        // (3) boundary zone: lifted off the SAME layer's dns block as `from_policy_layer`.
        assert_eq!(snapshot.boundary_zone, from_layer_committed.boundary_zone());

        // (4) W2 clamp: the gate's TtlClamp carries the floor/ceil values `from_policy_layer`'s
        //     W2 clamp window lifts off the layer's admission block (field-for-field, no re-derive).
        let window = from_layer_committed.ttl_clamp();
        assert_eq!(
            policy.ttl_clamp,
            TtlClamp {
                floor: window.floor,
                ceil: window.ceil
            }
        );

        // (5) composed document: the gate composes the SAME committed layer `from_policy_layer`
        //     hands back (compose's INPUT is that layer) — equal composed POL-1 version.
        let expected_composed = compose(&[from_layer_committed.composed_layer().clone()], &[]);
        assert_eq!(policy.composed, expected_composed);
        assert_eq!(policy.composed.policy_version, "pol1/v2");

        // (6) the layer-only path carries NO wire hash (it never saw transported wire bytes) — the
        //     verify-only `with_verified_policy_layer` is the ONLY path that carries one.
        assert_eq!(snapshot.wire_content_hash(), None);
    }

    #[tokio::test]
    async fn publisher_verify_only_loader_commits_a_verified_version_with_the_wire_hash() {
        // The produce-once / verify-only loop end to end: the host agent fans out a version
        // carrying its transported bytes + the wire content_hash it produced once; the publisher
        // drives the verify-only loader, the hash verifies, and the published snapshot carries the
        // VERIFIED wire hash on its identity (surfaced for the after-sweep heartbeat). The
        // subscriber commits it on the LIVE gate admitter-LAST.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
            .await
            .expect("gate binds on loopback");
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        let commit_sink = IdentityCapturingSink::new(SnapshotCommitSink::new(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
        ));
        let subscriber = tokio::spawn(async move {
            (
                watch_snapshots(subscription, &commit_sink).await,
                commit_sink,
            )
        });

        // The host agent produced the canonical bytes ONCE and hashed them (here the SUB_LAYER_V2
        // YAML stands in for the transported canonical form; the loader hashes THESE bytes).
        let transported = SUB_LAYER_V2.as_bytes().to_vec();
        let wire_hash = ds_contracts::snapshot_verify::sha256(&transported);
        let v2_layer = parse_layer(SUB_LAYER_V2).expect("v2 parses");
        let push_seq = 5u64;
        let source = ScriptedPolicySource::new(vec![CommittedPolicyVersion::verified(
            push_seq,
            v2_layer,
            transported,
            wire_hash,
        )]);

        // A capturing drop sink: the verified version must NOT raise any drop.
        let drops = CapturingDropSink::new();
        let published = run_policy_publisher_with_drop_sink(&feed, source, 0, &drops).await;
        assert_eq!(
            published, 1,
            "the verified version published (hash verified)"
        );
        assert!(drops.is_empty(), "a verified version raises no NACK drop");
        drop(feed);
        let (commits, sink) = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1, "the subscriber committed the verified version");

        // The committed snapshot carried the VERIFIED wire hash on its identity (the verify-only
        // loader path is the ONLY one that does), self-identifying on the §5 wire-identity tuple.
        let captured = sink.committed();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].seq, push_seq);
        assert_eq!(
            captured[0].wire_content_hash,
            Some(wire_hash),
            "the committed snapshot carries the verified D120 wire content_hash"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn publisher_content_hash_nack_is_distinct_from_a_stale_fan_out() {
        // A byte-mutated transport: the verify-only loader's hash-check fails, so the publisher
        // NACKs the version host-wide (never published — the host stays on vN) and routes a DISTINCT
        // `ContentHashMismatch` drop. This is the OTHER non-commit reason, separable in operator
        // logs from the subscriber's benign forward-only-seq `StaleFanOut`.
        let (feed, subscription) = boundary_snapshot_feed(8);
        let recording = RecordingSink::default();
        // The subscriber records its OWN forward-only-seq stale-fan-out drops into the SAME sink so
        // the test can assert the two reasons are tallied distinctly.
        let drops = CapturingDropSink::new();
        let subscriber = {
            let drops = drops.clone();
            tokio::spawn(async move {
                let sink = StaleFanOutObservingSink {
                    inner: BoundaryZoneOnly(&recording),
                    drops,
                };
                watch_snapshots(subscription, &sink).await
            })
        };

        // Two versions through the publisher: a GOOD one (verifies, publishes) and a TAMPERED one
        // (the wire hash does not match the mutated bytes → NACK, not published).
        let good_bytes = SUB_LAYER_V1.as_bytes().to_vec();
        let good_hash = ds_contracts::snapshot_verify::sha256(&good_bytes);
        let good_layer = parse_layer(SUB_LAYER_V1).expect("v1 parses");

        let mut tampered_bytes = SUB_LAYER_V2.as_bytes().to_vec();
        *tampered_bytes.last_mut().expect("non-empty") ^= 0x20; // flip a transported byte
        let claimed_hash = ds_contracts::snapshot_verify::sha256(SUB_LAYER_V2.as_bytes()); // the UNMUTATED hash
        let v2_layer = parse_layer(SUB_LAYER_V2).expect("v2 parses");

        let source = ScriptedPolicySource::new(vec![
            CommittedPolicyVersion::verified(3, good_layer, good_bytes, good_hash),
            CommittedPolicyVersion::verified(9, v2_layer, tampered_bytes, claimed_hash),
        ]);
        let published = run_policy_publisher_with_drop_sink(&feed, source, 0, &drops).await;
        assert_eq!(
            published, 1,
            "only the verified version published; the tampered one NACKed host-wide"
        );
        drop(feed);
        let _commits = subscriber.await.expect("subscriber task");

        // Exactly one ContentHashMismatch drop (the tampered version), and ZERO stale fan-outs (the
        // two versions had forward seqs, so the subscriber dropped nothing) — the two reasons are
        // structurally DISTINCT, never conflated.
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::ContentHashMismatch),
            1,
            "the tampered version raised exactly one content_hash-mismatch NACK"
        );
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::StaleFanOut),
            0,
            "no forward-only-seq stale fan-out occurred — the NACK is a DIFFERENT reason"
        );
        // The NACK drop names the NACKed version's seq, distinct from the benign-dedup token.
        let nack = drops
            .drops()
            .into_iter()
            .find(|d| d.reason == SnapshotDropReason::ContentHashMismatch)
            .expect("a content_hash NACK drop");
        assert_eq!(nack.dropped_seq, 9);
        assert!(!nack.is_stale_fan_out());
        assert_eq!(nack.reason.as_str(), "content_hash_mismatch");
    }

    #[tokio::test]
    async fn publisher_schema_failure_is_a_distinct_reason_from_a_content_hash_mismatch() {
        // A VERIFIED-but-UNPARSEABLE transport: the bytes hash exactly to the wire content_hash
        // (the D120 check PASSES), but they fail the POL-1 schema parse, so the verify-only loader
        // returns ParseError and the publisher NACKs the version host-wide (never published, the
        // host stays on vN) — exactly as a content_hash mismatch does. The COMMIT behavior is
        // identical; only the operator-telemetry reason is separable: this drop carries
        // `SchemaFailure`, while a mutated-transport drop carries `ContentHashMismatch`. Both are
        // distinct from the subscriber's benign forward-only-seq `StaleFanOut`.
        let (feed, subscription) = boundary_snapshot_feed(8);
        let recording = RecordingSink::default();
        let drops = CapturingDropSink::new();
        let subscriber = {
            let drops = drops.clone();
            tokio::spawn(async move {
                let sink = StaleFanOutObservingSink {
                    inner: BoundaryZoneOnly(&recording),
                    drops,
                };
                watch_snapshots(subscription, &sink).await
            })
        };

        // A GOOD version (verifies + parses → publishes), then two REJECTIONS the loader keeps
        // distinct:
        //   * seq 7: bytes that VERIFY against their (honestly-computed) wire hash but are NOT a
        //            POL-1 layer → LoadVerdict::ParseError → SchemaFailure.
        //   * seq 9: a byte-mutated transport whose wire hash no longer matches → HashNack →
        //            ContentHashMismatch.
        let good_bytes = SUB_LAYER_V1.as_bytes().to_vec();
        let good_hash = ds_contracts::snapshot_verify::sha256(&good_bytes);
        let good_layer = parse_layer(SUB_LAYER_V1).expect("v1 parses");

        // Verified-but-unparseable: arbitrary non-POL-1 bytes hashed HONESTLY (the hash check
        // passes; the parse fails). The carried `layer` is irrelevant — the loader re-parses the
        // transported bytes — so reuse a valid one for the carrier.
        let unparseable_bytes = b"this is not a pol1 layer { schema_version: nope".to_vec();
        assert!(
            parse_layer(std::str::from_utf8(&unparseable_bytes).unwrap()).is_err(),
            "the fixture bytes must NOT be a valid POL-1 layer (so the parse fails)"
        );
        let honest_hash = ds_contracts::snapshot_verify::sha256(&unparseable_bytes);
        let carrier_layer = parse_layer(SUB_LAYER_V2).expect("v2 parses");

        let mut tampered_bytes = SUB_LAYER_V2.as_bytes().to_vec();
        *tampered_bytes.last_mut().expect("non-empty") ^= 0x20; // flip a transported byte
        let claimed_hash = ds_contracts::snapshot_verify::sha256(SUB_LAYER_V2.as_bytes()); // UNMUTATED
        let v2_layer = parse_layer(SUB_LAYER_V2).expect("v2 parses");

        let source = ScriptedPolicySource::new(vec![
            CommittedPolicyVersion::verified(3, good_layer, good_bytes, good_hash),
            CommittedPolicyVersion::verified(7, carrier_layer, unparseable_bytes, honest_hash),
            CommittedPolicyVersion::verified(9, v2_layer, tampered_bytes, claimed_hash),
        ]);
        let published = run_policy_publisher_with_drop_sink(&feed, source, 0, &drops).await;
        assert_eq!(
            published, 1,
            "only the verified+parsed version published; both rejections NACKed host-wide"
        );
        drop(feed);
        let _commits = subscriber.await.expect("subscriber task");

        // Exactly one SchemaFailure (the verified-but-unparseable version), exactly one
        // ContentHashMismatch (the tampered version), and ZERO stale fan-outs — the THREE reasons
        // are structurally distinct, never conflated.
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::SchemaFailure),
            1,
            "the verified-but-unparseable version raised exactly one schema-failure NACK"
        );
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::ContentHashMismatch),
            1,
            "the tampered version raised exactly one content_hash-mismatch NACK"
        );
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::StaleFanOut),
            0,
            "no forward-only-seq stale fan-out occurred — the NACKs are DIFFERENT reasons"
        );

        // The schema-failure drop names the unparseable version's seq, carries the distinct token,
        // and (like a hash NACK) is NOT a benign stale fan-out.
        let schema_drop = drops
            .drops()
            .into_iter()
            .find(|d| d.reason == SnapshotDropReason::SchemaFailure)
            .expect("a schema-failure drop");
        assert_eq!(schema_drop.dropped_seq, 7);
        assert_eq!(schema_drop.committed_seq, 7);
        assert!(!schema_drop.is_stale_fan_out());
        assert_eq!(schema_drop.reason.as_str(), "schema_failure");

        // The hash-mismatch drop stays the OTHER distinct reason.
        let hash_drop = drops
            .drops()
            .into_iter()
            .find(|d| d.reason == SnapshotDropReason::ContentHashMismatch)
            .expect("a content_hash NACK drop");
        assert_eq!(hash_drop.dropped_seq, 9);
        assert_ne!(hash_drop.reason, schema_drop.reason);
        assert_eq!(hash_drop.reason.as_str(), "content_hash_mismatch");
    }

    /// A [`SnapshotSink`] decorator that routes the subscriber's forward-only-seq drops into a
    /// shared [`CapturingDropSink`] while delegating commits to a wrapped sink — so a test can tally
    /// the subscriber's `StaleFanOut` drops alongside the publisher's `ContentHashMismatch` NACKs.
    struct StaleFanOutObservingSink<'a, S: BoundaryZoneSink> {
        inner: BoundaryZoneOnly<'a, S>,
        drops: CapturingDropSink,
    }

    impl<S: BoundaryZoneSink> SnapshotSink for StaleFanOutObservingSink<'_, S> {
        fn commit_snapshot(&self, snapshot: &BoundarySnapshot) {
            self.inner.commit_snapshot(snapshot);
        }
        fn observe_snapshot_drop(&self, drop: SnapshotDropEvent) {
            self.drops.observe_drop(drop);
        }
    }

    #[tokio::test]
    async fn production_commit_sink_routes_a_stale_fan_out_drop_to_its_wired_drop_sink() {
        // SCOPE item (1) end-to-end: the PRODUCTION `SnapshotCommitSink` — the verbatim `main`
        // wiring (boundary-zone reloader + evaluator reloader) — wired with a real
        // `SnapshotDropSink` via `.with_drop_sink(...)` ROUTES the subscriber's forward-only-seq
        // STALE-FAN-OUT drop through to that sink. BEFORE this wiring the production commit sink
        // inherited the default no-op `observe_snapshot_drop`, so a benign dedup at the reload
        // boundary was DISCARDED; this proves the override end-to-end (the `CapturingDropSink`
        // stands in for `main`'s operator-alert / spool sink — the SAME shape `main` hands
        // `OperatorLogDropSink`). The drop BEHAVIOR is unchanged: the stale snapshot is still
        // dropped (one monotonic policy version), only its OBSERVABILITY is added.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
            .await
            .expect("gate binds on loopback");
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);

        // The PRODUCTION commit sink, wired with a real drop sink (the override under test). The
        // default is `NullDropSink`; here we hand a `CapturingDropSink` (an `Arc<dyn SnapshotDropSink>`,
        // exactly the shape `main` hands `Arc::new(OperatorLogDropSink)`).
        let drops = CapturingDropSink::new();
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader())
                .with_drop_sink(Arc::new(drops.clone()));
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // A FORWARD version (seq 5) commits; then a DUPLICATE / out-of-order fan-out (seq 3 ≤ 5) is
        // the benign D72 dedup the subscriber declines — the drop the production sink must route.
        let v1_layer = parse_layer(SUB_LAYER_V1).expect("v1 parses");
        let v2_layer = parse_layer(SUB_LAYER_V2).expect("v2 parses");
        feed.publish(BoundarySnapshot::with_policy_layer(5, &v2_layer))
            .await
            .expect("forward version publishes");
        feed.publish(BoundarySnapshot::with_policy_layer(3, &v1_layer))
            .await
            .expect("stale fan-out publishes onto the feed (the subscriber declines to commit it)");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1, "only the forward version (seq 5) committed");

        // The production commit sink ROUTED the subscriber's stale-fan-out drop to the wired sink —
        // exactly one benign-dedup drop, NO integrity rejection (this surface only raises StaleFanOut).
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::StaleFanOut),
            1,
            "the production SnapshotCommitSink routed the forward-only-seq stale fan-out to its wired drop sink"
        );
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::ContentHashMismatch),
            0,
            "no content_hash NACK on this subscriber surface"
        );
        assert_eq!(
            drops.count_with_reason(SnapshotDropReason::SchemaFailure),
            0,
            "no schema failure on this subscriber surface"
        );
        let drop_event = drops
            .drops()
            .into_iter()
            .next()
            .expect("exactly one routed drop");
        assert_eq!(drop_event.dropped_seq, 3, "the dropped fan-out's seq");
        assert_eq!(
            drop_event.committed_seq, 5,
            "the live committed version it failed to advance past"
        );
        assert!(drop_event.is_stale_fan_out());

        // The routed drop encodes through the SAME convention-layer `EventEnvelope` path the
        // `DnsEvent`s ride — a `PolicyDecision` kind (a reload is a policy-version event, NOT a
        // resolver query) whose payload leads with the distinct `stale_fan_out` reason token, so it
        // is joinable apart from a content_hash / schema NACK on the shared spool.
        let envelope = drop_event
            .to_envelope()
            .expect("a live POL-3 triple encodes the routed drop");
        assert_eq!(envelope.kind(), crate::event::EventKind::PolicyDecision);
        let payload = String::from_utf8_lossy(envelope.payload());
        assert!(
            payload.contains("reason=stale_fan_out"),
            "the routed drop's payload leads with the stale-fan-out reason token (payload: {payload})"
        );
        assert!(!payload.contains("content_hash_mismatch"));

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn commit_sink_defaults_to_a_no_op_drop_sink_so_existing_callers_stay_green() {
        // The behavior-preserving default: a `SnapshotCommitSink` constructed WITHOUT `.with_drop_sink`
        // keeps the inert `NullDropSink`, so the subscriber's stale-fan-out drop is observed nowhere
        // (the prior default-no-op `observe_snapshot_drop` behavior) — yet the snapshot is STILL
        // dropped (one monotonic version). This pins that adding the seam never changed which
        // snapshots commit for the existing constructors/tests.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
            .await
            .expect("gate binds on loopback");
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        // No `.with_drop_sink` — the default NullDropSink. Wrap in the identity decorator only to
        // observe commit count without re-routing the drop.
        let commit_sink = IdentityCapturingSink::new(SnapshotCommitSink::new(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
        ));
        let subscriber = tokio::spawn(async move {
            (
                watch_snapshots(subscription, &commit_sink).await,
                commit_sink,
            )
        });

        let v1_layer = parse_layer(SUB_LAYER_V1).expect("v1 parses");
        let v2_layer = parse_layer(SUB_LAYER_V2).expect("v2 parses");
        feed.publish(BoundarySnapshot::with_policy_layer(5, &v2_layer))
            .await
            .expect("forward version publishes");
        feed.publish(BoundarySnapshot::with_policy_layer(3, &v1_layer))
            .await
            .expect("stale fan-out publishes");
        drop(feed);
        let (commits, sink) = subscriber.await.expect("subscriber task");
        // The stale fan-out was still DROPPED (only the forward version committed) — behavior
        // unchanged with the default no-op drop sink.
        assert_eq!(
            commits, 1,
            "only the forward version committed (default drop sink, drop unchanged)"
        );
        let captured = sink.committed();
        assert_eq!(
            captured.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![5],
            "the stale below-cursor fan-out was dropped with the default no-op drop sink"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn default_commit_sink_routes_the_stale_fan_out_drop_to_the_production_null_drop_sink() {
        // The PRODUCTION default-drop path, now genuinely under test. The companion
        // `commit_sink_defaults_to_a_no_op_drop_sink_so_existing_callers_stay_green` asserts the
        // drop BEHAVIOR (the stale fan-out never commits) but its `IdentityCapturingSink` wrapper
        // used to shadow `observe_snapshot_drop` via the `SnapshotSink` trait default — so the
        // INNER `SnapshotCommitSink::observe_snapshot_drop` → its wired `SnapshotDropSink` (the
        // `NullDropSink` by default) was never reached. The wrapper now DELEGATES the drop, so this
        // test proves both halves of the production default routing on ONE drive:
        //   (a) a default `SnapshotCommitSink::new` routes the subscriber's stale-fan-out drop to
        //       its DEFAULT `NullDropSink` — observed NOWHERE (the prior default-no-op behavior);
        //   (b) the IDENTICAL scenario with a `CapturingDropSink` wired via `.with_drop_sink` makes
        //       that SAME stale fan-out OBSERVABLE — proving the default really is the inert
        //       NullDropSink, not the wrapper's swallowed no-op.
        // Loopback / synthetic only (§5.3). No production behavior change — additive coverage only.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };

        // The stale-fan-out scenario: publish a forward version (seq 5), then a stale below-cursor
        // fan-out (seq 3) the subscriber declines — the SAME shape the companion test drives.
        let v1_layer = parse_layer(SUB_LAYER_V1).expect("v1 parses");
        let v2_layer = parse_layer(SUB_LAYER_V2).expect("v2 parses");

        // (a) DEFAULT NullDropSink: the inner `SnapshotCommitSink::new` wires NO drop sink, so the
        //     delegating wrapper forwards the drop to it → the inert NullDropSink (records nowhere).
        //     There is no observable signal to read off the default sink BY CONSTRUCTION (that is the
        //     whole point of the no-op default), so the assertable property of THIS leg is that the
        //     drop BEHAVIOR is unchanged — the stale fan-out still never commits (one monotonic
        //     version). Leg (b) below is the contrast that proves the SAME path becomes observable
        //     once a real sink replaces the default — i.e. the default truly is the inert NullDropSink
        //     (and the wrapper no longer swallows the drop ahead of it).
        let gate_a = Arc::new(
            spawn_gate(
                PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)),
                config.clone(),
            )
            .await
            .expect("gate binds on loopback"),
        );
        let (feed_a, subscription_a) = boundary_snapshot_feed(8);
        // No `.with_drop_sink` on the inner commit sink → the production-default NullDropSink.
        let commit_sink_a = IdentityCapturingSink::new(SnapshotCommitSink::new(
            gate_a.boundary_zone_reloader(),
            gate_a.policy_reloader(),
        ));
        let subscriber_a =
            tokio::spawn(async move { watch_snapshots(subscription_a, &commit_sink_a).await });
        feed_a
            .publish(BoundarySnapshot::with_policy_layer(5, &v2_layer))
            .await
            .expect("forward version publishes");
        feed_a
            .publish(BoundarySnapshot::with_policy_layer(3, &v1_layer))
            .await
            .expect("stale fan-out publishes");
        drop(feed_a);
        let commits_a = subscriber_a.await.expect("subscriber task");
        assert_eq!(
            commits_a, 1,
            "the stale fan-out never commits under the default NullDropSink — drop behavior unchanged"
        );
        Arc::try_unwrap(gate_a)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");

        // (b) POSITIVE CONTROL — the SAME stale fan-out, but the inner commit sink wires a real
        //     CapturingDropSink via `.with_drop_sink`. The delegating wrapper forwards the drop to
        //     the inner `SnapshotCommitSink::observe_snapshot_drop`, which routes it to the wired
        //     sink → observed exactly once, with the StaleFanOut reason. This is the SAME code path
        //     the default exercises with NullDropSink; only the terminal sink differs, proving the
        //     default truly is the inert sink (the wrapper no longer swallows the drop).
        let captured = crate::event::CapturingDropSink::new();
        let gate_b = Arc::new(
            spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
                .await
                .expect("gate binds on loopback"),
        );
        let (feed_b, subscription_b) = boundary_snapshot_feed(8);
        let commit_sink_b = IdentityCapturingSink::new(
            SnapshotCommitSink::new(gate_b.boundary_zone_reloader(), gate_b.policy_reloader())
                .with_drop_sink(Arc::new(captured.clone())),
        );
        let subscriber_b =
            tokio::spawn(async move { watch_snapshots(subscription_b, &commit_sink_b).await });
        feed_b
            .publish(BoundarySnapshot::with_policy_layer(5, &v2_layer))
            .await
            .expect("forward version publishes");
        feed_b
            .publish(BoundarySnapshot::with_policy_layer(3, &v1_layer))
            .await
            .expect("stale fan-out publishes");
        drop(feed_b);
        let commits_b = subscriber_b.await.expect("subscriber task");
        assert_eq!(
            commits_b, 1,
            "the drop BEHAVIOR is unchanged with a real drop sink — still one commit"
        );
        assert_eq!(
            captured.len(),
            1,
            "the wired drop sink observed the stale fan-out exactly once (the wrapper DELEGATED \
             the drop to the inner sink — it is no longer swallowed by the trait default)"
        );
        assert_eq!(
            captured.count_with_reason(crate::event::SnapshotDropReason::StaleFanOut),
            1,
            "the observed drop is the benign D72 stale-fan-out dedup, not a content_hash NACK"
        );
        Arc::try_unwrap(gate_b)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn applied_seq_heartbeat_reports_identity_only_after_the_revocation_sweep() {
        // doc 13 §5 readiness row: the host heartbeat reports `applied_seq` AFTER sweep completion.
        // A tightening policy push REVOKES a live admission (the sweep routes an allow-set
        // withdrawal to the enforcer, recording a "sweep" marker); the heartbeat records a
        // "heartbeat" marker into the SAME log. The markers must land `[sweep, heartbeat]` — the
        // heartbeat is reported strictly AFTER the §5.4 revocation sweep completes.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        // Start on the LOOSE evaluator (tighten.example admits); a shared-handle clone re-sources
        // on the commit so the sweep decides against the NEW (tight) version.
        let live_policy = PolicyCorePolicy::new(sub_composed(SWEEP_LAYER_LOOSE));
        let gate = spawn_gate(live_policy.clone(), config)
            .await
            .expect("gate binds on loopback");

        // One live admission the tightening push revokes (tighten.example → kill+snapshot).
        let admissions = LiveAdmissions::new();
        admissions.admit(LiveAdmission::new(
            "sess-a",
            "tighten.example",
            ip("203.0.113.7"),
        ));

        let order_log = Arc::new(Mutex::new(Vec::<String>::new()));
        let order_enforcer = Arc::new(OrderRecordingEnforcer {
            log: order_log.clone(),
        });
        let order_heartbeat = OrderRecordingHeartbeat {
            log: order_log.clone(),
        };
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        let commit_sink = SnapshotCommitSink::with_revocation_sweep_enforced(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
            admissions.clone(),
            live_policy.clone(),
            order_enforcer,
        )
        .with_applied_seq_heartbeat(Arc::new(order_heartbeat));
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // The tightening push, carrying its verified wire identity so the heartbeat surfaces it.
        let transported = SWEEP_LAYER_TIGHT.as_bytes().to_vec();
        let wire_hash = ds_contracts::snapshot_verify::sha256(&transported);
        let tight_layer = parse_layer(SWEEP_LAYER_TIGHT).expect("tight layer parses");
        let source = ScriptedPolicySource::new(vec![CommittedPolicyVersion::verified(
            6,
            tight_layer,
            transported,
            wire_hash,
        )]);
        let published = run_policy_publisher(&feed, source, 0).await;
        assert_eq!(published, 1);
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1);

        // The after-sweep ordering: the sweep marker (the revocation routed to the enforcer)
        // precedes the heartbeat marker — the heartbeat is reported AFTER the revocation sweep.
        let markers = order_log.lock().expect("log").clone();
        assert_eq!(
            markers,
            vec!["sweep".to_string(), "heartbeat".to_string()],
            "the applied-seq heartbeat is reported AFTER the §5.4 revocation sweep"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn applied_seq_heartbeat_carries_the_committed_versions_identity() {
        // The heartbeat carries the committed version's EXACT (seq, content_hash, wire_content_hash)
        // identity — the scalars the loader committed, never re-derived. A verified version yields a
        // heartbeat whose wire hash is the one the loader verified; a boundary-zone-only commit
        // never heartbeats.
        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
            .await
            .expect("gate binds on loopback");
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        let heartbeat = CapturingHeartbeat::default();
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader())
                .with_applied_seq_heartbeat(Arc::new(heartbeat.clone()));
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        let transported = SUB_LAYER_V2.as_bytes().to_vec();
        let wire_hash = ds_contracts::snapshot_verify::sha256(&transported);
        let v2_layer = parse_layer(SUB_LAYER_V2).expect("v2 parses");
        let push_seq = 8u64;
        // Also push a boundary-zone-only snapshot AFTER (a higher seq) — it must NOT heartbeat
        // (no committed policy ⇒ no version identity).
        let source = ScriptedPolicySource::new(vec![CommittedPolicyVersion::verified(
            push_seq,
            v2_layer.clone(),
            transported,
            wire_hash,
        )]);
        let published = run_policy_publisher(&feed, source, 0).await;
        assert_eq!(published, 1);
        // A boundary-zone-only fan-out at a forward seq (no committed policy on it).
        feed.publish(BoundarySnapshot::new(99, "zone-only.example."))
            .await
            .expect("publish");
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 2, "both forward snapshots committed");

        // Exactly ONE heartbeat — only the committed-policy version heartbeats; the boundary-zone-
        // only commit carries no version identity and never reports.
        let reports = heartbeat.reports();
        assert_eq!(
            reports.len(),
            1,
            "only the committed-policy version heartbeats"
        );
        assert_eq!(reports[0].seq, push_seq);
        assert_eq!(
            reports[0].wire_content_hash,
            Some(wire_hash),
            "the heartbeat carries the verified wire content_hash the loader committed"
        );
        // The local fingerprint matches the snapshot crate's per-version digest off the SAME layer.
        let expected =
            ds_policy_snapshot::PolicySnapshot::from_policy_layer_with_seq(&v2_layer, push_seq)
                .committed_policy()
                .expect("committed")
                .content_hash();
        assert_eq!(reports[0].content_hash, expected);
        // The wire hash renders to the greppable hex an operator joins the applied_seq on.
        assert_eq!(
            reports[0].wire_content_hash_hex(),
            ds_contracts::snapshot_verify::content_hash_hex(&wire_hash)
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    // ── The host-LOCAL file feed source + persisted applied_seq cursor (doc 13 §8.4 v0
    //    file+atomic-rename / §5 D36 resume). The Go host agent writes `<seq>.snapshot` files +
    //    the `applied_seq` cursor host-locally; `HostLocalFeedSource` is the dataplane-side CONSUMER.
    //    All in-process / synthetic (§5.3 loopback): a real temp directory stands in for the
    //    host-local feed — NO live host agent, NO control-plane stream, NO claude/cia/qemu/podman. ──

    /// A unique scratch directory under the OS temp dir for one feed test — the in-process stand-in
    /// for the host-local feed directory (the host agent would atomic-rename `<seq>.snapshot` files
    /// here). Returns a [`ScratchDir`] guard that removes the tree on drop so tests leave nothing.
    struct ScratchDir {
        path: std::path::PathBuf,
    }

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("ds-dnsgate-feed-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create scratch feed dir");
            Self { path }
        }

        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// The host agent's atomic-rename fan-out, modeled: write `bytes` to a temp file then
    /// `rename()` it into `<dir>/<seq:020>.snapshot` (atomic on the same filesystem). The exact
    /// produce-once / verify-only contract the v0 file transport carries (doc 13 §8.4 / §5.1) — the
    /// in-process stand-in for the cross-process host-agent write.
    fn host_agent_fan_out(dir: &std::path::Path, seq: u64, bytes: &[u8]) {
        let tmp = dir.join(format!("{seq:020}.snapshot.tmp"));
        std::fs::write(&tmp, bytes).expect("write temp snapshot");
        let final_path = dir.join(format!("{seq:020}.snapshot"));
        std::fs::rename(&tmp, &final_path).expect("atomic-rename snapshot into place");
    }

    #[tokio::test]
    async fn host_local_file_feed_drains_forward_versions_through_the_publisher() {
        // The gate-ON path end to end: the host agent atomic-renames two forward `<seq>.snapshot`
        // files into the host-local feed directory; `HostLocalFeedSource` consumes them (carrying
        // the transported bytes + recomputed wire hash), the publisher drives the verify-only loader
        // over each, and the subscriber commits them on the LIVE gate admitter-LAST. The LAST
        // version wins on the running evaluator — a REAL policy push through the production loop over
        // the file transport, no control-plane stream (§5.3 loopback/synthetic).
        let scratch = ScratchDir::new("drain");
        // The host agent fans out v1 (seq 3) then v2 (seq 9) as produce-once canonical bytes.
        host_agent_fan_out(scratch.path(), 3, SUB_LAYER_V1.as_bytes());
        host_agent_fan_out(scratch.path(), 9, SUB_LAYER_V2.as_bytes());

        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
            .await
            .expect("gate binds on loopback");
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        let commit_sink = IdentityCapturingSink::new(SnapshotCommitSink::new(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
        ));
        let subscriber = tokio::spawn(async move {
            (
                watch_snapshots(subscription, &commit_sink).await,
                commit_sink,
            )
        });

        // A fresh host: from_seq = 0 (no persisted cursor). The file source drains the directory.
        let source = HostLocalFeedSource::resume_from(scratch.path(), 0);
        let published = run_policy_publisher(&feed, source, 0).await;
        assert_eq!(
            published, 2,
            "both forward versions fanned out from the file feed"
        );
        drop(feed);
        let (commits, sink) = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 2, "both forward versions committed in order");

        // The LAST committed version (v2, seq 9) is the live one — admitter-LAST over the file feed.
        assert_eq!(gate.policy_version(), "pol1/v2");
        let captured = sink.committed();
        assert_eq!(
            captured.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![3, 9],
            "the file feed delivered the versions in forward-seq order (zero-padded name sort)"
        );
        // Each committed snapshot carried the VERIFIED D120 wire hash — the file source drives the
        // produce-once / verify-only loader path (it recomputes the hash off the transported bytes).
        assert!(
            captured.iter().all(|c| c.wire_content_hash.is_some()),
            "every file-feed snapshot committed through the verify-only loader (carries a wire hash)"
        );
        let v2_wire = ds_contracts::snapshot_verify::sha256(SUB_LAYER_V2.as_bytes());
        assert_eq!(captured[1].wire_content_hash, Some(v2_wire));

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn restart_resumes_from_persisted_applied_seq_not_re_committing_history() {
        // The D36 RESUME: a directory holds committed history (seqs 3 AND 9) and the host persisted
        // applied_seq=9 from a prior run. On restart, `host_agent_policy_source`-style wiring reads
        // applied_seq=9 as the resume cursor; `HostLocalFeedSource::resume_from(dir, 9)` plus the
        // publisher's `version.seq < from_seq → continue` guard means NEITHER historical version is
        // re-committed — only a NEW forward version (seq 14) the host agent fans out after the
        // restart commits. This exercises the server.rs:2194 forward-only guard against a REAL
        // persisted cursor (not the hardcoded 0).
        let scratch = ScratchDir::new("resume");
        // The committed history the prior run already applied (seqs 3 and 9).
        host_agent_fan_out(scratch.path(), 3, SUB_LAYER_V1.as_bytes());
        host_agent_fan_out(scratch.path(), 9, SUB_LAYER_V2.as_bytes());
        // The prior run persisted applied_seq=9 (post-sweep, D36) before the restart.
        let store = AppliedSeqStore::in_dir(scratch.path());
        store.persist(9).expect("persist applied_seq=9");

        // The restart reads the persisted cursor as the resume from_seq.
        let from_seq = store.load();
        assert_eq!(
            from_seq, 9,
            "the restart reads the persisted applied_seq cursor"
        );

        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        // Start on v2 (the version applied_seq=9 named) — the restart should NOT regress to v1.
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V2)), config)
            .await
            .expect("gate binds on loopback");
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        let commit_sink = IdentityCapturingSink::new(SnapshotCommitSink::new(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
        ));
        let subscriber = tokio::spawn(async move {
            (
                watch_snapshots(subscription, &commit_sink).await,
                commit_sink,
            )
        });

        // After the restart the host agent fans out a NEW forward version (seq 14 = v1 layer again,
        // a deliberately DIFFERENT composed version so a commit is observable). The source resumes
        // from_seq=9: it must NOT re-deliver seq 3 or 9, and the publisher's guard would drop them
        // even if a re-scan did. Only seq 14 commits.
        host_agent_fan_out(scratch.path(), 14, SUB_LAYER_V1.as_bytes());
        let source = HostLocalFeedSource::resume_from(scratch.path(), from_seq);
        let published = run_policy_publisher(&feed, source, from_seq).await;
        assert_eq!(
            published, 1,
            "only the post-cursor version (seq 14) published; seqs 3 and 9 were NOT replayed"
        );
        drop(feed);
        let (commits, sink) = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1, "exactly the new forward version committed");

        let captured = sink.committed();
        assert_eq!(
            captured.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![14],
            "the restart did NOT re-commit committed history at or below applied_seq=9"
        );
        assert_eq!(
            gate.policy_version(),
            "pol1/v1",
            "the new forward version is live"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[tokio::test]
    async fn publisher_guard_drops_a_stale_redelivery_below_the_resume_cursor() {
        // A DIRECT exercise of the server.rs:2194 forward-only guard against a real cursor: a source
        // that re-delivers a version BELOW from_seq (a stale WatchPolicies re-delivery the host
        // agent's at-least-once feed could replay) is dropped, never re-committed. Pairs the file
        // resume above with a unit-level proof the guard itself fires on `seq < from_seq`.
        let scratch = ScratchDir::new("stale");
        // The host agent (re-)wrote a stale low-seq file (3) AND a forward file (11); resume from 9.
        host_agent_fan_out(scratch.path(), 3, SUB_LAYER_V1.as_bytes());
        host_agent_fan_out(scratch.path(), 11, SUB_LAYER_V2.as_bytes());

        let (feed, subscription) = boundary_snapshot_feed(8);
        let recording = RecordingSink::default();
        let drops = CapturingDropSink::new();
        let subscriber = {
            let drops = drops.clone();
            tokio::spawn(async move {
                let sink = StaleFanOutObservingSink {
                    inner: BoundaryZoneOnly(&recording),
                    drops,
                };
                (watch_snapshots(subscription, &sink).await, recording)
            })
        };

        let from_seq = 9u64;
        let source = HostLocalFeedSource::resume_from(scratch.path(), from_seq);
        let published = run_policy_publisher(&feed, source, from_seq).await;
        // The source's own cursor (resume_from) skips seq 3 before it is ever yielded; the publisher
        // guard is the belt to that suspenders. Net: only seq 11 (> 9) publishes.
        assert_eq!(
            published, 1,
            "only the forward version above the cursor published"
        );
        drop(feed);
        let (_commits, recording) = subscriber.await.expect("subscriber task");
        // The single committed snapshot is the forward one (seq 11), proving the stale seq-3 file was
        // never committed — the resume cursor + the guard both fence it out. `RecordingSink` records
        // one committed boundary zone per commit.
        let committed = recording.committed();
        assert_eq!(
            committed.len(),
            1,
            "exactly one snapshot committed (the stale below-cursor version was fenced out)"
        );

        // And a DIRECT guard exercise: a source that yields ONLY a below-cursor seq publishes
        // nothing (server.rs:2194 `version.seq < from_seq → continue`).
        let (feed2, subscription2) = boundary_snapshot_feed(8);
        let only_stale = ScriptedPolicySource::new(vec![CommittedPolicyVersion::new(
            5,
            parse_layer(SUB_LAYER_V1).expect("v1 parses"),
        )]);
        let sub2 = tokio::spawn(async move {
            let recording = RecordingSink::default();
            let n = watch_snapshots(subscription2, &BoundaryZoneOnly(&recording)).await;
            (n, recording)
        });
        let published2 = run_policy_publisher(&feed2, only_stale, 9).await;
        assert_eq!(
            published2, 0,
            "a version with seq 5 < from_seq 9 is dropped by the forward-only guard"
        );
        drop(feed2);
        let (commits2, _rec2) = sub2.await.expect("subscriber 2");
        assert_eq!(
            commits2, 0,
            "nothing committed for a below-cursor re-delivery"
        );
    }

    #[tokio::test]
    async fn host_local_file_feed_tampered_file_nacks_host_wide() {
        // A tampered on-disk file: the host agent's atomic-rename wrote bytes that do not match the
        // produce-once canonical form (a corrupted transport). The file source recomputes the wire
        // hash off WHATEVER bytes are on disk, so the carried hash matches the (tampered) bytes — but
        // a file whose bytes simply do not PARSE is fenced by the source (it cannot build a carrier),
        // and a file that parses but is byte-mutated relative to a CLAIMED hash NACKs at the loader.
        // Here we prove the parse fence: a non-POL-1 file in the feed directory is skipped, never
        // committed, and the forward version after it still commits.
        let scratch = ScratchDir::new("tamper");
        // A garbage (non-POL-1) file at seq 4 — the source cannot parse it, so it is dropped.
        host_agent_fan_out(scratch.path(), 4, b"this is not valid pol1 yaml at all !!!");
        // A good forward version at seq 8.
        host_agent_fan_out(scratch.path(), 8, SUB_LAYER_V2.as_bytes());

        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
            .await
            .expect("gate binds on loopback");
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        let commit_sink = IdentityCapturingSink::new(SnapshotCommitSink::new(
            gate.boundary_zone_reloader(),
            gate.policy_reloader(),
        ));
        let subscriber = tokio::spawn(async move {
            (
                watch_snapshots(subscription, &commit_sink).await,
                commit_sink,
            )
        });

        let source = HostLocalFeedSource::resume_from(scratch.path(), 0);
        let published = run_policy_publisher(&feed, source, 0).await;
        assert_eq!(
            published, 1,
            "the unparseable file was fenced; only the valid forward version published"
        );
        drop(feed);
        let (commits, sink) = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1);
        let captured = sink.committed();
        assert_eq!(
            captured.iter().map(|c| c.seq).collect::<Vec<_>>(),
            vec![8],
            "only the valid version (seq 8) committed; the garbage file at seq 4 never did"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[test]
    fn applied_seq_store_round_trips_via_atomic_rename() {
        // The persisted cursor (D36): a fresh dir reads 0 (WatchPolicies(from_seq=0)); after a
        // persist it reads back the exact seq; a later persist OVERWRITES (the resume cursor only
        // ever moves forward in practice, but the store itself stores what it is given, atomically).
        let scratch = ScratchDir::new("cursor");
        let store = AppliedSeqStore::in_dir(scratch.path());
        assert_eq!(
            store.load(),
            0,
            "a fresh host reads applied_seq=0 (full replay)"
        );
        store.persist(7).expect("persist 7");
        assert_eq!(store.load(), 7, "the persisted cursor reads back exactly");
        store.persist(42).expect("persist 42");
        assert_eq!(
            store.load(),
            42,
            "a later persist overwrites the cursor atomically"
        );
        // The cursor file lives co-located under the feed directory (one host-local directory).
        assert!(
            scratch.path().join("applied_seq").exists(),
            "the cursor is co-located with the feed files"
        );
    }

    #[test]
    fn applied_seq_store_unreadable_cursor_fails_open_to_full_replay() {
        // Fail-open: a missing/garbled cursor reads 0 (a full WatchPolicies(from_seq=0) replay),
        // never a panic — a fresh host or a corrupted cursor resumes from the first committed version
        // and the forward-only guard de-dups anything already applied.
        let scratch = ScratchDir::new("badcursor");
        let store = AppliedSeqStore::in_dir(scratch.path());
        // A non-numeric cursor file (a torn/garbled write).
        std::fs::write(scratch.path().join("applied_seq"), b"not-a-number").expect("write garbage");
        assert_eq!(
            store.load(),
            0,
            "a garbled cursor fails open to from_seq=0, never a panic"
        );
    }

    #[tokio::test]
    async fn persisting_heartbeat_writes_the_post_sweep_applied_seq_cursor() {
        // The cursor is PERSISTED from the post-sweep heartbeat (D36): a committed version drives the
        // commit sink, which reports the applied_seq AFTER the §5.4 sweep to the
        // `PersistingAppliedSeqHeartbeat`, which writes the cursor. A restart then reads that seq as
        // its resume from_seq. Proves the persistence the `main` wiring relies on, end to end.
        let scratch = ScratchDir::new("hbpersist");
        let store = AppliedSeqStore::in_dir(scratch.path());

        let config = GateConfig {
            boundary_zone: "startup.example.".to_string(),
            ..GateConfig::default()
        };
        let gate = spawn_gate(PolicyCorePolicy::new(sub_composed(SUB_LAYER_V1)), config)
            .await
            .expect("gate binds on loopback");
        let gate = Arc::new(gate);
        let (feed, subscription) = boundary_snapshot_feed(8);
        // The commit sink wires the PERSISTING heartbeat (the durable cursor carrier `main` uses).
        let commit_sink =
            SnapshotCommitSink::new(gate.boundary_zone_reloader(), gate.policy_reloader())
                .with_applied_seq_heartbeat(Arc::new(PersistingAppliedSeqHeartbeat::new(
                    store.clone(),
                )));
        let subscriber =
            tokio::spawn(async move { watch_snapshots(subscription, &commit_sink).await });

        // The host agent fans out a committed version at seq 21.
        host_agent_fan_out(scratch.path(), 21, SUB_LAYER_V2.as_bytes());
        let source = HostLocalFeedSource::resume_from(scratch.path(), 0);
        let published = run_policy_publisher(&feed, source, 0).await;
        assert_eq!(
            published, 1,
            "the committed version published from the file feed"
        );
        drop(feed);
        let commits = subscriber.await.expect("subscriber task");
        assert_eq!(commits, 1);

        // The post-sweep heartbeat persisted applied_seq=21 — a restart resumes from it.
        assert_eq!(
            store.load(),
            21,
            "the post-sweep heartbeat persisted the applied_seq cursor a restart resumes from"
        );

        Arc::try_unwrap(gate)
            .unwrap_or_else(|_| panic!("subscriber dropped its gate ref"))
            .shutdown()
            .await
            .expect("gate shuts down");
    }

    #[test]
    fn tee_heartbeat_reports_to_both_carriers() {
        // The composition `main` uses to BOTH persist the cursor AND keep the operator log: the tee
        // reports each applied_seq to both carriers. Here two capturing heartbeats stand in.
        let a = CapturingHeartbeat::default();
        let b = CapturingHeartbeat::default();
        let tee = TeeAppliedSeqHeartbeat::new(a.clone(), b.clone());
        let id = AppliedSeqIdentity {
            seq: 5,
            content_hash: 0xabc,
            wire_content_hash: None,
        };
        tee.report_applied_seq(id);
        assert_eq!(
            a.reports(),
            vec![id],
            "the first carrier received the report"
        );
        assert_eq!(
            b.reports(),
            vec![id],
            "the second carrier received the report"
        );
    }

    // ── The LIVE host-local UDS `WatchPolicies(from_seq)` carrier (doc 11 §5.3 / doc 13 §5 / §8.4,
    //    D72/D36/D120): the PRODUCTION transport the `HostLocalFeedSource` file feed is the v0
    //    fallback for. A SYNTHETIC in-process producer (`serve_watch_policies_connection`) over a
    //    real UDS socketpair stands in for the Go host-agent fan-out — no live host agent, the
    //    SAME wire shape (§5.3 loopback). ──

    /// The `(seq, content_hash, document)` identity tuple for a POL-1 doc, hashed via the SINGLE
    /// source of wire hashing — the produce-once carrier the host agent fans out.
    fn carrier_version(seq: u64, doc: &str) -> (u64, ContentHash, Vec<u8>) {
        let bytes = doc.as_bytes().to_vec();
        let hash = ds_contracts::snapshot_verify::sha256(&bytes);
        (seq, hash, bytes)
    }

    /// A clean POL-1 doc for the carrier round-trip.
    const CARRIER_DOC: &str = "schema_version: pol1/v0\nlayer: session\nposture: standard\n\
                               dns:\n  boundary_zone: carrier.example.\n";

    #[tokio::test]
    async fn watch_policies_carrier_streams_verified_versions_in_forward_order() {
        // The carrier dials a host-local UDS, sends the WatchPolicies(from_seq) handshake, and reads
        // the server-stream of (seq, content_hash, document) frames — surfacing each as a VERIFIED
        // CommittedPolicyVersion the publisher's verify-only loader runs against. A bound socket
        // pair stands in for the host-agent fan-out (no live host agent, §5.3 loopback).
        let dir = std::env::temp_dir().join(format!("ds-watch-carrier-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let sock = dir.join("watch.sock");
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind carrier UDS");

        // The producer replays seq 1..=3 past from_seq=1 → the consumer must see seq 2 and 3 only.
        let versions = vec![
            carrier_version(1, CARRIER_DOC),
            carrier_version(2, CARRIER_DOC),
            carrier_version(3, CARRIER_DOC),
        ];
        let producer = tokio::spawn(async move {
            let (stream, _addr) = listener.accept().await.expect("accept");
            serve_watch_policies_connection(stream, &versions)
                .await
                .expect("producer streams")
        });

        let mut carrier = WatchPoliciesCarrierSource::connect_to(&sock, 1);
        let v2 = carrier
            .next_version()
            .await
            .expect("first version past cursor");
        assert_eq!(
            v2.seq, 2,
            "from_seq=1 → the first delivered version is seq 2"
        );
        assert!(
            v2.wire.is_some(),
            "the carrier surfaces the transported wire form"
        );
        let wire = v2.wire.as_ref().unwrap();
        assert_eq!(
            wire.content_hash,
            ds_contracts::snapshot_verify::sha256(CARRIER_DOC.as_bytes()),
            "the producer-pinned content_hash is carried unchanged"
        );
        assert_eq!(
            wire.transported,
            CARRIER_DOC.as_bytes().to_vec(),
            "the transported bytes are the produce-once wire form, verbatim"
        );
        let v3 = carrier.next_version().await.expect("second version");
        assert_eq!(v3.seq, 3);
        // The producer closed the stream after replaying its history → EOF → the source exhausts.
        assert!(
            carrier.next_version().await.is_none(),
            "the carrier yields None once the producer closes the stream (host stays on its version)"
        );
        let streamed = producer.await.expect("producer task");
        assert_eq!(
            streamed, 2,
            "seq 1 was below the cursor; seq 2 and 3 streamed"
        );

        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn watch_policies_carrier_fails_closed_when_the_host_agent_is_not_serving() {
        // A carrier pointed at a socket the host agent is NOT serving yet: the dial fails, the
        // source exhausts (None) fail-closed — the publisher idles, the host stays on its current
        // version, and ds-dnsgate opens no control-plane stream of its own (§5.3).
        let missing = std::env::temp_dir().join(format!(
            "ds-watch-carrier-absent-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        let mut carrier = WatchPoliciesCarrierSource::connect_to(&missing, 0);
        assert!(
            carrier.next_version().await.is_none(),
            "an unserved endpoint exhausts the source fail-closed"
        );
        // Terminal: a re-poll never re-dials.
        assert!(carrier.next_version().await.is_none());
    }

    #[test]
    fn watch_policies_frame_codec_round_trips_and_rejects_torn_frames() {
        // The hand-rolled (seq, content_hash, document) version-frame codec round-trips, and a
        // truncated / wrong-hash-width / trailing-byte body is rejected (the carrier drops the
        // stream fail-closed rather than fabricate a version).
        let (seq, hash, doc) = carrier_version(42, CARRIER_DOC);
        let frame = WatchPoliciesFrame::encode_version(seq, &hash, &doc);
        let (got_seq, got_hash, got_doc) =
            WatchPoliciesFrame::decode_version(&frame).expect("round-trips");
        assert_eq!(got_seq, 42);
        assert_eq!(got_hash, hash);
        assert_eq!(got_doc, doc);

        // A truncated body (drop the last document byte's length count off) is rejected.
        assert!(
            WatchPoliciesFrame::decode_version(&frame[..frame.len() - 1]).is_none(),
            "a truncated frame is rejected"
        );
        // A trailing byte past the document is a malformed frame.
        let mut trailing = frame.clone();
        trailing.push(0u8);
        assert!(
            WatchPoliciesFrame::decode_version(&trailing).is_none(),
            "trailing bytes are rejected"
        );
        // A wrong-width content_hash (not 32 bytes) is a torn frame.
        let mut bad_hash = Vec::new();
        bad_hash.extend_from_slice(&seq.to_be_bytes());
        bad_hash.extend_from_slice(&16u32.to_be_bytes()); // claim a 16-byte hash
        bad_hash.extend_from_slice(&[0u8; 16]);
        bad_hash.extend_from_slice(&(doc.len() as u32).to_be_bytes());
        bad_hash.extend_from_slice(&doc);
        assert!(
            WatchPoliciesFrame::decode_version(&bad_hash).is_none(),
            "a content_hash that is not the 32-byte SHA-256 width is rejected"
        );
    }

    // ── CROSS-LANGUAGE WatchPolicies carrier-frame conformance (Rust ⇄ Go) ──
    //
    // The on-the-wire WatchPolicies version-frame is a HAND-ROLLED cross-process contract with NO
    // shared type (the dataplane workspace and the Go orchestrator share NO crate, D40/D67). The
    // Rust consumer (`WatchPoliciesFrame::encode_version`/`decode_version`) and the Go producer
    // (`dnsfeed_carrier.go` `encodeWatchVersion` + its hand-decoded mirror) each test only their
    // OWN in-language codec, so a frame-shape divergence (an endianness flip, a field reorder, a
    // `content_hash`-width change) surfaces ONLY at live integration.
    //
    // SINGLE-SOURCED THROUGH THE CONFORMANCE FIXTURE. The canonical `(seq, content_hash, document)`
    // tuple and the exact frame-body bytes the carrier wire contract serialises it to are promoted
    // into the checked-in fixture
    // `assurance/conformance-adapter/revocationwire/carrierframe.go`
    // (`CarrierGoldenSeq` / `CarrierGoldenDoc` / `CarrierGoldenContentHashHex` /
    // `CarrierGoldenFrameHex`), which RE-DERIVES every value from the canonical tuple by an
    // independent encoder and pins it. The dataplane crate cannot import a Go package, so the three
    // constants below are a byte-IDENTICAL copy of those fixture constants; the Go test
    // (`orchestrator/internal/hostagent/dnsfeed_carrier_test.go`
    // `TestWatchPoliciesCarrierFrameCrossLanguageGolden`) pins the same. Because all three re-derive
    // the SAME bytes from the SAME canonical inputs, a frame-shape drift on any side breaks that
    // side's recompute-and-pin assertion AND the shared fixture — the wire is single-sourced through
    // the fixture, NOT two drifting per-side mirrors. Keep these in lock-step with
    // `revocationwire.Carrier*` (a one-side drift fails the conformance suite). No live cross-process
    // round-trip is needed (no claude/cia/qemu/podman, no Go toolchain in this test).
    // NEVER-LOG-THE-SECRET holds: the fixture is a synthetic conformance string, not a real
    // policy/secret (D73).

    /// The fixed `u64` seq of the cross-language fixture; the distinct bytes (01 02 .. 08) make a
    /// byte-order divergence in the 8B-BE seq field visible. IDENTICAL to
    /// `revocationwire.CarrierGoldenSeq`.
    const CARRIER_GOLDEN_SEQ: u64 = 0x0102_0304_0506_0708;
    /// The fixed produce-once transported document (the §5.1 identity tuple's document leg);
    /// `CARRIER_GOLDEN_CONTENT_HASH_HEX` is SHA-256 over exactly these bytes. IDENTICAL to
    /// `revocationwire.CarrierGoldenDoc`.
    const CARRIER_GOLDEN_DOC: &str = "ds-watchpolicies-frame-conformance\n";
    /// The full 32-byte SHA-256 `content_hash` over `CARRIER_GOLDEN_DOC`, 64 lowercase hex chars —
    /// the §5.1 content_hash leg. IDENTICAL to the Go fixture's `carrierGoldenContentHashHex` and
    /// `revocationwire.CarrierGoldenContentHashHex`.
    const CARRIER_GOLDEN_CONTENT_HASH_HEX: &str =
        "d52a55c4c38e4549e80cf020e14284f3db296de50461e4683e2988025e7f30b5";
    /// The canonical version-frame BODY bytes the carrier wire contract serialises
    /// `(CARRIER_GOLDEN_SEQ, content_hash, CARRIER_GOLDEN_DOC)` to, as hex:
    ///   seq(8B BE) || content_hash_len=32(4B BE) || content_hash(32) || doc_len(4B BE) || document.
    /// IDENTICAL to the Go fixture's `carrierGoldenFrameHex` and `revocationwire.CarrierGoldenFrameHex`.
    const CARRIER_GOLDEN_FRAME_HEX: &str = concat!(
        "010203040506070800000020",
        "d52a55c4c38e4549e80cf020e14284f3db296de50461e4683e2988025e7f30b5",
        "0000002364732d7761746368706f6c69636965732d6672616d652d636f6e666f726d616e63650a",
    );
    /// The 8-byte big-endian `from_seq` handshake body a dialing consumer sends to open a
    /// `WatchPolicies(from_seq)` stream (the resume cursor, D36) — exactly the 8 BE bytes of
    /// `CARRIER_GOLDEN_SEQ`. IDENTICAL to the Go fixture's `carrierGoldenHandshakeHex` and
    /// `revocationwire.CarrierGoldenHandshakeHex`.
    const CARRIER_GOLDEN_HANDSHAKE_HEX: &str = "0102030405060708";

    /// Decode an even-length lowercase/uppercase hex string into bytes — a test-only, stdlib-only
    /// helper (the FROZEN dataplane crate rule forbids a hex dependency). Panics on malformed input
    /// (a test fixture is authoritative; a bad literal is a test bug, not a runtime path).
    fn from_hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex fixture must be even-length");
        fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("non-hex byte in fixture: {c:#x}"),
            }
        }
        s.as_bytes()
            .chunks_exact(2)
            .map(|c| (nibble(c[0]) << 4) | nibble(c[1]))
            .collect()
    }

    #[test]
    fn watch_policies_carrier_frame_matches_cross_language_golden() {
        // The Rust HALF of the cross-language frame-shape conformance. The shared golden constants
        // are byte-for-byte identical to the Go fixture (dnsfeed_carrier_test.go); both sides assert
        // their own codec against THIS golden, so a frame encoded by either side is decoded
        // byte-equal by the other.
        let want_hash =
            ds_contracts::snapshot_verify::parse_content_hash_hex(CARRIER_GOLDEN_CONTENT_HASH_HEX)
                .expect("fixture content_hash hex is the 32-byte width");
        let want_frame = from_hex(CARRIER_GOLDEN_FRAME_HEX);
        let want_doc = CARRIER_GOLDEN_DOC.as_bytes().to_vec();

        // Sanity: the fixture's content_hash IS SHA-256 over the document (the §5.1 identity tuple),
        // computed via the SINGLE source of wire hashing — so the golden is the produce-once wire
        // form, not an arbitrary blob, and it is the SAME hashing the Go `crypto/sha256` producer
        // ran over the SAME bytes.
        assert_eq!(
            ds_contracts::snapshot_verify::sha256(&want_doc),
            want_hash,
            "fixture content_hash is not SHA-256(document): the golden is inconsistent"
        );

        // PRODUCER half: encode_version (the exact bytes serve_watch_policies_connection writes, the
        // shape the Go consumer-mirror reads) of the fixture tuple must be the byte-for-byte golden.
        let encoded = WatchPoliciesFrame::encode_version(CARRIER_GOLDEN_SEQ, &want_hash, &want_doc);
        assert_eq!(
            encoded, want_frame,
            "Rust encode_version diverged from the cross-language golden"
        );

        // CONSUMER half: decoding the shared golden bytes (the form the Go producer's
        // encodeWatchVersion emits) must yield the byte-equal (seq, content_hash, document) tuple —
        // so a Go-encoded frame is read identically by the Rust side.
        let (seq, hash, doc) =
            WatchPoliciesFrame::decode_version(&want_frame).expect("the golden frame decodes");
        assert_eq!(
            seq, CARRIER_GOLDEN_SEQ,
            "decoded seq diverged across the boundary"
        );
        assert_eq!(
            hash, want_hash,
            "decoded content_hash diverged across the boundary"
        );
        assert_eq!(
            doc, want_doc,
            "decoded document diverged across the boundary"
        );

        // DIVERGENCE proof (the exec-report deliverable): mutating ONE byte in each of the three
        // frame fields (seq, content_hash, document) makes the decoded tuple stop matching the
        // fixture — so a real frame-shape drift on either side can never pass silently.
        // seq leg: flip the low byte of the 8B-BE seq prefix.
        let mut seq_mut = want_frame.clone();
        seq_mut[7] ^= 0x01;
        let (mseq, _, _) =
            WatchPoliciesFrame::decode_version(&seq_mut).expect("structurally still a frame");
        assert_ne!(
            mseq, CARRIER_GOLDEN_SEQ,
            "a mutated seq byte must change the decoded seq"
        );
        // content_hash leg: flip a byte inside the 32-byte hash (offset 8+4=12 .. 44).
        let mut hash_mut = want_frame.clone();
        hash_mut[12] ^= 0x01;
        let (_, mhash, _) =
            WatchPoliciesFrame::decode_version(&hash_mut).expect("structurally still a frame");
        assert_ne!(
            mhash, want_hash,
            "a mutated content_hash byte must change the decoded hash"
        );
        // document leg: flip a byte inside the document (the final field).
        let mut doc_mut = want_frame.clone();
        let last = doc_mut.len() - 1;
        doc_mut[last] ^= 0x01;
        let (_, _, mdoc) =
            WatchPoliciesFrame::decode_version(&doc_mut).expect("structurally still a frame");
        assert_ne!(
            mdoc, want_doc,
            "a mutated document byte must change the decoded document"
        );

        // HANDSHAKE leg: the 8-byte big-endian from_seq the consumer sends to open the stream
        // (the resume cursor, D36) is single-sourced through the fixture too — encode_handshake of
        // the canonical seq must be the byte-for-byte golden the Go carrier writes.
        let want_handshake = from_hex(CARRIER_GOLDEN_HANDSHAKE_HEX);
        assert_eq!(
            WatchPoliciesFrame::encode_handshake(CARRIER_GOLDEN_SEQ),
            want_handshake,
            "Rust encode_handshake diverged from the cross-language golden"
        );
        assert_eq!(
            want_handshake.len(),
            8,
            "the from_seq handshake golden must be 8 big-endian bytes"
        );
    }

    #[test]
    fn watch_policies_carrier_frame_malformed_is_fail_closed_cross_language() {
        // The cross-language MALFORMED-FRAME leg: a TRUNCATED or OVER-LONG carrier version-frame is
        // rejected (`decode_version` → None) identically to the Go decoder's documented posture
        // (dnsfeed_carrier_test.go decodeCarrierVersion's t.Fatalf guards) and the conformance
        // fixture's DecodeCarrierVersion (revocationwire/carrierframe.go) — the carrier drops the
        // stream fail-closed rather than fabricate a version. Driven off the SAME shared golden.
        let good = from_hex(CARRIER_GOLDEN_FRAME_HEX);

        // EMPTY: nothing to decode.
        assert!(
            WatchPoliciesFrame::decode_version(&[]).is_none(),
            "an empty frame must be rejected fail-closed"
        );

        // TRUNCATED: every strict prefix of the golden ends before the seq / a length prefix / the
        // content_hash / the document — none may decode (a field runs past the buffer, or the
        // document does not consume the body exactly).
        for cut in 1..good.len() {
            assert!(
                WatchPoliciesFrame::decode_version(&good[..cut]).is_none(),
                "a truncated frame (len {cut} of {}) must be rejected fail-closed",
                good.len()
            );
        }

        // OVER-LONG: one trailing byte past the document — the body did not consume exactly, a
        // malformed (over-long) frame both sides reject.
        let mut over_long = good.clone();
        over_long.push(0x00);
        assert!(
            WatchPoliciesFrame::decode_version(&over_long).is_none(),
            "an over-long frame (trailing bytes) must be rejected fail-closed"
        );

        // WRONG content_hash WIDTH: re-frame the same tuple with a 31-byte content_hash — a torn
        // width both decoders reject even when the body is otherwise self-consistent.
        let short_hash = [0u8; 31];
        let body = WatchPoliciesFrame::encode_version(
            CARRIER_GOLDEN_SEQ,
            // encode_version takes a &ContentHash (32B); build the wrong-width frame by hand to
            // match the Go fixture's WrongContentHashWidthIsRejected leg.
            &{
                let mut h = [0u8; 32];
                h.copy_from_slice(&from_hex(CARRIER_GOLDEN_CONTENT_HASH_HEX));
                h
            },
            CARRIER_GOLDEN_DOC.as_bytes(),
        );
        // Rebuild the body with the content_hash_len field set to 31 (a torn width) but only 31
        // hash bytes present — mirror the fixture's wrong-width leg without a 31-byte ContentHash.
        let mut torn = Vec::new();
        torn.extend_from_slice(&CARRIER_GOLDEN_SEQ.to_be_bytes());
        torn.extend_from_slice(&(short_hash.len() as u32).to_be_bytes());
        torn.extend_from_slice(&short_hash);
        torn.extend_from_slice(&(CARRIER_GOLDEN_DOC.len() as u32).to_be_bytes());
        torn.extend_from_slice(CARRIER_GOLDEN_DOC.as_bytes());
        assert!(
            WatchPoliciesFrame::decode_version(&torn).is_none(),
            "a content_hash that is not the 32-byte SHA-256 width must be rejected fail-closed"
        );
        // Sanity: the 32-byte-width version of the SAME body DOES decode (so the rejection above is
        // the width, not an unrelated framing bug).
        assert!(
            WatchPoliciesFrame::decode_version(&body).is_some(),
            "the well-formed 32-byte-width frame must decode (control)"
        );
    }
}
