# orchestrator/ — control plane + per-host agent

**Owner workstream:** Orchestrator (doc 05 §3). **License:** OSS — the entire
tree is Apache-2.0 (D25/D80); it is listed in `oss-manifest.yaml`.

This tree is the **productivity control plane** (D28): one command to a running
session in seconds, parallel fleets routed per call, collaboration surfaces fed
from one event stream. Concretely it owns session/VM lifecycle, the session
record (the never-recycled index→UUID join key everything else joins through),
policy_log + WatchPolicies serving, the WatchSession event leg and attach
handles, placement, attendedness computation, env-config recording, and
metering. Primary doc: doc 15 — read it
before touching anything here.

## Shape: two services + one all-in-one (D35, D80)

| Binary | What it is |
|---|---|
| `cmd/orchestrator` | Stateless control-plane replicas over external Postgres (D6); reconciler, scheduler, WatchSession fan-out, WatchPolicies serving |
| `cmd/host-agent` | Per-host agent: the ONE WatchPolicies subscriber per host (D72), snapshot fan-out (admitter-last), tap/IP/index allocation, event-socket termination (D38), and the **libvirt driver** (doc 15 §5.1 puts it here, not in `vm/`) |
| `cmd/orchestrator-lite` | **IS the OSS single-host all-in-one** (D80) — M0's orchestrator and a first-class assembly forever. Not a demo build; no feature flags. The paid fleet control plane is a *distinct M3 service* in `paid/fleet/`, speaking the **same public protos** (D58) — the OSS/paid line falls on a service boundary, never through a binary |

`internal/` package charters live in each package's `doc.go`. The Go↔Rust edge
is exactly one package: `internal/nftbridge` (cgo to the `ds-nft` staticlib;
content_hash contract tests — doc 15 OQ3 / doc 13 OQ2).

### Control-plane wiring — `internal/controlplane` (the capstone)

`internal/controlplane.NewControlPlane` assembles the three constructible
components shipped deliberately un-wired — the §4.1 session-create coordinator
(`internal/sessions`), the level-triggered reconciler (`internal/reconciler`),
and the §7 scheduler (`internal/scheduler`) — plus the scheduler `Adapter` and
the concrete `Redriver` into ONE runnable control plane, so `cmd/orchestrator`'s
`main.go` is a thin bootstrap that constructs the backends and calls it
(doc 15 §3 / §4.1). Three legs converge on
the wiring:

- **(a) `CreateSession` RPC** — `SessionService` implements the frozen
  `orchestrator.v1` `SessionService.CreateSession` over `sessions.SessionCreator`
  (the §4.1 ten-step spine), built with the production hypervisor.v1 gRPC-backed
  host seams (`seams.go`) + the Identity/boundary mint/digest/inject/boot/revoke
  seams (`identityseams.go`), and the **single-store coherence** accessor
  (`StoreSeamsStrict`) so the launch-gate linker, the `launching_user` resolver,
  and the role-pin writer provably share one store (D95/D106).
- **(b) reconciler driving loop** — `reconcileLoop` (`reconcileloop.go`) is the
  single-goroutine owner: it `Observe`s per inbound `hostagent.v1.Heartbeat`
  (recording the live feed) and `Resync`s on cadence, honoring the `lastBeat`
  single-goroutine contract. The `ConcreteRedriver` is wired with
  `SpineRunnerFunc(RedriveSpine)` + a host-side re-create continuation
  (`redrive.go`) and passed as `reconciler.New`'s redriver argument (§3 rule b).
- **(c) scheduler placement** — `scheduler.Adapter` is injected as the
  `SessionCreator`'s `Placer` (§4.1 step 3), built over the
  `StoreCandidateSource` (the live `HeartbeatStore` feed + tenancy scope + the
  store lister) and a policy_log-head `PolicySeqSource`
  (`store.PolicyHead`, the additive `controlplane_wiring_queries.go`).

The whole assembly is unit-tested against the generated hypervisor.v1 fake +
synthetic fixtures with no live VM/host-agent/podman (D50); the live network
edges (host-driver dials, the Identity D22/D82 service, Postgres) are env-gated
in `main.go` (`DS_ORCH_LIVE=1`). With the deployment-input edges filled (below),
a live run constructs `NewControlPlane` end-to-end and the full path **dial →
serve → `CreateSession` → reconcile closes**.

**Live edges landed (every transport + deployment-input edge, env-gated behind
`DS_ORCH_LIVE`, D50).** The capstone's env-gated `liveDeps`/`serve` stubs are now
filled with the real edges (still gated; tests use fakes + bufconn, never a live
backend):

- **(a) host-driver dial** — `NewDialRegistry` (`dialregistry.go`) is the
  production `DriverRegistry`: it resolves a host_id to its per-host
  `hypervisor.v1` driver client by dialing the host's endpoint
  (`DS_ORCH_HOST_DRIVERS`, lazy + cached), wraps the dialed generated client in a
  `ClientShim`, and `Close`s every connection at shutdown. The dial stays confined
  to `internal/controlplane`; tests exercise dial→cache→resolve→close over a
  bufconn-served `hypervisor.v1` fake (D50, no live host-agent). A deployment that
  fronts the internal D35 host-agent link with mutual TLS (doc 15 §2) supplies the
  orchestrator client cert/key/CA via `DS_ORCH_TLS_CERT`/`DS_ORCH_TLS_KEY`/
  `DS_ORCH_TLS_CA` PATHS, and `cmd/orchestrator/mtls.go` (`hostDriverDialOpts` →
  `controlplane.MTLSDialOptionFromEnv`) is the bootstrap composition that turns those env-named
  PEM PATHS into the registry's transport-credentials `DialOption`: it loads the
  client keypair + CA-pinned `RootCAs` and threads `grpc.WithTransportCredentials`
  onto `NewDialRegistry`'s variadic `DialOption` tail from `liveDeps` (no
  interface/wiring change; the cmd-side builder reuses the controlplane-exported
  `EnvDialTLS*` name constants and the dial seam's variadic tail, so it never
  edits `dialregistry.go`). NONE-set keeps the insecure default for the internal
  isolated link; a SOME-but-not-all triplet or a non-PEM CA is a hard construction
  error (a live run fails loudly rather than silently downgrade transport
  security). Proven with synthetic in-test certs, no live dial (D50).
- **(b) gRPC serve + registration** — `ControlPlane.Register` puts `SessionService`
  (orchestrator.v1) AND the heartbeat ingest (hostagent.v1) on a `grpc.Server`;
  `controlplane.Serve` (`serve.go`) constructs the server, registers both, starts
  the reconcile-loop `Run`, listens, and graceful-stops on context cancel.
  `cmd/orchestrator/main.go` is the thin bootstrap binding the real TCP listener
  (`DS_ORCH_LISTEN`); tests register + drive a `CreateSession` over bufconn.
- **(c) heartbeat ingest → `Reconcile.Observe`** — `heartbeatIngest`
  (`heartbeatingest.go`) is the orchestrator-side `hostagent.v1`
  `HostAgentService.ReportHeartbeat` client-streaming server: it drains each
  inbound frame's `Heartbeat` through the reconcile loop's `Observe`, so a beat
  both updates the live `HeartbeatStore` feed (the scheduler's candidate input)
  AND submits a reconcile (the level-triggered drop-on-full-buffer semantics
  preserved). Imports stay `proto/gen/go` + `google.golang.org/grpc`
  (D35/D72/D95/D106/D50).
- **(d) deployment-input edges → the path closes** (`liveedges.go`) — `liveDeps`
  no longer fail-closes on the store + Identity/boundary backends:
  - **External Postgres store (D6/D33)** — `NewPostgresStore` opens
    `*store.Postgres` from `DS_ORCH_PG_DSN` (driver `DS_PG_DRIVER`, default
    `postgres`; the operator registers a Postgres driver at the binary boundary,
    the module stays stdlib-only). An unset DSN selects `*store.Memory` (the
    single-binary posture — a dev live run closes without an external DB).
  - **Identity D22/D82 mint/digest/revoke** — `NewIdentityClients` dials the
    `identity.v1` mint + digest faces (`DS_ORCH_IDENTITY_ENDPOINT`) and assembles
    the `MintClient`/`DigestClient`/`RevokeClient` seams (`MintInterceptionCA`
    step 5 D82; `DigestPublish` step 6 D73, the routable gate reads `committed`;
    `DigestRevoke` session-scope, the step-5/6 rollback). The dial stays confined
    to `liveedges.go` — `mintShim`/`digestShim` adapt the generated clients onto
    narrow generated-fake-shaped wire faces, so the generated `identityv1fake`
    satisfies them natively in tests (the `ClientShim` discipline).
  - **Boundary CA-inject + boot (steps 7–8)** — host-folded: the host agent's
    libvirt driver runs the fail-closed CA injection (D17/D29) + boot (D38)
    host-side inside `CloneFromImage`, so the `InjectClient`/`BootClient` are the
    host-folded adapter (an M3 split onto a boundary RPC swaps the adapter, not
    the seam).

  The live constructors are unit-tested via the generated `identity.v1` fakes (a
  clean §4.1 step-5/6 mapping + the fault/uncommitted paths) and the closed path
  is asserted by a `CreateSession` over a bufconn against a `ControlPlane` wired
  from the live constructors (no live backend, D50). Imports stay `proto/gen/go`
  + `google.golang.org/grpc` + `database/sql` (D6/D22/D33/D82/D50).

**Operator runbook — Control-link mTLS cert rotation/renewal (D22, doc 15 §2.1).**
The control-link mTLS material is **short-lived by design** (D22: the orchestrator
mints short-lived per-session certs/tokens; the same machinery backs the
control-link keypairs), so the operator's job is to **renew before expiry**, never
to let a cert lapse. A lapsed cert is a *control-link* interruption only — a
cert-expired host-agent dial is a TLS handshake failure that surfaces as
`ErrNoDriverForHost` and drops the host into the missed-heartbeat recovery path
(doc 15 §2.1 degraded-mode posture): running sessions and the kernel boundary floor
keep working, but new create/suspend/destroy drives to that host stall until the
link re-establishes. The design-level rotation precedence (renew strictly before
expiry; the bring-compute fleet-stagger window) lives in doc 15 §2.1; this is the
concrete env-var-and-steps procedure.

- **The material under rotation.** Two leaves rotate independently:
  - **Orchestrator client material** — the `DS_ORCH_TLS_CERT` / `DS_ORCH_TLS_KEY`
    / `DS_ORCH_TLS_CA` PEM **paths** the bootstrap (`cmd/orchestrator/mtls.go`
    `liveDialOpts` → `controlplane.MTLSDialOptionFromEnv`) loads to dial each
    host agent with CA-pinned transport credentials. This is the leaf the
    *orchestrator* presents (hosted tier) or trusts against (the host-agent CA on
    the bring-compute/on-prem dial-in).
  - **Host-agent keypair** — at the bring-compute and on-prem tiers each host
    agent's own D22 keypair, presented when it dials out to `DS_ORCH_LISTEN`.

- **Renewal step (per cert, before expiry).** Renewal is a **re-mint of a leaf**
  through the off-host D22 mint service — the long-lived signing roots never leave
  the D39 trust zone, so an operator never re-keys a root:
  1. Re-mint the leaf (cert + key) and refresh the CA bundle from the same D22
     issuer that minted the current one.
  2. Stage the new PEM files at fresh paths (or atomically replace the files the
     `DS_ORCH_TLS_*` paths point at — write-to-temp + `rename(2)` so a partial
     write is never read).
  3. **Restart-to-rotate at v0:** the env paths are loaded ONCE at bootstrap
     (`MTLSDialOptionFromEnv` builds the credentials at construction, not per dial),
     so picking up rotated material is a graceful orchestrator restart (the
     stateless control-plane replicas restart without dropping running sessions —
     reconnect supersedes the prior dial-cache link; the verbs are idempotent on
     `session_uuid`). Rolling the replicas one at a time keeps the fleet's control
     link continuously served. A hot SIGHUP re-read of the `DS_ORCH_TLS_*` paths
     without a restart (a graceful credential-reload that re-runs
     `MTLSDialOptionFromEnv` and recycles the dial-cache) is a future hardening, not
     the v0 path.
  4. Validate the new material before retiring the old: a mis-paired cert/key, a
     partial (SOME-but-not-all) triplet, or a non-PEM CA is a **hard construction
     error** at the next bootstrap (`MTLSDialOptionFromEnv` / `loadDialTLSCredentials`
     fail loudly rather than silently downgrade to the insecure default), so a
     botched rotation fails the restart visibly instead of dialing unprotected.

- **Cadence (relative to the short-lived TTL).** Begin renewal at **~⅔ of the
  cert TTL** (the operator default), i.e. no later than `TTL − margin` where the
  margin exceeds the worst-case re-mint-plus-restart latency — so the replacement
  is in place with a full third of the lifetime left as recovery slack for a
  transient mint/store outage. Shorter TTLs simply mean more frequent re-mints;
  the precedence (replacement-before-expiry) is what matters, not a fixed wall-clock
  period.

- **Bring-compute rotation window — no fleet-wide control-link interruption.** At
  the bring-compute tier mTLS is *required* and every customer host multiplexes its
  `HypervisorDriver` + `WatchPolicies` streams over one outbound link, so a
  fleet-wide *simultaneous* expiry would drop every host's control link at once.
  **Stagger the issuance/renewal schedule across the fleet** (offset cert lifetimes
  so they do not align on a single expiry instant), and renew per host by
  **establishing a fresh outbound link with the new credential and only then
  retiring the old one** — a reconnect supersedes the prior link (doc 15 §2.1 "a
  reconnect supersedes the prior link"), and the brief overlap is harmless because
  the verbs are idempotent on `session_uuid`. The hosted tier carries the same
  window wherever mTLS is armed; the on-prem tier inherits it under the customer's
  own D22-equivalent issuer (D33: no cloud managed-cert service assumed).

  Verify the result on the admin surface — a host whose link dropped on a missed
  rotation reads `UNKNOWN` on `orchestrator_host_liveness` / `/debug/liveness` (the
  liveness runbook below), and flips back to `LIVE` on the next scrape once the
  renewed credential re-establishes the dial.

  > Mint-side bookkeeping: the per-session credential's expiry is surfaced through
  > the `MintClient` seam (`MintReply.Expiry`, the optional `MintWithExpiry`
  > extension) and fired through the `sessions.CreateSeams.OnMintExpiry` re-mint
  > sink (D22/D82, doc 16 §5.4 "expired creds re-mint"); that path tracks the
  > **per-session** workload-identity/CA TTL inside a live session, distinct from the
  > **control-link** keypair rotation this runbook covers (the control link is a
  > host/fleet-lifetime credential, not a session-lifetime one). Both ride the same
  > short-lived-by-design D22 posture.

**Two notes on the capstone's edges:**

- **Re-drive restores a FULLY-routable VM** — the rule-b host re-create
  continuation now re-drives §4.1 step 6 (the D73 session-scoped digest re-write +
  host-agent re-ack, D109): a re-created VM lost its host-side digest state with the
  domain, so re-materializing the domain (step 4) without re-acking the digest would
  leave a HALF-CONVERGED VM the step-9 routable gate (`{3,6} ≺ 9`) would refuse. The
  seam is installed through the variadic `withDigestReAck(d.Digest)` option on
  `newHostReCreate` and re-acks through the SAME Identity-owned (D22/D82) step-6 face
  the create coordinator drives; a write that the host does NOT ack is the structural
  refusal `sessions.ErrDigestNotAcked` (D73), so the reconciler takes the §3 rule-b
  fail arm rather than declaring a not-routable VM converged. Idempotent on
  `session_uuid` (the host re-acks a re-written digest). Landed +
  test-pinned in `internal/controlplane/redrive.go` (+ `redrive_test.go`); the seam
  is OPTIONAL, and it is installed at the `wiring.go` re-drive construction site so
  the production re-drive re-acks rather than running the pre-D73 convergence-only
  posture — **the production continuation carries `withDigestReAck(d.Digest)`**
  (D73/D109/D72/D22/D82).
- **Quarantine host hint** — `registryDriver.runVerb` fleet-broadcasts an orphan's
  idempotent quarantine verb to every host (O(hosts) per orphan); thread the
  observing host (known from its `hostagent.v1.Heartbeat`, D72) as an optional
  hint to target the one host, falling back to broadcast when unresolved, WITHOUT
  widening the frozen `reconciler.Driver` seam (D35 rule-a quarantine-not-destroy
  unchanged). A scale optimization, fine to leave at v0 few-host scale; revisit
  near the ~500-host checkpoint. Extends `internal/controlplane/seams.go`.

**Create-spine residual windows now closed (D66/D72):** two honest-correctness
windows on the create coordinator (`internal/sessions/sessioncreate.go`) are now
shut:

- **Retry-vs-resurrection guard (D66)** — `CreateSession` is idempotent on the
  session UUID, and the store validates state *vocabulary*, not §3 *transitions*,
  so a same-store retry by UUID after an earlier attempt finalized the row
  (DESTROYED — the sole terminal state, `store.SessionState.IsTerminal`) would
  have had the next step (placement → `UpdateSession(State=CREATING)`) silently
  *resurrect* a finalized, retained (D66) record. The coordinator now refuses
  fail-closed at step 2 (`ErrSessionFinalized`): a retry of a finalized session
  must mint a FRESH UUID; a still-live non-terminal record is returned
  idempotently as before (a legitimate resuming retry, not a resurrection).
- **Live step-9 freshness probe (D72)** — `recheckFreshness` re-read only the
  *recorded* `PolicyAppliedSeq`, catching a reconciler-marked-stale host but NOT
  a host that fell behind in the placement→step-9 window with no record write.
  The §4.1 step-9 routable gate now also re-validates the placed host's CURRENT
  applied_seq via the additive `Placer.CurrentFreshness` probe (backed
  production-side by `scheduler.Adapter`'s optional `HostFreshness` seam), closing
  that residual D72 window. The probe is additive — `Placer.Place` and the
  `Adapter`/`SessionCreator` constructors are unchanged — and an unprobeable host
  (no live-freshness seam wired, or the placed host absent from the live feed,
  both surfacing as `ErrFreshnessUnknown`) degrades to the recorded re-check (the
  pre-probe behavior, never newly stricter): there is no live signal to judge, so
  the create proceeds on the recorded freshness the recorded re-check just vouched
  for. The degrade is emitted as an observable WARN log AND increments an
  aggregatable stdlib `expvar.Int` counter
  (`orchestrator_sessions_step9_freshness_degrade_total`, on the standard
  `/debug/vars` surface) at the exact degrade branch, so a residual-window
  admission is never silent in production and its RATE is graphable/alertable —
  not just greppable in logs (D72; stdlib-only, no new dependency, constructors
  unchanged). The same degrade branch also bumps a companion `expvar.Map`
  (`orchestrator_sessions_step9_freshness_degrade_by_host`) keyed by the placed
  `host_id`, so the rate splits BY host: one hot key is a single host falling
  behind, many keys climbing together is a systemic live-freshness outage — the
  flat total stays the unbroken fleet observable, the per-host map rides next to
  it (never instead of it). Only a live probe that DOES answer with
  a CURRENT seq beyond the staleness budget fails closed (`ErrPolicyStale`), never
  waved through to READY.
- **Per-host degrade map cardinality guard (D72)** — an `expvar.Map` keyed by an
  unbounded id is an operational cardinality risk: `/debug/vars` renders EVERY
  key, so a churny fleet (hosts cycling in/out) or a buggy caller (a placement
  loop minting fresh `host_id`s) could grow
  `orchestrator_sessions_step9_freshness_degrade_by_host` without bound and bloat
  the `/debug/vars` payload an operator or scraper pulls. The map is therefore
  bounded by an LRU eviction policy (default `1024` distinct keys,
  `internal/sessions/sessioncreate.go`): it retains the most-recently-degraded
  ACTIVE set as exact per-host keys, and when a NEW host would push past the cap
  the LEAST-recently-degraded host's key is evicted and its accumulated count is
  folded into a single reserved overflow bucket (the `__other__` key, which itself
  never counts toward the cap). So the map size is bounded at the effective cap
  + 1 keys (the active set plus the overflow bucket), the per-host signal stays
  EXACT within the active set, and no degrade is ever lost — every increment lands
  in either a per-host key or `__other__`. The default cap (1024) is generous: far
  above any realistic single-rack active host fleet, so in normal operation every
  degrading host keeps its own exact key and the cap bites only under pathological
  churn. The flat fleet total
  (`orchestrator_sessions_step9_freshness_degrade_total`) is **untouched** by the
  guard — it counts every degrade unconditionally — so adding the bound does not
  perturb the pre-existing total observable.

  **Operator knob — `DS_ORCH_DEGRADE_HOST_CAP` (D72).** The active-set cap is an
  env-gated runtime knob, so an operator can retune the bound without a recompile:
  set `DS_ORCH_DEGRADE_HOST_CAP` to a positive integer to raise it (a larger fleet
  that wants exact per-host attribution for more hosts) or lower it (a tighter
  `/debug/vars` payload budget). It is read EXACTLY ONCE at construction
  (`resolveDegradeHostCap`, wired into the process-global guard's package-init
  construction) — never on the per-degrade hot path, so tuning it costs nothing at
  runtime. The fallback is fail-safe: an unset, empty, non-integer, or non-positive
  value falls back to the `1024` default (and a non-empty malformed value is logged
  ONCE at startup so the misconfiguration is visible without breaking boot), and the
  resolved cap is floored at `>=1` — so a bad knob can never configure the map into
  an unbounded (or a zero) state. The eviction/overflow policy is unchanged; only the
  cap VALUE becomes env-driven.

  **Operator runbook — reading the degrade map on `/debug/vars`.** The admin
  surface is served by `cmd/orchestrator/startAdminServer` (`admin.go`) — it mounts
  the stdlib `expvar.Handler()` at `/debug/vars` on a dedicated `net/http` listener,
  armed only when `DS_ORCH_ADMIN_ADDR` is set (e.g. `DS_ORCH_ADMIN_ADDR=127.0.0.1:6060`)
  and reached only under the `DS_ORCH_LIVE=1` bootstrap (D50: a non-live run and an
  unset addr bind no admin socket); it serves on a PRIVATE mux (exactly `/debug/vars`,
  never `http.DefaultServeMux`) and graceful-stops with the rest of `run()`. The
  surface is hardened fail-closed: it binds LOOPBACK by default (a non-loopback addr is
  refused at startup unless an explicit opt-out is armed) and takes an OPTIONAL bearer
  token — see "Securing the admin surface" below before exposing it. Pull the surface
  (`curl -s http://<orch-admin>/debug/vars`) and inspect four vars:
  1. `orchestrator_sessions_step9_freshness_degrade_total` — the FLEET total rate
     of residual-D72-window admissions (unprobeable hosts admitted on the recorded
     re-check alone). Graph/alert on its RATE; a flat zero means the live-freshness
     probe is wired and answering for every placement.
  2. `orchestrator_sessions_step9_freshness_degrade_by_host` — the SAME degrades
     split by `host_id`. One hot key is a single host falling behind (chase that
     host's heartbeat/applied_seq); many keys climbing together is a systemic
     live-freshness outage (the live-probe seam is down, or a broad fleet lag).
  3. The `__other__` key INSIDE that map is the overflow bucket. A non-zero (and
     especially a climbing) `__other__` means MORE distinct hosts have degraded
     than the active-set cap (`DS_ORCH_DEGRADE_HOST_CAP`, default 1024) retains —
     itself a breadth/churn signal: the degrade is broad enough that the per-host
     attribution has saturated, so read it together with the flat total (which
     still counts those degrades exactly) and treat it as "fleet-wide degrade
     breadth", not a single-host problem. The map is guaranteed bounded at the
     effective cap + 1 keys (1025 at the default), so the `/debug/vars` payload for
     this var never grows without bound regardless of fleet churn — and a saturated
     `__other__` is the signal to raise `DS_ORCH_DEGRADE_HOST_CAP` if exact
     attribution for more hosts is wanted.
  4. `orchestrator_sessions_step9_degrade_host_cap` — the static, init-time
     SELF-REPORT of the RESOLVED effective per-host degrade-map cap (D72): the
     distinct-`host_id` key bound that the active set in var 2 is held to, already
     resolved from the `DS_ORCH_DEGRADE_HOST_CAP` knob (default `1024`, floored at
     `>=1`) at `NewSessionCreator`. Read it to CONFIRM which cap actually booted —
     env-applied vs the default-1024 fallback vs the `>=1` clamp — rather than
     GUESSING whether `DS_ORCH_DEGRADE_HOST_CAP` was applied. It pairs with the
     `__other__` overflow signal above: a saturated (climbing) `__other__` read
     together with this var's value tells an operator the active set is full at the
     booted cap, so raising `DS_ORCH_DEGRADE_HOST_CAP` (and confirming the new value
     here on the next boot) is the lever to recover exact per-host attribution. Like
     the budget below it is a static configuration readout published ONCE at init
     (never touched on the per-degrade hot path), so it never moves after startup.
  5. `orchestrator_sessions_step9_staleness_budget` — the RESOLVED step-9 staleness
     budget (the re-check window, D72): how far behind its placement `applied_seq` a
     host's CURRENT (or recorded) `applied_seq` may fall before `recheckFreshness`
     fail-closes the session as `ErrPolicyStale` (not freshness-routable). It is a
     static configuration readout published ONCE at `NewSessionCreator` from the
     INSTANCE-scoped `SessionCreator.stalenessBudget` the wiring passes
     (`controlplane.Dependencies.StalenessBudget`), with a negative input clamped to
     `0` (the strictest budget — an exact `applied_seq` match required). It never
     moves after startup. Read it to CONFIRM the effective window the gate booted with
     (the wired value vs the `0` clamp) rather than inferring it from a refusal: a `0`
     means exact-match-only; a larger value is the slack the gate tolerates before it
     refuses (a high value loosens the freshness gate — pair it with the degrade
     observables above to see how often the live re-check is even running). This is the
     same self-report seam as `..._degrade_host_cap`, applied to the per-instance
     re-check window (the budget is construction-resolved; this var surfaces it).
  6. `orchestrator_host_liveness` — the per-host **LIVE/UNKNOWN liveness readout** (doc 15
     §3/§5.2; D35/D72): the queryable form of the "3 missed beats → UNKNOWN" annotation the
     missed-beat sweep otherwise raises only as the `AlarmHostUnknown` operator alarm, so an
     operator can answer "which hosts are UNKNOWN right now?" without scraping the alarm log.
     It renders a JSON array, one object per host — `host_id`, `liveness` (`LIVE`/`UNKNOWN`),
     `ever_seen`, `last_beat_unix`, `since_last_beat_seconds`, `silence_window_seconds` — sorted
     by `host_id`, so each entry is self-describing (a `UNKNOWN` host reads "silent 30s, window
     15s" without re-deriving it). `UNKNOWN` is a NON-state liveness annotation, never a §3
     record state and never a record mutation: an `UNKNOWN` host's sessions are never
     auto-destroyed, and the moment heartbeats resume the next scrape flips the host back to
     `LIVE`. The readout is served by the LOOP-SERIALIZED snapshotter (the read marshals onto
     the reconcile-loop goroutine, the sole heartbeat owner — never a racing read of the live
     reconciler), and it is **single-surface-safe**: the process-global var renders exactly one
     admin surface's reconciler, and a second concurrent surface arming it is logged as a
     warning rather than silently clobbering the first (the production bootstrap arms exactly
     one surface). It is only published when the bootstrap threads the snapshotter in (the
     `DS_ORCH_LIVE=1` admin wiring); with no snapshotter the var is absent and `/debug/vars`
     stays byte-for-byte the historical degrade-only payload.

     **Never-seen enrichment (expected-but-silent hosts).** Under `DS_ORCH_LIVE` the bootstrap
     arms the snapshotter with a store-backed `ExpectedHostSupplier` (the distinct `host_id`s of
     the live, non-`DESTROYED` session records — the hosts that SHOULD be heartbeating). So a
     host that has a placed session but has **NEVER** heartbeated renders as `ever_seen:false` /
     `liveness:"UNKNOWN"` (a zero `last_beat_unix`) instead of being silently ABSENT — the case
     an operator most needs (a placed host that never came up). Without the supplier the readout
     reports only the heard-from hosts; the enrichment is purely additive (an empty live fleet
     degrades to the heard-from-only view).

  **Operator runbook — `/debug/liveness` (the dedicated liveness sub-handler).** Alongside the
  `orchestrator_host_liveness` var inside `/debug/vars`, the admin surface mounts a dedicated
  `GET /debug/liveness` route that renders the SAME per-host LIVE/UNKNOWN array as a standalone
  JSON document — the convenience face for the liveness view alone, rather than buried in the
  full expvar object. It rides the SAME private mux behind the SAME optional bearer guard as
  `/debug/vars` (a missing/mismatched token is `401` when `DS_ORCH_ADMIN_TOKEN` is set), is
  `GET`/`HEAD` only (any other method is `405`, the surface is read-only), and is mounted ONLY
  when the snapshotter is threaded in (a never-armed surface 404s the route). Each surface's
  `/debug/liveness` closes over ITS OWN snapshotter, so it stays correct per-surface even if a
  second surface re-points the process-global expvar var.

  ```sh
  # The liveness view alone (bearer required only when DS_ORCH_ADMIN_TOKEN is set).
  curl -fsS -H "Authorization: Bearer $(cat /run/secrets/orch-admin-token)" \
    http://127.0.0.1:6060/debug/liveness | jq '.[] | select(.liveness == "UNKNOWN")'
  ```

  **Securing the admin surface — loopback default + optional bearer token (D77).**
  The `/debug/vars` payload above exposes internal metric NAMES and VALUES (the
  degrade totals, the per-host map keyed by `host_id`, the resolved cap), so the
  surface is hardened fail-closed and must never be world-reachable by accident:
  - **Loopback bind is the default; a public bind is REFUSED at construction.** A
    non-loopback `DS_ORCH_ADMIN_ADDR` (a routable IP, `0.0.0.0`, `::`, a
    non-`localhost` hostname, or a BARE-PORT `:6060` — the empty host binds every
    interface, so it is non-loopback too) fails the bootstrap LOUDLY before any
    socket binds — the error names the addr and the opt-out. Bind a loopback address
    (`DS_ORCH_ADMIN_ADDR=127.0.0.1:6060`, or `[::1]:6060`); the surface is then
    reachable only from the host (curl it locally, or pull it over an SSH tunnel /
    `kubectl port-forward`). To deliberately front the surface on a routable
    interface — e.g. behind a TLS-terminating reverse proxy that itself
    authenticates the operator — set `DS_ORCH_ADMIN_ALLOW_NONLOOPBACK=1` to arm the
    explicit opt-out AND arm the bearer token below; an unauthenticated public bind
    is the operator's deliberate choice, never a silent default.
  - **Optional bearer token.** Set `DS_ORCH_ADMIN_TOKEN=<secret>` to require an
    `Authorization: Bearer <secret>` header on every `/debug/vars` request; a missing
    or mismatched header gets `401` (the secret is constant-time compared via
    `crypto/subtle`). When the token is UNSET on a loopback bind the surface serves
    unauthenticated — the dev-default, fine because only the host can reach it. The
    secret is **env-sourced only and never committed** (D50): supply it at the binary
    boundary, e.g. from a secrets manager. Stdlib-only throughout (`net/http`,
    `crypto/subtle`, `expvar`) — no new dependency.

  **Manual live smoke (DEFERRED, env-gated — not a CI lane).** The `run()` admin
  wiring is exercised in CI only via `startAdminServer` directly over a synthetic
  `127.0.0.1:0` listener (D50 — no live bootstrap, no live-network test); the
  end-to-end "the binary serves the real degrade counters" check is a runbook
  procedure an operator runs by hand against a live process, behind the same
  `DS_ORCH_LIVE` / `DS_ORCH_ADMIN_ADDR` gates:

  ```sh
  # 1. Start the orchestrator live with a loopback admin surface (+ optional token).
  DS_ORCH_LIVE=1 DS_ORCH_ADMIN_ADDR=127.0.0.1:6060 \
    DS_ORCH_ADMIN_TOKEN=$(cat /run/secrets/orch-admin-token) \
    ./orchestrator &

  # 2. Pull the surface from the host (the token is required only when it is set).
  curl -fsS -H "Authorization: Bearer $(cat /run/secrets/orch-admin-token)" \
    http://127.0.0.1:6060/debug/vars | jq '
      .orchestrator_sessions_step9_freshness_degrade_total,
      .orchestrator_sessions_step9_freshness_degrade_by_host,
      .orchestrator_sessions_step9_degrade_host_cap,
      .orchestrator_sessions_step9_staleness_budget,
      .orchestrator_host_liveness'

  # 2b. The per-host LIVE/UNKNOWN liveness readout alone, on its dedicated sub-handler —
  #     an expected-but-never-heartbeated host renders ever_seen:false / liveness:"UNKNOWN".
  curl -fsS -H "Authorization: Bearer $(cat /run/secrets/orch-admin-token)" \
    http://127.0.0.1:6060/debug/liveness | jq '.[] | {host_id, liveness, ever_seen}'

  # 3. Without DS_ORCH_ADMIN_TOKEN set, drop the -H header (loopback dev-default).
  # 4. A non-loopback DS_ORCH_ADMIN_ADDR refuses at startup unless
  #    DS_ORCH_ADMIN_ALLOW_NONLOOPBACK=1 is also set (then the token is mandatory).
  ```

  Confirm the vars render with live values (a fresh process shows the degrade totals at `0`
  and the cap at its resolved value — `1024` by default or the `DS_ORCH_DEGRADE_HOST_CAP`
  override) and that `orchestrator_host_liveness` / `/debug/liveness` list the fleet's hosts
  with their derived LIVE/UNKNOWN annotation (a placed-but-silent host as `UNKNOWN`). This step
  requires a live orchestrator and so is intentionally left as a manual operator procedure, not
  automated in CI.

## Contracts

This workstream's three proto packages — `dreamserpent.orchestrator.v1`,
`hypervisor.v1`, `hostagent.v1` — live in `../proto/` (the single contract
home; zero `.proto` files in this tree, CI-enforced). Per doc 05 OQ3
(confirmed), this workstream publishes **contract-first fakes first**; see
[`fakes/README.md`](fakes/README.md) for the deliverable list, headed by the
D49 cassette-driven WatchSession fake. The only cross-tree Go import this
module may take is `proto/gen/go`.

## What must NOT live here

- **MintIdentity / any CA or digest machinery** — deliberately a SEPARATE
  service (D22/D82) so the M3 SPIFFE move stays a substrate swap; lives in
  `identity/`. The orchestrator never holds or transits long-lived
  credentials (D39).
- **Runtime-specific knowledge** (D38/D20) — it launches "an image plus an
  entrypoint config"; per-runtime adapters live in `client/wrapper/adapters/`.
- **Registry-protocol code** — D41 is a buy (Nexus CE); deploy config only,
  in `images/cache/`.
- **Policy language / guardrail semantics** — doc 13 owns these; this tree
  composes and distributes policy, it does not define it.
- **Suspend/resume TCP mechanics and netflow attribution** — Boundary-owned
  (`dataplane/`); the 30–60 s socket hold is explicitly not a VM state (D77).
- **Host bootstrap config over the policy stream** — the host baseline is a
  distinct artifact (doc 14 §11),
  `dataplane/artifacts/host-baseline/`.
- **Fleet scheduling/rebalancing/dashboards** — the paid M3 service,
  `paid/fleet/` (D80).
- **A generic multi-hypervisor layer or a Firecracker driver** (D30) — see
  `internal/hypervisor/libvirt/doc.go`.
- **Env-spec schema** — UNOWNED (doc 15 OQ10); only the RecordEnvConfig
  reference shape is frozen here.

## Neighbors

- `proto/` — contracts + generated stubs/fakes (`proto/gen/go` is the one
  shared Go module).
- `dataplane/` — the boundary services the host agent fans snapshots out to;
  `ds-nft` is linked via `internal/nftbridge` only. Pinned Rust-side choices
  (pingora 0.8.x, hickory 0.26.x, one tokio major) are recorded there, not here.
- `vm/` — guest-side entrypoint + disk tooling; the driver stays here
  (doc 15 §5.1); the tap-create RACI row is OPEN (settles with Boundary before
  the Stage-1 spike).
- `identity/` — D22 validate seam, D82 CA mint, D73 digest feed; consumed at
  create steps 5–6.
- `roles/` — session-role schema + built-in bundles; this workstream is the
  **proposed** steward (doc 18 §4, not yet ratified in the decision log):
  create-time `role_ref` resolution and session-record pinning
  would live in this tree, while bundle contents stay owned elsewhere.
- `infra/` — provisioning shims (govmomi = the one throwaway layer), owned by
  this workstream (doc 15 §2).
- `assurance/contract-harness/` — the dual-run harness whose **first seam is
  orchestrator ↔ host-agent** (doc 15 §11).

## Governing decisions

D6, D28, D30, D32, D33, D35–D39, D44, D46, D49, D56, D57, D66, D72, D73,
D77–D82 — log of record: doc 04 §6;
design: doc 15; roadmap:
doc 05 §3, §7–§8.
