package controlplane

// wiring.go is the CONTROL-PLANE CAPSTONE: it assembles the three constructible
// components shipped deliberately un-wired (the §4.1 session-create coordinator, the
// level-triggered reconciler, the §7 scheduler) plus the orch18 scheduler.Adapter and
// the concrete Redriver into ONE runnable control plane, so main.go is a thin
// bootstrap that constructs the backends and calls NewControlPlane (doc 15 §2/§3/§4.1
// "wired into main.go"). It is a CONSTRUCTIBLE component itself — built from injected
// backends (the store, the per-host hypervisor.v1 driver registry, the Identity mint /
// digest / revoke seams, the boundary CA-inject + boot seams, the enrollment / role /
// principal resolvers) — so the whole wiring is unit-tested against synthetic fixtures
// + the generated fakes with NO live VM/host-agent/podman (D50), exactly how
// session-create / reconciler / scheduler were tested.
//
// THE THREE LEGS CONVERGING HERE (the task's wiring surface):
//
//   (a) CreateSession RPC handler — sessionService (sessionservice.go) drives the
//       §4.1 ten-step coordinator (sessions.SessionCreator) on the frozen
//       orchestrator.v1 CreateSession server method. The coordinator is built with the
//       PRODUCTION host-side seams (seams.go / identityseams.go) and the STORE-SEAMS
//       single-store coherence accessor (the orch15/16 StoreSeams) so the gate linker,
//       the launching_user resolver, and the role-pin writer provably share one store.
//
//   (b) reconciler driving loop — reconcileLoop (reconcileloop.go) calls Observe per
//       inbound hostagent.v1.Heartbeat and Resync on cadence, holding a per-host Driver
//       client (resolved through the registry) and the ConcreteRedriver wired with
//       SpineRunnerFunc(RedriveSpine) + SpineContinuationFunc(host-side re-create),
//       passed as reconciler.New's redriver argument. An Alarmer sink relays to LOG-1.
//
//   (c) scheduler placement — the orch18 scheduler.Adapter is injected as the
//       SessionCreator's Placer (doc 15 §4.1 step 3), built over the StoreCandidateSource
//       (HeartbeatFeed + TenancyScopeSource + *store Lister) and a policy_log-head
//       PolicySeqSource (the additive store.PolicyHead query).
//
// THE orch18 CARRYING COST IS PAID OFF HERE. Before this capstone the
// scheduler.Adapter was never injected as the Placer and reconciler.New was called
// with no redriver, leaving the exported SpineRunnerFunc / SpineContinuationFunc
// closures unreferenced. NewControlPlane references all three — the adapter is the
// coordinator's Placer, the closures install the concrete Redriver — so the unreferenced
// surfaces become live (the build's no-dead-export posture holds).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/auth"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/parkstore"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/scheduler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// heartbeatFeed aliases scheduler.HeartbeatFeed so the HeartbeatStore's compile-time
// proof (heartbeatstore.go) names the scheduler seam without that file importing the
// scheduler package directly into its var block.
type heartbeatFeed = scheduler.HeartbeatFeed

// ControlPlaneStore is the single backing store the whole control plane is wired from
// (doc 15 §4.1 single-store coherence): it is the union of every store method the
// coordinator, the scheduler candidate assembler, the policy head, the reconciler, and
// the launch gate need. Both *store.Memory and *store.Postgres satisfy it (these are
// EXISTING exported methods — the store package stays frozen). The methods are listed
// explicitly (not by embedding cross-package interfaces, some of which are unexported)
// so the one value provably satisfies every consuming seam. Handing ONE
// ControlPlaneStore to NewControlPlane is what makes the gate linker, the
// launching_user resolver, and the pin writer provably coherent (the StoreSeams
// accessor cuts them from this one value).
type ControlPlaneStore interface {
	// §4.1 spine store-backed seams (coherence: gate linker + launching_user resolver
	// + pin writer) — sessions.SessionStore.
	SetSessionLaunchingPrincipal(ctx context.Context, sessionUUID, principalID string) error
	ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error)
	UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error)

	// §4.1 record-mutation seam — sessions.SessionRecordStore (+ reconciler.RecordStore
	// shares ListSessions/UpdateSession).
	CreateSession(ctx context.Context, s store.Session) (store.Session, error)
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
	AppendIndexEpoch(ctx context.Context, sessionUUID string, e store.IndexEpoch) (store.Session, error)
	ListSessions(ctx context.Context, f store.SessionFilter) ([]store.Session, error)

	// policy-head PolicySeqSource (D72) — store.PolicyHeadSource.
	ListPolicy(ctx context.Context, fromSeq int64, limit int) ([]store.PolicyLogRow, error)

	// two-key step-1 second key (D56) — the env-config reader.
	GetEnvConfig(ctx context.Context, ref string) (store.EnvConfig, error)

	// launch-gate principal upsert (doc 16 §3.2/§11.2) — the auth.Resolver's store.
	GetPrincipalByIdP(ctx context.Context, idpSubject, org string) (store.Principal, error)
	CreatePrincipal(ctx context.Context, p store.Principal) (store.Principal, error)
	SetPrincipalRoles(ctx context.Context, id string, roles []store.PrincipalRole) (store.Principal, error)
}

// DigestPublisher is the §6.1 mint-before-attach DIGEST-PUBLISH seam (D73/D84, doc 16
// §6.1): the create coordinator drives it BETWEEN the step-5 cred-mint and mark-routable
// and gates routability on the host ack. It mirrors the sessions package's narrow
// digest-publish interface (sessions.DigestFeedPublisher satisfies it) so NewControlPlane
// can thread a control-plane-supplied publisher into the coordinator's CreateSeams without
// the control plane importing the unexported seam by name (D80: the control plane depends
// only on this Go interface, never on identity/*). It is FLAG-GATED by
// DS_ORCH_DIGEST_PUBLISH_WIRE at the spine call-site: OFF (the wave default) the coordinator
// SKIPS the step and a wired publisher is UNUSED (byte-identical, D50); ARMED, a nil
// publisher fails the create CLOSED (ErrDigestPublisherUnwired) and a publish/transport
// error or an uncommitted ack fails it closed too — a session is never marked routable when
// its digests did not land.
type DigestPublisher interface {
	PublishSessionDigests(ctx context.Context, sessionUUID string) (sessions.DigestPublishOutcome, error)
}

// Deps is the bundle of injected backends NewControlPlane assembles into a runnable
// control plane. main.go fills it from real backends (a dialed store, a dialed per-host
// driver registry, the Identity/boundary service clients); tests fill it from the
// generated fakes + synthetic fixtures (D50). Every REQUIRED field nil is a
// construction-time misconfiguration (NewControlPlane refuses fail-closed) so a
// half-wired control plane can never half-run a create or a reconcile.
type Deps struct {
	// Store is the single backing store (coherence root). Required.
	Store ControlPlaneStore

	// Drivers resolves a host_id to its per-host hypervisor.v1 driver client (the
	// host agent's driver face). Required — the create coordinator and the reconciler
	// both drive host verbs through it. main.go supplies a dialing registry; tests a
	// fake-returning one.
	Drivers DriverRegistry

	// HostAgent is the IN-PROCESS host-agent §4.2 destroy orchestrator (doc 15 §4.2),
	// supplied ONLY in the orchestrator-lite single-binary posture (D80: the host agent
	// runs in the SAME process as the control plane). When set, NewControlPlane drives the
	// create coordinator's compensating-rollback destroy AND the public DestroySession
	// teardown through the in-process adapter (inProcessHostDestroyer over this seam + the
	// single store) instead of the remote hypervisor.v1 Destroy verb — no gRPC dial, no
	// loopback; the frozen §4.2 ordering is identical, only the transport collapses. Nil =
	// the FLEET posture: the create rollback + DestroySession drive the REMOTE host's driver
	// over the wire (hostDestroyer{reg} over the registry). Both satisfy the same
	// sessions.HostDestroyer seam, so the coordinator + reconciler are unchanged. A
	// non-live orchestrator-lite / test wires a synthetic in-process destroyer behind this
	// seam (D50 — no live KVM/host-agent/cgo).
	HostAgent HostAgentDestroyer

	// Heartbeats is the live latest-per-host heartbeat feed (the scheduler's candidate
	// input + the reconciler's resync input). Optional: nil installs a fresh in-process
	// HeartbeatStore (the single-binary posture) that the reconcile loop feeds.
	Heartbeats *HeartbeatStore

	// --- §4.1 step seams not on the hypervisor driver (Identity / boundary owned) ---

	// Mint backs §4.1 step 5 (identity + interception-CA mint, D82). Required.
	Mint MintClient
	// Digest backs §4.1 step 6 (digest write + ack, D73). Required.
	Digest DigestClient
	// Inject backs §4.1 step 7 (fail-closed CA injection, D17/D29). Required.
	Inject InjectClient
	// Boot backs §4.1 step 8 (boot + entrypoint, D38). Required.
	Boot BootClient
	// Revoke backs the §4.1 step-5/6 rollback (identity/CA revocation, D22/D82). Required.
	Revoke RevokeClient
	// DigestPublisher installs the OPTIONAL §6.1 mint-before-attach digest-publish adapter
	// (D73/D84, doc 16 §6.1) into the create coordinator's CreateSeams. Optional: nil leaves
	// the seam UNWIRED — with DS_ORCH_DIGEST_PUBLISH_WIRE OFF (the wave default) the spine
	// skips the step and the create path is byte-for-byte the pre-wire behavior (D50); with
	// the flag ARMED a nil publisher fails every create CLOSED (ErrDigestPublisherUnwired, the
	// safe posture for an armed-but-unwired deployment). When set, NewControlPlane threads it
	// into CreateSeams.DigestPublisher so an armed create drives the mint-before-attach push
	// through it and gates routability on the host ack. main.go supplies the production
	// per-session sessions.DigestFeedPublisher (over the frozen identityv1.DigestFeedService,
	// proto/gen/go only — D80); tests supply a synthetic publisher (D50 — no live boundary).
	DigestPublisher DigestPublisher

	// --- create-time resolvers (steps 1–2) ---

	// Enrollment backs §4.1 step 1's first key (D56 control-plane enrollment). Required.
	Enrollment sessions.EnrollmentResolver
	// Roles backs §4.1 steps 1–2 role resolve+pin (doc 18 §6). Required.
	Roles sessions.RoleResolver
	// RoleCatalog is the roles.v1 RoleCatalogService READ-path server (ListRoles /
	// GetRole, doc 18 §6 seam 2; D89–D96), served wherever CreateSession is — incl.
	// orchestrator-lite (D80). Optional: nil leaves the catalog API UNREGISTERED (the
	// create path still resolves+pins through Roles; only the read API is absent), so
	// a deployment that does not serve the catalog read path is a clean degrade rather
	// than a refusal. Built via NewRoleCatalogServiceFromDir over the checked-in roles/.
	RoleCatalog *RoleCatalogService
	// PrincipalIDGen mints IDs for newly-created principals at the launch gate (the
	// auth.Resolver's ID generator). Optional: nil uses a time-based default.
	PrincipalIDGen func() string
	// DefaultOrg is the v0 single-org deployment's org the CreateSession handler keys
	// the launch-gate principal upsert on (the frozen orchestrator.v1 request carries
	// the launching_user subject, not its org — doc 16 §3.2). Empty leaves it unset (a
	// multi-org deployment threads the org through the IdP boundary the M2 band adds).
	DefaultOrg string

	// --- D18 fan-out sub-token leg (subtoken.go, doc 23 §5; D126) ---

	// SubTokenAttenuator is the narrow tokenAttenuator seam (subtoken.go) the D18 fan-out
	// derives ONE narrowed agent sub-token per launched VM through (the frozen
	// dreamserpent.auth.v1 TokenAttenuationService.DeriveAgentToken). Optional: nil leaves
	// the sub-token leg UNWIRED — CreateSession then fans out no sub-token (a deployment
	// without the auth SDK reachable is a clean degrade, never a half-injected VM; additive).
	// main.go supplies the gRPC-shim attenuator (NewTokenAttenuatorClient, env-gated by
	// DS_AUTHSDK_ENDPOINT); tests supply the generated authv1fake (D50 — no live dial). When
	// set, NewControlPlane builds a fileSubTokenSink at DefaultAgentSubTokenMountDir + the
	// fan-out injector over this seam and calls Sessions.SetSubTokenServing so the leg is LIVE.
	SubTokenAttenuator tokenAttenuator
	// SubTokenAuthority resolves the launching principal's PARENT authority for the fan-out
	// derive from the create request (doc 23 §5): the D125 parent user auth token to
	// attenuate from, the requested-scope SUBSET of its ds_scopes (§5 rule 1 — narrow only),
	// and an optional sub-token lifetime override (§5 rule 3 — exp ≤ parent exp; zero = the
	// auth SDK defaults to the parent's remaining lifetime). The frozen CreateSessionRequest
	// carries the launching_user subject, NOT the parent token/scopes (those ride the IdP
	// claim the M2 multi-org band threads structurally, doc 16 §3.2), so the authority is
	// sourced through this seam rather than echoed on the wire. Optional: nil (the v0 posture
	// before the IdP boundary lands) resolves no parent authority, so the injector skips the
	// derive — the create is unaffected. Installed alongside SubTokenAttenuator via
	// SetSubTokenServing.
	SubTokenAuthority subTokenAuthorityFunc

	// --- scheduler ---

	// SchedulerConfig tunes the §7 filter chain (rig-tuned thresholds). Zero value
	// takes scheduler.DefaultConfig.
	SchedulerConfig scheduler.Config
	// Tenancy supplies the D19 tenancy host-pool scope per placement. Optional: nil
	// installs an unrestricted scope (the open/shared-pool posture — every reporting
	// host is a candidate, no cross-tenant guard).
	Tenancy scheduler.TenancyScopeSource

	// --- reconciler ---

	// ReconcilerConfig tunes the cadence/missed-beat thresholds (rig-tuned). Zero value
	// takes the documented strawmans.
	ReconcilerConfig reconciler.Config
	// Alarm is the §3 operator-alarm / LOG-1 sink. Optional: nil drops alarms (tests
	// that assert convergence, not alarming).
	Alarm reconciler.Alarmer
	// ResyncInterval is the reconcile loop's periodic full-resync cadence. Zero takes
	// DefaultResyncInterval.
	ResyncInterval time.Duration

	// --- suspend / park / resume + instant-start (the D46/D110/M2 suspend wiring) ---

	// EscalationConfig carries the two D46 tier boundaries the EscalationClock partitions
	// a pause against (escalationclock.go). The zero value takes the strawman defaults
	// (5 min / 15 min) via sessions.NewEscalationConfig; a rig may re-tune the boundaries
	// without touching the frozen three-tier shape (D46).
	EscalationConfig sessions.EscalationConfig
	// Suspender drives the FROZEN hypervisor.v1 Suspend verb (the WORKING→SUSPENDED edge)
	// on a session's placed host. Optional: nil installs a registry-backed adapter
	// (registrySuspender) over the per-host DriverClient.Suspend — the same path the
	// reconciler's quarantine Suspend uses — so the default production wiring needs no
	// extra backend. main.go may supply a real one (or, gate-off, an in-process fake, D50).
	Suspender sessions.Suspender
	// Resumer drives the in-place SUSPENDED→RESUMING→WORKING resume on the resident host.
	// Optional: the narrow production DriverClient seam does not carry the host Resume
	// verb (it is widened only behind DS_ORCH_LIVE in main.go), so absent a wired Resumer
	// the ParkResumeDriver leaves the in-place-resume seam unwired and validates it lazily
	// at the operation that needs it (a test-narrowed driver is constructible). Gate-off
	// CI wires an in-process fake (D50).
	Resumer sessions.Resumer
	// Snapshotter drives the SNAPSHOTTING step of the >15-min D46 escalation. Optional,
	// for the same reason as Resumer (the host Snapshot verb is not on the narrow
	// production DriverClient seam) — wired behind DS_ORCH_LIVE in main.go / by an
	// in-process fake gate-off (D50).
	Snapshotter sessions.Snapshotter
	// Approvals backs the policy_breach resume arm's landed-approval read (resumeauthority.go;
	// the §8.2 resume-on-answer gate). Optional: nil is safe for the user/scheduler arms
	// (their authority IS the gate); a policy_breach resume with no Approvals reader is
	// denied fail-closed. main.go wires the real policy_log read behind DS_ORCH_LIVE; a
	// synthetic fake wires it gate-off (D50).
	Approvals sessions.ApprovalPresence
	// ParkRecorder is the DURABLE backing for the D46 session<->question join behind the
	// askhold.ParkRecorder seam (parkstore.Store): the park machine drives RecordParked /
	// ClearParked through it as a rung-2 ask parks / resumes, and the boot re-adoption sweep
	// re-reads its List() so a parked ask outlives a real control-plane restart (doc 16 §8.2
	// / doc 15 §3 / D46). Optional: nil installs a fresh in-process parkstore.NewMemory()
	// (the stdlib-only reference posture, D50) — the park machine is still durable WITHIN the
	// process and the boot sweep re-adopts from it; a deployment fronts the database/sql twin
	// (parkstore.SQL) behind this SAME seam for genuine cross-restart durability. It must
	// satisfy parkReadAdopter (the List() read the sweep needs) as well as the recorder, which
	// every parkstore.Store does.
	ParkRecorder ParkRecorderStore
	// SuspendEmitter is the host-ward EMIT sink the SuspendCoordinator delivers the D110
	// SuspendCoord coordination signals onto (suspendcoord.go) — the boundary-owned
	// host-local channel ds-tlsproxy reads (doc 15 §2.1). Optional: nil installs an
	// in-process drop sink (the gate-off D50 posture — no boundary channel); main.go wires
	// the real host-local channel behind DS_ORCH_LIVE.
	SuspendEmitter SuspendCoordEmitter
	// GoldenImage is the §4.1 step-7 image-resolution seam the M2 FastStarter resolves the
	// pre-baked golden image through (faststart.go). Optional: nil takes
	// sessions.PrebakedGoldenResolver (the content-address IS the golden artifact — the v0
	// resolver). A future wiring fronts the Image & cache builder behind the SAME seam.
	GoldenImage sessions.GoldenImageResolver

	// AttachSocketDir is the host-local directory the gap-3 attach serving leg serves the
	// per-session attach UDS under (attachendpoint.go) — the DIRECT EndpointCandidate the
	// issued attach handle advertises is a per-session socket under this dir (doc 15 §5.4).
	// It is a host bring-up FACT (doc 13 §4) the daemon composition root (main.go) supplies
	// per host. Empty takes defaultAttachSocketDir, so a deployment that does not override it
	// still serves a well-formed host-local path; the resolver gates the candidate on the
	// session being placed + servable, so an empty/default dir never fabricates an endpoint
	// for an unplaced session.
	AttachSocketDir string

	// AttachModeReader is the OPTIONAL per-session resolved-mode source the attach endpoint
	// resolver reads to TAG the issued endpoint's transport (RAW_TERMINAL for a terminal
	// session, DIRECT otherwise) — the SAME <OverlayDir>/.ds-session-mode marker the
	// co-located host-agent's EntrypointProducer wrote (doc 04 §2.7). In the single-box MVP
	// serpent-tui's Attach is answered by THIS control-plane resolver (not the host-agent
	// minter), so without this source a terminal session would carry a DIRECT candidate and
	// serpent-tui would fall back to the structured loop (the U-CPWIRE live-found bug). It is
	// FAIL-SAFE: nil (the orchestrator is not co-located with the host overlay dir —
	// DS_ORCH_OVERLAY_DIR unset) leaves every session tagged DIRECT (no fabricated terminal
	// tag without a host marker to read). *libvirt.fileSessionModeStore (via
	// libvirt.SessionModeStore) satisfies it; main.go builds it from DS_ORCH_OVERLAY_DIR.
	AttachModeReader sessionModeReader

	// --- W2 writer-seat arbitration (D61/D137/D138, the browser writer seat) ---

	// WriterIdentity validates the D22/D55 human-identity assertion a RequestWriterSeat
	// carries and resolves it to the driver_identity that becomes the seat attribution
	// (doc 15 §5.4 / D8 / D55). Optional: nil leaves the WriterRelayService refusing
	// Unauthenticated (no seat without a wired human-identity check — fail-closed). main.go
	// adapts the real D55/SSO identity face; tests supply a fake.
	WriterIdentity IdentityAssertionValidator
	// WriterAttachAuth validates the D39 attach-auth token a RequestWriterSeat carries (the
	// v1 AttachHandle.AuthMaterial.token proving a valid, short-lived, session-scoped attach
	// to THIS session — the same token the attach minter issued). Optional: nil leaves the
	// WriterRelayService refusing PermissionDenied (the seat requires a valid attach —
	// fail-closed). main.go adapts the attach-token store; tests supply a fake.
	WriterAttachAuth AttachAuthValidator
	// WriterDriveSink is the W3 host-agent relay seam an ADMITTED DriveInput is forwarded
	// to Claude Code's stdin through (the RELAY endpoint transport — the symmetric twin of
	// the host-ward read-leg relay attachrelay.go feeds the Fanout from). Optional: nil
	// leaves DriveSession refusing Unavailable (no live relay configured — fail-closed, so
	// an admitted frame is never silently dropped). main.go adapts the live host-agent
	// bridge (Bridge.DriveInput) behind DS_ORCH_LIVE; tests supply a fake. The orchestrator
	// is the single choke point — the arbiter admits the frame for the live seat-holder and
	// only then is it carried here, so the relay originates no input of its own (D137
	// confused-deputy mitigation).
	WriterDriveSink DriveSink

	// ContentSource is the PRODUCTION read-stream content seam (contentrelay.go, D61/D79):
	// the host-agent per-session source of CC's projected attach.v1 CONTENT events (chat,
	// tool-use, subagent tree, ask, plan-delta, accounting) the content relay pumps into the
	// WatchSession Fanout so N READERS see CC output, not only the one writer. It is the
	// symmetric READ twin of WriterDriveSink (the write leg carries an admitted frame
	// host-ward; this reads CC content host-ward). Optional: nil DISABLES the content relay
	// (a clean degrade — the fan-out carries the control edges only, exactly the pre-relay
	// behavior). main.go adapts the live host-agent bridge's Events() ring onto it behind
	// DS_ORCH_LIVE (the live wiring is filed as a follow-up like WriterDriveSink's); tests
	// supply a fake. Readers stay provably read-only (D136): the relay only Publishes, and
	// it relays ONLY content event types (a source cannot forge a control edge).
	ContentSource ContentSource

	// --- tuning ---

	// StalenessBudget is the D72 step-9 routable re-check window (≤0 = exact match).
	StalenessBudget int64
	// Clock is the timestamp seam (nil → time.Now), overridable for deterministic tests.
	Clock func() time.Time
	// Logger nil → slog.Default.
	Logger *slog.Logger
}

// ControlPlane is the assembled, runnable control plane: the CreateSession RPC service
// (Sessions), the level-triggered reconcile loop (Reconcile), and the live heartbeat
// feed (Heartbeats) the gRPC heartbeat ingest records into. main.go registers
// Sessions on the gRPC server, starts Reconcile.Run in a goroutine, and routes inbound
// heartbeats to Reconcile.Observe (which records into Heartbeats and drives convergence).
type ControlPlane struct {
	// Sessions is the orchestrator.v1 SessionService server (the CreateSession handler).
	Sessions *SessionService
	// RoleCatalog is the roles.v1 RoleCatalogService READ-path server (ListRoles /
	// GetRole, doc 18 §6). Registered alongside Sessions by Register so the catalog
	// read path serves wherever CreateSession is (incl. orchestrator-lite, D80). Nil
	// when no catalog was wired (Deps.RoleCatalog absent) — the read API is then
	// simply not registered (a clean degrade, the create path is unaffected).
	RoleCatalog *RoleCatalogService
	// Reconcile is the level-triggered reconcile loop (Observe per heartbeat + Resync
	// on cadence). Its Run drives the periodic resync goroutine; Observe is called per
	// inbound heartbeat.
	Reconcile *reconcileLoop
	// Heartbeats is the live latest-per-host feed (the scheduler's candidate input +
	// the reconciler's resync input). The gRPC heartbeat ingest records into it (via
	// Reconcile.Observe); placement reads from it.
	Heartbeats *HeartbeatStore
	// Creator is the §4.1 ten-step coordinator (the constructible component the
	// CreateSession handler drives). Exposed so a re-drive continuation can re-create
	// host-side through the SAME coordinator (the SpineContinuationFunc closure).
	Creator *sessions.SessionCreator
	// Placer is the orch18 scheduler.Adapter wired as the coordinator's §4.1 step-3 Placer
	// AND, under DS_ORCH_LIVE, the §4.1 step-9 live-freshness probe (its optional Freshness
	// seam is assigned the production HostFreshness over the shared heartbeat feed). Exposed
	// so the step-9 re-check (Adapter.CurrentFreshness) is observable: gate-on it returns a
	// live applied_seq (the window-close fires), gate-off it stays nil → ErrFreshnessUnknown
	// (the coordinator degrades to the recorded re-check, D72).
	Placer *scheduler.Adapter

	// Fanout is the D18 WatchSession terminator (attach.Fanout, doc 15 §5.3): the
	// per-session, seq-stamped, ring-backed subscriber set the WatchSession handler Subscribes
	// to and the host-agent relay (attachrelay.go) Publishes host-ward state edges into. It is
	// the in-process leg behind orchestrator.v1 SessionService.WatchSession. Exposed so the
	// serve bootstrap (Register) can wrap the heartbeat ingest's observer in the relay that
	// feeds it, and so a test can drive the fan-out directly. Nil only on a control plane
	// constructed without the attach legs (never via NewControlPlane, which always wires them).
	Fanout *attach.Fanout

	// WriterRelay is the W2 attach.v1.WriterRelayService server (the D137 browser
	// writer-seat WRITE leg, sessions/10 §2.1; D61/D138): RequestWriterSeat /
	// YieldWriterSeat arbitrate the one seat at the single terminator (over the
	// SeatArbiter, emitting WRITER_SEAT_CHANGED on this same Fanout), DriveSession is
	// W3 (Unimplemented). Exposed so the serve bootstrap (Register) registers it
	// alongside SessionService. Always wired by NewControlPlane (over the single store +
	// this Fanout); the auth seams (Deps.WriterIdentity/WriterAttachAuth) are optional and
	// fail-closed when absent.
	WriterRelay *WriterRelayService

	// ContentRelay is the PRODUCTION read-stream content relay (contentrelay.go, D61/D79):
	// it pumps CC's projected attach.v1 CONTENT from the host-agent per-session source
	// (Deps.ContentSource) into THIS SAME Fanout, so N READERS see CC output, not only the
	// writer seat. Nil when no ContentSource was wired (the fan-out then carries the control
	// edges only — a clean degrade). Exposed so the serve bootstrap arms its pump lifetime
	// (Start) and wires its ensure/stop lifecycle onto the state-edge relay (Register), and
	// so a test can drive it directly. The state edges (attachrelay.go), seat handoff
	// (SeatArbiter), and write-activity (DriveSession) keep their own producers; this leg
	// adds ONLY CC content — readers stay read-only (D136).
	ContentRelay *contentRelay

	// reCreate is the production §3 rule-b host-side re-create continuation the redriver
	// drives (the SpineContinuationFunc target). It carries withDigestReAck(d.Digest) so a
	// re-driven VM re-acks its §4.1 step-6 digest before being declared converged (D73); held
	// here so the wiring test can prove the production construction installed the re-ack seam
	// (a re-drive re-acks the digest) without reaching through the reconciler's rule-b path.
	reCreate hostReCreate

	// --- the D46/D110/M2 suspend + instant-start components (the fenced components this
	// capstone gives production callers) ---

	// ParkResume is the §3/§4.3 suspend/park/resume coordinator (sessions.ParkResumeDriver):
	// it drives WORKING→SUSPENDED, the gated SUSPENDED→RESUMING→WORKING resume, the >15-min
	// SNAPSHOTTING→PARKED escalation, and the PARKED→CREATING@host' re-place. The reconcile
	// loop's escalation leg (reconcileloop.go) and the boundary suspend-signal terminator
	// drive it; exposed so the wiring test proves it was constructed.
	ParkResume *sessions.ParkResumeDriver
	// AskParkRouter is the policylog ask-routing PARK enrollment seam (leg 3, doc 15 §4.3 /
	// §6.2 step 4 / doc 16 §8.2; D46 rung-2 untimed park) the LIVE ask-routing call-site
	// (policylog.Service.RouteAsk) is handed so a GENUINE rung-2 ask is entered into the
	// DURABLE park end to end: RouteAsk decides off ask.Rung2 that the ask parks and calls
	// this seam's Park(sessionUUID, ask, now), which drives the control-plane *parkMachine's
	// RecordParked-backed enrollment (a later human answer resumes it via the machine's
	// ClearParked-backed Resume — NEVER a timeout into allow or kill, the load-bearing D46/D77
	// invariant). It is the *parkMachine itself (which satisfies policylog's askParkRouter
	// shape exactly — Park(sessionUUID, ask, now)). It is set ONLY under DS_ORCH_LIVE: gate
	// OFF leaves it nil and the live ask-routing site enters no durable park (the dispatch
	// decision still stands — the same nil-tolerant posture policylog.RouteAsk takes for a nil
	// park router), so a non-live run is unchanged. Exposed so the live RouteAsk wiring (and
	// the wiring test) reach the enrolled router off the assembled control plane.
	AskParkRouter AskParkRouter

	// ParkMachine is the D46 ask-a-human PARK MACHINE (parkadoption.go): the in-memory set of
	// outstanding genuine rung-2 asks (askhold.Parked keyed by session UUID), driving the
	// injected durable parkstore backing (Deps.ParkRecorder) as a rung-2 ask parks / resumes
	// on a human answer (doc 16 §8.2 / D46). On startup it is RE-ADOPTED from the durable
	// backing's List() so a park parked before a restart is still in the running machine — a
	// later human answer resolves it post-restart (doc 15 §3 RecoverSessions shape). Exposed
	// so the boundary ask-resume terminator drives a human answer into it, and so the wiring
	// test proves the boot re-adoption populated it. Always non-nil (NewControlPlane wires it
	// from the injected-or-default parkstore backing).
	ParkMachine *parkMachine
	// Escalation is the D46 escalation clock (sessions.EscalationClock): the pure, clock-
	// injected classifier the reconcile loop's escalation ticker leg consults per SUSPENDED
	// session to decide the transparent/best-effort/escalate tier (escalationclock.go).
	Escalation *sessions.EscalationClock
	// SuspendTerminator terminates the boundary→orchestrator suspend signal
	// (sessions.SuspendSignalTerminator): it validates+maps+dedups the frozen
	// boundary.v1.SuspendSignal into a hypervisor.v1.SuspendRequest the ParkResume driver
	// drives (suspendsignal.go). The DS_ORCH_LIVE real-feed path (main.go) hands signals to it.
	SuspendTerminator *sessions.SuspendSignalTerminator
	// SuspendCoord is the D110 orchestrator→ds-tlsproxy pause/resume coordination emitter
	// (suspendcoord.go): on the HOLD tiers it emits HOLD_BEGIN over the frozen
	// hostagent.v1.SuspendCoord slot; on resume it emits RESUME_RESYNCED after the guest
	// clock resync. It emits over the injected SuspendEmitter sink.
	SuspendCoord *SuspendCoordinator
	// FastStarter is the M2 golden-image instant-start fast path (sessions.FastStarter)
	// over the SAME §4.1 ten-step coordinator the CreateSession handler drives — exposed so
	// the §8 create→attach timing trend (Recorder().ServerSpanTrend()) is readable as the
	// measure-not-gate sink (D81/D32; no budget armed). The CreateSession handler holds the
	// same instance (sessionservice.go) so a golden create routes through the fast path.
	FastStarter *sessions.FastStarter
	// MintExpiry is the §4.1 step-5 minted-credential EXPIRY teardown/re-mint scheduler
	// (D22/D82, doc 16 §5.4) wired behind the create coordinator's CreateSeams.OnMintExpiry.
	// It is the REAL TTL-driven sink: a session that reaches READY with a non-zero minted
	// horizon arms a timer keyed on session UUID; on fire it re-reads the PERSISTED §5.6
	// MintExpiry horizon and re-mints (an expired credential re-mints on resume), dropping
	// idempotently for a destroyed session. Exposed so main.go can Stop it on shutdown and
	// the wiring test can prove the production construction installed a real (non-nop) sink.
	MintExpiry *mintExpiryScheduler

	// DestroyReDriver is the §4.2 destroy-path convergence backstop (reconciler.DestroyRedriver):
	// it sweeps records STUCK in DESTROYING and re-drives each forward to DESTROYED via the SAME
	// §4.2 teardown the create rollback + the public DestroySession handler drive (the in-process
	// adapter in orchestrator-lite, the remote driver in the fleet). DestroySession flips
	// desired→DESTROYING, drives the teardown, finalizes→DESTROYED — and on a TRANSIENT host fault
	// it LEAVES the record DESTROYING with the promise "reconciler will re-drive"; this re-driver
	// is that backstop (the §3 conflict rules deliberately exclude DESTROYING from the rule-b
	// missing-VM arm, so without it a transient teardown fault strands the session in DESTROYING
	// forever). The wiring runs it on a cadence (RunDestroyReDrive) alongside the reconcile loop;
	// it is exposed so main.go can start/stop the sweep and the wiring test can prove it was
	// constructed over the SAME destroyer + store the rest of the §4.2 path uses. Always non-nil
	// (NewControlPlane wires it from the required store + the §4.2 destroy seam).
	DestroyReDriver *reconciler.DestroyRedriver

	// SessionIdleReaper is the writer-less-RUNNING idle-TTL reaper (sessionidlereaper.go): it
	// destroys a RUNNING session ({READY,ATTACHED,WORKING}) that has had NO writer for longer
	// than DS_ORCH_SESSION_IDLE_TTL via the SAME §4.2 destroyer DestroySession + the create
	// rollback drive — closing the leak where a detached writer's per-session VM stays resident
	// forever (the reconcile escalation leg sweeps only SUSPENDED; the destroy re-driver only
	// re-drives DESTROYING). It is the env-gated opt-out: NIL when the TTL is ≤ 0 (the operator
	// set DS_ORCH_SESSION_IDLE_TTL=0, the reaper disabled). The wiring runs it on a cadence
	// (RunSessionIdleReap) alongside the reconcile loop + the destroy re-drive sweep; exposed so
	// main.go can start/stop the sweep and the wiring test can prove it was (or, when disabled,
	// was NOT) constructed.
	SessionIdleReaper *sessionIdleReaper

	// sessionIdleTTL is the resolved idle reap horizon the wiring parsed from
	// DS_ORCH_SESSION_IDLE_TTL (DefaultSessionIdleTTL when unset, 0 when explicitly disabled).
	// Held so RunSessionIdleReap can derive its default cadence from the TTL and the wiring test
	// can assert the env was honored without re-reading the environment.
	sessionIdleTTL time.Duration

	// mintBackstop is the constructed *reconciler.Reconciler the CREDENTIAL-TTL BACKSTOP cadence
	// sweep (RunMintExpiry, leg 1) drives ReconcileMintExpiry on. It is the SAME reconciler the
	// reconcile loop's Observe/Resync goroutine owns, but the backstop pass touches NO mutable
	// reconciler state (it never reads/writes lastBeat — credttl.go), so RunMintExpiry runs it
	// SAFELY on its own goroutine alongside the loop. Held here so RunMintExpiry reaches the
	// reconciler off the assembled control plane (the loop holds it privately) and the wiring
	// test can drive the backstop pass deterministically. Always non-nil (NewControlPlane
	// always builds the reconciler); whether the pass DRIVES anything depends on
	// WithMintReconverger being installed (leg 1, gated on DS_ORCH_LIVE) — gate-off the pass is
	// a documented no-op.
	mintBackstop *reconciler.Reconciler

	logger *slog.Logger
}

// DefaultDestroyReDriveInterval is the cadence the §4.2 destroy-path re-drive sweep runs at
// (RunDestroyReDrive) when the caller passes a non-positive interval — a strawman (doc 15 §10
// cadence values are free): often enough that a session left DESTROYING by a transient teardown
// fault converges to DESTROYED promptly, infrequent enough that the list-DESTROYING read is
// cheap. It mirrors the reconcile loop's DefaultResyncInterval so the two convergence cadences
// align.
const DefaultDestroyReDriveInterval = 30 * time.Second

// DefaultSessionIdleReapInterval is the cadence the writer-less-RUNNING idle reaper sweeps at
// (RunSessionIdleReap) when the caller passes a non-positive interval AND no TTL-derived cadence
// applies — a strawman (doc 15 §10 cadence values are free): frequent enough that a session that
// crosses the idle TTL is reaped promptly after, infrequent enough that the list read is cheap.
// In practice RunSessionIdleReap derives its cadence from the reaper's TTL (re-checking at least
// once per idle window); this names the floor a degenerate sub-strawman TTL would fall back to.
const DefaultSessionIdleReapInterval = 30 * time.Second

// DefaultResyncInterval is the reconcile loop's periodic full-resync cadence strawman
// (doc 15 §3 periodic full resync; a rig-tuned value, free per §10).
const DefaultResyncInterval = 30 * time.Second

// NewControlPlane assembles the runnable control plane from the injected backends. It
// refuses a wiring missing a REQUIRED backend (fail-closed at construction, never at
// the first create/reconcile) so a half-wired control plane can never half-run. The
// assembly order is the doc 15 §4.1 single-store-coherence contract:
//
//  1. Cut the §4.1 spine's three store-backed seams from ONE store value via the
//     StrictStoreSeams accessor (gate linker + launching_user resolver + pin writer all
//     name one store — coherent by construction; the runtime assertion re-proves it).
//  2. Build the launch gate over that one store's gate linker (the launch-gate-before-
//     mint ordering writes the session→principal link the step-5 resolver reads).
//  3. Build the scheduler.Adapter as the coordinator's Placer (doc 15 §4.1 step 3) over
//     the StoreCandidateSource (live heartbeat feed + tenancy scope + the store lister)
//     and the policy-head PolicySeqSource, and under DS_ORCH_LIVE assign its optional
//     §4.1 step-9 Freshness probe the production HostFreshness over the shared feed (D72).
//  4. Build the §4.1 ten-step coordinator (SessionCreator) with the PRODUCTION host-side
//     seams (the hypervisor.v1 driver registry + the Identity/boundary seams).
//  5. Build the concrete Redriver (the §3 rule-b/rule-c convergence closer) with the
//     SpineRunnerFunc(RedriveSpine) + SpineContinuationFunc(host-side re-create, the
//     re-create carrying withDigestReAck(d.Digest) so a re-driven VM re-acks its step-6
//     digest before being declared converged, D73) closures installed, and pass it as
//     reconciler.New's redriver argument.
//  6. Build the reconcile loop (Observe + Resync) over the reconciler + the heartbeat feed.
func NewControlPlane(d Deps) (*ControlPlane, error) {
	logger := d.Logger
	if logger == nil {
		logger = slog.Default()
	}
	clock := d.Clock
	if clock == nil {
		clock = time.Now
	}

	missing := make([]string, 0, 12)
	if d.Store == nil {
		missing = append(missing, "Store")
	}
	if d.Drivers == nil {
		missing = append(missing, "Drivers")
	}
	if d.Mint == nil {
		missing = append(missing, "Mint")
	}
	if d.Digest == nil {
		missing = append(missing, "Digest")
	}
	if d.Inject == nil {
		missing = append(missing, "Inject")
	}
	if d.Boot == nil {
		missing = append(missing, "Boot")
	}
	if d.Revoke == nil {
		missing = append(missing, "Revoke")
	}
	if d.Enrollment == nil {
		missing = append(missing, "Enrollment")
	}
	if d.Roles == nil {
		missing = append(missing, "Roles")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("controlplane: NewControlPlane: missing required deps: %v", missing)
	}

	heartbeats := d.Heartbeats
	if heartbeats == nil {
		heartbeats = NewHeartbeatStore(clock)
	}

	// (1) SINGLE-STORE COHERENCE — cut the §4.1 spine's three store-backed seams from
	// ONE store value via the STRICT accessor (the production posture, doc 15 §4.1:
	// "Production wiring SHOULD flip require-coherence on"). The resolver + pin writer
	// drop straight into the coordinator; the gate is built over the same store's
	// linker and stamped with TagGate so the runtime assertion proves the gate hits the
	// same store as the resolver/pin writer.
	spineSeams, err := sessions.StoreSeamsStrict(d.Store)
	if err != nil {
		return nil, fmt.Errorf("controlplane: store seams: %w", err)
	}

	// (2) LAUNCH GATE — over the one store's gate linker (the auth resolver upserts the
	// principal; the linker writes the session→principal link). Wrapped in the data-seam
	// adapter (gateAdapter) so the coordinator never imports auth in production, then
	// tagged with the store identity (TagGate) for the coherence assertion.
	resolverOpts := []auth.Option(nil)
	if d.PrincipalIDGen != nil {
		resolverOpts = append(resolverOpts, auth.WithIDGen(d.PrincipalIDGen))
	}
	principalResolver := auth.NewResolver(d.Store, resolverOpts...)
	launchGate := auth.NewLaunchGate(principalResolver, spineSeams.GateLinker)
	taggedGate := spineSeams.TagGate(gateAdapter{gate: launchGate})

	// (3) SCHEDULER PLACER — the orch18 Adapter injected as the coordinator's Placer
	// (doc 15 §4.1 step 3). Candidates from the live heartbeat feed scoped by the
	// tenancy source over the store lister; the staleness reference is the policy_log
	// head (the additive store.PolicyHead query, read per placement).
	tenancy := d.Tenancy
	if tenancy == nil {
		tenancy = unrestrictedTenancy{}
	}
	candidateSource := scheduler.StoreCandidateSource{
		Lister: d.Store,
		Feed:   heartbeats,
		Scope:  tenancy,
	}
	policySeq := policyHeadSeqSource{store: d.Store}
	sched := scheduler.New(d.SchedulerConfig)
	placer := scheduler.NewAdapter(sched, candidateSource, policySeq)
	// §4.1 step-9 LIVE FRESHNESS PROBE (D72) — flip the orch25-armed HostFreshness seam to
	// live by assigning the scheduler.Adapter's optional Freshness field. The seam re-probes
	// a placed host's CURRENT applied_seq from the SAME shared latest-per-host feed
	// StoreCandidateSource places against (heartbeats), so the step-9 routable re-check
	// re-validates against the host's present freshness — closing the residual placement→
	// step-9 window the recorded-only re-check misses. It is the single capstone line that
	// flips the probe from armed (NewHostFreshness constructed in main.go, never assigned) to
	// live; gated on DS_ORCH_LIVE so a non-live run is UNCHANGED — gate off leaves Freshness
	// nil and Adapter.CurrentFreshness returns sessions.ErrFreshnessUnknown, the coordinator
	// degrading to the recorded re-check (backwards-compatible, D50).
	if os.Getenv("DS_ORCH_LIVE") == "1" {
		placer.Freshness = NewHostFreshness(heartbeats)
	}

	// (4) §4.1 TEN-STEP COORDINATOR — built with the PRODUCTION host-side seams. The
	// two-key gate, the launch gate, the role resolver, the launching_user resolver, and
	// the pin writer come from the coherent store seams; the host verbs from the driver
	// registry; the identity/boundary verbs from their seams.
	twoKey := twoKeyAdapter{
		enroll: d.Enrollment,
		envs:   d.Store,
	}
	// §4.1 step-5 MINTED-CREDENTIAL EXPIRY SINK (D22/D82, doc 16 §5.4) — the REAL
	// TTL-driven teardown/re-mint scheduler wired behind CreateSeams.OnMintExpiry. It is
	// NON-BLOCKING on the create hot path (OnMintExpiry arms a timer and returns; the
	// create commit is unaffected by a slow/faulty re-mint) and IDEMPOTENT across a
	// post-step-5 create rollback (the fire path re-reads the persisted record and DROPS
	// on a terminal/destroyed session — the destroy supersedes the registration keyed on
	// session UUID, so no leaked re-mint fires for a session that no longer exists). On
	// fire it reads the PERSISTED §5.6 MintExpiry horizon (migration 0010) and re-mints
	// through the SAME production mint seam (an expired credential re-mints on resume, doc
	// 16 §5.4), persisting the fresh identity/CA + the new horizon back onto the record.
	mintExpirySink := newMintExpiryScheduler(d.Store, d.Mint, spineSeams.Resolver, clock, logger)
	// BOOT RE-ARM SWEEP (doc 16 §5.4) — the scheduler's per-session timers are in-process
	// only (time.AfterFunc), so this restart lost every armed timer; the DURABLE §5.6
	// MintExpiry horizon (migration 0010) each live record carries SURVIVED. Re-arm the
	// scheduler from the durable record so it is the system of record across restarts: list
	// the live (non-terminal) sessions and, for every one carrying a non-zero persisted
	// horizon, call OnMintExpiry(uuid, horizon). A past horizon arms delay=0 → the credential
	// re-mints promptly (an already-expired credential re-mints on resume); fire() then
	// re-reads the persisted horizon and re-mints or re-arms, and DROPS idempotently for a
	// terminal/DESTROYING session. The sweep is additive + best-effort (a store fault is
	// logged and tolerated; the reconciler is the backstop) and NON-BLOCKING (OnMintExpiry
	// swaps a timer and returns; the re-mint runs later on the timer goroutine).
	reArmMintExpiry(context.Background(), d.Store, mintExpirySink, logger)

	// §4.2 DESTROY SEAM (one ordering, two transports) — the compensating-rollback
	// destroy the create coordinator drives AND the public DestroySession teardown both
	// drive the SAME sessions.HostDestroyer. In the orchestrator-lite single-binary
	// posture (Deps.HostAgent set, D80) it is the IN-PROCESS adapter (inProcessHostDestroyer
	// over the in-process host-agent §4.2 orchestrator + the single store's recorded
	// host-side state), so a teardown drives the local host agent directly — no gRPC dial.
	// In the FLEET posture (HostAgent nil) it is the REMOTE driver verb (hostDestroyer{reg}),
	// sending the host-folded hypervisor.v1 Destroy to the placed host's driver over the
	// wire. The create coordinator + reconciler see only the seam, unchanged either way.
	var destroyer sessions.HostDestroyer = hostDestroyer{reg: d.Drivers}
	if d.HostAgent != nil {
		inProc, derr := newInProcessHostDestroyer(d.HostAgent, storeDestroyStateLookup{recs: d.Store})
		if derr != nil {
			return nil, fmt.Errorf("controlplane: build in-process host destroyer: %w", derr)
		}
		destroyer = inProc
	}

	creator, err := sessions.NewSessionCreator(sessions.CreateSeams{
		TwoKey:          twoKey,
		Store:           d.Store,
		Gate:            taggedGate,
		RoleResolver:    d.Roles,
		MintResolver:    spineSeams.Resolver,
		PinWriter:       spineSeams.PinWriter,
		Placer:          placer,
		HostAllocator:   hostAllocator{reg: d.Drivers},
		Minter:          minter{c: d.Mint},
		DigestWriter:    digestWriter{c: d.Digest},
		Injector:        injector{c: d.Inject},
		Booter:          booter{c: d.Boot},
		AttachIssuer:    attachIssuer{reg: d.Drivers},
		HostDestroyer:   destroyer,
		IdentityRevoker: identityRevoker{c: d.Revoke},
		OnMintExpiry:    mintExpirySink,
		// §6.1 MINT-BEFORE-ATTACH DIGEST-PUBLISH SEAM (D73/D84) — thread the optional
		// control-plane-supplied publisher into the coordinator. FLAG-GATED at the spine
		// call-site (DS_ORCH_DIGEST_PUBLISH_WIRE): OFF (default) the step is skipped and this
		// is UNUSED (byte-identical, D50); ARMED, the coordinator drives the push through it and
		// a nil publisher fails the create CLOSED (ErrDigestPublisherUnwired). A nil
		// d.DigestPublisher assigns a nil interface (not a typed-nil), so the coordinator's
		// nil-publisher fail-closed check is exact.
		DigestPublisher: d.DigestPublisher,
	}, d.StalenessBudget, logger)
	if err != nil {
		return nil, fmt.Errorf("controlplane: build session creator: %w", err)
	}

	// (5) CONCRETE REDRIVER — the §3 rule-b/rule-c convergence-loop closer, wired with
	// the SpineRunnerFunc(RedriveSpine) + SpineContinuationFunc(host-side re-create)
	// closures so the re-drive routes through the SAME create spine the CreateSession
	// RPC runs (never a reconciler-side copy). This references the orch18
	// SpineRunnerFunc / SpineContinuationFunc adapters — paying off the carrying cost.
	spineRunner := reconciler.SpineRunnerFunc(func(ctx context.Context, rec store.Session) (sessions.CreateSpineResult, error) {
		return sessions.RedriveSpine(ctx, taggedGate, d.Roles, spineSeams.Resolver, spineSeams.PinWriter, rec, logger)
	})
	// The host-side re-create continuation (§4.1 steps 3–4, 6–10): the SpineRunner above
	// already re-asserted the steps-1–2 + step-5 cluster (the part the reconciler must
	// NOT re-implement); this drives the host-side re-create of the MISSING VM through
	// the SAME production host seams the coordinator uses — the host agent's idempotent
	// verbs (CloneFromImage on the record's bound host, then boot), keyed on
	// session_uuid so a re-create of an already-present VM is a no-op and a re-create of
	// a missing one re-materializes it. It re-asserts onto the EXISTING record (the
	// re-drive is an already-created session, doc 16 §3.1 — never a re-create of the
	// record, which the create RPC owns), so it does NOT re-run the coordinator's
	// record-creation (steps 1–2); it re-drives the host verbs the missing VM needs.
	// withDigestReAck(d.Digest) installs the §4.1 step-6 digest re-write+re-ack seam (D73)
	// on the PRODUCTION re-create continuation: orch22 landed the seam on redrive.go behind
	// this variadic option but the production wiring never installed it, so a re-driven VM
	// was declared converged WITHOUT re-acking its session-scoped digest (a HALF-CONVERGED,
	// not-routable VM the §4.1 step-9 routable gate, {3,6} ≺ 9, would have refused). The
	// DigestClient is the SAME Identity-owned (D22/D82) step-6 face the create coordinator
	// drove, so the re-drive re-acks through the exact seam the original create acked through.
	hostReCreate := newHostReCreate(d.Drivers, d.Mint, d.Inject, d.Boot, spineSeams.Resolver, logger,
		withDigestReAck(d.Digest))
	spineContinuation := reconciler.SpineContinuationFunc(func(ctx context.Context, rec store.Session, spine sessions.CreateSpineResult) error {
		return hostReCreate.reCreate(ctx, rec, spine)
	})
	redriver, err := reconciler.NewConcreteRedriver(spineRunner, spineContinuation, logger)
	if err != nil {
		return nil, fmt.Errorf("controlplane: build redriver: %w", err)
	}

	// (6) RECONCILER + LOOP — the level-triggered convergence component, with the
	// concrete Redriver passed as reconciler.New's redriver argument and a fleet Driver
	// over the per-host registry (the reconciler's host-agnostic Suspend/Destroy verbs
	// resolve the host from the record, else broadcast the idempotent verb). The loop
	// calls Observe per heartbeat and Resync on cadence, honoring the lastBeat
	// single-goroutine contract (the loop owner serializes Observe/Resync).
	driver := registryDriver{reg: d.Drivers, recs: d.Store}
	rec, err := reconciler.New(d.Store, driver, redriver, d.Alarm, clock, d.ReconcilerConfig)
	if err != nil {
		return nil, fmt.Errorf("controlplane: build reconciler: %w", err)
	}
	// CREDENTIAL-TTL BACKSTOP ENROLLMENT (leg 1, doc 16 §5.4) — flip the reconciler's
	// credttl.go backstop seam to LIVE behind DS_ORCH_LIVE. credttl.go shipped the narrow
	// MintReconverger seam + the WithMintReconverger builder + the ReconcileMintExpiry pass
	// already, but NOTHING installed a reconverger, so the pass was a documented no-op and the
	// in-process mintExpiryScheduler timers + the single-shot boot re-arm were the SOLE
	// credential-TTL mechanism. Here the reconciler becomes the COARSE PERIODIC backstop behind
	// them: NewSchedulerRearmReconverger re-arms the SAME mintExpiryScheduler (mintExpirySink,
	// constructed above) at a stale record's persisted horizon — a PAST horizon arms delay=0 so
	// the scheduler's fire() re-reads the persisted §5.6 horizon and re-mints promptly (doc 16
	// §5.4), the boot-sweep mechanism. So the backstop owns no mint logic; it re-establishes the
	// timer the scheduler lost in the two miss windows credttl.go documents (a horizon the boot
	// re-arm's ListSessions faulted past, or a mid-resume re-mint that failed closed and left the
	// session SUSPENDED with its expired horizon). It is DISTINCT from the boot re-arm
	// (reArmMintExpiry above, single-shot at assembly): this re-converges on the periodic cadence.
	//
	// GATED / ADDITIVE. Gate OFF (the default) leaves the reconverger UNINSTALLED and
	// ReconcileMintExpiry a no-op (credttl.go) — fully backwards-compatible with the
	// pre-backstop in-process-timer path. A nil sink cannot reach here (mintExpirySink is
	// always constructed), but NewSchedulerRearmReconverger refuses a nil sink fail-closed, so
	// the construction surfaces a wiring miss rather than silently swallowing every re-arm.
	if os.Getenv("DS_ORCH_LIVE") == "1" {
		mintReconverger, mrErr := reconciler.NewSchedulerRearmReconverger(mintExpirySink)
		if mrErr != nil {
			return nil, fmt.Errorf("controlplane: build mint reconverger: %w", mrErr)
		}
		rec.WithMintReconverger(mintReconverger)
	}
	resyncInterval := d.ResyncInterval
	if resyncInterval <= 0 {
		resyncInterval = DefaultResyncInterval
	}

	// (7) D46 ESCALATION CLOCK — the pure, clock-injected pause classifier the reconcile
	// loop's escalation ticker leg consults (escalationclock.go). The boundaries take the
	// strawman defaults (5 min / 15 min) when Deps.EscalationConfig is the zero value; a
	// rig-tuned config re-tunes them without touching the frozen three-tier shape (D46).
	// NewEscalationClock validates the boundaries (a collapsed/inverted partition is a
	// construction error), so a mis-tuned config fails CLOSED here, never at the first tick.
	escCfg := d.EscalationConfig
	if escCfg.TransparentMax <= 0 && escCfg.BestEffortMax <= 0 {
		escCfg = sessions.NewEscalationConfig()
	}
	escalation, err := sessions.NewEscalationClock(escCfg, clock)
	if err != nil {
		return nil, fmt.Errorf("controlplane: build escalation clock: %w", err)
	}

	// (8) SUSPEND/PARK/RESUME DRIVER — the §3/§4.3 coordinator over the suspend host verbs
	// + the re-place seams the create coordinator already wired. Suspender defaults to a
	// registry-backed adapter over DriverClient.Suspend (the SAME per-host driver face the
	// create + reconciler use) so the default production wiring needs no extra backend; the
	// Resume/Snapshot host verbs are NOT on the narrow production DriverClient seam (they
	// are widened only behind DS_ORCH_LIVE in main.go), so they ride as injected Deps seams
	// (nil leaves them lazily-validated — a test-narrowed driver is constructible). The
	// re-place arm reuses the EXACT seams the create coordinator was built from (the same
	// Placer/HostAllocator/Minter), so a PARKED re-place runs the SAME §7 placement + §4.1
	// step-4 allocate + step-5 re-mint the create did. Approvals backs the policy_breach
	// resume arm (resumeauthority.go); nil is safe for the user/scheduler arms.
	suspender := d.Suspender
	if suspender == nil {
		suspender = registrySuspender{reg: d.Drivers, recs: d.Store}
	}
	parkSeams := sessions.ParkResumeSeams{
		Store:         d.Store,
		Suspender:     suspender,
		Resumer:       d.Resumer,
		Snapshotter:   d.Snapshotter,
		Placer:        placer,
		HostAllocator: hostAllocator{reg: d.Drivers},
		Minter:        minter{c: d.Mint},
		Approvals:     d.Approvals,
	}
	// LIVE RESUME-GRANT READER ENROLLMENT (leg 2, doc 16 §8.2 / §3 note 3) — flip the
	// policy_breach (BIC) resume arm's landed-approval check to REAL policy_log state behind
	// DS_ORCH_LIVE. resumedriver.go shipped sessions.WithLiveGrantApprovals (it installs the
	// production LiveGrantApprovalPresence over the EXISTING narrow store.LiveGrants read — the
	// "is a currently-valid PolicyKindAskGrant landed for this session?" query) but left the
	// seam for the caller to fill; today ParkResumeSeams.Approvals is whatever Deps.Approvals
	// carried (nil in the v0 posture, which denies every policy_breach resume fail-closed
	// regardless of a landed approval). Here, when the single backing store exposes the
	// LiveGrants read (every *store.Memory / *store.Postgres does — the store stays FROZEN), we
	// thread it through WithLiveGrantApprovals so AuthorizeResume's BIC arm reads the live
	// grant state in production. The approval-liveness clock reuses the wiring clock so a
	// deterministic test pins both the driver-timing and approval-TTL instants together.
	//
	// GATED / ADDITIVE / FAIL-CLOSED. The enrollment is the v0 PLACEHOLDER fill: it installs the
	// live reader ONLY when Deps.Approvals is nil ("today Deps.Approvals is the seam" — the nil
	// placeholder that denies every policy_breach resume). A deployment / test that DID supply its
	// own Approvals KEEPS it (WithLiveGrantApprovals would otherwise overwrite a deliberately
	// injected reader — the additive direction is to fill the gap, not clobber a caller choice).
	// Gate OFF leaves Approvals exactly as supplied (the pre-enrollment posture, unchanged). Gate
	// ON with a nil Approvals but a store that does NOT expose LiveGrants (a test-narrowed
	// ControlPlaneStore) leaves Approvals nil rather than installing a half-wired reader — and the
	// production presence is itself fail-closed (a nil reader reports a read fault, never a false
	// "no approval"), so a mis-wired build denies a policy_breach resume rather than silently
	// allowing it. The user/scheduler resume arms never consult Approvals, so they are unaffected.
	//
	// SELF-APPROVAL GUARD (doc 16 §8.2). When the SAME backing store ALSO exposes the
	// principal-rank reads (GetPrincipal → Principal.MayApprove + GetSessionLaunching-
	// Principal — every *store.Memory / *store.Postgres does), the enrollment threads the
	// GUARDED builder (WithLiveGrantApprovalsAndRank) so a live ask-grant counts ONLY when
	// its approver is a rung-2 human DISTINCT from the session's requestor / launching_user
	// — closing the gap where a launching user (or a prompt-injected agent acting as that
	// principal) approves its own policy_breach park. A store that exposes LiveGrants but
	// NOT the principal reads (a test-narrowed store) keeps the prior un-guarded fill
	// (behavior-preserving); a store that exposes neither leaves Approvals nil (still
	// fail-closed via the nil-reader read fault).
	if os.Getenv("DS_ORCH_LIVE") == "1" && d.Approvals == nil {
		if reader, ok := d.Store.(liveGrantReader); ok {
			if ranks, ok := d.Store.(principalRankStore); ok {
				parkSeams = sessions.WithLiveGrantApprovalsAndRank(parkSeams, reader, ranks, clock)
			} else {
				parkSeams = sessions.WithLiveGrantApprovals(parkSeams, reader, clock)
			}
		}
	}
	parkResume, err := sessions.NewParkResumeDriver(parkSeams, clock)
	if err != nil {
		return nil, fmt.Errorf("controlplane: build park/resume driver: %w", err)
	}

	// (8b) D46 ASK-A-HUMAN PARK MACHINE + BOOT RE-ADOPTION (doc 16 §8.2 / doc 15 §3
	// RecoverSessions shape). parkstore (a durable package shipped un-consumed) is wired
	// here as the askhold.ParkRecorder behind the park machine: a genuine rung-2 ask parks
	// through RecordParked and resumes on a human answer through ClearParked, so the
	// session<->question join is DURABLE. Deps.ParkRecorder lets a deployment front the
	// database/sql twin (parkstore.SQL) for genuine cross-restart durability; nil installs a
	// fresh in-process parkstore.NewMemory() (the stdlib-only reference posture, D50 — durable
	// WITHIN the process). The boot re-adoption sweep then enumerates the backing's List() and
	// re-adopts every outstanding park into the in-memory machine the restart lost, so a park
	// parked before the restart is back in the running machine and a later human answer still
	// resolves it (NEVER timing out into allow or kill — the load-bearing D46/D77 invariant).
	// The sweep is additive + best-effort (a backing List() fault is logged and tolerated; the
	// durable join is retained for the next assembly) and NON-BLOCKING (it lists and re-adopts).
	parkRecorder := d.ParkRecorder
	if parkRecorder == nil {
		parkRecorder = parkstore.NewMemory()
	}
	parkMch := newParkMachine(parkRecorder)
	reAdoptParks(parkRecorder, parkMch, logger)

	// POLICYLOG ASK-PARK ROUTER ENROLLMENT (leg 3, doc 15 §4.3 / §6.2 step 4 / doc 16 §8.2)
	// — enroll the *parkMachine as the policylog ask-routing PARK router behind DS_ORCH_LIVE so
	// D46 rung-2 untimed park is DURABLE end to end. The live ask-routing call-site
	// (policylog.Service.RouteAsk) takes an injected askParkRouter and, on a GENUINE rung-2 ask
	// (ask.Rung2), enters it into the untimed park via that seam's Park(sessionUUID, ask, now);
	// the *parkMachine satisfies the seam exactly and routes the enrollment through the durable
	// parkstore backing (RecordParked), so a later human answer resumes the ask through the
	// machine's ClearParked-backed Resume — never a timeout into allow or kill (the load-bearing
	// D46/D77 invariant). Without this enrollment the live site would compute the rung-2 dispatch
	// decision but enter NO durable park (the nil-router posture policylog.RouteAsk tolerates).
	// Gate OFF leaves the router nil (the v0 posture, unchanged); the binding holds the SAME
	// machine the boot re-adoption sweep re-reads and the suspend escalation drives, so the
	// running set, the durable join, and the live ask-routing site converge on one park machine.
	var askParkRouter AskParkRouter
	if os.Getenv("DS_ORCH_LIVE") == "1" {
		askParkRouter = parkMch
	}

	// (9) BOUNDARY SUSPEND-SIGNAL TERMINATOR — validates+maps+dedups the frozen
	// boundary.v1.SuspendSignal into the hypervisor.v1.SuspendRequest the ParkResume driver
	// drives (suspendsignal.go). It owns its dedup set; the DS_ORCH_LIVE real boundary feed
	// (main.go) hands it each delivered signal, gate-off an in-process fake does (D50).
	suspendTerminator := sessions.NewSuspendSignalTerminator()

	// (10) D110 SUSPEND-COORD EMITTER — the orchestrator→ds-tlsproxy pause/resume
	// coordination over the frozen hostagent.v1.SuspendCoord slot (suspendcoord.go). It
	// emits over the injected host-ward sink; nil installs an in-process DROP sink (the
	// gate-off D50 posture — no boundary channel wired), so a non-live run constructs a
	// usable coordinator without a real channel. main.go wires the real host-local channel
	// behind DS_ORCH_LIVE.
	emitter := d.SuspendEmitter
	if emitter == nil {
		emitter = dropSuspendCoordEmitter{}
	}
	suspendCoord, err := NewSuspendCoordinator(emitter)
	if err != nil {
		return nil, fmt.Errorf("controlplane: build suspend coordinator: %w", err)
	}

	// (11) M2 INSTANT-START FAST PATH — the FastStarter over the SAME §4.1 ten-step
	// coordinator (faststart.go). The golden-image resolver defaults to the v0
	// PrebakedGoldenResolver (the content-address IS the golden artifact); the §8 timing
	// recorder is a fresh in-process trend sink the fast path feeds every create — MEASURE,
	// NOT GATE (D81/D32: no budget armed). The CreateSession handler is constructed with the
	// SAME FastStarter instance (newSessionService below) so a golden-image create routes
	// the §7 image-cache-locality lever through it and its trend folds into one Recorder.
	fastStarter, err := sessions.NewFastStarter(creator, d.GoldenImage, nil, clock)
	if err != nil {
		return nil, fmt.Errorf("controlplane: build fast starter: %w", err)
	}

	loop := newReconcileLoop(rec, heartbeats, resyncInterval, logger)
	// Install the D46 escalation leg on the loop: a SECOND ticker leg inside the SAME
	// single-goroutine Run (reconcileloop.go), classifying every SUSPENDED session per the
	// EscalationClock and driving the ParkResume escalation+coordination — NO new goroutine
	// racing the loop's lastBeat owner (the single-goroutine serialization contract).
	loop.installEscalation(escalation, parkResume, suspendCoord, d.Store)

	// (7) ATTACH-SERVING LEGS (D18/D61/D79, doc 15 §5.3/§5.4) — the WatchSession fan-out
	// terminator + the attach-handle issuer, both cut from the SAME single backing store the
	// rest of the control plane is wired from (so the D61 writer seat the issuer arbitrates
	// lives in the same record the create coordinator wrote). The Fanout is the seq-stamping,
	// ring-backed WatchSession terminator (watch.go); the Issuer runs the server-side seat
	// arbitration (seat.go) and mints the transport-ambivalent attach.v1.AttachHandle
	// (handle.go). The host-agent relay (attachrelay.go) Publishes host-ward state edges into
	// this Fanout; the WatchSession handler Subscribes to it.
	//
	// GAP-3 ENDPOINT RESOLVER (the M0 DIRECT host-agent attach address, doc 15 §5.4): the
	// issuer is wired with the sessionEndpointResolver (attachendpoint.go) so an issued
	// handle carries the HOST-LOCAL UDS DIRECT candidate the gap-3 serving leg serves the
	// session on — flipping the Attach RPC from a seat-and-auth-only handle (handle.go's
	// documented no-endpoint degrade) to a SERVABLE one, so serpent-tui maps the DIRECT
	// candidate to its TransportUnix carrier and takes the writer-seat branch. The resolver
	// is cut from the SAME single backing store (the record authority the seat arbitration
	// already reads), gating the candidate on the session being placed + servable so a
	// not-yet-placed session still issues a handle with no fabricated endpoint. A nil-store
	// guard cannot trip here (d.Store is required, checked above), but the construction is
	// surfaced fail-closed for symmetry with the other seam builds.
	fanout := attach.NewFanout(0)
	// The endpoint resolver also TAGS the issued endpoint's transport from the host-resolved
	// per-session mode (d.AttachModeReader — the shared <OverlayDir>/.ds-session-mode marker):
	// RAW_TERMINAL for a terminal session, DIRECT otherwise. In the single-box MVP THIS
	// resolver (not the host-agent minter) answers serpent-tui's Attach, so this is what flips
	// `serpent claude --vm --raw on` out of the structured fallback for a terminal session
	// (U-CPWIRE). A nil reader (DS_ORCH_OVERLAY_DIR unset) leaves every session DIRECT —
	// fail-safe, byte-identical to before.
	endpointResolver, err := NewSessionEndpointResolver(d.Store, d.AttachSocketDir, WithSessionModeReader(d.AttachModeReader))
	if err != nil {
		return nil, fmt.Errorf("controlplane: build attach endpoint resolver: %w", err)
	}
	issuer := attach.NewIssuer(d.Store, attach.WithEndpointResolver(endpointResolver))
	sessionSvc := newSessionService(creator, fastStarter, d.Store, d.DefaultOrg, clock, logger)
	sessionSvc.SetAttachServing(fanout, issuer)

	// (7b) W2 WRITER-SEAT ARBITRATION (D61/D137/D138, sessions/10 §2.1 — the browser writer
	// seat WRITE leg). The single attach.SeatArbiter is the ONE choke point the seat changes
	// hands through: it serializes RequestWriterSeat per session (exactly one live seat,
	// D61), mirrors the attributed holder onto the SAME session record the create coordinator
	// wrote (so D78 attendedness reads the seat honestly), and emits the observable
	// WRITER_SEAT_CHANGED read event through THIS SAME Fanout (so a steal cannot be silent,
	// D137 — the stamped seq IS the granted_seq/released_seq). The D138 steal gate consults
	// the attendedness signal over the record (writerSeatAttendedness): a force_steal of an
	// ATTENDED held seat is refused by default. The WriterRelayService gates the arbiter
	// behind the D22/D55 identity + D39 attach auth (Deps.WriterIdentity/WriterAttachAuth,
	// fail-closed when absent). DriveSession stays W3 (Unimplemented).
	seatArbiter := attach.NewSeatArbiter(d.Store, fanout,
		attach.WithSeatClock(clock),
		attach.WithAttendednessProbe(writerSeatAttendedness(d.Store)),
	)
	// W3 DRIVE LEG (sessions/10 §3/§5/§6 W3; D78/D137/D138) — DriveSession validates the
	// writer_seat_id against the live grant at this SAME seatArbiter, forwards the admitted
	// DriveInput to CC stdin via the host-agent relay (Deps.WriterDriveSink — the DriveSink
	// seam, fail-closed nil ⇒ DriveSession refuses), and emits the v1 InputActivity on this
	// SAME Fanout (so the read leg projects every accepted input + the D78 attendedness clock
	// advances, server-stamped through the shared clock). The drive sink is the host-agent
	// relay adapter wired behind DS_ORCH_LIVE in main.go (the live wiring is filed as a
	// followup like W2's auth adapters); gate-off it stays nil and DriveSession refuses
	// Unavailable (no live relay), exactly as the unwired-auth seams refuse RequestWriterSeat.
	writerRelay := newWriterRelayService(seatArbiter, fanout, d.WriterDriveSink, d.WriterIdentity, d.WriterAttachAuth, clock)
	// §4.2 DESTROY LEG (doc 15 §4.2; D35/D72) — the public DestroySession surface drives the
	// SAME sessions.HostDestroyer the create coordinator's compensating rollback uses (the
	// in-process adapter in orchestrator-lite, the remote driver in the fleet) over the SAME
	// single backing store it flips desired=DESTROYING→DESTROYED on, so an operator tears a
	// session down over the wire through the public handler — never reaching for the driver.
	sessionSvc.SetDestroyServing(destroyer, d.Store)

	// (7b′) D81 CREATE-TIMING FOLD LEG (createtiming-feed; D81/D32/D50) — make the observability
	// leg LIVE. The createtiming-feed wave shipped the fold + read surface (foldCreateTiming /
	// CreateTimingServerSpanTrend) and the SAME-flag self-armed recorder on the reconcile loop
	// (reconcileloop.go: createTiming *CreateTimingWire, armed from CreateTimingWireEnabled()), but
	// left the ONE composition-root wire deferred, so the create path had NO sink to fold into at
	// runtime. Here it becomes live: the reconcile loop (cp.Reconcile — the `loop` built above)
	// satisfies createTimingSink natively (RecordCreateTiming + CreateTimingServerSpanTrend), so the
	// create fold and the (b)-row read land on the SAME shared trend recorder — no second recorder,
	// no Deps field.
	//
	// ADDITIVE / DEFAULT-OFF BYTE-IDENTICAL (D50). Installing the sink only assigns a field; the
	// fold itself is flag-gated inside foldCreateTiming (DS_ORCH_CREATETIMING_WIRE off ⇒ it returns
	// before reading the sink) AND the loop's wire self-armed from the SAME flag no-ops the fold — a
	// belt-and-suspenders double gate. With the flag unset a create is byte-for-byte unchanged
	// whether or not the sink is installed; with it armed the fold reaches the loop's armed recorder.
	sessionSvc.SetCreateTimingServing(loop)

	// (7c) D18 FAN-OUT SUB-TOKEN LEG (subtoken.go, doc 23 §5; D126) — make the leg LIVE.
	// The wave-d18fanout seam shipped the injector + sink + the per-VM deriveAndMount that
	// CreateSession already calls, but NOTHING constructed the injector at the real wiring
	// site, so the leg was DEAD CODE at runtime. Here it becomes live: when an attenuator is
	// wired (Deps.SubTokenAttenuator — the gRPC-shim over the frozen
	// dreamserpent.auth.v1 TokenAttenuationService that main.go dials env-gated by
	// DS_AUTHSDK_ENDPOINT, or the generated authv1fake in tests, D50), NewControlPlane builds
	// the fan-out injector over that seam + a fileSubTokenSink at the documented well-known
	// in-VM mount dir (DefaultAgentSubTokenMountDir = /run/ds/agent-token) and installs it
	// alongside the parent-authority resolver via Sessions.SetSubTokenServing. The sink writes
	// the derived sub-token to the per-VM path the agent reads LOCALLY inside its VM — never
	// over the network (doc 23 §5). The authority (Deps.SubTokenAuthority) sources the D125
	// parent user auth token + the requested-scope SUBSET of its ds_scopes from the create
	// request (the frozen CreateSessionRequest carries the launching_user subject, not the
	// token/scopes — those ride the IdP claim the M2 band threads, doc 16 §3.2).
	//
	// ADDITIVE / FAIL-OPEN. A nil attenuator (a deployment without the auth SDK reachable,
	// the v0 posture, or a test-narrowed handler) leaves the leg UNWIRED — CreateSession then
	// fans out no sub-token and is otherwise unaffected. A nil authority (no IdP boundary yet)
	// leaves no parent authority resolvable, so the injector skips the derive (nothing to
	// attenuate). Either way the create path is unchanged.
	if d.SubTokenAttenuator != nil {
		subTokenInjector := newSubTokenInjector(d.SubTokenAttenuator, fileSubTokenSink{MountDir: DefaultAgentSubTokenMountDir})
		sessionSvc.SetSubTokenServing(subTokenInjector, d.SubTokenAuthority)
	}

	// §4.2 DESTROY-PATH CONVERGENCE BACKSTOP — the DestroyRedriver re-drives a session STUCK in
	// DESTROYING (a transient host-teardown fault left it there; DestroySession's own comment
	// promises the reconciler re-drives it) FORWARD to DESTROYED via the SAME §4.2 destroyer the
	// create rollback + the public handler drive, idempotent on session_uuid. The §3 conflict
	// rules deliberately exclude DESTROYING from the rule-b missing-VM reap (a teardown-in-flight
	// record is not a no-VM fault), so this is the missing arm that closes the destroy loop. It
	// lists stuck records through the store (State=DESTROYING) and finalizes the §3-terminal
	// transition through the SAME single store; both adapters are slices of the ControlPlaneStore
	// surface, adding no store method.
	destroyReDriver, err := reconciler.NewDestroyRedriver(
		destroyingLister{recs: d.Store, clock: clock},
		destroyReDriveDriver{destroyer: destroyer},
		destroyFinalizer{recs: d.Store, clock: clock},
		logger,
	)
	if err != nil {
		return nil, fmt.Errorf("controlplane: build destroy re-driver: %w", err)
	}

	// SESSION IDLE-TTL REAPER (the writer-less-RUNNING leak closer, sessionidlereaper.go) —
	// destroys a RUNNING session ({READY,ATTACHED,WORKING}) left writer-less past the idle TTL
	// via the SAME §4.2 destroyer the create rollback + the public DestroySession handler drive
	// (idempotent on session_uuid), over the SAME single backing store. It closes the leak the
	// other two convergence legs do NOT cover: the reconcile escalation leg sweeps only SUSPENDED
	// sessions, and the destroy re-driver only re-drives records already STUCK in DESTROYING — so
	// a session whose human writer detaches and never re-attaches stays RUNNING (its ≈8 GB VM
	// resident) forever. The TTL comes from DS_ORCH_SESSION_IDLE_TTL (a Go duration; default
	// DefaultSessionIdleTTL = 30m; 0 = disabled): newSessionIdleReaper returns nil for a ≤ 0 TTL,
	// so the reaper is the env-gated OPT-OUT (a nil reaper has RunSessionIdleReap block-until-
	// shutdown — no sweep). Conservative by construction: only RUNNING + continuously writer-less
	// past the whole window is reaped (sessionidlereaper.go).
	sessionIdleTTL := resolveSessionIdleTTL(logger)
	idleReaper := newSessionIdleReaper(d.Store, destroyer, sessionIdleTTL, clock, logger)

	// (7d) PRODUCTION READ-STREAM CONTENT RELAY (contentrelay.go, D61/D79) — relay CC's
	// projected attach.v1 CONTENT (chat/tool/subagent/ask/plan/accounting) through the SAME
	// WatchSession Fanout the state edges + seat handoff ride, so N READERS observe CC output,
	// not only the writer seat's own SocketConn. Constructed ONLY when a ContentSource is wired
	// (Deps.ContentSource — the live host-agent bridge Events() adapter behind DS_ORCH_LIVE);
	// nil source leaves ContentRelay nil and the fan-out carries the control edges only (a
	// clean degrade, byte-identical to before). The serve bootstrap arms its pump lifetime
	// (Start) and drives ensure/stop off the state-edge relay's observed-session set. Readers
	// stay read-only (D136): the relay only Publishes, and it relays only content event types.
	var contentRelay *contentRelay
	if d.ContentSource != nil {
		contentRelay = newContentRelay(d.ContentSource, fanout, logger)
	}

	return &ControlPlane{
		Sessions:          sessionSvc,
		RoleCatalog:       d.RoleCatalog,
		Reconcile:         loop,
		Heartbeats:        heartbeats,
		Creator:           creator,
		Placer:            placer,
		Fanout:            fanout,
		WriterRelay:       writerRelay,
		ContentRelay:      contentRelay,
		reCreate:          hostReCreate,
		ParkResume:        parkResume,
		ParkMachine:       parkMch,
		AskParkRouter:     askParkRouter,
		Escalation:        escalation,
		SuspendTerminator: suspendTerminator,
		SuspendCoord:      suspendCoord,
		FastStarter:       fastStarter,
		MintExpiry:        mintExpirySink,
		DestroyReDriver:   destroyReDriver,
		SessionIdleReaper: idleReaper,
		sessionIdleTTL:    sessionIdleTTL,
		mintBackstop:      rec,
		logger:            logger,
	}, nil
}

// RunMintExpiry runs the CREDENTIAL-TTL BACKSTOP (leg 1, doc 16 §5.4) on the periodic
// Resync cadence until ctx is cancelled: every interval it runs one reconciler
// ReconcileMintExpiry pass — list the live records and re-arm / re-mint every one whose
// persisted §5.6 MintExpiry horizon is already past, through the installed MintReconverger
// (WithMintReconverger, gated on DS_ORCH_LIVE). It is the COARSE periodic backstop behind
// the in-process mintExpiryScheduler timers + the single-shot boot re-arm: a horizon BOTH
// of those missed (the two windows credttl.go documents) re-converges here. It mirrors the
// sibling convergence sweeps (RunDestroyReDrive / RunSessionIdleReap) so the control plane
// joins the credential-TTL backstop to the convergence loop with one uniform
// start-in-a-goroutine lifecycle; main.go starts it in its own goroutine alongside
// cp.Reconcile.Run. Running it concurrently with the reconcile loop is SAFE because
// ReconcileMintExpiry touches no mutable reconciler state (it never reads/writes lastBeat).
//
// A non-positive interval takes the reconcile loop's full-resync cadence (DefaultResyncInterval)
// so the credential-TTL backstop and the §3 VM-presence resync run on aligned rhythms. With no
// MintReconverger installed (gate off) each pass is a no-op (credttl.go), so a non-live run
// still has the uniform lifecycle. It returns ctx.Err() on a clean shutdown.
func (cp *ControlPlane) RunMintExpiry(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultResyncInterval
	}
	return cp.mintBackstop.RunMintExpiry(ctx, interval, cp.logger)
}

// EnvSessionIdleTTL is the environment variable name the writer-less-RUNNING idle reaper reads
// its TTL from (a Go duration string, e.g. "30m", "2h", "45s"). Unset → DefaultSessionIdleTTL
// (30m); "0" (or any non-positive duration) → the reaper is DISABLED. An unparseable value is
// logged and falls back to the default (a typo never silently disables the leak guard).
const EnvSessionIdleTTL = "DS_ORCH_SESSION_IDLE_TTL"

// resolveSessionIdleTTL reads DS_ORCH_SESSION_IDLE_TTL into the idle-reaper TTL. The empty/unset
// case takes DefaultSessionIdleTTL (the leak guard is ON by default); an explicit "0" (or any
// ≤ 0 duration) DISABLES the reaper (returns 0 → newSessionIdleReaper yields nil); an
// unparseable value is logged and takes the default (a typo must not silently disable the guard,
// the fail-safe direction). It is the ONE place the env is read so the wiring + RunSessionIdleReap
// share one resolved value.
func resolveSessionIdleTTL(logger *slog.Logger) time.Duration {
	raw := os.Getenv(EnvSessionIdleTTL)
	if raw == "" {
		return DefaultSessionIdleTTL
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil {
		if logger != nil {
			logger.Warn("controlplane: unparseable DS_ORCH_SESSION_IDLE_TTL; falling back to default idle TTL (idle reaper stays enabled)",
				slog.String("value", raw), slog.Duration("default", DefaultSessionIdleTTL), slog.Any("err", err))
		}
		return DefaultSessionIdleTTL
	}
	return ttl
}

// RunSessionIdleReap runs the writer-less-RUNNING idle reaper on a cadence until ctx is
// cancelled: every interval it runs one reaper Sweep (list → advance the in-memory writer-less
// clock → reap the over-TTL writer-less RUNNING sessions via the §4.2 destroyer). It mirrors
// RunDestroyReDrive's ticker idiom and delegates to the reaper's own Run (sessionidlereaper.go).
// A non-positive interval lets the reaper derive its cadence from the TTL (re-checking at least
// once per idle window). When the reaper is DISABLED (TTL ≤ 0 ⇒ cp.SessionIdleReaper nil) this
// blocks until ctx is cancelled and runs NO sweep — so main.go can start it unconditionally in a
// goroutine with one uniform lifecycle. It returns ctx.Err() on a clean shutdown.
func (cp *ControlPlane) RunSessionIdleReap(ctx context.Context, interval time.Duration) error {
	// sessionIdleReaper.Run is nil-safe (a nil reaper blocks until ctx done), so a disabled
	// reaper still has a uniform start-in-a-goroutine lifecycle without a nil check here.
	return cp.SessionIdleReaper.Run(ctx, interval)
}

// RunDestroyReDrive runs the §4.2 destroy-path convergence sweep on a cadence until ctx is
// cancelled: every interval it re-drives every record STUCK in DESTROYING forward to DESTROYED
// via the §4.2 teardown (the DestroyRedriver). It is the backstop for a session DestroySession
// left DESTROYING on a transient teardown fault (the §3 conflict rules do not reap DESTROYING).
// A non-positive interval takes DefaultDestroyReDriveInterval. It returns when ctx is done
// (a clean shutdown), draining one final sweep is NOT attempted (the next process re-converges
// from the durable DESTROYING records — the level-triggered contract). A degraded-mode list
// fault (store unavailable) is logged and the sweep retries on the next tick; it never stalls
// the ticker. main.go starts this in its own goroutine alongside cp.Reconcile.Run.
func (cp *ControlPlane) RunDestroyReDrive(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultDestroyReDriveInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := cp.DestroyReDriver.Sweep(ctx); err != nil {
				cp.logger.WarnContext(ctx, "controlplane: destroy re-drive sweep faulted; will retry next tick", slog.Any("err", err))
			}
		}
	}
}

// destroyingLister adapts the single backing store onto the reconciler.DestroyingLister seam:
// it lists the records STUCK in DESTROYING (the in-flight teardown marker) by filtering
// ListSessions on State=DESTROYING. IncludeDestroyed stays false (a DESTROYED record is already
// converged — never re-listed). It is a slice of the ControlPlaneStore (ListSessions), adding no
// store method.
type destroyingLister struct {
	recs  ControlPlaneStore
	clock func() time.Time
}

func (l destroyingLister) ListDestroying(ctx context.Context) ([]store.Session, error) {
	return l.recs.ListSessions(ctx, store.SessionFilter{State: store.SessionDestroying})
}

// destroyReDriveDriver adapts the SAME sessions.HostDestroyer the create rollback + the public
// DestroySession handler drive onto the reconciler.DestroyDriver seam: the host-folded §4.2
// teardown keyed on (hostID, sessionUUID), idempotent and re-driveable (doc 15 §4.2).
type destroyReDriveDriver struct {
	destroyer sessions.HostDestroyer
}

func (d destroyReDriveDriver) Destroy(ctx context.Context, hostID, sessionUUID string) error {
	return d.destroyer.Destroy(ctx, hostID, sessionUUID)
}

// destroyFinalizer adapts the single backing store onto the reconciler.DestroyFinalizer seam:
// it writes the §3-terminal DESTROYING→DESTROYED transition, stamping DestroyedAt (the record is
// RETAINED, never deleted — D66). It is a slice of the ControlPlaneStore (UpdateSession), adding
// no store method, and mirrors the DESTROYED finalize DestroySession's own success path writes
// (sessionservice.go) so a re-driven finalize is identical to the handler's.
type destroyFinalizer struct {
	recs  ControlPlaneStore
	clock func() time.Time
}

func (f destroyFinalizer) FinalizeDestroyed(ctx context.Context, sessionUUID string) (store.Session, error) {
	destroyed := store.SessionDestroyed
	return f.recs.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		State:       &destroyed,
		DestroyedAt: store.SetTime(f.clock()),
	})
}

// CreateTimingTrend relays the M2 FastStarter's §8 create→attach server-span trend
// (Recorder().ServerSpanTrend()) as the measure-not-gate sink (D81/D32, doc 15 §8): the
// per-create trigger-eligible span distribution (RTT excluded) the M2 release budget will
// EVENTUALLY be set against — recorded now, gated NEVER (no budget armed here). A
// production observability reader (or the integration test) reads it off the control plane
// rather than reaching into the fast path. It is a pure read of the in-process recorder.
func (cp *ControlPlane) CreateTimingTrend() createtiming.Trend {
	return cp.FastStarter.Recorder().ServerSpanTrend()
}

// FoldHostAttachSegment is the host→control-plane CARRIAGE call-site for the doc 15 §8
// attach-leg segment (foldattach-carriage; D81/D32/D50). The create/attach flow calls it
// POST session-serve — after the host-agent AttachBridge has served (offline-RENDERED under
// DS_HOSTAGENT_LIVE unset) the per-session serving leg and, under the SAME flag this method
// gates on, MEASURED its SegAttachHandshake segment — to thread that host-side attach-leg
// contribution into THIS control plane's shared §8 trend. It hands the bridge the reconcile
// loop (cp.Reconcile) as the createTimingFoldSink and lets AttachBridge.FoldAttachSegment fold
// the measured single-entry stack fragment (AttachSegmentStack) plus the trigger-EXCLUDED
// client RTT through the loop's RecordCreateTiming, so the host's attach-leg segment lands on
// the SAME shared trend the create-side fold (foldCreateTiming) and the (b)-row read consume —
// no second recorder, no Deps field. Before this call-site the bridge's FoldAttachSegment
// producer had NO production caller, so the attach-leg segment never reached the trend even
// with the wire armed; this is that caller.
//
// FLAG-GATED / DEFAULT-OFF BYTE-IDENTICAL (D50). It is armed by the SAME single flag the
// create-timing wire reads (DS_ORCH_CREATETIMING_WIRE, CreateTimingWireEnabled): with the flag
// unset it returns before touching the bridge or the loop — no fold — so a non-armed
// create/attach is byte-for-byte unchanged. This is a belt-and-suspenders gate on top of the
// two the fold already carries (off the flag the bridge never measured a segment, so
// AttachSegmentStack is nil and FoldAttachSegment no-ops; and the loop's wire self-armed from
// the SAME flag no-ops RecordCreateTiming). A nil bridge, a nil control plane, or one with no
// reconcile loop is likewise a clean no-op.
//
// PURE / MEASURE-NOT-GATE (D81/D32). It never gates or mutates the serving leg (the session is
// already served); it returns the recorded trend and ok=true when a segment was folded, and a
// sink fold error surfaces to the caller with ok=false for the caller to log-and-swallow —
// exactly the posture the create-side foldCreateTiming takes.
func (cp *ControlPlane) FoldHostAttachSegment(bridge *hostagent.AttachBridge, sessionUUID string, clientRTT time.Duration) (createtiming.Trend, bool, error) {
	if !CreateTimingWireEnabled() || cp == nil || bridge == nil || cp.Reconcile == nil {
		return createtiming.Trend{}, false, nil
	}
	return bridge.FoldAttachSegment(cp.Reconcile, sessionUUID, clientRTT)
}

// ---------------------------------------------------------------------------
// Small adapters the wiring needs — each bridges an injected backend onto a seam.
// ---------------------------------------------------------------------------

// AskParkRouter is the policylog ask-routing PARK enrollment seam (leg 3): the exact
// shape policylog.Service.RouteAsk's injected askParkRouter argument requires
// (Park(sessionUUID, ask, now) (askhold.Parked, error)). The control-plane *parkMachine
// satisfies it natively, so the live wiring hands the SAME machine the boot re-adoption
// sweep re-reads and a human answer resumes through — the durable D46 session<->question
// join is end-to-end. It is exported because it types the optional
// ControlPlane.AskParkRouter field the live RouteAsk site reads; declared here (not
// imported from policylog, whose askParkRouter is unexported) so the control plane owns
// the seam name it publishes.
type AskParkRouter interface {
	Park(sessionUUID string, ask askhold.Ask, now time.Time) (askhold.Parked, error)
}

// liveGrantReader is the NARROW read slice the live resume-grant enrollment (leg 2)
// type-asserts the single backing store to: just LiveGrants, the EXISTING store method
// returning a session's currently-valid (TTL-checked) PolicyKindAskGrant rows. It mirrors
// the sessions package's own (unexported) liveGrantReader shape so a successful assertion
// hands sessions.WithLiveGrantApprovals exactly the reader it needs — *store.Memory and
// *store.Postgres both satisfy it natively (the store package stays FROZEN, no method
// added). Declaring it HERE (a one-method slice over the existing read) keeps the
// enrollment depending on the minimum store surface, the same discipline as
// policyHeadSeqSource over ListPolicy. A ControlPlaneStore that does NOT expose LiveGrants
// (a test-narrowed store) simply fails the assertion and the live reader is not installed.
type liveGrantReader interface {
	LiveGrants(ctx context.Context, sessionUUID string, now time.Time) ([]store.PolicyLogRow, error)
}

// principalRankStore is the NARROW read slice the §8.2 self-approval-guard enrollment
// (leg 2b) type-asserts the single backing store to: GetPrincipal (→ Principal.MayApprove,
// the rung-2 role gate in store/principalroles.go) + GetSessionLaunchingPrincipal (the
// §3.2 requestor link). It mirrors the sessions package's own (unexported) principalRankStore
// shape so a successful assertion hands sessions.WithLiveGrantApprovalsAndRank a store that
// backs the production StoreApproverRankResolver — *store.Memory and *store.Postgres both
// satisfy it natively (the store package stays FROZEN, no method added). Declaring it HERE
// (a two-method slice over the existing reads) keeps the enrollment depending on the minimum
// store surface, the same discipline as liveGrantReader over LiveGrants. A ControlPlaneStore
// that does NOT expose these reads (a test-narrowed store) simply fails the assertion and the
// enrollment falls back to the un-guarded presence (behavior-preserving).
type principalRankStore interface {
	GetPrincipal(ctx context.Context, id string) (store.Principal, error)
	GetSessionLaunchingPrincipal(ctx context.Context, sessionUUID string) (string, error)
}

// gateAdapter wraps the real *auth.LaunchGate onto the sessions spine's data-typed
// launchGate seam (sessions consumes the gate as DATA, never importing auth in
// production — the same-tree import-cycle reason, createspine.go header). It copies the
// resolved auth into auth.ResolvedAuth and the gate's result back into the spine's
// LaunchOutcome, wrapping an auth refusal as the spine's classified sentinel.
type gateAdapter struct{ gate *auth.LaunchGate }

func (a gateAdapter) AuthorizeLaunch(ctx context.Context, sessionUUID string, in *sessions.LaunchInput) (sessions.LaunchOutcome, error) {
	var ra *auth.ResolvedAuth
	if in != nil {
		ra = &auth.ResolvedAuth{
			Org:         in.Org,
			Subject:     in.Subject,
			Roles:       principalRolesFrom(in.Roles),
			DisplayName: in.DisplayName,
		}
	}
	authz, err := a.gate.AuthorizeLaunch(ctx, sessionUUID, ra)
	if err != nil {
		// A nil *ResolvedAuth (unauthenticated launch) or an out-of-vocabulary role is
		// auth.ErrAuth — classify it as the spine's launch-refusal sentinel so the
		// coordinator surfaces a fail-closed, attributable refusal. A store fault is
		// surfaced verbatim (NOT wrapped as the refusal sentinel).
		if errors.Is(err, auth.ErrAuth) {
			return sessions.LaunchOutcome{}, fmt.Errorf("%w: %v", sessions.ErrLaunchRefused, err)
		}
		return sessions.LaunchOutcome{}, err
	}
	return sessions.LaunchOutcome{
		PrincipalID: authz.Principal.ID,
		Subject:     authz.Claim.Subject,
		Org:         authz.Claim.Org,
		Linked:      true,
	}, nil
}

// principalRolesFrom maps the spine's string roles onto the store's PrincipalRole
// vocabulary. An unknown role string is carried through verbatim (as a PrincipalRole);
// the auth resolver's validate() refuses an out-of-vocabulary role fail-closed, so an
// invalid role becomes an attributable launch refusal rather than a silent drop.
func principalRolesFrom(roles []string) []store.PrincipalRole {
	if len(roles) == 0 {
		return nil
	}
	out := make([]store.PrincipalRole, 0, len(roles))
	for _, r := range roles {
		out = append(out, store.PrincipalRole(r))
	}
	return out
}

// envConfigReader is the §4.1 step-1 second-key read (D56): GetEnvConfig. It is the
// store shape CheckTwoKeyActivation consumes; declared narrow here so the adapter
// depends only on the one method (the ControlPlaneStore satisfies it).
type envConfigReader interface {
	GetEnvConfig(ctx context.Context, ref string) (store.EnvConfig, error)
}

// twoKeyAdapter wraps the §4.1 step-1 CheckTwoKeyActivation function onto the
// coordinator's TwoKeyChecker seam (sessioncreate.go). It holds the enrollment resolver
// (the first key) and the env-config reader (the second key — the same store value).
type twoKeyAdapter struct {
	enroll sessions.EnrollmentResolver
	envs   envConfigReader
}

func (a twoKeyAdapter) Check(ctx context.Context, req sessions.TwoKeyRequest) (sessions.TwoKeyResult, error) {
	return sessions.CheckTwoKeyActivation(ctx, a.enroll, a.envs, req)
}

// policyHeadSeqSource satisfies scheduler.PolicySeqSource by reading the policy_log
// HEAD (the additive store.PolicyHead query) per placement — the current swept policy
// version the D72 staleness filter measures each host's applied_seq against.
type policyHeadSeqSource struct{ store store.PolicyHeadSource }

func (s policyHeadSeqSource) CurrentPolicySeq(ctx context.Context) (uint64, error) {
	return store.PolicyHead(ctx, s.store)
}

// unrestrictedTenancy is the open/shared-pool TenancyScopeSource: an empty scope (no
// pool restriction, no cross-tenant guard). It is the default when no tenancy source
// is wired — every reporting host is a candidate (the single-tenant isolation guard
// needs an explicit pool/tenancy to activate, D19).
type unrestrictedTenancy struct{}

func (unrestrictedTenancy) ScopeFor(_ context.Context, _ string) (store.CandidateScope, error) {
	return store.CandidateScope{}, nil
}

// registrySuspender satisfies sessions.Suspender (the WORKING→SUSPENDED host verb) over
// the per-host DriverClient.Suspend — the SAME driver face the create coordinator and the
// reconciler's quarantine Suspend drive (seams.go). The ParkResumeDriver names the placed
// host (rec.Ref.HostID) per Suspend, so this resolves THAT host's driver directly (never a
// fleet broadcast — the record carries the host). It is the default Suspender so the
// production wiring needs no extra backend beyond the driver registry already wired. The
// recs lookup is unused for the host-keyed Suspend path but kept for symmetry with the
// reconciler's registryDriver; the host comes from the request the driver passes.
type registrySuspender struct {
	reg  DriverRegistry
	recs sessionHostLookup
}

// Suspend resolves the named host's driver and drives the frozen hypervisor.v1 Suspend
// verb (idempotent on session_uuid). The ParkResumeDriver passes the placed host id
// (rec.Ref.HostID) so the verb targets exactly that host — never a broadcast.
func (s registrySuspender) Suspend(ctx context.Context, hostID string, req *hypervisorv1.SuspendRequest) error {
	drv, err := s.reg.DriverFor(ctx, hostID)
	if err != nil {
		return fmt.Errorf("controlplane: suspend on %s: %w", hostID, err)
	}
	if _, err := drv.Suspend(ctx, req); err != nil {
		return fmt.Errorf("controlplane: Suspend verb on %s: %w", hostID, err)
	}
	return nil
}

// Compile-time proof the registry-backed adapter satisfies the sessions suspend seam.
var _ sessions.Suspender = registrySuspender{}

// dropSuspendCoordEmitter is the gate-off in-process DROP sink for the D110 SuspendCoord
// coordination (the no-boundary-channel posture, D50): it accepts and discards each
// SessionLifecycleUpdate. It lets NewControlPlane construct a usable SuspendCoordinator in
// a non-live run (no real host-local channel) WITHOUT the coordination signal escaping the
// process — the real host-local channel is wired only behind DS_ORCH_LIVE (main.go). It
// never errors (a drop cannot fail), so a non-live coordination call is a clean no-op.
type dropSuspendCoordEmitter struct{}

func (dropSuspendCoordEmitter) EmitSuspendCoord(_ context.Context, _ *hostagentv1.SessionLifecycleUpdate) error {
	return nil
}

// Compile-time proof the drop sink satisfies the host-ward emit seam.
var _ SuspendCoordEmitter = dropSuspendCoordEmitter{}

// ---------------------------------------------------------------------------
// mintExpiryScheduler — the production §4.1 step-5 minted-credential EXPIRY
// teardown/re-mint sink (D22/D82, doc 16 §5.4), wired behind the create
// coordinator's CreateSeams.OnMintExpiry.
// ---------------------------------------------------------------------------

// mintExpiryStore is the NARROW persistence seam the scheduler depends on: read the
// session record (to re-read the PERSISTED §5.6 MintExpiry horizon + the current §3
// state) and advance it (write the re-minted identity/CA + the fresh horizon). It is a
// slice of the ControlPlaneStore surface — *store.Memory / *store.Postgres satisfy it
// natively, and tests wire a synthetic fake — so the scheduler adds NO method to any
// store interface (the storeseams discipline).
type mintExpiryStore interface {
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
	UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error)
}

// mintExpiryReMintBudget bounds the per-fire re-mint work (the resolve + mint + persist
// round trip) so a wedged identity service cannot pin a scheduler goroutine forever. It
// is the re-mint hot path's own deadline — independent of (and never blocking) the
// create path, which already committed READY before the timer was even armed.
const mintExpiryReMintBudget = 30 * time.Second

// mintExpiryScheduler is the REAL TTL-driven teardown/re-mint scheduler. It satisfies
// sessions.MintExpirySink: the create coordinator hands it a session UUID + the
// minted-credential expiry horizon ONCE the session is durably READY (past every create
// rollback point), and the scheduler arms a per-session timer that, on the horizon,
// re-mints the credential (an expired credential re-mints on resume — doc 16 §5.4).
//
// THE THREE LOAD-BEARING CONTRACTS:
//
//   - NON-BLOCKING on the create hot path. OnMintExpiry only computes a delay, swaps a
//     timer into a UUID-keyed map under a short mutex, and returns. The re-mint work runs
//     LATER on the timer's own goroutine (time.AfterFunc) with its own deadline budget, so
//     a slow or fault-prone identity service NEVER slows a create (the create already
//     committed READY; the sink is fire-and-forget bookkeeping).
//
//   - IDEMPOTENT across a post-step-5 create rollback (the destroy supersedes the
//     registration keyed on session UUID — NO leaked timer). The coordinator already fires
//     OnMintExpiry only for a durably-READY session, so a minted-then-rolled-back session
//     never registers. As defense in depth the FIRE path re-reads the persisted record and
//     DROPS on a terminal/DESTROYED session (a session torn down between arm and fire): the
//     destroy supersedes the registration, the timer self-cancels on fire, and no spurious
//     re-mint runs for a session that no longer exists. Re-arming for the same UUID swaps
//     (and stops) the prior timer, so a re-mint that lands a NEW horizon never leaves the
//     old timer pending — at most one armed timer per live session.
//
//   - READS THE PERSISTED HORIZON (doc 16 §5.4). On fire the scheduler re-reads
//     GetSession(...).MintExpiry — the DURABLE §5.6 column (migration 0010), not the
//     arm-time value — so a horizon a re-mint (or a park/resume re-mint elsewhere) moved
//     forward is honored: if the persisted horizon is now LATER than the fired one, the
//     credential was already refreshed and the scheduler simply re-arms to the new horizon
//     rather than re-minting again. This makes the durable record the system of record and
//     the in-process timer merely its scheduler.
type mintExpiryScheduler struct {
	store    mintExpiryStore
	mint     MintClient
	resolver launchingUserResolver
	now      func() time.Time
	logger   *slog.Logger

	mu      sync.Mutex
	timers  map[string]*time.Timer // session UUID → armed teardown/re-mint timer
	stopped bool
}

// launchingUserResolver names the sessions step-5 launching_user resolver seam the
// re-mint claims are assembled through (sessions.ResolveMintClaims). It is an alias of
// the same shape spineSeams.Resolver carries, declared here so the scheduler field is
// typed without importing an unexported sessions type by name.
type launchingUserResolver interface {
	ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error)
}

// newMintExpiryScheduler constructs the production sink over the single backing store,
// the production mint seam, and the step-5 launching_user resolver. clock nil → time.Now;
// logger nil → slog.Default.
func newMintExpiryScheduler(s mintExpiryStore, mint MintClient, resolver launchingUserResolver, clock func() time.Time, logger *slog.Logger) *mintExpiryScheduler {
	if clock == nil {
		clock = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &mintExpiryScheduler{
		store:    s,
		mint:     mint,
		resolver: resolver,
		now:      clock,
		logger:   logger,
		timers:   make(map[string]*time.Timer),
	}
}

// OnMintExpiry arms (or re-arms) the per-session teardown/re-mint timer for sessionUUID
// at the minted-credential horizon. It is the sessions.MintExpirySink fire point — called
// once per create after the session is durably READY (the coordinator's idempotency
// contract) — and is NON-BLOCKING: it computes the delay, swaps the timer under a short
// mutex, and returns immediately. A zero expiry never reaches here (the coordinator's
// no-track guard). A horizon already in the past arms a zero/near-zero delay so the
// re-mint fires promptly (an already-expired credential re-mints on the next tick). After
// Stop the sink is inert (a late fire from a coordinator racing shutdown is dropped).
func (s *mintExpiryScheduler) OnMintExpiry(sessionUUID string, expiry time.Time) {
	if sessionUUID == "" || expiry.IsZero() {
		return
	}
	delay := expiry.Sub(s.now())
	if delay < 0 {
		delay = 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	// Supersede any prior timer for this UUID so a re-arm never leaves two pending (at
	// most one armed timer per live session — the no-leaked-timer contract).
	if prev, ok := s.timers[sessionUUID]; ok {
		prev.Stop()
	}
	s.timers[sessionUUID] = time.AfterFunc(delay, func() { s.fire(sessionUUID, expiry) })
}

// fire is the timer callback (its own goroutine): re-read the PERSISTED horizon, drop
// idempotently for a torn-down session, and otherwise re-mint. It clears the UUID's timer
// slot first (the timer is one-shot; the slot is freed so a later OnMintExpiry can re-arm).
func (s *mintExpiryScheduler) fire(sessionUUID string, firedHorizon time.Time) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	delete(s.timers, sessionUUID)
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), mintExpiryReMintBudget)
	defer cancel()

	rec, err := s.store.GetSession(ctx, sessionUUID)
	if err != nil {
		// A missing record (destroyed-and-pruned, or never persisted) supersedes the
		// registration — nothing to re-mint. Any other read fault is logged; the timer is
		// not re-armed (the reconciler is the backstop for a live session whose record read
		// transiently failed).
		if errors.Is(err, store.ErrNotFound) {
			return
		}
		s.logger.Warn("controlplane: mint-expiry sink: record read failed — dropping re-mint (reconciler backstop)",
			slog.String("session", sessionUUID), slog.Any("err", err))
		return
	}

	// IDEMPOTENT DROP: a session torn down (or MID-TEARDOWN) between arm and fire — the
	// destroy supersedes the registration keyed on session UUID — re-mints nothing: no
	// leaked re-mint, and no identity CHURN during teardown. The drop covers BOTH the
	// terminal DESTROYED state (the §4.2 step-5 rollback already revoked the identity/CA)
	// AND the DESTROYING mid-teardown state — a session whose teardown is in flight must not
	// have its credential re-minted out from under the destroy choreography (doc 16 §5.4).
	if rec.State == store.SessionDestroying || rec.State.IsTerminal() {
		s.logger.Debug("controlplane: mint-expiry sink: session destroying/terminal — re-mint superseded by destroy",
			slog.String("session", sessionUUID), slog.String("state", string(rec.State)))
		return
	}

	// READ THE PERSISTED HORIZON (doc 16 §5.4). If the durable horizon moved FORWARD past
	// the one this timer fired for, the credential was already refreshed (a prior re-mint
	// here, or a park/resume re-mint) — re-arm to the new horizon instead of re-minting.
	// A persisted horizon that has gone to the not-set zero value means the record no
	// longer tracks a TTL (e.g. a re-mint with no expiry) — drop.
	persisted := rec.MintExpiry
	if persisted.IsZero() {
		return
	}
	if persisted.After(firedHorizon) {
		s.OnMintExpiry(sessionUUID, persisted)
		return
	}

	// RE-MINT (an expired credential re-mints on resume, doc 16 §5.4). Re-assemble the
	// step-5 launching_user claims through the SAME resolver the create spine uses and
	// re-mint through the production mint seam (mintReply lifts the FRESH expiry off the
	// typed reply). The role_ref rides the pinned triple on the record (rec.RolePin.Name).
	claims, err := sessions.ResolveMintClaims(ctx, s.resolver, sessionUUID)
	if err != nil {
		s.logger.Warn("controlplane: mint-expiry sink: re-mint claims resolve failed (reconciler backstop)",
			slog.String("session", sessionUUID), slog.Any("err", err))
		return
	}
	reply, err := mintReply(ctx, s.mint, claims, rec.RolePin.Name)
	if err != nil {
		s.logger.Warn("controlplane: mint-expiry sink: re-mint failed (reconciler backstop)",
			slog.String("session", sessionUUID), slog.Any("err", err))
		return
	}

	// Persist the re-minted identity/CA + the FRESH horizon onto the durable record — the
	// same UpdateSession the §4.1 step-5 / §4.2 resume re-mint writes (IdentityRef/CARef +
	// the MintExpiry column, migration 0010). The new horizon becomes the record's system
	// of record; we then re-arm to it so the credential is kept fresh across its lifetime.
	if _, err := s.store.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		IdentityRef: &reply.IdentityRef,
		CARef:       &reply.CARef,
		MintExpiry:  &reply.Expiry,
	}); err != nil {
		s.logger.Warn("controlplane: mint-expiry sink: persist re-minted horizon failed (reconciler backstop)",
			slog.String("session", sessionUUID), slog.Any("err", err))
		return
	}
	s.logger.Info("controlplane: mint-expiry sink: re-minted expired credential (doc 16 §5.4)",
		slog.String("session", sessionUUID), slog.Time("new_horizon", reply.Expiry))

	// Keep the credential fresh: re-arm for the new horizon when the re-mint surfaced one
	// (a re-mint that surfaced no TTL leaves the record's not-set posture — no further timer).
	if !reply.Expiry.IsZero() {
		s.OnMintExpiry(sessionUUID, reply.Expiry)
	}
}

// Stop halts the scheduler: every armed timer is stopped and the sink goes inert (further
// OnMintExpiry calls are dropped). main.go calls it on control-plane shutdown so no
// teardown/re-mint goroutine outlives the process. It is idempotent.
func (s *mintExpiryScheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return
	}
	s.stopped = true
	for uuid, t := range s.timers {
		t.Stop()
		delete(s.timers, uuid)
	}
}

// armedCount reports how many session timers are currently armed. It exists so the wiring
// test can assert the production sink armed (and superseded) timers without reaching into
// the unexported map directly.
func (s *mintExpiryScheduler) armedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.timers)
}

// Compile-time proof the scheduler is the real sink the create coordinator drives.
var _ sessions.MintExpirySink = (*mintExpiryScheduler)(nil)
