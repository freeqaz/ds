package controlplane

// sessionservice.go is the orchestrator.v1 SessionService server's CreateSession
// handler (doc 15 §5.3: "runs §4.1; two-key structural refusal (D56)") — leg (a) of
// the control-plane capstone. It embeds the frozen UnimplementedSessionServiceServer
// (so the other RPCs stay unimplemented until their wiring tasks land) and implements
// CreateSession by building a sessions.CreateRequest from the frozen
// CreateSessionRequest (role_ref → the §4.1 ten-step coordinator) and mapping the
// coordinator's result / failure onto the frozen Session response + gRPC status.
//
// THE PROTO PRECONDITION IS SATISFIED (the task's pin). The M0 orchestrator.v1
// freeze landed with CreateSessionRequest.role_ref INCLUDED (D95/D106), so this
// handler is buildable now: it resolves role_ref against the catalog and pins it
// through the coordinator's steps-1–2, exactly the doc 15 §4.1 step-5 deferral the
// orch15/16 coherence mechanism was landed for. NO proto edit, NO proto regeneration
// — the handler is built against the FROZEN generated server interface + messages.
//
// ERROR MAPPING (frozen status/Suspend semantics). The coordinator returns a typed
// *sessions.CreateError naming the §4.1 step that failed and whether the compensating
// rollback completed cleanly. The handler maps it onto gRPC status codes by the failure
// CLASS (the create-refusal sentinels → the precondition/permission/argument codes; a
// seam/store fault → Unavailable/Internal), so a client tells a structural refusal (its
// own bad request) from a transient stall (retry) — never a bare opaque error.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/attach"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/createtiming"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/sessions"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// SessionService is the orchestrator.v1 SessionService server. It drives the §4.1
// ten-step create coordinator (sessions.SessionCreator) on CreateSession and leaves
// the other RPCs to the embedded UnimplementedSessionServiceServer (their wiring is
// out of this capstone's scope). Construct with newSessionService (via NewControlPlane).
type SessionService struct {
	orchestratorv1.UnimplementedSessionServiceServer

	creator *sessions.SessionCreator
	// fastStarter is the M2 golden-image instant-start fast path (sessions.FastStarter)
	// over the SAME creator: CreateSession drives the create THROUGH it so a create resolves
	// the pre-baked golden image (the §7 image-cache-locality lever) and records the §8
	// create→attach timing decomposition into the shared trend Recorder — MEASURE, NOT GATE
	// (D81/D32: the fast path adds resolution + measurement, never a budget; the create
	// reaches ATTACHED regardless of the span). Constructed in NewControlPlane (step 11) over
	// the GoldenImageResolver injected via Deps and handed here so the handler and the
	// control plane's CreateTimingTrend read one Recorder. Required (NewControlPlane always
	// builds it); a nil fast starter falls back to the raw creator (a test-narrowed handler).
	fastStarter *sessions.FastStarter
	envs        envConfigReader
	clock       func() time.Time
	logger      *slog.Logger

	// defaultOrg is the v0 single-org deployment's org (doc 15 §5.3 / doc 16 §3.2): the
	// frozen orchestrator.v1 CreateSessionRequest carries the launching_user SUBJECT but
	// NOT its org (the org rides the IdP claim the M2 multi-org product band threads
	// structurally). At v0 the deployment is single-org, so the org is a configured
	// constant the launch gate keys the principal upsert on (subject, org). Empty =
	// unset (a create then refuses at the gate unless the principal was pre-enrolled
	// with an empty org — never in practice).
	defaultOrg string

	// newSessionUUID mints a session UUID for a create (the retry key + join key). It
	// is a seam so tests get deterministic UUIDs; nil uses a time-based default.
	newSessionUUID func() string

	// fanout is the D18 WatchSession terminator (attach.Fanout, doc 15 §5.3): the
	// per-session subscriber set the one WRITER + N READERs join, seq-stamped + ring-backed
	// (watch.go). The WatchSession handler Subscribes to it; the host-agent relay
	// (attachrelay.go) Publishes host-ward state edges into it. Nil = the attach legs are
	// NOT being served (a test-narrowed handler or a deployment without the fan-out wired):
	// WatchSession then refuses Unavailable rather than serving an empty stream. Installed
	// via SetAttachServing (by NewControlPlane).
	fanout *attach.Fanout

	// issuer is the D79 attach-handle issuer (attach.Issuer, doc 15 §5.4): it runs the D61
	// seat arbitration (one-writer/N-reader, server-side) and mints the transport-ambivalent
	// attach.v1.AttachHandle (endpoint candidate + short-lived session-scoped auth + the
	// granted Role + expiry). The Attach handler drives it. Nil = the attach legs are NOT
	// being served: Attach then refuses Unavailable. Installed via SetAttachServing.
	issuer *attach.Issuer

	// destroyer is the §4.2 reconciler-driven teardown seam DestroySession drives (doc 15
	// §4.2): the SAME sessions.HostDestroyer the create coordinator's compensating rollback
	// uses (the in-process inProcessHostDestroyer in the orchestrator-lite single-binary
	// posture, the remote hostDestroyer{reg} in the fleet posture). DestroySession flips the
	// record to desired=DESTROYED, drives this seam for the host-owned §4.2 ordering, then
	// finalizes the record to DESTROYED. Nil = the destroy leg is NOT being served (a
	// test-narrowed handler): DestroySession then refuses Unavailable rather than half-tearing
	// a session down. Installed via SetDestroyServing (by NewControlPlane).
	destroyer sessions.HostDestroyer
	// destroyRecords is the §5.6 session-record store DestroySession reads the desired/observed
	// state from and writes the DESTROYING→DESTROYED lifecycle transition to (doc 15 §5.6;
	// D35/D72). Installed alongside destroyer via SetDestroyServing.
	destroyRecords destroySessionStore

	// listRecords is the §5.6 session-record store ListSessions enumerates (doc 15 §5.3: the
	// fleet/console read). It is the SAME single backing store the destroy leg flips lifecycle
	// state on — the full ControlPlaneStore (which carries store.ListSessions) is handed to
	// SetDestroyServing as the destroyRecords value, so the list leg is installed there by a
	// type-assertion (the production store satisfies the lister; a test-narrowed store that does
	// not leaves listRecords nil and ListSessions refuses Unavailable, the same clean degrade the
	// other read legs use). No second wiring callsite and no second store interface on Deps — the
	// list read rides the one coherent store the whole control plane is cut from. Nil = the list
	// leg is NOT being served.
	listRecords listSessionStore

	// launchingUserResolver is the OPTIONAL §3.1 launching-user attribution resolver the
	// ListSessions launching_user filter narrows by (doc 16 §3.1/§3.2). The frozen
	// ListSessionsRequest carries a launching_user filter field, but the §5.6 session RECORD
	// does NOT carry the launching_user on its wire face (it is resolved at the IdP boundary
	// through the session→principal link, not stored on the record — sessionToProto leaves the
	// wire field empty by the same rule). So a launching_user-scoped list cannot be answered
	// from the record slice alone; it resolves each candidate's launching-user value through
	// this seam and keeps only the exact matches. The production store satisfies it natively via
	// ResolveLaunchingUserClaim (the SAME resolver the mint surface uses), so no field is added
	// to any store interface. Nil = the launching-user resolver is NOT wired: a launching_user
	// filter then refuses Unavailable (the clean degrade the other unserved read legs use — never
	// silently returning the unfiltered fleet, which would leak other principals' sessions). An
	// empty launching_user filter is unaffected (the resolver is never consulted — fleet-wide).
	// Installed via SetLaunchingUserResolver (by NewControlPlane, off the same backing store).
	launchingUserResolver listLaunchingUserResolverFunc

	// subtokens is the D18 fan-out sub-token injector (subtoken.go, doc 23 §5): after a
	// CreateSession fans out a VM, it derives ONE narrowed agent sub-token for that VM via
	// the frozen dreamserpent.auth.v1 TokenAttenuationService.DeriveAgentToken and mounts it
	// at the documented well-known in-VM path (the agent reads it locally, never over the
	// network — doc 23 §5). Nil = the fan-out sub-token seam is NOT wired (a test-narrowed
	// handler / a deployment without the auth SDK reachable): CreateSession then fans out no
	// sub-token and is otherwise unaffected (additive). Installed via SetSubTokenServing.
	subtokens *subTokenInjector
	// subTokenAuthority resolves the launching principal's PARENT authority for the fan-out
	// derive (doc 23 §5): the D125 parent user auth token to attenuate from and the
	// requested-scope SUBSET of the parent ds_scopes the agent is granted (§5 rule 1 — scope
	// can only narrow). The frozen orchestrator.v1 CreateSessionRequest carries the
	// launching_user SUBJECT but NOT the parent token / scopes (those ride the IdP claim the
	// M2 multi-org band threads structurally, doc 16 §3.2), so the authority is resolved
	// through this seam from the create request rather than echoed on the wire. Nil = no
	// authority resolvable → the injector skips the derive (nothing to attenuate). Installed
	// alongside the injector via SetSubTokenServing.
	subTokenAuthority subTokenAuthorityFunc

	// createTiming is the FLAG-GATED D81 §8 create→attach timing fold sink (createtiming-feed):
	// the reconcile loop's RecordCreateTiming / CreateTimingServerSpanTrend surface
	// (reconcileloop.go), reached here through the narrow createTimingSink seam so the create
	// path hands each golden-image create's MEASURED §8 stack decomposition (RTT excluded) into
	// the SAME trend recorder the (b)-row instrument reads. It is a live producer ONLY when the
	// deployment opts in (DS_ORCH_CREATETIMING_WIRE=1) AND the sink is wired; with the flag off
	// (the default) runCreate folds nothing and the create path is byte-for-byte unchanged, and
	// the recorder itself no-ops the fold (the loop's wire self-armed from the SAME flag). Nil =
	// the fold leg is NOT wired (the create records no timing; CreateTimingServerSpanTrend is an
	// empty trend) — the clean degrade a test-narrowed handler / a deployment that does not serve
	// the observability leg takes. Installed via SetCreateTimingServing. The production wiring
	// call-site (SetCreateTimingServing(cp.Reconcile) in NewControlPlane) is the deferred
	// one-liner outside this unit's owned files; the fold + read surface + the flag gate land here.
	createTiming createTimingSink

	// meteringRecords is the D57 metering-event READ leg (createtiming-feed): the store's
	// ListMeteringEvents projection, exposed on the admin/observability read surface so the
	// (b)/(d)-rig instruments consume the idempotent billing-transition + D37-sample stream the
	// metering-wire records. It is installed off the SAME single backing store the destroy/list
	// legs receive (a type-assertion in SetDestroyServing — *store.Memory / *store.Postgres
	// satisfy ListMeteringEvents natively, so no field is added to any store interface and no
	// second wiring call-site is needed). Nil = the metering read leg is NOT served (a
	// test-narrowed store that does not enumerate metering events): ListMeteringEvents refuses
	// Unavailable — the clean degrade the other read legs use.
	meteringRecords meteringReader

	// sessionRecords is the OPTIONAL §4/§4.1 host-local session-record PRODUCER (liveedges.go's
	// fileSessionRecordProducer, doc 14 §4.1): on a successful create it DROPS the
	// (session_uuid, host_id) record keyed on the interface-anchored tap name the coordinator
	// bound post-CloneFromImageResponse, and on teardown it REMOVEs that drop — the WRITE side
	// of the on-disk contract ds-tlsproxy's LiveSessionRecordClient reads (armed under
	// DS_SESSION_JOIN_LIVE) to resolve the M0-host egress JOIN. Nil = the live join seam is NOT
	// wired (the default, and every non-live / test-narrowed handler): CreateSession /
	// DestroySession then drop / remove NOTHING and are byte-for-byte their prior behavior, so
	// an unarmed proxy simply MISSes the join and degrades to AddressDerived attribution (safe).
	// Installed via AttachSessionRecordStore — the DEFERRED cmd-side call main.go makes under
	// DS_SESSION_JOIN_LIVE with the host's OverlayDir (the SAME base the ds-tlsproxy reader
	// points DS_TLSPROXY_SESSION_RECORD_DIR at), mirroring IdentityClients.AttachCABundleStore.
	// The write/remove are best-effort side effects: a fault is logged and swallowed (the
	// session is already created / torn down — a host-local drop error never fails the RPC or
	// strands a teardown; the join degrades to AddressDerived, D50 safe-degrade).
	sessionRecords sessionRecordProducer

	// postureResolver is the OPTIONAL POL-1 per-session permission-posture resolver seam
	// (doc 09 / doc 13 §2): it maps the resolved role/env posture onto the runtime.v1
	// PermissionPosture enum the create forwards as DATA into sessions.CreateRequest.Posture
	// (-> the step-4 VmSpec.posture -> the gap-1 EntrypointConfig producer). The POL-1
	// resolution itself does NOT exist yet — this seam IS the activation point; a real
	// resolver lands behind it (it is NOT a policy engine here). CreateSession SEEDS the
	// posture from the request's own posture field (the orchestrator-forwarded value) and a
	// wired resolver WINS when it yields a CONCRETE posture (resolver-wins). Nil (the default,
	// every test-narrowed handler and the current production wiring) or a resolver that yields
	// PERMISSION_POSTURE_UNSPECIFIED leaves the seed untouched — so absent resolution is
	// BYTE-IDENTICAL to today (the frozen request carries no posture -> UNSPECIFIED ->
	// daemon-pinned LOCKED fallback at the producer, M0 default-deny preserved). Installed via
	// SetPostureResolver.
	postureResolver PostureResolver
}

// PostureResolver resolves the per-session runtime permission posture (POL-1, doc 09 / doc 13
// §2) for a create, mapping the resolved role/env posture onto the runtime.v1 PermissionPosture
// enum. It is consulted at CreateSession AFTER the request's own posture is read as the seed:
// a CONCRETE result WINS (resolver-wins), a PERMISSION_POSTURE_UNSPECIFIED result means "no
// opinion" and leaves the seed. The resolver stays runtime-external — it returns DATA the
// orchestrator forwards; it decides nothing about HOW the guest enforces the posture.
type PostureResolver interface {
	// ResolvePosture returns the per-session posture for req, or
	// PERMISSION_POSTURE_UNSPECIFIED to defer to the request-seeded value (no opinion).
	ResolvePosture(ctx context.Context, req *orchestratorv1.CreateSessionRequest) runtimev1.PermissionPosture
}

// sessionRecordProducer is the narrow WRITE seam CreateSession/DestroySession drive to
// maintain the doc 14 §4.1 host-local session-record drop (the tap-keyed (session_uuid,
// host_id) record ds-tlsproxy's live M0-host JOIN reader resolves). The production
// *fileSessionRecordProducer (liveedges.go) satisfies it natively (its write/remove method
// set is exactly this), so the live wiring installs that producer and a test installs a fake
// that records the calls — no new concrete type, no store-interface change. write drops the
// record on the create bind; remove deletes it on teardown (idempotent).
type sessionRecordProducer interface {
	write(tapName, sessionUUID, hostID string) error
	remove(tapName string) error
}

// createTimingSink is the narrow D81 create-timing fold + read seam the observability leg needs
// (createtiming-feed): fold one create's MEASURED §8 stack decomposition into the shared trend
// recorder (RecordCreateTiming, client RTT excluded from the server span) and read the recorded
// trigger-eligible server-span trend across every folded create (CreateTimingServerSpanTrend).
// The reconcile loop (*reconcileLoop) satisfies it natively (reconcileloop.go), so the fold lands
// on the SAME recorder the (b)-row instrument reads — no second recorder, no Deps field.
type createTimingSink interface {
	RecordCreateTiming(sessionUUID string, stack map[createtiming.Segment]time.Duration, clientRTT time.Duration) (createtiming.Trend, []createtiming.Segment, error)
	CreateTimingServerSpanTrend() createtiming.Trend
}

// meteringReader is the narrow D57 metering-event read seam the admin/observability surface needs:
// the store's ListMeteringEvents projection for a session (the idempotent event stream the
// metering-wire records). The single ControlPlaneStore satisfies it natively (*store.Memory /
// *store.Postgres carry ListMeteringEvents), so the read leg is installed off the SAME store value
// the destroy/list legs already receive — no method added to any store interface, no Deps field.
type meteringReader interface {
	ListMeteringEvents(ctx context.Context, sessionUUID string) ([]store.MeteringEvent, error)
}

// subTokenAuthorityFunc resolves the parent authority for the D18 fan-out derive from a
// create request (doc 23 §5): the parent user auth token to attenuate from, the
// requested-scope SUBSET of the parent ds_scopes (§5 rule 1 — narrow only), and an
// optional sub-token lifetime override (§5 rule 3 — exp ≤ parent exp; zero = parent
// remaining). An empty parentUserAuthToken means no parent authority is resolvable (the
// unauthenticated launch / a deployment that mints no user auth token), and the injector
// skips the derive. It is a seam so the parent token + scope subset are sourced from the
// IdP boundary the request threads (doc 16 §3.2) without widening the frozen
// CreateSessionRequest wire message.
type subTokenAuthorityFunc func(ctx context.Context, req *orchestratorv1.CreateSessionRequest) (parentUserAuthToken string, requestedScopes []string, lifetimeSeconds int32)

// destroySessionStore is the narrow record-store seam DestroySession needs: read the
// §5.6 record (to resolve the host the teardown targets + reject an unknown session)
// and write the lifecycle transition (DESTROYING when the teardown starts, DESTROYED +
// DestroyedAt when it finishes — the record is RETAINED, never deleted, D66). The single
// ControlPlaneStore satisfies it natively (GetSession + UpdateSession), so the handler
// adds no method to any store interface.
type destroySessionStore interface {
	GetSession(ctx context.Context, sessionUUID string) (store.Session, error)
	UpdateSession(ctx context.Context, sessionUUID string, u store.SessionUpdate) (store.Session, error)
}

// listSessionStore is the narrow record-store seam ListSessions needs: enumerate the §5.6
// records (doc 15 §5.3, the fleet/console read), newest-first, filtered by host and
// destroyed-inclusion. The single ControlPlaneStore satisfies it natively (store.ListSessions
// is already on *store.Memory / *store.Postgres), so the handler adds no method to any store
// interface and no field to Deps — the list leg is installed off the SAME store value the
// destroy leg already receives.
type listSessionStore interface {
	ListSessions(ctx context.Context, f store.SessionFilter) ([]store.Session, error)
}

// listLaunchingUserResolverFunc resolves a session's launching-user attribution VALUE (the §3.1
// `launching_user` claim — the launching principal's IdP subject) so the ListSessions
// launching_user filter can narrow by it without the record carrying the claim on its wire
// face (doc 16 §3.1/§3.2). It returns:
//   - (subject, true, nil): the session has a launching principal; subject is the claim value;
//   - ("", false, nil):     the session exists but has NO launching principal (the nullable
//     pre-mint / system-session case) — it never matches a non-empty launching_user filter;
//   - ("", false, err):     a resolve fault (the session is unknown to the resolver, or its
//     link dangles) — the handler treats a resolve fault as "not a match" rather than failing
//     the whole list (a single dangling link does not poison the console read).
//
// The production store satisfies it natively via ResolveLaunchingUserClaim, so the resolver is
// installed off the SAME backing store value (no second store interface, no Deps field).
type listLaunchingUserResolverFunc func(ctx context.Context, sessionUUID string) (subject string, ok bool, err error)

// newSessionService builds the SessionService over the constructed coordinator and the
// env-config reader (used to resolve the content-addressed image + entrypoint the
// create materializes from the checked-in env spec, doc 15 §9 — the orchestrator stays
// runtime-ignorant, it only joins the resolved refs).
func newSessionService(creator *sessions.SessionCreator, fastStarter *sessions.FastStarter, envs envConfigReader, defaultOrg string, clock func() time.Time, logger *slog.Logger) *SessionService {
	if clock == nil {
		clock = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &SessionService{creator: creator, fastStarter: fastStarter, envs: envs, defaultOrg: defaultOrg, clock: clock, logger: logger}
}

// SetSessionUUIDGen installs a deterministic session-UUID generator (test seam). The
// production default mints a time-based UUID per create.
func (s *SessionService) SetSessionUUIDGen(gen func() string) { s.newSessionUUID = gen }

// SetAttachServing installs the D18/D61/D79 attach-serving legs onto the handler: the
// WatchSession fan-out terminator (attach.Fanout) the WatchSession stream Subscribes to,
// and the attach-handle issuer (attach.Issuer) the Attach RPC drives. NewControlPlane
// wires both over the single backing store + the production endpoint resolver; a
// test-narrowed handler that leaves them unset has WatchSession / Attach refuse Unavailable
// (a deployment that does not serve the attach legs is a clean degrade, never a half-served
// stream). It is additive — CreateSession is unaffected whether or not the attach legs are
// installed.
func (s *SessionService) SetAttachServing(fanout *attach.Fanout, issuer *attach.Issuer) {
	s.fanout = fanout
	s.issuer = issuer
}

// SetDestroyServing installs the §4.2 destroy leg onto the handler: the
// sessions.HostDestroyer the DestroySession RPC drives (the host-owned §4.2 teardown
// ordering) and the §5.6 record store it flips desired=DESTROYED / DESTROYED on.
// NewControlPlane wires the SAME HostDestroyer the create coordinator's compensating
// rollback uses (the in-process adapter in orchestrator-lite, the remote driver in the
// fleet) over the SAME single backing store; a test-narrowed handler that leaves the
// destroyer unset has DestroySession refuse Unavailable (a deployment that does not serve
// the destroy leg is a clean degrade, never a half-torn-down session). It is additive —
// CreateSession / Attach / WatchSession are unaffected whether or not the destroy leg is
// installed.
func (s *SessionService) SetDestroyServing(destroyer sessions.HostDestroyer, recs destroySessionStore) {
	s.destroyer = destroyer
	s.destroyRecords = recs
	// Install the §5.3 list-read leg off the SAME store value: NewControlPlane hands the full
	// ControlPlaneStore here (it carries store.ListSessions), so the public ListSessions surface
	// becomes served without a second wiring callsite or a second Deps field. A store that does
	// not enumerate (a test-narrowed destroyRecords with only Get/Update) leaves listRecords nil
	// and ListSessions refuses Unavailable — the same clean degrade the other read legs use.
	if lister, ok := recs.(listSessionStore); ok {
		s.listRecords = lister
	}
	// Install the D57 metering-event read leg off the SAME store value (createtiming-feed): the
	// production ControlPlaneStore (*store.Memory / *store.Postgres) carries ListMeteringEvents,
	// so the admin/observability read surface becomes served without a second wiring call-site.
	// A store that does not enumerate metering events leaves meteringRecords nil and
	// ListMeteringEvents refuses Unavailable — the same clean degrade the other read legs use.
	if mr, ok := recs.(meteringReader); ok {
		s.meteringRecords = mr
	}
}

// SetCreateTimingServing installs the D81 create-timing fold + read leg onto the handler
// (createtiming-feed): the createTimingSink the create path folds each golden-image create's
// MEASURED §8 stack decomposition into (RecordCreateTiming, client RTT excluded) and the
// admin/observability surface reads the recorded server-span trend from
// (CreateTimingServerSpanTrend). NewControlPlane wires the reconcile loop (*reconcileLoop) here so
// the fold lands on the SAME trend recorder the (b)-row instrument reads. It is additive and
// DEFAULT-OFF: the fold happens only under DS_ORCH_CREATETIMING_WIRE=1 (the loop's wire self-armed
// from the SAME flag no-ops the fold otherwise), so a create is byte-for-byte unchanged with the
// flag unset whether or not the sink is installed. Nil leaves the fold unwired (the create records
// no timing and CreateTimingServerSpanTrend is an empty trend). It is additive — the other RPCs are
// unaffected.
func (s *SessionService) SetCreateTimingServing(sink createTimingSink) { s.createTiming = sink }

// SetListServing installs the §5.3 ListSessions read leg directly (doc 15 §5.3). It is the
// explicit test seam (and the escape hatch for a deployment that serves the list read but not
// the destroy leg): NewControlPlane installs the lister implicitly off the destroy store
// (SetDestroyServing), so production needs no extra call, but a narrowed handler can wire the
// list leg alone. Nil leaves ListSessions refusing Unavailable. It is additive — the other RPCs
// are unaffected.
func (s *SessionService) SetListServing(recs listSessionStore) { s.listRecords = recs }

// SetLaunchingUserResolver installs the OPTIONAL §3.1 launching-user attribution resolver the
// ListSessions launching_user filter narrows by (doc 16 §3.1/§3.2). It is additive — an empty
// launching_user filter never consults the resolver (fleet-wide), and a launching_user filter
// against an UNWIRED resolver refuses Unavailable (the clean degrade, never the unfiltered
// fleet). NewControlPlane wires it off the SAME backing store the list/destroy legs receive
// (the production store's ResolveLaunchingUserClaim); a test-narrowed handler can wire it alone
// (or leave it nil to exercise the unwired refusal). Nil leaves launching_user-scoped lists
// refusing Unavailable while host-scoped / unscoped lists are unaffected.
func (s *SessionService) SetLaunchingUserResolver(r listLaunchingUserResolverFunc) {
	s.launchingUserResolver = r
}

// SetSubTokenServing installs the D18 fan-out sub-token leg onto the handler (subtoken.go,
// doc 23 §5): the subTokenInjector that derives ONE narrowed agent sub-token per launched
// VM via the frozen dreamserpent.auth.v1 TokenAttenuationService and mounts it at the
// documented well-known in-VM path, plus the subTokenAuthorityFunc that resolves the
// launching principal's parent user auth token + the requested-scope SUBSET of its
// ds_scopes from the create request (the frozen CreateSessionRequest carries the
// launching_user subject, not the token/scopes — those ride the IdP claim the M2 multi-org
// band threads structurally, doc 16 §3.2). NewControlPlane wires the gRPC-shim attenuator +
// a file mount sink under the auth SDK endpoint; a test-narrowed handler that leaves the
// injector unset fans out NO sub-token (a deployment without the auth SDK reachable is a
// clean degrade, never a half-injected VM). It is additive — CreateSession's create path is
// unaffected whether or not the sub-token leg is installed.
func (s *SessionService) SetSubTokenServing(injector *subTokenInjector, authority subTokenAuthorityFunc) {
	s.subtokens = injector
	s.subTokenAuthority = authority
}

// SetPostureResolver installs the OPTIONAL POL-1 per-session posture resolver seam (doc 09 /
// doc 13 §2): CreateSession consults it to map the resolved role/env posture onto the
// runtime.v1 PermissionPosture it forwards into sessions.CreateRequest.Posture (a CONCRETE
// result WINS over the request-seeded posture; an UNSPECIFIED result defers to the seed). Nil
// (the default) leaves posture resolution UNWIRED — the create then forwards only the
// request's own posture (UNSPECIFIED on the frozen no-posture path), so the create is
// byte-identical to today and the daemon-pinned LOCKED fallback (M0 default-deny) is intact.
func (s *SessionService) SetPostureResolver(r PostureResolver) { s.postureResolver = r }

// setSessionRecordProducer installs the OPTIONAL §4.1 host-local session-record producer
// (the tap-keyed (session_uuid, host_id) drop, doc 14 §4.1) the create/teardown path
// maintains. It is the narrow unexported seam AttachSessionRecordStore (the cmd-side
// baseDir call) and the wiring test both drive — the test installs a fake that records the
// write/remove calls (D50, no live host). Nil leaves the live-join seam UNWIRED (the
// default): the create drops nothing and the teardown removes nothing.
func (s *SessionService) setSessionRecordProducer(p sessionRecordProducer) { s.sessionRecords = p }

// AttachSessionRecordStore wires the host-readable session-record PRODUCER (doc 14 §4.1) onto
// the create/teardown path: after this returns, a successful CreateSession DROPS the
// (session_uuid, host_id) record to baseDir/.ds-session-records/<Sanitize(tap_name)>.record
// (keyed on the interface-anchored tap the coordinator bound post-CloneFromImageResponse) and
// DestroySession REMOVEs it, so ds-tlsproxy's live M0-host JOIN reader (LiveSessionRecordClient,
// armed under DS_SESSION_JOIN_LIVE) resolves the binding instead of MISSing it. It is an
// ADDITIVE, opt-in wiring the live cmd calls with the host's OverlayDir (the SAME base the
// ds-tlsproxy reader points DS_TLSPROXY_SESSION_RECORD_DIR at) — a non-live / fakes wiring never
// calls it, so the create/teardown path stays the bare, no-drop posture (every existing path
// unchanged, byte-for-byte with the seam unwired). It mirrors
// IdentityClients.AttachCABundleStore (liveedges.go): the producer construction lives on the
// live edge, the create/teardown callsites just check the seam is non-nil. An empty baseDir is
// rejected fail-closed.
//
// DEFERRED MANUAL STEP (D50): the live cmd-side call (orchestrator/cmd/orchestrator/main.go
// under DS_SESSION_JOIN_LIVE, with the OverlayDir from the host deployment input) is NOT wired
// here — main.go is outside this unit's owned files. Until that one-line wiring lands, the seam
// stays nil and an armed proxy degrades to AddressDerived attribution (safe); this method is the
// seam it plugs into.
func (s *SessionService) AttachSessionRecordStore(baseDir string) error {
	producer, err := NewFileSessionRecordProducer(baseDir)
	if err != nil {
		return err
	}
	s.setSessionRecordProducer(producer)
	return nil
}

// Compile-time proof the handler satisfies the frozen orchestrator.v1 server interface.
var _ orchestratorv1.SessionServiceServer = (*SessionService)(nil)

// CreateSession is the frozen orchestrator.v1 SessionService.CreateSession server
// method (doc 15 §5.3). It builds a sessions.CreateRequest from the frozen
// CreateSessionRequest — the role_ref flows to the coordinator's steps-1–2 resolve+pin,
// the launching_user to the launch gate, the env-config/image refs to steps 2/3 — and
// drives the §4.1 ten-step coordinator. On success it returns the frozen Session
// response projected from the persisted record (READY/ATTACHED). On a coordinator
// failure it maps the typed *sessions.CreateError onto a gRPC status by failure class.
func (s *SessionService) CreateSession(ctx context.Context, req *orchestratorv1.CreateSessionRequest) (*orchestratorv1.CreateSessionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "controlplane: nil CreateSessionRequest")
	}

	sessionUUID := s.mintSessionUUID()

	// Build the §4.1 CreateRequest. The launching_user becomes the launch-gate input
	// (an empty launching_user is the unauthenticated launch the gate REFUSES
	// fail-closed — doc 16 §11.2; the handler models it as a nil *LaunchInput, never a
	// fabricated subject). The role_ref flows to the steps-1–2 resolve+pin. The
	// env-config ref is the §4.1 step-1 second key + the step-2 record ref; the image
	// id is resolved from the env config by the coordinator's two-key step (the
	// TwoKeyResult carries the resolved ImageID), so the handler passes the env-config
	// ref and lets the coordinator resolve image at step 1/2.
	var auth *sessions.LaunchInput
	if req.GetLaunchingUser() != "" {
		auth = &sessions.LaunchInput{
			// The launching_user is the IdP subject; the org is the v0 single-org
			// deployment's configured org (the frozen orchestrator.v1 message carries the
			// subject, not the full claim — the org rides the IdP claim the M2 multi-org
			// band threads structurally, doc 16 §3.2). The gate keys the principal upsert
			// on (subject, org); a create whose principal is not enrolled is refused at
			// the gate fail-closed.
			Subject: req.GetLaunchingUser(),
			Org:     s.defaultOrg,
			Roles:   []string{string(store.RoleLauncher)},
		}
	}

	// Resolve the content-addressed image + entrypoint from the checked-in env spec
	// (doc 15 §9 — the env config is the authority for the image identity and the D38
	// entrypoint; the orchestrator stays runtime-ignorant). A missing env config is the
	// §4.1 step-1 second-key absence the two-key step ALSO refuses; resolving here lets
	// the handler surface a clean InvalidArgument before the coordinator runs (and the
	// coordinator's two-key step is the structural defense in depth).
	imageID, entrypointRef, err := s.resolveImageAndEntrypoint(ctx, req.GetEnvConfigRef())
	if err != nil {
		return nil, err
	}

	// Resolve the per-session permission posture (POL-1, doc 13 §2): SEED from the request's
	// own forwarded posture, then let a wired resolver WIN when it yields a concrete value.
	// Nil resolver / an UNSPECIFIED resolution leaves the seed — so the frozen no-posture
	// create forwards UNSPECIFIED and the gap-1 producer falls back to the daemon-pinned
	// LOCKED (M0 default-deny), byte-identical to today.
	posture := req.GetPosture()
	if s.postureResolver != nil {
		if resolved := s.postureResolver.ResolvePosture(ctx, req); resolved != runtimev1.PermissionPosture_PERMISSION_POSTURE_UNSPECIFIED {
			posture = resolved
		}
	}

	createReq := sessions.CreateRequest{
		SessionUUID:         sessionUUID,
		RepoID:              req.GetRepoId(),
		EnvConfigRef:        req.GetEnvConfigRef(),
		ImageID:             imageID,
		Auth:                auth,
		RoleRef:             req.GetRoleRef(),
		EntrypointConfigRef: entrypointRef,
		AttachRole:          store.RoleWriter,
		Posture:             posture,
	}

	out, err := s.runCreate(ctx, createReq)
	if err != nil {
		return nil, mapCreateError(err)
	}

	// D18 FAN-OUT SUB-TOKEN (doc 23 §5). The create fanned out this VM; derive ONE narrowed
	// agent sub-token for it via the frozen TokenAttenuationService.DeriveAgentToken — passing
	// the VM's host_session_index (the §5 rule-2 audience) and a requested-scope SUBSET of the
	// parent ds_scopes (§5 rule 1) — and mount it at the documented well-known in-VM path
	// (the agent reads it locally, never over the network). M0 launches exactly one VM per
	// create, so this is exactly ONE derive call per VM. A widening rejection from the auth SDK
	// (codes.InvalidArgument) surfaces as the create's error — a token the service refused
	// never lands at the mount path. Absent a wired injector (a test-narrowed handler / a
	// deployment without the auth SDK reachable) this is a no-op and the create is unaffected.
	if err := s.fanoutSubToken(ctx, req, out); err != nil {
		return nil, err
	}

	// §4.1 HOST-LOCAL SESSION-RECORD DROP (doc 14 §4.1). The coordinator has bound the
	// (host_session_index, tap_name) for this session post-CloneFromImageResponse (carried on
	// out.Ref). Drop the tap-keyed (session_uuid, host_id) record so ds-tlsproxy's live M0-host
	// JOIN reader resolves the binding on a real host. It is a no-op with the seam unwired (the
	// default) — the create is byte-for-byte unchanged; armed, the drop is best-effort (a
	// host-local write fault degrades the join to AddressDerived, never fails the created session).
	s.dropSessionRecord(ctx, out)

	return &orchestratorv1.CreateSessionResponse{Session: sessionToProto(out)}, nil
}

// dropSessionRecord writes the §4.1 host-local session-record for a just-created session (doc
// 14 §4.1): the tap-keyed (session_uuid, host_id) drop the live ds-tlsproxy M0-host JOIN reader
// resolves (LiveSessionRecordClient, armed under DS_SESSION_JOIN_LIVE). It is invoked ONCE per
// create, after the (host_session_index, tap_name) binding is recorded (out.Ref, bound
// post-CloneFromImageResponse). It is a NO-OP when the producer seam is unwired (the default —
// a non-live / test-narrowed handler) OR the session carries no bound tap yet (a create that
// never reached the host bind, e.g. a pre-host structural refusal path — nothing to key the
// join on), so the create path is byte-for-byte unchanged with the seam absent. The write is
// BEST-EFFORT: a host-local drop fault is logged and swallowed (the session is already created;
// a failed drop only degrades the live join to AddressDerived, safe — measure-not-gate, D50/D81),
// never failing the create RPC.
func (s *SessionService) dropSessionRecord(ctx context.Context, out store.Session) {
	if s.sessionRecords == nil || out.Ref.TapName == "" {
		return
	}
	if err := s.sessionRecords.write(out.Ref.TapName, out.Ref.SessionUUID, out.Ref.HostID); err != nil {
		s.logger.WarnContext(ctx, "controlplane: §4.1 session-record drop failed — live M0-host JOIN degrades to AddressDerived (best-effort, session created)",
			slog.String("session", out.Ref.SessionUUID),
			slog.String("host", out.Ref.HostID),
			slog.String("tap", out.Ref.TapName),
			slog.Any("err", err))
	}
}

// removeSessionRecord deletes the §4.1 host-local session-record drop for a torn-down session
// (doc 14 §4.1), keyed on the record's bound tap (rec.Ref.TapName), so an armed ds-tlsproxy no
// longer joins a stale (session_uuid, host_id) onto a recycled tap. It is invoked ONCE per
// teardown, after the §4.2 host teardown converges. It is a NO-OP when the producer seam is
// unwired (the default) OR the record carries no bound tap (nothing was ever dropped), and the
// underlying remove is IDEMPOTENT (a missing drop is a clean no-op), so a double-teardown never
// errors and DestroySession is byte-for-byte unchanged with the seam absent. The removal is
// BEST-EFFORT: a host-local remove fault is logged and swallowed (the teardown already
// converged; a lingering stale drop is bounded by the next create's tap-keyed overwrite), never
// failing the teardown RPC.
func (s *SessionService) removeSessionRecord(ctx context.Context, rec store.Session) {
	if s.sessionRecords == nil || rec.Ref.TapName == "" {
		return
	}
	if err := s.sessionRecords.remove(rec.Ref.TapName); err != nil {
		s.logger.WarnContext(ctx, "controlplane: §4.1 session-record removal failed — stale drop lingers until the tap is re-dropped (best-effort, teardown converged)",
			slog.String("session", rec.Ref.SessionUUID),
			slog.String("host", rec.Ref.HostID),
			slog.String("tap", rec.Ref.TapName),
			slog.Any("err", err))
	}
}

// fanoutSubToken runs the D18 fan-out sub-token hop for the VM the create launched (doc 23
// §5; subtoken.go). It resolves the launching principal's parent authority (the D125 parent
// user auth token + the requested-scope SUBSET of its ds_scopes) through the
// subTokenAuthority seam, then drives the injector's deriveAndMount ONCE: derive via
// TokenAttenuationService.DeriveAgentToken with the VM's host_session_index + the requested
// subset, and mount the derived sub-token at the documented well-known in-VM path. It is a
// no-op (returns nil) when the sub-token leg is not wired or no parent authority is
// resolvable — CreateSession is unaffected (additive). A derive fault (notably the §5 rule-1
// scope-widening rejection, codes.InvalidArgument) surfaces as a gRPC status the caller sees,
// preserving the auth SDK's status code so a client tells a widening refusal (its own bad
// scope request) from a transient stall.
func (s *SessionService) fanoutSubToken(ctx context.Context, req *orchestratorv1.CreateSessionRequest, out store.Session) error {
	if s.subtokens == nil {
		return nil
	}
	var parentToken string
	var requestedScopes []string
	var lifetimeSeconds int32
	if s.subTokenAuthority != nil {
		parentToken, requestedScopes, lifetimeSeconds = s.subTokenAuthority(ctx, req)
	}
	ft := fanoutSubTokenFor(out, parentToken, requestedScopes, lifetimeSeconds)
	mountPath, derivedJTI, err := s.subtokens.deriveAndMount(ctx, ft)
	if err != nil {
		return mapSubTokenError(err, out.Ref.HostSessionIndex)
	}
	if mountPath != "" {
		s.logger.InfoContext(ctx, "controlplane: D18 fan-out derived + mounted agent sub-token (doc 23 §5)",
			slog.String("session", out.Ref.SessionUUID),
			slog.Uint64("host_session_index", out.Ref.HostSessionIndex),
			slog.String("mount_path", mountPath),
			slog.String("derived_jti", derivedJTI))
	}
	return nil
}

// mapSubTokenError maps a D18 fan-out derive/mount fault onto a gRPC status (doc 23 §5).
// The derive call goes to the frozen TokenAttenuationService, which already returns typed
// gRPC status codes (codes.InvalidArgument on a §5 rule-1 scope-widening request,
// codes.Unauthenticated on an invalid parent token, codes.PermissionDenied on a parent
// missing v1:identity:mint, codes.Internal on a derive/lineage fault); the wrapper preserves
// that code so a client tells a widening refusal (its own bad scope request) from a transient
// stall. A mount-side fault (a non-status error from the sink) surfaces as Internal.
func mapSubTokenError(err error, hostSessionIndex uint64) error {
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		// Preserve the auth SDK's status code (the wrapper kept it via %w in deriveAndMount).
		return status.Errorf(st.Code(), "controlplane: D18 fan-out sub-token for VM index %d (doc 23 §5): %v", hostSessionIndex, err)
	}
	return status.Errorf(codes.Internal, "controlplane: D18 fan-out sub-token for VM index %d (doc 23 §5): %v", hostSessionIndex, err)
}

// WatchSession is the frozen orchestrator.v1 SessionService.WatchSession server method
// (doc 15 §5.3, D18): the session-event fan-out leg. It Subscribes the calling stream to
// the session's attach.Fanout (watch.go) — the per-session subscriber set the one WRITER
// and the N READERs share — and serves every fanned attach.v1.SessionEvent on the gRPC
// server stream (wrapped in WatchSessionResponse) until the client disconnects or the
// session's stream closes (DESTROYED teardown). Canvas/console subscribe as ORDINARY N-th
// readers — there is no special path here (the writer/reader distinction is the seat the
// Attach handle grants, not a WatchSession class).
//
// RESUME-FROM-LASTSEQ (D61 slow-reader recovery + D79 per-event seqs). from_seq replays
// the in-window tail from the per-session resume ring BEFORE registering the live
// subscription, so a reader resumes exactly where it dropped without re-attaching; from_seq
// == 0 streams from the current frontier (backfilling whatever the ring holds). A from_seq
// that aged out of the ring is attach.ErrResumeWindowExceeded → a clean OutOfRange refusal
// the client lifts into a re-attach-from-frontier (never a silent gap). The Fanout is the
// SEQ AUTHORITY (the host-side hostbridge ring and this control-plane ring are distinct,
// watch.go) — every event the client receives carries the monotonic per-session seq it
// recovers by.
//
// The per-frame Emit (the Fanout's sink) sends on the gRPC stream; a stream-send error
// (the client aborted / its connection died) stops the fan for THIS subscriber WITHOUT
// disturbing the other readers (independent reader-drop, D61) — the Fanout unsubscribes it
// and WatchSession returns. The whole subscription is torn down on return (the deferred
// unsubscribe), so a disconnected client leaves no orphaned subscriber.
func (s *SessionService) WatchSession(req *orchestratorv1.WatchSessionRequest, stream orchestratorv1.SessionService_WatchSessionServer) error {
	if req == nil || req.GetSessionUuid() == "" {
		return status.Error(codes.InvalidArgument, "controlplane: WatchSession requires a session_uuid")
	}
	if s.fanout == nil {
		// The attach legs are not being served (a test-narrowed handler / a deployment
		// without the fan-out wired). Refuse Unavailable rather than serving an empty
		// stream — the client retries against a control plane that serves the leg.
		return status.Error(codes.Unavailable, "controlplane: WatchSession fan-out not served (attach legs unwired)")
	}

	ctx := stream.Context()

	// SINGLE-WRITER SERIALIZATION (gRPC ServerStream is not Send-safe). The fan-out drives
	// this subscriber's Emit from TWO goroutines that can overlap: (1) the handler goroutine,
	// which sends the resume-replay tail synchronously inside Fanout.Subscribe, and (2) the
	// Publisher goroutine(s) — the host-agent relay (attachrelay.go), plus any same-session
	// split-brain second publisher — which fan a LIVE event the instant the subscriber is
	// registered (watch.go registers under the ring-snapshot lock, BEFORE replay emits). gRPC
	// documents stream.Send as unsafe for concurrent use, so two goroutines calling it on one
	// orchestrator.v1 WatchSession server stream is a data race AND can deliver out of the
	// monotonic Seq order. serializedWatchSender wraps the per-stream stream.Send behind a
	// sync.Mutex so every Send to THIS stream is serialized.
	//
	// REPLAY-BEFORE-LIVE ORDERING. beginReplay (before Subscribe) opens the replay phase: a
	// live Emit that races in during replay is BUFFERED rather than sent, so it cannot
	// interleave ahead of the ascending-Seq replay tail. endReplay (after Subscribe returns)
	// flushes the buffered live events in ascending-Seq order — every live event carries a Seq
	// strictly above the snapshotted replay tail (the Fanout stamps monotonic Seqs under its
	// lock, watch.go) — and switches to direct, serialized live delivery. A send error stops
	// the fan for this subscriber (the Fanout drops it independently, D61).
	sender := newSerializedWatchSender(stream)
	emitter := attach.EmitterFunc(sender.emit)

	sender.beginReplay()
	unsubscribe, err := s.fanout.Subscribe(ctx, req.GetSessionUuid(), req.GetFromSeq(), emitter)
	flushErr := sender.endReplay()
	if err != nil {
		if errors.Is(err, attach.ErrResumeWindowExceeded) {
			// from_seq aged out of the per-session resume ring: a clean refusal the client
			// lifts into a re-attach-from-frontier (the same semantics as the host-side
			// ErrResumeWindowExceeded, mirrored control-plane-side). OutOfRange names "the
			// requested replay point is no longer in the retained window".
			return status.Errorf(codes.OutOfRange, "controlplane: WatchSession from_seq %d aged out of the resume window (re-attach from frontier): %v", req.GetFromSeq(), err)
		}
		// A replay-send error during Subscribe (the client died mid-backfill) surfaces as the
		// stream's own context error if cancelled, else as an internal fan-out fault.
		if cerr := ctx.Err(); cerr != nil {
			return status.FromContextError(cerr).Err()
		}
		return status.Errorf(codes.Internal, "controlplane: WatchSession subscribe for session %q: %v", req.GetSessionUuid(), err)
	}
	defer unsubscribe()

	// A buffered-live-event flush error (the client died between Subscribe's replay and the
	// flush) tears this subscriber down the same way a replay-send error does: surface the
	// stream's context error if cancelled, else an internal fan-out fault. The deferred
	// unsubscribe drops it from the set; no other reader is disturbed (D61).
	if flushErr != nil {
		if cerr := ctx.Err(); cerr != nil {
			return status.FromContextError(cerr).Err()
		}
		return status.Errorf(codes.Internal, "controlplane: WatchSession live flush for session %q: %v", req.GetSessionUuid(), flushErr)
	}

	// Block until the client disconnects (ctx cancelled) — the fan-out delivers live events
	// to the emitter on the Publisher's goroutine (the host-agent relay), so this handler
	// only needs to hold the subscription open and tear it down on disconnect. A context
	// cancel (client gone) returns its status; a clean disconnect is not an error.
	<-ctx.Done()
	if cerr := ctx.Err(); cerr != nil && !errors.Is(cerr, context.Canceled) {
		return status.FromContextError(cerr).Err()
	}
	return nil
}

// serializedWatchSender is the single-writer guard around ONE orchestrator.v1 WatchSession
// server stream (sessionservice.go WatchSession). The attach.Fanout drives the subscriber's
// Emit from two goroutines that overlap — the handler goroutine sending the resume-replay
// tail synchronously inside Fanout.Subscribe, and the Publisher goroutine(s) (the host-agent
// relay attachrelay.go, plus any same-session split-brain second publisher) fanning a LIVE
// event the instant watch.go registers the subscriber (which it does under its ring-snapshot
// lock, BEFORE the tail replays). gRPC documents stream.Send as unsafe for concurrent use,
// so this serializes every Send to the stream behind mu (no data race) AND orders the wire
// (replay tail first, then live, ascending Seq).
//
// THE ORDERING MECHANISM (replay-before-live). beginReplay opens the replay phase. While the
// phase is open EVERY emit — replay tail AND any live event that races in — is BUFFERED under
// mu rather than sent, so no live event can interleave ahead of the tail. endReplay sorts the
// buffer by the Fanout's monotonic per-event Seq (the Fanout is the Seq authority, watch.go —
// every live event's Seq is strictly above the snapshotted replay tail's), drains it to the
// stream in ascending-Seq order, closes the phase, and thereafter emit sends each live event
// directly under mu (still serialized, single-writer). The buffer is bounded: the replay tail
// is at most the resume ring (historySize) and the live races are only those in the brief
// replay window. A send error is sticky — once the stream errors, the Fanout drops this
// subscriber (independent reader-drop, D61) and subsequent emits short-circuit to that error.
type serializedWatchSender struct {
	stream orchestratorv1.SessionService_WatchSessionServer

	mu        sync.Mutex
	replaying bool                                   // true between beginReplay and endReplay: emit buffers instead of sending
	buffered  []*orchestratorv1.WatchSessionResponse // events emitted during the replay phase, flushed in Seq order by endReplay
	sendErr   error                                  // first stream.Send error; sticky (the broken stream stays broken)
}

// newSerializedWatchSender wraps the WatchSession server stream in the single-writer guard.
func newSerializedWatchSender(stream orchestratorv1.SessionService_WatchSessionServer) *serializedWatchSender {
	return &serializedWatchSender{stream: stream}
}

// beginReplay opens the replay phase: until endReplay, emit buffers every event (the replay
// tail and any live event a Publisher races in) instead of sending, so the wire stays
// replay-before-live.
func (w *serializedWatchSender) beginReplay() {
	w.mu.Lock()
	w.replaying = true
	w.mu.Unlock()
}

// endReplay closes the replay phase: it drains the buffered events to the stream in
// ascending-Seq order (the Fanout-stamped monotonic Seq, watch.go) and switches emit to
// direct, serialized live delivery. It returns the first Send error encountered draining the
// buffer (so the handler tears the subscriber down), or nil. It holds mu across the drain so
// a concurrent live emit blocks until the buffer is flushed and the phase closed — no live
// event slips onto the wire ahead of, or interleaved with, the drained tail.
func (w *serializedWatchSender) endReplay() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	sort.SliceStable(w.buffered, func(i, j int) bool {
		return w.buffered[i].GetEvent().GetSeq() < w.buffered[j].GetEvent().GetSeq()
	})
	for _, resp := range w.buffered {
		if w.sendErr == nil {
			w.sendErr = w.stream.Send(resp)
		}
	}
	w.buffered = nil
	w.replaying = false
	return w.sendErr
}

// emit is the attach.Emitter sink the Fanout drives for this subscriber. During the replay
// phase it buffers the event under mu (so endReplay can order the wire); afterwards it sends
// directly under mu (serialized single-writer). A sticky prior send error short-circuits — the
// stream is broken and the Fanout will drop this subscriber on the returned error.
func (w *serializedWatchSender) emit(_ context.Context, ev *attachv1.SessionEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sendErr != nil {
		return w.sendErr
	}
	resp := &orchestratorv1.WatchSessionResponse{Event: ev}
	if w.replaying {
		w.buffered = append(w.buffered, resp)
		return nil
	}
	w.sendErr = w.stream.Send(resp)
	return w.sendErr
}

// Attach is the frozen orchestrator.v1 SessionService.Attach server method (doc 15 §5.4,
// D79): the attach-handle issuance leg. It runs the D61 seat arbitration server-side
// (attach.Issuer over the session record's writer seat — seat.go) for the requested Role
// and returns the transport-ambivalent attach.v1.AttachHandle the client connects with
// (M0: the DIRECT client→host-agent endpoint candidate, a short-lived session-scoped
// AuthMaterial that is NEVER a long-lived cred (D39), the granted WRITER/READER Role, and
// an expiry). The seat lives in the session record, so a WRITER acquisition is a record
// mutation with attribution and the handle + the record never disagree about who holds the
// one writer seat.
//
// SEAT ARBITRATION REFUSALS (D61). A second WRITER attach is refused with FailedPrecondition
// (attach.ErrWriterSeatHeld — the one writer seat is held; the M0 wire request carries no
// handoff/seat-identity field, so an M0 Attach never silently displaces the holder). A
// READER attach is always admitted (the unbounded N). An unset/unknown Role (ROLE_UNSPECIFIED
// on the wire) is InvalidArgument (attach.ErrUnknownRole — the seat class a handle grants
// must be a real D61 class). A store fault under the seat read/write surfaces Unavailable
// (the record store is the seat authority; a stalled store cannot arbitrate the seat).
func (s *SessionService) Attach(ctx context.Context, req *orchestratorv1.AttachRequest) (*orchestratorv1.AttachResponse, error) {
	if req == nil || req.GetSessionUuid() == "" {
		return nil, status.Error(codes.InvalidArgument, "controlplane: Attach requires a session_uuid")
	}
	if s.issuer == nil {
		return nil, status.Error(codes.Unavailable, "controlplane: Attach issuer not served (attach legs unwired)")
	}

	// The seat identity is the session_uuid-scoped writer holder. The M0 frozen AttachRequest
	// carries no separate seat-identity field (the seat identity is the attaching principal,
	// resolved at the M2 multi-org auth boundary the request threads); at M0 the writer seat
	// is keyed on the session itself, so the session_uuid is the seat holder identity for the
	// one-writer arbitration. handoff is false: the M0 request has no handoff field, so a
	// second writer is refused rather than silently displacing the holder.
	handle, _, err := s.issuer.Issue(ctx, req.GetSessionUuid(), req.GetSessionUuid(), req.GetRole(), false)
	if err != nil {
		return nil, mapAttachError(err, req.GetSessionUuid())
	}
	return &orchestratorv1.AttachResponse{Handle: handle}, nil
}

// DestroySession is the frozen orchestrator.v1 SessionService.DestroySession server method
// (doc 15 §5.3, §4.2): the public teardown surface. It closes the M0 lifecycle through the
// PUBLIC handler (an operator tears a session down over the wire) instead of any caller
// reaching for the host driver directly.
//
// THE RECONCILER-DRIVEN ORDERING (doc 15 §4.2; D35/D72). DESTROYING is reconciler-driven —
// desired = DESTROYED. The handler models that ordering in three steps over the §5.6 record
// (the single source of desired state):
//
//  1. Flip the record's desired state to DESTROYING (the in-flight teardown marker): the
//     session is now headed for DESTROYED, and any racing re-mint / reconcile reads the
//     DESTROYING posture and stands down (the mint-expiry sink, wiring.go, already DROPS on a
//     DESTROYING/terminal record — the destroy supersedes the registration).
//  2. Drive the host-owned §4.2 teardown ordering through the sessions.HostDestroyer seam
//     (the SAME seam the create coordinator's compensating rollback drives, doc 15 §4.1/§4.2):
//     domain destroy → unconditional flush_session(legs=all) + NFT-6 → overlay disposal +
//     durability finalize → digest flush → identity/CA revoke → DESTROYED report. It is
//     idempotent on session_uuid + re-driveable. A teardown fault leaves the record DESTROYING
//     (the reconciler is the backstop — it re-drives an in-flight teardown to convergence),
//     surfaced so the operator sees the teardown did not finish cleanly.
//  3. Finalize the record to DESTROYED with the teardown timestamp (§4.2 step 6; doc 06 §3b
//     clean-teardown done-when). The row is RETAINED, never deleted within the flow-log
//     retention window (D66); only the lifecycle state + DestroyedAt are written.
//
// IDEMPOTENT (doc 15 §4.2). A DestroySession of an ALREADY-terminal (DESTROYED) session is a
// clean no-op success (the teardown already converged) — the record's wire projection is
// returned without re-driving the host teardown. An unknown session is NotFound. A store
// fault under the lifecycle write is Unavailable (the operator retries; the reconciler is the
// backstop for a session left DESTROYING).
func (s *SessionService) DestroySession(ctx context.Context, req *orchestratorv1.DestroySessionRequest) (*orchestratorv1.DestroySessionResponse, error) {
	if req == nil || req.GetSessionUuid() == "" {
		return nil, status.Error(codes.InvalidArgument, "controlplane: DestroySession requires a session_uuid")
	}
	if s.destroyer == nil || s.destroyRecords == nil {
		// The destroy leg is not being served (a test-narrowed handler / a deployment without
		// the §4.2 teardown wired). Refuse Unavailable rather than half-tearing a session down.
		return nil, status.Error(codes.Unavailable, "controlplane: DestroySession teardown not served (destroy leg unwired)")
	}

	sessionUUID := req.GetSessionUuid()

	// Read the record: the single source of desired/observed state. It names the host the
	// teardown targets (rec.Ref.HostID) and lets the handler short-circuit an already-terminal
	// session (idempotent re-destroy) before driving any host verb.
	rec, err := s.destroyRecords.GetSession(ctx, sessionUUID)
	if err != nil {
		return nil, mapDestroyStoreError(err, sessionUUID)
	}
	if rec.State.IsTerminal() {
		// Already DESTROYED — the teardown converged. Return the retained record's wire
		// projection without re-driving the host teardown (idempotent on session_uuid).
		return &orchestratorv1.DestroySessionResponse{Session: sessionToProto(rec)}, nil
	}

	// (1) DESIRED = DESTROYING — flip the record to the in-flight teardown marker so a racing
	// re-mint / reconcile reads the DESTROYING posture and stands down (the destroy supersedes).
	// CLEAR the §3 SUSPENDED(reason) invariant alongside the flip: a SUSPENDED session (e.g. a
	// D77 policy_breach suspension an operator then tears down) is non-terminal, so it reaches
	// here, and the store's "reason set iff SUSPENDED" CHECK (checkSuspend) would REJECT a
	// DESTROYING write that left a stale reason — leaving the session undestroyable. Leaving
	// SUSPENDED forces the reason back to NULL (the SUSPENDED→RESUMING precedent), so the
	// DESTROYING flip carries SuspendReasonNone for every source state (a no-op on a record
	// that was never SUSPENDED).
	destroying := store.SessionDestroying
	noReason := store.SuspendReasonNone
	if _, err := s.destroyRecords.UpdateSession(ctx, sessionUUID, store.SessionUpdate{State: &destroying, SuspendReason: &noReason}); err != nil {
		return nil, mapDestroyStoreError(err, sessionUUID)
	}

	// (2) §4.2 TEARDOWN — drive the host-owned ordering through the SAME HostDestroyer seam the
	// create coordinator's compensating rollback drives. The host is the record's bound host
	// (rec.Ref.HostID); the verb is idempotent on session_uuid. A fault leaves the record
	// DESTROYING for the reconciler to re-drive to convergence, surfaced so the operator knows
	// the teardown did not finish cleanly.
	if err := s.destroyer.Destroy(ctx, rec.Ref.HostID, sessionUUID); err != nil {
		s.logger.WarnContext(ctx, "controlplane: DestroySession §4.2 teardown failed — record left DESTROYING (reconciler backstop)",
			slog.String("session", sessionUUID), slog.String("host", rec.Ref.HostID), slog.Any("err", err))
		return nil, status.Errorf(codes.Internal, "controlplane: DestroySession §4.2 teardown of %q failed (record left DESTROYING; reconciler will re-drive): %v", sessionUUID, err)
	}

	// §4.1 HOST-LOCAL SESSION-RECORD REMOVAL (doc 14 §4.1). The host teardown has converged, so
	// remove the tap-keyed (session_uuid, host_id) drop for this session's bound tap
	// (rec.Ref.TapName) — an armed ds-tlsproxy no longer joins a stale binding onto a recycled
	// tap. It is a no-op with the seam unwired (the default) and idempotent (a missing drop is a
	// clean no-op), so DestroySession is byte-for-byte unchanged when the live-join seam is absent.
	s.removeSessionRecord(ctx, rec)

	// (3) FINALIZE — DESTROYED + the teardown timestamp (§4.2 step 6; the record is RETAINED,
	// D66). The row is never deleted within the flow-log retention window — only the lifecycle
	// state + DestroyedAt are written.
	destroyed := store.SessionDestroyed
	out, err := s.destroyRecords.UpdateSession(ctx, sessionUUID, store.SessionUpdate{
		State:       &destroyed,
		DestroyedAt: store.SetTime(s.clock()),
	})
	if err != nil {
		return nil, mapDestroyStoreError(err, sessionUUID)
	}
	s.logger.InfoContext(ctx, "controlplane: session destroyed over the public surface (DESTROYED, §4.2 teardown converged)",
		slog.String("session", sessionUUID), slog.String("host", rec.Ref.HostID))
	return &orchestratorv1.DestroySessionResponse{Session: sessionToProto(out)}, nil
}

// listSessionsMaxPageSize caps a client's requested page_size so one over-eager request cannot
// pin a whole large fleet into one response (a server-side ceiling, doc 15 §5.3). A page_size
// above the cap is silently clamped to the cap (the client walks the rest via the returned
// next_page_token); page_size == 0 is the BACK-COMPAT single-shot path (return ALL — see below)
// and is NOT clamped. The cap is deliberately generous: pagination is opt-in, so the cap only
// bites a client that explicitly asked to page with an outsized window.
const listSessionsMaxPageSize = 1000

// ListSessions is the frozen orchestrator.v1 SessionService.ListSessions server method (doc 15
// §5.3): the public fleet/console read. It enumerates the §5.6 records the control plane is the
// single source of, projecting each onto the frozen Session wire message (uuid, host, lifecycle
// state, created-at — the same projection sessionToProto already builds for CreateSession /
// DestroySession, so the read and the write surfaces agree byte-for-byte on a record's wire
// face). The store returns records newest-first (CreatedAt DESC, session_uuid DESC tiebreak);
// the handler preserves that exact stable total order — the order the page cursor walks.
//
// FILTERS (frozen request). Both filters + the page cursor are pushed DOWN into the store's
// SessionFilter so the handler issues ONE bounded keyset query per page (it no longer
// enumerates the whole filtered slice, nor resolves launching_user per-row — the
// N+1-per-page the in-process walk did on the Postgres path).
//   - host_id narrows to one host (empty = fleet-wide), the store-side host filter.
//   - launching_user (the §3.1 attribution claim) narrows to the sessions one principal
//     launched. The §5.6 RECORD does not carry the launching_user on its wire face (it is
//     resolved at the IdP boundary, not stored on the record — sessionToProto leaves the wire
//     field empty by the same rule), so the store resolves each candidate's launching principal
//     → IdP subject through its own session→principal linkage + principal records and keeps only
//     the exact matches (the SAME narrowing ResolveLaunchingUserClaim's match test makes,
//     evaluated inside the one read). An empty launching_user is fleet-wide. A launching_user
//     filter against an UNWIRED resolver refuses Unavailable (the clean degrade — NEVER the
//     unfiltered fleet, which would leak other principals' sessions): the resolver seam's
//     PRESENCE is the "this deployment serves attribution" signal even though the store now
//     evaluates the match.
//
// PAGINATION (frozen request / response, BACK-COMPAT). The keyset scan lives in the store; the
// handler decodes/encodes the opaque cursor and detects the next page by requesting ONE extra
// row past the page (a full extra row ⇒ more remain).
//   - page_size == 0 returns ALL matching sessions in one shot and an EMPTY next_page_token —
//     the existing single-call clients (serpent / serpent-tui) keep seeing the full list and are
//     NEVER silently truncated. Pagination is strictly OPT-IN.
//   - page_size > 0 returns at most page_size sessions and, when more remain, a next_page_token
//     OPAQUE cursor over the stable newest-first order. A round-trip of the token walks every
//     matching session exactly once (no dup, no skip); the last page returns an empty token. The
//     paged sequence is BYTE-IDENTICAL to the historical in-process pages.
//   - page_token is server-opaque (a base64 (CreatedAt-unixnano, session_uuid) cursor); a
//     malformed token is InvalidArgument (a client must treat the token as opaque and echo back).
//
// DESTROYED records are INCLUDED so an operator can see a just-torn-down session settle (the row
// is retained, D66 — the console read surfaces the terminal state rather than hiding the session
// the instant it is destroyed).
//
// UNWIRED. A handler whose list leg is not installed (a test-narrowed handler, or a backing store
// that does not enumerate) refuses Unavailable rather than serving an empty enumeration that a
// caller cannot distinguish from "no sessions" — the same clean degrade the attach / destroy read
// legs use. A store fault under the enumeration maps by CLASS exactly like the destroy read.
func (s *SessionService) ListSessions(ctx context.Context, req *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
	if s.listRecords == nil {
		// The list leg is not being served (a test-narrowed handler / a deployment whose store
		// does not enumerate). Refuse Unavailable rather than masquerading an unserved read as an
		// empty fleet.
		return nil, status.Error(codes.Unavailable, "controlplane: ListSessions not served (list leg unwired)")
	}

	launchingUser := req.GetLaunchingUser()
	if launchingUser != "" && s.launchingUserResolver == nil {
		// A launching_user-scoped read against an unwired resolver. Refuse Unavailable rather
		// than ignoring the filter and returning the WHOLE fleet (which would leak other
		// principals' sessions) — the clean degrade the other unserved read legs use.
		return nil, status.Error(codes.Unavailable, "controlplane: ListSessions launching_user filter not served (attribution resolver unwired)")
	}

	// Decode the opaque page cursor BEFORE touching the store: a malformed token is the client's
	// own bad request (InvalidArgument), independent of any store state. An empty token starts at
	// the newest record.
	cursor, err := decodeSessionPageToken(req.GetPageToken())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "controlplane: ListSessions: malformed page_token: %v", err)
	}

	// ONE bounded keyset query for the page: the store applies the host filter, the launching_user
	// attribution narrowing, the cursor skip (strictly-after the previous page's last, in the
	// stable newest-first order), and the page LIMIT — so the handler stops re-enumerating the
	// whole fleet and resolving launching_user per-row. DESTROYED rows are included (D66 retention)
	// so the console can show a session settling into its terminal state. To know whether a NEXT
	// page exists, request ONE extra row past the page (limit+1): a full extra row means at least
	// one more matching record remains, so a continuation token is emitted; otherwise this is the
	// last page (empty token). limit == 0 is the back-compat single-shot path (PageSize <= 0 in the
	// store returns ALL — never bounded, never a token).
	limit := pageLimit(req.GetPageSize())
	storeLimit := limit
	if limit > 0 {
		storeLimit = limit + 1
	}
	recs, err := s.listRecords.ListSessions(ctx, store.SessionFilter{
		HostID:           req.GetHostId(),
		IncludeDestroyed: true,
		LaunchingUser:    launchingUser,
		PageToken:        storePageCursor(cursor),
		PageSize:         storeLimit,
	})
	if err != nil {
		return nil, mapListStoreError(err)
	}

	more := false
	if limit > 0 && len(recs) > limit {
		// The probe row past the page: there is at least one more matching record. Drop it and
		// emit a continuation token over the last EMITTED record's cursor.
		more = true
		recs = recs[:limit]
	}
	out := &orchestratorv1.ListSessionsResponse{Sessions: make([]*orchestratorv1.Session, 0, len(recs))}
	var lastCursor sessionPageCursor
	for _, rec := range recs {
		out.Sessions = append(out.Sessions, sessionToProto(rec))
		// The next token is built from the STORE record's FULL-precision CreatedAt (the wire
		// Session carries only whole-second created_at), so the cursor keeps the sub-second
		// precision both stores sort on.
		lastCursor = cursorOf(rec)
	}
	if more {
		out.NextPageToken = encodeSessionPageToken(lastCursor)
	}
	return out, nil
}

// storePageCursor projects the decoded wire cursor onto the store-side keyset cursor the
// SessionFilter scans by. The opaque wire token carries created_at as full-precision UnixNano
// (sessionPageCursor); time.Unix(0, ns) reconstructs the exact instant the store sorts on — a
// lossless round-trip for both stores (the in-memory store compares the time.Time, the Postgres
// store the microsecond timestamptz). The unset cursor (empty token) maps to the store's
// start-from-newest zero value.
func storePageCursor(c sessionPageCursor) store.SessionPageCursor {
	if !c.set {
		return store.SessionPageCursor{}
	}
	return store.SessionPageCursor{
		Set:       true,
		CreatedAt: time.Unix(0, c.createdAt).UTC(),
		UUID:      c.uuid,
	}
}

// pageLimit resolves the frozen page_size into a server-side page limit: 0 is the BACK-COMPAT
// single-shot path (return ALL — signalled as limit 0, "no limit"); a positive value is clamped
// to listSessionsMaxPageSize so one request cannot pin a whole large fleet.
func pageLimit(pageSize uint32) int {
	if pageSize == 0 {
		return 0 // back-compat: return ALL
	}
	if pageSize > listSessionsMaxPageSize {
		return listSessionsMaxPageSize
	}
	return int(pageSize)
}

// sessionPageCursor is the decoded position the opaque page_token names: the (CreatedAt,
// session_uuid) of the LAST record returned on the previous page, in the store's stable
// newest-first order (CreatedAt DESC, session_uuid DESC tiebreak). set == false is the
// start-from-newest (empty token) state.
//
// PRECISION (load-bearing). createdAt is the record's CreatedAt in NANOSECONDS (UnixNano), NOT
// whole seconds. Both stores order on the FULL-precision CreatedAt — *store.Memory sorts on
// time.Time.After/Equal (sub-second), *store.Postgres on `ORDER BY created_at DESC` over a
// microsecond timestamptz (postgres_sql.go) — so the cursor's comparison key MUST carry the
// same precision the store sorts on. A second-granularity cursor would treat two sessions
// created in the SAME second as a CreatedAt tie and fall through to the session_uuid tiebreak,
// disagreeing with the store's sub-second order — skipping or duplicating a session at a page
// boundary that lands inside a same-second cluster (routine on a fleet creating >1 session/s).
// UnixNano is lossless for both stores (microseconds fit; the memory store's nanos fit), so the
// cursor key is byte-identical to the store sort key and the walk is exact.
type sessionPageCursor struct {
	set       bool
	createdAt int64 // CreatedAt in nanoseconds (UnixNano) — full store-sort precision
	uuid      string
}

// cursorOf builds the cursor naming rec's position in the stable order.
func cursorOf(rec store.Session) sessionPageCursor {
	return sessionPageCursor{set: true, createdAt: rec.CreatedAt.UnixNano(), uuid: rec.Ref.SessionUUID}
}

// encodeSessionPageToken renders the cursor as the server-opaque page_token: a base64url of
// "<createdAt-unixnano>:<session_uuid>". The client treats it as opaque and only echoes it back.
func encodeSessionPageToken(c sessionPageCursor) string {
	raw := strconv.FormatInt(c.createdAt, 10) + ":" + c.uuid
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// decodeSessionPageToken parses the opaque page_token back into a cursor. An empty token is the
// start-from-newest position (set == false, no error). A token that is not valid base64url, or
// whose decoded body is not "<int-unixnano>:<uuid>", is a malformed-token error the handler lifts
// into InvalidArgument (the client must treat the token as opaque and echo it verbatim).
func decodeSessionPageToken(token string) (sessionPageCursor, error) {
	if token == "" {
		return sessionPageCursor{}, nil
	}
	rawBytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return sessionPageCursor{}, fmt.Errorf("not base64url: %w", err)
	}
	raw := string(rawBytes)
	sep := strings.IndexByte(raw, ':')
	if sep < 0 {
		return sessionPageCursor{}, fmt.Errorf("missing cursor separator")
	}
	createdAt, err := strconv.ParseInt(raw[:sep], 10, 64)
	if err != nil {
		return sessionPageCursor{}, fmt.Errorf("bad created-at in cursor: %w", err)
	}
	uuid := raw[sep+1:]
	if uuid == "" {
		return sessionPageCursor{}, fmt.Errorf("empty session_uuid in cursor")
	}
	return sessionPageCursor{set: true, createdAt: createdAt, uuid: uuid}, nil
}

// mapListStoreError maps a §5.6 record-store fault under ListSessions onto a gRPC status by CLASS:
// a store-unavailable is Unavailable (degraded mode — retry); anything else is Internal. There is
// no NotFound case (an enumeration of an empty / absent fleet is a clean empty result, never an
// error).
func mapListStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrUnavailable):
		return status.Errorf(codes.Unavailable, "controlplane: ListSessions: store unavailable (degraded mode; retry): %v", err)
	default:
		return status.Errorf(codes.Internal, "controlplane: ListSessions: store error: %v", err)
	}
}

// mapDestroyStoreError maps a §5.6 record-store fault under DestroySession onto a gRPC status
// by CLASS: an unknown session is NotFound (the operator named a session that does not exist);
// a store-unavailable is Unavailable (degraded mode — retry; the reconciler is the backstop);
// an inconsistent lifecycle write (ErrInvalid) is FailedPrecondition; anything else Internal.
func mapDestroyStoreError(err error, sessionUUID string) error {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return status.Errorf(codes.NotFound, "controlplane: DestroySession: session %q not found", sessionUUID)
	case errors.Is(err, store.ErrUnavailable):
		return status.Errorf(codes.Unavailable, "controlplane: DestroySession: store unavailable for %q (degraded mode; retry)", sessionUUID)
	case errors.Is(err, store.ErrInvalid):
		return status.Errorf(codes.FailedPrecondition, "controlplane: DestroySession: invalid lifecycle write for %q: %v", sessionUUID, err)
	default:
		return status.Errorf(codes.Internal, "controlplane: DestroySession: store error for %q: %v", sessionUUID, err)
	}
}

// mapAttachError maps the attach issuer's seat-arbitration failure onto a gRPC status by
// CLASS (doc 15 §5.4 / D61): the one-writer refusal is a structural precondition
// (FailedPrecondition — the seat is held); an unknown role is a bad request
// (InvalidArgument); a store fault under the seat read/write is transient (Unavailable);
// anything else is Internal. So a client tells a seat conflict (someone else is the writer)
// from a malformed request from a transient store stall.
func mapAttachError(err error, sessionUUID string) error {
	switch {
	case errors.Is(err, attach.ErrWriterSeatHeld):
		return status.Errorf(codes.FailedPrecondition, "attach refused (D61 one-writer; writer seat held) for session %q: %v", sessionUUID, err)
	case errors.Is(err, attach.ErrUnknownRole):
		return status.Errorf(codes.InvalidArgument, "attach refused (role must be WRITER or READER, D61) for session %q: %v", sessionUUID, err)
	case errors.Is(err, attach.ErrSeatIdentityRequired):
		return status.Errorf(codes.InvalidArgument, "attach refused (writer seat requires an identity, D61) for session %q: %v", sessionUUID, err)
	case errors.Is(err, store.ErrUnavailable):
		return status.Errorf(codes.Unavailable, "attach stalled (seat store unavailable) for session %q: %v", sessionUUID, err)
	case errors.Is(err, store.ErrNotFound):
		return status.Errorf(codes.NotFound, "attach refused (session %q not found) : %v", sessionUUID, err)
	default:
		return status.Errorf(codes.Internal, "attach failed for session %q: %v", sessionUUID, err)
	}
}

// runCreate drives the create. When a FastStarter is wired (the production path), the
// create runs THROUGH the M2 golden-image instant-start fast path: it resolves the
// pre-baked golden image (the §7 image-cache-locality lever) and records the §8
// create→attach timing decomposition into the shared trend Recorder — MEASURE, NOT GATE
// (D81/D32). The fast path drives the SAME §4.1 ten-step coordinator; it adds only
// resolution + measurement and NEVER refuses a create on the timing.
//
// A FastStart that fails the §8 EXISTENCE assertion (sessions.ErrTimingIncomplete — an
// INSTRUMENTATION gap on a create that REACHED ATTACHED) must NOT fail the create: the
// session is already created, so the handler logs the measurement gap and returns the
// session. Any OTHER FastStart error is the coordinator's own structural gate / seam fault
// (the typed *CreateError mapCreateError classifies) and is surfaced. Absent a wired fast
// starter (a test-narrowed handler) the create runs on the raw coordinator unchanged.
func (s *SessionService) runCreate(ctx context.Context, req sessions.CreateRequest) (store.Session, error) {
	if s.fastStarter == nil {
		return s.creator.Create(ctx, req)
	}
	res, err := s.fastStarter.FastStart(ctx, req)
	if err != nil {
		if errors.Is(err, sessions.ErrTimingIncomplete) {
			// The session REACHED ATTACHED; only the §8 decomposition was incomplete (a
			// measurement gap, NOT a release-budget verdict — there is no budget). Log it so
			// the instrument stays honest, and return the created session (the gap does not
			// un-create it, measure-not-gate per D81/D32). Still fold the PARTIAL decomposition
			// so the trend records what WAS measured (the fold does not require completeness —
			// the (b)-row existence assertion is the separate MissingSegments read).
			s.logger.WarnContext(ctx, "controlplane: golden-image create reached ATTACHED with an incomplete §8 create→attach decomposition (instrument gap; NOT a release-budget verdict, D81/D32)",
				slog.String("session", req.SessionUUID), slog.Any("err", err))
			s.foldCreateTiming(req.SessionUUID, res.Timing)
			return res.Session, nil
		}
		return store.Session{}, err
	}
	s.foldCreateTiming(req.SessionUUID, res.Timing)
	return res.Session, nil
}

// foldCreateTiming folds one golden-image create's MEASURED §8 create→attach decomposition into
// the wired create-timing trend recorder (createtiming-feed): it splits the create's measured
// segments into the trigger-eligible §8 STACK (handed as the fold's stack) and the OPTIONAL
// trigger-EXCLUDED client RTT (handed separately so it never enters the server span, doc 15 §8),
// and drives the sink's RecordCreateTiming — the (b)-row "trends are recorded" producer.
//
// It is a FLAG-GATED no-op (createtiming-feed default-off byte-identical): with
// DS_ORCH_CREATETIMING_WIRE unset it returns immediately (no sink read, no map allocation), so the
// create path is byte-for-byte its prior behavior; the sink itself also no-ops the fold on a
// disabled wire (the loop self-armed from the SAME flag), a belt-and-suspenders second gate. It
// never fails a create: the fold is observability-only (measure-not-gate, D81/D32), so a fold error
// (a clock ran backwards on a synthetic span) is logged and swallowed — the session is already
// created. A nil sink (the fold leg unwired) or nil timing (the raw-coordinator path) is a no-op.
func (s *SessionService) foldCreateTiming(sessionUUID string, timing *createtiming.CreateTiming) {
	if !CreateTimingWireEnabled() || s.createTiming == nil || timing == nil {
		return
	}
	stack := make(map[createtiming.Segment]time.Duration, len(timing.Segments))
	var clientRTT time.Duration
	for seg, d := range timing.Segments {
		if seg == createtiming.SegClientRTT {
			clientRTT = d
			continue
		}
		if createtiming.IsStackSegment(seg) {
			stack[seg] = d
		}
	}
	if _, _, err := s.createTiming.RecordCreateTiming(sessionUUID, stack, clientRTT); err != nil {
		s.logger.Warn("controlplane: create-timing fold rejected a segment (observability-only, create unaffected; D81/D32)",
			slog.String("session", sessionUUID), slog.Any("err", err))
	}
}

// CreateTimingServerSpanTrend is the D81 (b)-row ADMIN/OBSERVABILITY read surface
// (createtiming-feed): the recorded trigger-eligible server-span trend across every create the
// fold leg observed (client RTT EXCLUDED, doc 15 §8) — the read side the (b)/(d)-rig instruments
// consume. It is a PURE read (no gate, no verdict — gating arms at M2, D81/D32). An unwired fold
// leg (SetCreateTimingServing not called) or a disabled wire (DS_ORCH_CREATETIMING_WIRE unset)
// returns an empty trend (Count 0), never an error — the trend is absent, not a failure.
func (s *SessionService) CreateTimingServerSpanTrend() createtiming.Trend {
	if s.createTiming == nil {
		return createtiming.Trend{}
	}
	return s.createTiming.CreateTimingServerSpanTrend()
}

// ListMeteringEvents is the D57 ADMIN/OBSERVABILITY read surface (createtiming-feed): the
// idempotent metering event stream recorded for a session (the billing state transitions + the
// D37 RSS/CPU/IO samples the metering-wire appends), newest-or-store-order as the store projects
// it. It is the read side the (b)/(d)-rig instruments consume to observe billing transitions.
//
// A missing session_uuid is an InvalidArgument refusal. An UNWIRED metering read leg (a
// test-narrowed store that does not enumerate metering events) refuses Unavailable — the clean
// degrade the other read legs use, never a silently empty stream that could be mistaken for a
// session with no events. A store read fault surfaces as Internal.
func (s *SessionService) ListMeteringEvents(ctx context.Context, sessionUUID string) ([]store.MeteringEvent, error) {
	if sessionUUID == "" {
		return nil, status.Error(codes.InvalidArgument, "controlplane: ListMeteringEvents requires a session_uuid")
	}
	if s.meteringRecords == nil {
		return nil, status.Error(codes.Unavailable, "controlplane: metering read leg not served (observability leg unwired)")
	}
	events, err := s.meteringRecords.ListMeteringEvents(ctx, sessionUUID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "controlplane: list metering events for session %q: %v", sessionUUID, err)
	}
	return events, nil
}

// resolveImageAndEntrypoint reads the checked-in env config to source the
// content-addressed image id (doc 15 §9) and the D38 entrypoint ref the create
// materializes. A missing env config is an InvalidArgument refusal (the second key is
// absent — the two-key step refuses it too, defense in depth); a store-unavailable is
// Unavailable (retry). When the env config records no explicit entrypoint, the
// env-config ref itself is the entrypoint key the host-side boot resolves from.
func (s *SessionService) resolveImageAndEntrypoint(ctx context.Context, envConfigRef string) (imageID, entrypointRef string, err error) {
	if s.envs == nil || envConfigRef == "" {
		// No reader wired (a test-narrowed handler) or no ref: defer image resolution to
		// the coordinator's two-key step; the entrypoint key is the env-config ref.
		return "", envConfigRef, nil
	}
	cfg, gerr := s.envs.GetEnvConfig(ctx, envConfigRef)
	if gerr != nil {
		if errors.Is(gerr, store.ErrNotFound) {
			// The second D56 key is absent at the pre-flight read. Surface the SAME
			// machine-readable reason the coordinator's two-key step carries (reason=no-env-spec)
			// so a client sees one consistent which-key signal whether the refusal lands here
			// (pre-flight) or at step 1 (defense in depth).
			return "", "", status.Errorf(codes.FailedPrecondition, "create refused (two-key D56, reason=%s): env config %q not found (the checked-in env spec, D56 second key)",
				sessions.ReasonNoEnvSpec, envConfigRef)
		}
		if errors.Is(gerr, store.ErrUnavailable) {
			return "", "", status.Errorf(codes.Unavailable, "controlplane: env config %q read stalled (store unavailable)", envConfigRef)
		}
		return "", "", status.Errorf(codes.Internal, "controlplane: env config %q read failed: %v", envConfigRef, gerr)
	}
	return cfg.ImageID, envConfigRef, nil
}

// mintSessionUUID mints the create's session UUID (the retry key). Uses the test seam
// when installed; otherwise a time-based value (the production default mints a UUID at
// the dial boundary — the orchestrator never recycles it, doc 15 §5.6).
func (s *SessionService) mintSessionUUID() string {
	if s.newSessionUUID != nil {
		return s.newSessionUUID()
	}
	return "sess-" + s.clock().UTC().Format("20060102T150405.000000000")
}

// sessionToProto projects the persisted store record onto the frozen orchestrator.v1
// Session wire message (doc 15 §5.6: this message is the wire projection the verbs
// return; the FULL record is store-internal). The SessionRef quartet, create-time refs,
// pinned role triple, lifecycle state (via the attach.v1 §3 vocabulary), and timestamps
// map field-for-field.
func sessionToProto(s store.Session) *orchestratorv1.Session {
	return &orchestratorv1.Session{
		SessionUuid:           s.Ref.SessionUUID,
		HostId:                s.Ref.HostID,
		HostSessionIndex:      s.Ref.HostSessionIndex,
		TapName:               s.Ref.TapName,
		EnvConfigRef:          s.EnvConfigRef,
		ImageId:               s.ImageID,
		LaunchingUser:         "", // resolved at the IdP boundary; not echoed on the record's wire face
		PinnedRoleName:        s.RolePin.Name,
		PinnedRoleVersion:     s.RolePin.Version,
		PinnedRoleContentHash: contentHashBytes(s.RolePin.ContentHash),
		State:                 &attachv1.SessionState{Name: stateNameToProto(s.State)},
		CreatedAt:             uint64(maxZero(s.CreatedAt.Unix())),
		UpdatedAt:             uint64(maxZero(s.UpdatedAt.Unix())),
		ParentSessionUuid:     s.ParentSessionUUID,
		HasWriter:             sessionHasWriter(s),
	}
}

// contentHashBytes carries the role content hash onto the wire bytes field (the
// roles/SCHEMA.md canonical content hash, recorded as a string on the record). An empty
// hash (a pre-pin record) carries nil.
func contentHashBytes(h string) []byte {
	if h == "" {
		return nil
	}
	return []byte(h)
}

// maxZero clamps a negative unix time to 0 (a zero-value timestamp on a record that
// never set it) so the uint64 conversion never wraps.
func maxZero(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// stateNameToProto maps the store's §3 SessionState onto the attach.v1.SessionStateName
// (the SINGLE §3 vocabulary source, doc 15 §3 / §6.1 row 3 — imported, never
// re-declared). An unknown state maps to UNSPECIFIED (defensive; the store vocabulary is
// vocabpin'd to the §3 set at build time, so this is never reached in practice).
func stateNameToProto(s store.SessionState) attachv1.SessionStateName {
	switch s {
	case store.SessionPending:
		return attachv1.SessionStateName_SESSION_STATE_NAME_PENDING
	case store.SessionCreating:
		return attachv1.SessionStateName_SESSION_STATE_NAME_CREATING
	case store.SessionReady:
		return attachv1.SessionStateName_SESSION_STATE_NAME_READY
	case store.SessionAttached:
		return attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED
	case store.SessionWorking:
		return attachv1.SessionStateName_SESSION_STATE_NAME_WORKING
	case store.SessionSnapshotting:
		return attachv1.SessionStateName_SESSION_STATE_NAME_SNAPSHOTTING
	case store.SessionMigrating:
		return attachv1.SessionStateName_SESSION_STATE_NAME_MIGRATING
	case store.SessionParked:
		return attachv1.SessionStateName_SESSION_STATE_NAME_PARKED
	case store.SessionSuspended:
		return attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED
	case store.SessionResuming:
		return attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING
	case store.SessionDestroying:
		return attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYING
	case store.SessionDestroyed:
		return attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED
	default:
		return attachv1.SessionStateName_SESSION_STATE_NAME_UNSPECIFIED
	}
}

// mapCreateError maps the coordinator's failure onto a gRPC status by failure CLASS
// (the frozen status semantics). The typed *sessions.CreateError carries the §4.1 step
// and the underlying error; the handler branches on the underlying error's sentinel,
// picking the code that tells the caller WHAT it must change to retry:
//
//   - the two-key refusal (D56: the repo is not enrolled / the env spec is missing) is a
//     structural precondition the create cannot proceed without → FailedPrecondition;
//   - the unauthenticated-launch refusal (doc 16 §11.2: no/invalid launching_user) is an
//     authorization failure, not a request the deployment can satisfy by retry as-is →
//     PermissionDenied (a distinct, attributable class from the two-key precondition);
//   - the role_ref refusal (doc 18 §6: unknown/schema-invalid/unresolvable ref) is a bad
//     argument in the request itself → InvalidArgument;
//   - the D72 policy-stale / D73 digest-not-acked gate refusals are transient host
//     posture → FailedPrecondition (the host is not placement-fresh / has not acked;
//     a retry may land elsewhere), distinguished by message;
//   - the CA-injection fail-closed (D17/D29) is a security-load-bearing failure →
//     FailedPrecondition (the create aborted before boot, never a half-trusted VM);
//   - a store-unavailable (Postgres-down degraded mode) → Unavailable (retry);
//   - anything else (a seam fault) → Internal, with the rollback cleanliness noted.
func mapCreateError(err error) error {
	var ce *sessions.CreateError
	if !errors.As(err, &ce) {
		// Not a coordinator error (e.g. a pre-flight): surface as Internal.
		return status.Error(codes.Internal, err.Error())
	}
	switch {
	case errors.Is(err, sessions.ErrTwoKeyRefused):
		// The two-key refusal carries a MACHINE-READABLE which-key reason (D56): the
		// client tells "not enrolled" (a repo admin must enroll the repo) from "no env
		// spec" (merge the onboarding PR) — the two distinct doc 07 §2a-spec failure
		// modes. The reason rides the status message; the code stays FailedPrecondition
		// (both are structural preconditions the create cannot proceed without).
		return status.Errorf(codes.FailedPrecondition, "create refused (two-key D56, reason=%s) at %s: %v",
			sessions.TwoKeyReasonOf(err), ce.Step, ce.Err)
	case errors.Is(err, sessions.ErrLaunchRefused):
		return status.Errorf(codes.PermissionDenied, "create refused (unauthenticated launch, doc 16 §11.2) at %s: %v", ce.Step, ce.Err)
	case sessions.ErrIsRoleRefused(err):
		return status.Errorf(codes.InvalidArgument, "create refused (role_ref doc 18 §6) at %s: %v", ce.Step, ce.Err)
	case errors.Is(err, sessions.ErrPolicyStale):
		return status.Errorf(codes.FailedPrecondition, "create unplaceable (host policy stale, D72) at %s: %v", ce.Step, ce.Err)
	case errors.Is(err, sessions.ErrDigestNotAcked):
		return status.Errorf(codes.FailedPrecondition, "create not routable (digest not acked, D73) at %s: %v", ce.Step, ce.Err)
	case sessions.ErrIsDigestNotRoutable(err):
		// The FLAG-GATED (DS_ORCH_DIGEST_PUBLISH_WIRE) create-side digest-publish routable
		// gate the spine drives BETWEEN cred-mint and mark-routable (doc 16 §6.1
		// mint-before-attach, D73/D84): an ARMED publish that failed closed — a publisher
		// wired-but-uncommitted ack (ErrDigestNotRoutable) OR armed-but-no-publisher
		// (ErrDigestPublisherUnwired). Like the step-9 digest-not-acked gate this is a
		// transient/structural host-posture precondition (the digests did not land, so the
		// session is not matchable and must not become routable) → FailedPrecondition,
		// ATTRIBUTABLE to the digest edge rather than surfaced as an opaque Internal. The
		// spine fuses this refusal into its step attribution (ce.Step reads the launch/
		// two-key position, the spine's coarse pre-host classification), so the message
		// carries the digest-axis cause explicitly.
		return status.Errorf(codes.FailedPrecondition, "create not routable (digest publish fail-closed, D73/D84 mint-before-attach) at %s: %v", ce.Step, ce.Err)
	case errors.Is(err, sessions.ErrCAInjection):
		return status.Errorf(codes.FailedPrecondition, "create aborted (CA injection failed fail-closed, D17/D29) at %s: %v", ce.Step, ce.Err)
	case errors.Is(err, store.ErrUnavailable):
		return status.Errorf(codes.Unavailable, "create stalled (store unavailable, degraded mode) at %s: %v", ce.Step, ce.Err)
	default:
		// A seam/store fault — surface as Internal, noting whether the compensating
		// rollback completed cleanly (an un-clean rollback is the reconciler's
		// orphan-reaping backstop, surfaced honestly rather than claimed clean).
		if ce.RollbackErr != nil {
			return status.Errorf(codes.Internal, "create failed at %s (ROLLBACK ALSO FAILED — reconciler backstop): %v", ce.Step, ce.Err)
		}
		return status.Errorf(codes.Internal, "create failed at %s (rolled back cleanly): %v", ce.Step, ce.Err)
	}
}
