// SPDX-License-Identifier: Apache-2.0

package orchestratorsession

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"
)

// Synthetic fixtures (D50). Every identifier is obviously-synthetic — no real
// session ids, repos, users, or hosts. The create-key fixtures are stable so the
// suite's idempotency scenarios can re-issue the same content-addressed
// CreateSession. synthSeededA / synthSeededB are reserved for the ListSessions /
// WatchSession readback: both dialers pre-seed them (the standing live fleet)
// and NO mutating scenario touches them, so the enumeration is stable regardless
// of scenario order. Every mutating scenario drives its own dedicated create
// keys so scenarios stay independent across the shared in-process connection.
const (
	synthSeededA = "ses-aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa"
	synthSeededB = "ses-bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb"

	synthHostID        = "host-synthetic-01"
	synthLaunchingUser = "user-synthetic-alice"
	synthEnvConfigRef  = "envref-synthetic-cafef00d"

	synthRepoCreate  = "repo-synthetic-create"
	synthRepoDestroy = "repo-synthetic-destroy"
	synthRepoList    = "repo-synthetic-list"
	synthRepoSuspend = "repo-synthetic-suspend"
	synthRepoSnap    = "repo-synthetic-snapshot"
	synthRepoWatch   = "repo-synthetic-watch"
	synthRepoAttach  = "repo-synthetic-attach"
	synthRepoChild   = "repo-synthetic-child"
	synthRepoEnv     = "repo-synthetic-env"

	synthEnvA = "envref-synthetic-aaaa1111"
	synthEnvB = "envref-synthetic-bbbb2222"

	synthIndexA = uint64(101)
	synthIndexB = uint64(102)

	synthClockBase = uint64(1_700_000_000)
)

// Suite is the orchestrator-session seam's single conformance suite (doc 06 §3a:
// one suite, run against real + fake). Every scenario is stated purely in terms
// of the frozen orchestrator.v1 SessionService contract so the same suite is
// meaningful against any faithful implementation. It drives every SessionService
// verb's success path and asserts the properties the contract turns on
// (doc 15 §5.3/§4.2): CreateSession IDEMPOTENCY on session_uuid, the §4.2
// DestroySession teardown + idempotent retry, ListSessions enumeration, the
// WatchSession event leg, and the remaining lifecycle verbs.
func Suite() dualrun.Suite {
	return dualrun.Suite{
		Seam:      "client/console<->orchestrator(SessionService)",
		Scenarios: scenarios(),
	}
}

func scenarios() []dualrun.Scenario {
	return []dualrun.Scenario{
		{
			Name: "create-session/idempotent-on-session-uuid",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				req := createReq(synthRepoCreate, synthEnvA, synthLaunchingUser, "")
				first, err := cl.CreateSession(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				// Re-issue the SAME content-addressed request: idempotent on
				// session_uuid (doc 15 §4.1) — the record must be identical, not a
				// freshly-allocated second one with a new SessionRef quartet.
				second, err := cl.CreateSession(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("idempotent_record", "%t", sessionsEqual(first.GetSession(), second.GetSession()))
				return recordObservation(obs, second.GetSession()), nil
			},
		},
		{
			Name: "create-session/two-key-refusal-without-env-config",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				// The D56 two-key structural refusal: a create missing the second
				// key (env_config_ref) is refused before any VM is materialized.
				_, err := cl.CreateSession(ctx, &orchestratorv1.CreateSessionRequest{
					RepoId:        synthRepoCreate,
					LaunchingUser: synthLaunchingUser,
				})
				obs := dualrun.NewObservation()
				obs.Set("status", status.Code(err).String())
				return obs, nil
			},
		},
		{
			Name: "destroy-session/teardown-ordering-and-idempotent-retry",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				created, err := cl.CreateSession(ctx, createReq(synthRepoDestroy, synthEnvA, synthLaunchingUser, ""))
				if err != nil {
					return errObservation(err), nil
				}
				uuid := created.GetSession().GetSessionUuid()
				req := &orchestratorv1.DestroySessionRequest{SessionUuid: uuid}
				// First destroy drives the §4.2 ordering -> terminal DESTROYED record.
				first, err := cl.DestroySession(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				// Retried Destroy on an already-gone session SUCCEEDS (idempotent
				// teardown, doc 15 §4.2) — it must NOT error NotFound, and returns
				// the same terminal DESTROYED record.
				second, retryErr := cl.DestroySession(ctx, req)
				obs := dualrun.NewObservation()
				obs.Set("first_status", codes.OK.String())
				obs.Set("first_state", first.GetSession().GetState().GetName().String())
				obs.Set("retry_status", status.Code(retryErr).String())
				if retryErr == nil {
					obs.Set("retry_state", second.GetSession().GetState().GetName().String())
				}
				return obs, nil
			},
		},
		{
			Name: "list-sessions/enumerates-live-fleet",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				// Enumerate the live fleet scoped to launching_user. Both ends
				// pre-seeded the SAME two synthetic sessions and accumulate the SAME
				// scenario-created sessions in the SAME order (the dual-run drives one
				// shared connection per end through the scenario list sequentially), so
				// the enumeration — count and per-row shape — is identical real-vs-fake
				// regardless of which earlier same-user sessions are still live. The
				// suite asserts only that agreement, never an absolute count.
				resp, err := cl.ListSessions(ctx, &orchestratorv1.ListSessionsRequest{LaunchingUser: synthLaunchingUser})
				if err != nil {
					return errObservation(err), nil
				}
				return listObservation(resp), nil
			},
		},
		{
			Name: "suspend-resume/round-trip-acknowledged",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				created, err := cl.CreateSession(ctx, createReq(synthRepoSuspend, synthEnvA, synthLaunchingUser, ""))
				if err != nil {
					return errObservation(err), nil
				}
				uuid := created.GetSession().GetSessionUuid()
				susp, err := cl.SuspendSession(ctx, &orchestratorv1.SuspendSessionRequest{
					SessionUuid: uuid,
					Reason:      attachv1.SuspendReason_SUSPEND_REASON_USER,
				})
				if err != nil {
					return errObservation(err), nil
				}
				res, err := cl.ResumeSession(ctx, &orchestratorv1.ResumeSessionRequest{SessionUuid: uuid})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("suspended_state", susp.GetSession().GetState().GetName().String())
				obs.Set("suspend_reason", susp.GetSession().GetState().GetSuspendReason().String())
				obs.Set("resumed_state", res.GetSession().GetState().GetName().String())
				return obs, nil
			},
		},
		{
			Name: "snapshot-session/drives-snapshotting-state",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				created, err := cl.CreateSession(ctx, createReq(synthRepoSnap, synthEnvA, synthLaunchingUser, ""))
				if err != nil {
					return errObservation(err), nil
				}
				uuid := created.GetSession().GetSessionUuid()
				req := &orchestratorv1.SnapshotSessionRequest{SessionUuid: uuid, Label: "synthetic-label"}
				first, err := cl.SnapshotSession(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				// Idempotent on session_uuid: re-issue is a no-op on the record.
				second, err := cl.SnapshotSession(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("state", second.GetSession().GetState().GetName().String())
				obs.Setf("idempotent_uuid", "%t", first.GetSession().GetSessionUuid() == second.GetSession().GetSessionUuid())
				return obs, nil
			},
		},
		{
			Name: "watch-session/streams-seq-numbered-event-leg",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				// Watch the standing seeded session (no mutation). The D18 fan-out
				// leg carries attach.v1.SessionEvent — the §3 state vocabulary, every
				// event seq-numbered from M0 (doc 15 §6/§6.1). Both ends emit the same
				// deterministic synthetic leg, so the framing must match.
				stream, err := cl.WatchSession(ctx, &orchestratorv1.WatchSessionRequest{SessionUuid: synthSeededA})
				if err != nil {
					return errObservation(err), nil
				}
				return watchStreamObservation(stream), nil
			},
		},
		{
			Name: "watch-session/from-seq-replay-cursor-skips-acked",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				// from_seq is the replay cursor (attach.v1.SessionEvent.seq): events
				// at or before it are skipped, so a reader resuming mid-stream sees
				// only the tail. Both ends honor the same cursor.
				stream, err := cl.WatchSession(ctx, &orchestratorv1.WatchSessionRequest{
					SessionUuid: synthSeededA,
					FromSeq:     1,
				})
				if err != nil {
					return errObservation(err), nil
				}
				return watchStreamObservation(stream), nil
			},
		},
		{
			Name: "attach/echoes-session-and-role",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				created, err := cl.CreateSession(ctx, createReq(synthRepoAttach, synthEnvA, synthLaunchingUser, ""))
				if err != nil {
					return errObservation(err), nil
				}
				uuid := created.GetSession().GetSessionUuid()
				resp, err := cl.Attach(ctx, &orchestratorv1.AttachRequest{
					SessionUuid: uuid,
					Role:        attachv1.Role_ROLE_WRITER,
				})
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Set("handle_session_uuid", resp.GetHandle().GetSessionUuid())
				obs.Set("handle_role", resp.GetHandle().GetRole().String())
				return obs, nil
			},
		},
		{
			Name: "create-child-session/links-parent-and-inherits-user",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				parent, err := cl.CreateSession(ctx, createReq(synthRepoChild, synthEnvA, synthLaunchingUser, ""))
				if err != nil {
					return errObservation(err), nil
				}
				parentUUID := parent.GetSession().GetSessionUuid()
				req := &orchestratorv1.CreateChildSessionRequest{
					ParentSessionUuid: parentUUID,
					EnvConfigRef:      synthEnvB,
					RoleRef:           "roleref-synthetic-child",
					RequestedBy:       synthLaunchingUser,
				}
				first, err := cl.CreateChildSession(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				// Idempotent on the (parent, env, role) triple.
				second, err := cl.CreateChildSession(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("parent_linked", "%t", first.GetSession().GetParentSessionUuid() == parentUUID)
				obs.Set("inherited_user", first.GetSession().GetLaunchingUser())
				obs.Set("child_state", first.GetSession().GetState().GetName().String())
				obs.Setf("idempotent_child", "%t", first.GetSession().GetSessionUuid() == second.GetSession().GetSessionUuid())
				return obs, nil
			},
		},
		{
			Name: "record-env-config/idempotent-reference",
			Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
				cl := orchestratorv1.NewSessionServiceClient(conn)
				req := &orchestratorv1.RecordEnvConfigRequest{
					RepoId:  synthRepoEnv,
					EnvSpec: []byte("synthetic-env-spec-body"),
				}
				first, err := cl.RecordEnvConfig(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				// Idempotent: the ref is content-derived, so a re-issue matches.
				second, err := cl.RecordEnvConfig(ctx, req)
				if err != nil {
					return errObservation(err), nil
				}
				obs := dualrun.NewObservation()
				obs.Set("status", codes.OK.String())
				obs.Setf("has_ref", "%t", second.GetEnvConfigRef().GetRef() != "")
				obs.Setf("idempotent_ref", "%t", first.GetEnvConfigRef().GetRef() == second.GetEnvConfigRef().GetRef())
				return obs, nil
			},
		},
	}
}

// --- Observation builders ----------------------------------------------------

func errObservation(err error) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", status.Code(err).String())
	return obs
}

// recordObservation records the contract-observable SHAPE of a session record:
// the create-time references (derived from session identity, so stable), the
// never-recycled index/tap PRESENCE, the §3 state, and the host id. The raw host
// index/timestamps are intentionally NOT recorded — their values are allocation
// details; the idempotency fact (re-issue returns the same record) is asserted
// separately via idempotent_record.
func recordObservation(obs *dualrun.Observation, s *orchestratorv1.Session) *dualrun.Observation {
	obs.Set("host_id", s.GetHostId())
	obs.Setf("has_host_index", "%t", s.GetHostSessionIndex() != 0)
	obs.Setf("has_tap_name", "%t", s.GetTapName() != "")
	obs.Set("env_config_ref", s.GetEnvConfigRef())
	obs.Set("image_id", s.GetImageId())
	obs.Set("launching_user", s.GetLaunchingUser())
	obs.Set("state", s.GetState().GetName().String())
	return obs
}

// sessionsEqual reports whether two session records share the SessionRef quartet
// and create-time references — the idempotency anchor (a re-issue returns the
// SAME record, not a freshly-allocated one).
func sessionsEqual(a, b *orchestratorv1.Session) bool {
	return a.GetSessionUuid() == b.GetSessionUuid() &&
		a.GetHostId() == b.GetHostId() &&
		a.GetHostSessionIndex() == b.GetHostSessionIndex() &&
		a.GetTapName() == b.GetTapName() &&
		a.GetEnvConfigRef() == b.GetEnvConfigRef() &&
		a.GetImageId() == b.GetImageId() &&
		a.GetLaunchingUser() == b.GetLaunchingUser()
}

// listObservation records the live-fleet enumeration shape: the count and, per
// session (ordered by host index), the observable join keys and §3 state. This
// is the console/fleet view (doc 15 §5.3), so the suite proves the enumeration
// matches across real and fake.
func listObservation(resp *orchestratorv1.ListSessionsResponse) *dualrun.Observation {
	obs := dualrun.NewObservation()
	obs.Set("status", codes.OK.String())
	obs.Setf("listed_count", "%d", len(resp.GetSessions()))
	for i, s := range resp.GetSessions() {
		obs.Set(indexKey("uuid", i), s.GetSessionUuid())
		obs.Setf(indexKey("index", i), "%d", s.GetHostSessionIndex())
		obs.Set(indexKey("tap", i), s.GetTapName())
		obs.Set(indexKey("state", i), s.GetState().GetName().String())
	}
	return obs
}

// watchStreamObservation drains the WatchSession stream and records the event
// count plus, per event, the contract-observable shape: the sequence number
// (attach.v1.SessionEvent.seq), the event type, and the §3 state name the
// session-state payload carries. This is the D18 fan-out leg's observable
// framing (doc 15 §5.3/§6.1).
func watchStreamObservation(stream grpc.ServerStreamingClient[orchestratorv1.WatchSessionResponse]) *dualrun.Observation {
	obs := dualrun.NewObservation()
	var n int
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			obs.Set("status", codes.OK.String())
			break
		}
		if err != nil {
			obs.Set("status", status.Code(err).String())
			break
		}
		ev := resp.GetEvent()
		obs.Setf(indexKey("seq", n), "%d", ev.GetSeq())
		obs.Set(indexKey("type", n), ev.GetType().String())
		obs.Set(indexKey("state", n), ev.GetSessionState().GetName().String())
		n++
	}
	obs.Setf("event_count", "%d", n)
	return obs
}

func indexKey(field string, i int) string {
	return "event[" + decimal(uint64(i)) + "]." + field
}

// --- synthetic fixture constructors (D50) ------------------------------------

func createReq(repoID, envRef, user, roleRef string) *orchestratorv1.CreateSessionRequest {
	return &orchestratorv1.CreateSessionRequest{
		RepoId:        repoID,
		EnvConfigRef:  envRef,
		LaunchingUser: user,
		RoleRef:       roleRef,
	}
}

// --- deterministic synthetic derivations (D50) ------------------------------
//
// All of the following are obviously-synthetic, deterministic functions of the
// create identity so the reference impl and a fake programmed to the same
// contract observe identically. None contains a real session id, repo, user, or
// host.

// sessionUUID derives the content-addressed session uuid from the create keys —
// the idempotency anchor (a re-issue with the same keys finds the same record).
func sessionUUID(repoID, envRef, user string) string {
	return "ses-" + shortDigest("create/"+repoID+"/"+envRef+"/"+user)
}

func childSessionUUID(parent, envRef, roleRef string) string {
	return "ses-child-" + shortDigest("child/"+parent+"/"+envRef+"/"+roleRef)
}

func tapName(idx uint64) string {
	return "dstap-" + decimal(idx)
}

func imageID(envRef string) string {
	return "img-synthetic-" + shortDigest("image/"+envRef)
}

func envConfigRef(repoID string, envSpec []byte) string {
	return "envref-synthetic-" + shortDigest("envconfig/"+repoID+"/"+string(envSpec))
}

// terminalRecord synthesizes the terminal DESTROYED record an idempotent Destroy
// of an unknown/already-gone session returns (doc 15 §4.2). It carries only the
// uuid and the DESTROYED state — the rest of the quartet is already gone.
func terminalRecord(uuid string) *orchestratorv1.Session {
	return &orchestratorv1.Session{
		SessionUuid: uuid,
		State:       &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED},
	}
}

// watchEvents returns a short deterministic synthetic SessionEvent leg for a
// session (two seq-numbered session-state events: READY then WORKING). Content
// is derived from the session id, so a fake programmed to the same derivation
// streams event-identically. Every event carries a sequence number from M0
// (attach.v1.SessionEvent.seq) — the §6/§6.1 attach-event checklist.
func watchEvents(uuid string) []*orchestratorv1.WatchSessionResponse {
	return []*orchestratorv1.WatchSessionResponse{
		{Event: stateEvent(1, uuid, attachv1.SessionStateName_SESSION_STATE_NAME_READY)},
		{Event: stateEvent(2, uuid, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)},
	}
}

func stateEvent(seq uint64, uuid string, name attachv1.SessionStateName) *attachv1.SessionEvent {
	return &attachv1.SessionEvent{
		Seq:       seq,
		SessionId: uuid,
		Type:      attachv1.EventType_EVENT_TYPE_SESSION_STATE,
		Payload: &attachv1.SessionEvent_SessionState{
			SessionState: &attachv1.SessionState{Name: name},
		},
	}
}

func shortDigest(s string) string {
	sum := sha256.Sum256([]byte("ds-synthetic/" + s))
	return hex.EncodeToString(sum[:6])
}

func decimal(n uint64) string {
	var b [20]byte
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// --- dialers: real reference impl AND the generated fake --------------------
//
// Both ends of the seam need a matched pair of dialers (one for the real impl,
// one for the fake) pre-seeded with the SAME standing live fleet, so the only
// thing that varies across the two dual-run passes is which server is registered.

// RealDialer returns the dual-run Dialer for the reference impl. It pre-seeds the
// two synthetic sessions ListSessions / WatchSession enumerate — the standing
// live fleet (doc 15 §5.3).
func RealDialer() dualrun.Dialer {
	impl := NewRefImpl()
	impl.SeedSession(synthSeededA, synthIndexA, attachv1.SessionStateName_SESSION_STATE_NAME_READY)
	impl.SeedSession(synthSeededB, synthIndexB, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)
	return dualrun.InProcess(impl.Register)
}

// FakeDialer returns the dual-run Dialer for the GENERATED programmable fake,
// programmed to the same contract Suite() asserts. The fake is driven only
// through its canned-response surface; the dual-run proves it is observationally
// identical to the real impl on every scenario. The fake is pre-seeded (via its
// mirror) with the two synthetic sessions the enumeration legs read.
func FakeDialer() dualrun.Dialer {
	f, mirror := programmedFake()
	mirror.SeedSession(synthSeededA, synthIndexA, attachv1.SessionStateName_SESSION_STATE_NAME_READY)
	mirror.SeedSession(synthSeededB, synthIndexB, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING)
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		orchestratorv1fake.RegisterSessionService(s, f)
	})
}

// programmedFake programs the generated fake to the honest contract by routing
// its per-verb responders at a mirror RefImpl — so the fake and the real impl
// share one honest behavior definition (idempotency on session_uuid, the §4.2
// idempotent Destroy, the WatchSession event leg). It returns both the fake (to
// register) and the mirror (so a dialer can pre-seed the standing fleet). This is
// the programmable-fake-driven-only-through-its-surface pattern (doc 06 §2.1):
// the dual-run still proves the fake observationally matches the production impl
// when it lands, because the suite never touches the mirror directly. The
// WatchSession responder is wired explicitly because the fake's streaming surface
// is a []resp responder (collect-then-Send), not a server-stream method.
func programmedFake() (*orchestratorv1fake.SessionServiceFake, *RefImpl) {
	f := orchestratorv1fake.NewSessionServiceFake()
	mirror := NewRefImpl()

	f.CreateSessionResponder = mirror.CreateSession
	f.DestroySessionResponder = mirror.DestroySession
	f.SuspendSessionResponder = mirror.SuspendSession
	f.ResumeSessionResponder = mirror.ResumeSession
	f.SnapshotSessionResponder = mirror.SnapshotSession
	f.ListSessionsResponder = mirror.ListSessions
	f.AttachResponder = mirror.Attach
	f.CreateChildSessionResponder = mirror.CreateChildSession
	f.RecordEnvConfigResponder = mirror.RecordEnvConfig
	f.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		if req.GetSessionUuid() == "" {
			return nil, status.Error(codes.InvalidArgument, "WatchSessionRequest.session_uuid is required")
		}
		if !mirror.HasSession(req.GetSessionUuid()) {
			return nil, status.Error(codes.NotFound, "no such session")
		}
		var out []*orchestratorv1.WatchSessionResponse
		for _, ev := range watchEvents(req.GetSessionUuid()) {
			if ev.GetEvent().GetSeq() <= req.GetFromSeq() {
				continue
			}
			out = append(out, ev)
		}
		return out, nil
	}
	return f, mirror
}
