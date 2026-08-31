// SPDX-License-Identifier: Apache-2.0

package orchestratorsession

import (
	"context"
	"sort"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// RefImpl is a minimal honest reference implementation of SessionService — the
// "real implementation" side of the dual-run. It implements exactly the doc 15
// §5.3 control-plane contract: CreateSession is idempotent on session_uuid
// (content-addressed on the create keys, so a re-issue returns the SAME session
// record — same SessionRef quartet — never a freshly-allocated second one), the
// lifecycle verbs drive the doc 15 §3 state machine onto the record, and Destroy
// follows the §4.2 ordering with an idempotent retry that SUCCEEDS rather than
// erroring NotFound.
//
// This is the M0 stand-in until the production orchestrator control plane (a
// skeleton today) lands. When that lands it replaces RefImpl as the "real" end
// and the conformance suite is unchanged — which is the whole point: the suite
// is the contract, not the implementation.
//
// State is held in-memory, keyed by session_uuid; access is mutex-guarded so the
// in-process gRPC server is safe under concurrent calls. Session uuids are
// content-derived from the create keys so the reference impl and a fake
// programmed to the same contract observe identically. Synthetic fixtures only
// (D50).
type RefImpl struct {
	orchestratorv1.UnimplementedSessionServiceServer

	mu       sync.Mutex
	sessions map[string]*orchestratorv1.Session
	nextIdx  uint64
	clock    uint64
}

// NewRefImpl returns a reference SessionService server with an empty store.
func NewRefImpl() *RefImpl {
	return &RefImpl{sessions: map[string]*orchestratorv1.Session{}}
}

// CreateSession runs the §4.1 canonical create and returns the created Session
// record (doc 15 §5.3). Idempotent on session_uuid: the uuid is derived
// deterministically from the create keys (repo_id + env_config_ref +
// launching_user), so a re-issue of the SAME content-addressed request finds the
// existing record and returns it verbatim — the SessionRef quartet
// (uuid/host/index/tap) is allocated ONCE and reused, never a duplicate
// (doc 15 §4.1 "create is retryable by session UUID").
func (s *RefImpl) CreateSession(_ context.Context, req *orchestratorv1.CreateSessionRequest) (*orchestratorv1.CreateSessionResponse, error) {
	if req.GetRepoId() == "" {
		return nil, status.Error(codes.InvalidArgument, "CreateSessionRequest.repo_id is required")
	}
	if req.GetEnvConfigRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "CreateSessionRequest.env_config_ref is required (the D56 second key)")
	}
	if req.GetLaunchingUser() == "" {
		return nil, status.Error(codes.InvalidArgument, "CreateSessionRequest.launching_user is required (the D99 attribution root)")
	}

	uuid := sessionUUID(req.GetRepoId(), req.GetEnvConfigRef(), req.GetLaunchingUser())

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.sessions[uuid]; ok {
		// Idempotent re-issue: same content-addressed request -> same record.
		return &orchestratorv1.CreateSessionResponse{Session: existing}, nil
	}

	idx := s.allocIndexLocked()
	now := s.tickLocked()
	rec := &orchestratorv1.Session{
		SessionUuid:      uuid,
		HostId:           synthHostID,
		HostSessionIndex: idx,
		TapName:          tapName(idx),
		EnvConfigRef:     req.GetEnvConfigRef(),
		ImageId:          imageID(req.GetEnvConfigRef()),
		LaunchingUser:    req.GetLaunchingUser(),
		State:            &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_READY},
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	s.sessions[uuid] = rec
	return &orchestratorv1.CreateSessionResponse{Session: rec}, nil
}

// DestroySession tears a session down, driving the doc 15 §4.2 ordering, and
// returns the terminal DESTROYED record (doc 15 §5.3). Idempotent: a retried
// Destroy on an already-gone session SUCCEEDS (it does not error NotFound) and
// returns the same terminal record — the orchestrator must be able to re-drive
// teardown safely. The terminal record is RETAINED (D66), never deleted, so the
// retry returns the same DESTROYED record verbatim.
func (s *RefImpl) DestroySession(_ context.Context, req *orchestratorv1.DestroySessionRequest) (*orchestratorv1.DestroySessionResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "DestroySessionRequest.session_uuid is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[uuid]
	if !ok {
		// Idempotent: a Destroy of an unknown/already-gone session SUCCEEDS,
		// returning a synthesized terminal record (doc 15 §4.2/§4.1 rollback).
		return &orchestratorv1.DestroySessionResponse{Session: terminalRecord(uuid)}, nil
	}
	rec.State = &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED}
	rec.UpdatedAt = s.tickLocked()
	return &orchestratorv1.DestroySessionResponse{Session: rec}, nil
}

// SuspendSession pauses a session with a D77-narrowed reason and returns the
// SUSPENDED record (doc 15 §4.3/§5.3). Idempotent: suspending an already-
// suspended session is a no-op acknowledged the same way.
func (s *RefImpl) SuspendSession(_ context.Context, req *orchestratorv1.SuspendSessionRequest) (*orchestratorv1.SuspendSessionResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "SuspendSessionRequest.session_uuid is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[uuid]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	rec.State = &attachv1.SessionState{
		Name:          attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED,
		SuspendReason: req.GetReason(),
	}
	rec.UpdatedAt = s.tickLocked()
	return &orchestratorv1.SuspendSessionResponse{Session: rec}, nil
}

// ResumeSession restarts a suspended session and returns the record (doc 15
// §4.3/§5.3). Idempotent: resuming a running session is a no-op.
func (s *RefImpl) ResumeSession(_ context.Context, req *orchestratorv1.ResumeSessionRequest) (*orchestratorv1.ResumeSessionResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "ResumeSessionRequest.session_uuid is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[uuid]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	rec.State = &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_READY}
	rec.UpdatedAt = s.tickLocked()
	return &orchestratorv1.ResumeSessionResponse{Session: rec}, nil
}

// SnapshotSession captures a session and returns the SNAPSHOTTING record
// (doc 15 §4.3/§5.3). Idempotent on session_uuid: a re-issue returns the same
// record.
func (s *RefImpl) SnapshotSession(_ context.Context, req *orchestratorv1.SnapshotSessionRequest) (*orchestratorv1.SnapshotSessionResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "SnapshotSessionRequest.session_uuid is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[uuid]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	rec.State = &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_SNAPSHOTTING}
	rec.UpdatedAt = s.tickLocked()
	return &orchestratorv1.SnapshotSessionResponse{Session: rec}, nil
}

// ListSessions enumerates the live fleet (doc 15 §5.3). Terminal (DESTROYED)
// records are RETAINED but excluded from the live enumeration. Results are
// ordered by host index so the report is deterministic (the suite compares the
// report shape across real and fake).
func (s *RefImpl) ListSessions(_ context.Context, req *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*orchestratorv1.Session, 0, len(s.sessions))
	for _, rec := range s.sessions {
		if rec.GetState().GetName() == attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED {
			continue
		}
		if hu := req.GetLaunchingUser(); hu != "" && rec.GetLaunchingUser() != hu {
			continue
		}
		if h := req.GetHostId(); h != "" && rec.GetHostId() != h {
			continue
		}
		out = append(out, rec)
	}
	sortSessionsByIndex(out)
	return &orchestratorv1.ListSessionsResponse{Sessions: out}, nil
}

// WatchSession is the D18 session-event fan-out leg (doc 15 §5.3). It streams the
// session's lifecycle as attach.v1.SessionEvent payloads — the doc 15 §3 state
// vocabulary, every event seq-numbered from M0 (the §6/§6.1 attach-event
// checklist). The reference impl emits a deterministic synthetic event leg
// derived from the session id so a fake programmed to the same derivation
// streams event-identically. Events at or before from_seq are skipped (the
// replay cursor, attach.v1.SessionEvent.seq).
func (s *RefImpl) WatchSession(req *orchestratorv1.WatchSessionRequest, stream grpc.ServerStreamingServer[orchestratorv1.WatchSessionResponse]) error {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return status.Error(codes.InvalidArgument, "WatchSessionRequest.session_uuid is required")
	}
	s.mu.Lock()
	_, ok := s.sessions[uuid]
	s.mu.Unlock()
	if !ok {
		return status.Error(codes.NotFound, "no such session")
	}
	for _, ev := range watchEvents(uuid) {
		if ev.GetEvent().GetSeq() <= req.GetFromSeq() {
			continue
		}
		if err := stream.Send(ev); err != nil {
			return err
		}
	}
	return nil
}

// Attach returns the D79 transport-ambivalent attach handle (doc 15 §5.4). The
// handle is attach.v1-owned (returned wrapped); the reference impl fills the
// session-scoped fields it owns and echoes the requested role.
func (s *RefImpl) Attach(_ context.Context, req *orchestratorv1.AttachRequest) (*orchestratorv1.AttachResponse, error) {
	uuid := req.GetSessionUuid()
	if uuid == "" {
		return nil, status.Error(codes.InvalidArgument, "AttachRequest.session_uuid is required")
	}
	s.mu.Lock()
	_, ok := s.sessions[uuid]
	s.mu.Unlock()
	if !ok {
		return nil, status.Error(codes.NotFound, "no such session")
	}
	return &orchestratorv1.AttachResponse{
		Handle: &attachv1.AttachHandle{
			SessionUuid: uuid,
			Role:        req.GetRole(),
		},
	}, nil
}

// CreateChildSession is RESERVED at M0, implemented M3 (doc 15 §5.3): the in-
// process leg derives a narrower child off the parent, links the parent_session
// hop, and returns the child record. The reference impl realizes the minimal
// honest in-process leg so the seam exercises the verb's success shape — the RPC
// message stays M0-reserved-until-M3 (no proto touched). The child uuid is
// content-derived from the parent + child references, so the verb is idempotent
// on the (parent, env, role) triple.
func (s *RefImpl) CreateChildSession(_ context.Context, req *orchestratorv1.CreateChildSessionRequest) (*orchestratorv1.CreateChildSessionResponse, error) {
	parent := req.GetParentSessionUuid()
	if parent == "" {
		return nil, status.Error(codes.InvalidArgument, "CreateChildSessionRequest.parent_session_uuid is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prec, ok := s.sessions[parent]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such parent session")
	}

	childUUID := childSessionUUID(parent, req.GetEnvConfigRef(), req.GetRoleRef())
	if existing, ok := s.sessions[childUUID]; ok {
		return &orchestratorv1.CreateChildSessionResponse{Session: existing}, nil
	}
	idx := s.allocIndexLocked()
	now := s.tickLocked()
	envRef := req.GetEnvConfigRef()
	if envRef == "" {
		envRef = prec.GetEnvConfigRef()
	}
	child := &orchestratorv1.Session{
		SessionUuid:       childUUID,
		HostId:            synthHostID,
		HostSessionIndex:  idx,
		TapName:           tapName(idx),
		EnvConfigRef:      envRef,
		ImageId:           imageID(envRef),
		LaunchingUser:     prec.GetLaunchingUser(),
		State:             &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_READY},
		CreatedAt:         now,
		UpdatedAt:         now,
		ParentSessionUuid: parent,
	}
	s.sessions[childUUID] = child
	return &orchestratorv1.CreateChildSessionResponse{Session: child}, nil
}

// RecordEnvConfig records a D7 env/build config and returns a REFERENCE (doc 15
// §5.3/§9). Idempotent: the ref is derived deterministically from the
// (repo_id, env_spec) content, so a re-issue returns the same ref.
func (s *RefImpl) RecordEnvConfig(_ context.Context, req *orchestratorv1.RecordEnvConfigRequest) (*orchestratorv1.RecordEnvConfigResponse, error) {
	if req.GetRepoId() == "" {
		return nil, status.Error(codes.InvalidArgument, "RecordEnvConfigRequest.repo_id is required")
	}
	return &orchestratorv1.RecordEnvConfigResponse{
		EnvConfigRef: &orchestratorv1.EnvConfigRef{Ref: envConfigRef(req.GetRepoId(), req.GetEnvSpec())},
	}, nil
}

// SeedSession installs a live session directly, so the suite can stand up a
// fleet ListSessions / WatchSession must report without first driving a create.
// It is a test affordance on the reference impl — not a contract verb. Synthetic
// fixtures only (D50).
func (s *RefImpl) SeedSession(uuid string, idx uint64, state attachv1.SessionStateName) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.tickLocked()
	s.sessions[uuid] = &orchestratorv1.Session{
		SessionUuid:      uuid,
		HostId:           synthHostID,
		HostSessionIndex: idx,
		TapName:          tapName(idx),
		EnvConfigRef:     synthEnvConfigRef,
		ImageId:          imageID(synthEnvConfigRef),
		LaunchingUser:    synthLaunchingUser,
		State:            &attachv1.SessionState{Name: state},
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	if idx >= s.nextIdx {
		s.nextIdx = idx + 1
	}
}

// HasSession reports whether the reference impl is tracking the session. It is a
// test affordance used by the fake-programming code to mirror the real impl's
// NotFound gating without re-implementing the store.
func (s *RefImpl) HasSession(uuid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.sessions[uuid]
	return ok
}

// Register registers the reference impl on a grpc.ServiceRegistrar.
func (s *RefImpl) Register(reg grpc.ServiceRegistrar) {
	orchestratorv1.RegisterSessionServiceServer(reg, s)
}

// allocIndexLocked hands out the next never-recycled per-host index (D66). The
// caller holds s.mu.
func (s *RefImpl) allocIndexLocked() uint64 {
	s.nextIdx++
	return s.nextIdx
}

// tickLocked advances the synthetic monotonic lifecycle clock (doc 15 §5.6
// metering input). The caller holds s.mu. Deterministic so created_at/updated_at
// are stable, but the suite never records raw timestamps (allocation detail).
func (s *RefImpl) tickLocked() uint64 {
	s.clock++
	return synthClockBase + s.clock
}

// ReadyState / SuspendedState / WorkingState expose the §3 state values the
// seam's fixtures use, so the external _test package can seed a mirror without
// importing attach.v1 directly. Synthetic fixtures only (D50).
func ReadyState() attachv1.SessionStateName {
	return attachv1.SessionStateName_SESSION_STATE_NAME_READY
}

func SuspendedState() attachv1.SessionStateName {
	return attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED
}

func WorkingState() attachv1.SessionStateName {
	return attachv1.SessionStateName_SESSION_STATE_NAME_WORKING
}

// WatchEventsFor exposes the deterministic synthetic event leg for a session so
// the external _test package can program an honest WatchSession responder on a
// hand-built fake (the negative-test drifted fake). Synthetic fixtures only
// (D50).
func WatchEventsFor(uuid string) []*orchestratorv1.WatchSessionResponse {
	return watchEvents(uuid)
}

// sortSessionsByIndex orders sessions by their never-recycled host index so
// ListSessions reports deterministically. Insertion-free stable sort: the slice
// is tiny.
func sortSessionsByIndex(xs []*orchestratorv1.Session) {
	sort.SliceStable(xs, func(i, j int) bool {
		return xs[i].GetHostSessionIndex() < xs[j].GetHostSessionIndex()
	})
}
