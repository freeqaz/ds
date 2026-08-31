package reconciler

// Synthetic test fakes + fixture builders (D50: synthetic fixtures only, no live
// VM/host-agent/podman). The reconciler's collaborators are all interfaces this
// package owns, so the whole convergence is exercised against these in-memory
// fakes plus the real *store.Memory desired-state store.

import (
	"context"
	"sync"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// fixedClock returns a deterministic, advanceable clock for the missed-beat math.
type fixedClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t time.Time) *fixedClock { return &fixedClock{t: t} }

func (c *fixedClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fixedClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// recordingDriver records every Suspend/Destroy the reconciler drives, so a test
// can assert exactly which convergence verbs fired (and, critically, that
// Destroy NEVER fires on the quarantine / missed-beat paths). suspendErr/
// destroyErr inject a driver fault for the failure-arm tests.
type recordingDriver struct {
	mu         sync.Mutex
	suspends   []*hypervisorv1.SuspendRequest
	destroys   []*hypervisorv1.DestroyRequest
	suspendErr error
	destroyErr error
}

func (d *recordingDriver) Suspend(_ context.Context, req *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.suspends = append(d.suspends, req)
	if d.suspendErr != nil {
		return nil, d.suspendErr
	}
	return &hypervisorv1.SuspendResponse{}, nil
}

func (d *recordingDriver) Destroy(_ context.Context, req *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.destroys = append(d.destroys, req)
	if d.destroyErr != nil {
		return nil, d.destroyErr
	}
	return &hypervisorv1.DestroyResponse{}, nil
}

func (d *recordingDriver) suspendCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.suspends)
}
func (d *recordingDriver) destroyCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.destroys)
}
func (d *recordingDriver) lastSuspend() *hypervisorv1.SuspendRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.suspends) == 0 {
		return nil
	}
	return d.suspends[len(d.suspends)-1]
}

// recordingRedriver records re-drive requests and optionally fails them (the
// fail-to-DESTROYED fallback arm of §3 rule b).
type recordingRedriver struct {
	mu       sync.Mutex
	redrives []string // session UUIDs requested
	err      error
}

func (rd *recordingRedriver) RedriveSession(_ context.Context, s store.Session) error {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	rd.redrives = append(rd.redrives, s.Ref.SessionUUID)
	return rd.err
}

func (rd *recordingRedriver) count() int { rd.mu.Lock(); defer rd.mu.Unlock(); return len(rd.redrives) }

// recordingAlarmer captures every Alarm the reconciler raises, so a test can
// assert the §3 audit/alarm events (quarantine, fail-to-DESTROYED, reconverge,
// host-UNKNOWN, degraded) and that the right ones fired.
type recordingAlarmer struct {
	mu     sync.Mutex
	alarms []Alarm
}

func (a *recordingAlarmer) Alarm(_ context.Context, al Alarm) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.alarms = append(a.alarms, al)
}

func (a *recordingAlarmer) byKind(k AlarmKind) []Alarm {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []Alarm
	for _, al := range a.alarms {
		if al.Kind == k {
			out = append(out, al)
		}
	}
	return out
}

func (a *recordingAlarmer) has(k AlarmKind) bool { return len(a.byKind(k)) > 0 }

// degradedStore wraps a RecordStore and forces store.ErrUnavailable on the
// chosen methods — the Postgres-DOWN degraded mode (doc 15 §3). It lets a test
// assert the reconciler STALLS (no driver verb, no state write) rather than
// destroying/quarantining on a store outage.
type degradedStore struct {
	inner      RecordStore
	failList   bool
	failUpdate bool
	updateErr  error // when set, UpdateSession returns THIS (a non-degraded fault)
}

func (s *degradedStore) ListSessions(ctx context.Context, f store.SessionFilter) ([]store.Session, error) {
	if s.failList {
		return nil, store.ErrUnavailable
	}
	return s.inner.ListSessions(ctx, f)
}

func (s *degradedStore) UpdateSession(ctx context.Context, uuid string, u store.SessionUpdate) (store.Session, error) {
	if s.updateErr != nil {
		return store.Session{}, s.updateErr
	}
	if s.failUpdate {
		return store.Session{}, store.ErrUnavailable
	}
	return s.inner.UpdateSession(ctx, uuid, u)
}

// --- fixture builders ---

// observedSession builds a synthetic ObservedSession for a host's heartbeat /
// re-adoption set, in the given §3 state.
func observedSession(sessionUUID, domainUUID string, idx uint64, st store.SessionState) *hypervisorv1.ObservedSession {
	return &hypervisorv1.ObservedSession{
		SessionUuid:      sessionUUID,
		DomainUuid:       domainUUID,
		HostSessionIndex: idx,
		TapName:          "dstap-0",
		OverlayPath:      "/overlays/" + sessionUUID + ".qcow2",
		ObservedState:    observedStateProto(st),
	}
}

// observedSessionNoState builds an observed element whose state the host could
// not pin down (UNSPECIFIED) — the un-pin-downable observation path.
func observedSessionNoState(sessionUUID string) *hypervisorv1.ObservedSession {
	return &hypervisorv1.ObservedSession{
		SessionUuid: sessionUUID,
		DomainUuid:  "dom-" + sessionUUID,
	}
}

// observedStateProto maps a store state back to the attach.v1 wire state for
// fixtures (the inverse of states.go's stateNameToStore). Returns nil for an
// unknown state (UNSPECIFIED).
func observedStateProto(st store.SessionState) *attachv1.SessionState {
	var name attachv1.SessionStateName
	switch st {
	case store.SessionPending:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_PENDING
	case store.SessionCreating:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_CREATING
	case store.SessionReady:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_READY
	case store.SessionAttached:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED
	case store.SessionWorking:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_WORKING
	case store.SessionSnapshotting:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_SNAPSHOTTING
	case store.SessionMigrating:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_MIGRATING
	case store.SessionParked:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_PARKED
	case store.SessionSuspended:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED
	case store.SessionResuming:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING
	case store.SessionDestroying:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYING
	case store.SessionDestroyed:
		name = attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED
	default:
		return nil
	}
	return &attachv1.SessionState{Name: name}
}

// heartbeat wraps an observed set into a Heartbeat for the host.
func heartbeat(hostID string, observed ...*hypervisorv1.ObservedSession) *hostagentv1.Heartbeat {
	return &hostagentv1.Heartbeat{HostId: hostID, Observed: observed}
}

// seedRecord writes a desired record in the given host/state into the store.
func seedRecord(t testingT, st *store.Memory, sessionUUID, hostID string, idx uint64, state store.SessionState) store.Session {
	t.Helper()
	s := store.Session{
		Ref: store.SessionRef{
			SessionUUID:      sessionUUID,
			HostID:           hostID,
			HostSessionIndex: idx,
			TapName:          "dstap-0",
		},
		State: state,
	}
	// SUSPENDED requires a reason (store invariant); supply the user reason for
	// fixtures that seed a suspended record.
	if state == store.SessionSuspended {
		s.SuspendReason = store.SuspendReasonUser
	}
	out, err := st.CreateSession(context.Background(), s)
	if err != nil {
		t.Fatalf("seedRecord %s: %v", sessionUUID, err)
	}
	return out
}

// testingT is the minimal *testing.T surface seedRecord needs (Helper/Fatalf),
// so the fixture builder stays usable from any test without importing testing in
// this file's signature noise.
type testingT interface {
	Helper()
	Fatalf(format string, args ...any)
}
