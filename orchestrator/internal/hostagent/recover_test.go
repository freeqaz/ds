package hostagent

import (
	"context"
	"errors"
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// fakeHandleStore is an in-memory HandleStore: the host-local persistence a real
// agent would back with a durable on-host store (NOT control-plane Postgres, D6).
type fakeHandleStore struct {
	byHost map[string][]PersistedHandle
	err    error
}

func (f *fakeHandleStore) ListHandles(_ context.Context, hostID string) ([]PersistedHandle, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byHost[hostID], nil
}

func state(name attachv1.SessionStateName) *attachv1.SessionState {
	return &attachv1.SessionState{Name: name}
}

// TestRecoverSessions_ReadoptsPersistedHandles verifies a restart re-adopts the
// running set from persisted handles, reconstructing the shared ObservedSession
// element field-for-field.
func TestRecoverSessions_ReadoptsPersistedHandles(t *testing.T) {
	store := &fakeHandleStore{byHost: map[string][]PersistedHandle{
		"host-A": {
			{
				SessionUUID:      "sess-1",
				DomainUUID:       "dom-1",
				HostSessionIndex: 3,
				TapName:          "dstap-3",
				OverlayPath:      "/var/lib/ds/overlays/sess-1.qcow2",
				ObservedState:    state(attachv1.SessionStateName_SESSION_STATE_NAME_WORKING),
			},
			{
				SessionUUID:      "sess-2",
				DomainUUID:       "dom-2",
				HostSessionIndex: 7,
				TapName:          "dstap-7",
				OverlayPath:      "/var/lib/ds/overlays/sess-2.qcow2",
				ObservedState:    state(attachv1.SessionStateName_SESSION_STATE_NAME_PARKED),
			},
		},
	}}

	resp, err := RecoverSessions(context.Background(), store, &hypervisorv1.RecoverSessionsRequest{HostId: "host-A"})
	if err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}
	if len(resp.GetSessions()) != 2 {
		t.Fatalf("re-adopted %d sessions, want 2", len(resp.GetSessions()))
	}
	got := resp.GetSessions()[0]
	if got.GetSessionUuid() != "sess-1" || got.GetDomainUuid() != "dom-1" {
		t.Fatalf("session identity not reconstructed: %+v", got)
	}
	if got.GetHostSessionIndex() != 3 || got.GetTapName() != "dstap-3" {
		t.Fatalf("host handle binding not reconstructed: %+v", got)
	}
	if got.GetOverlayPath() != "/var/lib/ds/overlays/sess-1.qcow2" {
		t.Fatalf("overlay path not reconstructed: %+v", got)
	}
	if got.GetObservedState().GetName() != attachv1.SessionStateName_SESSION_STATE_NAME_WORKING {
		t.Fatalf("observed state not reconstructed: %+v", got.GetObservedState())
	}
	// The §3 state vocabulary survives re-adoption: PARKED is a first-class state.
	if resp.GetSessions()[1].GetObservedState().GetName() != attachv1.SessionStateName_SESSION_STATE_NAME_PARKED {
		t.Fatalf("PARKED session not re-adopted with its state")
	}
}

// TestRecoverSessions_EmptyHostIsNotAnError verifies a host with no persisted
// handles re-adopts an EMPTY set cleanly (a fresh host / drained host), not an
// error.
func TestRecoverSessions_EmptyHostIsNotAnError(t *testing.T) {
	store := &fakeHandleStore{byHost: map[string][]PersistedHandle{}}
	resp, err := RecoverSessions(context.Background(), store, &hypervisorv1.RecoverSessionsRequest{HostId: "host-empty"})
	if err != nil {
		t.Fatalf("RecoverSessions on empty host: %v", err)
	}
	if len(resp.GetSessions()) != 0 {
		t.Fatalf("expected empty re-adoption, got %d", len(resp.GetSessions()))
	}
}

func TestRecoverSessions_RejectsEmptyHostID(t *testing.T) {
	store := &fakeHandleStore{}
	_, err := RecoverSessions(context.Background(), store, &hypervisorv1.RecoverSessionsRequest{HostId: ""})
	if err == nil {
		t.Fatal("RecoverSessions accepted an empty host_id")
	}
}

// TestRecoverSessions_StoreErrorIsLoud verifies a persistence read failure fails
// LOUDLY rather than presenting an empty set (which would orphan running VMs).
func TestRecoverSessions_StoreErrorIsLoud(t *testing.T) {
	store := &fakeHandleStore{err: errors.New("disk read failed")}
	_, err := RecoverSessions(context.Background(), store, &hypervisorv1.RecoverSessionsRequest{HostId: "host-A"})
	if err == nil {
		t.Fatal("a store read failure must surface as an error, never an empty re-adoption")
	}
}

// TestRestoreCounter_ResumesAboveLiveHighWaterMark pins the never-recycle floor
// (D66): the restored counter is strictly greater than every re-adopted index,
// so the next allocation cannot collide with a currently-running session.
func TestRestoreCounter_ResumesAboveLiveHighWaterMark(t *testing.T) {
	handles := []PersistedHandle{
		{HostSessionIndex: 3},
		{HostSessionIndex: 7},
		{HostSessionIndex: 5},
	}
	if got := RestoreCounter(handles); got != 8 {
		t.Fatalf("RestoreCounter = %d, want 8 (one past the high-water mark 7)", got)
	}
}

// TestRestoreCounter_FreshHostStartsAtOne verifies index 0 stays reserved as
// "unallocated" (the proto zero value): a fresh host's first index is 1.
func TestRestoreCounter_FreshHostStartsAtOne(t *testing.T) {
	if got := RestoreCounter(nil); got != 1 {
		t.Fatalf("RestoreCounter(nil) = %d, want 1", got)
	}
}

// TestObservedFromHandles_MatchesRecoverProjection verifies the heartbeat's
// post-restart seeding goes through the SAME mapping RecoverSessions uses, so
// re-adoption and the steady-state heartbeat can never project a handle two
// different ways.
func TestObservedFromHandles_MatchesRecoverProjection(t *testing.T) {
	handles := []PersistedHandle{
		{
			SessionUUID:      "s",
			DomainUUID:       "d",
			HostSessionIndex: 9,
			TapName:          "dstap-9",
			OverlayPath:      "/o",
			ObservedState:    state(attachv1.SessionStateName_SESSION_STATE_NAME_READY),
		},
	}

	viaHeartbeat := ObservedFromHandles(handles)

	store := &fakeHandleStore{byHost: map[string][]PersistedHandle{"h": handles}}
	resp, err := RecoverSessions(context.Background(), store, &hypervisorv1.RecoverSessionsRequest{HostId: "h"})
	if err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}
	viaRecover := resp.GetSessions()

	if len(viaHeartbeat) != len(viaRecover) {
		t.Fatalf("len mismatch: heartbeat=%d recover=%d", len(viaHeartbeat), len(viaRecover))
	}
	a, b := viaHeartbeat[0], viaRecover[0]
	if a.GetSessionUuid() != b.GetSessionUuid() ||
		a.GetDomainUuid() != b.GetDomainUuid() ||
		a.GetHostSessionIndex() != b.GetHostSessionIndex() ||
		a.GetTapName() != b.GetTapName() ||
		a.GetOverlayPath() != b.GetOverlayPath() ||
		a.GetObservedState().GetName() != b.GetObservedState().GetName() {
		t.Fatalf("heartbeat and recover projections diverge:\n heartbeat=%+v\n recover=%+v", a, b)
	}
}
