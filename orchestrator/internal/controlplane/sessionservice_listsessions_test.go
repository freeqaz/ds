package controlplane

// sessionservice_listsessions_test.go drives the ListSessions RPC handler (doc 15 §5.3, the
// fleet/console read) against the synthetic fixtures (D50): the handler enumerates the §5.6
// records the control plane is the single source of and projects each onto the frozen Session
// wire message. It pins the seeded-records enumeration, the host_id filter, the host/state/
// created-at projection, the clean-degrade Unavailable when the list leg is unwired, and the
// store-fault status mapping. All seams are fakes — no live VM/host-agent/podman.

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestListSessions_ReturnsSeededSessions proves the handler enumerates the sessions in the store:
// one driven all the way through the create spine to ATTACHED, plus a second seeded directly in
// the same backing store (a distinct host_session_index, since indices are burned-never-recycled
// per host). ListSessions surfaces BOTH, projected onto the frozen Session wire message. The list
// leg is installed implicitly off the destroy store (NewControlPlane → SetDestroyServing), so the
// wired fixture serves it with no extra wiring.
func TestListSessions_ReturnsSeededSessions(t *testing.T) {
	f := newFixture(t, fixtureOpts{})

	a, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession a: %v", err)
	}
	// A second record placed directly in the SAME backing store (the create spine burns one
	// host_session_index per create on the single fixture host, so a second full create would
	// collide; the read leg's job is to enumerate whatever the store holds).
	if _, err := f.st.CreateSession(context.Background(), store.Session{
		Ref:          store.SessionRef{SessionUUID: "sess-seeded-2", HostID: testHostID, HostSessionIndex: 99, TapName: "tap-seeded-2"},
		EnvConfigRef: testEnvRef,
		State:        store.SessionReady,
	}); err != nil {
		t.Fatalf("seed second session: %v", err)
	}

	resp, err := f.cp.Sessions.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	got := map[string]attachv1.SessionStateName{}
	for _, s := range resp.GetSessions() {
		got[s.GetSessionUuid()] = s.GetState().GetName()
	}
	if len(got) != 2 {
		t.Fatalf("ListSessions returned %d sessions, want 2 (the created + the seeded); got=%v", len(got), got)
	}
	if st := got[a.GetSession().GetSessionUuid()]; st != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Errorf("created session %q state = %v, want ATTACHED", a.GetSession().GetSessionUuid(), st)
	}
	if st := got["sess-seeded-2"]; st != attachv1.SessionStateName_SESSION_STATE_NAME_READY {
		t.Errorf("seeded session state = %v, want READY", st)
	}
}

// TestListSessions_ProjectsRecordFields seeds the store directly with a controlled record and
// asserts the handler projects uuid, host, state, and created-at onto the frozen wire message
// (the §5.3 console columns) exactly as sessionToProto maps them. A SetListServing-narrowed
// handler over the seeded *store.Memory exercises the read leg without the whole create spine.
func TestListSessions_ProjectsRecordFields(t *testing.T) {
	created := time.Unix(1_700_000_500, 0).UTC()
	st := store.NewMemoryClock(func() time.Time { return created })

	rec := store.Session{
		Ref: store.SessionRef{
			SessionUUID:      "sess-list-1",
			HostID:           "host-zeta",
			HostSessionIndex: 7,
			TapName:          "ds-tap-7",
		},
		EnvConfigRef: testEnvRef,
		WriterSeat:   "dev@org", // a session with a writer held (the has-writer console signal)
	}
	if _, err := st.CreateSession(context.Background(), rec); err != nil {
		t.Fatalf("seed CreateSession: %v", err)
	}
	// Drive it to ATTACHED so the projected state is a meaningful console value.
	attached := store.SessionAttached
	if _, err := st.UpdateSession(context.Background(), "sess-list-1", store.SessionUpdate{State: &attached}); err != nil {
		t.Fatalf("seed UpdateSession: %v", err)
	}

	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	svc.SetListServing(st)

	resp, err := svc.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(resp.GetSessions()) != 1 {
		t.Fatalf("ListSessions returned %d sessions, want 1", len(resp.GetSessions()))
	}
	s := resp.GetSessions()[0]
	if s.GetSessionUuid() != "sess-list-1" {
		t.Errorf("uuid = %q, want sess-list-1", s.GetSessionUuid())
	}
	if s.GetHostId() != "host-zeta" {
		t.Errorf("host_id = %q, want host-zeta", s.GetHostId())
	}
	if got := s.GetState().GetName(); got != attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED {
		t.Errorf("state = %v, want ATTACHED", got)
	}
	if s.GetCreatedAt() != uint64(created.Unix()) {
		t.Errorf("created_at = %d, want %d", s.GetCreatedAt(), created.Unix())
	}
}

// TestListSessions_HostFilter pins that the frozen host_id filter narrows the enumeration to one
// host: two sessions on different hosts, a host-scoped list returns only the matching one.
func TestListSessions_HostFilter(t *testing.T) {
	st := store.NewMemoryClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() })
	for _, c := range []struct{ uuid, host string }{
		{"sess-a", "host-a"},
		{"sess-b", "host-b"},
	} {
		if _, err := st.CreateSession(context.Background(), store.Session{
			Ref:          store.SessionRef{SessionUUID: c.uuid, HostID: c.host, HostSessionIndex: 1, TapName: "tap-" + c.uuid},
			EnvConfigRef: testEnvRef,
		}); err != nil {
			t.Fatalf("seed %s: %v", c.uuid, err)
		}
	}

	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	svc.SetListServing(st)

	resp, err := svc.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{HostId: "host-b"})
	if err != nil {
		t.Fatalf("ListSessions(host=host-b): %v", err)
	}
	if len(resp.GetSessions()) != 1 || resp.GetSessions()[0].GetSessionUuid() != "sess-b" {
		t.Fatalf("host-scoped ListSessions = %v, want exactly sess-b", resp.GetSessions())
	}
}

// TestListSessions_OverWire proves the enumeration closes END-TO-END over the gRPC ListSessions
// RPC (bufconn): a console dials the public surface, and the handler returns the created session
// — the §5.3 read served through the wire.
func TestListSessions_OverWire(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	client := serveSessions(t, f.cp)

	created, err := client.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession over wire: %v", err)
	}
	resp, err := client.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions over wire: %v", err)
	}
	found := false
	for _, s := range resp.GetSessions() {
		if s.GetSessionUuid() == created.GetSession().GetSessionUuid() {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListSessions over wire omitted the created session %q; got=%v", created.GetSession().GetSessionUuid(), resp.GetSessions())
	}
}

// TestListSessions_Unwired_Unavailable proves a handler with no list leg installed (a
// test-narrowed SessionService) refuses Unavailable rather than serving an empty enumeration a
// caller cannot distinguish from "no sessions" — the clean-degrade posture the destroy/attach read
// legs use.
func TestListSessions_Unwired_Unavailable(t *testing.T) {
	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	_, err := svc.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{})
	if st, _ := status.FromError(err); st.Code() != codes.Unavailable {
		t.Fatalf("ListSessions error code = %v, want Unavailable (list leg unwired); err=%v", st.Code(), err)
	}
}

// faultyLister is a listSessionStore that always faults — to pin mapListStoreError's status
// CLASS mapping (ErrUnavailable → Unavailable; anything else → Internal).
type faultyLister struct{ err error }

func (f faultyLister) ListSessions(context.Context, store.SessionFilter) ([]store.Session, error) {
	return nil, f.err
}

// TestListSessions_StoreFaultMapsByClass proves a store fault under the enumeration maps onto the
// gRPC status by CLASS: a store-unavailable is retryable Unavailable, any other fault is Internal.
func TestListSessions_StoreFaultMapsByClass(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want codes.Code
	}{
		{"unavailable", store.ErrUnavailable, codes.Unavailable},
		{"other", errors.New("boom"), codes.Internal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
			svc.SetListServing(faultyLister{err: c.err})
			_, err := svc.ListSessions(context.Background(), &orchestratorv1.ListSessionsRequest{})
			if st, _ := status.FromError(err); st.Code() != c.want {
				t.Fatalf("ListSessions store fault %q → code %v, want %v; err=%v", c.name, st.Code(), c.want, err)
			}
		})
	}
}
