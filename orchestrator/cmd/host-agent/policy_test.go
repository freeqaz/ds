// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hostagent"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// newTestCoordinator builds the same offline ApplyCoordinator the daemon wires, so the
// state source's policy-version leg is exercised exactly as in production.
func newTestCoordinator(t *testing.T) *hostagent.ApplyCoordinator {
	t.Helper()
	coord, err := newOfflineApplyCoordinator()
	if err != nil {
		t.Fatalf("newOfflineApplyCoordinator: %v", err)
	}
	return coord
}

// TestCoordStateSourceNilObserverReportsNoSessions pins the backwards-compatible
// posture: with NO observer wired (the offline default), the heartbeat reports an
// EMPTY observed-session list — byte-identical to the pre-fix behavior — while still
// reporting the host id and the three HEALTHY boundary consumers.
func TestCoordStateSourceNilObserverReportsNoSessions(t *testing.T) {
	src := &coordStateSource{hostID: "host-1", coord: newTestCoordinator(t)} // observed nil
	st, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if st.HostID != "host-1" {
		t.Fatalf("host id = %q, want host-1", st.HostID)
	}
	if len(st.Observed) != 0 {
		t.Fatalf("nil observer must report no observed sessions, got %d", len(st.Observed))
	}
	if len(st.Boundary) != 3 {
		t.Fatalf("expected the 3 boundary consumers, got %d", len(st.Boundary))
	}
}

// TestCoordStateSourceReportsObservedSessions is the core of the fix: an observer that
// returns resident sessions makes the heartbeat carry them in the §3 observed set, so the
// reconciler joins each placed record to its running VM instead of re-driving it as a
// missing VM every cadence (which tears a live attach stream). The reported elements carry
// the observer's session/binding fields verbatim.
func TestCoordStateSourceReportsObservedSessions(t *testing.T) {
	want := []*hypervisorv1.ObservedSession{
		{SessionUuid: "sess-a", DomainUuid: "dom-a", HostSessionIndex: 3, TapName: "dstap-3", OverlayPath: "/ov/sess-a.qcow2"},
		{SessionUuid: "sess-b", DomainUuid: "dom-b", HostSessionIndex: 4, TapName: "dstap-4", OverlayPath: "/ov/sess-b.qcow2"},
	}
	src := &coordStateSource{
		hostID:   "host-1",
		coord:    newTestCoordinator(t),
		observed: func(context.Context) ([]*hypervisorv1.ObservedSession, error) { return want, nil },
	}
	st, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(st.Observed) != len(want) {
		t.Fatalf("observed sessions = %d, want %d", len(st.Observed), len(want))
	}
	for i, o := range st.Observed {
		if o.GetSessionUuid() != want[i].GetSessionUuid() || o.GetHostSessionIndex() != want[i].GetHostSessionIndex() {
			t.Fatalf("observed[%d] = %v, want %v", i, o, want[i])
		}
		// The reconciler-safe posture: present (joins to the record) but state un-pin-downable
		// (no rule-c regression). The observer must NOT fabricate a §3 state.
		if o.GetObservedState() != nil {
			t.Fatalf("observed[%d] must carry a nil ObservedState (present, state unknown), got %v", i, o.GetObservedState())
		}
	}
}

// TestCoordStateSourceObserverFaultReportsEmptyNotError pins the failure posture: a
// self-probe fault (e.g. virsh unreachable) must NOT fail the whole heartbeat — going
// silent would mark the host UNKNOWN. The beat is reported with an EMPTY observed set and
// a nil error; the level-triggered reconciler re-converges on the next clean beat.
func TestCoordStateSourceObserverFaultReportsEmptyNotError(t *testing.T) {
	src := &coordStateSource{
		hostID: "host-1",
		coord:  newTestCoordinator(t),
		observed: func(context.Context) ([]*hypervisorv1.ObservedSession, error) {
			return nil, errors.New("virsh unreachable")
		},
	}
	st, err := src.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("an observer fault must NOT fail the heartbeat, got err: %v", err)
	}
	if len(st.Observed) != 0 {
		t.Fatalf("an observer fault must report an empty observed set, got %d", len(st.Observed))
	}
}

// TestRecoveredObservedSessionsMapping pins the SessionRecoverer → ObservedSession
// projection the live observer uses: the recovered session uuid, domain uuid, and the
// three-keys-agree binding (index/tap/overlay) project onto the observed element, with a
// nil ObservedState (the recoverer is read-only re-observation and does not probe §3 state).
func TestRecoveredObservedSessionsMapping(t *testing.T) {
	rec := &fakeRecoverer{out: []libvirt.RecoveredSession{
		{
			SessionUUID: "sess-x",
			DomainUUID:  "dom-x",
			Binding:     libvirt.Binding{HostSessionIndex: 9, TapName: "dstap-9", OverlayPath: "/ov/sess-x.qcow2"},
		},
	}}
	obsFn := recoveredObservedSessions(rec, "host-1")
	got, err := obsFn(context.Background())
	if err != nil {
		t.Fatalf("observer: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 observed session, got %d", len(got))
	}
	o := got[0]
	if o.GetSessionUuid() != "sess-x" || o.GetDomainUuid() != "dom-x" {
		t.Fatalf("session/domain mismatch: %v", o)
	}
	if o.GetHostSessionIndex() != 9 || o.GetTapName() != "dstap-9" || o.GetOverlayPath() != "/ov/sess-x.qcow2" {
		t.Fatalf("binding fields not projected: %v", o)
	}
	if o.GetObservedState() != nil {
		t.Fatalf("ObservedState must be nil (present, state unknown), got %v", o.GetObservedState())
	}
	if rec.gotHostID != "host-1" {
		t.Fatalf("recoverer called with host id %q, want host-1", rec.gotHostID)
	}
}

// TestRecoveredObservedSessionsFaultPropagates pins that a recoverer fault propagates to
// the caller (coordStateSource.Snapshot then logs it and reports an empty beat) rather than
// being silently swallowed inside the projection.
func TestRecoveredObservedSessionsFaultPropagates(t *testing.T) {
	rec := &fakeRecoverer{err: errors.New("virsh list failed")}
	obsFn := recoveredObservedSessions(rec, "host-1")
	if _, err := obsFn(context.Background()); err == nil {
		t.Fatal("a recoverer fault must propagate from the observer")
	}
}

// fakeRecoverer is an in-memory libvirt.SessionRecoverer for the projection tests.
type fakeRecoverer struct {
	out       []libvirt.RecoveredSession
	err       error
	gotHostID string
}

func (f *fakeRecoverer) RecoverSessions(_ context.Context, hostID string) ([]libvirt.RecoveredSession, error) {
	f.gotHostID = hostID
	if f.err != nil {
		return nil, f.err
	}
	return f.out, nil
}
