// SPDX-License-Identifier: Apache-2.0

package libvirt

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func newTestRecoverer(t *testing.T, rr *recordingRunner) (*liveSessionRecoverer, *fileSessionRecordStore) {
	t.Helper()
	store, err := NewFileSessionRecordStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &liveSessionRecoverer{virshBin: "virsh", run: rr, records: store}, store
}

func TestListActiveDomainsArgs(t *testing.T) {
	name, args := listActiveDomainsArgs("virsh")
	if name != "virsh" || strings.Join(args, " ") != "list --name" {
		t.Fatalf("list args = %q %q, want virsh list --name", name, args)
	}
}

func TestSessionFromDomainName(t *testing.T) {
	if s, ok := sessionFromDomainName("ds-sess-7"); !ok || s != "sess-7" {
		t.Fatalf("ds-sess-7 -> (%q,%v), want (sess-7,true)", s, ok)
	}
	if _, ok := sessionFromDomainName("other-vm"); ok {
		t.Fatal("a non-ds domain must yield ok=false")
	}
	if _, ok := sessionFromDomainName("ds-"); ok {
		t.Fatal("an empty session id must yield ok=false")
	}
}

// TestRecoverSessionsJoinsResidentDomainsToRecords: the recoverer lists active
// domains, keeps the ds-<session> ones, and joins each to its persisted record to
// produce a RecoveredSession with the recorded binding.
func TestRecoverSessionsJoinsResidentDomainsToRecords(t *testing.T) {
	// virsh list --name reports two ds-sessions + one foreign domain.
	rr := &recordingRunner{outputs: []string{"ds-sess-a\nother-vm\nds-sess-b\n"}}
	r, store := newTestRecoverer(t, rr)
	_ = store.Put(context.Background(), SessionRecord{SessionUUID: "sess-a", DomainUUID: "dom-a", Binding: testBinding(3)})
	_ = store.Put(context.Background(), SessionRecord{SessionUUID: "sess-b", DomainUUID: "dom-b", Binding: testBinding(7)})

	got, err := r.RecoverSessions(context.Background(), "host-1")
	if err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("recovered %d sessions, want 2 (the two ds-sessions with records): %+v", len(got), got)
	}
	bySession := map[string]RecoveredSession{}
	for _, rs := range got {
		bySession[rs.SessionUUID] = rs
	}
	a, ok := bySession["sess-a"]
	if !ok || a.DomainUUID != "dom-a" || a.Binding.HostSessionIndex != 3 {
		t.Fatalf("sess-a recovered wrong: %+v", a)
	}
	b, ok := bySession["sess-b"]
	if !ok || b.DomainUUID != "dom-b" || b.Binding.HostSessionIndex != 7 {
		t.Fatalf("sess-b recovered wrong: %+v", b)
	}
	// the foreign domain is NOT recovered
	if _, ok := bySession["other-vm"]; ok {
		t.Fatal("a non-ds domain must not be recovered")
	}
}

// TestRecoverSessionsSkipsResidentDomainWithoutRecord: a ds-domain still resident
// but whose record was lost is SKIPPED (it cannot be re-adopted without its binding).
func TestRecoverSessionsSkipsResidentDomainWithoutRecord(t *testing.T) {
	rr := &recordingRunner{outputs: []string{"ds-sess-a\nds-sess-orphan\n"}}
	r, store := newTestRecoverer(t, rr)
	_ = store.Put(context.Background(), SessionRecord{SessionUUID: "sess-a", DomainUUID: "dom-a", Binding: testBinding(1)})
	// sess-orphan has NO record.

	got, err := r.RecoverSessions(context.Background(), "host-1")
	if err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}
	if len(got) != 1 || got[0].SessionUUID != "sess-a" {
		t.Fatalf("expected only sess-a recovered (orphan skipped), got %+v", got)
	}
}

// TestRecoverSessionsEmptyHostIsNoOp: a host with no active domains recovers nothing.
func TestRecoverSessionsEmptyHostIsNoOp(t *testing.T) {
	rr := &recordingRunner{outputs: []string{"\n"}}
	r, _ := newTestRecoverer(t, rr)
	got, err := r.RecoverSessions(context.Background(), "host-1")
	if err != nil {
		t.Fatalf("RecoverSessions: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a fresh host must recover nothing, got %+v", got)
	}
}

// TestRecoverSessionsListFailureSurfacesError: a virsh list failure is a genuine
// host fault surfaced non-nil.
func TestRecoverSessionsListFailureSurfacesError(t *testing.T) {
	rr := &recordingRunner{outputs: []string{"error: failed to connect to the hypervisor"}, errs: []error{errors.New("exit 1")}}
	r, _ := newTestRecoverer(t, rr)
	if _, err := r.RecoverSessions(context.Background(), "host-1"); err == nil {
		t.Fatal("expected RecoverSessions to surface the virsh list failure")
	}
}

// TestNewSessionRecovererRequiresStore: the live recoverer requires a record store
// (it cannot read bindings without one).
func TestNewSessionRecovererRequiresStore(t *testing.T) {
	if _, err := NewLiveSessionRecoverer(LiveConfig{VirshBin: "virsh"}, nil); err == nil {
		t.Fatal("expected NewLiveSessionRecoverer to reject a nil record store")
	}
}

// TestNewSessionRecovererGateOff: off the gate NewSessionRecoverer returns nil (the
// DriverService answers RecoverSessions with Unimplemented).
func TestNewSessionRecovererGateOff(t *testing.T) {
	t.Setenv(EnvHostAgentLive, "")
	r, err := NewSessionRecoverer(LiveConfig{VirshBin: "virsh"}, nil)
	if err != nil {
		t.Fatalf("gate off: %v", err)
	}
	if r != nil {
		t.Fatalf("gate off must return nil, got %T", r)
	}
}
