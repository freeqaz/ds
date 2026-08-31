// SPDX-License-Identifier: Apache-2.0

package controlplane

// sessionrecordwire_test.go proves the §4.1 host-local session-record PRODUCER is WIRED into
// the live create/teardown coordinator (doc 14 §4.1): CreateSession drops the tap-keyed
// (session_uuid, host_id) record once the (host_session_index, tap_name) binding is bound
// post-CloneFromImageResponse, DestroySession removes it, and the seam is a strict no-op when
// unwired (the default, mirroring IdentityClients.AttachCABundleStore). It drives the full
// wired ControlPlane over the synthetic fakes (D50 — no live host / VM / ds-tlsproxy); a fake
// producer records the write/remove calls so the callsite invariants (write-on-bind ONCE,
// remove-on-teardown ONCE, exact (tap, uuid, host) arguments) are asserted directly, and one
// case exercises the REAL *fileSessionRecordProducer over a temp dir end-to-end through the
// exported AttachSessionRecordStore wiring.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// fakeSessionRecordProducer records the write/remove calls the create/teardown callsites make
// (D50 — no host-local filesystem touched). It satisfies the sessionRecordProducer seam
// natively, exactly as the production *fileSessionRecordProducer does.
type fakeSessionRecordProducer struct {
	writes    []recordWrite
	removes   []string
	writeErr  error
	removeErr error
}

type recordWrite struct {
	tapName     string
	sessionUUID string
	hostID      string
}

func (f *fakeSessionRecordProducer) write(tapName, sessionUUID, hostID string) error {
	f.writes = append(f.writes, recordWrite{tapName: tapName, sessionUUID: sessionUUID, hostID: hostID})
	return f.writeErr
}

func (f *fakeSessionRecordProducer) remove(tapName string) error {
	f.removes = append(f.removes, tapName)
	return f.removeErr
}

// TestSessionRecord_WriteOnBind_RemoveOnTeardown is the acceptance: with the producer seam
// wired, a CreateSession drops the record EXACTLY ONCE with the tap the coordinator bound
// post-CloneFromImageResponse (dstap-7 / index 7 per the driver fake) and the created session's
// (uuid, host), and a DestroySession removes it EXACTLY ONCE keyed on that same tap.
func TestSessionRecord_WriteOnBind_RemoveOnTeardown(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	prod := &fakeSessionRecordProducer{}
	f.cp.Sessions.setSessionRecordProducer(prod)

	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	uuid := created.GetSession().GetSessionUuid()

	// write-on-bind: exactly one drop, keyed on the bound tap, carrying the session's binding.
	if len(prod.writes) != 1 {
		t.Fatalf("session-record writes = %d, want 1 (drop once on the create bind)", len(prod.writes))
	}
	w := prod.writes[0]
	if w.tapName != "dstap-7" {
		t.Errorf("drop tap = %q, want %q (the coordinator's post-CloneFromImageResponse binding)", w.tapName, "dstap-7")
	}
	if w.sessionUUID != uuid {
		t.Errorf("drop session_uuid = %q, want %q", w.sessionUUID, uuid)
	}
	if w.hostID != testHostID {
		t.Errorf("drop host_id = %q, want %q (the placed host)", w.hostID, testHostID)
	}
	if len(prod.removes) != 0 {
		t.Errorf("session-record removes after create = %d, want 0", len(prod.removes))
	}

	if _, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: uuid}); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}

	// remove-on-teardown: exactly one removal, keyed on the same bound tap; no second write.
	if len(prod.removes) != 1 {
		t.Fatalf("session-record removes = %d, want 1 (remove once on teardown)", len(prod.removes))
	}
	if prod.removes[0] != "dstap-7" {
		t.Errorf("remove tap = %q, want %q (the record's bound tap)", prod.removes[0], "dstap-7")
	}
	if len(prod.writes) != 1 {
		t.Errorf("session-record writes after teardown = %d, want 1 (teardown never re-drops)", len(prod.writes))
	}
}

// TestSessionRecord_UnwiredIsNoOp proves the DEFAULT posture (no producer wired) is byte-for-byte
// the pre-seam behavior: the create/teardown succeed and touch no producer — an unarmed proxy
// simply MISSes the join and degrades to AddressDerived (safe). It is the guard that the seam is
// additive and never on unless explicitly wired.
func TestSessionRecord_UnwiredIsNoOp(t *testing.T) {
	f := newFixture(t, fixtureOpts{}) // no setSessionRecordProducer → seam nil

	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	uuid := created.GetSession().GetSessionUuid()

	resp, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: uuid})
	if err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
	// The create + teardown converged exactly as before — the nil seam changed nothing.
	if got := resp.GetSession().GetState().GetName().String(); got == "" {
		t.Fatalf("DestroySession returned an empty state; the nil session-record seam must not alter the teardown")
	}
}

// TestSessionRecord_WriteFaultIsBestEffort proves a host-local DROP fault does NOT fail the
// create: the session is already created, so a failed drop only degrades the live join to
// AddressDerived (measure-not-gate, D50/D81). The write is still attempted exactly once.
func TestSessionRecord_WriteFaultIsBestEffort(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	prod := &fakeSessionRecordProducer{writeErr: errors.New("synthetic drop fault")}
	f.cp.Sessions.setSessionRecordProducer(prod)

	if _, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq()); err != nil {
		t.Fatalf("CreateSession must succeed despite a best-effort drop fault: %v", err)
	}
	if len(prod.writes) != 1 {
		t.Errorf("session-record writes = %d, want 1 (the drop was attempted despite failing)", len(prod.writes))
	}
}

// TestSessionRecord_RemoveFaultIsBestEffort proves a host-local REMOVE fault does NOT fail the
// teardown: the §4.2 teardown already converged, so a lingering stale drop is bounded by the
// next create's tap-keyed overwrite. The teardown still reaches DESTROYED.
func TestSessionRecord_RemoveFaultIsBestEffort(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	prod := &fakeSessionRecordProducer{removeErr: errors.New("synthetic remove fault")}
	f.cp.Sessions.setSessionRecordProducer(prod)

	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	uuid := created.GetSession().GetSessionUuid()

	if _, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: uuid}); err != nil {
		t.Fatalf("DestroySession must succeed despite a best-effort remove fault: %v", err)
	}
	if len(prod.removes) != 1 {
		t.Errorf("session-record removes = %d, want 1 (the removal was attempted despite failing)", len(prod.removes))
	}
}

// TestSessionRecord_AttachSessionRecordStore_EndToEnd exercises the EXPORTED cmd-side wiring
// (AttachSessionRecordStore, the deferred main.go call under DS_SESSION_JOIN_LIVE) against the
// REAL *fileSessionRecordProducer over a temp OverlayDir: a create lands the two-line drop at
// the byte-exact path/format the ds-tlsproxy reader resolves, and a teardown removes it.
func TestSessionRecord_AttachSessionRecordStore_EndToEnd(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	base := t.TempDir()
	if err := f.cp.Sessions.AttachSessionRecordStore(base); err != nil {
		t.Fatalf("AttachSessionRecordStore: %v", err)
	}

	created, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	uuid := created.GetSession().GetSessionUuid()

	wantPath := filepath.Join(base, sessionRecordSubdirName, trustpath.Sanitize("dstap-7")+sessionRecordExt)
	got, rerr := os.ReadFile(wantPath)
	if rerr != nil {
		t.Fatalf("read dropped session record at %q: %v", wantPath, rerr)
	}
	// Doc 14 §4.1 two-line body: "<session_uuid>\n<host_id>\n".
	if want := uuid + "\n" + testHostID + "\n"; string(got) != want {
		t.Errorf("dropped record body = %q, want %q", string(got), want)
	}

	if _, err := f.cp.Sessions.DestroySession(context.Background(), &orchestratorv1.DestroySessionRequest{SessionUuid: uuid}); err != nil {
		t.Fatalf("DestroySession: %v", err)
	}
	if _, statErr := os.Stat(wantPath); !os.IsNotExist(statErr) {
		t.Errorf("session record still present after teardown (stat err = %v), want removed", statErr)
	}
}

// TestSessionRecord_AttachSessionRecordStore_EmptyBaseRejected proves the exported wiring is
// fail-closed on an empty OverlayDir (a live run that resolved no host state area) and leaves
// the seam UNWIRED, so a mis-wired cmd never installs a producer that would drop under a
// degenerate path.
func TestSessionRecord_AttachSessionRecordStore_EmptyBaseRejected(t *testing.T) {
	svc := newSessionService(nil, nil, nil, testOrg, nil, nil)
	if err := svc.AttachSessionRecordStore(""); err == nil {
		t.Fatal("AttachSessionRecordStore(\"\"): expected a fail-closed error for an empty base dir")
	}
	if svc.sessionRecords != nil {
		t.Error("a rejected AttachSessionRecordStore must leave the session-record seam unwired")
	}
}
