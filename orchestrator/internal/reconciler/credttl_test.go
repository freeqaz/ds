package reconciler

// credttl_test.go — coverage for the CREDENTIAL-TTL BACKSTOP (credttl.go), the §3 /
// doc 16 §5.4 backstop that re-converges an EXPIRED persisted MintExpiry horizon
// WITHOUT the in-process timer. The two miss windows it closes are exercised
// end-to-end against the real *store.Memory desired-state store + a synthetic
// MintReconverger (D50: synthetic fixtures only, no live mint/podman/host-agent):
//
//   (1) BOOT-SWEEP MISS — a live session whose horizon the best-effort, single-shot
//       boot re-arm sweep never armed (simulated: the record carries a past horizon
//       but no timer is driving it) gets re-converged on the backstop pass.
//   (2) MID-RESUME RE-MINT FAILURE — a session left SUSPENDED with an expired horizon
//       by a Resume re-mint fault is re-attempted on the backstop pass.
//
// Plus the guard cases the additivity discipline demands: a still-future / zero horizon
// is left untouched, a DESTROYING/terminal record churns no identity, and a store-outage
// pass STALLS without destroying (doc 15 §3 degraded mode).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// recordingMintReconverger records every credential-TTL re-convergence the backstop
// drives (so a test asserts EXACTLY which sessions were re-driven), and optionally fails
// the re-converge (the failure-arm: the record is left untouched for the next pass).
type recordingMintReconverger struct {
	reconverged []string // session UUIDs the backstop asked to re-converge, in order
	err         error    // when set, every ReconvergeMintExpiry returns it
}

func (m *recordingMintReconverger) ReconvergeMintExpiry(_ context.Context, s store.Session) error {
	m.reconverged = append(m.reconverged, s.Ref.SessionUUID)
	return m.err
}

func (m *recordingMintReconverger) has(uuid string) bool {
	for _, u := range m.reconverged {
		if u == uuid {
			return true
		}
	}
	return false
}

// seedRecordWithHorizon seeds a desired record (like fakes_test.go's seedRecord) but
// also persists a MintExpiry horizon on it — the durable column both miss windows leave
// stale. CreateSession clones the supplied session, so the horizon is preserved verbatim.
func seedRecordWithHorizon(t *testing.T, st *store.Memory, sessionUUID, hostID string, idx uint64, state store.SessionState, horizon time.Time) store.Session {
	t.Helper()
	s := store.Session{
		Ref: store.SessionRef{
			SessionUUID:      sessionUUID,
			HostID:           hostID,
			HostSessionIndex: idx,
			TapName:          "dstap-0",
		},
		State:      state,
		MintExpiry: horizon,
	}
	if state == store.SessionSuspended {
		s.SuspendReason = store.SuspendReasonUser
	}
	out, err := st.CreateSession(context.Background(), s)
	if err != nil {
		t.Fatalf("seedRecordWithHorizon %s: %v", sessionUUID, err)
	}
	if !out.MintExpiry.Equal(horizon) {
		t.Fatalf("seedRecordWithHorizon %s: horizon not persisted: got %s want %s", sessionUUID, out.MintExpiry, horizon)
	}
	return out
}

// newCredTTLReconciler constructs a Reconciler with the credential-TTL backstop wired,
// at the given clock. The driver/redriver are inert recording fakes — the backstop pass
// drives NEITHER (it re-converges credentials, not VM presence), which the tests assert.
func newCredTTLReconciler(t *testing.T, st RecordStore, mr MintReconverger, al Alarmer, now func() time.Time) *Reconciler {
	t.Helper()
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, al, now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r.WithMintReconverger(mr)
}

// --- (1) BOOT-SWEEP MISS: a live session with a past horizon and no armed timer
// re-converges on the backstop pass. ---

func TestReconcileMintExpiry_BootSweepMiss_ReconvergesUnarmedHorizon(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)

	// A LIVE (WORKING) session whose persisted horizon expired 10 min ago — the boot
	// sweep's ListSessions faulted at assembly, so this session's in-process timer was
	// never armed (window 1). No heartbeat/observed set is needed: the horizon is a
	// durable column, not a host observation.
	past := clk.now().Add(-10 * time.Minute)
	rec := seedRecordWithHorizon(t, st, "sess-bootmiss", "host-A", 0, store.SessionWorking, past)

	mr := &recordingMintReconverger{}
	al := &recordingAlarmer{}
	r := newCredTTLReconciler(t, st, mr, al, clk.now)

	if err := r.ReconcileMintExpiry(context.Background()); err != nil {
		t.Fatalf("ReconcileMintExpiry: unexpected error: %v", err)
	}

	if !mr.has(rec.Ref.SessionUUID) {
		t.Fatalf("boot-sweep-miss horizon was NOT re-converged: reconverged=%v", mr.reconverged)
	}
	if len(mr.reconverged) != 1 {
		t.Fatalf("expected exactly one re-converge, got %d: %v", len(mr.reconverged), mr.reconverged)
	}
	if !al.has(AlarmCredentialTTLReconverge) {
		t.Fatalf("expected an AlarmCredentialTTLReconverge audit event; alarms=%v", al.alarms)
	}
}

// --- (2) MID-RESUME RE-MINT FAILURE: a session left SUSPENDED with an expired horizon
// is re-attempted on the backstop pass. ---

func TestReconcileMintExpiry_MidResumeRemintFailure_ReattemptsSuspended(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)

	// A session ParkResumeDriver.Resume left SUSPENDED because its re-mint failed: the
	// record is SUSPENDED and STILL carries its expired persisted horizon (window 2).
	past := clk.now().Add(-2 * time.Minute)
	rec := seedRecordWithHorizon(t, st, "sess-resumefail", "host-B", 1, store.SessionSuspended, past)

	mr := &recordingMintReconverger{}
	al := &recordingAlarmer{}
	r := newCredTTLReconciler(t, st, mr, al, clk.now)

	if err := r.ReconcileMintExpiry(context.Background()); err != nil {
		t.Fatalf("ReconcileMintExpiry: unexpected error: %v", err)
	}

	if !mr.has(rec.Ref.SessionUUID) {
		t.Fatalf("mid-resume re-mint-failure horizon was NOT re-attempted: reconverged=%v", mr.reconverged)
	}
	// The backstop NEVER mutates state: the session is still SUSPENDED (re-convergence
	// is the seam's job; the reconciler only re-drives, it never resumes/destroys here).
	got, err := st.GetSession(context.Background(), rec.Ref.SessionUUID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.State != store.SessionSuspended {
		t.Fatalf("backstop must not mutate state: got %s want SUSPENDED", got.State)
	}
}

// --- a re-converge FAILURE leaves the record untouched and alarms (retried next pass). ---

func TestReconcileMintExpiry_ReconvergeFailure_AlarmsAndLeavesRecord(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	past := clk.now().Add(-time.Hour)
	rec := seedRecordWithHorizon(t, st, "sess-mrfault", "host-C", 0, store.SessionWorking, past)

	mr := &recordingMintReconverger{err: errors.New("mint service unavailable")}
	al := &recordingAlarmer{}
	r := newCredTTLReconciler(t, st, mr, al, clk.now)

	if err := r.ReconcileMintExpiry(context.Background()); err != nil {
		t.Fatalf("ReconcileMintExpiry: a per-record re-converge fault must be absorbed, not returned: %v", err)
	}
	if !mr.has(rec.Ref.SessionUUID) {
		t.Fatalf("re-converge was not attempted: %v", mr.reconverged)
	}
	if !al.has(AlarmCredentialTTLReconverge) {
		t.Fatalf("expected an AlarmCredentialTTLReconverge audit event on the failure arm")
	}
	// Record state unchanged — never auto-destroyed on a credential fault.
	got, _ := st.GetSession(context.Background(), rec.Ref.SessionUUID)
	if got.State != store.SessionWorking {
		t.Fatalf("record state changed on re-converge failure: got %s want WORKING", got.State)
	}
}

// --- (3) still-FUTURE and ZERO horizons are left UNTOUCHED. ---

func TestReconcileMintExpiry_FutureAndZeroHorizons_LeftUntouched(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)

	// A still-FUTURE horizon: the in-process timer (if armed) owns it; the backstop must
	// not fire prematurely.
	future := clk.now().Add(30 * time.Minute)
	seedRecordWithHorizon(t, st, "sess-future", "host-D", 0, store.SessionWorking, future)
	// A ZERO horizon: the no-TTL not-set posture; nothing to track.
	seedRecordWithHorizon(t, st, "sess-zero", "host-D", 1, store.SessionWorking, time.Time{})

	mr := &recordingMintReconverger{}
	al := &recordingAlarmer{}
	r := newCredTTLReconciler(t, st, mr, al, clk.now)

	if err := r.ReconcileMintExpiry(context.Background()); err != nil {
		t.Fatalf("ReconcileMintExpiry: %v", err)
	}
	if len(mr.reconverged) != 0 {
		t.Fatalf("future/zero horizons must be left untouched, but re-converged: %v", mr.reconverged)
	}
	if al.has(AlarmCredentialTTLReconverge) {
		t.Fatalf("no credential-TTL alarm should fire for future/zero horizons; alarms=%v", al.alarms)
	}
}

// --- (4) DESTROYING / terminal records with an expired horizon churn NO identity. ---

func TestReconcileMintExpiry_DestroyingAndTerminal_NoIdentityChurn(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	past := clk.now().Add(-time.Hour)

	// DESTROYING: mid-teardown; re-minting would churn identity the §4.2 teardown is
	// about to revoke. Even with a past horizon the backstop must skip it.
	seedRecordWithHorizon(t, st, "sess-destroying", "host-E", 0, store.SessionDestroying, past)
	// DESTROYED (terminal): never re-minted. (ListSessions with IncludeDestroyed=false
	// omits it at the source; the in-loop IsTerminal guard is the belt-and-suspenders.)
	seedRecordWithHorizon(t, st, "sess-destroyed", "host-E", 1, store.SessionDestroyed, past)

	mr := &recordingMintReconverger{}
	al := &recordingAlarmer{}
	r := newCredTTLReconciler(t, st, mr, al, clk.now)

	if err := r.ReconcileMintExpiry(context.Background()); err != nil {
		t.Fatalf("ReconcileMintExpiry: %v", err)
	}
	if len(mr.reconverged) != 0 {
		t.Fatalf("DESTROYING/terminal records must churn no identity, but re-converged: %v", mr.reconverged)
	}
}

// --- (5) a store-outage pass STALLS without destroying (doc 15 §3 degraded mode). ---

func TestReconcileMintExpiry_StoreOutage_StallsWithoutDestroying(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC))
	inner := store.NewMemoryClock(clk.now)
	past := clk.now().Add(-time.Hour)
	seedRecordWithHorizon(t, inner, "sess-degraded", "host-F", 0, store.SessionWorking, past)

	deg := &degradedStore{inner: inner, failList: true} // Postgres-DOWN: ListSessions faults
	mr := &recordingMintReconverger{}
	al := &recordingAlarmer{}
	r := newCredTTLReconciler(t, deg, mr, al, clk.now)

	err := r.ReconcileMintExpiry(context.Background())
	if !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a store-outage pass must return the degraded error, got: %v", err)
	}
	// STALL: no re-converge driven, and the AlarmDegraded notice fired (never a destroy).
	if len(mr.reconverged) != 0 {
		t.Fatalf("degraded pass must drive no re-converge, got: %v", mr.reconverged)
	}
	if !al.has(AlarmDegraded) {
		t.Fatalf("expected an AlarmDegraded notice on the store-outage pass; alarms=%v", al.alarms)
	}
	if al.has(AlarmCredentialTTLReconverge) {
		t.Fatalf("no credential-TTL re-converge alarm on a degraded pass; alarms=%v", al.alarms)
	}
}

// --- no-seam posture: with no MintReconverger wired the pass is a documented no-op. ---

func TestReconcileMintExpiry_NoSeam_IsNoOp(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	past := clk.now().Add(-time.Hour)
	seedRecordWithHorizon(t, st, "sess-noseam", "host-G", 0, store.SessionWorking, past)

	al := &recordingAlarmer{}
	// Construct WITHOUT WithMintReconverger — the backstop is disabled.
	r, err := New(st, &recordingDriver{}, &recordingRedriver{}, al, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.ReconcileMintExpiry(context.Background()); err != nil {
		t.Fatalf("no-seam pass must be a clean no-op, got: %v", err)
	}
	if al.has(AlarmCredentialTTLReconverge) {
		t.Fatalf("no-seam pass must raise no credential-TTL alarm; alarms=%v", al.alarms)
	}
}

// --- the backstop drives NEITHER the hypervisor Driver NOR the Redriver (it converges
// credentials, not VM presence) — a guard against a future refactor conflating them. ---

func TestReconcileMintExpiry_DrivesNeitherDriverNorRedriver(t *testing.T) {
	clk := newClock(time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC))
	st := store.NewMemoryClock(clk.now)
	past := clk.now().Add(-time.Hour)
	seedRecordWithHorizon(t, st, "sess-isolate", "host-H", 0, store.SessionWorking, past)

	drv := &recordingDriver{}
	rd := &recordingRedriver{}
	mr := &recordingMintReconverger{}
	r, err := New(st, drv, rd, &recordingAlarmer{}, clk.now, Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.WithMintReconverger(mr)

	if err := r.ReconcileMintExpiry(context.Background()); err != nil {
		t.Fatalf("ReconcileMintExpiry: %v", err)
	}
	if !mr.has("sess-isolate") {
		t.Fatalf("expected the credential re-converge to fire")
	}
	if drv.suspendCount() != 0 || drv.destroyCount() != 0 {
		t.Fatalf("backstop must drive no hypervisor verb: suspends=%d destroys=%d", drv.suspendCount(), drv.destroyCount())
	}
	if rd.count() != 0 {
		t.Fatalf("backstop must drive no Redriver: redrives=%d", rd.count())
	}
}
