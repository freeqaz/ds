// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// The §4.2/§4.3 resume leg must honor the PERSISTED minted-credential horizon (doc 15
// §5.6 / doc 16 §5.4 — an expired credential re-mints on resume). These tests pin the
// two resume verbs:
//
//   - ResumeFromPark (PARKED→CREATING@host') always re-mints (the re-place spine) and
//     MUST advance the durable MintExpiry horizon on the same UpdateSession that records
//     the re-minted IdentityRef/CARef.
//   - Resume (in-place SUSPENDED→RESUMING→WORKING) re-mints ONLY when the persisted
//     horizon is non-zero AND already past — BEFORE the host Resume verb is driven — and
//     resumes unchanged (no Minter call) for a future/zero horizon.
//
// They build on the pr-prefixed synthetic seams in parkresume_test.go (same package);
// only the Expiry-bearing minter and the ordering recorder are new here.

// prMinterExp is an Expiry-bearing Minter fake: it surfaces a configurable
// MintResult.Expiry so the persist + horizon-advance assertions can observe a concrete
// fresh horizon (the pr-prefixed prMinter in parkresume_test.go never sets Expiry).
type prMinterExp struct {
	idRef  string
	caRef  string
	expiry time.Time
	err    error
	calls  int
}

func (m *prMinterExp) Mint(_ context.Context, _ MintWorkloadIdentityClaims, _ string) (MintResult, error) {
	m.calls++
	if m.err != nil {
		return MintResult{}, m.err
	}
	return MintResult{IdentityRef: m.idRef, CARef: m.caRef, Expiry: m.expiry}, nil
}

// prOrderResumer records the call ORDER relative to a shared sequence counter so a test
// can assert the re-mint happened BEFORE the host Resume verb was driven.
type prOrderResumer struct {
	seq      *int
	resumeAt int // the sequence value captured when Resume was driven (0 = not driven)
	calls    int
	err      error
}

func (r *prOrderResumer) Resume(_ context.Context, _, _ string) error {
	*r.seq++
	r.resumeAt = *r.seq
	r.calls++
	return r.err
}

// prOrderMinter records the call ORDER for the same shared sequence counter.
type prOrderMinter struct {
	seq    *int
	mintAt int // the sequence value captured when Mint was called (0 = not called)
	idRef  string
	caRef  string
	expiry time.Time
	calls  int
	err    error
}

func (m *prOrderMinter) Mint(_ context.Context, _ MintWorkloadIdentityClaims, _ string) (MintResult, error) {
	*m.seq++
	m.mintAt = *m.seq
	m.calls++
	if m.err != nil {
		return MintResult{}, m.err
	}
	return MintResult{IdentityRef: m.idRef, CARef: m.caRef, Expiry: m.expiry}, nil
}

// setMintExpiry advances the seeded record's persisted MintExpiry through the store seam
// (the §5.6 column, migration 0010), mirroring the create-time persist.
func setMintExpiry(t *testing.T, repo *store.Memory, uuid string, horizon time.Time) {
	t.Helper()
	if _, err := repo.UpdateSession(context.Background(), uuid, store.SessionUpdate{MintExpiry: &horizon}); err != nil {
		t.Fatalf("seed MintExpiry: %v", err)
	}
}

// fixedClock is the driver clock the mintexpiry tests pin time against (the same instant
// mustDriver uses, named here for the before/after-horizon arithmetic).
var fixedNow = time.Unix(1_700_000_000, 0)

// TestResumeExpiredCredentialReMintsBeforeHostResume is the headline §4.2 assertion: a
// session whose PERSISTED MintExpiry is in the PAST re-mints at resume — the Minter is
// called, the fresh horizon + identity/CA are persisted, and the re-mint happens BEFORE
// the host Resume verb is driven (the session never resumes onto a dead credential).
func TestResumeExpiredCredentialReMintsBeforeHostResume(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	// Persist an EXPIRED horizon (one hour before the driver clock).
	setMintExpiry(t, repo, "s1", fixedNow.Add(-time.Hour))

	seq := 0
	minter := &prOrderMinter{seq: &seq, idRef: "id-fresh", caRef: "ca-fresh", expiry: fixedNow.Add(time.Hour)}
	res := &prOrderResumer{seq: &seq}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res, Minter: minter})

	rec, err := d.Resume(context.Background(), "s1", ResumeAuthorityUser)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if rec.State != store.SessionWorking {
		t.Fatalf("record=%s, want WORKING", rec.State)
	}
	if minter.calls != 1 {
		t.Fatalf("expired credential must re-mint exactly once, got %d Minter calls", minter.calls)
	}
	if res.calls != 1 {
		t.Fatalf("host Resume driven %d times, want 1", res.calls)
	}
	// ORDERING: the re-mint MUST precede the host Resume verb.
	if !(minter.mintAt > 0 && res.resumeAt > 0 && minter.mintAt < res.resumeAt) {
		t.Fatalf("re-mint must run BEFORE the host Resume verb: mintAt=%d resumeAt=%d", minter.mintAt, res.resumeAt)
	}
	// The FRESH identity/CA + advanced horizon are persisted (re-readable through the store).
	got, _ := repo.GetSession(context.Background(), "s1")
	if got.IdentityRef != "id-fresh" || got.CARef != "ca-fresh" {
		t.Fatalf("re-minted identity/CA not persisted: %s/%s", got.IdentityRef, got.CARef)
	}
	if !got.MintExpiry.Equal(fixedNow.Add(time.Hour)) {
		t.Fatalf("durable horizon not advanced to the fresh mint expiry: got %v want %v", got.MintExpiry, fixedNow.Add(time.Hour))
	}
}

// TestResumeFutureHorizonNoReMint: a session whose persisted horizon is still in the
// FUTURE resumes unchanged — NO Minter call, no identity/CA churn, the horizon intact.
func TestResumeFutureHorizonNoReMint(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	future := fixedNow.Add(time.Hour)
	setMintExpiry(t, repo, "s1", future)
	// Pin the seed identity/CA so a (forbidden) re-mint would be observable as churn.
	if _, err := repo.UpdateSession(context.Background(), "s1", store.SessionUpdate{
		IdentityRef: ptr("id-orig"), CARef: ptr("ca-orig"),
	}); err != nil {
		t.Fatalf("seed identity/CA: %v", err)
	}

	minter := &prMinterExp{idRef: "id-NEW", caRef: "ca-NEW", expiry: fixedNow.Add(2 * time.Hour)}
	res := &prResumer{}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res, Minter: minter})

	rec, err := d.Resume(context.Background(), "s1", ResumeAuthorityUser)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if rec.State != store.SessionWorking {
		t.Fatalf("record=%s, want WORKING", rec.State)
	}
	if minter.calls != 0 {
		t.Fatalf("a future-horizon resume must NOT re-mint, got %d Minter calls", minter.calls)
	}
	if res.calls != 1 {
		t.Fatalf("host Resume driven %d times, want 1", res.calls)
	}
	got, _ := repo.GetSession(context.Background(), "s1")
	if got.IdentityRef != "id-orig" || got.CARef != "ca-orig" {
		t.Fatalf("a no-churn resume must not rewrite identity/CA: got %s/%s", got.IdentityRef, got.CARef)
	}
	if !got.MintExpiry.Equal(future) {
		t.Fatalf("future horizon must be left intact: got %v want %v", got.MintExpiry, future)
	}
}

// TestResumeZeroHorizonNoReMint: a session with NO tracked horizon (zero MintExpiry — the
// not-set / bare-MintClient posture) resumes unchanged with no Minter call.
func TestResumeZeroHorizonNoReMint(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	// No setMintExpiry: the seeded record carries the zero (not-set) horizon.

	minter := &prMinterExp{idRef: "id-NEW", caRef: "ca-NEW", expiry: fixedNow.Add(time.Hour)}
	res := &prResumer{}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res, Minter: minter})

	rec, err := d.Resume(context.Background(), "s1", ResumeAuthorityUser)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if rec.State != store.SessionWorking {
		t.Fatalf("record=%s, want WORKING", rec.State)
	}
	if minter.calls != 0 {
		t.Fatalf("a zero-horizon (no TTL tracked) resume must NOT re-mint, got %d Minter calls", minter.calls)
	}
	if res.calls != 1 {
		t.Fatalf("host Resume driven %d times, want 1", res.calls)
	}
}

// TestResumeExpiredCredentialNoMinterIsClearError: an expired horizon with NO Minter seam
// wired is a clear fail-closed error — the session stays SUSPENDED and the host Resume
// verb is never driven (resuming onto a dead credential is refused).
func TestResumeExpiredCredentialNoMinterIsClearError(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	setMintExpiry(t, repo, "s1", fixedNow.Add(-time.Hour))

	res := &prResumer{}
	// Minter deliberately unwired.
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res})

	_, err := d.Resume(context.Background(), "s1", ResumeAuthorityUser)
	if err == nil {
		t.Fatal("expected a clear error when an expired credential needs a re-mint but no Minter is wired")
	}
	if res.calls != 0 {
		t.Fatalf("a refused re-mint must not drive the host Resume verb, got %d calls", res.calls)
	}
	got, _ := repo.GetSession(context.Background(), "s1")
	if got.State != store.SessionSuspended {
		t.Fatalf("a refused resume must stay at SUSPENDED, got %s", got.State)
	}
}

// TestResumeExpiredReMintFailureStaysSuspended: when the re-mint of an expired credential
// FAILS, the error surfaces and the session stays SUSPENDED (the reconciler re-drives) —
// the host Resume verb is never driven.
func TestResumeExpiredReMintFailureStaysSuspended(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	setMintExpiry(t, repo, "s1", fixedNow.Add(-time.Hour))

	res := &prResumer{}
	minter := &prMinterExp{err: errors.New("mint backend down")}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res, Minter: minter})

	_, err := d.Resume(context.Background(), "s1", ResumeAuthorityUser)
	if err == nil {
		t.Fatal("expected the re-mint failure to surface")
	}
	if res.calls != 0 {
		t.Fatalf("a failed re-mint must not drive the host Resume verb, got %d calls", res.calls)
	}
	got, _ := repo.GetSession(context.Background(), "s1")
	if got.State != store.SessionSuspended {
		t.Fatalf("a failed re-mint must leave the session SUSPENDED, got %s", got.State)
	}
}

// TestResumeExpiredCredentialDeniedDoesNotReMint: the authority gate runs BEFORE the
// horizon check, so a DENIED resume (policy_breach without a landed approval) does NOT
// re-mint and does not touch the host — the session stays SUSPENDED. This pins the
// ordering: no credential churn for a resume that authority refuses.
func TestResumeExpiredCredentialDeniedDoesNotReMint(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionSuspended, store.SuspendReasonPolicyBreach)
	setMintExpiry(t, repo, "s1", fixedNow.Add(-time.Hour))

	res := &prResumer{}
	minter := &prMinterExp{idRef: "id-fresh", caRef: "ca-fresh", expiry: fixedNow.Add(time.Hour)}
	d := mustDriver(t, ParkResumeSeams{Store: repo, Resumer: res, Minter: minter, Approvals: prApprovals{landed: false}})

	_, err := d.Resume(context.Background(), "s1", ResumeAuthorityHumanApproval)
	var denied *ErrResumeDenied
	if !errors.As(err, &denied) {
		t.Fatalf("expected ErrResumeDenied, got %v", err)
	}
	if minter.calls != 0 {
		t.Fatalf("a denied resume must not re-mint, got %d Minter calls", minter.calls)
	}
	if res.calls != 0 {
		t.Fatal("a denied resume must not drive the host Resume verb")
	}
}

// TestResumeFromParkAdvancesDurableHorizon is the §4.3 re-place assertion: ResumeFromPark
// re-mints on the re-place spine and MUST advance the durable MintExpiry horizon — the
// fresh MintResult.Expiry lands on the PARKED→CREATING UpdateSession alongside the
// re-minted IdentityRef/CARef, and is re-readable through the store.
func TestResumeFromParkAdvancesDurableHorizon(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionParked, store.SuspendReasonNone)
	freshHorizon := fixedNow.Add(90 * time.Minute)
	placer := &prPlacer{hostID: "host-b", appliedSeq: 42}
	alloc := &prAlloc{idx: 5, tap: "dstap-5"}
	minter := &prMinterExp{idRef: "id-rp", caRef: "ca-rp", expiry: freshHorizon}
	d := mustDriver(t, ParkResumeSeams{
		Store: repo, Placer: placer, HostAllocator: alloc, Minter: minter,
		Approvals: prApprovals{landed: true},
	})

	rec, err := d.ResumeFromPark(context.Background(), "s1", ResumeAuthorityUser, attachReasonUser)
	if err != nil {
		t.Fatalf("ResumeFromPark: %v", err)
	}
	if rec.State != store.SessionCreating {
		t.Fatalf("record=%s, want CREATING@host'", rec.State)
	}
	if minter.calls != 1 {
		t.Fatalf("re-place must re-mint exactly once, got %d Minter calls", minter.calls)
	}
	if rec.IdentityRef != "id-rp" || rec.CARef != "ca-rp" {
		t.Fatalf("re-minted identity/CA not recorded: %s/%s", rec.IdentityRef, rec.CARef)
	}
	if !rec.MintExpiry.Equal(freshHorizon) {
		t.Fatalf("durable horizon not advanced on re-place: got %v want %v", rec.MintExpiry, freshHorizon)
	}
	// Re-readable through the store (the persist landed, not just the returned value).
	got, _ := repo.GetSession(context.Background(), "s1")
	if !got.MintExpiry.Equal(freshHorizon) {
		t.Fatalf("advanced horizon not persisted: got %v want %v", got.MintExpiry, freshHorizon)
	}
}

// TestResumeFromParkZeroExpiryPersistsNotSet: a re-place re-mint that surfaces NO expiry
// (a bare Minter — the zero MintResult.Expiry) persists the not-set (zero) horizon, never
// a spurious TTL.
func TestResumeFromParkZeroExpiryPersistsNotSet(t *testing.T) {
	repo := store.NewMemory()
	seedSession(t, repo, "s1", "host-a", 1, store.SessionParked, store.SuspendReasonNone)
	// Pre-seed a stale horizon to prove the zero-expiry re-mint clears it to not-set.
	setMintExpiry(t, repo, "s1", fixedNow.Add(-time.Hour))
	placer := &prPlacer{hostID: "host-b", appliedSeq: 1}
	alloc := &prAlloc{idx: 3, tap: "dstap-3"}
	minter := &prMinterExp{idRef: "id-rp", caRef: "ca-rp"} // expiry left zero
	d := mustDriver(t, ParkResumeSeams{
		Store: repo, Placer: placer, HostAllocator: alloc, Minter: minter,
		Approvals: prApprovals{landed: true},
	})

	rec, err := d.ResumeFromPark(context.Background(), "s1", ResumeAuthorityUser, attachReasonUser)
	if err != nil {
		t.Fatalf("ResumeFromPark: %v", err)
	}
	if !rec.MintExpiry.IsZero() {
		t.Fatalf("a zero-expiry re-mint must persist the not-set horizon, got %v", rec.MintExpiry)
	}
	got, _ := repo.GetSession(context.Background(), "s1")
	if !got.MintExpiry.IsZero() {
		t.Fatalf("not-set horizon not re-readable as zero: got %v", got.MintExpiry)
	}
}

func ptr[T any](v T) *T { return &v }
