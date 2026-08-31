// SPDX-License-Identifier: Apache-2.0

// Grant-fetch protocol contract tests (doc 16 §5.1, §5.4, §9): per-session fetch
// (never per-request), cache-rides-outage (a store outage stalls only NEW
// fetches while in-flight sessions ride their cache), eviction-on-suspend, and
// park/resume TTL re-validation. Everything synthetic (D50); the clock is pinned.
package grantservice

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	// attachv1 is consumed READ-ONLY for the §5.4 SUSPENDED(reason) cause (D35/D77):
	// the frozen attach.v1 SuspendReason the eviction records. Projection only — no
	// re-declare, no new enum (D80).
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

const (
	testSession = "00000000-0000-4000-8000-0000000000f1"
	testService = "github"
	testRef     = "grant:00000000-0000-4000-8000-0000000000f1:github"
)

func fixedClock() func() time.Time {
	t := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// countingBackend wraps a Backend and counts Fetch calls — the lever for the
// "per-session fetch, never per-request" assertion (§9).
type countingBackend struct {
	inner Backend
	calls int64
}

func (c *countingBackend) Fetch(grantRef string) (Credential, error) {
	atomic.AddInt64(&c.calls, 1)
	return c.inner.Fetch(grantRef)
}

func newTestService(t *testing.T) (*Service, *countingBackend, *FileKVBackend) {
	t.Helper()
	fake := NewInMemoryBackend(map[string]Credential{
		testRef: {Secret: []byte("synthetic-pat-DO-NOT-USE"), Location: "Authorization"},
	})
	cb := &countingBackend{inner: fake}
	svc := New(cb, WithClock(fixedClock()))
	return svc, cb, fake
}

// TestFetch_PerSessionNeverPerRequest proves the §9 invariant: the swap executor
// fetches PER-SESSION, then rides the cache — N requests for the same
// session×service hit the backend exactly ONCE.
func TestFetch_PerSessionNeverPerRequest(t *testing.T) {
	svc, cb, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))

	for i := 0; i < 50; i++ {
		cred, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute))
		if err != nil {
			t.Fatalf("fetch %d: %v", i, err)
		}
		if string(cred.Secret) != "synthetic-pat-DO-NOT-USE" {
			t.Fatalf("fetch %d: wrong secret %q", i, cred.Secret)
		}
	}
	if got := atomic.LoadInt64(&cb.calls); got != 1 {
		t.Fatalf("backend hit %d times; per-session fetch must hit exactly once", got)
	}
}

// TestFetch_CacheRidesOutage is the load-bearing §5.1 test: a store outage
// stalls only NEW grant fetches; an in-flight session whose grant is already
// cached rides its cache and keeps serving.
func TestFetch_CacheRidesOutage(t *testing.T) {
	svc, cb, fake := newTestService(t)
	now := svc.now()

	// In-flight session: registered and warmed (one fetch) BEFORE the outage.
	svc.RegisterSession(testSession, now.Add(time.Hour))
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("warm fetch: %v", err)
	}

	// The store goes down.
	fake.SetAvailable(false)

	// The in-flight session RIDES its cache — still serves, backend not consulted.
	cred, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("in-flight session must ride cache through outage, got: %v", err)
	}
	if string(cred.Secret) != "synthetic-pat-DO-NOT-USE" {
		t.Fatalf("cached secret wrong: %q", cred.Secret)
	}
	// The backend was hit exactly once (the warm fetch) — the outage never added
	// a call, because the cache served.
	if got := atomic.LoadInt64(&cb.calls); got != 1 {
		t.Fatalf("backend hit %d times; cache should have served through outage", got)
	}

	// A NEW session's NEW fetch STALLS during the outage (only new fetches stall).
	newSession := "00000000-0000-4000-8000-0000000000f2"
	newRef := "grant:00000000-0000-4000-8000-0000000000f2:github"
	svc.RegisterSession(newSession, now.Add(time.Hour))
	_, err = svc.Fetch(newSession, testService, newRef, now.Add(30*time.Minute))
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("new fetch during outage must stall with ErrStoreUnavailable, got: %v", err)
	}

	// When the store recovers, the new fetch succeeds (the stall was transient).
	fake.SetAvailable(true)
	// Seed the new session's credential so recovery has something to read.
	fake2 := NewInMemoryBackend(map[string]Credential{newRef: {Secret: []byte("synthetic-pat-2"), Location: "Authorization"}})
	svc.backend = &countingBackend{inner: fake2}
	if _, err := svc.Fetch(newSession, testService, newRef, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("new fetch after recovery should succeed: %v", err)
	}
}

// TestSuspend_EvictsGrants proves the §5.4 eviction-on-suspend: the suspend
// signal evicts a session's grants, so a subsequent fetch fails closed until the
// session is re-registered. It drives the reasoned form (SuspendWithReason) so the
// caller passes the frozen attach.v1 SUSPENDED(reason) cause (D77 POLICY_BREACH,
// the genuine-threat class), and asserts BOTH that eviction behavior is UNCHANGED
// (fail-closed, cache gone) AND that the recorded cause is read-back-able via the
// read-only LastSuspendReason accessor after the grants are gone.
func TestSuspend_EvictsGrants(t *testing.T) {
	svc, _, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(svc.CachedServices(testSession)) != 1 {
		t.Fatal("expected one cached grant before suspend")
	}
	// No suspend record exists before the suspend fires (fail-closed absence).
	if _, ok := svc.LastSuspendReason(testSession); ok {
		t.Fatal("no suspend reason should be recorded before suspend")
	}

	svc.SuspendWithReason(testSession, attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH)

	// The cache is gone; a fetch fails closed — eviction behavior UNCHANGED.
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); !errors.Is(err, ErrSessionNotLive) {
		t.Fatalf("post-suspend fetch must fail closed, got: %v", err)
	}
	if svc.CachedServices(testSession) != nil {
		t.Fatal("suspend must evict the session cache entirely")
	}
	// The recorded cause SURVIVES the eviction and reads back read-only (§5.4/§8.2):
	// the POLICY_BREACH classification the caller drove is observable after the grants
	// are gone, projected from the frozen enum.
	got, ok := svc.LastSuspendReason(testSession)
	if !ok {
		t.Fatal("suspend must record the SUSPENDED(reason) cause, read-back-able after eviction")
	}
	if got != attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH {
		t.Fatalf("recorded suspend reason = %v, want POLICY_BREACH", got)
	}
}

// TestSuspend_UserReasonShim proves the sessionUUID-only Suspend shim keeps its
// exact shape AND records the offboarding/user-initiated cause (SUSPEND_REASON_USER,
// §11.2): an unqualified suspend evicts identically to SuspendWithReason and the
// recorded cause is USER — distinguishable from the POLICY_BREACH form, so the
// §8.2 resume-authority split can tell the two apart.
func TestSuspend_UserReasonShim(t *testing.T) {
	svc, _, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	svc.Suspend(testSession)

	// Eviction behavior unchanged: fail-closed, cache gone.
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); !errors.Is(err, ErrSessionNotLive) {
		t.Fatalf("post-suspend fetch must fail closed, got: %v", err)
	}
	// The bare shim records the USER cause — the read-only accessor reads it back and
	// it is DISTINGUISHABLE from POLICY_BREACH.
	got, ok := svc.LastSuspendReason(testSession)
	if !ok {
		t.Fatal("the Suspend shim must record a SUSPENDED(reason) cause")
	}
	if got != attachv1.SuspendReason_SUSPEND_REASON_USER {
		t.Fatalf("bare Suspend recorded reason = %v, want USER", got)
	}
	if got == attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH {
		t.Fatal("USER and POLICY_BREACH suspend causes must be distinguishable")
	}
}

// TestParkResume_SurvivesAndReValidates proves the §5.4 park/resume path: cached
// grants SURVIVE park (unlike suspend), the session fetches no NEW grants while
// parked, and Resume re-validates against liveness + TTL — dropping a cached
// grant past its TTL so the caller re-mints.
func TestParkResume_SurvivesAndReValidates(t *testing.T) {
	// A movable clock so we can advance past a grant TTL across the park.
	tick := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return tick }
	fake := NewInMemoryBackend(map[string]Credential{
		testRef: {Secret: []byte("synthetic-pat"), Location: "Authorization"},
	})
	svc := New(fake, WithClock(clock))

	sessionDeadline := tick.Add(2 * time.Hour)
	svc.RegisterSession(testSession, sessionDeadline)
	// Warm a grant with a SHORT TTL (10 min) so it expires across the park.
	grantExpiry := tick.Add(10 * time.Minute)
	if _, err := svc.Fetch(testSession, testService, testRef, grantExpiry); err != nil {
		t.Fatal(err)
	}

	// Park: the cache SURVIVES (unlike suspend).
	svc.Park(testSession)
	if len(svc.CachedServices(testSession)) != 1 {
		t.Fatal("park must keep the cache (grants survive snapshot+park, §5.4)")
	}
	// A parked session does NOT fetch NEW grants (a not-yet-cached service stalls).
	// The ref is the contract handle for THIS session×npm (FormatGrantRef), so the
	// reader-side GrantRef guard passes and the test exercises the park refusal,
	// not a ref mismatch.
	if _, err := svc.Fetch(testSession, "npm", FormatGrantRef(testSession, "npm"), tick.Add(time.Hour)); !errors.Is(err, errParkedSession) {
		t.Fatalf("parked session must refuse a NEW fetch, got: %v", err)
	}

	// Advance the clock past the grant TTL but within the session deadline.
	tick = tick.Add(30 * time.Minute) // now 12:30; grant TTL was 12:10

	// Resume re-validates: the expired cached grant is dropped (expired creds
	// re-mint, §5.4), the session is live again.
	if err := svc.Resume(testSession, time.Time{}); err != nil {
		t.Fatalf("resume within session deadline should succeed: %v", err)
	}
	if len(svc.CachedServices(testSession)) != 0 {
		t.Fatal("resume must drop the cached grant past its TTL (re-validation)")
	}
	// And the session is LIVE: a fresh fetch works again.
	if _, err := svc.Fetch(testSession, testService, testRef, tick.Add(time.Hour)); err != nil {
		t.Fatalf("post-resume fetch should succeed: %v", err)
	}
}

// TestResume_DeadSessionFailsClosed proves a session past its session-lifetime
// deadline is NOT resumed (fail-closed): a dead session does not silently
// resume (§5.4 / §11.2 offboarding discipline).
func TestResume_DeadSessionFailsClosed(t *testing.T) {
	tick := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return tick }
	fake := NewInMemoryBackend(map[string]Credential{testRef: {Secret: []byte("x")}})
	svc := New(fake, WithClock(clock))

	svc.RegisterSession(testSession, tick.Add(10*time.Minute))
	if _, err := svc.Fetch(testSession, testService, testRef, tick.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	svc.Park(testSession)

	// Advance past the session deadline.
	tick = tick.Add(20 * time.Minute)
	if err := svc.Resume(testSession, time.Time{}); !errors.Is(err, ErrSessionNotLive) {
		t.Fatalf("resuming a session past its deadline must fail closed, got: %v", err)
	}
}

// TestFetch_GrantNotFound proves a missing grant is a definitive deny, distinct
// from an outage stall.
func TestFetch_GrantNotFound(t *testing.T) {
	svc, _, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))
	// A well-formed contract ref (passes the reader-side guard) whose grant_ref the
	// store simply does not hold: the result is a definitive ErrGrantNotFound,
	// distinct from both an outage stall and a ref mismatch.
	_, err := svc.Fetch(testSession, "unknown", FormatGrantRef(testSession, "unknown"), now.Add(time.Hour))
	if !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("missing grant must be ErrGrantNotFound, got: %v", err)
	}
}

// TestFetchForRecord_SameCredentialAsStringPath proves the record-keyed
// FetchForRecord entry point and the string-keyed Fetch resolve to the IDENTICAL
// Backend.Fetch call: a caller holding a frozen grant RECORD gets the exact same
// credential as the raw-string caller, and — because both paths key the session
// cache on the same service_id — the second (record) call is served from cache,
// so the backend is hit exactly ONCE across both (the §9 per-session invariant is
// preserved across the two entry points).
func TestFetchForRecord_SameCredentialAsStringPath(t *testing.T) {
	svc, cb, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))

	// String path warms the cache.
	strCred, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("string-keyed Fetch: %v", err)
	}

	// Record path: the caller holds a frozen identity.v1.Grant whose grant_ref and
	// service_id are the same contract handle. It must return the same credential —
	// and ride the cache the string path warmed (no new backend call).
	rec := &GrantRecord{GrantRef: testRef, ServiceId: testService}
	recCred, err := svc.FetchForRecord(testSession, rec, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("record-keyed FetchForRecord: %v", err)
	}
	if string(recCred.Secret) != string(strCred.Secret) || recCred.Location != strCred.Location {
		t.Fatalf("record path credential %+v != string path credential %+v", recCred, strCred)
	}
	if string(recCred.Secret) != "synthetic-pat-DO-NOT-USE" {
		t.Fatalf("record path served wrong secret: %q", recCred.Secret)
	}
	if got := atomic.LoadInt64(&cb.calls); got != 1 {
		t.Fatalf("string+record paths must resolve to ONE Backend.Fetch (same key); got %d", got)
	}
}

// TestFetchForRecord_CacheRidesOutage is the record-keyed form of the load-bearing
// §5.1 assertion: FetchForRecord obeys the identical cache-hit/outage semantics —
// a cache HIT never consults the backend (rides an outage), while a cache MISS with
// the store DOWN returns ErrStoreUnavailable (only NEW fetches stall).
func TestFetchForRecord_CacheRidesOutage(t *testing.T) {
	svc, cb, fake := newTestService(t)
	now := svc.now()

	// Warm an in-flight session through the record path BEFORE the outage.
	svc.RegisterSession(testSession, now.Add(time.Hour))
	warmRec := &GrantRecord{GrantRef: testRef, ServiceId: testService}
	if _, err := svc.FetchForRecord(testSession, warmRec, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("warm record fetch: %v", err)
	}

	// Store goes down. The warmed session RIDES its cache — backend not consulted.
	fake.SetAvailable(false)
	cred, err := svc.FetchForRecord(testSession, warmRec, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("cached record must ride outage, got: %v", err)
	}
	if string(cred.Secret) != "synthetic-pat-DO-NOT-USE" {
		t.Fatalf("cached secret wrong: %q", cred.Secret)
	}
	if got := atomic.LoadInt64(&cb.calls); got != 1 {
		t.Fatalf("record cache should have served through outage; backend hit %d times", got)
	}

	// A NEW session's cache MISS during the outage STALLS with ErrStoreUnavailable
	// (only new fetches stall) — driven through the record entry point.
	newSession := "00000000-0000-4000-8000-0000000000f3"
	newRef := FormatGrantRef(newSession, testService)
	svc.RegisterSession(newSession, now.Add(time.Hour))
	newRec := &GrantRecord{GrantRef: newRef, ServiceId: testService}
	if _, err := svc.FetchForRecord(newSession, newRec, now.Add(30*time.Minute)); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("new record fetch during outage must stall with ErrStoreUnavailable, got: %v", err)
	}
}

// TestFetchForRecord_MisBoundRecordFailsClosed proves the reader-side fail-closed
// guard on the record path: a MIS-BOUND record — one whose grant_ref does not
// parse back to (session, record.ServiceId) — is a definitive non-match
// (ErrGrantRefMismatch), never a silently-wrong store lookup, and never reaches
// the backend.
func TestFetchForRecord_MisBoundRecordFailsClosed(t *testing.T) {
	svc, cb, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))

	// grant_ref is bound to service "github" but the record claims service_id
	// "npm" — the axes disagree, so the record is mis-bound.
	misBound := &GrantRecord{GrantRef: testRef, ServiceId: "npm"}
	if _, err := svc.FetchForRecord(testSession, misBound, now.Add(30*time.Minute)); !errors.Is(err, ErrGrantRefMismatch) {
		t.Fatalf("mis-bound record must fail closed with ErrGrantRefMismatch, got: %v", err)
	}

	// A record whose grant_ref is for a DIFFERENT session is likewise a non-match.
	wrongSession := &GrantRecord{GrantRef: FormatGrantRef("00000000-0000-4000-8000-0000000000ff", testService), ServiceId: testService}
	if _, err := svc.FetchForRecord(testSession, wrongSession, now.Add(30*time.Minute)); !errors.Is(err, ErrGrantRefMismatch) {
		t.Fatalf("record bound to a different session must fail closed, got: %v", err)
	}

	// The fail-closed guard runs BEFORE any store lookup — the backend was never hit.
	if got := atomic.LoadInt64(&cb.calls); got != 0 {
		t.Fatalf("mis-bound record must not reach the backend; got %d Fetch calls", got)
	}
}

// TestFileKVBackend_LoadsSyntheticFixture proves the OSS local file/KV fake
// loads a synthetic JSON fixture (D50) — never a live store.
func TestFileKVBackend_LoadsSyntheticFixture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	fixture := `{"grant:s:github":{"secret":"synthetic-only","location":"Authorization"}}`
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	be, err := NewFileKVBackend(path)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := be.Fetch("grant:s:github")
	if err != nil {
		t.Fatal(err)
	}
	if string(cred.Secret) != "synthetic-only" || cred.Location != "Authorization" {
		t.Fatalf("fixture not loaded: %+v", cred)
	}
}

// TestFileKVBackend_CommittedFixture exercises the committed synthetic store
// fixture (testdata/synthetic-store.json) end to end through the per-session
// fetch — proving the OSS local file/KV substrate is wired and the fixture is
// strictly synthetic (D50).
func TestFileKVBackend_CommittedFixture(t *testing.T) {
	be, err := NewFileKVBackend(filepath.Join("testdata", "synthetic-store.json"))
	if err != nil {
		t.Fatal(err)
	}
	svc := New(be, WithClock(fixedClock()))
	session := "00000000-0000-4000-8000-000000000001"
	ref := "grant:00000000-0000-4000-8000-000000000001:github"
	svc.RegisterSession(session, svc.now().Add(time.Hour))
	cred, err := svc.Fetch(session, "github", ref, svc.now().Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if string(cred.Secret) != "SYNTHETIC-PAT-DO-NOT-USE-d50-fixture" {
		t.Fatalf("committed fixture not served through the cache: %q", cred.Secret)
	}
}

// TestResumeAuthority_PolicyBreachBlocksPlainResume proves the doc 16 §8.2
// resume-authority split (D35) on the grant service: a session whose recorded
// last-suspend reason is the genuine-threat SUSPEND_REASON_POLICY_BREACH FAILS
// CLOSED on the plain Resume path (ErrResumeApprovalRequired) without an explicit
// human-approval attestation, and PROCEEDS with one via ResumeWithApproval. The
// attestation is a NON-SECRET marker (doc 16 §5.2), never a credential. Because
// Suspend evicts (§5.4), the session is re-registered before the resume — the
// authority gate reads the read-back-able lastSuspend record, which SURVIVES the
// eviction.
func TestResumeAuthority_PolicyBreachBlocksPlainResume(t *testing.T) {
	svc, _, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A genuine-threat (BIC) suspension: evicts + records POLICY_BREACH.
	svc.SuspendWithReason(testSession, attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH)

	// Re-register the session (eviction dropped its cache entry). The POLICY_BREACH
	// cause is still on record.
	svc.RegisterSession(testSession, now.Add(time.Hour))

	// Plain Resume FAILS CLOSED: a POLICY_BREACH suspension's resume authority is
	// human approval, not the plain path.
	if err := svc.Resume(testSession, time.Time{}); !errors.Is(err, ErrResumeApprovalRequired) {
		t.Fatalf("plain Resume of a POLICY_BREACH-suspended session must fail closed, got: %v", err)
	}
	// An ABSENT (zero-value) attestation is treated exactly like the plain path —
	// still fails closed.
	if err := svc.ResumeWithApproval(testSession, time.Time{}, ResumeApproval{}); !errors.Is(err, ErrResumeApprovalRequired) {
		t.Fatalf("ResumeWithApproval with an absent attestation must fail closed, got: %v", err)
	}

	// A PRESENT human-approval attestation authorizes the resume — it proceeds.
	approval := ResumeApproval{Approver: "org-admin:alice", Reference: "ask-grant:synthetic-001"}
	if err := svc.ResumeWithApproval(testSession, time.Time{}, approval); err != nil {
		t.Fatalf("approved resume of a POLICY_BREACH-suspended session must proceed, got: %v", err)
	}
	// The session is LIVE again: a fresh fetch works.
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("post-approved-resume fetch should succeed: %v", err)
	}
	// The attestation is a non-secret marker: it carries no credential material.
	if strings.Contains(approval.Approver+approval.Reference, "PAT") {
		t.Fatal("a ResumeApproval must never carry credential material (doc 16 §5.2)")
	}
}

// TestResumeAuthority_UserResumesOnExistingPathUnchanged proves the §8.2 split is
// POLICY_BREACH-ONLY: a session whose recorded last-suspend reason is the
// offboarding/user-initiated SUSPEND_REASON_USER resumes on the EXISTING plain
// Resume path with signature AND semantics INTACT — no attestation invented, USER
// is NOT made to fail closed (doc 15 §3; the D35 split enforced exactly).
func TestResumeAuthority_UserResumesOnExistingPathUnchanged(t *testing.T) {
	svc, _, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// The bare Suspend shim records USER (§11.2 offboarding fires the existing signal).
	svc.Suspend(testSession)
	if got, _ := svc.LastSuspendReason(testSession); got != attachv1.SuspendReason_SUSPEND_REASON_USER {
		t.Fatalf("bare Suspend must record USER, got %v", got)
	}
	// Re-register and resume on the PLAIN path — it must succeed unchanged (no
	// approval required for USER).
	svc.RegisterSession(testSession, now.Add(time.Hour))
	if err := svc.Resume(testSession, time.Time{}); err != nil {
		t.Fatalf("plain Resume of a USER-suspended session must proceed unchanged, got: %v", err)
	}
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("post-resume fetch should succeed for a USER-suspended session: %v", err)
	}
}

// TestResumeAuthority_RebalanceRecordsReadsBackAndResumes is the third frozen
// value's first grant-service coverage: a REBALANCE suspension (recorded via
// SuspendWithReason(REBALANCE)) reads back through LastSuspendReason as REBALANCE
// AND resumes on the NON-APPROVAL plain path (D35: only POLICY_BREACH gates on an
// attestation; REBALANCE rides the existing Resume path like USER).
func TestResumeAuthority_RebalanceRecordsReadsBackAndResumes(t *testing.T) {
	svc, _, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A load-rebalance suspension: evicts + records REBALANCE (the third frozen value).
	svc.SuspendWithReason(testSession, attachv1.SuspendReason_SUSPEND_REASON_REBALANCE)

	// The cause reads back as REBALANCE, distinguishable from USER and POLICY_BREACH.
	got, ok := svc.LastSuspendReason(testSession)
	if !ok {
		t.Fatal("a REBALANCE suspend must record a read-back-able cause")
	}
	if got != attachv1.SuspendReason_SUSPEND_REASON_REBALANCE {
		t.Fatalf("recorded REBALANCE cause = %v, want REBALANCE", got)
	}
	if got == attachv1.SuspendReason_SUSPEND_REASON_USER || got == attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH {
		t.Fatal("REBALANCE must be distinguishable from USER and POLICY_BREACH")
	}

	// Re-register and resume on the PLAIN path — REBALANCE does NOT gate on approval.
	svc.RegisterSession(testSession, now.Add(time.Hour))
	if err := svc.Resume(testSession, time.Time{}); err != nil {
		t.Fatalf("plain Resume of a REBALANCE-suspended session must proceed (non-approval path), got: %v", err)
	}
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("post-resume fetch should succeed for a REBALANCE-suspended session: %v", err)
	}
}

// TestResumeAuthority_NoRecordedReasonResumesUnchanged proves a session with NO
// recorded suspend reason (never suspended, or park/resume without a suspend)
// resumes on the plain path unchanged — the authority gate keys on the presence of
// a POLICY_BREACH record, so its absence never fails closed.
func TestResumeAuthority_NoRecordedReasonResumesUnchanged(t *testing.T) {
	svc, _, _ := newTestService(t)
	now := svc.now()
	svc.RegisterSession(testSession, now.Add(time.Hour))
	if _, err := svc.Fetch(testSession, testService, testRef, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	// No suspend recorded — park then resume on the plain path succeeds unchanged.
	if _, ok := svc.LastSuspendReason(testSession); ok {
		t.Fatal("no suspend reason should be recorded for a never-suspended session")
	}
	svc.Park(testSession)
	if err := svc.Resume(testSession, time.Time{}); err != nil {
		t.Fatalf("plain Resume of a session with no recorded suspend reason must proceed, got: %v", err)
	}
}
