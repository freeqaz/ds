package store

// This file is the SHARED repository conformance suite — the D33 equivalence
// pin. It lives in a non-test file so both the in-memory test (memory_test.go)
// and the env-gated Postgres test (postgres_test.go, behind DS_PG_DSN) drive
// the IDENTICAL assertions against whatever Repository the harness hands it.
//
// The factory the suite receives must return a FRESH, EMPTY Repository on each
// call, wired to the supplied clock so the TTL-expiry assertions are
// deterministic. The in-memory impl uses NewMemoryClock; the Postgres impl
// truncates its tables and returns NewPostgresClock.
//
// Vocabulary: the suite names states through the store's SessionState constants
// (SessionPending … SessionDestroyed), which are pinned token-for-token to the
// §3 transition table in internal/sessions (the vocabpin package + the
// sessions cross-test). Two of the cases below — MigrateSnapshotToReadyRebindsEpoch and
// SuspendResumeClearsReason — exercise the precise transitions whose omission
// (MIGRATING, RESUMING) the rejected wave hid behind a green build.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// RepoFactory builds a fresh empty Repository using the supplied clock.
type RepoFactory func(now func() time.Time) Repository

// fixedClock returns a clock that always reports t (call sites advance it by
// returning a fresh closure when they need a different now).
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// RunConformance runs the full suite against the factory. Both impls call it.
func RunConformance(t *testing.T, newRepo RepoFactory) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(*testing.T, RepoFactory)
	}{
		{"CreateChoreography", testCreateChoreography},
		{"CreateIdempotentOnUUID", testCreateIdempotent},
		{"CreateConflictingRef", testCreateConflictingRef},
		{"BurnedIndexNeverRecycled", testBurnedIndex},
		{"DestroyFinalizationRetainsRecord", testDestroyFinalization},
		{"SuspendReasonInvariant", testSuspendReasonInvariant},
		{"SuspendResumeClearsReason", testSuspendResumeClearsReason},
		{"IndexEpochHistory", testIndexEpochHistory},
		{"MigrateSnapshotToReadyRebindsEpoch", testMigrateRebindsEpoch},
		{"PolicyLogAppendOnlyMonotonicActor", testPolicyLog},
		{"AskGrantTTL", testAskGrantTTL},
		{"EnvConfigRoundTrip", testEnvConfig},
		{"PlanRoundTrip", testPlan},
		{"RepositoryOrphanFKWritesRejected", testRepositoryOrphanFKWrites},
		{"MeteringIdempotent", testMetering},
		{"ListSessionsFilters", testListSessions},
		{"ListSessionsKeysetPagination", testListSessionsKeysetPagination},
		{"PrincipalRoundTrip", testPrincipalRoundTrip},
		{"PrincipalIdPSubjectLookup", testPrincipalIdPLookup},
		{"PrincipalRoleCheckParity", testPrincipalRoleCheckParity},
		{"SessionLaunchingPrincipalAttribution", testSessionLaunchingPrincipal},
		{"RolePinPersistence", testRolePinPersistence},
		{"MintExpiryPersistence", testMintExpiryPersistence},
		{"MintExpiryReArmReadPosture", testMintExpiryReArmReadPosture},
		{"NotFound", testNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newRepo) })
	}
}

var baseTime = time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)

// newSession returns a minimal valid §5.6 record skeleton for create.
func newSession(uuid, host string, idx uint64) Session {
	return Session{
		Ref: SessionRef{
			SessionUUID:      uuid,
			HostID:           host,
			HostSessionIndex: idx,
			TapName:          fmt.Sprintf("dstap-%d", idx),
		},
		State:        SessionPending,
		EnvConfigRef: "env-ref-1",
		ImageID:      "sha256:img",
	}
}

// testCreateChoreography exercises the doc 15 §4.1 create writes end to end:
// create the record with the SessionRef quartet, policy-posture update, the
// digest-ack gate flip, and the gated READY transition.
func testCreateChoreography(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()

	// Step 2: session record created with the quartet.
	in := newSession("sess-1", "host-a", 7)
	in.IdentityRef, in.CARef = "id-1", "ca-1" // §4.1 step 5 mint refs
	got, err := repo.CreateSession(ctx, in)
	mustNoErr(t, err)
	if got.Ref != in.Ref {
		t.Fatalf("SessionRef quartet not round-tripped: got %+v want %+v", got.Ref, in.Ref)
	}
	if got.State != SessionPending {
		t.Fatalf("new session state = %q, want PENDING", got.State)
	}

	// Step 3: policy-fresh placement records the applied_seq posture.
	creating := SessionCreating
	seq := int64(42)
	got, err = repo.UpdateSession(ctx, "sess-1", SessionUpdate{State: &creating, PolicyAppliedSeq: &seq})
	mustNoErr(t, err)
	if got.PolicyAppliedSeq != 42 || got.State != SessionCreating {
		t.Fatalf("policy posture update not applied: %+v", got)
	}

	// Step 6: digest write + ack gate. Before the ack, routability is blocked.
	if got.DigestAcked {
		t.Fatalf("digest acked before the ack write")
	}
	ack := true
	digest := "digest-set-1"
	got, err = repo.UpdateSession(ctx, "sess-1", SessionUpdate{DigestRef: &digest, DigestAcked: &ack})
	mustNoErr(t, err)
	if !got.DigestAcked || got.DigestRef != "digest-set-1" {
		t.Fatalf("digest-ack gate not flipped: %+v", got)
	}

	// Step 9: gated READY transition (digest ack + policy freshness both hold).
	ready := SessionReady
	got, err = repo.UpdateSession(ctx, "sess-1", SessionUpdate{State: &ready, ReadyAt: SetTime(baseTime)})
	mustNoErr(t, err)
	if got.State != SessionReady || got.ReadyAt == nil || !got.ReadyAt.Equal(baseTime) {
		t.Fatalf("gated READY transition not recorded: %+v", got)
	}

	// Step 10: attach — writer seat + attended begin.
	attached := SessionAttached
	seat, role := "user@org", RoleWriter
	att := true
	got, err = repo.UpdateSession(ctx, "sess-1", SessionUpdate{
		State: &attached, WriterSeat: &seat, WriterRole: &role, Attended: &att,
		AttachState: &role, AttachedAt: SetTime(baseTime),
	})
	mustNoErr(t, err)
	if got.State != SessionAttached || got.WriterSeat != "user@org" || got.WriterRole != RoleWriter || !got.Attended {
		t.Fatalf("attach state not recorded: %+v", got)
	}
}

func testCreateIdempotent(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	in := newSession("sess-idem", "host-a", 1)
	_, err := repo.CreateSession(ctx, in)
	mustNoErr(t, err)
	// Re-create with an identical Ref: idempotent success (every verb idempotent
	// on session_uuid, §4.1).
	again, err := repo.CreateSession(ctx, in)
	mustNoErr(t, err)
	if again.Ref != in.Ref {
		t.Fatalf("idempotent re-create changed the Ref: %+v", again.Ref)
	}
}

func testCreateConflictingRef(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("sess-c", "host-a", 1))
	mustNoErr(t, err)
	// Same UUID, different host_session_index → conflict.
	conflicting := newSession("sess-c", "host-a", 2)
	_, err = repo.CreateSession(ctx, conflicting)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Ref re-create: got %v, want ErrConflict", err)
	}
}

func testBurnedIndex(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("sess-x", "host-a", 5))
	mustNoErr(t, err)
	// Destroy it (record retained) — the index stays burned.
	destroyed := SessionDestroyed
	_, err = repo.UpdateSession(ctx, "sess-x", SessionUpdate{State: &destroyed, DestroyedAt: SetTime(baseTime)})
	mustNoErr(t, err)
	// A NEW session may not reuse index 5 on host-a (D66 burned-never-recycled).
	_, err = repo.CreateSession(ctx, newSession("sess-y", "host-a", 5))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("recycling burned index: got %v, want ErrInvalid", err)
	}
	// The same index on a DIFFERENT host is fine (index is host-scoped).
	_, err = repo.CreateSession(ctx, newSession("sess-z", "host-b", 5))
	mustNoErr(t, err)
}

// testDestroyFinalization exercises §4.2 destroy finalization: DESTROYING →
// DESTROYED teardown timestamps set, record retained per D66.
func testDestroyFinalization(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("sess-d", "host-a", 9))
	mustNoErr(t, err)

	destroying := SessionDestroying
	_, err = repo.UpdateSession(ctx, "sess-d", SessionUpdate{State: &destroying})
	mustNoErr(t, err)

	destroyed := SessionDestroyed
	teardown := baseTime.Add(time.Minute)
	got, err := repo.UpdateSession(ctx, "sess-d", SessionUpdate{State: &destroyed, DestroyedAt: SetTime(teardown)})
	mustNoErr(t, err)
	if got.State != SessionDestroyed || got.DestroyedAt == nil || !got.DestroyedAt.Equal(teardown) {
		t.Fatalf("destroy finalization not recorded: %+v", got)
	}
	// Record is RETAINED — still gettable after destroy (D66).
	retained, err := repo.GetSession(ctx, "sess-d")
	mustNoErr(t, err)
	if retained.State != SessionDestroyed {
		t.Fatalf("destroyed record not retained: %+v", retained)
	}
}

func testSuspendReasonInvariant(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("sess-s", "host-a", 3))
	mustNoErr(t, err)

	// SUSPENDED without a reason is invalid.
	suspended := SessionSuspended
	_, err = repo.UpdateSession(ctx, "sess-s", SessionUpdate{State: &suspended})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("SUSPENDED with no reason: got %v, want ErrInvalid", err)
	}
	// SUSPENDED(policy_breach) is valid.
	reason := SuspendReasonPolicyBreach
	got, err := repo.UpdateSession(ctx, "sess-s", SessionUpdate{State: &suspended, SuspendReason: &reason})
	mustNoErr(t, err)
	if got.State != SessionSuspended || got.SuspendReason != SuspendReasonPolicyBreach {
		t.Fatalf("suspend not recorded: %+v", got)
	}
	// A reason set while not SUSPENDED is invalid.
	working := SessionWorking
	_, err = repo.UpdateSession(ctx, "sess-s", SessionUpdate{State: &working})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("leaving SUSPENDED without clearing reason: got %v, want ErrInvalid", err)
	}
	// A direct clear-to-working (legal at the store layer) clears the reason.
	none := SuspendReasonNone
	got, err = repo.UpdateSession(ctx, "sess-s", SessionUpdate{State: &working, SuspendReason: &none})
	mustNoErr(t, err)
	if got.SuspendReason != SuspendReasonNone {
		t.Fatalf("clear-to-working did not clear reason: %+v", got)
	}
}

// testSuspendResumeClearsReason exercises the FOLDED §3 transition
// SUSPENDED → RESUMING → WORKING and the reason-clears invariant: the reason is
// set iff SUSPENDED, so entering RESUMING (a non-SUSPENDED state) forces the
// reason back to NULL. This is one of the two transitions the rejected wave hid
// by omitting RESUMING from the state vocabulary. The 0001_sessions.sql
// "reason set iff SUSPENDED" CHECK is the SQL mirror of this Go invariant.
func testSuspendResumeClearsReason(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("sess-r", "host-a", 4))
	mustNoErr(t, err)

	// Walk into WORKING so the suspend descends from the §3 state it comes from.
	working := SessionWorking
	_, err = repo.UpdateSession(ctx, "sess-r", SessionUpdate{State: &working})
	mustNoErr(t, err)

	// WORKING → SUSPENDED(rebalance) (col-37 spine).
	suspended := SessionSuspended
	rebalance := SuspendReasonRebalance
	got, err := repo.UpdateSession(ctx, "sess-r", SessionUpdate{State: &suspended, SuspendReason: &rebalance})
	mustNoErr(t, err)
	if got.State != SessionSuspended || got.SuspendReason != SuspendReasonRebalance {
		t.Fatalf("WORKING→SUSPENDED(rebalance) not recorded: %+v", got)
	}

	// SUSPENDED → RESUMING WITHOUT clearing the reason is invalid: RESUMING is a
	// non-SUSPENDED state, so a lingering reason violates "reason set iff
	// SUSPENDED".
	resuming := SessionResuming
	_, err = repo.UpdateSession(ctx, "sess-r", SessionUpdate{State: &resuming})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("SUSPENDED→RESUMING with a lingering reason: got %v, want ErrInvalid", err)
	}

	// SUSPENDED → RESUMING WITH the reason cleared is the legal resume entry.
	none := SuspendReasonNone
	got, err = repo.UpdateSession(ctx, "sess-r", SessionUpdate{State: &resuming, SuspendReason: &none})
	mustNoErr(t, err)
	if got.State != SessionResuming {
		t.Fatalf("SUSPENDED→RESUMING not recorded: %+v", got)
	}
	if got.SuspendReason != SuspendReasonNone {
		t.Fatalf("RESUMING must carry a NULL reason (reason set iff SUSPENDED): %+v", got)
	}

	// RESUMING → WORKING completes the resume.
	got, err = repo.UpdateSession(ctx, "sess-r", SessionUpdate{State: &working})
	mustNoErr(t, err)
	if got.State != SessionWorking || got.SuspendReason != SuspendReasonNone {
		t.Fatalf("RESUMING→WORKING not recorded with cleared reason: %+v", got)
	}
}

// testIndexEpochHistory exercises migration/park re-placement: a new host
// index/tap on the target, the record keeps the prior binding, and the new
// binding becomes the current Ref. It also pins the D29 OverlayPath durability
// contract on BOTH stores (the destroy-after-restart fix): the per-session CoW
// overlay recorded on the open epoch (doc 15 §4.1 step 4/7) round-trips through
// AppendIndexEpoch → GetSession (a "simulated restart" — a fresh read of ONLY
// what was persisted, no create-local HostAllocation in scope), so the §4.2
// teardown / DESTROYING re-drive can dispose the REAL overlay after a control-
// plane restart instead of driving OverlayPath="" and leaking it. Until the
// Postgres path persisted overlay_path (migration 0011) this assertion passed on
// the in-memory store but FAILED on Postgres — exactly the gap it closes.
func testIndexEpochHistory(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("sess-m", "host-a", 1))
	mustNoErr(t, err)

	clk2 := baseTime.Add(time.Hour)
	const overlay = "/var/lib/ds/overlays/sess-m.qcow2"
	got, err := repo.AppendIndexEpoch(ctx, "sess-m", IndexEpoch{
		HostID: "host-b", HostSessionIndex: 4, TapName: "dstap-4",
		GuestIP: []byte{10, 0, 0, 4}, GuestIPFamily: IPFamilyV4,
		OverlayPath: overlay, StartedAt: clk2,
	})
	mustNoErr(t, err)
	if got.Ref.HostID != "host-b" || got.Ref.HostSessionIndex != 4 || got.Ref.TapName != "dstap-4" {
		t.Fatalf("Ref not advanced to target binding: %+v", got.Ref)
	}
	if len(got.IndexHistory) != 2 {
		t.Fatalf("index history length = %d, want 2", len(got.IndexHistory))
	}
	if got.IndexHistory[0].EndedAt == nil {
		t.Fatalf("prior epoch not closed")
	}
	if got.IndexHistory[1].EndedAt != nil {
		t.Fatalf("current epoch should be open")
	}

	// SIMULATED RESTART: a fresh read of the persisted record (no create-local
	// state). The open (current) epoch must carry the D29 overlay the §4.2 teardown
	// disposes; the original seed epoch carried none (pre-clone binding).
	reread, err := repo.GetSession(ctx, "sess-m")
	mustNoErr(t, err)
	if len(reread.IndexHistory) != 2 {
		t.Fatalf("re-read index history length = %d, want 2", len(reread.IndexHistory))
	}
	var open *IndexEpoch
	for i := range reread.IndexHistory {
		if reread.IndexHistory[i].EndedAt == nil {
			open = &reread.IndexHistory[i]
		}
	}
	if open == nil {
		t.Fatalf("no open index epoch after re-read; history=%+v", reread.IndexHistory)
	}
	if open.OverlayPath != overlay {
		t.Fatalf("persisted overlay path not durable across restart: got %q, want %q", open.OverlayPath, overlay)
	}
	if open.HostSessionIndex != 4 || open.TapName != "dstap-4" {
		t.Fatalf("open epoch binding lost: idx=%d tap=%q", open.HostSessionIndex, open.TapName)
	}
	// The seed epoch (recorded from the Ref quartet before any overlay clone)
	// carries the empty overlay — the "no overlay recorded on this binding" posture.
	if reread.IndexHistory[0].OverlayPath != "" {
		t.Fatalf("pre-clone seed epoch should carry no overlay, got %q", reread.IndexHistory[0].OverlayPath)
	}

	// The original index on host-a stays burned; reusing it is invalid.
	_, err = repo.CreateSession(ctx, newSession("sess-m2", "host-a", 1))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("reusing migrated-away index: got %v, want ErrInvalid", err)
	}
}

// testMigrateRebindsEpoch exercises the FOLDED §3 transition path
// SNAPSHOTTING → MIGRATING → READY at a NEW host, driving the index-epoch
// rebind (per-host index history). This is the other transition the rejected
// wave hid by omitting MIGRATING from the state vocabulary. It checks that:
//   - the lifecycle walks WORKING → SNAPSHOTTING → MIGRATING → READY through
//     legal §3 states (each accepted by the store's state validation), and
//   - the host rebind that MIGRATING represents lands as a new index epoch on
//     the target host, with the prior per-host binding retained and burned.
func testMigrateRebindsEpoch(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("sess-mig", "host-a", 2))
	mustNoErr(t, err)

	// Walk into WORKING so the snapshot/migrate path starts from the §3 state it
	// descends from.
	working := SessionWorking
	_, err = repo.UpdateSession(ctx, "sess-mig", SessionUpdate{State: &working})
	mustNoErr(t, err)

	// WORKING → SNAPSHOTTING (col-37 spine): the pause/snap before migration.
	snap := SessionSnapshotting
	got, err := repo.UpdateSession(ctx, "sess-mig", SessionUpdate{State: &snap})
	mustNoErr(t, err)
	if got.State != SessionSnapshotting {
		t.Fatalf("WORKING→SNAPSHOTTING not recorded: %+v", got)
	}

	// SNAPSHOTTING → MIGRATING: enter the migrate state. The host retarget itself
	// is the index-epoch rebind, recorded next.
	migrating := SessionMigrating
	got, err = repo.UpdateSession(ctx, "sess-mig", SessionUpdate{State: &migrating})
	mustNoErr(t, err)
	if got.State != SessionMigrating {
		t.Fatalf("SNAPSHOTTING→MIGRATING not recorded: %+v", got)
	}

	// The migrate rebinds the session onto host-c with a new host index/tap; the
	// prior host-a binding is retained in history and stays burned (D66).
	rebindAt := baseTime.Add(2 * time.Hour)
	got, err = repo.AppendIndexEpoch(ctx, "sess-mig", IndexEpoch{
		HostID: "host-c", HostSessionIndex: 8, TapName: "dstap-8",
		GuestIP: []byte{10, 0, 0, 8}, GuestIPFamily: IPFamilyV4, StartedAt: rebindAt,
	})
	mustNoErr(t, err)
	if got.Ref.HostID != "host-c" || got.Ref.HostSessionIndex != 8 {
		t.Fatalf("MIGRATING rebind did not advance Ref to host-c/8: %+v", got.Ref)
	}
	if len(got.IndexHistory) != 2 || got.IndexHistory[0].HostID != "host-a" || got.IndexHistory[0].EndedAt == nil {
		t.Fatalf("prior host-a epoch not retained+closed across migrate: %+v", got.IndexHistory)
	}

	// MIGRATING → READY@host' (col-25 ▲): converge on the target host.
	ready := SessionReady
	got, err = repo.UpdateSession(ctx, "sess-mig", SessionUpdate{State: &ready, ReadyAt: SetTime(rebindAt)})
	mustNoErr(t, err)
	if got.State != SessionReady {
		t.Fatalf("MIGRATING→READY not recorded: %+v", got)
	}

	// The migrated-away host-a index stays burned; a new session cannot reuse it.
	_, err = repo.CreateSession(ctx, newSession("sess-mig2", "host-a", 2))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("reusing the migrated-away host-a index: got %v, want ErrInvalid", err)
	}
}

// testPolicyLog exercises append-only with monotonically increasing seq and
// actor recorded on every row (D36).
func testPolicyLog(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()

	// Actor is required.
	_, err := repo.AppendPolicy(ctx, PolicyLogRow{ContentHash: "h"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("append with no actor: got %v, want ErrInvalid", err)
	}

	var lastSeq int64
	for i := 0; i < 5; i++ {
		row, err := repo.AppendPolicy(ctx, PolicyLogRow{
			Actor: "org-admin", ContentHash: fmt.Sprintf("hash-%d", i),
			Payload: []byte(fmt.Sprintf("policy-%d", i)),
		})
		mustNoErr(t, err)
		if row.Seq <= lastSeq {
			t.Fatalf("seq not monotonically increasing: %d after %d", row.Seq, lastSeq)
		}
		lastSeq = row.Seq
	}

	// WatchPolicies(from_seq) replay shape.
	rows, err := repo.ListPolicy(ctx, 0, 0)
	mustNoErr(t, err)
	if len(rows) != 5 {
		t.Fatalf("ListPolicy(0) returned %d rows, want 5", len(rows))
	}
	for _, r := range rows {
		if r.Actor != "org-admin" {
			t.Fatalf("actor not recorded: %+v", r)
		}
	}
	from, err := repo.ListPolicy(ctx, rows[2].Seq, 0)
	mustNoErr(t, err)
	if len(from) != 2 {
		t.Fatalf("from_seq replay returned %d, want 2", len(from))
	}
	// Limit honored.
	lim, err := repo.ListPolicy(ctx, 0, 2)
	mustNoErr(t, err)
	if len(lim) != 2 {
		t.Fatalf("limit not honored: %d", len(lim))
	}
}

// testAskGrantTTL exercises §4.3 ask-grants: TTL'd, session-scoped rows under
// the policy_log seq, with the live-grant view excluding expired rows.
func testAskGrantTTL(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("sess-g", "host-a", 2))
	mustNoErr(t, err)

	expiry := baseTime.Add(5 * time.Minute)
	_, err = repo.AppendPolicy(ctx, PolicyLogRow{
		Kind: PolicyKindAskGrant, Actor: "approver@org",
		SessionUUID: "sess-g", ExpiresAt: &expiry, Payload: []byte("allow example.com"),
	})
	mustNoErr(t, err)

	// Before expiry: live.
	live, err := repo.LiveGrants(ctx, "sess-g", baseTime.Add(time.Minute))
	mustNoErr(t, err)
	if len(live) != 1 {
		t.Fatalf("live grant not visible before expiry: %d", len(live))
	}
	if live[0].Actor != "approver@org" {
		t.Fatalf("grant actor not recorded: %+v", live[0])
	}
	// After expiry: gone from the live view (still an audit row in policy_log).
	live, err = repo.LiveGrants(ctx, "sess-g", baseTime.Add(10*time.Minute))
	mustNoErr(t, err)
	if len(live) != 0 {
		t.Fatalf("expired grant still live: %d", len(live))
	}
	// The audit row persists.
	all, err := repo.ListPolicy(ctx, 0, 0)
	mustNoErr(t, err)
	if len(all) != 1 {
		t.Fatalf("ask-grant audit row not retained: %d", len(all))
	}
}

func testEnvConfig(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	in := EnvConfig{
		Ref: "env-1", RepoRef: "git@host:repo#abc", SpecHash: "spec-hash",
		ImageID: "sha256:img", CoupledPin: "2.1.116", PackVersion: "pack-9",
		PackExclusion: "downloads.claude.ai",
	}
	out, err := repo.PutEnvConfig(ctx, in)
	mustNoErr(t, err)
	if out.CreatedAt.IsZero() {
		t.Fatalf("CreatedAt not stamped")
	}
	got, err := repo.GetEnvConfig(ctx, "env-1")
	mustNoErr(t, err)
	if got.CoupledPin != "2.1.116" || got.PackExclusion != "downloads.claude.ai" {
		t.Fatalf("coupled invariants not round-tripped: %+v", got)
	}
}

func testPlan(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("sess-p", "host-a", 11))
	mustNoErr(t, err)
	_, err = repo.PutPlan(ctx, Plan{ID: "plan-1", SessionUUID: "sess-p", Title: "do the thing", Body: []byte("steps")})
	mustNoErr(t, err)
	got, err := repo.GetPlan(ctx, "plan-1")
	mustNoErr(t, err)
	if got.Title != "do the thing" {
		t.Fatalf("plan not round-tripped: %+v", got)
	}
	list, err := repo.ListPlans(ctx, "sess-p")
	mustNoErr(t, err)
	if len(list) != 1 {
		t.Fatalf("ListPlans returned %d, want 1", len(list))
	}
}

// testRepositoryOrphanFKWrites is the §5.6 Repository orphan-write equivalence
// pin — the Repository-suite counterpart of the ContextStore's testOrphanWriteRejected
// (sessioncontext_test.go). It sweeps the genuine NON-EMPTY FK edges the live
// schema enforces and the in-memory store now mirrors, so a write naming a
// missing referent is REJECTED by BOTH impls (in-memory existence guard ↔ live
// REFERENCES …, SQLSTATE 23503), and the legal cases (empty/nullable, real
// referent) succeed on both:
//
//   - plans.session_uuid REFERENCES sessions (0004, NULLABLE): a non-empty
//     session_uuid naming no session is an orphan PutPlan; an EMPTY one is legal
//     (an unscoped plan).
//   - sessions.parent_session_uuid REFERENCES sessions (0001, NULLABLE self-ref):
//     a non-empty parent naming no session is an orphan CreateSession; an EMPTY
//     parent is a legal root session.
//   - session_index_epochs.session_uuid REFERENCES sessions (0001, NOT NULL):
//     AppendIndexEpoch onto a missing session is rejected (ErrNotFound — the
//     epoch write targets the session row directly, so a missing session is "not
//     found", not an orphan reference). This case ASSERTS that pre-existing parity
//     holds; it is unchanged by this unit.
//
// SENTINEL NOTE: the shared assertion is errors.Is(err, ErrInvalid) for the two
// FK edges — the impls now agree on the SENTINEL. The in-memory guard returns
// ErrInvalid (pinned exactly in memory_test.go TestMemory_OrphanFKWritesReturnErrInvalid),
// and the live Postgres PutPlan / CreateSession now route the orphan 23503 through
// the shared mapFKErr (postgres.go), which maps it to the SAME ErrInvalid sentinel
// — so a caller doing errors.Is(err, ErrInvalid) cannot tell the impls apart (D33
// reference-impl == database/sql parity). The synthetic-23503 → ErrInvalid mapping
// is proven driver-free in postgres_test.go (TestMapFKErr_Synthetic23503ToErrInvalid),
// and the live FK firing is proven in plan_session_fk_pg_conformance_test.go.
//
// The deliberately-SOFT refs (metering_events.session_uuid 0005, policy_log.session_uuid
// 0002 — NO REFERENCES clause, attribution-only text columns) are NOT swept: they
// admit any session_uuid by design, so an orphan metering/policy write is legal on
// both impls and the testMetering / testAskGrantTTL cases exercise exactly that.
func testRepositoryOrphanFKWrites(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()

	// A real session the legal (non-orphan) control cases attribute to.
	_, err := repo.CreateSession(ctx, newSession("sess-fk", "host-a", 1))
	mustNoErr(t, err)

	// plans.session_uuid (0004) — orphan PutPlan rejected with ErrInvalid; empty + real both legal.
	if _, err := repo.PutPlan(ctx, Plan{ID: "plan-orphan", SessionUUID: "ghost-session"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("orphan PutPlan (missing session_uuid referent): got %v, want ErrInvalid (in-memory guard ↔ live FK via mapFKErr, D33 sentinel parity)", err)
	}
	if _, err := repo.GetPlan(ctx, "plan-orphan"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected orphan plan should not have persisted: got %v, want ErrNotFound", err)
	}
	if _, err := repo.PutPlan(ctx, Plan{ID: "plan-unscoped"}); err != nil { // EMPTY session_uuid is legal (nullable, unscoped)
		t.Fatalf("unscoped plan (empty session_uuid) must be legal: got %v", err)
	}
	if _, err := repo.PutPlan(ctx, Plan{ID: "plan-real", SessionUUID: "sess-fk"}); err != nil {
		t.Fatalf("plan attributed to a real session must succeed: got %v", err)
	}

	// sessions.parent_session_uuid (0001) — orphan parent rejected with ErrInvalid; empty + real both legal.
	orphanParent := newSession("sess-orphan-parent", "host-a", 2)
	orphanParent.ParentSessionUUID = "ghost-session"
	if _, err := repo.CreateSession(ctx, orphanParent); !errors.Is(err, ErrInvalid) {
		t.Fatalf("orphan parent_session_uuid (missing referent): got %v, want ErrInvalid (in-memory guard ↔ live FK via mapFKErr, D33 sentinel parity)", err)
	}
	if _, err := repo.GetSession(ctx, "sess-orphan-parent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected orphan-parent session should not have persisted: got %v, want ErrNotFound", err)
	}
	root := newSession("sess-root", "host-a", 3) // EMPTY parent is a legal root session
	if _, err := repo.CreateSession(ctx, root); err != nil {
		t.Fatalf("root session (empty parent) must be legal: got %v", err)
	}
	child := newSession("sess-child", "host-a", 4)
	child.ParentSessionUUID = "sess-root" // a real parent is legal
	if _, err := repo.CreateSession(ctx, child); err != nil {
		t.Fatalf("child with a real parent must succeed: got %v", err)
	}

	// session_index_epochs.session_uuid (0001, NOT NULL) — AppendIndexEpoch parity
	// (PRE-EXISTING; asserted, not introduced): the epoch write targets the session
	// row, so a missing session is ErrNotFound. A real session accepts the epoch.
	if _, err := repo.AppendIndexEpoch(ctx, "ghost-session", IndexEpoch{HostID: "host-z", HostSessionIndex: 99, TapName: "dstap-99"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("AppendIndexEpoch onto a missing session: got %v, want ErrNotFound (pre-existing parity)", err)
	}
	if _, err := repo.AppendIndexEpoch(ctx, "sess-fk", IndexEpoch{HostID: "host-b", HostSessionIndex: 5, TapName: "dstap-5", StartedAt: baseTime}); err != nil {
		t.Fatalf("AppendIndexEpoch onto a real session must succeed: got %v", err)
	}
}

func testMetering(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	e := MeteringEvent{
		EventID: "evt-1", SessionUUID: "sess-meter", Kind: "state_transition",
		State: SessionWorking, OccurredAt: baseTime, Payload: []byte("x"),
	}
	mustNoErr(t, repo.AppendMeteringEvent(ctx, e))
	// Re-emit identical: idempotent no-op.
	mustNoErr(t, repo.AppendMeteringEvent(ctx, e))
	// Re-emit with a different body under the same id: conflict.
	e2 := e
	e2.Payload = []byte("y")
	if err := repo.AppendMeteringEvent(ctx, e2); !errors.Is(err, ErrConflict) {
		t.Fatalf("differing metering body: got %v, want ErrConflict", err)
	}
	list, err := repo.ListMeteringEvents(ctx, "sess-meter")
	mustNoErr(t, err)
	if len(list) != 1 {
		t.Fatalf("metering not deduped: %d rows", len(list))
	}
}

func testListSessions(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	_, err := repo.CreateSession(ctx, newSession("p-root", "host-a", 1))
	mustNoErr(t, err)
	child := newSession("p-child", "host-a", 2)
	child.ParentSessionUUID = "p-root"
	_, err = repo.CreateSession(ctx, child)
	mustNoErr(t, err)
	_, err = repo.CreateSession(ctx, newSession("other-host", "host-b", 1))
	mustNoErr(t, err)

	// Host filter.
	byHost, err := repo.ListSessions(ctx, SessionFilter{HostID: "host-a"})
	mustNoErr(t, err)
	if len(byHost) != 2 {
		t.Fatalf("host filter returned %d, want 2", len(byHost))
	}
	// Parent filter.
	kids, err := repo.ListSessions(ctx, SessionFilter{ParentSessionUUID: "p-root"})
	mustNoErr(t, err)
	if len(kids) != 1 || kids[0].Ref.SessionUUID != "p-child" {
		t.Fatalf("parent filter wrong: %+v", kids)
	}
	// Destroyed excluded by default, included on request.
	destroyed := SessionDestroyed
	_, err = repo.UpdateSession(ctx, "other-host", SessionUpdate{State: &destroyed, DestroyedAt: SetTime(baseTime)})
	mustNoErr(t, err)
	live, err := repo.ListSessions(ctx, SessionFilter{})
	mustNoErr(t, err)
	if len(live) != 2 {
		t.Fatalf("default list included destroyed: %d", len(live))
	}
	all, err := repo.ListSessions(ctx, SessionFilter{IncludeDestroyed: true})
	mustNoErr(t, err)
	if len(all) != 3 {
		t.Fatalf("include-destroyed list returned %d, want 3", len(all))
	}
}

// --- ListSessions keyset pagination (the §5.3 console read pushed down as a keyset scan) ---
//
// The new SessionFilter keyset fields (PageToken / PageSize / LaunchingUser) and the
// sqlListSessions keyset SQL were exercised only TRANSITIVELY through the controlplane
// handler tests; no store-package case drove them directly, and the PG keyset SQL was
// verified only by static schema/index inspection. testListSessionsKeysetPagination closes
// BOTH gaps at once by driving the REAL store seam (Memory per-commit, Postgres under
// DS_PG_DSN) through the exact page-walk the handler relies on and asserting the §5.3
// keyset invariants hold identically on both backends.
//
// The fixture is a mixed-principal, sub-second-CLUSTERED, partly-orphan session set seeded
// with EXPLICIT created_at stamps (CreateSession inserts a non-zero CreatedAt verbatim on
// both backends, microsecond-precision so the Postgres timestamptz round-trips byte-equal),
// so the (created_at DESC, session_uuid DESC) order — including the full-precision cursor
// across a same-created_at tie — is deterministic and independent of wall-clock.

// keysetSeed is one fixture session: its uuid, its explicit created_at stamp (the keyset
// sort key), and the launching principal it should resolve to (or one of the orphan kinds).
type keysetSeed struct {
	uuid      string
	createdAt time.Time
	// launcher selects how the session links to a principal (see seedKeysetFixture):
	//   "alice"/"bob" → linked to the real principal with that IdP subject (scopable),
	//   "" (none)     → no launching principal (the nullable case; excluded from any scope),
	//   "dangling"    → linked to the "carol" principal whose subject no scope selects — the
	//                   reachable stand-in for a dangling/never-scoped link (a TRUE dangling
	//                   link can't be seeded; see the seedKeysetFixture doc).
	launcher string
}

// keysetClusterAt is the shared instant the sub-second cluster sessions all carry, chosen at
// MICROSECOND precision (no sub-µs digits) so the Postgres timestamptz stores and reads it
// back byte-identically to the in-memory time.Time — the full-precision cursor must order the
// tied trio by session_uuid DESC on BOTH backends, never collapse them to one slot or skip one.
var keysetClusterAt = baseTime.Add(3*time.Second + 500*time.Microsecond)

// keysetFixture is the canonical seed list, shared by the conformance case and the
// PG-vs-Memory byte-identical twin so both drive the IDENTICAL data. It spans:
//   - distinct created_at instants (the ordinary multi-page walk), AND
//   - a three-session cluster tied on keysetClusterAt (the full-precision-cursor walk
//     across a same-created_at sub-second cluster), AND
//   - every launching-principal kind (alice / bob / none / dangling), so the
//     LaunchingUser scope can be asserted to exclude the NULL and dangling links.
//
// The list is deliberately NOT in sorted order so the seeding order can't be mistaken for
// the keyset order; the expected order is computed from the stamps + uuids by the assertions.
func keysetFixture() []keysetSeed {
	return []keysetSeed{
		// Distinct instants (newest → oldest by created_at).
		{uuid: "ks-newest", createdAt: baseTime.Add(10 * time.Second), launcher: "alice"},
		{uuid: "ks-second", createdAt: baseTime.Add(8 * time.Second), launcher: "bob"},
		{uuid: "ks-none-mid", createdAt: baseTime.Add(6 * time.Second), launcher: ""},         // NULL launching_principal
		{uuid: "ks-dangling", createdAt: baseTime.Add(5 * time.Second), launcher: "dangling"}, // link to a missing principal
		// The same-created_at sub-second cluster: three sessions tied on keysetClusterAt,
		// ordered among themselves by session_uuid DESC (ks-c > ks-b > ks-a).
		{uuid: "ks-cluster-a", createdAt: keysetClusterAt, launcher: "alice"},
		{uuid: "ks-cluster-b", createdAt: keysetClusterAt, launcher: ""},
		{uuid: "ks-cluster-c", createdAt: keysetClusterAt, launcher: "bob"},
		// Oldest.
		{uuid: "ks-oldest", createdAt: baseTime.Add(1 * time.Second), launcher: "alice"},
	}
}

// seedKeysetFixture writes keysetFixture() onto any Repository: three real principals (alice,
// bob, carol), then a session per seed with its EXPLICIT created_at, linked to its launcher.
//
// Note on the "dangling" seed kind: a TRUE dangling launching_principal (a link to a principal
// id that names no row) cannot be produced through the store seam — SetSessionLaunchingPrincipal
// rejects an unknown principal with ErrInvalid (the soft-FK guard, mirrored by the nullable
// column's REFERENCES in 0006), and the in-memory store mirrors that. The two link states the
// LaunchingUser scope actually has to exclude are therefore (i) the NULL launching_principal
// ("" seeds) and (ii) a link to a principal whose IdP subject is NEITHER the scoped subject —
// the "carol" principal the "dangling" seeds link to. Both are excluded from an alice- or
// bob-scoped walk exactly as a dangling link would be, so this fixture exercises the full
// excluded-from-scope surface the keyset filter must never leak.
func seedKeysetFixture(t *testing.T, repo Repository) {
	t.Helper()
	ctx := context.Background()

	// Real principals the LaunchingUser filter resolves against.
	mustCreatePrincipal(t, repo, "prin-alice", "idp-alice", "acme", RoleLauncher)
	mustCreatePrincipal(t, repo, "prin-bob", "idp-bob", "acme", RoleLauncher)
	// "carol" stands in for the never-scoped principal (the launcher of the "dangling" seed):
	// a real, linkable principal whose subject neither an alice- nor a bob-scoped walk selects,
	// so it is excluded from every scoped page the same way a NULL/dangling link is.
	mustCreatePrincipal(t, repo, "prin-carol", "idp-carol", "acme", RoleLauncher)

	idx := uint64(20)
	for _, s := range keysetFixture() {
		sess := newSession(s.uuid, "host-ks", idx)
		idx++
		sess.CreatedAt = s.createdAt // inserted verbatim (non-zero) on both backends
		_, err := repo.CreateSession(ctx, sess)
		mustNoErr(t, err)
		switch s.launcher {
		case "":
			// No launching principal — the nullable case; leave the link unset.
		case "alice":
			mustNoErr(t, repo.SetSessionLaunchingPrincipal(ctx, s.uuid, "prin-alice"))
		case "bob":
			mustNoErr(t, repo.SetSessionLaunchingPrincipal(ctx, s.uuid, "prin-bob"))
		case "dangling":
			// Modeled as a real "carol" link (see seedKeysetFixture doc): excluded from any
			// alice/bob-scoped walk exactly as a NULL/dangling link is.
			mustNoErr(t, repo.SetSessionLaunchingPrincipal(ctx, s.uuid, "prin-carol"))
		default:
			t.Fatalf("unknown launcher kind %q in keyset fixture", s.launcher)
		}
	}
}

// mustCreatePrincipal creates a single-role principal or fails the test.
func mustCreatePrincipal(t *testing.T, repo Repository, id, idpSubject, org string, role PrincipalRole) {
	t.Helper()
	_, err := repo.CreatePrincipal(context.Background(), Principal{
		ID: id, IdPSubject: idpSubject, Org: org, Roles: []PrincipalRole{role},
	})
	mustNoErr(t, err)
}

// expectedKeysetOrder returns the uuids of keysetFixture(), restricted to the launchers in
// `launchers` (nil = all), in the stable newest-first keyset order (created_at DESC, then
// session_uuid DESC) — the order both stores must return and the page-walk must reconstruct.
func expectedKeysetOrder(launchers map[string]bool) []string {
	seeds := keysetFixture()
	kept := make([]keysetSeed, 0, len(seeds))
	for _, s := range seeds {
		if launchers == nil || launchers[s.launcher] {
			kept = append(kept, s)
		}
	}
	sortKeysetSeeds(kept)
	out := make([]string, len(kept))
	for i, s := range kept {
		out[i] = s.uuid
	}
	return out
}

// sortKeysetSeeds orders seeds newest-first by (created_at DESC, session_uuid DESC) — the EXACT
// comparator both stores sort on (memory.ListSessions' sort.Slice and the sqlListSessions
// ORDER BY), so the test's expected order is the store's order by construction.
func sortKeysetSeeds(s []keysetSeed) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].createdAt.Equal(s[j].createdAt) {
			return s[i].uuid > s[j].uuid // session_uuid DESC on a created_at tie
		}
		return s[i].createdAt.After(s[j].createdAt) // created_at DESC
	})
}

// walkKeyset pages through ListSessions with a limit+1 keyset walk over the given base filter
// (PageSize = pageSize, cursor advanced from each page's LAST record) and returns the uuids it
// visited in page order. It asserts no page exceeds pageSize and the walk terminates (a short
// page or an empty page ends it), so a cursor that fails to advance — re-emitting a boundary
// record forever — is caught as a non-termination/over-visit rather than hanging.
func walkKeyset(t *testing.T, repo Repository, base SessionFilter, pageSize int) []string {
	t.Helper()
	ctx := context.Background()
	var visited []string
	cursor := SessionPageCursor{} // unset → start from newest
	for page := 0; ; page++ {
		if page > len(keysetFixture())+2 {
			t.Fatalf("keyset walk did not terminate after %d pages (cursor not advancing?); visited=%v", page, visited)
		}
		f := base
		f.PageSize = pageSize
		f.PageToken = cursor
		got, err := repo.ListSessions(ctx, f)
		mustNoErr(t, err)
		if len(got) > pageSize {
			t.Fatalf("page %d returned %d rows, exceeds PageSize %d", page, len(got), pageSize)
		}
		for _, rec := range got {
			visited = append(visited, rec.Ref.SessionUUID)
		}
		if len(got) < pageSize {
			break // a short (or empty) page is the last page
		}
		last := got[len(got)-1]
		cursor = SessionPageCursor{Set: true, CreatedAt: last.CreatedAt, UUID: last.Ref.SessionUUID}
	}
	return visited
}

// testListSessionsKeysetPagination is the conformance case that drives the keyset seam on
// whichever backend the harness supplies (Memory per-commit; Postgres under DS_PG_DSN). It
// asserts, against the REAL impl (no fake):
//
//	(a) PageSize <= 0 returns ALL matching records newest-first with NO cursor (back-compat),
//	(b) a limit+1 keyset page-walk over (created_at DESC, session_uuid DESC) visits every
//	    matching session EXACTLY once — no dup / no skip — INCLUDING across the same-created_at
//	    sub-second cluster (the full-precision cursor), for several page sizes,
//	(c) a non-empty LaunchingUser scopes the walk to that principal's sessions only — the
//	    NULL-launching-principal and never-scoped ("carol") rows are EXCLUDED, never leaked.
//
// Part (d) — Memory and Postgres pages BYTE-IDENTICAL for a fixed seed — is asserted by the
// DS_PG_DSN-gated TestPostgres_ListSessionsKeysetPaginationMatchesMemory below, which can hold
// both backends at once (the conformance harness hands one backend per run).
func testListSessionsKeysetPagination(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	seedKeysetFixture(t, repo)

	// (a) PageSize <= 0 returns ALL matching, newest-first, with no cursor — the back-compat
	// single-shot path every non-paginating caller relies on.
	wantAll := expectedKeysetOrder(nil)
	for _, ps := range []int{0, -1} {
		all, err := repo.ListSessions(ctx, SessionFilter{PageSize: ps})
		mustNoErr(t, err)
		gotAll := uuidsOf(all)
		if !equalStrings(gotAll, wantAll) {
			t.Fatalf("PageSize=%d single-shot order wrong:\n got %v\nwant %v", ps, gotAll, wantAll)
		}
	}

	// (b) limit+1 keyset page-walk visits every matching session exactly once across several
	// page sizes — including a page size of 2 that splits the three-session cluster across a
	// page boundary (the full-precision cursor must resume MID-CLUSTER without dup/skip).
	for _, ps := range []int{1, 2, 3, 5, len(wantAll)} {
		got := walkKeyset(t, repo, SessionFilter{}, ps)
		if !equalStrings(got, wantAll) {
			t.Fatalf("keyset walk (PageSize=%d) did not reproduce the full order exactly (dup/skip?):\n got %v\nwant %v", ps, got, wantAll)
		}
		assertNoDupNoSkip(t, got, wantAll, ps)
	}

	// (c) a non-empty LaunchingUser scopes the walk to that principal's sessions only. The
	// NULL-launching-principal rows and the never-scoped "carol" rows must be EXCLUDED.
	for _, tc := range []struct {
		subject  string
		launcher string
	}{
		{"idp-alice", "alice"},
		{"idp-bob", "bob"},
	} {
		wantScoped := expectedKeysetOrder(map[string]bool{tc.launcher: true})
		if len(wantScoped) == 0 {
			t.Fatalf("fixture bug: launcher %q has no sessions", tc.launcher)
		}
		// Single-shot scoped (back-compat path) returns exactly that principal's set, ordered.
		scoped, err := repo.ListSessions(ctx, SessionFilter{LaunchingUser: tc.subject})
		mustNoErr(t, err)
		if got := uuidsOf(scoped); !equalStrings(got, wantScoped) {
			t.Fatalf("LaunchingUser=%q single-shot scope wrong:\n got %v\nwant %v", tc.subject, got, wantScoped)
		}
		// And the keyset walk under the same scope reconstructs that scoped order with no
		// dup/skip — the LIMIT applies to the FILTERED set, page after page.
		for _, ps := range []int{1, 2, len(wantScoped)} {
			got := walkKeyset(t, repo, SessionFilter{LaunchingUser: tc.subject}, ps)
			if !equalStrings(got, wantScoped) {
				t.Fatalf("scoped keyset walk LaunchingUser=%q PageSize=%d wrong:\n got %v\nwant %v", tc.subject, ps, got, wantScoped)
			}
			// No NULL/never-scoped row ever leaks into a scoped page.
			for _, u := range got {
				if u == "ks-none-mid" || u == "ks-cluster-b" || u == "ks-dangling" {
					t.Fatalf("LaunchingUser=%q leaked a NULL/never-scoped session %q into the page: %v", tc.subject, u, got)
				}
			}
		}
	}

	// A LaunchingUser that names no principal's subject yields an EMPTY page (never the whole
	// fleet — the filter is a narrowing, not a no-op when unmatched).
	none, err := repo.ListSessions(ctx, SessionFilter{LaunchingUser: "idp-nobody"})
	mustNoErr(t, err)
	if len(none) != 0 {
		t.Fatalf("LaunchingUser naming no principal returned %d rows, want 0 (must not widen to the fleet): %v", len(none), uuidsOf(none))
	}
}

// uuidsOf projects a session slice to its session_uuid sequence (the keyset order key).
func uuidsOf(ss []Session) []string {
	out := make([]string, len(ss))
	for i := range ss {
		out[i] = ss[i].Ref.SessionUUID
	}
	return out
}

// equalStrings (order-significant slice equality — the keyset order IS the assertion) is
// shared with scheduler_candidates_queries_test.go in this package's test build.

// assertNoDupNoSkip independently re-checks that the walked sequence is a permutation of want
// with NO duplicate and NO missing element — a stronger statement than equalStrings on its own,
// localized to the dup/skip failure mode the keyset cursor is meant to prevent.
func assertNoDupNoSkip(t *testing.T, got, want []string, pageSize int) {
	t.Helper()
	seen := make(map[string]int, len(got))
	for _, u := range got {
		seen[u]++
		if seen[u] > 1 {
			t.Fatalf("keyset walk (PageSize=%d) visited %q %d times — DUPLICATE across a page boundary; got=%v", pageSize, u, seen[u], got)
		}
	}
	for _, u := range want {
		if seen[u] == 0 {
			t.Fatalf("keyset walk (PageSize=%d) SKIPPED %q (missing from the walk); got=%v want=%v", pageSize, u, got, want)
		}
	}
}

// TestPostgres_ListSessionsKeysetPaginationMatchesMemory is the DS_PG_DSN-gated part (d): for
// a FIXED seed it asserts the *store.Memory and *store.Postgres keyset pages are BYTE-IDENTICAL
// — the same session_uuid sequence, page by page, across the single-shot path, the limit+1
// page-walk (including the same-created_at sub-second cluster split across a page boundary), and
// a LaunchingUser-scoped walk. It seeds the IDENTICAL keysetFixture() on a fresh *Memory (the
// D33 parity oracle) and on the live *Postgres, then compares Memory-vs-Postgres rather than a
// hand-maintained expectation. SKIPS cleanly without DS_PG_DSN (deferred manual step); it reuses
// openPostgresOrSkip's gate+truncate plumbing, never the migration or any production code.
func TestPostgres_ListSessionsKeysetPaginationMatchesMemory(t *testing.T) {
	pg := openPostgresOrSkip(t).(*Postgres) // skip-without-DB + truncateAll; *Postgres for the seed

	mem := NewMemoryClock(fixedClock(baseTime))
	seedKeysetFixture(t, mem)
	seedKeysetFixture(t, pg)

	ctx := context.Background()

	// Single-shot (PageSize <= 0): the whole newest-first order must match byte-for-byte.
	memAll, err := mem.ListSessions(ctx, SessionFilter{})
	mustNoErr(t, err)
	pgAll, err := pg.ListSessions(ctx, SessionFilter{})
	mustNoErr(t, err)
	if m, p := uuidsOf(memAll), uuidsOf(pgAll); !equalStrings(m, p) {
		t.Fatalf("single-shot order differs Memory vs Postgres:\n mem %v\n pg  %v", m, p)
	}

	// Page-by-page: the limit+1 walk must visit the SAME uuids in the SAME page order on both
	// backends — across every page size, including the cluster-splitting size 2.
	for _, ps := range []int{1, 2, 3, len(keysetFixture())} {
		memWalk := walkKeyset(t, mem, SessionFilter{}, ps)
		pgWalk := walkKeyset(t, pg, SessionFilter{}, ps)
		if !equalStrings(memWalk, pgWalk) {
			t.Fatalf("keyset walk (PageSize=%d) differs Memory vs Postgres:\n mem %v\n pg  %v", ps, memWalk, pgWalk)
		}
	}

	// LaunchingUser-scoped walk: the scoped page sequence must also match byte-for-byte (the PG
	// EXISTS-over-principals filter agrees with the in-memory linkage resolver).
	for _, subject := range []string{"idp-alice", "idp-bob"} {
		for _, ps := range []int{1, 2} {
			memWalk := walkKeyset(t, mem, SessionFilter{LaunchingUser: subject}, ps)
			pgWalk := walkKeyset(t, pg, SessionFilter{LaunchingUser: subject}, ps)
			if !equalStrings(memWalk, pgWalk) {
				t.Fatalf("scoped keyset walk LaunchingUser=%q PageSize=%d differs Memory vs Postgres:\n mem %v\n pg  %v", subject, ps, memWalk, pgWalk)
			}
		}
	}
}

// TestPostgres_KeysetCoveringIndexPlan pins that the migration-0014 composite
// covering index sessions_keyset_idx (launching_principal, created_at DESC,
// session_uuid DESC) — the index that makes the §5.3 console read (sqlListSessions)
// "one bounded store query per page" (doc 15 §8) instead of a per-page seq-scan +
// sort — EXISTS, has the right column shape, and is the plan the live engine
// serves the scoped+paged keyset predicate with. It guards the index against a
// future migration that drops or renames it before that becomes a fleet-scale
// tail-latency regression.
//
// DS_PG_DSN-gated: SKIPS without a reachable database (reusing pgInventory →
// openPostgresOrSkip, which truncates the shared tables), the same deferred-manual
// posture as every other TestPostgres_* case. The target DB must have migrations
// 0001..0014 applied (the covering index lands in 0014); the pg-conformance lane
// wires DS_PG_DSN so this RUNS in CI rather than skips.
//
// NON-VACUITY (why this trips when the index is gone). A bare "no Seq Scan"
// EXPLAIN would be flaky: on a tiny table the planner legitimately prefers a seq
// scan even WITH a usable index (the exact caveat inventory_pg_conformance_test.go
// documents), so it would fail spuriously present-or-absent. Instead we (a) assert
// the index's presence + column shape structurally via pg_indexes + indexColumns
// (which trip directly on a drop/rename), and (b) run the EXPLAIN with
// `SET LOCAL enable_seqscan = off` so the planner is forced to reveal whether an
// index-ordered plan for the scoped+paged predicate EXISTS. With seqscan disabled:
// if sessions_keyset_idx is present, the plan is an Index/Index-Only Scan naming
// it and carries NO Sort node (the DESC/DESC ordering is index-served); if the
// index is ABSENT, the only plans left are a Seq Scan (seqscan is merely
// discouraged, not forbidden — enable_seqscan=off adds a large cost penalty but
// keeps it legal as a last resort) plus a Sort, so the "Index Scan naming
// sessions_keyset_idx, no Sort" assertion FAILS. That is the trip we require: the
// assertion is green ONLY with the 0014 index in place.
func TestPostgres_KeysetCoveringIndexPlan(t *testing.T) {
	pg, db := pgInventory(t) // skip-without-DB + truncateAll; raw *sql.DB for introspection
	ctx := context.Background()

	const idxName = "sessions_keyset_idx"

	// (1) The 0014 covering index exists on `sessions`. This is the primary guard:
	// a future migration that drops or renames it trips HERE with a clear message.
	var present bool
	if err := db.QueryRowContext(ctx,
		`SELECT EXISTS (
		   SELECT 1 FROM pg_indexes
		   WHERE schemaname = current_schema()
		     AND tablename  = 'sessions'
		     AND indexname  = $1)`, idxName).Scan(&present); err != nil {
		t.Fatalf("pg_indexes lookup for %s: %v", idxName, err)
	}
	if !present {
		t.Fatalf("0014 covering index %q is missing on sessions — the keyset console read seq-scans+sorts per page (doc 15 §8 regression)", idxName)
	}

	// (2) Its column shape is (launching_principal, created_at, session_uuid) in
	// that order — the leading scoping key the EXISTS filter probes, then the two
	// keyset order keys carried so the newest-first ORDER BY is index-served. The
	// DESC direction is not read from pg_attribute here (indexColumns reads names
	// only); the plan check in (3) is what proves the ordering is actually served
	// without a Sort. A column-order drift (e.g. someone rebuilds the index with
	// the keys transposed) trips here.
	cols, err := indexColumns(ctx, db, idxName)
	mustNoErr(t, err)
	wantCols := []string{"launching_principal", "created_at", "session_uuid"}
	if len(cols) != len(wantCols) || cols[0] != wantCols[0] || cols[1] != wantCols[1] || cols[2] != wantCols[2] {
		t.Fatalf("0014 index column order: got %v, want %v (leading launching_principal, then the created_at/session_uuid keyset order keys)", cols, wantCols)
	}

	// Seed one principal + a scoped session so the EXPLAIN predicate binds against a
	// non-empty table (the plan shape, not the row count, is what we assert).
	_, err = pg.CreatePrincipal(ctx, Principal{ID: "p-keyset", IdPSubject: "okta|keyset", Org: "acme", Roles: []PrincipalRole{RoleLauncher}})
	mustNoErr(t, err)
	_, err = pg.CreateSession(ctx, newSession("sess-keyset", "host-a", 1))
	mustNoErr(t, err)
	mustNoErr(t, pg.SetSessionLaunchingPrincipal(ctx, "sess-keyset", "p-keyset"))

	// (3) Plan-scan assertion (non-vacuous, seqscan-forced). We EXPLAIN the SCOPED +
	// PAGED keyset predicate — the exact access sqlListSessions issues for a scoped
	// page: filter by launching_principal, order newest-first (created_at DESC,
	// session_uuid DESC), bounded LIMIT — inside a transaction with
	// `SET LOCAL enable_seqscan = off`. With seqscan penalized, an index-ordered
	// plan is chosen IFF one exists; the assertion below (Index Scan naming the
	// covering index, no Sort node) is therefore true ONLY when 0014 is present.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin EXPLAIN tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SET LOCAL enable_seqscan = off`); err != nil {
		t.Fatalf("SET LOCAL enable_seqscan = off: %v", err)
	}
	rows, err := tx.QueryContext(ctx,
		`EXPLAIN SELECT session_uuid FROM sessions
		   WHERE launching_principal = $1
		   ORDER BY created_at DESC, session_uuid DESC
		   FETCH FIRST 2 ROWS ONLY`, "p-keyset")
	if err != nil {
		t.Fatalf("EXPLAIN of the scoped+paged keyset predicate failed — schema/type mismatch: %v", err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			_ = rows.Close()
			t.Fatalf("scan EXPLAIN line: %v", err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatalf("EXPLAIN rows error: %v", err)
	}
	_ = rows.Close()
	planText := plan.String()
	if planText == "" {
		t.Fatalf("EXPLAIN produced no plan for the scoped+paged keyset query")
	}

	// The plan must use OUR covering index by name — this is what proves the
	// scoped+ordered access is index-served. If 0014 is absent, the only plan left
	// under enable_seqscan=off is a Seq Scan (legal last resort) + Sort, which names
	// neither an Index Scan nor sessions_keyset_idx, so this fails — the required
	// trip.
	if !strings.Contains(planText, idxName) {
		t.Fatalf("scoped+paged keyset plan does NOT use %q (index absent or not chosen even with enable_seqscan=off) — the console read is not index-served:\n%s", idxName, planText)
	}
	if !strings.Contains(planText, "Index Scan") && !strings.Contains(planText, "Index Only Scan") {
		t.Fatalf("scoped+paged keyset plan has no Index/Index-Only Scan node (got a fallback scan) — covering index not serving the access:\n%s", planText)
	}
	// The (created_at DESC, session_uuid DESC) ordering must be served BY THE INDEX,
	// not by a post-scan Sort — that is the whole point of carrying the order keys
	// in the composite. A Sort node here means the index isn't covering the order.
	if strings.Contains(planText, "Sort") {
		t.Fatalf("scoped+paged keyset plan includes a Sort node — the keyset order is not index-served by %q (missing/wrong-shape covering index):\n%s", idxName, planText)
	}
}

// testPrincipalRoundTrip exercises the doc 16 §3.2 minimal principal record:
// create with an IdP subject + org + role set, get it back, the
// UNIQUE(idp_subject, org) collision → ErrConflict, idempotent re-create on ID,
// and the role-set update.
func testPrincipalRoundTrip(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()

	in := Principal{
		ID: "prin-1", IdPSubject: "okta|user-1", Org: "acme",
		Roles:       []PrincipalRole{RoleLauncher, RoleApprover},
		DisplayName: "Ada",
	}
	got, err := repo.CreatePrincipal(ctx, in)
	mustNoErr(t, err)
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("principal timestamps not stamped: %+v", got)
	}
	if got.IdPSubject != "okta|user-1" || got.Org != "acme" || len(got.Roles) != 2 {
		t.Fatalf("principal not round-tripped: %+v", got)
	}

	fetched, err := repo.GetPrincipal(ctx, "prin-1")
	mustNoErr(t, err)
	if fetched.DisplayName != "Ada" || fetched.Roles[0] != RoleLauncher || fetched.Roles[1] != RoleApprover {
		t.Fatalf("get did not round-trip the record: %+v", fetched)
	}

	// Idempotent on ID: identical re-create returns the existing row.
	again, err := repo.CreatePrincipal(ctx, in)
	mustNoErr(t, err)
	if again.ID != "prin-1" {
		t.Fatalf("idempotent re-create changed the record: %+v", again)
	}

	// UNIQUE(idp_subject, org): the same human in the same org under a NEW id is
	// a conflict.
	dup := Principal{ID: "prin-2", IdPSubject: "okta|user-1", Org: "acme", Roles: []PrincipalRole{RoleViewer}}
	if _, err := repo.CreatePrincipal(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate (idp_subject, org): got %v, want ErrConflict", err)
	}

	// The same subject in a DIFFERENT org is a different, legal principal.
	other := Principal{ID: "prin-3", IdPSubject: "okta|user-1", Org: "globex", Roles: []PrincipalRole{RoleLauncher}}
	if _, err := repo.CreatePrincipal(ctx, other); err != nil {
		t.Fatalf("same subject in a different org should be legal: %v", err)
	}

	// Role-set update replaces the set atomically.
	updated, err := repo.SetPrincipalRoles(ctx, "prin-1", []PrincipalRole{RoleOrgAdmin})
	mustNoErr(t, err)
	if len(updated.Roles) != 1 || updated.Roles[0] != RoleOrgAdmin {
		t.Fatalf("role update not applied: %+v", updated.Roles)
	}
	reread, err := repo.GetPrincipal(ctx, "prin-1")
	mustNoErr(t, err)
	if len(reread.Roles) != 1 || reread.Roles[0] != RoleOrgAdmin {
		t.Fatalf("role update not persisted: %+v", reread.Roles)
	}
}

// testPrincipalIdPLookup exercises the `launching_user`-claim resolution lookup
// (doc 16 §3.2/§11.2): get a principal by its (IdP subject, org) pair, scoped by
// org so the same subject in another org never collides.
func testPrincipalIdPLookup(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()

	_, err := repo.CreatePrincipal(ctx, Principal{
		ID: "p-acme", IdPSubject: "sub-42", Org: "acme", Roles: []PrincipalRole{RoleLauncher},
	})
	mustNoErr(t, err)
	_, err = repo.CreatePrincipal(ctx, Principal{
		ID: "p-globex", IdPSubject: "sub-42", Org: "globex", Roles: []PrincipalRole{RoleViewer},
	})
	mustNoErr(t, err)

	acme, err := repo.GetPrincipalByIdP(ctx, "sub-42", "acme")
	mustNoErr(t, err)
	if acme.ID != "p-acme" {
		t.Fatalf("IdP lookup crossed org boundary: got %s, want p-acme", acme.ID)
	}
	globex, err := repo.GetPrincipalByIdP(ctx, "sub-42", "globex")
	mustNoErr(t, err)
	if globex.ID != "p-globex" {
		t.Fatalf("IdP lookup wrong org: got %s, want p-globex", globex.ID)
	}
	// A subject the org never asserted misses.
	if _, err := repo.GetPrincipalByIdP(ctx, "sub-99", "acme"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown IdP subject: got %v, want ErrNotFound", err)
	}
}

// testPrincipalRoleCheckParity pins that the in-memory Valid() mirrors the SQL
// role CHECK: an out-of-vocabulary role is rejected with ErrInvalid both on
// create and on role update, exactly as the 0006_principals.sql role CHECK
// rejects it at the database layer. It also asserts PrincipalRole.Valid() agrees
// with the PrincipalRoles() vocabulary the SQL CHECK enumerates — so a drift
// between the Go vocabulary and the SQL CHECK fails this case.
func testPrincipalRoleCheckParity(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()

	// Every advertised role is Valid(); nothing else is.
	for _, r := range PrincipalRoles() {
		if !r.Valid() {
			t.Fatalf("advertised role %q is not Valid()", r)
		}
	}
	if len(PrincipalRoles()) != 5 {
		t.Fatalf("role vocabulary size = %d, want exactly 5 (§3.2)", len(PrincipalRoles()))
	}
	for _, bad := range []PrincipalRole{"", "admin", "Launcher", "org_admin", "superuser"} {
		if bad.Valid() {
			t.Fatalf("non-vocabulary role %q reported Valid()", bad)
		}
	}

	// Create with an out-of-vocabulary role → ErrInvalid (the SQL CHECK mirror).
	bad := Principal{ID: "p-bad", IdPSubject: "sub-bad", Org: "acme", Roles: []PrincipalRole{RoleLauncher, "superuser"}}
	if _, err := repo.CreatePrincipal(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("create with bad role: got %v, want ErrInvalid", err)
	}

	// A good create, then a role update with a bad role → ErrInvalid.
	_, err := repo.CreatePrincipal(ctx, Principal{
		ID: "p-good", IdPSubject: "sub-good", Org: "acme", Roles: []PrincipalRole{RoleLauncher},
	})
	mustNoErr(t, err)
	if _, err := repo.SetPrincipalRoles(ctx, "p-good", []PrincipalRole{"org_admin"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("role update with bad role: got %v, want ErrInvalid", err)
	}
	// The bad update did not corrupt the stored set.
	reread, err := repo.GetPrincipal(ctx, "p-good")
	mustNoErr(t, err)
	if len(reread.Roles) != 1 || reread.Roles[0] != RoleLauncher {
		t.Fatalf("rejected role update mutated stored roles: %+v", reread.Roles)
	}
}

// testSessionLaunchingPrincipal exercises the doc 04 §5 attribution linkage: a
// session links to the principal that launched it, the link is nullable (clears
// to ""), a non-existent principal is rejected, and the link is unknown for an
// unknown session.
func testSessionLaunchingPrincipal(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()

	_, err := repo.CreateSession(ctx, newSession("sess-attr", "host-a", 1))
	mustNoErr(t, err)
	_, err = repo.CreatePrincipal(ctx, Principal{
		ID: "launcher-1", IdPSubject: "sub-launch", Org: "acme", Roles: []PrincipalRole{RoleLauncher},
	})
	mustNoErr(t, err)

	// Before linking: the nullable case returns "".
	ref, err := repo.GetSessionLaunchingPrincipal(ctx, "sess-attr")
	mustNoErr(t, err)
	if ref != "" {
		t.Fatalf("new session should have no launching principal, got %q", ref)
	}

	// Link the session to the principal.
	mustNoErr(t, repo.SetSessionLaunchingPrincipal(ctx, "sess-attr", "launcher-1"))
	ref, err = repo.GetSessionLaunchingPrincipal(ctx, "sess-attr")
	mustNoErr(t, err)
	if ref != "launcher-1" {
		t.Fatalf("attribution not recorded: got %q, want launcher-1", ref)
	}

	// Clearing the link (empty principal) restores the nullable case.
	mustNoErr(t, repo.SetSessionLaunchingPrincipal(ctx, "sess-attr", ""))
	ref, err = repo.GetSessionLaunchingPrincipal(ctx, "sess-attr")
	mustNoErr(t, err)
	if ref != "" {
		t.Fatalf("link not cleared: got %q", ref)
	}

	// Linking to a non-existent principal is rejected (the soft-FK guard).
	if err := repo.SetSessionLaunchingPrincipal(ctx, "sess-attr", "ghost"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("link to unknown principal: got %v, want ErrInvalid", err)
	}

	// Linking on an unknown session is ErrNotFound.
	if err := repo.SetSessionLaunchingPrincipal(ctx, "nope", "launcher-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("link on unknown session: got %v, want ErrNotFound", err)
	}
	if _, err := repo.GetSessionLaunchingPrincipal(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get link on unknown session: got %v, want ErrNotFound", err)
	}
}

func testNotFound(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()
	if _, err := repo.GetSession(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetSession miss: got %v, want ErrNotFound", err)
	}
	if _, err := repo.GetEnvConfig(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetEnvConfig miss: got %v, want ErrNotFound", err)
	}
	if _, err := repo.GetPlan(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPlan miss: got %v, want ErrNotFound", err)
	}
	if _, err := repo.GetPrincipal(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPrincipal miss: got %v, want ErrNotFound", err)
	}
	state := SessionReady
	if _, err := repo.UpdateSession(ctx, "nope", SessionUpdate{State: &state}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateSession miss: got %v, want ErrNotFound", err)
	}
}

// testRolePinPersistence pins the doc 18 §7 role triple onto the never-recycled
// session record and proves it round-trips through the store seam (migration
// 0009): a pin written at create is re-readable through GetSession, a pin written
// by the create choreography via UpdateSession is re-readable, and the pre-pin
// zero value is the "no pin yet" posture distinct from the recorded default. This
// is the "pin persisted and re-readable through the store seam" acceptance.
func testRolePinPersistence(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()

	// A fresh record carries the pre-pin zero value (no pin written yet) — Pinned
	// reports false, distinct from the recorded-default pin.
	in := newSession("sess-pin", "host-a", 3)
	created, err := repo.CreateSession(ctx, in)
	mustNoErr(t, err)
	if created.RolePin.Pinned() {
		t.Fatalf("fresh record reports a pin: %+v", created.RolePin)
	}

	// The create choreography writes the resolved pin through UpdateSession (the
	// store seam RunCreateSpine uses). A named role with an inert-widening posture.
	pin := RolePin{
		Name:           "researcher",
		Version:        "2026.06.11-v1",
		ContentHash:    "deadbeefcafef00dba5eba11deadbeefcafef00dba5eba11deadbeefcafef00d0",
		WideningsInert: true,
	}
	updated, err := repo.UpdateSession(ctx, "sess-pin", SessionUpdate{RolePin: &pin})
	mustNoErr(t, err)
	if updated.RolePin != pin {
		t.Fatalf("pin not applied on update: got %+v want %+v", updated.RolePin, pin)
	}
	if !updated.RolePin.Pinned() {
		t.Fatalf("pinned record reports no pin: %+v", updated.RolePin)
	}
	if got, want := updated.RolePin.Ref(), "researcher@2026.06.11-v1"; got != want {
		t.Fatalf("pin Ref() = %q, want %q", got, want)
	}

	// Re-read through the store seam: the persisted triple is byte-for-byte the
	// one written (the pin's system of record is the record, doc 18 §11 "every
	// session record carries role fields").
	reread, err := repo.GetSession(ctx, "sess-pin")
	mustNoErr(t, err)
	if reread.RolePin != pin {
		t.Fatalf("pin not persisted/re-readable: got %+v want %+v", reread.RolePin, pin)
	}

	// A pin written AT create round-trips too (the create write path, not just the
	// update path). The recorded default is an explicit, non-empty triple.
	withPin := newSession("sess-pin-create", "host-a", 4)
	withPin.RolePin = RolePin{
		Name:        "default",
		Version:     "2026.06.11-v1",
		ContentHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	gotCreate, err := repo.CreateSession(ctx, withPin)
	mustNoErr(t, err)
	if gotCreate.RolePin != withPin.RolePin {
		t.Fatalf("create-time pin not stored: got %+v want %+v", gotCreate.RolePin, withPin.RolePin)
	}
	rereadCreate, err := repo.GetSession(ctx, "sess-pin-create")
	mustNoErr(t, err)
	if rereadCreate.RolePin != withPin.RolePin {
		t.Fatalf("create-time pin not re-readable: got %+v want %+v", rereadCreate.RolePin, withPin.RolePin)
	}

	// A subsequent UpdateSession that does NOT touch the pin leaves it intact (the
	// immutable-per-session posture: the triple is written once, never churned by
	// later posture updates).
	state := SessionCreating
	afterOther, err := repo.UpdateSession(ctx, "sess-pin", SessionUpdate{State: &state})
	mustNoErr(t, err)
	if afterOther.RolePin != pin {
		t.Fatalf("unrelated update churned the pin: got %+v want %+v", afterOther.RolePin, pin)
	}
}

// testMintExpiryPersistence pins the doc 15 §5.6 / doc 16 §5.4 minted-credential
// expiry horizon onto the never-recycled session record and proves it round-trips
// through the store seam (migration 0010), mirroring testRolePinPersistence: a fresh
// record carries the not-set zero horizon; a horizon written by the §4.1 step-5
// UpdateSession (alongside IdentityRef/CARef) is re-readable through GetSession; a
// horizon written AT create round-trips; an unrelated update leaves it intact; and a
// re-mint (the §4.2 resume path) advances it. This is the "MintExpiry round-trips
// through the store seam" acceptance (memory + postgres, DS_PG_DSN-gated).
func testMintExpiryPersistence(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	ctx := context.Background()

	// A fresh record carries the not-set ZERO horizon (no TTL tracked) — the NULL
	// posture, distinct from a real expiry.
	in := newSession("sess-mint", "host-a", 9)
	created, err := repo.CreateSession(ctx, in)
	mustNoErr(t, err)
	if !created.MintExpiry.IsZero() {
		t.Fatalf("fresh record carries a non-zero mint expiry: %v", created.MintExpiry)
	}

	// The §4.1 step-5 create choreography writes the resolved horizon through
	// UpdateSession alongside IdentityRef/CARef. The horizon persists and re-reads.
	horizon := baseTime.Add(90 * time.Minute)
	idRef, caRef := "id-mint-1", "ca-mint-1"
	updated, err := repo.UpdateSession(ctx, "sess-mint", SessionUpdate{
		IdentityRef: &idRef,
		CARef:       &caRef,
		MintExpiry:  &horizon,
	})
	mustNoErr(t, err)
	if !updated.MintExpiry.Equal(horizon) {
		t.Fatalf("mint expiry not applied on update: got %v want %v", updated.MintExpiry, horizon)
	}
	if updated.IdentityRef != idRef || updated.CARef != caRef {
		t.Fatalf("identity/CA refs not applied alongside expiry: %+v", updated)
	}

	reread, err := repo.GetSession(ctx, "sess-mint")
	mustNoErr(t, err)
	if !reread.MintExpiry.Equal(horizon) {
		t.Fatalf("mint expiry not persisted/re-readable: got %v want %v", reread.MintExpiry, horizon)
	}

	// A horizon written AT create round-trips too (the create write path, not just the
	// update path).
	withExp := newSession("sess-mint-create", "host-a", 10)
	createHorizon := baseTime.Add(45 * time.Minute)
	withExp.MintExpiry = createHorizon
	gotCreate, err := repo.CreateSession(ctx, withExp)
	mustNoErr(t, err)
	if !gotCreate.MintExpiry.Equal(createHorizon) {
		t.Fatalf("create-time mint expiry not stored: got %v want %v", gotCreate.MintExpiry, createHorizon)
	}
	rereadCreate, err := repo.GetSession(ctx, "sess-mint-create")
	mustNoErr(t, err)
	if !rereadCreate.MintExpiry.Equal(createHorizon) {
		t.Fatalf("create-time mint expiry not re-readable: got %v want %v", rereadCreate.MintExpiry, createHorizon)
	}

	// An UpdateSession that does NOT touch the horizon (nil MintExpiry) leaves it intact
	// — the leave-alone semantics (a posture update never churns the persisted horizon).
	state := SessionCreating
	afterOther, err := repo.UpdateSession(ctx, "sess-mint", SessionUpdate{State: &state})
	mustNoErr(t, err)
	if !afterOther.MintExpiry.Equal(horizon) {
		t.Fatalf("unrelated update churned the mint expiry: got %v want %v", afterOther.MintExpiry, horizon)
	}

	// The §4.2 resume re-mint advances the horizon (an expired credential re-mints on
	// resume — doc 16 §5.4): a later non-nil MintExpiry replaces the persisted one.
	resumeHorizon := baseTime.Add(3 * time.Hour)
	remint, err := repo.UpdateSession(ctx, "sess-mint", SessionUpdate{MintExpiry: &resumeHorizon})
	mustNoErr(t, err)
	if !remint.MintExpiry.Equal(resumeHorizon) {
		t.Fatalf("re-mint did not advance the persisted horizon: got %v want %v", remint.MintExpiry, resumeHorizon)
	}

	// A re-mint that surfaced NO TTL sets the not-set zero posture back (NULL), distinct
	// from leave-alone (nil): a non-nil pointer to the zero time clears the horizon.
	var zero time.Time
	cleared, err := repo.UpdateSession(ctx, "sess-mint", SessionUpdate{MintExpiry: &zero})
	mustNoErr(t, err)
	if !cleared.MintExpiry.IsZero() {
		t.Fatalf("explicit zero horizon did not persist as not-set: got %v", cleared.MintExpiry)
	}
	rereadCleared, err := repo.GetSession(ctx, "sess-mint")
	mustNoErr(t, err)
	if !rereadCleared.MintExpiry.IsZero() {
		t.Fatalf("not-set horizon not re-readable as zero: got %v", rereadCleared.MintExpiry)
	}
}

// --- reArmMintExpiry live-set READ posture (the store half of the boot re-arm) ---
//
// controlplane.reArmMintExpiry (wave-1 owned — NOT edited here) re-arms the in-process
// mint-expiry timers across an orchestrator restart by reading the durable set with
// ListSessions(IncludeDestroyed=false), then re-arming every returned record whose
// MintExpiry is non-zero (skipping the not-set NULL posture) and is non-terminal. It adds
// NO method to any store seam — it relies ENTIRELY on the STORE'S ListSessions read posture:
//
//   - DESTROYED records are OMITTED at the SQL filter ($4 OR state <> 'DESTROYED'); the
//     terminal session is never re-armed.
//   - DESTROYING (mid-teardown) records ARE returned (non-terminal in the §3 machine); the
//     sweep may re-arm them, which is safe (fire()'s drop covers DESTROYING).
//   - the persisted MintExpiry horizon round-trips on every returned record, with a NULL
//     column read back as the zero (not-set) value the sweep SKIPS.
//
// This test asserts that STORE read posture directly (so it stays disjoint from the
// wave-1 controlplane file): it seeds live + DESTROYING + DESTROYED records with persisted
// horizons (and a NULL/zero one), lists with IncludeDestroyed=false on BOTH backends, and
// asserts the with-horizon set the sweep would re-arm is IDENTICAL across *Memory and
// *Postgres (DESTROYED omitted, NULL/zero skipped). It is the live-engine companion to
// testMintExpiryPersistence (which round-trips the column) for exactly the read shape the
// boot re-arm consumes.

// rearmHorizon is one session's {uuid → persisted MintExpiry} as the boot re-arm would read
// it after listing the live set and applying its non-zero / non-terminal filters.
type rearmHorizon struct {
	uuid    string
	horizon time.Time
}

// seedMintExpiryReArmFixture writes the SAME fixture the boot re-arm reads onto any
// Repository: four records spanning the read-posture matrix —
//   - a live SUSPENDED session with a persisted (non-zero) horizon  → re-armed,
//   - a DESTROYING session with a persisted horizon                 → re-armed (non-terminal),
//   - a DESTROYED session with a persisted horizon                  → OMITTED at the filter,
//   - a live ATTACHED session with the NULL not-set (zero) horizon  → returned but SKIPPED.
//
// Distinct created_at stamps are not needed; the suite compares the set, not the order.
func seedMintExpiryReArmFixture(t *testing.T, repo Repository, clk time.Time) {
	t.Helper()
	ctx := context.Background()

	// (1) live SUSPENDED with a persisted horizon — re-armed.
	liveHorizon := clk.Add(30 * time.Minute)
	_, err := repo.CreateSession(ctx, newSession("rearm-live", "host-a", 1))
	mustNoErr(t, err)
	suspended := SessionSuspended
	reason := SuspendReasonUser
	_, err = repo.UpdateSession(ctx, "rearm-live", SessionUpdate{State: &suspended, SuspendReason: &reason, MintExpiry: &liveHorizon})
	mustNoErr(t, err)

	// (2) DESTROYING (mid-teardown, non-terminal) with a persisted horizon — re-armed.
	destroyingHorizon := clk.Add(15 * time.Minute)
	_, err = repo.CreateSession(ctx, newSession("rearm-destroying", "host-a", 2))
	mustNoErr(t, err)
	destroying := SessionDestroying
	_, err = repo.UpdateSession(ctx, "rearm-destroying", SessionUpdate{State: &destroying, MintExpiry: &destroyingHorizon})
	mustNoErr(t, err)

	// (3) DESTROYED (terminal) with a persisted horizon — OMITTED at the SQL filter.
	destroyedHorizon := clk.Add(45 * time.Minute)
	_, err = repo.CreateSession(ctx, newSession("rearm-destroyed", "host-a", 3))
	mustNoErr(t, err)
	destroying2 := SessionDestroying
	_, err = repo.UpdateSession(ctx, "rearm-destroyed", SessionUpdate{State: &destroying2, MintExpiry: &destroyedHorizon})
	mustNoErr(t, err)
	destroyed := SessionDestroyed
	_, err = repo.UpdateSession(ctx, "rearm-destroyed", SessionUpdate{State: &destroyed, DestroyedAt: SetTime(clk)})
	mustNoErr(t, err)

	// (4) live ATTACHED with the NULL not-set (zero) horizon — returned by the list but
	// SKIPPED by the re-arm (no TTL to track).
	_, err = repo.CreateSession(ctx, newSession("rearm-nullhorizon", "host-a", 4))
	mustNoErr(t, err)
	attached := SessionAttached
	_, err = repo.UpdateSession(ctx, "rearm-nullhorizon", SessionUpdate{State: &attached})
	mustNoErr(t, err)
}

// collectReArmSet replays the boot re-arm's STORE read posture on a Repository and returns
// the set of records it would re-arm: list IncludeDestroyed=false, then keep every returned
// record that is non-terminal AND carries a non-zero horizon (the exact two filters
// reArmMintExpiry applies after the list). The result is a uuid→horizon map so the two
// backends can be compared as a SET (order-independent).
func collectReArmSet(t *testing.T, repo Repository) map[string]time.Time {
	t.Helper()
	live, err := repo.ListSessions(context.Background(), SessionFilter{IncludeDestroyed: false})
	mustNoErr(t, err)
	out := map[string]time.Time{}
	for _, rec := range live {
		if rec.State.IsTerminal() { // defense in depth: the filter omits DESTROYED already
			continue
		}
		if rec.MintExpiry.IsZero() { // the not-set NULL posture is skipped (no TTL to track)
			continue
		}
		out[rec.Ref.SessionUUID] = rec.MintExpiry
	}
	return out
}

// testMintExpiryReArmReadPosture is the in-memory half: it pins the EXACT set the boot
// re-arm would re-arm (rearm-live + rearm-destroying, at their persisted horizons), with
// the DESTROYED record omitted at the filter and the NULL-horizon record skipped. It is
// run through the conformance harness so the same assertions hold for *Memory; the live
// *Postgres equivalence is asserted in TestPostgres_MintExpiryReArmReadPostureMatchesMemory.
func testMintExpiryReArmReadPosture(t *testing.T, newRepo RepoFactory) {
	repo := newRepo(fixedClock(baseTime))
	seedMintExpiryReArmFixture(t, repo, baseTime)

	want := []rearmHorizon{
		{"rearm-live", baseTime.Add(30 * time.Minute)},
		{"rearm-destroying", baseTime.Add(15 * time.Minute)},
	}
	got := collectReArmSet(t, repo)
	assertReArmSet(t, got, want)
}

// assertReArmSet asserts the collected re-arm set equals the expected {uuid → horizon}
// pairs EXACTLY (no extra, no missing, horizons equal) — so a DESTROYED record leaking
// through, a NULL-horizon record re-armed, or a dropped/wrong horizon all fail.
func assertReArmSet(t *testing.T, got map[string]time.Time, want []rearmHorizon) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("re-arm set size = %d, want %d (DESTROYED must be omitted, NULL-horizon skipped); got=%v", len(got), len(want), got)
	}
	for _, w := range want {
		h, ok := got[w.uuid]
		if !ok {
			t.Fatalf("re-arm set missing %q (the live/destroying set the boot re-arm reads); got=%v", w.uuid, got)
		}
		if !h.Equal(w.horizon) {
			t.Fatalf("re-arm horizon for %q = %v, want %v", w.uuid, h, w.horizon)
		}
	}
}

// TestPostgres_MintExpiryReArmReadPostureMatchesMemory is the DS_PG_DSN-gated live-engine
// half: it seeds the IDENTICAL re-arm fixture on a real *store.Postgres, replays the boot
// re-arm's read posture (ListSessions IncludeDestroyed=false + the non-terminal/non-zero
// filters), and asserts the re-armed set is byte-for-byte what *Memory produces for the
// same seed — proving DESTROYED is omitted at the live SQL filter ($4 OR state <>
// 'DESTROYED'), the NULL mint_expiry column reads back as the skipped zero posture, and the
// DESTROYING horizon round-trips. SKIPS cleanly without DS_PG_DSN (deferred manual step);
// it reuses openPostgresOrSkip's gate plumbing (which also truncates), never the migration
// or the wave-1 controlplane re-arm code.
func TestPostgres_MintExpiryReArmReadPostureMatchesMemory(t *testing.T) {
	pg := openPostgresOrSkip(t).(*Postgres) // skip-without-DB + truncateAll; *Postgres for the seed

	// The deterministic clock the fixture's horizons are computed against — the SAME
	// instant the in-memory half uses, so the two backends' horizons compare equal.
	clk := baseTime

	// Compute the reference set from a FRESH *Memory seeded identically (the D33 parity
	// oracle), so the assertion is "Postgres == Memory" rather than a hand-maintained list.
	mem := NewMemoryClock(fixedClock(clk))
	seedMintExpiryReArmFixture(t, mem, clk)
	wantSet := collectReArmSet(t, mem)

	seedMintExpiryReArmFixture(t, pg, clk)
	gotSet := collectReArmSet(t, pg)

	if len(gotSet) != len(wantSet) {
		t.Fatalf("Postgres re-arm set size = %d, want %d (== Memory); pg=%v mem=%v", len(gotSet), len(wantSet), gotSet, wantSet)
	}
	for uuid, wantHorizon := range wantSet {
		gotHorizon, ok := gotSet[uuid]
		if !ok {
			t.Fatalf("Postgres re-arm set missing %q present in Memory; pg=%v mem=%v", uuid, gotSet, wantSet)
		}
		if !gotHorizon.Equal(wantHorizon) {
			t.Fatalf("Postgres re-arm horizon for %q = %v, want %v (== Memory)", uuid, gotHorizon, wantHorizon)
		}
	}
	// Belt-and-suspenders: the DESTROYED record must NOT appear (omitted at the SQL filter)
	// and the NULL-horizon record must NOT appear (skipped) — on the LIVE backend.
	if _, leaked := gotSet["rearm-destroyed"]; leaked {
		t.Fatalf("DESTROYED record leaked into the live re-arm set (SQL filter $4 OR state <> 'DESTROYED' failed): %v", gotSet)
	}
	if _, leaked := gotSet["rearm-nullhorizon"]; leaked {
		t.Fatalf("NULL-horizon record was re-armed on the live backend (the not-set posture must be skipped): %v", gotSet)
	}
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
