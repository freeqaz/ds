// SPDX-License-Identifier: Apache-2.0

package sessions

// parkresume_postgres_test.go — DS_PG_DSN-gated LIVE-Postgres conformance for the
// durable minted-credential horizon (doc 15 §5.6, doc 16 §5.4; migration 0010
// session_mint_expiry) ACROSS the §4.2/§4.3 resume re-mint CODE PATHS, driven against a
// real *store.Postgres rather than the in-memory fake.
//
// WHY THIS FILE EXISTS (the gap it closes). The wave-1 mint-expiry units validated the
// durable-horizon read/persist contract with synthetic *store.Memory fakes only
// (parkresume_mintexpiry_test.go drives ParkResumeDriver.Resume / ResumeFromPark over
// NewMemory()), and store/conformance_test.go's testMintExpiryPersistence round-trips the
// migration-0010 column through the store seam. What was UNEXERCISED is the actual NEW
// CODE PATH end to end on a live engine: ParkResumeDriver.Resume (the in-place
// SUSPENDED→RESUMING→WORKING re-mint of an EXPIRED persisted horizon) and ResumeFromPark
// (the PARKED→CREATING@host' re-place re-mint) advancing the durable {IdentityRef, CARef,
// MintExpiry} through *store.Postgres.UpdateSession and re-reading it through GetSession.
// This file drives those verbs against the real Postgres-backed Repository so the
// persist + read of the 0010 column is proven on the engine, not asserted against *Memory.
//
// GATING (D50 synthetic-vs-live discipline). The whole suite SKIPS cleanly when DS_PG_DSN
// is UNSET, so the default `go test ./...` run is unaffected (no live VM / host-agent /
// podman / Postgres required). It also SKIPS — never fails — when the driver is
// unregistered or the database is unreachable: a live run is a DEFERRED MANUAL STEP an
// operator enables by exporting DS_PG_DSN (and DS_PG_DRIVER, registering a Postgres driver
// at the binary boundary, D33). The gate plumbing MIRRORS store/postgres_open_conformance_test.go's
// openOrchPostgresOrSkip / the DS_PG_DSN suites' openPostgresOrSkip (same env var, same
// default driver, same skip-or-ping posture), kept in-package because a sessions test
// cannot import the store package's test-file helper.
//
// DISJOINTNESS. This is a NEW file only. It edits NO production file (parkresume.go /
// mintexpiry_rearm.go / wiring.go / reconciler.go are FROZEN here) and NO migration: it
// constructs *store.Postgres via the EXPORTED store.NewPostgresClock (the same constructor
// controlplane.NewPostgresStore reaches) and reuses the same-package pr-prefixed synthetic
// seams (prMinterExp / prResumer / prPlacer / prAlloc / prApprovals) the wave-1
// mint-expiry tests already defined. It TRUNCATEs only the session-scoped tables it seeds,
// the same lifecycle the DS_PG_DSN store suites use, so it never collides with another
// suite's fixtures.

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// pgResumeClock is the driver clock the live-Postgres resume tests pin time against — the
// SAME instant the in-memory mustDriver / fixedNow use, so the before/after-horizon
// arithmetic (expired = clock-1h, fresh = clock+1h) reads identically on both backends.
var pgResumeClock = time.Unix(1_700_000_000, 0)

// openSessionsPostgresOrSkip opens the live store the SAME way controlplane.NewPostgresStore
// does — sql.Open(driver, dsn) then store.NewPostgresClock — and returns both the typed
// *store.Postgres (the driver's Store seam) and the raw *sql.DB (for the per-test truncate).
// It reads DS_PG_DSN / DS_PG_DRIVER (default "postgres"), the SAME gate the store package's
// DS_PG_DSN conformance suites use, so a CI lane that exports DS_PG_DSN runs this too. It
// SKIPS — never fails — without the env, an unregistered driver, or an unreachable database,
// so the default `go test ./...` run is unaffected and a live run stays a deferred manual
// step. The returned store is wired to the pgResumeClock so the store's own timestamps are
// deterministic; the DRIVER's horizon arithmetic uses the same instant via mustDriver.
func openSessionsPostgresOrSkip(t *testing.T) (*store.Postgres, *sql.DB) {
	t.Helper()
	// The open/ping/skip dance is single-sourced through storetest.OpenOrSkip (its
	// SkipMessages reproduce this caller's exact skip wording byte-for-byte); this
	// function keeps its OWN env var (DS_PG_DSN), its OWN post-open steps
	// (truncateSessionTables + the pgResumeClock-wired NewPostgresClock), and its
	// (*store.Postgres, *sql.DB) return shape.
	db := storetest.OpenOrSkip(t, "DS_PG_DSN", "DS_PG_DRIVER", storetest.SkipMessages{
		Unset:   "DS_PG_DSN not set: skipping live-Postgres park/resume re-mint conformance (deferred manual step)",
		OpenErr: "sql.Open(%q): %v — register a Postgres driver at the binary boundary (DS_PG_DRIVER, D33) to run this",
		PingErr: "ping %s: %v — Postgres unreachable; deferred manual step (set DS_PG_DSN to a reachable DB)",
	})
	truncateSessionTables(t, db)
	return store.NewPostgresClock(db, func() time.Time { return pgResumeClock }), db
}

// truncateSessionTables resets the session-scoped tables this suite seeds so each test
// starts from a clean slate (the in-memory fresh-store parity). CASCADE handles the FK
// edges (session_index_epochs → sessions); RESTART IDENTITY is harmless here. It mirrors
// the store suites' truncateAll but scopes to exactly the tables these resume tests touch.
func truncateSessionTables(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const stmt = `TRUNCATE session_index_epochs, sessions RESTART IDENTITY CASCADE`
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		t.Fatalf("truncate session tables: %v", err)
	}
}

// seedPostgresSession writes a session record at the given state directly through the
// *store.Postgres Repository (mirroring the in-memory seedSession in parkresume_test.go):
// create at WORKING with a real RolePin (the re-mint reads rec.RolePin.Name), then advance
// to the desired state (suspend reason set iff SUSPENDED, the 0001 CHECK). It returns the
// persisted record.
func seedPostgresSession(t *testing.T, pg *store.Postgres, uuid, hostID string, idx uint64, state store.SessionState, reason store.SuspendReason) store.Session {
	t.Helper()
	ctx := context.Background()
	_, err := pg.CreateSession(ctx, store.Session{
		Ref:     store.SessionRef{SessionUUID: uuid, HostID: hostID, HostSessionIndex: idx, TapName: "dstap-1"},
		ImageID: "img-1",
		State:   store.SessionWorking,
		RolePin: store.RolePin{Name: "default", Version: "v1", ContentHash: "h"},
	})
	if err != nil {
		t.Fatalf("seed CreateSession (postgres): %v", err)
	}
	if state != store.SessionWorking {
		u := store.SessionUpdate{State: &state}
		if reason != store.SuspendReasonNone {
			u.SuspendReason = &reason
		}
		if _, err := pg.UpdateSession(ctx, uuid, u); err != nil {
			t.Fatalf("seed advance to %s (postgres): %v", state, err)
		}
	}
	got, err := pg.GetSession(ctx, uuid)
	if err != nil {
		t.Fatalf("seed GetSession (postgres): %v", err)
	}
	return got
}

// setPostgresMintExpiry advances the seeded record's persisted MintExpiry through the
// *store.Postgres seam (the §5.6 column, migration 0010), mirroring the in-memory
// setMintExpiry helper — a non-nil pointer sets the durable horizon (the zero time persists
// as the NULL not-set posture).
func setPostgresMintExpiry(t *testing.T, pg *store.Postgres, uuid string, horizon time.Time) {
	t.Helper()
	if _, err := pg.UpdateSession(context.Background(), uuid, store.SessionUpdate{MintExpiry: &horizon}); err != nil {
		t.Fatalf("seed MintExpiry (postgres): %v", err)
	}
}

// TestPostgres_ResumeExpiredCredentialReMintRoundTrips is the headline live-Postgres §4.2
// assertion: an expired-horizon SUSPENDED session, resumed through ParkResumeDriver.Resume
// against a REAL *store.Postgres, re-mints (Minter fake returns a fresh Expiry) and the
// advanced {IdentityRef, CARef, MintExpiry} ROUND-TRIPS through Postgres — re-readable via
// GetSession — and the record reaches RESUMING→WORKING. This proves the migration-0010
// column persist/read on the engine across the actual resume re-mint code path (the
// in-memory mirror is TestResumeExpiredCredentialReMintsBeforeHostResume).
func TestPostgres_ResumeExpiredCredentialReMintRoundTrips(t *testing.T) {
	pg, _ := openSessionsPostgresOrSkip(t)
	ctx := context.Background()

	seedPostgresSession(t, pg, "pg-resume-1", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	// Persist an EXPIRED horizon (one hour before the driver clock) so the resume must re-mint.
	setPostgresMintExpiry(t, pg, "pg-resume-1", pgResumeClock.Add(-time.Hour))

	freshHorizon := pgResumeClock.Add(time.Hour)
	minter := &prMinterExp{idRef: "id-fresh-pg", caRef: "ca-fresh-pg", expiry: freshHorizon}
	res := &prResumer{}
	d := mustDriver(t, ParkResumeSeams{Store: pg, Resumer: res, Minter: minter})

	rec, err := d.Resume(ctx, "pg-resume-1", ResumeAuthorityUser)
	if err != nil {
		t.Fatalf("Resume over *store.Postgres: %v", err)
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

	// THE ROUND-TRIP: the advanced {IdentityRef, CARef, MintExpiry} must be re-readable
	// through Postgres GetSession (the persist landed in the 0010 column on the engine,
	// not just the returned value).
	got, err := pg.GetSession(ctx, "pg-resume-1")
	if err != nil {
		t.Fatalf("GetSession after resume: %v", err)
	}
	if got.State != store.SessionWorking {
		t.Fatalf("persisted state=%s, want WORKING", got.State)
	}
	if got.IdentityRef != "id-fresh-pg" || got.CARef != "ca-fresh-pg" {
		t.Fatalf("re-minted identity/CA not persisted through Postgres: %s/%s", got.IdentityRef, got.CARef)
	}
	if !got.MintExpiry.Equal(freshHorizon) {
		t.Fatalf("durable horizon not advanced/round-tripped through Postgres: got %v want %v", got.MintExpiry, freshHorizon)
	}
}

// TestPostgres_ResumeFutureHorizonNoChurn pins the no-churn arm on the live engine: a
// session whose persisted horizon is still in the FUTURE resumes through Postgres with NO
// Minter call and NO identity/CA churn — the durable horizon and refs are left byte-for-byte
// intact across the resume (the "no spurious update" posture, mirrored in-memory by
// TestResumeFutureHorizonNoReMint).
func TestPostgres_ResumeFutureHorizonNoChurn(t *testing.T) {
	pg, _ := openSessionsPostgresOrSkip(t)
	ctx := context.Background()

	seedPostgresSession(t, pg, "pg-resume-2", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	future := pgResumeClock.Add(time.Hour)
	setPostgresMintExpiry(t, pg, "pg-resume-2", future)
	// Pin the seed identity/CA so a (forbidden) re-mint would be observable as churn on read-back.
	if _, err := pg.UpdateSession(ctx, "pg-resume-2", store.SessionUpdate{
		IdentityRef: ptr("id-orig-pg"), CARef: ptr("ca-orig-pg"),
	}); err != nil {
		t.Fatalf("seed identity/CA (postgres): %v", err)
	}

	minter := &prMinterExp{idRef: "id-NEW-pg", caRef: "ca-NEW-pg", expiry: pgResumeClock.Add(2 * time.Hour)}
	res := &prResumer{}
	d := mustDriver(t, ParkResumeSeams{Store: pg, Resumer: res, Minter: minter})

	rec, err := d.Resume(ctx, "pg-resume-2", ResumeAuthorityUser)
	if err != nil {
		t.Fatalf("Resume (future horizon) over *store.Postgres: %v", err)
	}
	if rec.State != store.SessionWorking {
		t.Fatalf("record=%s, want WORKING", rec.State)
	}
	if minter.calls != 0 {
		t.Fatalf("a future-horizon resume must NOT re-mint, got %d Minter calls", minter.calls)
	}

	got, err := pg.GetSession(ctx, "pg-resume-2")
	if err != nil {
		t.Fatalf("GetSession after no-churn resume: %v", err)
	}
	if got.IdentityRef != "id-orig-pg" || got.CARef != "ca-orig-pg" {
		t.Fatalf("a no-churn resume must not rewrite identity/CA on the engine: got %s/%s", got.IdentityRef, got.CARef)
	}
	if !got.MintExpiry.Equal(future) {
		t.Fatalf("future horizon must be left intact through Postgres: got %v want %v", got.MintExpiry, future)
	}
}

// TestPostgres_ResumeFromParkAdvancesDurableHorizonRoundTrips is the live §4.3 re-place
// assertion: ResumeFromPark re-mints on the PARKED→CREATING@host' spine and the fresh
// MintResult.Expiry lands on the SAME UpdateSession alongside the re-minted IdentityRef/CARef,
// round-tripping through Postgres GetSession. It also asserts the ZERO-expiry NULL posture is
// preserved: a re-place re-mint that surfaces NO expiry clears the stale horizon to the
// not-set (zero/NULL) value on the engine, never a spurious TTL (mirrored in-memory by
// TestResumeFromParkAdvancesDurableHorizon / TestResumeFromParkZeroExpiryPersistsNotSet).
func TestPostgres_ResumeFromParkAdvancesDurableHorizonRoundTrips(t *testing.T) {
	pg, _ := openSessionsPostgresOrSkip(t)
	ctx := context.Background()

	// Arm 1: a re-mint that surfaces a FRESH expiry advances the durable horizon.
	seedPostgresSession(t, pg, "pg-park-1", "host-a", 1, store.SessionParked, store.SuspendReasonNone)
	freshHorizon := pgResumeClock.Add(90 * time.Minute)
	placer := &prPlacer{hostID: "host-b", appliedSeq: 42}
	alloc := &prAlloc{idx: 5, tap: "dstap-5"}
	minter := &prMinterExp{idRef: "id-rp-pg", caRef: "ca-rp-pg", expiry: freshHorizon}
	d := mustDriver(t, ParkResumeSeams{
		Store: pg, Placer: placer, HostAllocator: alloc, Minter: minter,
		Approvals: prApprovals{landed: true},
	})

	rec, err := d.ResumeFromPark(ctx, "pg-park-1", ResumeAuthorityUser, attachReasonUser)
	if err != nil {
		t.Fatalf("ResumeFromPark over *store.Postgres: %v", err)
	}
	if rec.State != store.SessionCreating {
		t.Fatalf("record=%s, want CREATING@host'", rec.State)
	}
	if minter.calls != 1 {
		t.Fatalf("re-place must re-mint exactly once, got %d Minter calls", minter.calls)
	}

	got, err := pg.GetSession(ctx, "pg-park-1")
	if err != nil {
		t.Fatalf("GetSession after re-place: %v", err)
	}
	if got.IdentityRef != "id-rp-pg" || got.CARef != "ca-rp-pg" {
		t.Fatalf("re-minted identity/CA not persisted through Postgres on re-place: %s/%s", got.IdentityRef, got.CARef)
	}
	if !got.MintExpiry.Equal(freshHorizon) {
		t.Fatalf("durable horizon not advanced/round-tripped through Postgres on re-place: got %v want %v", got.MintExpiry, freshHorizon)
	}

	// Arm 2: a re-place re-mint that surfaces NO expiry (bare Minter, zero MintResult.Expiry)
	// persists the not-set (NULL) horizon — clearing a pre-seeded stale one — never a spurious
	// TTL. Seed a stale horizon first so the clear is observable on read-back.
	seedPostgresSession(t, pg, "pg-park-2", "host-c", 2, store.SessionParked, store.SuspendReasonNone)
	setPostgresMintExpiry(t, pg, "pg-park-2", pgResumeClock.Add(-time.Hour))
	placer2 := &prPlacer{hostID: "host-d", appliedSeq: 7}
	alloc2 := &prAlloc{idx: 9, tap: "dstap-9"}
	minterZero := &prMinterExp{idRef: "id-rp2-pg", caRef: "ca-rp2-pg"} // expiry left zero
	d2 := mustDriver(t, ParkResumeSeams{
		Store: pg, Placer: placer2, HostAllocator: alloc2, Minter: minterZero,
		Approvals: prApprovals{landed: true},
	})

	rec2, err := d2.ResumeFromPark(ctx, "pg-park-2", ResumeAuthorityUser, attachReasonUser)
	if err != nil {
		t.Fatalf("ResumeFromPark (zero expiry) over *store.Postgres: %v", err)
	}
	if !rec2.MintExpiry.IsZero() {
		t.Fatalf("a zero-expiry re-mint must persist the not-set horizon, got %v", rec2.MintExpiry)
	}
	gotZero, err := pg.GetSession(ctx, "pg-park-2")
	if err != nil {
		t.Fatalf("GetSession after zero-expiry re-place: %v", err)
	}
	if !gotZero.MintExpiry.IsZero() {
		t.Fatalf("not-set (NULL) horizon not re-readable as zero through Postgres: got %v", gotZero.MintExpiry)
	}
}

// TestPostgres_ResumeZeroHorizonNoUpdateChurn pins the zero/NULL-posture preservation on
// the engine independent of the resume re-mint: a session with NO tracked horizon (NULL
// mint_expiry — the not-set posture) resumes through Postgres with no Minter call, and an
// UNRELATED UpdateSession (a state-only posture write) never materializes a spurious TTL on
// the NULL column. This is the §5.6 "no churn on an unrelated update" / NULL-posture
// acceptance, asserted on the live engine where a real timestamptz NULL is at stake.
func TestPostgres_ResumeZeroHorizonNoUpdateChurn(t *testing.T) {
	pg, _ := openSessionsPostgresOrSkip(t)
	ctx := context.Background()

	seedPostgresSession(t, pg, "pg-resume-3", "host-a", 1, store.SessionSuspended, store.SuspendReasonUser)
	// No setPostgresMintExpiry: the seeded record carries the zero (NULL not-set) horizon.

	// Sanity: the seeded record's horizon is genuinely NULL/not-set before the resume.
	pre, err := pg.GetSession(ctx, "pg-resume-3")
	if err != nil {
		t.Fatalf("GetSession pre-resume: %v", err)
	}
	if !pre.MintExpiry.IsZero() {
		t.Fatalf("seeded record must carry the not-set (NULL) horizon, got %v", pre.MintExpiry)
	}

	minter := &prMinterExp{idRef: "id-NEW-pg", caRef: "ca-NEW-pg", expiry: pgResumeClock.Add(time.Hour)}
	res := &prResumer{}
	d := mustDriver(t, ParkResumeSeams{Store: pg, Resumer: res, Minter: minter})

	rec, err := d.Resume(ctx, "pg-resume-3", ResumeAuthorityUser)
	if err != nil {
		t.Fatalf("Resume (zero horizon) over *store.Postgres: %v", err)
	}
	if rec.State != store.SessionWorking {
		t.Fatalf("record=%s, want WORKING", rec.State)
	}
	if minter.calls != 0 {
		t.Fatalf("a zero-horizon (no TTL tracked) resume must NOT re-mint, got %d Minter calls", minter.calls)
	}

	// The resume's RESUMING/WORKING advances are unrelated to the horizon and must leave the
	// NULL column untouched on the engine — no spurious TTL appears.
	got, err := pg.GetSession(ctx, "pg-resume-3")
	if err != nil {
		t.Fatalf("GetSession after zero-horizon resume: %v", err)
	}
	if !got.MintExpiry.IsZero() {
		t.Fatalf("an unrelated (state-only) resume update must not churn the NULL horizon into a TTL: got %v", got.MintExpiry)
	}
}
