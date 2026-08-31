package store

// postgres_open_conformance_test.go — a DS_ORCH_PG_DSN-gated conformance test for
// the LIVE store-OPEN + MIGRATION-APPLY path end to end against a real Postgres
// engine (D6: control-plane state lives in external Postgres only; D33: the driver
// choice is the operator's, so this package — and orchestrator/go.mod — stay
// stdlib-only and import NO Postgres driver).
//
// WHY THIS FILE EXISTS (the gap it closes). The live-edge constructor
// controlplane.NewPostgresStore (orchestrator/internal/controlplane/liveedges.go,
// reached under DS_ORCH_LIVE=1) opens the external store from a DSN via
// sql.Open(driver, dsn) + store.NewPostgres(db). sql.Open does not dial, so a
// non-live run never touches a database; until now NO test drove that open path
// against a REAL engine WITH the orchestrator/migrations schema applied. This file
// adds that proof: when DS_ORCH_PG_DSN is set, it
//
//   1. opens the live *store.Postgres exactly the way NewPostgresStore does
//      (sql.Open + NewPostgres — the same two calls; this package cannot import
//      controlplane without an import cycle, since controlplane imports store, so it
//      exercises the identical open primitives in-package rather than the wrapper);
//   2. applies orchestrator/migrations/NNNN_*.sql in the apply.sh LEXICAL order
//      (the zero-padded prefix == apply order), recording a schema_migrations
//      ledger so a re-run over a populated database is a safe no-op — the same
//      re-run posture apply.sh implements;
//   3. round-trips a session record and exercises a couple of the landed queries
//      (CreateSession→GetSession, an UpdateSession state transition, a
//      ListSessions filter, and an AppendPolicy→ListPolicy append-log read) — so
//      the open + migrate + read/write path is proven on the engine, not asserted
//      against *Memory.
//
// GATING. The whole test SKIPS cleanly when DS_ORCH_PG_DSN is UNSET, so the default
// `go test ./...` run is unaffected (no live VM / host-agent / podman / Postgres
// required, D50). It also SKIPS — never fails — when the driver is unregistered or
// the database is unreachable: an actual live run is a DEFERRED MANUAL STEP that an
// operator enables by exporting DS_ORCH_PG_DSN (and DS_ORCH_PG_DRIVER, registering a
// Postgres driver at the binary boundary, D33). The CI pg-conformance lane
// (.github/workflows/pg-conformance.yml) could later export DS_ORCH_PG_DSN so this
// RUNS there rather than skips, the same way the DS_PG_DSN suites are wired.
//
// DISJOINTNESS. This is a NEW file only. It edits NO existing store source (all
// FROZEN) and NO migration: it reads the .sql files from disk and applies them, and
// it reuses the package's existing newSession helper for the record skeleton. It
// uses its OWN env var (DS_ORCH_PG_DSN / DS_ORCH_PG_DRIVER) so it never collides
// with the DS_PG_DSN-gated suites' truncate-then-run lifecycle.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// orchPGMigrationName is the apply-ordering convention's regexp from
// orchestrator/migrations (a zero-padded 4-digit sequence prefix == apply
// order), single-sourced from storetest.MigrationNamePattern (the shared
// open-or-skip home this suite already imports). The zero-padding is what
// makes LEXICAL filename order == NUMERIC apply order.
//
// It is the SAME *regexp.Regexp the migrations suite's migrationName
// (orchestrator/migrations/apply_smoke_test.go) and the policylog suite's
// policylogMigrationName use, so the SEMANTICS pinned identically across the
// store & migrations suites by TestOrchPGMigrationName_Contract here and
// TestMigrationNamePattern_Contract there (the same accept/reject table)
// cannot diverge — there is exactly one literal left to edit.
var orchPGMigrationName = storetest.MigrationNamePattern

// orchPGMigrationsDir is the migrations directory relative to this package
// (orchestrator/internal/store → orchestrator/migrations).
const orchPGMigrationsDir = "../../migrations"

// TestPostgres_OpenAndMigrateRoundTrip is the DS_ORCH_PG_DSN-gated live store-open +
// migration smoke. It opens the live store the way controlplane.NewPostgresStore
// does, applies orchestrator/migrations/*.sql in lexical order, and round-trips a
// session record plus a couple of landed queries. SKIPS cleanly without a DSN, an
// unregistered driver, or an unreachable database (the deferred manual step).
func TestPostgres_OpenAndMigrateRoundTrip(t *testing.T) {
	repo, db := openOrchPostgresOrSkip(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 2: apply the migrations in apply.sh lexical order, re-runnably (a
	// schema_migrations ledger skips already-applied files — the same posture
	// apply.sh implements, so re-running this test over a populated DB is a no-op).
	applyOrchMigrations(ctx, t, db)

	// Step 2b: DRIFT GUARD — assert the FULL orchMigrationFiles() set landed in the
	// schema_migrations ledger. applyOrchMigrations records each file but never proves
	// the whole set is present; a silently renamed / dropped / unenumerated migration
	// would otherwise pass this test (the round-trip below only touches the tables the
	// landed migrations happen to create). This pins every migration basename into the
	// ledger so such drift fails fast on a live run (D6: the Postgres schema is the
	// control-plane state of record).
	assertAllOrchMigrationsRecorded(ctx, t, db)

	// Start the round-trip from a clean slate so it is independent of any prior
	// state the (possibly shared) target DB carries — this test owns its own
	// session_uuid / host_id space and removes its rows on cleanup, never
	// truncating the shared tables the DS_PG_DSN suites manage.
	const (
		sessUUID = "orch-open-conformance-sess-1"
		hostID   = "orch-open-conformance-host-a"
		hostIdx  = uint64(424242)
	)
	cleanupOrchRoundtrip(ctx, t, db, sessUUID)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanupOrchRoundtrip(c, t, db, sessUUID)
	})

	// Step 3a: CreateSession → GetSession round-trips the §5.6 record (the
	// SessionRef quartet, the default PENDING state, the seeded index epoch).
	in := newSession(sessUUID, hostID, hostIdx)
	in.IdentityRef, in.CARef = "orch-open-id-1", "orch-open-ca-1"
	created, err := repo.CreateSession(ctx, in)
	mustNoErr(t, err)
	if created.Ref != in.Ref {
		t.Fatalf("SessionRef quartet not round-tripped on open store: got %+v want %+v", created.Ref, in.Ref)
	}
	if created.State != SessionPending {
		t.Fatalf("new session state = %q, want PENDING", created.State)
	}
	if len(created.IndexHistory) != 1 || created.IndexHistory[0].HostID != hostID {
		t.Fatalf("create did not seed the index epoch history: %+v", created.IndexHistory)
	}

	got, err := repo.GetSession(ctx, sessUUID)
	mustNoErr(t, err)
	if got.Ref != in.Ref || got.IdentityRef != "orch-open-id-1" || got.CARef != "orch-open-ca-1" {
		t.Fatalf("GetSession did not read back the persisted record: %+v", got)
	}

	// Step 3b: an UpdateSession state transition (PENDING → CREATING) with a
	// policy-posture write — proves the update path's tx round-trip on the engine.
	creating := SessionCreating
	seq := int64(7)
	updated, err := repo.UpdateSession(ctx, sessUUID, SessionUpdate{State: &creating, PolicyAppliedSeq: &seq})
	mustNoErr(t, err)
	if updated.State != SessionCreating || updated.PolicyAppliedSeq != 7 {
		t.Fatalf("UpdateSession state/posture not persisted: %+v", updated)
	}

	// Step 3c: a ListSessions filter — the host-scoped read path over the live
	// engine (a landed query). The just-created session must surface under its host.
	byHost, err := repo.ListSessions(ctx, SessionFilter{HostID: hostID})
	mustNoErr(t, err)
	if !containsSessionUUID(byHost, sessUUID) {
		t.Fatalf("ListSessions(host=%q) did not return the created session: %+v", hostID, byHost)
	}

	// Step 3d: AppendPolicy → ListPolicy — the append-only policy log (D36 actor
	// attribution), exercising the bigserial seq assignment + the from-seq read on
	// the live engine. We read the head seq first so the assertion is independent
	// of any rows a shared DB already carries.
	head, err := repo.ListPolicy(ctx, 0, 0)
	mustNoErr(t, err)
	var fromSeq int64
	if n := len(head); n > 0 {
		fromSeq = head[n-1].Seq
	}
	appended, err := repo.AppendPolicy(ctx, PolicyLogRow{
		Kind:        PolicyKindAppend,
		Actor:       "orch-open-conformance",
		ContentHash: "sha256:orch-open-policy",
		Payload:     []byte(`{"orch-open":"smoke"}`),
		SessionUUID: sessUUID,
	})
	mustNoErr(t, err)
	if appended.Seq <= fromSeq {
		t.Fatalf("AppendPolicy did not advance the monotonic seq: got %d, head was %d", appended.Seq, fromSeq)
	}
	after, err := repo.ListPolicy(ctx, fromSeq, 0)
	mustNoErr(t, err)
	if !containsPolicySeq(after, appended.Seq) {
		t.Fatalf("ListPolicy(from=%d) did not return the appended row seq=%d: %+v", fromSeq, appended.Seq, after)
	}
}

// TestOrchMigrationFiles_EnumerationOrderAndNames is the SANDBOX-RUNNABLE
// enumeration guard over orchMigrationFiles — the apply-order contract proven WITHOUT a
// database. applyOrchMigrations / assertAllOrchMigrationsRecorded only run on the live
// (DS_ORCH_PG_DSN) path, so the on-disk migration SET's shape (non-empty, lexical==numeric
// apply order, NNNN_*.sql name convention) would otherwise be unchecked on the default
// `go test ./...` run. This test pins all three from disk (no DB, no driver, no skip):
//
//  1. NON-EMPTY: orchMigrationFiles must return at least one file (13 today). An empty
//     set is itself a regression — the live applyOrchMigrations would then apply nothing
//     and the round-trip would lean on an unmigrated schema.
//  2. ORDER (the load-bearing apply-order contract): the returned slice is in strict
//     lexical order (it is the order applyOrchMigrations Execs the files in), and — because
//     the zero-padded 4-digit prefix makes LEXICAL filename order == NUMERIC apply order —
//     the parsed NNNN prefixes are STRICTLY increasing. This is the property the comment
//     "the zero-padded prefix == apply order" asserts; a file whose padding broke (e.g. a
//     3-digit or 5-digit prefix, or a duplicate sequence number) would transpose apply
//     order silently, and that regresses HERE. (Order/strict-monotonic only — NOT a
//     contiguity/gap assert, since a dropped sequence number is a separate concern.)
//  3. NAME FORMAT: every returned name matches orchPGMigrationName — redundant by
//     construction (orchMigrationFiles filters on it) but pinned so a future relaxation of
//     the enumeration filter cannot let a non-conforming basename through unnoticed.
//
// It runs in the default test pass (no env, no DB), so the enumeration guard is the
// NON-VACUOUS part of this file's coverage. The optional negative control below
// (TestOrchMigrations_LiveReRunNoOp) is DS_ORCH_PG_DSN-gated and SKIPS in the sandbox.
func TestOrchMigrationFiles_EnumerationOrderAndNames(t *testing.T) {
	files := orchMigrationFiles(t) // t.Fatalf's on an unreadable dir or an empty set

	// 1. NON-EMPTY. orchMigrationFiles already t.Fatalf's on len==0, but assert it here
	// too so this test's intent is explicit and a future loosening of that helper is caught.
	if len(files) == 0 {
		t.Fatalf("orchMigrationFiles returned no migrations; expected the NNNN_*.sql set (13 today)")
	}

	// 2. ORDER + 3. NAME FORMAT, in one pass over the returned slice.
	var prevSeq = -1
	var prevName string
	for i, name := range files {
		// 3. NAME FORMAT: every name matches the apply-order convention.
		m := orchPGMigrationName.FindStringSubmatch(name)
		if m == nil {
			t.Fatalf("migration[%d] %q does not match the NNNN_*.sql convention %q", i, name, orchPGMigrationName.String())
		}

		// 2a. LEXICAL order: the slice must be sorted ascending by filename (the order
		// applyOrchMigrations Execs the files in). Compare each name to its predecessor.
		if prevName != "" && !(prevName < name) {
			t.Fatalf("migration order is not strictly lexical-ascending: %q (index %d) does not sort after %q", name, i, prevName)
		}

		// 2b. NUMERIC == LEXICAL: the zero-padded 4-digit prefix parses to a number that is
		// STRICTLY greater than the previous one. With consistent zero-padding this is
		// implied by the lexical order, and asserting both pins exactly that equivalence:
		// a prefix whose width drifted (so lexical and numeric order diverge) regresses here.
		seq, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("migration[%d] %q: parse NNNN prefix %q: %v", i, name, m[1], err)
		}
		if seq <= prevSeq {
			t.Fatalf("migration[%d] %q: NNNN prefix %d is not strictly greater than the previous %d — lexical order and numeric apply order diverged (zero-padding drift or a duplicate sequence)", i, name, seq, prevSeq)
		}

		prevSeq = seq
		prevName = name
	}

	// Belt-and-suspenders: the slice equals its own sorted copy (the lexical-order claim,
	// stated once over the whole set so a single mis-ordered pair is unmistakable).
	sortedCopy := append([]string(nil), files...)
	sort.Strings(sortedCopy)
	for i := range files {
		if files[i] != sortedCopy[i] {
			t.Fatalf("orchMigrationFiles is not in lexical order: index %d is %q, sorted want %q (full=%v)", i, files[i], sortedCopy[i], files)
		}
	}
}

// TestOrchMigrations_LiveReRunNoOp is the OPTIONAL DS_ORCH_PG_DSN-gated negative control:
// applying the migrations twice over the SAME live database is a safe no-op (the
// schema_migrations ledger skips already-applied files — the apply.sh re-run posture). It
// SKIPS cleanly in the sandbox (no DSN), so the enumeration guard above is the non-vacuous
// part; on a live run it proves the second applyOrchMigrations pass records NO new ledger
// rows. This complements TestPostgres_OpenAndMigrateRoundTrip (which applies once) without
// touching its state: it opens its OWN pool and never round-trips a session record.
func TestOrchMigrations_LiveReRunNoOp(t *testing.T) {
	_, db := openOrchPostgresOrSkip(t) // SKIPS without DS_ORCH_PG_DSN / a reachable DB

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First pass brings the schema (and the ledger) to current. Count the recorded set.
	applyOrchMigrations(ctx, t, db)
	first := countRecordedOrchMigrations(ctx, t, db)

	// Second pass must be a no-op: every file is already in the ledger, so nothing new is
	// applied or recorded. The recorded count is unchanged.
	applyOrchMigrations(ctx, t, db)
	second := countRecordedOrchMigrations(ctx, t, db)

	if second != first {
		t.Fatalf("re-running applyOrchMigrations changed the schema_migrations count: first=%d second=%d — the ledger re-run no-op posture (apply.sh) regressed", first, second)
	}
	// The recorded set must cover the full enumerated set after the re-run.
	if want := len(orchMigrationFiles(t)); first < want {
		t.Fatalf("schema_migrations recorded %d versions, want at least the %d enumerated migrations", first, want)
	}
}

// countRecordedOrchMigrations returns how many rows the schema_migrations ledger holds.
// Used by the live re-run no-op control to prove a second apply records nothing new.
func countRecordedOrchMigrations(ctx context.Context, t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count schema_migrations ledger rows: %v", err)
	}
	return n
}

// openOrchPostgresOrSkip opens the live store the SAME way
// controlplane.NewPostgresStore does — sql.Open(driver, dsn) then store.NewPostgres
// — and returns both the typed Repository and the raw *sql.DB (the test needs the
// pool to apply migrations / clean up its own rows). It reads DS_ORCH_PG_DSN and
// DS_ORCH_PG_DRIVER (default "postgres", the conventional driver name the operator
// registers under, D33), distinct from the DS_PG_DSN suites so the two never share a
// truncate lifecycle. It SKIPS — never fails — without the env, an unregistered
// driver, or an unreachable database, so the default `go test ./...` run is
// unaffected and a live run stays a deferred manual step.
func openOrchPostgresOrSkip(t *testing.T) (Repository, *sql.DB) {
	t.Helper()
	// The sql.Open + ping + skip dance is single-sourced through storetest.OpenOrSkip
	// (its SkipMessages reproduce this caller's exact skip wording byte-for-byte). This
	// function keeps its OWN env var (DS_ORCH_PG_DSN), distinct from the DS_PG_DSN
	// suites so the two never share a truncate lifecycle, and its OWN post-open step:
	// NewPostgres wraps the pool as the *store.Postgres Repository — the second of the
	// two calls controlplane.NewPostgresStore makes (kept in-package because store
	// cannot import controlplane without a cycle; sql.Open inside OpenOrSkip validates
	// the driver registration + DSN shape but does NOT dial).
	db := storetest.OpenOrSkip(t, "DS_ORCH_PG_DSN", "DS_ORCH_PG_DRIVER", storetest.SkipMessages{
		Unset:   "DS_ORCH_PG_DSN not set: skipping live store-open + migration conformance (deferred manual step)",
		OpenErr: "sql.Open(%q): %v — register a Postgres driver at the binary boundary (DS_ORCH_PG_DRIVER, D33) to run this",
		PingErr: "ping %s: %v — Postgres unreachable; deferred manual step (set DS_ORCH_PG_DSN to a reachable DB)",
	})
	return NewPostgres(db), db
}

// applyOrchMigrations applies orchestrator/migrations/NNNN_*.sql in lexical order,
// re-runnably: it records a schema_migrations ledger and SKIPS files already present
// (the apply.sh re-run posture), so applying the set to a populated database is a
// safe no-op and a fresh database gets the full schema in order. Each file is sent
// as a single Exec inside its own transaction (apply.sh's `-1` per-file
// single-transaction posture); the ledger insert rides the same tx so a half-applied
// file never records as done. A failure here is a real conformance failure (the open
// store could not take the schema), not a skip.
func applyOrchMigrations(ctx context.Context, t *testing.T, db *sql.DB) {
	t.Helper()

	if _, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());`,
	); err != nil {
		t.Fatalf("create schema_migrations ledger: %v", err)
	}

	for _, name := range orchMigrationFiles(t) {
		version := name[:len(name)-len(".sql")] // basename without .sql, matching apply.sh
		var applied bool
		err := db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version,
		).Scan(&applied)
		if err != nil {
			t.Fatalf("check schema_migrations for %s: %v", version, err)
		}
		if applied {
			continue // already applied: the re-run no-op posture
		}

		ddl, err := os.ReadFile(filepath.Join(orchPGMigrationsDir, name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin tx for migration %s: %v", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(ddl)); err != nil {
			_ = tx.Rollback()
			t.Fatalf("apply migration %s: %v", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO schema_migrations (version) VALUES ($1)`, version,
		); err != nil {
			_ = tx.Rollback()
			t.Fatalf("record migration %s in ledger: %v", version, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit migration %s: %v", name, err)
		}
	}
}

// assertAllOrchMigrationsRecorded is the migration-drift guard: it reads back the
// schema_migrations ledger after applyOrchMigrations and asserts EVERY orchMigrationFiles()
// basename (the .sql stripped, exactly the `version` applyOrchMigrations records) is
// present. applyOrchMigrations applies + records each file it enumerates, but nothing
// proves the enumerated SET fully landed — a migration that is renamed off the NNNN_*.sql
// convention (so orchMigrationFiles no longer sees it) or otherwise dropped would silently
// shrink the applied set, and the round-trip only exercises whatever tables the surviving
// migrations create. This assertion fails fast on that drift: it compares the on-disk
// migration set against the ledger and names any basename missing from schema_migrations.
// It runs only on the live (DS_ORCH_PG_DSN) path — the whole test skips without a DB (D50).
func assertAllOrchMigrationsRecorded(ctx context.Context, t *testing.T, db *sql.DB) {
	t.Helper()

	// The ledger as the database holds it: the set of recorded `version` strings.
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		t.Fatalf("read schema_migrations ledger for drift guard: %v", err)
	}
	defer rows.Close()
	recorded := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan schema_migrations version: %v", err)
		}
		recorded[v] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate schema_migrations rows: %v", err)
	}

	// Every enumerated migration's basename (== the `version` applyOrchMigrations records)
	// must be in the ledger. A missing one is drift: a renamed / dropped / unenumerated
	// migration the live open store did not take.
	var missing []string
	for _, name := range orchMigrationFiles(t) {
		version := name[:len(name)-len(".sql")] // basename without .sql, matching applyOrchMigrations
		if !recorded[version] {
			missing = append(missing, version)
		}
	}
	if len(missing) != 0 {
		t.Fatalf("schema_migrations is missing %d migration(s) %v — the full orchMigrationFiles() set did not land in the ledger (a renamed/dropped/unenumerated migration); recorded versions = %v", len(missing), missing, recorded)
	}
}

// orchMigrationFiles returns the NNNN_*.sql migration basenames in lexical order
// (== apply order, the zero-padded prefix). It reads the directory by FILENAME (it
// imports no .sql and edits nothing), the same enumeration apply.sh and the
// migrations package's apply_smoke_test.go use.
func orchMigrationFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(orchPGMigrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir %s: %v", orchPGMigrationsDir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if orchPGMigrationName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatalf("no NNNN_*.sql migrations found in %s", orchPGMigrationsDir)
	}
	sort.Strings(names) // lexical order == apply order
	return names
}

// cleanupOrchRoundtrip removes this test's own rows (its session and the policy_log
// rows attributed to it) so the round-trip is independent of prior state and leaves
// the target DB as it found it. It never truncates the shared tables (the DS_PG_DSN
// suites own that lifecycle); it deletes only the keys this test creates. Best
// effort: a missing schema or row is not an error here.
func cleanupOrchRoundtrip(ctx context.Context, t *testing.T, db *sql.DB, sessUUID string) {
	t.Helper()
	// Order matters for the FK edges: epochs and policy_log reference the session.
	stmts := []string{
		`DELETE FROM policy_log WHERE session_uuid = $1`,
		`DELETE FROM session_index_epochs WHERE session_uuid = $1`,
		`DELETE FROM sessions WHERE session_uuid = $1`,
	}
	for _, s := range stmts {
		// Ignore "relation does not exist" and similar: cleanup runs before the
		// migrations on first entry, so the tables may not exist yet — that is fine.
		_, _ = db.ExecContext(ctx, s, sessUUID)
	}
}

// containsSessionUUID reports whether ss contains a session with the given UUID.
func containsSessionUUID(ss []Session, uuid string) bool {
	for _, s := range ss {
		if s.Ref.SessionUUID == uuid {
			return true
		}
	}
	return false
}

// containsPolicySeq reports whether rows contains a policy row with the given seq.
func containsPolicySeq(rows []PolicyLogRow, seq int64) bool {
	for _, r := range rows {
		if r.Seq == seq {
			return true
		}
	}
	return false
}

// TestOrchPGMigrationName_Contract pins the accept/reject SEMANTICS of
// storetest.MigrationNamePattern identically to the migrations suite's
// TestMigrationNamePattern_Contract (same table) — both now assert the
// identical *regexp.Regexp value, so there is nothing left to diverge. No DB,
// no env, no skip — it runs in the default `go test ./...` pass.
func TestOrchPGMigrationName_Contract(t *testing.T) {
	// ACCEPT: the NNNN_lower_snake.sql convention (zero-padded 4-digit prefix).
	for _, name := range []string{
		"0001_init.sql",
		"0042_add_principal_roles.sql",
		"9999_z.sql",
	} {
		if !orchPGMigrationName.MatchString(name) {
			t.Errorf("migration-name pattern %q must ACCEPT %q (the NNNN_name.sql convention)", orchPGMigrationName.String(), name)
		}
	}
	// REJECT: every off-convention shape that would silently break LEXICAL==NUMERIC
	// apply order or admit a stray file.
	for _, name := range []string{
		"001_init.sql",      // 3-digit prefix (padding drift)
		"00001_init.sql",    // 5-digit prefix (padding drift)
		"0001init.sql",      // missing the underscore separator
		"0001_Init.sql",     // uppercase in the name (the class is [a-z0-9_])
		"0001_init.txt",     // wrong extension
		"0001_.sql",         // empty name segment
		"_0001_init.sql",    // leading underscore (no NNNN prefix)
		"0001_init.sql.bak", // trailing suffix past .sql
	} {
		if orchPGMigrationName.MatchString(name) {
			t.Errorf("migration-name pattern %q must REJECT %q", orchPGMigrationName.String(), name)
		}
	}
}

// --- synthetic-driver skip-arm pins for openOrchPostgresOrSkip -----------------
//
// The two tests below drive openOrchPostgresOrSkip — this package's real open-or-skip
// wrapper around storetest.OpenOrSkip — through its sql.Open-error (OpenErr) and
// PingContext-error (PingErr) skip arms END TO END, using SYNTHETIC database/sql
// drivers registered in this test binary (D50: no live engine; the drivers dial
// nothing and return canned errors). Until now NO test reached those arms: with no
// Postgres driver registered, openOrchPostgresOrSkip's prior unit coverage only
// exercised the unset-DSN skip. These pin that each error PATH SKIPS — never fails,
// never returns a half-open Repository — so a regression that turned either arm into a
// t.Fatal/Error, or that let the wrapper hand back a pool on a dial failure, regresses
// here. They set the wrapper's OWN env vars (DS_ORCH_PG_DSN / DS_ORCH_PG_DRIVER) via
// t.Setenv (isolated + restored per test, never colliding with a live operator DSN),
// so they exercise openOrchPostgresOrSkip itself, not OpenOrSkip in isolation.

const (
	orchOpenErrDriverName = "store_orch_selftest_open_err"
	orchPingErrDriverName = "store_orch_selftest_ping_err"
)

// orchOpenErrDriver makes sql.Open return an error: it implements driver.DriverContext,
// whose OpenConnector sql.Open calls eagerly, and errors there — the only way a plain
// sql.Open (which otherwise defers dialing) surfaces an error to the OpenErr arm.
type orchOpenErrDriver struct{}

func (orchOpenErrDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("store selftest: orchOpenErrDriver.Open must not be called")
}

func (orchOpenErrDriver) OpenConnector(string) (driver.Connector, error) {
	return nil, errors.New("store selftest: synthetic OpenConnector refused")
}

// orchPingErrDriver makes sql.Open succeed (it defers dialing) but the first real
// connection — forced by db.PingContext — fail, driving the PingErr arm.
type orchPingErrDriver struct{}

func (orchPingErrDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("store selftest: synthetic connect refused (unreachable)")
}

func init() {
	// Registered once per test binary (init, not test body) so `go test -count=N`
	// never re-registers a name (sql.Register panics on a duplicate).
	sql.Register(orchOpenErrDriverName, orchOpenErrDriver{})
	sql.Register(orchPingErrDriverName, orchPingErrDriver{})
}

// runOpenOrchOrSkipInSubtest runs openOrchPostgresOrSkip against the synthetic driver
// in an inner sub-test and reports whether that sub-test SKIPPED and whether it FAILED.
// OpenOrSkip's t.Skip* calls runtime.Goexit, so the terminal state is read from a
// deferred closure on the inner *testing.T.
func runOpenOrchOrSkipInSubtest(t *testing.T, name, driverName string) (skipped, failed bool) {
	t.Helper()
	t.Setenv("DS_ORCH_PG_DSN", "synthetic://"+name) // non-empty: passes the unset-DSN gate
	t.Setenv("DS_ORCH_PG_DRIVER", driverName)       // resolves to the synthetic driver
	t.Run(name, func(st *testing.T) {
		defer func() {
			skipped = st.Skipped()
			failed = st.Failed()
		}()
		_, _ = openOrchPostgresOrSkip(st)
		st.Fatalf("openOrchPostgresOrSkip returned a store instead of skipping on a synthetic %s failure", name)
	})
	return skipped, failed
}

func TestOpenOrchPostgresOrSkip_SkipsOnOpenErr(t *testing.T) {
	skipped, failed := runOpenOrchOrSkipInSubtest(t, "open-err", orchOpenErrDriverName)
	if !skipped {
		t.Errorf("openOrchPostgresOrSkip did not skip on an sql.Open error; the OpenErr arm must skip, never fall through to a returned store")
	}
	if failed {
		t.Errorf("openOrchPostgresOrSkip marked the sub-test FAILED on an sql.Open error; the OpenErr arm must skip, never fail")
	}
}

func TestOpenOrchPostgresOrSkip_SkipsOnPingErr(t *testing.T) {
	skipped, failed := runOpenOrchOrSkipInSubtest(t, "ping-err", orchPingErrDriverName)
	if !skipped {
		t.Errorf("openOrchPostgresOrSkip did not skip on a PingContext error; the PingErr arm must skip, never fall through to a returned store")
	}
	if failed {
		t.Errorf("openOrchPostgresOrSkip marked the sub-test FAILED on a PingContext error; the PingErr arm must skip, never fail")
	}
}
