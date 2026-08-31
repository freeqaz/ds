package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// ContextRepoFactory builds a fresh empty ContextStore using the supplied clock,
// mirroring RepoFactory for the §5.6 Repository conformance suite.
type ContextRepoFactory func(now func() time.Time) ContextStore

// RunContextConformance runs the shared prompt + session-context suite against a
// factory. Both the in-memory impl (below) and the env-gated Postgres impl
// (TestPostgresContext_Conformance) drive these IDENTICAL assertions, the D33
// equivalence pin for the doc 02 §8 store.
func RunContextConformance(t *testing.T, newStore ContextRepoFactory) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(*testing.T, ContextRepoFactory)
	}{
		{"PromptRecordedQueryableAttributed", testPromptRoundTrip},
		{"PromptOrderedBySeq", testPromptOrdering},
		{"PromptReputIsFullReplace", testPromptReput},
		{"PromptRequiresSessionAttribution", testPromptAttribution},
		{"OrphanWriteRejected", testOrphanWriteRejected},
		{"ContextSaveReplacesPreservingBirth", testContextReplace},
		{"ContextQueryableByKind", testContextQueryable},
		{"ContextRequiresSessionAndKind", testContextValidation},
		{"NotFound", testContextNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, newStore) })
	}
}

var ctxBaseTime = time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC)

func testPromptRoundTrip(t *testing.T, newStore ContextRepoFactory) {
	store := newStore(fixedClock(ctxBaseTime))
	ctx := context.Background()
	out, err := store.PutPrompt(ctx, Prompt{
		ID: "pr-1", SessionUUID: "sess-a", Label: "reuse-me", Body: []byte("build the thing"),
	})
	mustNoErr(t, err)
	if out.CreatedAt.IsZero() {
		t.Fatalf("CreatedAt not stamped")
	}
	if out.Role != "user" {
		t.Fatalf("empty role should default to user, got %q", out.Role)
	}
	got, err := store.GetPrompt(ctx, "pr-1")
	mustNoErr(t, err)
	if got.SessionUUID != "sess-a" || got.Label != "reuse-me" || string(got.Body) != "build the thing" {
		t.Fatalf("prompt not round-tripped/attributed: %+v", got)
	}
	// Queryable by its attributed session.
	list, err := store.ListPrompts(ctx, "sess-a")
	mustNoErr(t, err)
	if len(list) != 1 || list[0].ID != "pr-1" {
		t.Fatalf("ListPrompts not attributed: %+v", list)
	}
	// A different session sees none.
	other, err := store.ListPrompts(ctx, "sess-b")
	mustNoErr(t, err)
	if len(other) != 0 {
		t.Fatalf("prompt leaked across sessions: %+v", other)
	}
}

func testPromptOrdering(t *testing.T, newStore ContextRepoFactory) {
	store := newStore(fixedClock(ctxBaseTime))
	ctx := context.Background()
	mustPutPrompt(t, store, Prompt{ID: "pr-c", SessionUUID: "s", Seq: 3})
	mustPutPrompt(t, store, Prompt{ID: "pr-a", SessionUUID: "s", Seq: 1})
	mustPutPrompt(t, store, Prompt{ID: "pr-b", SessionUUID: "s", Seq: 2})
	list, err := store.ListPrompts(ctx, "s")
	mustNoErr(t, err)
	if len(list) != 3 {
		t.Fatalf("want 3 prompts, got %d", len(list))
	}
	for i, want := range []int64{1, 2, 3} {
		if list[i].Seq != want {
			t.Fatalf("prompts not seq-ordered: position %d has seq %d, want %d", i, list[i].Seq, want)
		}
	}
}

// testPromptReput pins the documented full-replace semantics of PutPrompt across
// BOTH impls: re-putting an existing id with a fresh (zero) CreatedAt replaces
// the whole row, CreatedAt included, and the persisted row reflects the replace.
// This is the equivalence guard that catches the Postgres upsert silently
// keeping a stale created_at (the DO UPDATE must carry created_at), which the
// round-trip and ordering cases — each putting distinct ids — never exercise.
func testPromptReput(t *testing.T, newStore ContextRepoFactory) {
	t0 := ctxBaseTime
	t1 := ctxBaseTime.Add(time.Hour)
	clock := t0
	store := newStore(func() time.Time { return clock })
	ctx := context.Background()

	first, err := store.PutPrompt(ctx, Prompt{ID: "pr-r", SessionUUID: "s", Body: []byte("v1")})
	mustNoErr(t, err)
	if !first.CreatedAt.Equal(t0) {
		t.Fatalf("first put stamps t0, got %v", first.CreatedAt)
	}
	// Re-put the same id at t1 with a zero CreatedAt: a full replace restamps it.
	clock = t1
	second, err := store.PutPrompt(ctx, Prompt{ID: "pr-r", SessionUUID: "s", Body: []byte("v2")})
	mustNoErr(t, err)
	if !second.CreatedAt.Equal(t1) {
		t.Fatalf("re-put is a full replace: CreatedAt should restamp to %v, got %v", t1, second.CreatedAt)
	}
	// The persisted row matches the returned value (no stale created_at left behind).
	got, err := store.GetPrompt(ctx, "pr-r")
	mustNoErr(t, err)
	if !got.CreatedAt.Equal(t1) {
		t.Fatalf("persisted CreatedAt diverged from replace: got %v, want %v", got.CreatedAt, t1)
	}
	if string(got.Body) != "v2" {
		t.Fatalf("re-put body should win: got %q, want v2", got.Body)
	}
	// Still one row for the session (replace, not insert).
	list, err := store.ListPrompts(ctx, "s")
	mustNoErr(t, err)
	if len(list) != 1 {
		t.Fatalf("re-put should keep one row, got %d", len(list))
	}
}

func testPromptAttribution(t *testing.T, newStore ContextRepoFactory) {
	store := newStore(fixedClock(ctxBaseTime))
	ctx := context.Background()
	if _, err := store.PutPrompt(ctx, Prompt{ID: "pr-x"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("prompt without session_uuid: got %v, want ErrInvalid", err)
	}
	if _, err := store.PutPrompt(ctx, Prompt{SessionUUID: "s"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("prompt without id: got %v, want ErrInvalid", err)
	}
	if _, err := store.ListPrompts(ctx, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ListPrompts without session: got %v, want ErrInvalid", err)
	}
}

// testOrphanWriteRejected is the §5.6/D33 orphan-write equivalence pin: a
// PutPrompt / PutContext attributed to a session that does NOT exist is rejected
// with ErrInvalid by BOTH impls — the in-memory MemoryContext.requireSession
// guard and the live REFERENCES sessions(session_uuid) FK
// (0008_session_context.sql, mapped through mapContextErr) reach the identical
// verdict, so a caller cannot tell the impls apart (doc 02 §8: prompts and
// context exist only for real sessions). The first live pg-conformance run
// (2026-06-13) exposed this gap — live REJECTED, in-memory ACCEPTED — which this
// case now pins shut for both. The valid-session put-cases above prove the guard
// admits real sessions; this one proves it rejects orphans.
func testOrphanWriteRejected(t *testing.T, newStore ContextRepoFactory) {
	store := newStore(fixedClock(ctxBaseTime))
	ctx := context.Background()

	// orphan names a session NOT in the provisioned set, so it has no sessions row
	// in either impl — the orphan-write condition.
	const orphan = "ghost-session"
	for _, provisioned := range contextConformanceSessions {
		if orphan == provisioned {
			t.Fatalf("test bug: %q must be an UNprovisioned session for the orphan case", orphan)
		}
	}

	// An orphan PutPrompt (non-empty session_uuid, no existing session) is rejected.
	if _, err := store.PutPrompt(ctx, Prompt{ID: "pr-orphan", SessionUUID: orphan, Body: []byte("x")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("orphan PutPrompt: got %v, want ErrInvalid (the FK-rejection parity)", err)
	}
	// It left no row behind (the write was refused, not partially applied).
	if _, err := store.GetPrompt(ctx, "pr-orphan"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected orphan prompt should not have persisted: got %v, want ErrNotFound", err)
	}

	// An orphan PutContext is rejected the same way.
	if _, err := store.PutContext(ctx, SessionContext{SessionUUID: orphan, Kind: "init-script", Body: []byte("x")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("orphan PutContext: got %v, want ErrInvalid (the FK-rejection parity)", err)
	}
	if _, err := store.GetContext(ctx, orphan, "init-script"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected orphan context should not have persisted: got %v, want ErrNotFound", err)
	}

	// A write attributed to a REAL (provisioned) session still succeeds — the guard
	// rejects only orphans, never real attribution.
	if _, err := store.PutPrompt(ctx, Prompt{ID: "pr-real", SessionUUID: contextConformanceSessions[0], Body: []byte("ok")}); err != nil {
		t.Fatalf("put to a provisioned session should succeed, got %v", err)
	}
}

func testContextReplace(t *testing.T, newStore ContextRepoFactory) {
	// First save at t0, replace at t1: CreatedAt is preserved, UpdatedAt advances,
	// and the body is the latest (save = replace, doc 02 §8).
	t0 := ctxBaseTime
	t1 := ctxBaseTime.Add(time.Hour)
	clock := t0
	store := newStore(func() time.Time { return clock })
	ctx := context.Background()

	first, err := store.PutContext(ctx, SessionContext{SessionUUID: "s", Kind: "init-script", Body: []byte("v1")})
	mustNoErr(t, err)
	if !first.CreatedAt.Equal(t0) || !first.UpdatedAt.Equal(t0) {
		t.Fatalf("first save stamps: %+v", first)
	}
	clock = t1
	second, err := store.PutContext(ctx, SessionContext{SessionUUID: "s", Kind: "init-script", Body: []byte("v2")})
	mustNoErr(t, err)
	if !second.CreatedAt.Equal(t0) {
		t.Fatalf("replace should preserve CreatedAt %v, got %v", t0, second.CreatedAt)
	}
	if !second.UpdatedAt.Equal(t1) {
		t.Fatalf("replace should advance UpdatedAt to %v, got %v", t1, second.UpdatedAt)
	}
	got, err := store.GetContext(ctx, "s", "init-script")
	mustNoErr(t, err)
	if string(got.Body) != "v2" {
		t.Fatalf("replace should win: got %q, want v2", got.Body)
	}
	// One row per (session, kind): the replace did not add a second row.
	list, err := store.ListContext(ctx, "s")
	mustNoErr(t, err)
	if len(list) != 1 {
		t.Fatalf("replace should keep one row per kind, got %d", len(list))
	}
}

func testContextQueryable(t *testing.T, newStore ContextRepoFactory) {
	store := newStore(fixedClock(ctxBaseTime))
	ctx := context.Background()
	mustPutContext(t, store, SessionContext{SessionUUID: "s", Kind: "task", Body: []byte("t")})
	mustPutContext(t, store, SessionContext{SessionUUID: "s", Kind: "notes", Body: []byte("n")})
	mustPutContext(t, store, SessionContext{SessionUUID: "other", Kind: "task", Body: []byte("x")})

	// Per-session view is kind-ordered and session-attributed.
	list, err := store.ListContext(ctx, "s")
	mustNoErr(t, err)
	if len(list) != 2 || list[0].Kind != "notes" || list[1].Kind != "task" {
		t.Fatalf("context not queryable/attributed/ordered: %+v", list)
	}
	// Query a single facet.
	got, err := store.GetContext(ctx, "s", "task")
	mustNoErr(t, err)
	if string(got.Body) != "t" {
		t.Fatalf("query by kind failed: %+v", got)
	}
}

func testContextValidation(t *testing.T, newStore ContextRepoFactory) {
	store := newStore(fixedClock(ctxBaseTime))
	ctx := context.Background()
	if _, err := store.PutContext(ctx, SessionContext{Kind: "k"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("context without session: got %v, want ErrInvalid", err)
	}
	if _, err := store.PutContext(ctx, SessionContext{SessionUUID: "s"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("context without kind: got %v, want ErrInvalid", err)
	}
	if _, err := store.ListContext(ctx, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ListContext without session: got %v, want ErrInvalid", err)
	}
}

func testContextNotFound(t *testing.T, newStore ContextRepoFactory) {
	store := newStore(fixedClock(ctxBaseTime))
	ctx := context.Background()
	if _, err := store.GetPrompt(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetPrompt miss: got %v, want ErrNotFound", err)
	}
	if _, err := store.GetContext(ctx, "s", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetContext miss: got %v, want ErrNotFound", err)
	}
}

// --- the in-memory impl runs the shared suite (the reference impl) ---

func TestMemoryContext_Conformance(t *testing.T) {
	RunContextConformance(t, func(now func() time.Time) ContextStore {
		// Provision the referenced sessions UNIFORMLY with the live factory: the
		// in-memory ContextStore now enforces the §5.6/D33 orphan-write guard
		// (REFERENCES sessions(session_uuid)), so it must be wired to a session set
		// that contains exactly the sessions the put-cases attribute to — the same
		// rows provisionContextSessions inserts on the live side. The aggregate
		// in-memory Repository (Memory) owns the session set and hands out the
		// attribution-enforcing ContextStore.
		mem := NewMemoryClock(now)
		provisionMemoryContextSessions(t, mem, now)
		return mem.ContextStore()
	})
}

// provisionMemoryContextSessions creates the contextConformanceSessions rows in
// the in-memory Repository so the in-memory ContextStore's orphan-write guard
// admits the suite's put-cases — the in-memory mirror of provisionContextSessions
// on the live side. Provisioning is UNIFORM across both impls (the parity
// contract): the same session UUIDs exist for both before any prompt/context put.
func provisionMemoryContextSessions(t *testing.T, mem *Memory, now func() time.Time) {
	t.Helper()
	ctx := context.Background()
	for i, uuid := range contextConformanceSessions {
		if _, err := mem.CreateSession(ctx, newSession(uuid, "ctx-conf-host", uint64(9000+i))); err != nil {
			t.Fatalf("provision session %q for the in-memory context guard: %v", uuid, err)
		}
	}
}

// --- the database/sql impl runs the SAME suite, env-gated behind DS_PG_DSN ---

// TestPostgresContext_Conformance is a DEFERRED MANUAL STEP, skipped without
// DS_PG_DSN (never run in the sandbox), driver-agnostic so the module stays
// stdlib-only. The target database must already have
// orchestrator/migrations/*.sql applied (incl. 0008_session_context.sql).
func TestPostgresContext_Conformance(t *testing.T) {
	// The sql.Open + 5s-ping + skip dance is single-sourced through storetest.OpenOrSkip
	// (its SkipMessages reproduce this test's exact skip wording byte-for-byte, including
	// the "context conformance" Unset phrasing): this caller keeps its OWN env var
	// (DS_PG_DSN / DS_PG_DRIVER) and its OWN post-open steps — the per-case
	// truncateContext + provisionContextSessions + NewPostgresContextClock factory below.
	db := storetest.OpenOrSkip(t, "DS_PG_DSN", "DS_PG_DRIVER", storetest.SkipMessages{
		Unset:   "DS_PG_DSN not set: skipping live-Postgres context conformance (deferred manual step)",
		OpenErr: "sql.Open(%q): %v — register a Postgres driver and apply migrations to run this",
		PingErr: "ping %s: %v — Postgres unreachable; deferred manual step",
	})

	RunContextConformance(t, func(now func() time.Time) ContextStore {
		truncateContext(t, db)
		provisionContextSessions(t, db)
		return NewPostgresContextClock(db, now)
	})
}

// contextConformanceSessions are the session UUIDs the shared suite attributes
// prompts and context rows to. The live schema (0008_session_context.sql)
// carries REFERENCES sessions(session_uuid) on both tables — context and
// prompts exist only for real sessions — so the live factory provisions
// exactly these rows after each truncate (the first live pg-conformance run,
// 2026-06-13, failed on this FK; the in-memory impl does not enforce the
// reference, a parity gap routed to the orchestrator workstream via taskdb).
var contextConformanceSessions = []string{"s", "sess-a", "other"}

// provisionContextSessions inserts the minimal session rows the FK edges
// require. Attribution fields beyond the SessionRef quartet ride defaults.
func provisionContextSessions(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i, uuid := range contextConformanceSessions {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO sessions (session_uuid, host_id, host_session_index, tap_name, created_at, updated_at)
			 VALUES ($1, 'ctx-conf-host', $2, $3, now(), now())
			 ON CONFLICT (session_uuid) DO NOTHING`,
			uuid, int64(9000+i), fmt.Sprintf("dstap-%d", 9000+i)); err != nil {
			t.Fatalf("provision session %q for the context FK edges: %v", uuid, err)
		}
	}
}

// truncateContext resets the doc 02 §8 tables before each sub-case so the shared
// factory hands out an empty store, the in-memory parity contract. It does NOT
// touch the §5.6 tables (the Repository suite's truncateAll owns those).
func truncateContext(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	const stmt = `TRUNCATE prompts, session_context`
	if _, err := db.ExecContext(ctx, stmt); err != nil {
		t.Fatalf("truncate context tables: %v", err)
	}
}

// --- mapContextErr FK-detection coupling guard (PART B) ---

// TestSingleFKPerContextTable pins the assumption mapContextErr's 23503→ErrInvalid
// mapping depends on: 0008_session_context.sql carries EXACTLY ONE foreign key per
// table (session_uuid REFERENCES sessions on both prompts and session_context), so
// a foreign-key violation on a prompts / session_context write is UNAMBIGUOUSLY the
// attribution-orphan FK and mapping it to the attribution ErrInvalid is exact.
//
// This is the option-(b) guard for the doc 02 §8 store: rather than re-pinning
// detection to the (auto-generated) constraint NAME today, it asserts the
// single-FK-per-table invariant and FAILS LOUDLY the day a second FK is introduced
// on either table — that is the moment mapContextErr would start silently
// misclassifying a DIFFERENT integrity failure (a label-catalog ref, a
// kind-vocabulary ref) as the attribution ErrInvalid, so the failure forces the
// detection to be re-pinned to the constraint name in lockstep before the new FK
// ships. It is stdlib-only and driver-agnostic (it reads the migration DDL, not a
// live engine), so it runs in the sandbox like any unit test.
func TestSingleFKPerContextTable(t *testing.T) {
	const migration = "../../migrations/0008_session_context.sql"
	src, err := os.ReadFile(migration)
	if err != nil {
		t.Fatalf("read %s: %v", migration, err)
	}
	for _, table := range []string{"prompts", "session_context"} {
		body, ok := createTableBody(string(src), table)
		if !ok {
			t.Fatalf("no CREATE TABLE %s block found in %s", table, migration)
		}
		// Count REFERENCES (the inline-FK syntax this migration uses) plus any
		// explicit FOREIGN KEY clause, so the guard catches BOTH spellings of a
		// future second FK.
		n := strings.Count(body, "REFERENCES") + strings.Count(body, "FOREIGN KEY")
		if n != 1 {
			t.Fatalf("table %s declares %d foreign keys, want exactly 1: mapContextErr maps ANY 23503 on this "+
				"table to the attribution ErrInvalid, which is only correct while the lone FK is "+
				"session_uuid REFERENCES sessions. A second FK landed — re-pin mapContextErr to the "+
				"session_uuid constraint NAME before shipping it, or this orphan-attribution sentinel will "+
				"mask the new FK's violation.\nblock:\n%s", table, n, body)
		}
	}
}

// createTableBody returns the parenthesized body of the `CREATE TABLE <table> (...)`
// statement in src (the text between the opening `(` after the table name and its
// matching close paren), and whether it was found. It is a small, dependency-free
// brace-matcher sufficient for the migration DDL the guard inspects.
func createTableBody(src, table string) (string, bool) {
	head := "CREATE TABLE " + table
	i := strings.Index(src, head)
	if i < 0 {
		return "", false
	}
	open := strings.IndexByte(src[i:], '(')
	if open < 0 {
		return "", false
	}
	open += i
	depth := 0
	for j := open; j < len(src); j++ {
		switch src[j] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return src[open+1 : j], true
			}
		}
	}
	return "", false
}

// --- test helpers ---

func mustPutPrompt(t *testing.T, store ContextStore, p Prompt) {
	t.Helper()
	if _, err := store.PutPrompt(context.Background(), p); err != nil {
		t.Fatalf("PutPrompt(%s): %v", p.ID, err)
	}
}

func mustPutContext(t *testing.T, store ContextStore, c SessionContext) {
	t.Helper()
	if _, err := store.PutContext(context.Background(), c); err != nil {
		t.Fatalf("PutContext(%s/%s): %v", c.SessionUUID, c.Kind, err)
	}
}
