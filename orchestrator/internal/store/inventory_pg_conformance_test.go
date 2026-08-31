package store

// inventory_pg_conformance_test.go — DEEPER live-Postgres coverage for the
// migration-0007 agent-inventory read path (doc 16 §3.3; D45/D56/D57/D62), in a
// NEW file so the FROZEN inventory_test.go is never touched (re-scope task
// 01KTYKF7D0 exists because orch8 collided on inventory_test.go — this unit does
// not repeat that).
//
// inventory_test.go already drives the shared runAgentInventory / runResolveLaunchingUser
// assertions against both *Memory and (env-gated) *Postgres via openPostgresOrSkip,
// so VIEW row-shape parity with the in-memory impl is covered there. This file adds
// the assertions that ONLY a live SQL engine exercises and that the parity suite
// cannot express against *Memory:
//
//   - the agent_inventory VIEW's LEFT-join semantics under real SQL: a session
//     whose launching principal is unset (NULL link) and a session whose env config
//     was pruned (no env_configs row) both still surface, with NULL → empty
//     attribution / image columns — i.e. the join never drops a row;
//   - the VIEW's newest-first total order (ORDER BY session_created_at DESC,
//     session_uuid DESC) over rows with distinct and with TIED created_at, so the
//     0007 index-served ordering is verified on the engine, not just the Go sort;
//   - composite-index plan sanity: the per-principal drill-down
//     (sessions_launching_principal_created_idx, the 0007 hot-path index) is
//     present and usable, asserted structurally via pg_indexes + EXPLAIN rather
//     than by trusting a row count.
//
// Every test here is DS_PG_DSN-gated and SKIPS without a reachable database
// (reusing openPostgresOrSkip from inventory_test.go, which also truncates the
// shared tables), mirroring the existing pattern: this is a deferred manual step,
// never a sandbox gate. The target DB must have migrations 0001..0007 applied (the
// VIEW + composite index land in 0007). The lane wires DS_PG_DSN so these RUN in
// CI rather than skip (.github/workflows/pg-conformance.yml).

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// pgInventory opens the live store via the shared gate and returns the *Postgres
// concretely (so this file can reach the raw *sql.DB for EXPLAIN / pg_indexes
// introspection the typed read methods do not expose). It SKIPS without a DB,
// exactly like openPostgresOrSkip, which it delegates to for the open + truncate.
func pgInventory(t *testing.T) (*Postgres, *sql.DB) {
	t.Helper()
	repo := openPostgresOrSkip(t) // skip-without-DB + truncateAll
	pg, ok := repo.(*Postgres)
	if !ok {
		t.Fatalf("openPostgresOrSkip returned %T, want *Postgres", repo)
	}
	return pg, pg.db
}

// TestPostgres_InventoryViewLeftJoinNulls pins the agent_inventory VIEW's LEFT-join
// semantics on the live engine: neither an unset launching principal nor a pruned
// env config drops the session from the inventory — both surface with NULL columns
// that the read path maps to empty strings. *Memory cannot exercise this (it has no
// SQL LEFT JOIN); this is the live-only check the parity suite cannot make.
func TestPostgres_InventoryViewLeftJoinNulls(t *testing.T) {
	pg, _ := pgInventory(t)
	ctx := context.Background()

	// A principal + a launched session that joins BOTH a principal and an env
	// config (the fully-resolved row), to contrast the null rows against.
	_, err := pg.PutEnvConfig(ctx, EnvConfig{Ref: "env-live", ImageID: "sha256:live-img"})
	mustNoErr(t, err)
	_, err = pg.CreatePrincipal(ctx, Principal{
		ID: "p-live", IdPSubject: "okta|live", Org: "acme",
		Roles: []PrincipalRole{RoleLauncher}, DisplayName: "Live",
	})
	mustNoErr(t, err)

	linked := newSession("sess-linked", "host-a", 1)
	linked.EnvConfigRef = "env-live"
	_, err = pg.CreateSession(ctx, linked)
	mustNoErr(t, err)
	mustNoErr(t, pg.SetSessionLaunchingPrincipal(ctx, "sess-linked", "p-live"))

	// A session with NO launching principal (NULL link) AND an env config ref that
	// has NO env_configs row (pruned): BOTH LEFT joins miss, yet the row must list.
	orphan := newSession("sess-orphan", "host-b", 1)
	orphan.EnvConfigRef = "env-pruned" // no matching env_configs row
	_, err = pg.CreateSession(ctx, orphan)
	mustNoErr(t, err)

	all, err := pg.AgentInventory(ctx, InventoryFilter{})
	mustNoErr(t, err)
	byUUID := map[string]InventoryRow{}
	for _, r := range all {
		byUUID[r.SessionUUID] = r
	}
	if len(all) != 2 {
		t.Fatalf("LEFT-join inventory should list BOTH sessions, got %d: %+v", len(all), all)
	}

	// The orphan row survives both join misses with empty attribution + image, and
	// still carries its own session columns (the LEFT side is never null).
	orphRow, ok := byUUID["sess-orphan"]
	if !ok {
		t.Fatalf("orphan session dropped by the inventory VIEW (LEFT join collapsed to INNER)")
	}
	if orphRow.LaunchingPrincipalID != "" || orphRow.LaunchingUser != "" || orphRow.Org != "" || orphRow.DisplayName != "" {
		t.Fatalf("orphan attribution must be empty (NULL principal join): %+v", orphRow)
	}
	if orphRow.ImageID != "" {
		t.Fatalf("orphan image must be empty (NULL env_config join): %+v", orphRow)
	}
	if orphRow.EnvConfigRef != "env-pruned" || orphRow.HostID != "host-b" {
		t.Fatalf("orphan must retain its own (LEFT-side) columns: %+v", orphRow)
	}

	// The fully-linked row resolves all join columns — the positive control.
	linkedRow := byUUID["sess-linked"]
	if linkedRow.LaunchingUser != "okta|live" || linkedRow.Org != "acme" || linkedRow.DisplayName != "Live" {
		t.Fatalf("linked attribution not resolved by the VIEW: %+v", linkedRow)
	}
	if linkedRow.ImageID != "sha256:live-img" {
		t.Fatalf("linked env-config image not resolved by the VIEW: %+v", linkedRow)
	}
}

// TestPostgres_InventoryNewestFirstOrdering pins the VIEW's ORDER BY on the live
// engine: rows come back newest created_at first, and ties on created_at break by
// session_uuid DESC for a stable total order (the same total order the in-memory
// sort mirrors). Distinct timestamps verify the primary key of the order; the tie
// pair verifies the secondary key — neither is observable from *Memory's clock,
// which stamps one fixed instant.
func TestPostgres_InventoryNewestFirstOrdering(t *testing.T) {
	pg, db := pgInventory(t)
	ctx := context.Background()

	// Three sessions at distinct created_at instants (oldest → newest) plus a
	// fourth that TIES the newest instant, so both order keys are exercised. We
	// drive created_at directly via UPDATE so the ordering is deterministic and
	// independent of the store clock (the VIEW orders on the column, not the clock).
	for _, uuid := range []string{"sess-a", "sess-b", "sess-c", "sess-d"} {
		_, err := pg.CreateSession(ctx, newSession(uuid, "host-a", hostIdx(uuid)))
		mustNoErr(t, err)
	}
	t0 := time.Date(2026, 6, 12, 8, 0, 0, 0, time.UTC)
	stamp := map[string]time.Time{
		"sess-a": t0,                    // oldest
		"sess-b": t0.Add(1 * time.Hour), // middle
		"sess-c": t0.Add(2 * time.Hour), // newest
		"sess-d": t0.Add(2 * time.Hour), // TIE with sess-c (newest instant)
	}
	for uuid, at := range stamp {
		if _, err := db.ExecContext(ctx,
			`UPDATE sessions SET created_at = $1 WHERE session_uuid = $2`, at, uuid); err != nil {
			t.Fatalf("stamp created_at for %s: %v", uuid, err)
		}
	}

	all, err := pg.AgentInventory(ctx, InventoryFilter{})
	mustNoErr(t, err)
	got := make([]string, len(all))
	for i, r := range all {
		got[i] = r.SessionUUID
	}
	// Newest-first by created_at, then session_uuid DESC for the sess-c/sess-d tie
	// (sess-d > sess-c lexically, so it sorts first under DESC).
	want := []string{"sess-d", "sess-c", "sess-b", "sess-a"}
	if len(got) != len(want) {
		t.Fatalf("inventory order length: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("inventory not newest-first with uuid tie-break: got %v, want %v", got, want)
		}
	}
}

// TestPostgres_InventoryCompositeIndexPlan asserts the 0007 composite index
// sessions_launching_principal_created_idx (launching_principal, created_at DESC)
// — the per-principal drill-down hot path the inventory query's ORDER BY relies on
// — exists and is plan-usable on the live engine. This is the "index-served rather
// than post-join sort" claim 0007_principal_roles.sql makes, checked structurally
// (pg_indexes presence + EXPLAIN reachability) rather than by a row count, which
// would pass whether or not the index were ever used.
func TestPostgres_InventoryCompositeIndexPlan(t *testing.T) {
	pg, db := pgInventory(t)
	ctx := context.Background()

	const idxName = "sessions_launching_principal_created_idx"

	// (1) The 0007 composite index exists on `sessions`.
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
		t.Fatalf("0007 composite index %q is missing on sessions — the inventory drill-down hot path is unindexed", idxName)
	}

	// (2) Its column shape is (launching_principal, created_at) in that order —
	// the leading key the per-principal filter probes, with created_at carried so
	// the newest-first ORDER BY is index-served. We read the indexed column list
	// from pg_index/pg_attribute in attribute order.
	cols, err := indexColumns(ctx, db, idxName)
	mustNoErr(t, err)
	wantCols := []string{"launching_principal", "created_at"}
	if len(cols) != len(wantCols) || cols[0] != wantCols[0] || cols[1] != wantCols[1] {
		t.Fatalf("0007 index column order: got %v, want %v (leading principal key, created_at carried)", cols, wantCols)
	}

	// (3) Plan sanity: the per-principal drill-down query is reachable through the
	// planner. We seed one principal + session so the table is non-empty, then
	// EXPLAIN the exact predicate the inventory drill-down issues. On a tiny table
	// the planner may legitimately prefer a seq scan, so we DO NOT assert the scan
	// node (that would be a flaky plan-shape assertion); we assert the plan is
	// well-formed and the index is a candidate the planner knows about (proved by
	// (1)+(2)). EXPLAIN succeeding without ANALYZE confirms the predicate is valid
	// against the live schema — the VIEW + index + column types all line up.
	_, err = pg.CreatePrincipal(ctx, Principal{ID: "p-plan", IdPSubject: "okta|plan", Org: "acme", Roles: []PrincipalRole{RoleLauncher}})
	mustNoErr(t, err)
	_, err = pg.CreateSession(ctx, newSession("sess-plan", "host-a", 1))
	mustNoErr(t, err)
	mustNoErr(t, pg.SetSessionLaunchingPrincipal(ctx, "sess-plan", "p-plan"))

	rows, err := db.QueryContext(ctx,
		`EXPLAIN SELECT session_uuid FROM sessions
		   WHERE launching_principal = $1
		   ORDER BY created_at DESC`, "p-plan")
	if err != nil {
		t.Fatalf("EXPLAIN of the drill-down predicate failed — schema/type mismatch: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan EXPLAIN line: %v", err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	mustNoErr(t, rows.Err())
	if plan.Len() == 0 {
		t.Fatalf("EXPLAIN produced no plan for the drill-down query")
	}
}

// TestPostgres_InventoryPerPrincipalDrillDown exercises the per-principal
// LaunchingPrincipalID filter in AgentInventory against a live Postgres engine,
// covering the exact assertions the 0007 composite index's drill-down hot path
// serves:
//
//   - multiple principals × multiple sessions: filtering by one principal returns
//     ONLY that principal's sessions, never those of others;
//   - sessions with no launching principal (unlinked / NULL link) are EXCLUDED
//     from a per-principal drill-down, even though an unscoped sweep lists them;
//   - DESTROYED sessions are OMITTED by default (IncludeDestroyed=false) and
//     INCLUDED when the caller asks (IncludeDestroyed=true), per the InventoryFilter
//     contract (mirrors SessionFilter's destroyed-omitted default);
//   - the result is newest-first (ORDER BY session_created_at DESC, session_uuid DESC)
//     within the per-principal slice, the same stable total order the full-sweep
//     tests pin — verified here with explicit created_at stamps so the ordering is
//     deterministic and independent of the store clock.
//
// DS_PG_DSN-gated: SKIPS without a reachable database, the same as every other
// case in this file (pgInventory → openPostgresOrSkip).
func TestPostgres_InventoryPerPrincipalDrillDown(t *testing.T) {
	pg, db := pgInventory(t)
	ctx := context.Background()

	// Three principals in two orgs.
	_, err := pg.CreatePrincipal(ctx, Principal{
		ID: "p-alice", IdPSubject: "okta|alice", Org: "acme",
		Roles: []PrincipalRole{RoleLauncher}, DisplayName: "Alice",
	})
	mustNoErr(t, err)
	_, err = pg.CreatePrincipal(ctx, Principal{
		ID: "p-carol", IdPSubject: "okta|carol", Org: "acme",
		Roles: []PrincipalRole{RoleLauncher}, DisplayName: "Carol",
	})
	mustNoErr(t, err)
	_, err = pg.CreatePrincipal(ctx, Principal{
		ID: "p-dave", IdPSubject: "okta|dave", Org: "globex",
		Roles: []PrincipalRole{RoleLauncher}, DisplayName: "Dave",
	})
	mustNoErr(t, err)

	// An env config for the D7 join (used by some sessions).
	_, err = pg.PutEnvConfig(ctx, EnvConfig{Ref: "env-drill", ImageID: "sha256:drill-img"})
	mustNoErr(t, err)

	// Alice's sessions: three at distinct instants (oldest → newest) to pin the
	// newest-first order within the per-principal slice.
	for i, uuid := range []string{"alice-old", "alice-mid", "alice-new"} {
		s := newSession(uuid, "host-alice", uint64(i+1))
		s.EnvConfigRef = "env-drill"
		_, err = pg.CreateSession(ctx, s)
		mustNoErr(t, err)
		mustNoErr(t, pg.SetSessionLaunchingPrincipal(ctx, uuid, "p-alice"))
	}
	// Carol's sessions: two sessions (one of which will be DESTROYED).
	carolLive := newSession("carol-live", "host-carol", 1)
	_, err = pg.CreateSession(ctx, carolLive)
	mustNoErr(t, err)
	mustNoErr(t, pg.SetSessionLaunchingPrincipal(ctx, "carol-live", "p-carol"))

	carolGone := newSession("carol-gone", "host-carol", 2)
	_, err = pg.CreateSession(ctx, carolGone)
	mustNoErr(t, err)
	mustNoErr(t, pg.SetSessionLaunchingPrincipal(ctx, "carol-gone", "p-carol"))

	// Dave's session (different org — must NOT appear in Alice/Carol filters).
	daveS := newSession("dave-s", "host-dave", 1)
	_, err = pg.CreateSession(ctx, daveS)
	mustNoErr(t, err)
	mustNoErr(t, pg.SetSessionLaunchingPrincipal(ctx, "dave-s", "p-dave"))

	// An unlinked system session (no launching principal).
	_, err = pg.CreateSession(ctx, newSession("drill-sys", "host-sys", 1))
	mustNoErr(t, err)

	// Stamp created_at for Alice's sessions deterministically so newest-first order
	// is testable. Oldest → newest: alice-old < alice-mid < alice-new.
	t0 := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	aliceStamps := map[string]time.Time{
		"alice-old": t0,
		"alice-mid": t0.Add(1 * time.Hour),
		"alice-new": t0.Add(2 * time.Hour),
	}
	for uuid, at := range aliceStamps {
		if _, err := db.ExecContext(ctx,
			`UPDATE sessions SET created_at = $1 WHERE session_uuid = $2`, at, uuid); err != nil {
			t.Fatalf("stamp created_at for %s: %v", uuid, err)
		}
	}

	// DESTROY carol-gone — it should be absent from the default drill-down.
	destroyed := SessionDestroyed
	_, err = pg.UpdateSession(ctx, "carol-gone", SessionUpdate{State: &destroyed, DestroyedAt: SetTime(t0)})
	mustNoErr(t, err)

	// --- filter: Alice's sessions ---

	aliceRows, err := pg.AgentInventory(ctx, InventoryFilter{LaunchingPrincipalID: "p-alice"})
	mustNoErr(t, err)
	if len(aliceRows) != 3 {
		t.Fatalf("Alice drill-down: got %d rows, want 3 (alice-old/mid/new)", len(aliceRows))
	}
	for _, r := range aliceRows {
		if r.LaunchingPrincipalID != "p-alice" {
			t.Fatalf("Alice drill-down returned a row for wrong principal: %+v", r)
		}
		if r.LaunchingUser != "okta|alice" || r.Org != "acme" || r.DisplayName != "Alice" {
			t.Fatalf("Alice attribution not resolved: %+v", r)
		}
		if r.ImageID != "sha256:drill-img" {
			t.Fatalf("env-config image not resolved for Alice's session: %+v", r)
		}
	}
	// Newest-first order within Alice's slice:
	// alice-new (t0+2h) > alice-mid (t0+1h) > alice-old (t0).
	wantAliceOrder := []string{"alice-new", "alice-mid", "alice-old"}
	gotAliceOrder := make([]string, len(aliceRows))
	for i, r := range aliceRows {
		gotAliceOrder[i] = r.SessionUUID
	}
	for i, want := range wantAliceOrder {
		if gotAliceOrder[i] != want {
			t.Fatalf("Alice drill-down newest-first order wrong: got %v, want %v", gotAliceOrder, wantAliceOrder)
		}
	}

	// --- filter: Carol's sessions (destroyed omitted by default) ---

	carolDefault, err := pg.AgentInventory(ctx, InventoryFilter{LaunchingPrincipalID: "p-carol"})
	mustNoErr(t, err)
	if len(carolDefault) != 1 {
		t.Fatalf("Carol drill-down (default): got %d rows, want 1 (carol-gone must be omitted)", len(carolDefault))
	}
	if carolDefault[0].SessionUUID != "carol-live" {
		t.Fatalf("Carol drill-down default: unexpected row %+v", carolDefault[0])
	}

	// With IncludeDestroyed: the DESTROYED carol-gone surfaces too.
	carolAll, err := pg.AgentInventory(ctx, InventoryFilter{LaunchingPrincipalID: "p-carol", IncludeDestroyed: true})
	mustNoErr(t, err)
	if len(carolAll) != 2 {
		t.Fatalf("Carol drill-down (IncludeDestroyed): got %d rows, want 2", len(carolAll))
	}
	carolByUUID := map[string]InventoryRow{}
	for _, r := range carolAll {
		carolByUUID[r.SessionUUID] = r
	}
	if _, ok := carolByUUID["carol-gone"]; !ok {
		t.Fatalf("Carol IncludeDestroyed: carol-gone not returned: %+v", carolAll)
	}
	if carolByUUID["carol-gone"].State != SessionDestroyed {
		t.Fatalf("carol-gone should be DESTROYED: %+v", carolByUUID["carol-gone"])
	}

	// --- cross-principal isolation: Dave's session must NOT appear in Alice or Carol filters ---

	for _, uuid := range []string{"dave-s"} {
		for _, rows := range [][]InventoryRow{aliceRows, carolDefault} {
			for _, r := range rows {
				if r.SessionUUID == uuid {
					t.Fatalf("cross-principal leak: %s appeared in a filter not targeted at p-dave", uuid)
				}
			}
		}
	}

	// --- unlinked session excluded from ANY per-principal filter ---

	// The drill-sys session has no launching principal; it must be absent from all
	// three per-principal filters above. Also verify it does appear in an unscoped
	// sweep (so we are not chasing a creation bug).
	for _, rows := range [][]InventoryRow{aliceRows, carolDefault, carolAll} {
		for _, r := range rows {
			if r.SessionUUID == "drill-sys" {
				t.Fatalf("unlinked drill-sys should be excluded from per-principal filter: %+v", r)
			}
		}
	}
	unscopedAll, err := pg.AgentInventory(ctx, InventoryFilter{IncludeDestroyed: true})
	mustNoErr(t, err)
	foundSys := false
	for _, r := range unscopedAll {
		if r.SessionUUID == "drill-sys" {
			foundSys = true
		}
	}
	if !foundSys {
		t.Fatalf("unlinked drill-sys should appear in an unscoped sweep but was absent: %+v", unscopedAll)
	}
}

// indexColumns returns the indexed column names of idx in key order, read from the
// pg_index/pg_attribute catalogs. Expression/INCLUDE columns (attnum 0 or beyond
// the key count) are not part of this index, so a plain attribute join suffices.
func indexColumns(ctx context.Context, db *sql.DB, idx string) ([]string, error) {
	const q = `
SELECT a.attname
FROM pg_class c
JOIN pg_index i ON i.indexrelid = c.oid
JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
WHERE c.relname = $1
ORDER BY array_position(i.indkey, a.attnum)`
	rows, err := db.QueryContext(ctx, q, idx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, rows.Err()
}

// hostIdx maps a fixture session uuid to a distinct host_session_index so the
// CreateSession SessionRef quartet stays unique per host (the ordering fixture
// reuses host-a for every row).
func hostIdx(uuid string) uint64 {
	switch uuid {
	case "sess-a":
		return 1
	case "sess-b":
		return 2
	case "sess-c":
		return 3
	case "sess-d":
		return 4
	default:
		return 9
	}
}
