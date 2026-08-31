// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// cores.go holds the value-returning query cores shared by the CLI printers
// (cmd_task.go) and the MCP handlers (mcp_tools.go): one write path, identical
// semantics. Each core does the DB work and returns data or a typed error;
// printing, flag parsing, and os.Exit live in the callers.

// claimTask is the dispatch claim, shared by the CLI (`task claim`) and the MCP
// task_claim tool — so routing the shared-lock-server decision HERE covers both
// callers with no duplication. When a reachable shared lock server is
// configured it claims through Postgres (claimRemote); otherwise it falls back
// to the single-statement local claim (claimLocal). The local SQLite lock
// columns are kept as a mirror in both cases, so downstream readers
// (readyWhere, list, tui, task_report's holder guard) are unchanged.
func claimTask(db *sql.DB, session, optionalID string) (*Task, error) {
	t, _, err := claimTaskReaped(db, session, optionalID)
	return t, err
}

// claimTaskReaped is claimTask plus the ids of any stale foreign locks the
// shared-lock-server claim path aged out on the way in (the claim-time auto-reap,
// TASKDB_LOCK_AUTOREAP_AGE). It exists so the CLI printer (cmd_task.go) and the
// MCP task_claim handler (mcp_tools.go) can surface a reaped_locks field instead
// of the reap living only on claimRemote's stderr. The local-only claim path
// (claimLocal, no shared server) reaps nothing, so it returns a nil slice; a
// FAIL-CLOSED refusal (TASKDB_LOCK_REQUIRED with an unreachable server) also
// returns nil. claimTask keeps its original signature for the non-observing
// callers (existing tests, any path that does not consume the reaped set).
func claimTaskReaped(db *sql.DB, session, optionalID string) (*Task, []string, error) {
	ls, err := lockServerOrLocal()
	if err != nil {
		// FAIL-CLOSED (TASKDB_LOCK_REQUIRED): refuse — do NOT fall back to a
		// local-only claim. The error propagates to a non-zero CLI/MCP exit.
		return nil, nil, err
	}
	if ls != nil {
		defer ls.close()
		return claimRemoteReaped(db, ls, session, devHost(), optionalID)
	}
	t, err := claimLocal(db, session, optionalID)
	return t, nil, err
}

// claimLocal is the original atomic dispatch claim. A single statement flips
// the highest ready task to in-progress and returns it, reusing the readyWhere
// constant verbatim (deps.go) so "ready" means exactly what `task list --ready`
// means. optionalID (already resolved by the caller) narrows the candidate to
// one task. sql.ErrNoRows is the drained/not-ready signal — callers map it to
// an exit-1 message. UPDATE…RETURNING is proven against modernc v1.38.2.
//
// The claim does NOT mint a branch (docs/22 §2.1): an abandoned never-started
// claim freezes nothing, so there is no dead-branch diff noise.
func claimLocal(db *sql.DB, session, optionalID string) (*Task, error) {
	now := timeToMs(time.Now())
	args := []any{session, now, now}
	idFilter := ""
	if optionalID != "" {
		idFilter = " AND t.id = ?"
		args = append(args, optionalID)
	}
	q := `UPDATE tasks SET locked_by=?, locked_at=?, status='in-progress', updated_at=?
		WHERE id = (
			SELECT t.id FROM tasks t WHERE ` + readyWhere + idFilter + `
			ORDER BY t.priority DESC, t.id LIMIT 1)
		RETURNING id, title, body, status, priority, parent_id, branch, locked_by, locked_at, created_at, updated_at`
	// queryRetry, NOT db.Query: the UPDATE…RETURNING is atomic, so a SQLITE_BUSY
	// means it never took the write lock and updated NO row. Re-running re-runs
	// the whole ready-select+update and still claims at most one task — exact-once
	// is preserved (see queryRetry's contract). A drained queue (no ready row)
	// returns sql.ErrNoRows below, which is NOT a BUSY error and is never retried.
	rows, err := queryRetry(db, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		// No row updated: the WHERE subselect found no ready task.
		return nil, sql.ErrNoRows
	}
	t, err := scanTask(rows)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// releaseTask lands a claimed task in a deliberate state and unlocks it. With a
// reachable shared lock server it releases the Postgres lock first (the
// cross-machine authority) and mirrors the result locally; otherwise it uses
// the original local-only transaction. Both honor the holder guard.
func releaseTask(db *sql.DB, id, session, status, note string) (*Task, error) {
	ls, err := lockServerOrLocal()
	if err != nil {
		// FAIL-CLOSED (TASKDB_LOCK_REQUIRED): a release of a HELD task is a
		// claim-path sibling — refuse rather than silently local-release a task
		// the shared registry believes is held elsewhere.
		return nil, err
	}
	if ls != nil {
		defer ls.close()
		return releaseTaskRemote(db, ls, id, session, status, note)
	}
	return releaseTaskLocal(db, id, session, status, note)
}

// releaseTaskRemote releases the shared lock (holder-guarded) then mirrors the
// landing locally: set status, clear the lock, append the optional note. The
// remote release IS the authority check — a successful release means this
// session held it — so the local update is unconditional. If the task row is
// not present locally (e.g. lives only on another branch) the remote release
// still stands and a minimal Task is returned.
func releaseTaskRemote(db *sql.DB, ls *lockServer, id, session, status, note string) (*Task, error) {
	released, err := ls.release(id, session, false)
	if err != nil {
		return nil, err
	}
	if !released {
		return nil, fmt.Errorf("task %s not found or not locked by your session", id)
	}
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := timeToMs(time.Now())
	if _, err := tx.Exec(
		`UPDATE tasks SET status=?, locked_by=NULL, locked_at=NULL, updated_at=? WHERE id=?`,
		status, now, id,
	); err != nil {
		return nil, err
	}
	if note != "" {
		if _, err := tx.Exec(
			`INSERT INTO notes(id,task_id,body,author,created_at) VALUES(?,?,?,?,?)`,
			newID(), id, note, session, now,
		); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// Reflect the terminal/non-terminal landing into the shared done-tombstone
	// registry (docs/23 Proposal A) so other clones' claims skip/refuse this id
	// before they have pulled the terminal state. A TERMINAL release (done|dropped)
	// upserts the tombstone; a NON-terminal release (open/in-progress/blocked — a
	// deliberate reopen) DELETEs it (OQ-A3). Best-effort: an upsert/delete error is
	// swallowed (the local landing above already stands), mirroring emitLandEvent's
	// posture — soft coordination state must never fail a release.
	if isTerminalStatus(status) {
		_ = ls.upsertTombstone(id, status, session, devHost())
	} else {
		_ = ls.deleteTombstone(id)
	}
	if t, err := getTask(db, id); err == nil {
		return t, nil
	}
	return &Task{ID: id, Status: Status(status)}, nil
}

// releaseTaskLocal is the original local-only release: set status, append the
// optional note (author = session), and unlock — all in one transaction,
// guarded by `WHERE id=? AND locked_by=?` so only the holder can release. The
// id is already resolved; status is already validated by the caller. Returns
// the post-release task. A guard miss returns the existing wording so the CLI
// and MCP agree.
func releaseTaskLocal(db *sql.DB, id, session, status, note string) (*Task, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := timeToMs(time.Now())
	res, err := tx.Exec(
		`UPDATE tasks SET status=?, locked_by=NULL, locked_at=NULL, updated_at=? WHERE id=? AND locked_by=?`,
		status, now, id, session,
	)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, fmt.Errorf("task %s not found or not locked by your session", id)
	}
	if note != "" {
		if _, err := tx.Exec(
			`INSERT INTO notes(id,task_id,body,author,created_at) VALUES(?,?,?,?,?)`,
			newID(), id, note, session, now,
		); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return getTask(db, id)
}

// reapResult is one reaped row: which task and why (a forced-release of a stale
// lock, or a requeue of an orphaned in-progress task).
type reapResult struct {
	ID     string `json:"id"`
	Reason string `json:"reason"` // stale-lock | requeue
}

// reapLocks force-releases locks held longer than age and, when requeue is set,
// flips unlocked in-progress tasks back to open. With a reachable shared lock
// server the stale-lock reaping targets the Postgres registry (the
// cross-machine truth, judged by the server clock) and mirrors the clears
// locally; the requeue half is always local (it is about orphaned local
// in-progress rows). dryRun reports without mutating.
func reapLocks(db *sql.DB, age time.Duration, requeue, dryRun bool) ([]reapResult, error) {
	// Admin cleanup, NOT a claim: ignore a TASKDB_LOCK_REQUIRED fail-closed
	// refusal and stay fail-open (reap the local mirror) — a down tunnel must
	// not block stale-lock cleanup.
	ls, _ := lockServerOrLocal()
	if ls != nil {
		defer ls.close()
		return reapLocksRemote(db, ls, age, requeue, dryRun)
	}
	return reapLocksLocal(db, age, requeue, dryRun)
}

// reapLocksRemote reaps stale locks from the shared registry (authoritative,
// server-clock) and requeues local orphans. clearLockLocal keeps the SQLite
// mirror in step with each remote removal.
func reapLocksRemote(db *sql.DB, ls *lockServer, age time.Duration, requeue, dryRun bool) ([]reapResult, error) {
	out := []reapResult{}
	if dryRun {
		// Use the SAME activity-aware, server-side predicate the real reap() runs
		// (listStaleLocks shares reapLockStaleSQL with reap()), so the preview can
		// never disagree with the mutation — a live, heartbeating agent's lock past
		// the age cutoff is NOT listed here, exactly as it would NOT be reaped.
		stale, err := ls.listStaleLocks(age)
		if err != nil {
			return nil, err
		}
		for _, id := range stale {
			out = append(out, reapResult{ID: id, Reason: "stale-lock"})
		}
	} else {
		reaped, err := ls.reap(age)
		if err != nil {
			return nil, err
		}
		for _, id := range reaped {
			clearLockLocal(db, id)
			out = append(out, reapResult{ID: id, Reason: "stale-lock"})
		}
		// Opportunistically age out stale done-tombstones on the standing reap path
		// (OQ-A2), by the tombstone's own TTL (NOT the lock age). Best-effort and
		// non-fatal — a tombstone reap error must not fail stale-lock cleanup; the
		// reaped ids are NOT added to `out` (this is lock-reap output, not tombstone
		// output). Skipped under dryRun (this branch only runs when !dryRun).
		_, _ = ls.reapTombstones(tombstoneTTL())
	}
	if requeue {
		rq, err := requeueOrphans(db, dryRun)
		if err != nil {
			return nil, err
		}
		out = append(out, rq...)
	}
	return out, nil
}

// requeueOrphans flips local unlocked in-progress tasks back to open (an agent
// that died after unlocking but before releasing leaves them stranded).
// Returns the affected ids; dryRun reports without mutating.
func requeueOrphans(db *sql.DB, dryRun bool) ([]reapResult, error) {
	rows, err := db.Query(`SELECT id FROM tasks WHERE status='in-progress' AND locked_by IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []reapResult{}
	now := timeToMs(time.Now())
	for _, id := range ids {
		if !dryRun {
			res, err := execRetry(db, `UPDATE tasks SET status='open', updated_at=? WHERE id=? AND status='in-progress' AND locked_by IS NULL`, now, id)
			if err != nil {
				return nil, err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue
			}
		}
		out = append(out, reapResult{ID: id, Reason: "requeue"})
	}
	return out, nil
}

// reapLocksLocal is the original local-only reap: force-releases locks held
// longer than age and, when requeue is set, flips unlocked in-progress tasks
// back to open (an agent that died after unlocking but before a release left
// them stranded). dryRun reports the same set without mutating. The dispatcher
// runs `task reap --requeue` at loop start.
func reapLocksLocal(db *sql.DB, age time.Duration, requeue, dryRun bool) ([]reapResult, error) {
	cutoff := timeToMs(time.Now().Add(-age))
	out := []reapResult{} // empty, not nil: --json prints [] when nothing reaped

	stale, err := db.Query(`SELECT id FROM tasks WHERE locked_by IS NOT NULL AND locked_at < ? ORDER BY id`, cutoff)
	if err != nil {
		return nil, err
	}
	for stale.Next() {
		var id string
		if err := stale.Scan(&id); err != nil {
			stale.Close()
			return nil, err
		}
		out = append(out, reapResult{ID: id, Reason: "stale-lock"})
	}
	stale.Close()
	if err := stale.Err(); err != nil {
		return nil, err
	}

	if requeue {
		orphan, err := db.Query(`SELECT id FROM tasks WHERE status='in-progress' AND locked_by IS NULL ORDER BY id`)
		if err != nil {
			return nil, err
		}
		for orphan.Next() {
			var id string
			if err := orphan.Scan(&id); err != nil {
				orphan.Close()
				return nil, err
			}
			out = append(out, reapResult{ID: id, Reason: "requeue"})
		}
		orphan.Close()
		if err := orphan.Err(); err != nil {
			return nil, err
		}
	}

	if dryRun {
		return out, nil
	}

	// Re-assert the observed staleness in each clear UPDATE so a concurrent
	// claimTask that re-locked a row (set locked_at=now) between our SELECT and
	// this write is never wiped: the cutoff guard makes the UPDATE a no-op, and a
	// RowsAffected==0 row is dropped from the report rather than claimed as reaped.
	now := timeToMs(time.Now())
	reaped := out[:0] // reuse the backing array; keep only rows we actually mutated
	for _, r := range out {
		var res sql.Result
		var err error
		switch r.Reason {
		case "stale-lock":
			res, err = execRetry(db, `UPDATE tasks SET locked_by=NULL, locked_at=NULL, updated_at=? WHERE id=? AND locked_at < ?`, now, r.ID, cutoff)
		case "requeue":
			res, err = execRetry(db, `UPDATE tasks SET status='open', updated_at=? WHERE id=? AND status='in-progress' AND locked_by IS NULL`, now, r.ID)
		}
		if err != nil {
			return nil, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // re-locked or re-claimed underneath us: not reaped
		}
		reaped = append(reaped, r)
	}
	return reaped, nil
}

// searchTasks runs an FTS5 MATCH over tasks_fts ordered by rank (best first).
// Raw user input is wrapped as a quoted phrase unless raw is set, because bare
// FTS5 operators (-, *, NEAR, unbalanced quotes) raise a syntax error on
// otherwise innocent queries; --raw opts into the FTS5 mini-language.
func searchTasks(db *sql.DB, query string, limit int, raw bool) ([]*Task, error) {
	match := query
	if !raw {
		match = ftsPhrase(query)
	}
	rows, err := db.Query(
		`SELECT t.id, t.title, t.body, t.status, t.priority, t.parent_id, t.branch, t.locked_by, t.locked_at, t.created_at, t.updated_at
		FROM tasks t JOIN tasks_fts f ON f.rowid = t.rowid
		WHERE tasks_fts MATCH ? ORDER BY rank LIMIT ?`,
		match, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := []*Task{} // empty, not nil: --json prints [] on no hits
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := attachDeps(db, tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

// ftsPhrase wraps raw input as a single FTS5 quoted phrase, escaping embedded
// double quotes by doubling them — the safe form for arbitrary user text.
func ftsPhrase(query string) string {
	return `"` + strings.ReplaceAll(query, `"`, `""`) + `"`
}

// lastRuns returns the newest n agent_runs rows for a task (the dc3
// get_attempts analog), so a future agent sees prior attempts. Empty (not nil)
// so it omits cleanly when the ledger has no rows.
func lastRuns(db *sql.DB, taskID string, n int) ([]*AgentRun, error) {
	rows, err := db.Query(
		`SELECT id, task_id, session, worktree_path, model, status, exit_code, num_turns, cost_usd, input_tokens, output_tokens, started_at, finished_at, note
		FROM agent_runs WHERE task_id=? ORDER BY finished_at DESC, id DESC LIMIT ?`,
		taskID, n,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AgentRun{}
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// taskSourceLink is one task↔doc edge for the context pack: the raw fragment
// plus whether the cited doc is still on disk (a dangling link otherwise).
type taskSourceLink struct {
	DocPath string `json:"doc_path"`
	Section string `json:"section,omitempty"`
	Missing bool   `json:"missing,omitempty"`
}

// linkedSources returns the task_sources rows for a task, LEFT-JOINed against
// docs so a citation to a deleted file surfaces as missing. Empty when the doc
// index has not been built (doc sync never run) — the LEFT JOIN keeps it safe.
func linkedSources(db *sql.DB, taskID string) ([]taskSourceLink, error) {
	rows, err := db.Query(
		`SELECT s.doc_path, s.section, d.path IS NULL
		FROM task_sources s LEFT JOIN docs d ON d.path = s.doc_path
		WHERE s.task_id=? ORDER BY s.doc_path, s.section`,
		taskID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []taskSourceLink{}
	for rows.Next() {
		var l taskSourceLink
		if err := rows.Scan(&l.DocPath, &l.Section, &l.Missing); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// taskContext is the --json shape for `task get`: the task plus the last few
// run outcomes and linked docs when those (ephemeral/derived) tables have data.
// Empty slices are omitted, so a task with no runs/links serializes exactly as
// the bare Task did — keeping the schema-change gate (zero freeze diff) honest
// and old consumers working.
type taskContext struct {
	*Task
	Runs    []*AgentRun      `json:"runs,omitempty"`
	Sources []taskSourceLink `json:"sources,omitempty"`
}

// taskContextOf assembles the context pack for one task: deps attached, plus
// the last 3 runs and linked sources when present. Safe to call on a fresh DB
// with no agent_runs/task_sources rows (the queries simply return nothing).
func taskContextOf(db *sql.DB, t *Task) (*taskContext, error) {
	if err := attachDeps(db, []*Task{t}); err != nil {
		return nil, err
	}
	runs, err := lastRuns(db, t.ID, 3)
	if err != nil {
		return nil, err
	}
	sources, err := linkedSources(db, t.ID)
	if err != nil {
		return nil, err
	}
	ctx := &taskContext{Task: t}
	if len(runs) > 0 {
		ctx.Runs = runs
	}
	if len(sources) > 0 {
		ctx.Sources = sources
	}
	return ctx, nil
}
