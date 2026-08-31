// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// peelID splits a leading positional <id> from the remaining flag arguments.
//
// Go's flag package stops parsing at the first non-flag token, so a natural
// invocation like `task lock <id> --session X` would leave --session unparsed.
// Every task subcommand that takes an <id> puts it first; we peel it off here
// and let flag.Parse handle the rest.
func peelID(args []string, usage string) (string, []string, error) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, fmt.Errorf("usage: %s", usage)
	}
	return args[0], args[1:], nil
}

// resolveTaskID accepts a full task ID or any unambiguous prefix and returns
// the full ID. ULIDs are 26 chars; this lets callers type a short handle from
// the list/tree output. Matching is case-insensitive (SQLite LIKE), matching
// ULID's case-insensitivity. An ambiguous prefix is an error that lists the
// candidates so the caller can disambiguate.
func resolveTaskID(db *sql.DB, ref string) (string, error) {
	ref = strings.ToUpper(strings.TrimSpace(ref))
	if ref == "" {
		return "", fmt.Errorf("empty task ID")
	}
	rows, err := db.Query(`SELECT id FROM tasks WHERE id LIKE ? ORDER BY id`, ref+"%")
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var matches []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			return "", err
		}
		matches = append(matches, m)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("task %s not found", ref)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous task prefix %q matches %d tasks: %s", ref, len(matches), strings.Join(matches, ", "))
	}
}

func cmdTask(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb task <add|get|list|set|lock|unlock|edit|dep|undep|rm|drop|claim|release|reap|search>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return taskAdd(db, rest)
	case "get":
		return taskGet(db, rest)
	case "list":
		return taskList(db, rest)
	case "set":
		return taskSet(db, rest)
	case "lock":
		return taskLock(db, rest)
	case "unlock":
		return taskUnlock(db, rest)
	case "edit":
		return taskEdit(db, rest)
	case "dep":
		return taskDep(db, rest)
	case "undep":
		return taskUndep(db, rest)
	case "rm":
		return taskRm(db, rest)
	case "drop":
		return taskDrop(db, rest)
	case "claim":
		return taskClaim(db, rest)
	case "release":
		return taskRelease(db, rest)
	case "reap":
		return taskReap(db, rest)
	case "search":
		return taskSearch(db, rest)
	default:
		return fmt.Errorf("unknown task subcommand: %s", sub)
	}
}

func taskAdd(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("task add", flag.ContinueOnError)
	title := fs.String("title", "", "task title (required)")
	body := fs.String("body", "", "task description (markdown)")
	parent := fs.String("parent", "", "parent task ID")
	priority := fs.Int("priority", 0, "0-3")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *title == "" {
		return fmt.Errorf("--title is required")
	}

	parentRef := *parent
	if parentRef != "" {
		resolved, err := resolveTaskID(db, parentRef)
		if err != nil {
			return fmt.Errorf("--parent: %w", err)
		}
		parentRef = resolved
	}

	id := newID()
	now := time.Now().UTC()
	var parentID any = nil
	if parentRef != "" {
		parentID = parentRef
	}
	_, err := execRetry(db,
		`INSERT INTO tasks(id,title,body,status,priority,parent_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
		id, *title, *body, StatusOpen, *priority, parentID,
		timeToMs(now), timeToMs(now),
	)
	if err != nil {
		return err
	}
	t := &Task{ID: id, Title: *title, Body: *body, Status: StatusOpen, Priority: *priority, ParentID: parentRef, CreatedAt: now, UpdatedAt: now}
	return printTask(t, *asJSON)
}

func taskGet(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb task get <id> [--json]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task get", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	t, err := getTask(db, id)
	if err != nil {
		return err
	}
	// --json serves the context pack: the task plus the last 3 runs and linked
	// docs when those ephemeral/derived tables have data. On a bare DB the
	// extra slices stay empty and the JSON is byte-identical to the plain Task.
	if *asJSON {
		ctx, err := taskContextOf(db, t)
		if err != nil {
			return err
		}
		return printJSON(ctx)
	}
	if err := attachDeps(db, []*Task{t}); err != nil {
		return err
	}
	if err := printTask(t, false); err != nil {
		return err
	}
	dependents, err := dependentsOf(db, t.ID)
	if err != nil {
		return err
	}
	if len(dependents) > 0 {
		fmt.Printf("  blocks: %s\n", strings.Join(dependents, ", "))
	}
	return nil
}

func taskList(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("task list", flag.ContinueOnError)
	statusFilter := fs.String("status", "", "filter by status")
	parentFilter := fs.String("parent", "", "filter by parent ID")
	tree := fs.Bool("tree", false, "show as tree")
	ready := fs.Bool("ready", false, "only tasks dispatchable now: open, unlocked, all deps done, no children")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ready && *statusFilter != "" {
		return fmt.Errorf("--ready already implies --status open")
	}

	q := `SELECT id, title, body, status, priority, parent_id, branch, locked_by, locked_at, created_at, updated_at FROM tasks t WHERE 1=1`
	var params []any
	if *ready {
		q += ` AND ` + readyWhere
	}
	if *statusFilter != "" {
		q += ` AND status = ?`
		params = append(params, *statusFilter)
	}
	if *parentFilter != "" {
		parentID, err := resolveTaskID(db, *parentFilter)
		if err != nil {
			return fmt.Errorf("--parent: %w", err)
		}
		q += ` AND parent_id = ?`
		params = append(params, parentID)
	}
	q += ` ORDER BY priority DESC, created_at`

	rows, err := db.Query(q, params...)
	if err != nil {
		return err
	}
	defer rows.Close()

	var tasks []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return err
		}
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := attachDeps(db, tasks); err != nil {
		return err
	}

	if *asJSON {
		return printJSON(tasks)
	}
	if *tree {
		printTaskTree(tasks)
	} else {
		printTaskTable(tasks)
	}
	return nil
}

func taskSet(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb task set <id> --status <status>")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task set", flag.ContinueOnError)
	status := fs.String("status", "", "new status")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *status == "" {
		return fmt.Errorf("usage: taskdb task set <id> --status <status>")
	}
	validStatuses := map[string]bool{"open": true, "in-progress": true, "done": true, "blocked": true, "dropped": true}
	if !validStatuses[*status] {
		return fmt.Errorf("invalid status %q; must be one of: open, in-progress, done, blocked, dropped", *status)
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	res, err := execRetry(db, `UPDATE tasks SET status=?, updated_at=? WHERE id=?`, *status, timeToMs(time.Now()), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("task %s not found", id)
	}
	// Reflect the status into the shared done-tombstone registry (docs/23
	// Proposal A) so the two terminal-write paths stay consistent: a `set --status
	// done/dropped` outside the lock/release path STILL tombstones, and a `set
	// --status open/in-progress/blocked` on a previously-done task CLEARS the
	// tombstone so claim offers it again (OQ-A3). Best-effort and fail-open:
	// IGNORE a TASKDB_LOCK_REQUIRED refusal and an unreachable tunnel — a `set` is
	// a status edit, not a claim, so it must never be blocked by lock-server state.
	if ls, _ := lockServerOrLocal(); ls != nil {
		defer ls.close()
		if isTerminalStatus(*status) {
			_ = ls.upsertTombstone(id, *status, devHost(), devHost())
		} else {
			_ = ls.deleteTombstone(id)
		}
	}
	fmt.Printf("task %s → %s\n", id, *status)
	return nil
}

// resolveSession resolves the lock-holder identity for the four holder verbs
// (lock/unlock/claim/release) by the documented precedence: an explicit
// --session flag wins, else the TASKDB_SESSION environment variable exported by
// the wave provisioner's `.taskdb-session` file (scripts/wave_worktree.sh —
// "the per-unit lock-holder identity"), else EMPTY.
//
// Deliberately UNLIKE mcpSession (cmd_mcp.go), there is NO synthetic
// `cc-<user>-<pid>` fallback here. mcp is a long-lived server that needs a
// stable handle for its own bookkeeping; these verbs write a lock row that
// other machines read as a claim of ownership. Manufacturing an identity when
// the operator supplied none would turn a mistake into a false lock claim that
// nobody can attribute or reap. Returning "" keeps the callers' existing
// "session required" errors firing loudly and unchanged.
func resolveSession(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return os.Getenv("TASKDB_SESSION")
}

func taskLock(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb task lock <id> --session <session-id>")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task lock", flag.ContinueOnError)
	session := fs.String("session", "", "session ID claiming the lock (required)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	// Lock-holder identity: --session wins, else TASKDB_SESSION (exported by
	// the wave provisioner's .taskdb-session). No synthetic fallback — an
	// unresolved identity stays empty so the check below still refuses.
	sess := resolveSession(*session)
	if sess == "" {
		return fmt.Errorf("usage: taskdb task lock <id> --session <session-id>")
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	// Shared lock server (when reachable): acquire across machines first, then
	// mirror the hold into the local SQLite columns for display/readiness.
	// FAIL-CLOSED (TASKDB_LOCK_REQUIRED): refuse rather than take a local-only lock.
	ls, lsErr := lockServerOrLocal()
	if lsErr != nil {
		return lsErr
	}
	if ls != nil {
		defer ls.close()
		// Status-aware claim, explicit-id leg (docs/23 OQ-A1): an explicit
		// `lock <id>` of a task another clone already completed must REFUSE loudly,
		// not silently take a lock on done work. Gate only when the tombstone is
		// NEWER than the local row's updated_at (this clone has not pulled the
		// terminal state); a reopen that bumped updated_at, or a pulled terminal
		// row, has updated_at >= at and is correctly NOT gated. Best-effort lookup:
		// an un-migrated DB / read error yields no tombstone and the lock proceeds.
		if ts, _ := ls.isTombstoned(id); ts != nil {
			if t, gerr := getTask(db, id); gerr == nil && tombstoneGates(ts, t.UpdatedAt) {
				fmt.Fprintln(os.Stderr, tombstoneRefusal(id, ts))
				os.Exit(1)
			}
		}
		ok, holder, err := ls.acquire(id, sess, devHost())
		if err != nil {
			return err
		}
		if !ok {
			// IDEMPOTENT SAME-SESSION RELOCK (F4): acquire is INSERT..ON CONFLICT
			// DO NOTHING, so a re-lock by the SAME holder returns !ok with no row.
			// The docs say "same-session relock is tolerated" (post-outage
			// recovery: re-lock anything you claimed during the outage so it
			// registers cross-machine). Treat holder==self as success — refresh
			// locked_at so the row reads fresh — rather than exiting non-zero. The
			// refresh is an atomic session-scoped UPDATE (no release/re-acquire race
			// window): if a peer somehow took the lock in between, the WHERE guard
			// matches zero rows and we simply mirror what we hold and still succeed.
			if holder != nil && holder.LockedBy == sess {
				at := holder.LockedAt
				if refreshed, rerr := ls.refreshLock(id, sess); rerr == nil && refreshed {
					at = time.Now()
				}
				mirrorLockLocal(db, id, sess, at)
				fmt.Printf("locked task %s by session %s (shared lock server; same-session relock)\n", id, sess)
				return nil
			}
			if holder != nil {
				mirrorLockLocal(db, id, holder.LockedBy, holder.LockedAt)
				fmt.Fprintf(os.Stderr, "task %s is locked by %s on %s (since %s)\n",
					id, holder.LockedBy, holder.Host, holder.LockedAt.Format(time.RFC3339))
			} else {
				fmt.Fprintf(os.Stderr, "task %s is already locked\n", id)
			}
			os.Exit(1)
		}
		mirrorLockLocal(db, id, sess, time.Now())
		fmt.Printf("locked task %s by session %s (shared lock server)\n", id, sess)
		return nil
	}
	now := timeToMs(time.Now())
	// IDEMPOTENT SAME-SESSION RELOCK (F4), LOCAL path: admit a re-lock by the
	// SAME holder (locked_by = session) as well as a free task (locked_by IS
	// NULL), so a post-outage re-lock of work this session already holds succeeds
	// (refreshing locked_at) rather than colliding with itself. A lock held by
	// ANOTHER session still matches zero rows and falls through to the refusal.
	res, err := execRetry(db,
		`UPDATE tasks SET locked_by=?, locked_at=?, updated_at=? WHERE id=? AND (locked_by IS NULL OR locked_by = ?)`,
		sess, now, now, id, sess,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		t, err := getTask(db, id)
		if err != nil {
			return err
		}
		if t.LockedBy != "" {
			fmt.Fprintf(os.Stderr, "task %s is locked by %s (since %s)\n", id, t.LockedBy, msToTime(t.LockedAt).Format(time.RFC3339))
			os.Exit(1)
		}
		return fmt.Errorf("task %s not found", id)
	}
	fmt.Printf("locked task %s by session %s\n", id, sess)
	return nil
}

func taskUnlock(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb task unlock <id> [--session <id>] [--force]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task unlock", flag.ContinueOnError)
	session := fs.String("session", "", "session ID releasing the lock")
	force := fs.Bool("force", false, "bypass session check")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	// Lock-holder identity: --session wins, else TASKDB_SESSION (exported by
	// the wave provisioner's .taskdb-session). No synthetic fallback — an
	// unresolved identity stays empty so the check below still refuses.
	sess := resolveSession(*session)
	if !*force && sess == "" {
		return fmt.Errorf("--session required unless --force is set")
	}
	// Shared lock server (when reachable): release across machines, then clear
	// the local mirror. --force is idempotent (an already-free lock is fine).
	// FAIL-CLOSED (TASKDB_LOCK_REQUIRED): unlock is the lock-verb sibling — refuse
	// rather than clear only the local mirror of a remotely-held lock.
	ls, lsErr := lockServerOrLocal()
	if lsErr != nil {
		return lsErr
	}
	if ls != nil {
		defer ls.close()
		released, err := ls.release(id, sess, *force)
		if err != nil {
			return err
		}
		if !released && !*force {
			return fmt.Errorf("task %s not found or not locked by your session", id)
		}
		clearLockLocal(db, id)
		fmt.Printf("unlocked task %s\n", id)
		return nil
	}
	var res sql.Result
	if *force {
		res, err = execRetry(db, `UPDATE tasks SET locked_by=NULL, locked_at=NULL, updated_at=? WHERE id=?`, timeToMs(time.Now()), id)
	} else {
		res, err = execRetry(db, `UPDATE tasks SET locked_by=NULL, locked_at=NULL, updated_at=? WHERE id=? AND locked_by=?`, timeToMs(time.Now()), id, sess)
	}
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("task %s not found or not locked by your session", id)
	}
	fmt.Printf("unlocked task %s\n", id)
	return nil
}

func taskEdit(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb task edit <id> [--title ...] [--body ...] [--priority N] [--parent ID|none]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task edit", flag.ContinueOnError)
	title := fs.String("title", "", "new title")
	body := fs.String("body", "", "new body")
	priority := fs.Int("priority", -1, "new priority 0-3")
	parent := fs.String("parent", "", "new parent task ID, or 'none' to detach")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	t, err := getTask(db, id)
	if err != nil {
		return err
	}
	if *title != "" {
		t.Title = *title
	}
	if *body != "" {
		t.Body = *body
	}
	if *priority >= 0 {
		t.Priority = *priority
	}
	var parentID any = nil
	if t.ParentID != "" {
		parentID = t.ParentID
	}
	switch {
	case *parent == "none":
		parentID = nil
	case *parent != "":
		resolved, err := resolveTaskID(db, *parent)
		if err != nil {
			return fmt.Errorf("--parent: %w", err)
		}
		if resolved == id {
			return fmt.Errorf("task %s cannot be its own parent", id)
		}
		if chain, err := ancestorPath(db, resolved, id); err != nil {
			return err
		} else if chain != nil {
			return fmt.Errorf("would create a parent cycle: %s → %s", id, strings.Join(chain, " → "))
		}
		parentID = resolved
	}
	_, err = execRetry(db, `UPDATE tasks SET title=?, body=?, priority=?, parent_id=?, updated_at=? WHERE id=?`,
		t.Title, t.Body, t.Priority, parentID, timeToMs(time.Now()), id)
	if err != nil {
		return err
	}
	fmt.Printf("updated task %s\n", id)
	return nil
}

// taskDep records that one task depends on another: the dependent stays out
// of `list --ready` until the dependency is done. Rejects edges that would
// make the graph cyclic, printing the offending chain.
func taskDep(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb task dep <id> --on <id>")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task dep", flag.ContinueOnError)
	on := fs.String("on", "", "task that must be done first (required)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *on == "" {
		return fmt.Errorf("usage: taskdb task dep <id> --on <id>")
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	dep, err := resolveTaskID(db, *on)
	if err != nil {
		return fmt.Errorf("--on: %w", err)
	}
	if id == dep {
		return fmt.Errorf("task %s cannot depend on itself", id)
	}
	// Adding "id depends on dep" creates a cycle iff dep already (transitively)
	// depends on id.
	if path, err := depPath(db, dep, id); err != nil {
		return err
	} else if path != nil {
		return fmt.Errorf("would create a cycle: %s → %s", id, strings.Join(path, " → "))
	}
	_, err = execRetry(db, `INSERT OR IGNORE INTO task_deps(task_id,depends_on) VALUES(?,?)`, id, dep)
	if err != nil {
		return err
	}
	if _, err := execRetry(db, `UPDATE tasks SET updated_at=? WHERE id=?`, timeToMs(time.Now()), id); err != nil {
		return err
	}
	fmt.Printf("task %s now depends on %s\n", id, dep)
	return nil
}

func taskUndep(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb task undep <id> --on <id>")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task undep", flag.ContinueOnError)
	on := fs.String("on", "", "dependency to remove (required)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *on == "" {
		return fmt.Errorf("usage: taskdb task undep <id> --on <id>")
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	dep, err := resolveTaskID(db, *on)
	if err != nil {
		return fmt.Errorf("--on: %w", err)
	}
	res, err := execRetry(db, `DELETE FROM task_deps WHERE task_id=? AND depends_on=?`, id, dep)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("task %s does not depend on %s", id, dep)
	}
	if _, err := execRetry(db, `UPDATE tasks SET updated_at=? WHERE id=?`, timeToMs(time.Now()), id); err != nil {
		return err
	}
	fmt.Printf("task %s no longer depends on %s\n", id, dep)
	return nil
}

func taskRm(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb task rm <id>")
	}
	idArg, rest, err := peelID(args, "taskdb task rm <id>")
	if err != nil {
		return err
	}
	if err := rejectUnknownFlags(rest, "taskdb task rm <id>"); err != nil {
		return err
	}
	id, err := resolveTaskID(db, idArg)
	if err != nil {
		return err
	}
	// Explicit edge cleanup: don't rely on FK cascade for databases created
	// before foreign-key enforcement was fixed.
	if _, err := execRetry(db, `DELETE FROM task_deps WHERE task_id=? OR depends_on=?`, id, id); err != nil {
		return err
	}
	res, err := execRetry(db, `DELETE FROM tasks WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("task %s not found", id)
	}
	fmt.Printf("deleted task %s\n", id)
	return nil
}

// taskDrop terminally abandons a task: it sets status=dropped, clears any lock
// (local + the shared registry, force-released since a drop is a deliberate
// admin decision regardless of who holds it), and optionally records why.
//
// This REPLACES routine file-deletion (docs/23 Proposal B): instead of `rm`-ing
// a tasks/*.json a coordinator no longer wants, drop it. The tombstone stays in
// the frozen JSON so a stale branch can never resurrect the work (the merge
// driver ranks dropped above the non-terminal states), and dependents are
// unblocked exactly as a `done` would unblock them (readyWhere treats dropped as
// terminal). `rm` remains for genuine mistakes — a task that should never have
// existed — but the curation default is now `drop`.
func taskDrop(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb task drop <id> [--reason ...]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task drop", flag.ContinueOnError)
	reason := fs.String("reason", "", "why the task is being dropped (recorded as a note, author=human)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	t, err := getTask(db, id)
	if err != nil {
		return err
	}
	// Force-release any hold in the shared registry first (best-effort; a drop
	// must not be blocked by an unreachable tunnel — the local clear below still
	// stands). force=true: a drop overrides whoever holds the lock. A drop is a
	// removal, NOT a claim, so it IGNORES a TASKDB_LOCK_REQUIRED fail-closed
	// refusal (stays fail-open) — failing it closed would regress the
	// must-not-be-blocked guarantee.
	if t.LockedBy != "" {
		if ls, _ := lockServerOrLocal(); ls != nil {
			if _, rerr := ls.release(id, "", true); rerr != nil {
				fmt.Fprintf(os.Stderr, "warning: could not release shared lock for %s: %v\n", id, rerr)
			}
			ls.close()
		}
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := timeToMs(time.Now())
	res, err := tx.Exec(
		`UPDATE tasks SET status=?, locked_by=NULL, locked_at=NULL, updated_at=? WHERE id=?`,
		string(StatusDropped), now, id,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("task %s not found", id)
	}
	if *reason != "" {
		if _, err := tx.Exec(
			`INSERT INTO notes(id,task_id,body,author,created_at) VALUES(?,?,?,?,?)`,
			newID(), id, "dropped: "+*reason, "human", now,
		); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	fmt.Printf("task %s → dropped\n", id)
	return nil
}

// taskClaim atomically claims the highest-priority ready task (or the targeted
// one) for a session, flipping it to in-progress. This is the dispatch entry
// point; the dispatcher reads the returned task (--json) to provision a
// worktree. A drained/not-ready queue exits 1 (not an error) so the dispatcher
// loop can stop cleanly without a "taskdb: ..." prefix.
func taskClaim(db *sql.DB, args []string) error {
	// The <id> positional is optional, so peel it only when present and not a flag.
	var idArg string
	rest := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		idArg, rest = args[0], args[1:]
	}
	fs := flag.NewFlagSet("task claim", flag.ContinueOnError)
	session := fs.String("session", "", "session ID claiming the task (required)")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	// Lock-holder identity: --session wins, else TASKDB_SESSION (exported by
	// the wave provisioner's .taskdb-session). No synthetic fallback — an
	// unresolved identity stays empty so the check below still refuses.
	sess := resolveSession(*session)
	if sess == "" {
		return fmt.Errorf("usage: taskdb task claim [<id>] --session <session-id> [--json]")
	}

	var resolved string
	if idArg != "" {
		r, err := resolveTaskID(db, idArg)
		if err != nil {
			return err
		}
		resolved = r
	}

	t, reaped, err := claimTaskReaped(db, sess, resolved)
	if err == sql.ErrNoRows {
		if resolved != "" {
			fmt.Fprintf(os.Stderr, "task %s is not ready\n", resolved)
		} else {
			fmt.Fprintln(os.Stderr, "no ready tasks")
		}
		os.Exit(1)
	}
	if err != nil {
		return err
	}
	return printClaimedTask(t, reaped, *asJSON)
}

// printClaimedTask prints a freshly-claimed task and, when the claim-time
// auto-reap freed stale foreign locks, surfaces their ids. In JSON mode the ids
// ride a reaped_locks field embedded ALONGSIDE the flat task fields (omitempty →
// a no-reap claim is byte-identical to the prior task-only JSON). In human mode
// they print as a trailing line on stdout (in addition to claimRemote's per-lock
// stderr log), so a reap is visible in the claim's own output.
func printClaimedTask(t *Task, reaped []string, asJSON bool) error {
	if asJSON {
		return printJSON(struct {
			*Task
			ReapedLocks []string `json:"reaped_locks,omitempty"`
		}{Task: t, ReapedLocks: reaped})
	}
	if err := printTask(t, false); err != nil {
		return err
	}
	if len(reaped) > 0 {
		fmt.Printf("  reaped stale locks: %s\n", strings.Join(reaped, ", "))
	}
	return nil
}

// taskRelease lands a claimed task in a deliberate state and unlocks it. The
// holder's session must match (WHERE id=? AND locked_by=?); --status is
// required so a release always commits to open, blocked, or done.
func taskRelease(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb task release <id> --session <id> --status <open|blocked|done|dropped> [--note T]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task release", flag.ContinueOnError)
	session := fs.String("session", "", "session ID releasing the task (required)")
	status := fs.String("status", "", "new status: open|blocked|done|dropped (required)")
	note := fs.String("note", "", "note appended with author=session")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	// Lock-holder identity: --session wins, else TASKDB_SESSION (exported by
	// the wave provisioner's .taskdb-session). No synthetic fallback — an
	// unresolved identity stays empty so the check below still refuses.
	sess := resolveSession(*session)
	if sess == "" {
		return fmt.Errorf("--session is required")
	}
	if *status == "" {
		return fmt.Errorf("--status is required")
	}
	validStatuses := map[string]bool{"open": true, "blocked": true, "done": true, "dropped": true}
	if !validStatuses[*status] {
		return fmt.Errorf("invalid status %q; must be one of: open, blocked, done, dropped", *status)
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	if _, err := releaseTask(db, id, sess, *status, *note); err != nil {
		return err
	}
	fmt.Printf("released task %s → %s\n", id, *status)
	return nil
}

// taskReap force-releases stale locks (held longer than --age, default
// staleLockThreshold) and, with --requeue, flips orphaned unlocked in-progress
// tasks back to open. The dispatcher runs it at loop start to recover crashed
// agents' claims.
func taskReap(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("task reap", flag.ContinueOnError)
	age := fs.Duration("age", staleLockThreshold, "release locks older than this")
	requeue := fs.Bool("requeue", false, "also flip unlocked in-progress tasks back to open")
	dryRun := fs.Bool("dry-run", false, "report without mutating")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	reaped, err := reapLocks(db, *age, *requeue, *dryRun)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(reaped)
	}
	if len(reaped) == 0 {
		fmt.Println("nothing to reap")
		return nil
	}
	verb := "reaped"
	if *dryRun {
		verb = "would reap"
	}
	for _, r := range reaped {
		fmt.Printf("%s %s (%s)\n", verb, r.ID, r.Reason)
	}
	return nil
}

// taskSearch runs an FTS5 search over task title/body, best match first. Raw
// input is wrapped as a quoted phrase unless --raw, which opts into the FTS5
// mini-language (and may raise a syntax error the message names).
func taskSearch(db *sql.DB, args []string) error {
	query, rest, err := peelID(args, "taskdb task search <query> [--limit 20] [--raw] [--json]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("task search", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "max results")
	raw := fs.Bool("raw", false, "treat the query as raw FTS5 syntax")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	tasks, err := searchTasks(db, query, *limit, *raw)
	if err != nil {
		if *raw {
			return fmt.Errorf("%w (--raw uses the FTS5 query syntax: AND/OR/NOT, \"phrases\", prefix*)", err)
		}
		return err
	}
	if *asJSON {
		return printJSON(tasks)
	}
	printTaskTable(tasks)
	return nil
}

// helpers

func getTask(db *sql.DB, id string) (*Task, error) {
	rows, err := db.Query(`SELECT id, title, body, status, priority, parent_id, branch, locked_by, locked_at, created_at, updated_at FROM tasks WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("task %s not found", id)
	}
	return scanTask(rows)
}

func printTask(t *Task, asJSON bool) error {
	if asJSON {
		return printJSON(t)
	}
	lockInfo := ""
	if t.LockedBy != "" {
		lockInfo = fmt.Sprintf(" [locked by %s]", t.LockedBy)
	}
	parent := ""
	if t.ParentID != "" {
		parent = fmt.Sprintf(" (parent: %s)", t.ParentID)
	}
	fmt.Printf("[%s] %s (p%d) — %s%s%s\n", t.ID, t.Title, t.Priority, t.Status, parent, lockInfo)
	if t.Body != "" {
		fmt.Printf("  %s\n", strings.ReplaceAll(t.Body, "\n", "\n  "))
	}
	if len(t.DependsOn) > 0 {
		fmt.Printf("  depends on: %s\n", strings.Join(t.DependsOn, ", "))
	}
	return nil
}

func printTaskTable(tasks []*Task) {
	if len(tasks) == 0 {
		fmt.Println("no tasks")
		return
	}
	fmt.Printf("%-26s  %-3s  %-12s  %s\n", "ID", "PRI", "STATUS", "TITLE")
	fmt.Println(strings.Repeat("-", 70))
	for _, t := range tasks {
		lock := ""
		if t.LockedBy != "" {
			lock = " 🔒"
		}
		fmt.Printf("%-26s  %-3d  %-12s  %s%s\n", t.ID, t.Priority, t.Status, t.Title, lock)
	}
}

func printTaskTree(tasks []*Task) {
	byID := make(map[string]*Task, len(tasks))
	var roots []*Task
	for _, t := range tasks {
		byID[t.ID] = t
	}
	for _, t := range tasks {
		if t.ParentID == "" {
			roots = append(roots, t)
		}
	}
	var print func(t *Task, indent string)
	print = func(t *Task, indent string) {
		lock := ""
		if t.LockedBy != "" {
			lock = " 🔒"
		}
		fmt.Printf("%s[%s] %s (%s)%s\n", indent, t.ID, t.Title, t.Status, lock)
		for _, child := range tasks {
			if child.ParentID == t.ID {
				print(child, indent+"  ")
			}
		}
	}
	for _, r := range roots {
		print(r, "")
	}
	_ = byID
}

func printJSON(v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}
