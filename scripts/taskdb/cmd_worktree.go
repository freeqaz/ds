// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The worktree family is registry-only: the binary never execs git or shell
// scripts. scripts/setup_worktree.sh provisions and calls register;
// scripts/rm_worktree.sh tears down and calls unregister (docs/22 §3).
func cmdWorktree(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb worktree <register|list|unregister|prune>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "register":
		return worktreeRegister(db, rest)
	case "list":
		return worktreeList(db, rest)
	case "unregister":
		return worktreeUnregister(db, rest)
	case "prune":
		return worktreePrune(db, rest)
	default:
		return fmt.Errorf("unknown worktree subcommand: %s", sub)
	}
}

// worktreeRegister upserts the registry row keyed by path and sets
// tasks.branch — the moment the branch becomes durable (it exists in git now,
// so it freezes into the task's JSON; claiming never mints a branch).
// Re-registering the same task/path pair refreshes branch/base and bumps
// last_used_at.
func worktreeRegister(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb worktree register <task-id> --path <abs> --branch <b> --base <commit>")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("worktree register", flag.ContinueOnError)
	path := fs.String("path", "", "absolute worktree path (required)")
	branch := fs.String("branch", "", "git branch checked out in the worktree (required)")
	base := fs.String("base", "", "short commit the branch started from (required)")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *path == "" {
		return fmt.Errorf("--path is required")
	}
	if *branch == "" {
		return fmt.Errorf("--branch is required")
	}
	if *base == "" {
		return fmt.Errorf("--base is required")
	}
	if !filepath.IsAbs(*path) {
		return fmt.Errorf("--path must be absolute, got %q", *path)
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}

	// The owner-check and the upsert must be atomic: a concurrent register of the
	// same path between a bare SELECT and the write could let two tasks claim it.
	// One transaction (write lock held up front via _txlock=immediate) closes the
	// TOCTOU; the SELECT still resolves the owner for the exact error wording.
	now := timeToMs(time.Now())
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// A path belongs to at most one task.
	var owner string
	err = tx.QueryRow(`SELECT task_id FROM worktrees WHERE path=?`, *path).Scan(&owner)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if owner != "" && owner != id {
		return fmt.Errorf("path %s already registered to task %s", *path, owner)
	}

	if _, err := tx.Exec(
		`INSERT INTO worktrees(path,task_id,branch,base_ref,created_at,last_used_at) VALUES(?,?,?,?,?,?)
		ON CONFLICT(path) DO UPDATE SET branch=excluded.branch, base_ref=excluded.base_ref, last_used_at=excluded.last_used_at`,
		*path, id, *branch, *base, now, now,
	); err != nil {
		return err
	}
	res, err := tx.Exec(`UPDATE tasks SET branch=?, updated_at=? WHERE id=?`, *branch, now, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("task %s not found", id)
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	if *asJSON {
		w, err := worktreeByPath(db, *path)
		if err != nil {
			return err
		}
		return printJSON(w)
	}
	fmt.Printf("registered worktree %s for task %s (branch %s, base %s)\n", *path, id, *branch, *base)
	return nil
}

// worktreeListRow is the list shape: the registry row plus the joined task
// fields and a liveness flag (a path that fails os.Stat is missing).
type worktreeListRow struct {
	Worktree
	TaskTitle  string `json:"task_title,omitempty"`
	TaskStatus string `json:"task_status,omitempty"`
	Missing    bool   `json:"missing,omitempty"`
}

func worktreeList(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("worktree list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rows, err := db.Query(
		`SELECT w.path, w.task_id, w.branch, w.base_ref, w.created_at, w.last_used_at, t.title, t.status
		FROM worktrees w LEFT JOIN tasks t ON t.id = w.task_id ORDER BY w.created_at`)
	if err != nil {
		return err
	}
	defer rows.Close()

	list := []*worktreeListRow{} // empty, not nil: --json prints [] when drained
	for rows.Next() {
		var r worktreeListRow
		var createdMs, lastUsedMs int64
		var title, status sql.NullString
		if err := rows.Scan(&r.Path, &r.TaskID, &r.Branch, &r.BaseRef, &createdMs, &lastUsedMs, &title, &status); err != nil {
			return err
		}
		r.CreatedAt = msToTime(createdMs)
		r.LastUsedAt = msToTime(lastUsedMs)
		r.TaskTitle = title.String
		r.TaskStatus = status.String
		if _, err := os.Stat(r.Path); err != nil {
			r.Missing = true
		}
		list = append(list, &r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if *asJSON {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("no worktrees")
		return nil
	}
	fmt.Printf("%-26s  %-12s  %-18s  %s\n", "TASK", "STATUS", "BRANCH", "PATH")
	fmt.Println(strings.Repeat("-", 70))
	for _, r := range list {
		missing := ""
		if r.Missing {
			missing = "  (missing)"
		}
		fmt.Printf("%-26s  %-12s  %-18s  %s%s\n", r.TaskID, r.TaskStatus, r.Branch, r.Path, missing)
	}
	return nil
}

func worktreeUnregister(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb worktree unregister <task-id> [--clear-branch]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("worktree unregister", flag.ContinueOnError)
	clearBranch := fs.Bool("clear-branch", false, "also empty tasks.branch (use when the git ref was deleted)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	id, err = resolveTaskID(db, id)
	if err != nil {
		return err
	}
	res, err := db.Exec(`DELETE FROM worktrees WHERE task_id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("worktree for task %s not found", id)
	}
	if *clearBranch {
		// Keeps frozen JSON truthful once rm_worktree.sh --delete-branch has
		// removed the ref; by default the branch stays — it is the durable
		// result channel until merged.
		if _, err := db.Exec(`UPDATE tasks SET branch='', updated_at=? WHERE id=?`, timeToMs(time.Now()), id); err != nil {
			return err
		}
		fmt.Printf("unregistered worktree for task %s (branch cleared)\n", id)
		return nil
	}
	fmt.Printf("unregistered worktree for task %s\n", id)
	return nil
}

// worktreePrune drops registry rows whose path no longer exists on disk
// (crashed or hand-removed worktrees). The dispatcher runs it at startup.
func worktreePrune(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("worktree prune", flag.ContinueOnError)
	dryRun := fs.Bool("dry-run", false, "report without deleting")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	rows, err := db.Query(`SELECT path, task_id, branch, base_ref, created_at, last_used_at FROM worktrees ORDER BY created_at`)
	if err != nil {
		return err
	}
	defer rows.Close()
	dead := []*Worktree{} // empty, not nil: --json prints [] when clean
	for rows.Next() {
		w, err := scanWorktree(rows)
		if err != nil {
			return err
		}
		if _, err := os.Stat(w.Path); err != nil {
			dead = append(dead, w)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if !*dryRun {
		for _, w := range dead {
			if _, err := db.Exec(`DELETE FROM worktrees WHERE path=?`, w.Path); err != nil {
				return err
			}
		}
	}

	if *asJSON {
		return printJSON(dead)
	}
	if len(dead) == 0 {
		fmt.Println("nothing to prune")
		return nil
	}
	verb := "pruned"
	if *dryRun {
		verb = "would prune"
	}
	for _, w := range dead {
		fmt.Printf("%s %s (task %s)\n", verb, w.Path, w.TaskID)
	}
	return nil
}

// worktreeByPath fetches one registry row for printing after an upsert.
func worktreeByPath(db *sql.DB, path string) (*Worktree, error) {
	rows, err := db.Query(`SELECT path, task_id, branch, base_ref, created_at, last_used_at FROM worktrees WHERE path=?`, path)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, fmt.Errorf("worktree %s not found", path)
	}
	return scanWorktree(rows)
}
