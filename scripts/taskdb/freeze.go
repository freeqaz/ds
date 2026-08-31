// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cmdFreeze(db *sql.DB, args []string) error {
	// freeze is ADDITIVE by default: it writes/updates a task-/note-*.json for
	// every row in THIS DB and leaves any other tasks/*.json on disk UNTOUCHED.
	// It does NOT delete files for ids absent from the DB.
	//
	// Why: tasks/*.json is a SHARED, git-tracked store written by many
	// coordinators and machines, each with its own gitignored taskdb.sqlite. The
	// old freeze did `os.Remove` of EVERY task-/note-*.json then rewrote only the
	// local DB's rows — so a freeze run from a DB that had not thawed another
	// coordinator's/machine's tasks DELETED those tasks' files, and the
	// wholesale `git add tasks/` in the pre-commit hook committed the deletion
	// (the 2026-06-13 cross-machine clobber: a pure "tasks: sync freeze" commit
	// dropped 33 in-flight task files). Additive-by-default makes a diverged DB
	// unable to author a deletion at all.
	//
	// --gc restores orphan collection (remove JSONs for ids no longer in the DB)
	// for a DELIBERATE single-owner cleanup. Never run --gc as a shared/automated
	// step — only when you intend this DB to be authoritative over what exists.
	fs := flag.NewFlagSet("freeze", flag.ContinueOnError)
	gc := fs.Bool("gc", false, "also DELETE task-/note-*.json for rows absent from this live DB (orphan collection; deliberate single-owner cleanup only — NOT for shared/automated freezes)")
	force := fs.Bool("force", false, "overwrite even when this DB would REGRESS a terminal (done/dropped) task backward — a deliberate single-owner reopen; the default refuses such regressions to keep a stale DB from un-completing a finished task")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\nusage: taskdb freeze [--gc] [--force]\n(run `taskdb` with no arguments for full help)", err)
	}
	if extra := fs.Args(); len(extra) > 0 {
		return fmt.Errorf("unexpected argument %q\nusage: taskdb freeze [--gc] [--force]", extra[0])
	}

	dir, err := tasksDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tasks, err := allTasks(db)
	if err != nil {
		return fmt.Errorf("freeze tasks: %w", err)
	}
	notes, err := allNotes(db)
	if err != nil {
		return fmt.Errorf("freeze notes: %w", err)
	}

	if *gc {
		// Orphan collection: remove only files whose id is NOT in this DB; the
		// writes below refresh the rest. (Net effect matches the old
		// remove-all-then-write, but gated behind the explicit flag.)
		keep := make(map[string]bool, len(tasks)+len(notes))
		for _, t := range tasks {
			keep[filepath.Join(dir, "task-"+t.ID+".json")] = true
		}
		for _, n := range notes {
			keep[filepath.Join(dir, "note-"+n.ID+".json")] = true
		}
		for _, pat := range []string{"task-*.json", "note-*.json"} {
			existing, _ := filepath.Glob(filepath.Join(dir, pat))
			for _, f := range existing {
				if !keep[f] {
					os.Remove(f)
				}
			}
		}
	}

	// Regression guard (symmetric to thaw's drop-guard and the merge driver's
	// most-progressed-wins + newest-updated_at-wins): freeze is the ONE direction
	// with no protection — it blindly writes each DB row over disk, and because a
	// freeze→commit is a clean edit, the 3-way merge driver never fires to catch
	// it. A freeze from a STALE DB (one that never thawed a peer's completion —
	// the d4e1ad11 incident, enabled by inactive hooks) thus overwrote 6 already
	// `done` tasks/*.json with `open`, un-completing finished work. Two skips,
	// both overridable with --force:
	//
	//   P1 — terminal-status regression: refuse to walk a TERMINAL on-disk status
	//   (done/dropped) backward, regardless of timestamps. The acute data-loss
	//   case; guarding ONLY terminal regressions is deliberate so non-terminal
	//   churn (a legitimate in-progress→open reopen, an unblock) still propagates.
	//
	//   P4 — newer-on-disk content: refuse to overwrite a row whose on-disk
	//   updated_at is NEWER than this DB's (a peer froze a later edit; or, on a
	//   contended tree, a merge pulled newer tasks/*.json that this DB hasn't
	//   thawed — the canonical merge pattern disables the post-merge thaw, so the
	//   DB legitimately trails the merged JSON). Writing the older DB row would
	//   regress title/body/priority. Comparison is at the DB's millisecond
	//   granularity so an unchanged steady-state row (equal timestamps) is never
	//   skipped.
	var kept []string
	for _, t := range tasks {
		path := filepath.Join(dir, "task-"+t.ID+".json")
		if !*force {
			if ds, du, ok := diskTaskMeta(path); ok {
				nd := normalizeStatus(ds)
				switch {
				case nd.IsTerminal() && statusRank(nd) > statusRank(t.Status):
					kept = append(kept, fmt.Sprintf("%s — terminal regression (on disk %s → this DB %s)%s", t.ID, nd, normalizeStatus(t.Status), reconcileSkippedDeps(path, t)))
					continue
				case du.Truncate(time.Millisecond).After(t.UpdatedAt.Truncate(time.Millisecond)):
					kept = append(kept, fmt.Sprintf("%s — on-disk row is newer (disk updated_at %s > this DB %s)%s", t.ID, du.UTC().Format(time.RFC3339), t.UpdatedAt.UTC().Format(time.RFC3339), reconcileSkippedDeps(path, t)))
					continue
				}
			}
		}
		if err := writeJSON(path, t); err != nil {
			return err
		}
	}
	for _, n := range notes {
		if err := writeJSON(filepath.Join(dir, "note-"+n.ID+".json"), n); err != nil {
			return err
		}
	}

	// Loud, but NOT a failure: exit 0 so the pre-commit hook still stages the
	// protected tasks/ (it only `git add`s on a zero-exit freeze; a non-zero here
	// would make every commit on a tree with any stale terminal silently carry no
	// task state). The skip itself is the protection; this just puts it on record.
	if len(kept) > 0 {
		fmt.Fprintf(os.Stderr,
			"taskdb freeze: kept %d task(s) at their on-disk state — this DB would have REGRESSED them (a terminal status walked backward, or an older row overwriting a newer on-disk edit; likely a stale DB that never thawed). Left tasks/*.json UNTOUCHED for:\n  %s\n  to sync this DB forward first: taskdb thaw\n  to propagate this DB anyway (a deliberate reopen/override): taskdb freeze --force\n",
			len(kept), strings.Join(kept, "\n  "))
	}

	mode := "additive — foreign files left untouched"
	if *gc {
		mode = "gc — removed orphan files absent from this DB"
	}
	wrote := len(tasks) - len(kept)
	skipped := ""
	if len(kept) > 0 {
		skipped = fmt.Sprintf(" (%d kept at on-disk state — regression guarded; --force to override)", len(kept))
	}
	fmt.Printf("frozen: %d tasks%s, %d notes → %s [%s]\n", wrote, skipped, len(notes), dir, mode)
	return nil
}

// diskTaskMeta reads ONLY the status and updated_at of an existing task-<id>.json
// so the freeze regression guard can compare them against the live DB without a
// full parse. ok=false when the file is absent, unreadable, or malformed — a
// missing/garbled file is not a regression to protect, so freeze writes it.
func diskTaskMeta(path string) (Status, time.Time, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", time.Time{}, false
	}
	var probe struct {
		Status    Status    `json:"status"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	if err := json.Unmarshal(b, &probe); err != nil || probe.Status == "" {
		return "", time.Time{}, false
	}
	return probe.Status, probe.UpdatedAt, true
}

// reconcileSkippedDeps is the F6 dep-edge-loss guard. The freeze (and stage-owned)
// regression guard SKIPS a task wholesale — leaving its on-disk file UNTOUCHED —
// when the on-disk row is terminal-newer (P1) or strictly newer by updated_at
// (P4, ROUTINE on a contended tree after a canonical merge pulled newer
// tasks/*.json this DB hasn't thawed). But depends_on is a UNION-merged field
// (the merge driver never drops an edge either side added): if the DB row gained
// a NEW depends_on edge while its updated_at trails the on-disk file, a blind skip
// would silently lose that edge — it never reaches disk and is invisible (thaw's
// drop-guard only catches the opposite direction).
//
// This reconciles the SKIPPED task's edges ADDITIVELY and surgically: it unions
// the DB row's depends_on into the on-disk file's depends_on (the same union
// semantics the merge driver uses) and writes back ONLY when the union ADDS edges,
// touching ONLY the depends_on field — every other field is re-read from the
// on-disk file and written back unchanged, so the protected scalars (status,
// title, body, priority, parent, branch, updated_at) the regression guard
// deliberately keeps are never regressed. Returns a short " + edges …" suffix
// naming the newly-propagated edges for the kept/skip message (loud, on record),
// or "" when nothing was added. Any read/write/parse failure leaves the file as
// the skip already left it (untouched) and reports nothing extra — never a fatal:
// the dep reconciliation is a best-effort additive bonus on top of the skip, and
// must not turn a guarded skip into an error.
func reconcileSkippedDeps(path string, t *Task) string {
	if len(t.DependsOn) == 0 {
		return "" // DB row has no edges to propagate
	}
	var disk Task
	if err := readJSON(path, &disk); err != nil {
		return "" // unreadable/garbled — leave as the skip left it
	}
	have := make(map[string]bool, len(disk.DependsOn))
	for _, d := range disk.DependsOn {
		have[d] = true
	}
	var added []string
	for _, d := range t.DependsOn {
		if d != "" && !have[d] {
			added = append(added, d)
		}
	}
	if len(added) == 0 {
		return "" // disk already carries every DB edge — nothing to add
	}
	// Touch ONLY depends_on: keep every other field at its on-disk value, set the
	// union, write back. unionSorted matches the merge driver (sorted, deduped).
	disk.DependsOn = unionSorted(disk.DependsOn, t.DependsOn)
	if err := writeJSON(path, &disk); err != nil {
		return "" // write failed — the skip already left the file untouched
	}
	return fmt.Sprintf(" + propagated %d new dep edge(s) (depends_on only, scalars untouched): %s", len(added), strings.Join(added, ", "))
}

func allTasks(db *sql.DB) ([]*Task, error) {
	rows, err := db.Query(`SELECT id, title, body, status, priority, parent_id, branch, locked_by, locked_at, created_at, updated_at FROM tasks ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := attachDeps(db, out); err != nil {
		return nil, err
	}
	return out, nil
}

func allNotes(db *sql.DB) ([]*Note, error) {
	rows, err := db.Query(`SELECT id, task_id, body, author, created_at FROM notes ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Note
	for rows.Next() {
		n, err := scanNote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	// Write-temp-then-rename so a concurrent reader never observes a
	// half-written task-/note-*.json. With many coordinators each freezing its
	// own DB into the shared tasks/ tree, a plain os.WriteFile (truncate +
	// write) lets a parallel `git add tasks/`, another freeze, or a `git status`
	// catch a partial file. rename(2) is atomic within one filesystem; the temp
	// lives in the same dir to guarantee that, and CreateTemp's unique suffix
	// keeps two simultaneous freezes of the same id from colliding on the temp
	// path. The .tmp- prefix keeps these out of the task-*/note-* globs (freeze
	// --gc keepset, the thaw drop-guard) and is gitignored.
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0644); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
