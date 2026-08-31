// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// thawWarnOut is where thaw's loud dangling-reference warnings go (os.Stderr in
// production, a capture buffer in tests — mirrors searchWarnOut). A pruned
// reference is NEVER silent: the goal is resilience, not hiding corruption, so
// every dropped edge / NULLed parent / skipped note is named here.
var thawWarnOut io.Writer = os.Stderr

// rejectUnknownFlags fails a subcommand that does NOT parse flags when it is
// handed any token that looks like one (a leading '-'). The motivating incident
// was `taskdb thaw --help`: thaw took no args, so the flag was silently dropped
// and a real thaw ran (wiping 13 live-only tasks). Every flagless verb routes
// its trailing args through here so an unrecognized flag is a usage error, not a
// no-op. `usage` is echoed so the caller sees the verb's real shape (use bare
// `taskdb` for full help — there is no per-subcommand --help).
func rejectUnknownFlags(args []string, usage string) error {
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return fmt.Errorf("unknown flag %q\nusage: %s\n(run `taskdb` with no arguments for full help)", a, usage)
		}
	}
	if len(args) > 0 {
		return fmt.Errorf("unexpected argument %q\nusage: %s", args[0], usage)
	}
	return nil
}

func cmdThaw(db *sql.DB, args []string) error {
	// thaw parses exactly one flag, --force; any other flag (notably --help, the
	// incident trigger) is rejected by flag.ContinueOnError rather than executing
	// a thaw. We never serve a thaw to a caller who typed something we don't
	// understand.
	fs := flag.NewFlagSet("thaw", flag.ContinueOnError)
	force := fs.Bool("force", false, "proceed even though the rebuild would drop live-only tasks or notes")
	autoFreezeFlag := fs.Bool("auto-freeze", false, "on a live-only-DROP refusal ONLY, additively write the dropped rows (+ live-only dep edges) to tasks/*.json via the freeze path, then proceed instead of refusing — the hooks-only remedy (also enabled by TASKDB_THAW_AUTOFREEZE=1). Never masks an FK/prune error.")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w\nusage: taskdb thaw [--force] [--auto-freeze]\n(run `taskdb` with no arguments for full help)", err)
	}
	if extra := fs.Args(); len(extra) > 0 {
		return fmt.Errorf("unexpected argument %q\nusage: taskdb thaw [--force] [--auto-freeze]", extra[0])
	}
	// --auto-freeze is opt-in via the flag OR the TASKDB_THAW_AUTOFREEZE=1 env var
	// (the hooks pass the flag; the env is the same knob for a manual/scripted run).
	autoFreeze := *autoFreezeFlag || os.Getenv("TASKDB_THAW_AUTOFREEZE") == "1"

	dir, err := tasksDir()
	if err != nil {
		return err
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		fmt.Println("thaw: no tasks/ directory found, nothing to load")
		return nil
	}

	// Drop-guard: a thaw DELETEs every task AND every note and reinserts from
	// tasks/*.json, so a row that lives only in the DB (a parallel wave's
	// freshly-minted task or note that has not been frozen + committed yet) would
	// be silently wiped. Diff DB IDs against the JSON BEFORE mutating anything and
	// refuse — naming the per-kind counts and the IDs — unless --force is set.
	// This runs before db.Begin(), so a refused thaw never opens a transaction and
	// cannot corrupt state. A no-drop thaw falls straight through and still exits
	// 0, keeping the non-interactive post-checkout/merge/rewrite hooks working.
	dropped, err := thawDroppedIDs(db, dir)
	if err != nil {
		return err
	}
	droppedNotes, err := thawDroppedNoteIDs(db, dir)
	if err != nil {
		return err
	}
	droppedDeps, err := thawDroppedDepEdges(db, dir)
	if err != nil {
		return err
	}
	if len(dropped) > 0 || len(droppedNotes) > 0 || len(droppedDeps) > 0 {
		switch {
		case *force:
			// Fall through: --force intends to DROP the live-only rows; the drop is
			// reported after the commit below so it stays on the record.
		case autoFreeze:
			// Hook-path remedy (docs/23 OQ3): instead of refusing, additively write
			// task-/note-*.json for exactly the dropped ids (+ patch live-only dep
			// edges into their owner task JSON) via the freeze writeJSON path, so the
			// rows survive in BOTH stores. The freshly-written JSONs are untracked and
			// travel with the next commit (the pre-commit hook stages tasks/
			// wholesale). This ONLY intercepts the live-only-DROP cause — it runs
			// before db.Begin(), while an FK/dangling-reference error surfaces later
			// inside the transaction, so --auto-freeze can never mask a prune-and-warn
			// or FK failure.
			if err := thawAutoFreezeDropped(db, dir, dropped, droppedNotes, droppedDeps); err != nil {
				return fmt.Errorf("thaw --auto-freeze: %w", err)
			}
			// The drop-diff is now empty BY CONSTRUCTION (we just wrote every dropped
			// id + edge). Recompute and assert before mutating the DB: a non-empty
			// residue means the auto-freeze missed something and we must not proceed
			// (which would silently drop it after all).
			if dropped, err = thawDroppedIDs(db, dir); err != nil {
				return err
			}
			if droppedNotes, err = thawDroppedNoteIDs(db, dir); err != nil {
				return err
			}
			if droppedDeps, err = thawDroppedDepEdges(db, dir); err != nil {
				return err
			}
			if len(dropped) > 0 || len(droppedNotes) > 0 || len(droppedDeps) > 0 {
				return fmt.Errorf("thaw --auto-freeze: internal error — %d task(s), %d note(s), %d dep edge(s) still live-only after auto-freeze; refusing to proceed",
					len(dropped), len(droppedNotes), len(droppedDeps))
			}
		default:
			return droppedRowsError(dropped, droppedNotes, droppedDeps)
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Save live claims before the wipe: a thaw on the primary checkout (e.g.
	// post-merge while agents are dispatched) must not release running agents'
	// locks. Carried in-transaction only — nothing here is ever serialized.
	claims, err := thawLiveClaims(tx)
	if err != nil {
		return err
	}

	// Drop and re-insert to stay idempotent across branch switches.
	if _, err := tx.Exec(`DELETE FROM notes`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM task_deps`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM tasks`); err != nil {
		return err
	}

	taskFiles, _ := filepath.Glob(filepath.Join(dir, "task-*.json"))
	noteFiles, _ := filepath.Glob(filepath.Join(dir, "note-*.json"))

	// Insert tasks before dep edges and notes (FK constraints); dep edges
	// wait until every task row exists since they reference arbitrary tasks.
	//
	// parent_id is wired in a SECOND pass, not inline: a child can be re-parented
	// (`task edit --parent`) onto a task created LATER, so the parent's ULID sorts
	// AFTER the child's. taskFiles is in lexical id order (filepath.Glob), so the
	// child is reached first; setting parent_id inline would violate the
	// tasks(parent_id)->tasks(id) FK because the parent row does not exist yet
	// (foreign_keys is ON — the cold-thaw failure on the re-parented 01KV7SBQ6C…
	// child of 01KV8XSNEX…). Insert every task with parent_id=NULL, then wire
	// parents once all rows exist: order-independent, and a genuinely dangling
	// parent still surfaces with its own task id.
	// thawedIDs is the set of task ids actually being loaded this thaw — the
	// authoritative target set for every reference. A depends_on / parent_id /
	// note.task_id pointing OUTSIDE this set is a dangling reference: with
	// foreign_keys ON it would otherwise abort the whole single-tx thaw
	// ("FOREIGN KEY constraint failed (787)", 0 rows loaded) over one orphan. We
	// instead prune the dangling reference (drop the edge / NULL the parent /
	// skip the note) and LOUDLY warn, so the valid remainder still loads — and
	// note that --force does NOT help an FK error (it scopes only the live-only
	// DROP-guard above), so a single orphan must never be allowed to strand the
	// rebuild. Pruning is on the record, never silent.
	thawedIDs := make(map[string]bool, len(taskFiles))
	deps := map[string][]string{}
	parents := map[string]string{}
	for _, f := range taskFiles {
		var t Task
		if err := readJSON(f, &t); err != nil {
			return fmt.Errorf("thaw %s: %w", f, err)
		}
		_, err := tx.Exec(
			`INSERT INTO tasks(id,title,body,status,priority,parent_id,branch,created_at,updated_at) VALUES(?,?,?,?,?,NULL,?,?,?)`,
			t.ID, t.Title, t.Body, t.Status, t.Priority, t.Branch,
			timeToMs(t.CreatedAt), timeToMs(t.UpdatedAt),
		)
		if err != nil {
			return fmt.Errorf("thaw task %s: %w", t.ID, err)
		}
		thawedIDs[t.ID] = true
		if t.ParentID != "" {
			parents[t.ID] = t.ParentID
		}
		if len(t.DependsOn) > 0 {
			deps[t.ID] = t.DependsOn
		}
	}

	// Wire parent_id now that every task row exists (see above): the FK is
	// satisfiable regardless of the order parents and children were inserted.
	// A parent_id pointing at a task absent from this thaw is dangling — NULL it
	// (mirroring the schema's ON DELETE SET NULL intent) and warn, rather than
	// letting the tasks(parent_id)->tasks(id) FK abort the thaw.
	for id, parent := range parents {
		if !thawedIDs[parent] {
			fmt.Fprintf(thawWarnOut,
				"taskdb thaw: ⚠ DANGLING parent_id — task %s names missing parent %s; parent_id NULLed (the parent task is absent from tasks/*.json)\n",
				id, parent)
			continue
		}
		if _, err := tx.Exec(`UPDATE tasks SET parent_id=? WHERE id=?`, parent, id); err != nil {
			return fmt.Errorf("thaw task %s parent %s: %w", id, parent, err)
		}
	}

	// A depends_on edge whose target is absent from this thaw is dangling — drop
	// it and warn, rather than letting the task_deps(depends_on)->tasks(id) FK
	// abort the thaw. The source id is always present (it came from a task file).
	for id, on := range deps {
		for _, dep := range on {
			if !thawedIDs[dep] {
				fmt.Fprintf(thawWarnOut,
					"taskdb thaw: ⚠ DANGLING depends_on — edge %s -> %s dropped; target task %s is absent from tasks/*.json\n",
					id, dep, dep)
				continue
			}
			if _, err := tx.Exec(`INSERT INTO task_deps(task_id,depends_on) VALUES(?,?)`, id, dep); err != nil {
				return fmt.Errorf("thaw dep %s → %s: %w", id, dep, err)
			}
		}
	}

	notesLoaded := 0
	for _, f := range noteFiles {
		var n Note
		if err := readJSON(f, &n); err != nil {
			return fmt.Errorf("thaw %s: %w", f, err)
		}
		// A note whose task_id names a task absent from this thaw is dangling —
		// skip it and warn, rather than letting the notes(task_id)->tasks(id) FK
		// abort the thaw. (A note with an empty task_id is unattached and always
		// loads.)
		if n.TaskID != "" && !thawedIDs[n.TaskID] {
			fmt.Fprintf(thawWarnOut,
				"taskdb thaw: ⚠ DANGLING note.task_id — note %s skipped; its task %s is absent from tasks/*.json\n",
				n.ID, n.TaskID)
			continue
		}
		var taskID any = nil
		if n.TaskID != "" {
			taskID = n.TaskID
		}
		_, err := tx.Exec(
			`INSERT INTO notes(id,task_id,body,author,created_at) VALUES(?,?,?,?,?)`,
			n.ID, taskID, n.Body, n.Author, timeToMs(n.CreatedAt),
		)
		if err != nil {
			return fmt.Errorf("thaw note %s: %w", n.ID, err)
		}
		notesLoaded++
	}

	carried, err := thawRestoreClaims(tx, claims)
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// notesLoaded (not len(noteFiles)) so the count is honest when an orphan note
	// was skipped above for a dangling task_id.
	fmt.Printf("thawed: %d tasks, %d notes (carried %d live claims)\n", len(taskFiles), notesLoaded, carried)
	if len(dropped) > 0 {
		// Reachable only with --force: report what the override discarded so the
		// drop is on the record, not silent.
		fmt.Printf("thaw: --force dropped %d live-only task(s): %s\n", len(dropped), strings.Join(dropped, ", "))
	}
	if len(droppedNotes) > 0 {
		// Same as the task path: a --force drop of a live-only note is on the
		// record, never silent.
		fmt.Printf("thaw: --force dropped %d live-only note(s): %s\n", len(droppedNotes), strings.Join(droppedNotes, ", "))
	}
	if len(droppedDeps) > 0 {
		// Same as the task/note paths: a --force drop of a live-only dep edge is
		// on the record, never silent.
		fmt.Printf("thaw: --force dropped %d live-only dep edge(s): %s\n", len(droppedDeps), strings.Join(droppedDeps, ", "))
	}
	return nil
}

// thawDroppedIDs returns the task IDs present in the live DB but absent from
// tasks/*.json — exactly the rows a thaw would erase. Sorted for a stable
// message. tasks/ being the canonical store, anything here is a live-only row a
// freeze has not yet committed.
func thawDroppedIDs(db *sql.DB, dir string) ([]string, error) {
	// Live DB task IDs.
	rows, err := db.Query(`SELECT id FROM tasks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var liveIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		liveIDs = append(liveIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(liveIDs) == 0 {
		return nil, nil
	}

	// Canonical task IDs encoded in the on-disk filenames (task-<ID>.json). The
	// filename is the authoritative key (freeze writes task-<t.ID>.json), so we
	// read no file bodies here — cheaper, and robust to a malformed body.
	jsonFiles, _ := filepath.Glob(filepath.Join(dir, "task-*.json"))
	jsonIDs := make(map[string]bool, len(jsonFiles))
	for _, f := range jsonFiles {
		base := filepath.Base(f)
		id := strings.TrimSuffix(strings.TrimPrefix(base, "task-"), ".json")
		jsonIDs[id] = true
	}

	var dropped []string
	for _, id := range liveIDs {
		if !jsonIDs[id] {
			dropped = append(dropped, id)
		}
	}
	sort.Strings(dropped)
	return dropped, nil
}

// thawDroppedNoteIDs returns the note IDs present in the live DB but absent from
// the frozen note-*.json files — exactly the notes a thaw would erase (the
// rebuild DELETEs every row in `notes` and reinserts only what is frozen). This
// is the notes counterpart of thawDroppedIDs and shares its shape: the on-disk
// filename (note-<ID>.json, written by freeze) is the authoritative key, so no
// file bodies are read here. Sorted for a stable refusal message.
func thawDroppedNoteIDs(db *sql.DB, dir string) ([]string, error) {
	rows, err := db.Query(`SELECT id FROM notes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var liveIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		liveIDs = append(liveIDs, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(liveIDs) == 0 {
		return nil, nil
	}

	jsonFiles, _ := filepath.Glob(filepath.Join(dir, "note-*.json"))
	jsonIDs := make(map[string]bool, len(jsonFiles))
	for _, f := range jsonFiles {
		base := filepath.Base(f)
		id := strings.TrimSuffix(strings.TrimPrefix(base, "note-"), ".json")
		jsonIDs[id] = true
	}

	var dropped []string
	for _, id := range liveIDs {
		if !jsonIDs[id] {
			dropped = append(dropped, id)
		}
	}
	sort.Strings(dropped)
	return dropped, nil
}

// thawDroppedDepEdges returns the live task_deps edges present in the DB but
// absent from the union of the frozen tasks' DependsOn arrays — exactly the dep
// edges a thaw would erase. The rebuild DELETEs task_deps and reinserts edges
// solely from each task-<ID>.json's DependsOn array, so an edge minted live
// (`taskdb task dep A --on B`) on an already-frozen task A is invisible to the
// task/note guard (A's row exists in both stores; only its edge set differs) and
// is silently dropped by the next thaw — the same loss class. Each live-only edge
// is reported as "A -> B" (task_id -> depends_on). Sorted for a stable refusal.
// The frozen edge key is the file body's DependsOn (not the filename), so unlike
// the task/note diffs this reads the JSON bodies; a malformed body surfaces as a
// thaw error here, before any mutation.
func thawDroppedDepEdges(db *sql.DB, dir string) ([]string, error) {
	// Live DB edges, as "task_id -> depends_on".
	rows, err := db.Query(`SELECT task_id, depends_on FROM task_deps`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var liveEdges []string
	for rows.Next() {
		var taskID, dependsOn string
		if err := rows.Scan(&taskID, &dependsOn); err != nil {
			return nil, err
		}
		liveEdges = append(liveEdges, taskID+" -> "+dependsOn)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(liveEdges) == 0 {
		return nil, nil
	}

	// Union of frozen edges: every task-<ID>.json contributes one edge per entry
	// in its DependsOn array (the same source the reinsert reads), keyed
	// identically to the live edges so the diff is exact.
	taskFiles, _ := filepath.Glob(filepath.Join(dir, "task-*.json"))
	frozenEdges := map[string]bool{}
	for _, f := range taskFiles {
		var t Task
		if err := readJSON(f, &t); err != nil {
			return nil, fmt.Errorf("thaw %s: %w", f, err)
		}
		for _, dep := range t.DependsOn {
			frozenEdges[t.ID+" -> "+dep] = true
		}
	}

	var dropped []string
	for _, e := range liveEdges {
		if !frozenEdges[e] {
			dropped = append(dropped, e)
		}
	}
	sort.Strings(dropped)
	return dropped, nil
}

// droppedRowsError is the refusal a guarded thaw returns when the rebuild would
// drop live-only rows: a per-kind count (tasks, notes, and dep edges), the full
// list per kind, and actionable next steps including a copy-pasteable recovery
// one-liner. The hook path surfaces this on stderr with a non-zero exit and never
// mutates the DB, so the recovery options (freeze first, or knowingly --force)
// stay open. Callers only reach this with at least one dropped task, note, or
// dep edge.
func droppedRowsError(droppedTasks, droppedNotes, droppedDeps []string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "refusing to thaw: %d live-only task(s), %d live-only note(s), and %d live-only dep edge(s) would be DROPPED (present in taskdb.sqlite, absent from tasks/*.json):",
		len(droppedTasks), len(droppedNotes), len(droppedDeps))
	for _, id := range droppedTasks {
		fmt.Fprintf(&b, "\n  task %s", id)
	}
	for _, id := range droppedNotes {
		fmt.Fprintf(&b, "\n  note %s", id)
	}
	for _, edge := range droppedDeps {
		fmt.Fprintf(&b, "\n  dep edge %s", edge)
	}
	b.WriteString("\n\nthese rows have not been frozen to tasks/*.json, so a thaw would erase them.")
	b.WriteString("\nto keep them: run `taskdb freeze` (then commit tasks/) before thawing,")
	b.WriteString("\nor, if you intend to discard them, re-run with `taskdb thaw --force`.")
	b.WriteString("\nrecover with: taskdb freeze && git add tasks/ && taskdb thaw")
	return fmt.Errorf("%s", b.String())
}

// thawAutoFreezeDropped is the `--auto-freeze` remedy (docs/23 OQ3 / risk #5) for
// the live-only-DROP refusal: rather than refuse (droppedRowsError) or discard
// (--force), it ADDITIVELY writes task-/note-*.json for exactly the dropped ids
// and unions each live-only dep edge into its owner task's on-disk JSON, all via
// the same writeJSON path freeze uses. After it returns, the drop-diff is empty
// by construction and the caller proceeds with a normal thaw, so the rows land in
// BOTH stores; the freshly-written JSONs are untracked and travel with the next
// commit (the pre-commit hook stages tasks/ wholesale). It is reached ONLY on the
// live-only-drop cause — an FK/dangling-reference error surfaces later, inside the
// thaw transaction, and is never masked here.
func thawAutoFreezeDropped(db *sql.DB, dir string, droppedTasks, droppedNotes, droppedDeps []string) error {
	// Index the live DB rows once. allTasks attaches each task's depends_on, so a
	// dropped task is written with its full edge set and an edge owner appearing in
	// droppedDeps below is already complete on disk.
	tasks, err := allTasks(db)
	if err != nil {
		return err
	}
	taskByID := make(map[string]*Task, len(tasks))
	for _, t := range tasks {
		taskByID[t.ID] = t
	}
	notes, err := allNotes(db)
	if err != nil {
		return err
	}
	noteByID := make(map[string]*Note, len(notes))
	for _, n := range notes {
		noteByID[n.ID] = n
	}

	// Write each dropped task's JSON. Tasks go first so any dep-edge owner or
	// target that is itself a dropped (live-only) task exists on disk before the
	// edge patch and the subsequent thaw reference it.
	for _, id := range droppedTasks {
		t, ok := taskByID[id]
		if !ok {
			return fmt.Errorf("live-only task %s vanished from the DB before auto-freeze", id)
		}
		if err := writeJSON(filepath.Join(dir, "task-"+t.ID+".json"), t); err != nil {
			return err
		}
	}
	// Write each dropped note's JSON.
	for _, id := range droppedNotes {
		n, ok := noteByID[id]
		if !ok {
			return fmt.Errorf("live-only note %s vanished from the DB before auto-freeze", id)
		}
		if err := writeJSON(filepath.Join(dir, "note-"+n.ID+".json"), n); err != nil {
			return err
		}
	}
	// Patch each live-only dep edge ("A -> B") into owner A's on-disk task JSON. An
	// owner that was a dropped task (written just above) already carries the edge,
	// so the union is a no-op; an owner that was ALREADY frozen (only its edge is
	// live-only) gets the edge unioned into its depends_on with every other field
	// left at its on-disk value, so the pre-existing task's scalars never regress.
	owners := map[string]bool{}
	for _, e := range droppedDeps {
		a, _, ok := strings.Cut(e, " -> ")
		if !ok {
			return fmt.Errorf("malformed live-only dep edge %q", e)
		}
		owners[a] = true
	}
	for a := range owners {
		t, ok := taskByID[a]
		if !ok {
			return fmt.Errorf("live-only dep edge owner %s vanished from the DB before auto-freeze", a)
		}
		if err := unionDepsIntoFile(filepath.Join(dir, "task-"+a+".json"), t.DependsOn); err != nil {
			return err
		}
	}

	// One-line notice on the record (stderr, like the thaw warnings). Hook success
	// swallows it; a manual/scripted run and the tests see it.
	fmt.Fprintf(thawWarnOut,
		"taskdb thaw: --auto-freeze additively wrote %d live-only task(s), %d note(s), and %d dep edge(s) to tasks/*.json (untracked — commit tasks/ to persist), then proceeded\n",
		len(droppedTasks), len(droppedNotes), len(droppedDeps))
	return nil
}

// unionDepsIntoFile additively unions dbDeps into the depends_on array of an
// existing task-<id>.json, touching ONLY depends_on — every other field is
// re-read from disk and written back unchanged, so a pre-existing frozen owner's
// protected scalars (status/title/body/priority/parent/branch/updated_at) are
// preserved (the same surgical semantics as freeze's reconcileSkippedDeps). The
// file must already exist (auto-freeze writes dropped-task files before patching
// edges); unlike freeze's best-effort reconcile, a read/parse/write failure is a
// hard error here because the caller's empty-drop-diff assertion depends on the
// edge reaching disk. A no-op when disk already carries every DB edge.
func unionDepsIntoFile(path string, dbDeps []string) error {
	var disk Task
	if err := readJSON(path, &disk); err != nil {
		return fmt.Errorf("auto-freeze dep patch %s: %w", path, err)
	}
	have := make(map[string]bool, len(disk.DependsOn))
	for _, d := range disk.DependsOn {
		have[d] = true
	}
	added := false
	for _, d := range dbDeps {
		if d != "" && !have[d] {
			added = true
			break
		}
	}
	if !added {
		return nil // disk already carries every DB edge — nothing to write
	}
	disk.DependsOn = unionSorted(disk.DependsOn, dbDeps)
	return writeJSON(path, &disk)
}

// thawClaim is the live lock state of one task, held in memory across the
// drop-and-reinsert so a thaw never releases a running agent's claim.
type thawClaim struct {
	id       string
	lockedBy string
	lockedAt int64
	status   string
	branch   string
}

func thawLiveClaims(tx *sql.Tx) ([]thawClaim, error) {
	rows, err := tx.Query(`SELECT id, locked_by, locked_at, status, branch FROM tasks WHERE locked_by IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var claims []thawClaim
	for rows.Next() {
		var c thawClaim
		if err := rows.Scan(&c.id, &c.lockedBy, &c.lockedAt, &c.status, &c.branch); err != nil {
			return nil, err
		}
		claims = append(claims, c)
	}
	return claims, rows.Err()
}

// thawRestoreClaims re-applies saved claims to rows that survived the
// reinsert. Changed canonical state wins: deleted tasks drop their claims, a
// frozen done/blocked beats an unfrozen in-progress flip, and a frozen branch
// beats an unfrozen one.
//
// Branch coverage index (thaw_test.go):
//
//	(1) terminal-drop:        TestThawRestoreClaimsTerminalDrop
//	(2) deleted-task:         TestThawRestoreClaimsDeletedTask
//	(3) open-to-in-progress:  TestThawRestoreClaimsOpenToInProgress
//	(4) branch-carry:         TestThawRestoreClaimsBranchCarry
//	incidental:               TestThawLockSurvivesThaw
func thawRestoreClaims(tx *sql.Tx, claims []thawClaim) (int, error) {
	carried := 0
	for _, c := range claims {
		// Carry the lock only onto a row that survived the reinsert AND is not
		// frozen-terminal: a task that froze done/blocked has finished, so its
		// claim is dropped exactly like a deleted task's (a frozen terminal beats
		// an unfrozen in-progress claim).
		res, err := tx.Exec(
			`UPDATE tasks SET locked_by=?, locked_at=? WHERE id=? AND status NOT IN ('done','blocked','dropped')`,
			c.lockedBy, c.lockedAt, c.id,
		)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue // task deleted or frozen-terminal underneath the claim; not carried
		}
		carried++
		if c.status == string(StatusInProgress) {
			if _, err := tx.Exec(`UPDATE tasks SET status='in-progress' WHERE id=? AND status='open'`, c.id); err != nil {
				return 0, err
			}
		}
		if c.branch != "" {
			if _, err := tx.Exec(`UPDATE tasks SET branch=? WHERE id=? AND branch=''`, c.branch, c.id); err != nil {
				return 0, err
			}
		}
	}
	return carried, nil
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
