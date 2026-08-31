// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// cmdStageOwned writes + `git add`s EXACTLY the task-/note-*.json files this
// caller owns, by task id — never `git add tasks/` wholesale, never deleting
// another coordinator's files.
//
// This is the safe, one-command form of the landing discipline the wave engine
// (and every manual land) prescribes: "stage ONLY the owned tasks/*.json — never
// `git add tasks/`, which sweeps other coordinators' drift / deletions into your
// commit." Pass the task ids the wave owns (its unit + folded + filed-deferred
// ids); stage-owned freezes just those rows from THIS live DB into tasks/ and
// stages them, leaving every other file — and the index — untouched.
//
//	taskdb stage-owned [--into <worktree>] [--commit <msg>] <id> [<id>...]
//
// Each id must resolve in the live DB (a typo is loud, not a silent no-op). The
// matching note-*.json (notes whose task_id is an owned id) are staged too, so a
// task's status and its land/deferral notes land together. Combine with the
// additive `freeze` default (freeze never deletes) and the tasks/*.json merge
// driver to make shared-store landings clobber-proof.
//
// --into <worktree> freezes + stages the owned files into a LINKED WORKTREE's
// tasks/ + index instead of the primary checkout — the "tasks-on-branch" land
// discipline (doc 27 Lever 3): the wave's finalize, the single canonical-DB
// writer, commits the owned statuses ONTO the gate-green integration branch so
// the branch is SELF-CONTAINED. The serialized landing-queue leader then just
// FF-merges that branch and the tasks/*.json union driver reconciles the
// statuses — no separate stale-base tasks-commit on main at land time. The
// content still comes from THIS (the canonical) live DB; --into only redirects
// where the frozen files are written/staged. --commit <msg> additionally commits
// EXACTLY the owned paths there (--no-verify, so the pre-commit hook can't re-add
// tasks/ wholesale).
func cmdStageOwned(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("stage-owned", flag.ContinueOnError)
	into := fs.String("into", "", "stage into this linked worktree's tasks/ + index (default: the primary checkout)")
	commitMsg := fs.String("commit", "", "after staging, commit EXACTLY the owned paths here with --no-verify")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ids := fs.Args()
	if len(ids) == 0 {
		return fmt.Errorf("stage-owned: at least one task id is required\nusage: taskdb stage-owned [--into <worktree>] [--commit <msg>] <id> [<id>...]")
	}

	// Resolve the target root: --into <worktree> (a linked worktree on the branch
	// to carry the statuses) or, by default, the primary checkout (today's
	// behavior). The frozen content always comes from `db` (the live canonical DB).
	var dir, root string
	if *into != "" {
		root = strings.TrimRight(*into, "/")
		// A linked worktree's .git is a FILE pointing at the primary; the primary's
		// is a DIR. Either is a valid `git -C <root>` root — just require it exists.
		if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
			return fmt.Errorf("stage-owned --into %q: not a git worktree (no .git entry): %v", root, err)
		}
		dir = filepath.Join(root, "tasks")
		if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
			return fmt.Errorf("stage-owned --into %q: no tasks/ dir in that worktree", root)
		}
	} else {
		var err error
		if dir, err = tasksDir(); err != nil {
			return err
		}
		if root, err = repoRoot(); err != nil {
			return err
		}
	}

	tasks, err := allTasks(db)
	if err != nil {
		return fmt.Errorf("stage-owned tasks: %w", err)
	}
	notes, err := allNotes(db)
	if err != nil {
		return fmt.Errorf("stage-owned notes: %w", err)
	}

	// Resolve each requested id to a real task (exact id, or an unambiguous
	// prefix — the same affordance the other verbs give). A miss aborts before
	// any write so the caller fixes the id rather than silently staging nothing.
	byID := make(map[string]*Task, len(tasks))
	for _, t := range tasks {
		byID[t.ID] = t
	}
	owned := make(map[string]*Task)
	var missing []string
	for _, want := range ids {
		if t, ok := byID[want]; ok {
			owned[t.ID] = t
			continue
		}
		var matches []*Task
		for _, t := range tasks {
			if strings.HasPrefix(t.ID, want) {
				matches = append(matches, t)
			}
		}
		switch len(matches) {
		case 1:
			owned[matches[0].ID] = matches[0]
		case 0:
			missing = append(missing, want)
		default:
			return fmt.Errorf("stage-owned: id prefix %q is ambiguous (%d matches) — pass the full ULID", want, len(matches))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("stage-owned: %d id(s) not found in the live DB: %s", len(missing), strings.Join(missing, ", "))
	}

	// Write each owned task + its notes from the live DB, collect the paths.
	// Regression guards (same policy as cmdFreeze — see freeze.go for rationale):
	//
	//   P1 — terminal-status regression: skip if the on-disk file already carries
	//   a terminal status (done/dropped) and this DB has a lower-ranked status.
	//   A stale DB must never un-complete a finished task.
	//
	//   P4 — newer-on-disk content: skip if the on-disk updated_at is strictly
	//   newer than the DB row's. A peer may have frozen a later edit (or the
	//   integration branch already carries a post-merge tasks/*.json that this DB
	//   hasn't thawed); writing the older DB row would regress title/body/priority.
	//
	// Both checks are skipped when the file is absent/unreadable — a missing file
	// is not a regression to protect, so we write it. Skipped tasks are logged but
	// never block the rest of the owned set.
	//
	// F6: a wholesale skip would silently LOSE a NEW depends_on edge the DB row
	// gained while its updated_at trails the on-disk file (depends_on is a
	// union-merged field — see reconcileSkippedDeps). reconcileSkippedDeps
	// additively unions the DB edges into the on-disk file (depends_on ONLY,
	// protected scalars untouched) and names any newly-propagated edges in the
	// SKIP message.
	var kept []string
	var paths []string
	for id, t := range owned {
		p := filepath.Join(dir, "task-"+id+".json")
		if ds, du, ok := diskTaskMeta(p); ok {
			nd := normalizeStatus(ds)
			// F6: a regression-guarded SKIP must still propagate any NEW depends_on
			// edge the DB row gained (union-merged field — see reconcileSkippedDeps).
			// reconcileSkippedDeps touches ONLY depends_on (protected scalars
			// untouched). When it writes back, stage that path too so the additively
			// recovered edge actually lands with the rest of the owned set.
			switch {
			case nd.IsTerminal() && statusRank(nd) > statusRank(t.Status):
				depMsg := reconcileSkippedDeps(p, t)
				kept = append(kept, fmt.Sprintf("%s — terminal regression (on disk %s → this DB %s)%s", id, nd, normalizeStatus(t.Status), depMsg))
				if depMsg != "" {
					paths = append(paths, p)
				}
				continue
			case du.Truncate(time.Millisecond).After(t.UpdatedAt.Truncate(time.Millisecond)):
				depMsg := reconcileSkippedDeps(p, t)
				kept = append(kept, fmt.Sprintf("%s — on-disk row is newer (disk updated_at %s > DB %s)%s", id, du.UTC().Format(time.RFC3339), t.UpdatedAt.UTC().Format(time.RFC3339), depMsg))
				if depMsg != "" {
					paths = append(paths, p)
				}
				continue
			}
		}
		if err := writeJSON(p, t); err != nil {
			return err
		}
		paths = append(paths, p)
	}
	if len(kept) > 0 {
		fmt.Printf("stage-owned: skipped %d task(s) — on-disk state is newer or terminal (regression guard):\n", len(kept))
		for _, msg := range kept {
			fmt.Printf("  SKIP %s\n", msg)
		}
	}
	for _, n := range notes {
		if n.TaskID == "" {
			continue
		}
		if _, ok := owned[n.TaskID]; !ok {
			continue
		}
		p := filepath.Join(dir, "note-"+n.ID+".json")
		if err := writeJSON(p, n); err != nil {
			return err
		}
		paths = append(paths, p)
	}

	// Stage EXACTLY those paths — never `git add tasks/`. `--` guards against a
	// path that looks like a flag.
	addArgs := append([]string{"-C", root, "add", "--"}, paths...)
	out, err := exec.Command("git", addArgs...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("git add: %w\n%s", err, out)
	}

	// --commit: land the owned statuses as one commit scoped to EXACTLY these
	// paths (`commit -- <paths>`, so any other working-tree state in the target
	// worktree is untouched), with --no-verify so the pre-commit hook can't re-add
	// tasks/ wholesale. This is the tasks-on-branch step: finalize commits the
	// owned statuses onto the integration branch checked out in --into.
	if *commitMsg != "" {
		commitArgs := append([]string{"-C", root, "commit", "--no-verify", "-m", *commitMsg, "--"}, paths...)
		out, err := exec.Command("git", commitArgs...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("git commit: %w\n%s", err, out)
		}
		where := "the integration branch"
		if *into != "" {
			where = *into
		}
		fmt.Printf("stage-owned: committed %d file(s) for %d task(s) onto %s\n", len(paths), len(owned), where)
		return nil
	}

	fmt.Printf("stage-owned: staged %d file(s) for %d task(s) — review with `git diff --cached --name-only`, then commit with --no-verify (the pre-commit hook re-adds tasks/ wholesale, so --no-verify keeps the commit to exactly these files)\n", len(paths), len(owned))
	return nil
}
