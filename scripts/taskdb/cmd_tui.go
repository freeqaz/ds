// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"sort"

	tea "github.com/charmbracelet/bubbletea"
)

// cmdTUI opens the read-only, full-screen task-graph explorer. It loads one
// in-memory snapshot of the graph up front (and again on 'r'), and never
// writes — it is classified as a read verb in writeVerb, so it also runs
// against a 0444 wave-sandbox snapshot.
func cmdTUI(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("tui", flag.ContinueOnError)
	view := fs.String("view", "dag", "initial view: dag|epics|ready")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("usage: taskdb tui [--view dag|epics|ready]")
	}
	var mode viewMode
	switch *view {
	case "dag":
		mode = viewDAG
	case "epics":
		mode = viewEpics
	case "ready":
		mode = viewReady
	default:
		return fmt.Errorf("--view must be dag, epics, or ready (got %q)", *view)
	}
	snap, err := loadSnapshot(db)
	if err != nil {
		return err
	}
	m := newTUI(db, snap, mode)
	// Alt screen keeps the shell scrollback clean; mouse mode is enabled only
	// for wheel scrolling (every other mouse event is ignored).
	_, err = tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run()
	return err
}

// snapshot is the TUI's immutable in-memory copy of the graph: every task,
// both edge directions, the epic tree, notes, and computed readiness. The
// whole store is a few hundred rows, so loading it whole keeps every view a
// pure function of this struct.
type snapshot struct {
	tasks    []*Task // display order: priority DESC, created_at ASC
	byID     map[string]*Task
	rank     map[string]int      // id → position in tasks
	deps     map[string][]string // task → depends_on (display order)
	rdeps    map[string][]string // task → tasks that depend on it (display order)
	children map[string][]string // parent → children (display order)
	notes    map[string][]*Note  // task → notes, oldest first
	ready    map[string]bool     // mirrors readyWhere (deps.go), computed in Go
	counts   map[Status]int
	progress map[string][2]int // task → {settled, total} over all descendants (epics); settled = done + dropped
}

func loadSnapshot(db *sql.DB) (*snapshot, error) {
	rows, err := db.Query(`SELECT id, title, body, status, priority, parent_id, branch, locked_by, locked_at, created_at, updated_at FROM tasks ORDER BY priority DESC, created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []*Task
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

	deps, err := loadAllDeps(db)
	if err != nil {
		return nil, err
	}

	nrows, err := db.Query(`SELECT id, task_id, body, author, created_at FROM notes WHERE task_id IS NOT NULL AND task_id != '' ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer nrows.Close()
	var notes []*Note
	for nrows.Next() {
		n, err := scanNote(nrows)
		if err != nil {
			return nil, err
		}
		notes = append(notes, n)
	}
	if err := nrows.Err(); err != nil {
		return nil, err
	}

	return buildSnapshot(tasks, deps, notes), nil
}

// buildSnapshot derives every index the views read from the raw rows. Pure —
// the unit tests feed it hand-built graphs.
func buildSnapshot(tasks []*Task, deps map[string][]string, notes []*Note) *snapshot {
	s := &snapshot{
		tasks:    tasks,
		byID:     make(map[string]*Task, len(tasks)),
		rank:     make(map[string]int, len(tasks)),
		deps:     map[string][]string{},
		rdeps:    map[string][]string{},
		children: map[string][]string{},
		notes:    map[string][]*Note{},
		ready:    map[string]bool{},
		counts:   map[Status]int{},
	}
	for i, t := range tasks {
		s.byID[t.ID] = t
		s.rank[t.ID] = i
		s.counts[t.Status]++
	}

	// Dep lists arrive ID-sorted from loadAllDeps; re-sort into display order
	// and drop edges to unknown tasks so every view can index byID blindly.
	for id, list := range deps {
		if s.byID[id] == nil {
			continue
		}
		var l []string
		for _, d := range list {
			if s.byID[d] != nil {
				l = append(l, d)
			}
		}
		sort.SliceStable(l, func(i, j int) bool { return s.rank[l[i]] < s.rank[l[j]] })
		s.deps[id] = l
	}

	// Reverse edges and the epic tree, built by iterating tasks in display
	// order so every child list is already display-sorted.
	for _, t := range tasks {
		for _, d := range s.deps[t.ID] {
			s.rdeps[d] = append(s.rdeps[d], t.ID)
		}
		if t.ParentID != "" && s.byID[t.ParentID] != nil {
			s.children[t.ParentID] = append(s.children[t.ParentID], t.ID)
		}
	}

	for _, n := range notes {
		s.notes[n.TaskID] = append(s.notes[n.TaskID], n)
	}

	// Readiness mirrors readyWhere: open, unlocked, every dep done, no children.
	for _, t := range tasks {
		if t.Status != StatusOpen || t.LockedBy != "" || len(s.children[t.ID]) > 0 {
			continue
		}
		ok := true
		for _, d := range s.deps[t.ID] {
			// A dependency in any terminal state (done OR dropped) no longer
			// blocks — mirrors readyWhere's NOT IN ('done','dropped').
			if !s.byID[d].Status.IsTerminal() {
				ok = false
				break
			}
		}
		if ok {
			s.ready[t.ID] = true
		}
	}

	// Epic progress: settled/total over all descendants. "Settled" counts BOTH
	// terminal states (done AND dropped) toward the numerator — mirrors
	// cmd_audit.go treating an all-terminal epic as closeable and the dashboard's
	// settled = done + dropped. So an all-terminal epic (every descendant done or
	// dropped, none open/in-progress/blocked) reads 100%; blocked stays NOT
	// settled (a blocked child is unfinished work, matching the dashboard).
	// onPath guards against a parent cycle (nothing enforces acyclicity of
	// parent_id at the DB layer).
	memo := map[string][2]int{}
	var desc func(id string, onPath map[string]bool) [2]int
	desc = func(id string, onPath map[string]bool) [2]int {
		if v, ok := memo[id]; ok {
			return v
		}
		if onPath[id] {
			return [2]int{}
		}
		onPath[id] = true
		var settled, total int
		for _, c := range s.children[id] {
			total++
			if s.byID[c].Status.IsTerminal() {
				settled++
			}
			v := desc(c, onPath)
			settled += v[0]
			total += v[1]
		}
		delete(onPath, id)
		memo[id] = [2]int{settled, total}
		return memo[id]
	}
	for _, t := range tasks {
		desc(t.ID, map[string]bool{})
	}
	s.progress = memo

	return s
}
