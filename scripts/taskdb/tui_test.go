// SPDX-License-Identifier: Apache-2.0
package main

import (
	"testing"
	"time"
)

func tuiTask(id, parent string, status Status, title string) *Task {
	now := time.Now().UTC()
	return &Task{ID: id, Title: title, Status: status, ParentID: parent, CreatedAt: now, UpdatedAt: now}
}

// diamondSnapshot is A → (B, C) → D plus an isolated task X:
// B and C depend on A; D depends on both B and C.
func diamondSnapshot() *snapshot {
	tasks := []*Task{
		tuiTask("A", "", StatusDone, "alpha root"),
		tuiTask("B", "", StatusOpen, "beta left"),
		tuiTask("C", "", StatusOpen, "gamma right"),
		tuiTask("D", "", StatusOpen, "delta join"),
		tuiTask("X", "", StatusOpen, "xray isolated"),
	}
	deps := map[string][]string{
		"B": {"A"},
		"C": {"A"},
		"D": {"B", "C"},
	}
	return buildSnapshot(tasks, deps, nil)
}

func testModel(snap *snapshot, mode viewMode) *tuiModel {
	return &tuiModel{
		snap: snap,
		mode: mode,
		folds: map[viewMode]*foldState{
			viewDAG:   {defaultExpanded: true, toggled: map[string]bool{}},
			viewEpics: {defaultExpanded: true, toggled: map[string]bool{}},
			viewReady: {defaultExpanded: true, toggled: map[string]bool{}},
			viewChain: {defaultExpanded: true, toggled: map[string]bool{}},
		},
	}
}

func TestSnapshotReadyMirrorsReadyWhere(t *testing.T) {
	epic := tuiTask("E", "", StatusOpen, "epic")
	child := tuiTask("F", "E", StatusOpen, "child of epic")
	locked := tuiTask("L", "", StatusOpen, "locked")
	locked.LockedBy = "sess"
	tasks := []*Task{
		tuiTask("A", "", StatusDone, "done dep"),
		tuiTask("B", "", StatusOpen, "deps met"),
		tuiTask("C", "", StatusOpen, "deps unmet"),
		epic, child, locked,
	}
	deps := map[string][]string{"B": {"A"}, "C": {"B"}}
	s := buildSnapshot(tasks, deps, nil)

	wantReady := map[string]bool{"B": true, "F": true}
	for _, tk := range tasks {
		if s.ready[tk.ID] != wantReady[tk.ID] {
			t.Errorf("ready[%s] = %v, want %v", tk.ID, s.ready[tk.ID], wantReady[tk.ID])
		}
	}
}

func TestBuildDAGSuppressesRevisits(t *testing.T) {
	m := testModel(diamondSnapshot(), viewDAG)
	rows := m.buildDAG()

	var dRows, dRevisits, headers int
	for _, r := range rows {
		if r.kind == rowHeader {
			headers++
			continue
		}
		if r.id == "D" {
			dRows++
			if r.revisit {
				dRevisits++
			}
		}
	}
	// D is reached via B and via C: rendered twice, exactly once as a revisit
	// reference — full expansion would loop forever on denser graphs.
	if dRows != 2 || dRevisits != 1 {
		t.Fatalf("D rendered %d times with %d revisit marks, want 2 and 1", dRows, dRevisits)
	}
	// One chain-roots header (A) plus the isolated section (X).
	if headers != 2 {
		t.Fatalf("got %d headers, want 2", headers)
	}
}

func TestBuildDAGFilterKeepsAncestors(t *testing.T) {
	m := testModel(diamondSnapshot(), viewDAG)
	m.search = "delta" // matches only D

	got := map[string]bool{}
	for _, r := range m.buildDAG() {
		if r.kind == rowTask {
			got[r.id] = true
		}
	}
	// D's render ancestors (its transitive deps A, B, C) stay visible so the
	// chain to the match is intact; the unrelated X is filtered out.
	for _, id := range []string{"A", "B", "C", "D"} {
		if !got[id] {
			t.Errorf("filtered DAG lost %s", id)
		}
	}
	if got["X"] {
		t.Errorf("filtered DAG kept unrelated task X")
	}
}

func TestBuildEpicsFilterKeepsParentChain(t *testing.T) {
	tasks := []*Task{
		tuiTask("E", "", StatusOpen, "epic root"),
		tuiTask("M", "E", StatusOpen, "middle epic"),
		tuiTask("F", "M", StatusOpen, "needle leaf"),
		tuiTask("G", "E", StatusOpen, "other leaf"),
	}
	m := testModel(buildSnapshot(tasks, nil, nil), viewEpics)
	m.search = "needle"

	got := map[string]bool{}
	for _, r := range m.buildEpics() {
		if r.kind == rowTask {
			got[r.id] = true
		}
	}
	for _, id := range []string{"E", "M", "F"} {
		if !got[id] {
			t.Errorf("filtered epics lost %s", id)
		}
	}
	if got["G"] {
		t.Errorf("filtered epics kept non-matching sibling G")
	}
}

// TestEpicProgressSettledCountsDropped pins the epic-progress numerator: an
// all-terminal epic (children done + dropped, none open/in-progress/blocked)
// reads settled==total (100%), matching cmd_audit.go's all-terminal-is-closeable
// and the dashboard's settled = done + dropped. A blocked child stays NOT
// settled (it is unfinished work).
func TestEpicProgressSettledCountsDropped(t *testing.T) {
	// Epic A: two done + one dropped → all terminal → 3/3.
	// Epic B: one done + one dropped + one blocked → 2/3 (blocked unsettled).
	tasks := []*Task{
		tuiTask("A", "", StatusOpen, "all-terminal epic"),
		tuiTask("a1", "A", StatusDone, "done child"),
		tuiTask("a2", "A", StatusDone, "done child"),
		tuiTask("a3", "A", StatusDropped, "dropped child"),
		tuiTask("B", "", StatusOpen, "mixed epic"),
		tuiTask("b1", "B", StatusDone, "done child"),
		tuiTask("b2", "B", StatusDropped, "dropped child"),
		tuiTask("b3", "B", StatusBlocked, "blocked child"),
	}
	s := buildSnapshot(tasks, nil, nil)

	if got := s.progress["A"]; got != [2]int{3, 3} {
		t.Errorf("all-terminal epic A progress = %v, want [3 3] (100%%)", got)
	}
	if got := s.progress["B"]; got != [2]int{2, 3} {
		t.Errorf("mixed epic B progress = %v, want [2 3] (blocked stays unsettled)", got)
	}
}

func TestBuildChainCentersTask(t *testing.T) {
	m := testModel(diamondSnapshot(), viewChain)
	m.chainID = "B"
	rows := m.buildChain()

	var focal, upstream, downstream bool
	for _, r := range rows {
		if r.kind != rowTask {
			continue
		}
		switch {
		case r.focal:
			focal = r.id == "B"
		case r.id == "A":
			upstream = true
		case r.id == "D":
			downstream = true
		}
	}
	if !focal || !upstream || !downstream {
		t.Fatalf("chain view for B: focal=%v upstream-A=%v downstream-D=%v, want all true", focal, upstream, downstream)
	}
}
