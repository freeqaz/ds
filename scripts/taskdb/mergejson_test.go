// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// write a file (empty content => an "absent"/deleted side for the merge driver).
func mjWrite(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func mjReadTask(t *testing.T, path string) Task {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var tk Task
	if err := json.Unmarshal(b, &tk); err != nil {
		t.Fatalf("unmarshal %s: %v (%s)", path, err, b)
	}
	return tk
}

func TestMergeJSON_TaskUnionPrecedence(t *testing.T) {
	d := t.TempDir()
	o := mjWrite(t, d, "O", `{"id":"01T","title":"base","status":"open","priority":2,"created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`)
	// ours: done, later updated, depA
	a := mjWrite(t, d, "A", `{"id":"01T","title":"ours-newer","status":"done","priority":2,"depends_on":["01DEPA"],"created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T05:00:00Z"}`)
	// theirs: in-progress, earlier updated, depB, earlier created
	b := mjWrite(t, d, "B", `{"id":"01T","title":"theirs-older","status":"in-progress","priority":2,"depends_on":["01DEPB"],"created_at":"2026-06-13T00:30:00Z","updated_at":"2026-06-13T02:00:00Z"}`)

	if err := cmdMergeJSON([]string{o, a, b, "tasks/task-01T.json"}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	m := mjReadTask(t, a)
	if m.Status != StatusDone {
		t.Errorf("status = %q, want done (most-progressed wins)", m.Status)
	}
	if len(m.DependsOn) != 2 || m.DependsOn[0] != "01DEPA" || m.DependsOn[1] != "01DEPB" {
		t.Errorf("depends_on = %v, want [01DEPA 01DEPB] (sorted union)", m.DependsOn)
	}
	if m.Title != "ours-newer" {
		t.Errorf("title = %q, want ours-newer (later updated_at side's content)", m.Title)
	}
	if got := m.CreatedAt.UTC().Format("15:04"); got != "00:30" {
		t.Errorf("created_at = %s, want earliest 00:30", got)
	}
	if got := m.UpdatedAt.UTC().Format("15:04"); got != "05:00" {
		t.Errorf("updated_at = %s, want latest 05:00", got)
	}
}

func TestMergeJSON_PrecedenceIsSymmetric(t *testing.T) {
	// done must win regardless of which side carries it.
	d := t.TempDir()
	o := mjWrite(t, d, "O", `{"id":"01T","status":"open","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`)
	a := mjWrite(t, d, "A", `{"id":"01T","status":"open","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T03:00:00Z"}`)
	b := mjWrite(t, d, "B", `{"id":"01T","status":"done","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T02:00:00Z"}`)
	if err := cmdMergeJSON([]string{o, a, b, "tasks/task-01T.json"}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if m := mjReadTask(t, a); m.Status != StatusDone {
		t.Errorf("status = %q, want done (theirs=done must beat ours=open even though ours is newer)", m.Status)
	}
}

func TestMergeJSON_ResurrectOnDelete(t *testing.T) {
	d := t.TempDir()
	o := mjWrite(t, d, "O", `{"id":"01T","status":"done","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`)
	// theirs deleted (empty) -> ours kept
	a := mjWrite(t, d, "A", `{"id":"01T","status":"done","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T05:00:00Z"}`)
	b := mjWrite(t, d, "B", "")
	if err := cmdMergeJSON([]string{o, a, b, "tasks/task-01T.json"}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if m := mjReadTask(t, a); m.Status != StatusDone {
		t.Errorf("theirs-deleted: status = %q, want done (resurrect ours)", m.Status)
	}
	// ours deleted (empty) -> theirs kept
	a2 := mjWrite(t, d, "A2", "")
	b2 := mjWrite(t, d, "B2", `{"id":"01T","status":"blocked","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T05:00:00Z"}`)
	if err := cmdMergeJSON([]string{o, a2, b2, "tasks/task-01T.json"}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	if m := mjReadTask(t, a2); m.Status != StatusBlocked {
		t.Errorf("ours-deleted: status = %q, want blocked (resurrect theirs)", m.Status)
	}
}

func TestMergeJSON_NotePresentWins(t *testing.T) {
	d := t.TempDir()
	o := mjWrite(t, d, "O", "")
	a := mjWrite(t, d, "A", `{"id":"01N","task_id":"01T","body":"the note","author":"me","created_at":"2026-06-13T01:00:00Z"}`)
	b := mjWrite(t, d, "B", "")
	if err := cmdMergeJSON([]string{o, a, b, "tasks/note-01N.json"}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	var n Note
	bts, _ := os.ReadFile(a)
	if err := json.Unmarshal(bts, &n); err != nil {
		t.Fatalf("note unmarshal: %v", err)
	}
	if n.Body != "the note" {
		t.Errorf("note body = %q, want 'the note' (present side resurrected)", n.Body)
	}
}

// TestMergeJSON_DroppedBeatsNonTerminal proves a `dropped` drop PROPAGATES over
// the non-terminal states: whichever side abandoned the task wins the merge, in
// either direction, so a stale open/in-progress copy can never resurrect it.
func TestMergeJSON_DroppedBeatsNonTerminal(t *testing.T) {
	for _, tc := range []struct {
		name, ours, theirs string
	}{
		{"dropped-vs-open", "dropped", "open"},
		{"open-vs-dropped", "open", "dropped"},
		{"dropped-vs-in-progress", "dropped", "in-progress"},
		{"dropped-vs-blocked", "dropped", "blocked"},
		{"blocked-vs-dropped", "blocked", "dropped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			o := mjWrite(t, d, "O", `{"id":"01T","status":"open","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`)
			// give the NON-dropped side the LATER updated_at, to prove drop wins on
			// terminality, not on recency.
			ourU, theirU := "2026-06-13T02:00:00Z", "2026-06-13T02:00:00Z"
			if tc.ours == "dropped" {
				theirU = "2026-06-13T09:00:00Z"
			} else {
				ourU = "2026-06-13T09:00:00Z"
			}
			a := mjWrite(t, d, "A", `{"id":"01T","status":"`+tc.ours+`","created_at":"2026-06-13T01:00:00Z","updated_at":"`+ourU+`"}`)
			b := mjWrite(t, d, "B", `{"id":"01T","status":"`+tc.theirs+`","created_at":"2026-06-13T01:00:00Z","updated_at":"`+theirU+`"}`)
			if err := cmdMergeJSON([]string{o, a, b, "tasks/task-01T.json"}); err != nil {
				t.Fatalf("merge should auto-resolve, got error: %v", err)
			}
			if m := mjReadTask(t, a); m.Status != StatusDropped {
				t.Errorf("status = %q, want dropped (a drop must propagate over %v/%v)", m.Status, tc.ours, tc.theirs)
			}
		})
	}
}

// TestMergeJSON_DroppedVsDoneIsConflict proves the dropped-vs-done collision is
// a GENUINE conflict: the driver returns non-zero (so git falls back to conflict
// markers) and NEVER silently picks a winner — in either direction, and only
// when the two sides actually disagree.
func TestMergeJSON_DroppedVsDoneIsConflict(t *testing.T) {
	for _, tc := range []struct{ ours, theirs string }{
		{"dropped", "done"},
		{"done", "dropped"},
	} {
		d := t.TempDir()
		o := mjWrite(t, d, "O", `{"id":"01T","status":"in-progress","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`)
		a := mjWrite(t, d, "A", `{"id":"01T","status":"`+tc.ours+`","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T03:00:00Z"}`)
		b := mjWrite(t, d, "B", `{"id":"01T","status":"`+tc.theirs+`","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T02:00:00Z"}`)
		err := cmdMergeJSON([]string{o, a, b, "tasks/task-01T.json"})
		if err == nil {
			t.Fatalf("%s vs %s: merge returned nil, want a conflict error (non-zero exit → git conflict markers)", tc.ours, tc.theirs)
		}
	}
}

// ROOT CAUSE of the two field failures reported under BUG 01KV2RMTBV (the
// 11-case status-precedence reversal and the 13-note-drop) is NOT in this
// function — cmdMergeJSON's status precedence and note-resurrection are correct,
// as the cases below prove exhaustively. The failures came from the INVOCATION
// boundary, where git never reached this driver:
//
//  1. The precedence "reversal" (older in-progress overriding newer done) was git
//     falling back to its LINE-BASED text merge because merge.taskdb.driver was
//     UNREGISTERED on the reconciling worktree. With no driver, git resolves the
//     status line by recency/side, not by terminality — exactly the inversion
//     reported. The fix lives in ensureMergeDriver's self-heal (cmd_setup.go,
//     covered by mergedriver_selfheal_test.go), not here.
//  2. The dropped notes were delete-vs-clean paths git resolves WITHOUT invoking
//     a per-file merge driver at all: note-*.json are standalone per-file records,
//     so a "one side deleted, other side untouched" shape is a tree-level rename/
//     delete that git auto-resolves before any content merge — the driver below is
//     never called, so it cannot be the regression site.
//
// Neither is reproducible inside cmdMergeJSON's direct-call harness (there is no
// git here). The cases below therefore REGRESSION-LOCK the two invariants the
// driver DOES own, so that if the driver itself ever regressed it would be caught:
// (a) the max-precedence status side always wins across every ours/theirs ordering
// (including older-in-progress vs newer-done), and (b) a note present on exactly
// one side is never dropped under any present/absent O/A/B combination.

// TestMergeJSON_StatusMaxPrecedenceAllOrderings regression-locks invariant (a):
// the most-progressed/most-terminal status ALWAYS wins, in every ours/theirs
// ordering and regardless of which side carries the later updated_at. The crux
// case from the report — an OLDER in-progress side vs a NEWER done side — is
// included in both directions: done must win even when the in-progress copy is
// the more recently updated one (recency must never override terminality).
func TestMergeJSON_StatusMaxPrecedenceAllOrderings(t *testing.T) {
	// each pair excludes the dropped-vs-done collision (a genuine conflict, see
	// TestMergeJSON_DroppedVsDoneIsConflict); every remaining pair must auto-merge
	// to the higher-rank status. rank: done > dropped > blocked > in-progress > open.
	for _, tc := range []struct {
		name, ours, theirs, want string
		oursNewer                bool // true => ours carries the later updated_at
	}{
		// the reported crux, both directions: a NEWER non-terminal must NOT beat
		// an OLDER done.
		{"older-done_vs_newer-inprogress", "done", "in-progress", "done", false},
		{"newer-inprogress_vs_older-done", "in-progress", "done", "done", true},
		{"older-done_vs_newer-open", "done", "open", "done", false},
		{"newer-open_vs_older-done", "open", "done", "done", true},
		{"older-done_vs_newer-blocked", "done", "blocked", "done", false},
		{"newer-blocked_vs_older-done", "blocked", "done", "done", true},
		// non-done precedence rungs, both directions.
		{"blocked_vs_open", "blocked", "open", "blocked", false},
		{"open_vs_blocked", "open", "blocked", "blocked", true},
		{"blocked_vs_inprogress", "blocked", "in-progress", "blocked", false},
		{"inprogress_vs_blocked", "in-progress", "blocked", "blocked", true},
		{"inprogress_vs_open", "in-progress", "open", "in-progress", false},
		{"open_vs_inprogress", "open", "in-progress", "in-progress", true},
		// equal status: clean no-op, stays put either way.
		{"open_vs_open", "open", "open", "open", false},
		{"done_vs_done", "done", "done", "done", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			// Give the LOSER the later updated_at wherever possible, so a pass proves
			// terminality wins on RANK, not on recency. tc.oursNewer says which side
			// is newer; we set it so the lower-ranked side is the newer one.
			ourU, theirU := "2026-06-13T02:00:00Z", "2026-06-13T02:00:00Z"
			if tc.oursNewer {
				ourU = "2026-06-13T09:00:00Z"
			} else {
				theirU = "2026-06-13T09:00:00Z"
			}
			o := mjWrite(t, d, "O", `{"id":"01T","status":"open","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`)
			a := mjWrite(t, d, "A", `{"id":"01T","status":"`+tc.ours+`","created_at":"2026-06-13T01:00:00Z","updated_at":"`+ourU+`"}`)
			b := mjWrite(t, d, "B", `{"id":"01T","status":"`+tc.theirs+`","created_at":"2026-06-13T01:00:00Z","updated_at":"`+theirU+`"}`)
			if err := cmdMergeJSON([]string{o, a, b, "tasks/task-01T.json"}); err != nil {
				t.Fatalf("merge should auto-resolve, got error: %v", err)
			}
			if m := mjReadTask(t, a); string(m.Status) != tc.want {
				t.Errorf("status = %q, want %q (max-precedence side wins: ours=%s theirs=%s)", m.Status, tc.want, tc.ours, tc.theirs)
			}
		})
	}
}

// TestMergeJSON_NoteNeverDroppedAllCombos regression-locks invariant (b): a note
// present on EXACTLY ONE side is never dropped, across all four present/absent
// combinations of (ours, theirs). Notes are immutable per-file records; the
// driver's policy is present-side-wins (prefer ours), resurrect on a one-sided
// delete, empty only when BOTH sides are absent. Base (O) is varied independently
// to prove it does not change the outcome.
func TestMergeJSON_NoteNeverDroppedAllCombos(t *testing.T) {
	const noteJSON = `{"id":"01N","task_id":"01T","body":"the note","author":"me","created_at":"2026-06-13T01:00:00Z"}`
	for _, tc := range []struct {
		name         string
		ours, theirs string // "" => that side absent/deleted
		base         string // O content; "" => no base
		wantBody     string // "" => expect an empty (both-absent) result
	}{
		// present on exactly one side — must survive in every base shape.
		{"ours-present_theirs-absent_noBase", noteJSON, "", "", "the note"},
		{"ours-present_theirs-absent_baseHadIt", noteJSON, "", noteJSON, "the note"},
		{"ours-absent_theirs-present_noBase", "", noteJSON, "", "the note"},
		{"ours-absent_theirs-present_baseHadIt", "", noteJSON, noteJSON, "the note"},
		// present on BOTH — immutable, present (ours) wins.
		{"both-present", noteJSON, noteJSON, noteJSON, "the note"},
		// absent on BOTH — clean delete, an empty result is correct (nothing to drop).
		{"both-absent", "", "", noteJSON, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			o := mjWrite(t, d, "O", tc.base)
			a := mjWrite(t, d, "A", tc.ours)
			b := mjWrite(t, d, "B", tc.theirs)
			if err := cmdMergeJSON([]string{o, a, b, "tasks/note-01N.json"}); err != nil {
				t.Fatalf("note merge: %v", err)
			}
			bts, err := os.ReadFile(a)
			if err != nil {
				t.Fatalf("read merged note: %v", err)
			}
			if tc.wantBody == "" {
				if len(bts) != 0 {
					t.Errorf("both-absent: merged note = %q, want empty", bts)
				}
				return
			}
			var n Note
			if err := json.Unmarshal(bts, &n); err != nil {
				t.Fatalf("note unmarshal: %v (%s)", err, bts)
			}
			if n.Body != tc.wantBody {
				t.Errorf("note body = %q, want %q (present-side note must never be dropped)", n.Body, tc.wantBody)
			}
		})
	}
}

// TestStatusRank_NonCanonical proves statusRank folds mixed case + surrounding
// whitespace to the canonical form, so a non-canonical status can never be
// mis-ranked (e.g. " done " ranking as the unknown/open 0 and thus losing to a
// stale in-progress side).
func TestStatusRank_NonCanonical(t *testing.T) {
	for _, tc := range []struct {
		in   Status
		want int
	}{
		{"done", 4}, {" done ", 4}, {"DONE", 4}, {"Done", 4},
		{"dropped", 3}, {"Dropped", 3}, {" DROPPED ", 3},
		{"blocked", 2}, {"BLOCKED", 2},
		{"in-progress", 1}, {"In-Progress", 1},
		{"open", 0}, {"OPEN", 0}, {"garbage", 0},
	} {
		if got := statusRank(tc.in); got != tc.want {
			t.Errorf("statusRank(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestIsDropDoneCollision_NonCanonical proves the dropped-vs-done conflict guard
// fires regardless of case/whitespace — a side writing "Dropped" or " done "
// must NOT be able to slip past the guard and get auto-resolved by maxStatus.
func TestIsDropDoneCollision_NonCanonical(t *testing.T) {
	collide := []struct{ a, b Status }{
		{"Dropped", "done"}, {"dropped", "DONE"}, {" dropped ", " done "},
		{"DONE", "DROPPED"}, {"done", "Dropped"},
	}
	for _, tc := range collide {
		if !isDropDoneCollision(tc.a, tc.b) {
			t.Errorf("isDropDoneCollision(%q,%q) = false, want true", tc.a, tc.b)
		}
	}
	noCollide := []struct{ a, b Status }{
		{"DONE", "done"}, {" dropped ", "dropped"}, {"done", "In-Progress"},
	}
	for _, tc := range noCollide {
		if isDropDoneCollision(tc.a, tc.b) {
			t.Errorf("isDropDoneCollision(%q,%q) = true, want false", tc.a, tc.b)
		}
	}
}

// TestMergeJSON_NonCanonicalDropDoneIsConflict proves the end-to-end merge
// driver still refuses a dropped-vs-done collision when one side wrote the
// status in a non-canonical shape — the normalization closes the bypass.
func TestMergeJSON_NonCanonicalDropDoneIsConflict(t *testing.T) {
	for _, tc := range []struct{ ours, theirs string }{
		{"Dropped", "done"},
		{"done", " DROPPED "},
		{"DONE", "dropped"},
	} {
		d := t.TempDir()
		o := mjWrite(t, d, "O", `{"id":"01T","status":"in-progress","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`)
		a := mjWrite(t, d, "A", `{"id":"01T","status":"`+tc.ours+`","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T03:00:00Z"}`)
		b := mjWrite(t, d, "B", `{"id":"01T","status":"`+tc.theirs+`","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T02:00:00Z"}`)
		if err := cmdMergeJSON([]string{o, a, b, "tasks/task-01T.json"}); err == nil {
			t.Fatalf("%q vs %q: merge returned nil, want a conflict error", tc.ours, tc.theirs)
		}
	}
}

// TestMergeJSON_StoredStatusIsNormalized proves the WRITTEN merged status is
// folded to its canonical lowercase form (F10). maxStatus ranks by normalized
// value but returns the winning side's RAW string, so a non-canonical input
// ("DONE", " open ") used to be stored verbatim — a "DONE" row is then neither
// filtered as terminal NOR surfaced as ready by the exact-lowercase ready-query
// (deps.go), i.e. a stuck row. The normalization must close that gap WITHOUT
// disturbing an already-canonical merge.
func TestMergeJSON_StoredStatusIsNormalized(t *testing.T) {
	for _, tc := range []struct {
		name, ours, theirs, want string
	}{
		// non-canonical winning side must be stored canonicalized.
		{"upper-done_vs_open", "DONE", "open", "done"},
		{"open_vs_upper-done", "open", "DONE", "done"},
		{"padded-done_vs_inprogress", " done ", "in-progress", "done"},
		{"mixedcase-blocked_vs_open", "Blocked", "open", "blocked"},
		// the winner is the NON-canonical lower-ranked side (loser is canonical):
		// the stored value is still the winner, canonicalized.
		{"upper-inprogress_vs_open", "IN-PROGRESS", "open", "in-progress"},
		// already-canonical merges are unchanged.
		{"canonical-done_vs_open", "done", "open", "done"},
		{"canonical-open_vs_open", "open", "open", "open"},
		{"canonical-blocked_vs_inprogress", "blocked", "in-progress", "blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			o := mjWrite(t, d, "O", `{"id":"01T","status":"open","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`)
			a := mjWrite(t, d, "A", `{"id":"01T","status":"`+tc.ours+`","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T03:00:00Z"}`)
			b := mjWrite(t, d, "B", `{"id":"01T","status":"`+tc.theirs+`","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T02:00:00Z"}`)
			if err := cmdMergeJSON([]string{o, a, b, "tasks/task-01T.json"}); err != nil {
				t.Fatalf("merge should auto-resolve, got error: %v", err)
			}
			if m := mjReadTask(t, a); string(m.Status) != tc.want {
				t.Errorf("stored status = %q, want %q (merged status must be canonical lowercase)", m.Status, tc.want)
			}
		})
	}
}

// TestMergeJSON_SameTerminalNoConflict proves agreeing terminal sides are a
// clean no-op merge, never a false conflict.
func TestMergeJSON_SameTerminalNoConflict(t *testing.T) {
	for _, st := range []string{"dropped", "done"} {
		d := t.TempDir()
		o := mjWrite(t, d, "O", `{"id":"01T","status":"open","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T01:00:00Z"}`)
		a := mjWrite(t, d, "A", `{"id":"01T","status":"`+st+`","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T03:00:00Z"}`)
		b := mjWrite(t, d, "B", `{"id":"01T","status":"`+st+`","created_at":"2026-06-13T01:00:00Z","updated_at":"2026-06-13T02:00:00Z"}`)
		if err := cmdMergeJSON([]string{o, a, b, "tasks/task-01T.json"}); err != nil {
			t.Fatalf("both %s should auto-merge, got: %v", st, err)
		}
		if m := mjReadTask(t, a); string(m.Status) != st {
			t.Errorf("status = %q, want %s", m.Status, st)
		}
	}
}
