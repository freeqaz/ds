// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// cmdMergeJSON is the git merge driver for tasks/*.json. It 3-way-merges one
// task or note file by ID-stable union so two coordinators (or two machines)
// touching the SAME task file never clobber each other:
//
//	taskdb merge-json %O %A %B %P
//	  %O = ancestor (base), %A = ours/current (ALSO the output git reads),
//	  %B = theirs, %P = pathname (used to tell task- from note-).
//
// Registered by `taskdb setup` via .gitattributes (tasks/task-*.json merge=taskdb)
// + `git config merge.taskdb.driver`. It needs NO database (git invokes it in a
// clean merge context), so main dispatches it before openDB.
//
// Task merge policy (a deliberate, documented choice — see docs/21):
//   - status: most-progressed/most-terminal wins,
//     done > dropped > blocked > in-progress > open (a remote `done` can never be
//     reverted to `open` by a stale side — the clobber we are preventing;
//     reopening a done task is rare and done deliberately, so it must re-land done
//     explicitly). A `dropped` drop likewise propagates over the non-terminal
//     states. The SOLE exception is a dropped-vs-done collision on the same id:
//     that is a genuine conflict (one side abandoned, the other completed) and
//     the driver REFUSES it — it exits non-zero so git falls back to conflict
//     markers for manual review, never silently picking a winner.
//   - depends_on: union (sorted, deduped) — never drop an edge either side added.
//   - created_at: earliest; updated_at: latest; other scalar fields (title/body/
//     priority/parent/branch) taken from the side with the later updated_at.
//   - delete-vs-present: RESURRECT — if one side has the task and the other an
//     empty/absent file, keep the present one (a freeze should never author a
//     deletion now that freeze is additive, but be safe).
//
// Notes are immutable records: present-side wins, resurrect on delete.
//
// On any parse failure it exits non-zero so git falls back to conflict markers
// (fail safe — never silently write a half-merged file).
func cmdMergeJSON(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("merge-json: need %%O %%A %%B [%%P]\nusage: taskdb merge-json <ancestor> <ours> <theirs> [pathname]")
	}
	ancestorPath, oursPath, theirsPath := args[0], args[1], args[2]
	pathname := ""
	if len(args) >= 4 {
		pathname = args[3]
	}

	oursRaw, oursOK := readNonEmpty(oursPath)
	theirsRaw, theirsOK := readNonEmpty(theirsPath)
	_, _ = readNonEmpty(ancestorPath) // base is informational; union logic below does not need it

	isNote := strings.HasPrefix(filepath.Base(pathname), "note-")
	if pathname == "" {
		// No pathname given — infer: a note has no "status" field.
		probe := oursRaw
		if !oursOK {
			probe = theirsRaw
		}
		isNote = !hasJSONField(probe, "status")
	}

	if isNote {
		// Immutable record: keep whichever side is present (prefer ours).
		switch {
		case oursOK:
			return os.WriteFile(oursPath, ensureTrailingNewline(oursRaw), 0644)
		case theirsOK:
			return os.WriteFile(oursPath, ensureTrailingNewline(theirsRaw), 0644)
		default:
			return os.WriteFile(oursPath, []byte{}, 0644)
		}
	}

	// Task merge.
	switch {
	case oursOK && !theirsOK:
		return os.WriteFile(oursPath, ensureTrailingNewline(oursRaw), 0644) // theirs deleted → keep ours (resurrect)
	case !oursOK && theirsOK:
		return os.WriteFile(oursPath, ensureTrailingNewline(theirsRaw), 0644) // ours deleted → take theirs (resurrect)
	case !oursOK && !theirsOK:
		return os.WriteFile(oursPath, []byte{}, 0644)
	}

	var ours, theirs Task
	if err := json.Unmarshal(oursRaw, &ours); err != nil {
		return fmt.Errorf("merge-json: parse ours %s: %w", oursPath, err)
	}
	if err := json.Unmarshal(theirsRaw, &theirs); err != nil {
		return fmt.Errorf("merge-json: parse theirs %s: %w", theirsPath, err)
	}

	// Start from the side with the later updated_at (newest content for scalar
	// fields), then apply the union/precedence rules that must not regress.
	// dropped-vs-done is a GENUINE conflict: one side abandoned the task, the
	// other completed it — there is no defensible auto-pick (drop must propagate
	// over non-terminal states, but it must NOT silently override a completion,
	// nor be overridden by one). Refuse to merge so git falls back to conflict
	// markers for a human to resolve. Every OTHER status pair is auto-mergeable
	// by statusRank (most-terminal/most-progressed wins).
	if isDropDoneCollision(ours.Status, theirs.Status) {
		return fmt.Errorf("merge-json: irreconcilable status for %s: one side is %q, the other %q — manual resolution required",
			oursPath, ours.Status, theirs.Status)
	}

	merged := ours
	if theirs.UpdatedAt.After(ours.UpdatedAt) {
		merged = theirs
	}
	// maxStatus picks the winner by NORMALIZED rank but returns the raw string of
	// the winning side, so a side that wrote a non-canonical shape ("DONE", " open ")
	// would store that shape verbatim. The ready-query (deps.go) tests status against
	// the exact lowercase canonical set, so a stored "DONE" is neither filtered as
	// terminal NOR surfaced as ready — a stuck row. Normalize the stored value to the
	// canonical lowercase form (the rank/conflict-guard logic already normalizes for
	// COMPARISON; this closes the gap on the WRITTEN value).
	merged.Status = normalizeStatus(maxStatus(ours.Status, theirs.Status))
	merged.DependsOn = unionSorted(ours.DependsOn, theirs.DependsOn)
	merged.CreatedAt = ours.CreatedAt
	if theirs.CreatedAt.Before(merged.CreatedAt) || merged.CreatedAt.IsZero() {
		merged.CreatedAt = theirs.CreatedAt
	}
	if ours.UpdatedAt.After(merged.UpdatedAt) {
		merged.UpdatedAt = ours.UpdatedAt
	}
	if theirs.UpdatedAt.After(merged.UpdatedAt) {
		merged.UpdatedAt = theirs.UpdatedAt
	}
	// LockedBy/LockedAt are json:"-" (runtime-only, never frozen), so they do not
	// participate — a merge never resurrects a stale lock.

	b, err := json.MarshalIndent(&merged, "", "  ")
	if err != nil {
		return fmt.Errorf("merge-json: marshal merged: %w", err)
	}
	return os.WriteFile(oursPath, append(b, '\n'), 0644)
}

// normalizeStatus folds a possibly non-canonical status string (mixed case,
// surrounding whitespace — e.g. "Dropped", " done ", "DONE") to its canonical
// form so the merge precedence and the dropped-vs-done conflict guard can never
// be bypassed by a side that wrote a status in a non-canonical shape.
func normalizeStatus(s Status) Status {
	return Status(strings.ToLower(strings.TrimSpace(string(s))))
}

// statusRank orders statuses by progress/terminality for the merge precedence.
// Both terminal states rank above every non-terminal one so a stale side can
// never revert them: `done` is the top (a completion is the strongest claim),
// and `dropped` ranks just below it so a drop PROPAGATES over open/in-progress/
// blocked (the abandonment is honored), yet maxStatus would prefer `done` if
// they ever met — which is why a dropped-vs-done pair is intercepted as a
// genuine conflict BEFORE maxStatus runs (isDropDoneCollision), never silently
// resolved by this ranking.
func statusRank(s Status) int {
	switch normalizeStatus(s) {
	case StatusDone:
		return 4
	case StatusDropped:
		return 3
	case StatusBlocked:
		return 2
	case StatusInProgress:
		return 1
	default: // open / unknown
		return 0
	}
}

// isDropDoneCollision reports whether the two sides are the irreconcilable
// {dropped, done} pair (in either order). It is NOT a collision when both sides
// agree (both done or both dropped) — that is a clean no-op merge.
func isDropDoneCollision(a, b Status) bool {
	a, b = normalizeStatus(a), normalizeStatus(b)
	return (a == StatusDropped && b == StatusDone) || (a == StatusDone && b == StatusDropped)
}

func maxStatus(a, b Status) Status {
	if statusRank(b) > statusRank(a) {
		return b
	}
	return a
}

func unionSorted(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func readNonEmpty(path string) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil, false
	}
	return b, true
}

func hasJSONField(raw []byte, field string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	_, ok := m[field]
	return ok
}

func ensureTrailingNewline(b []byte) []byte {
	if len(b) == 0 || b[len(b)-1] == '\n' {
		return b
	}
	return append(b, '\n')
}
