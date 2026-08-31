// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newAuditTestDB builds a temp full-schema taskdb (production initSchema) and
// forces local-only locking, matching newDropTestDB's contract. The watermark
// gauge under test (auditWatermarksFindings) only reads the notes table, but the
// full schema keeps the fixture honest against the real DDL. Returns the live
// read-write DB.
func newAuditTestDB(t *testing.T) *sql.DB {
	t.Helper()
	t.Setenv("TASKDB_LOCK_DISABLE", "1")
	dbFile := filepath.Join(t.TempDir(), "taskdb.sqlite")
	db, err := sql.Open("sqlite", dbFile+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := initSchema(db); err != nil {
		t.Fatalf("initSchema: %v", err)
	}
	return db
}

// insertWatermarkNote seeds one taskless (task_id IS NULL) note — the only note
// kind auditWatermarks/auditWatermarksFindings scan. createdMs orders the
// newest-per-path baseline (auditWatermarks walks created_at DESC), so callers
// pass strictly increasing values to control which version wins per path.
func insertWatermarkNote(t *testing.T, db *sql.DB, id, body string, createdMs int64) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO notes(id, task_id, body, author, created_at) VALUES(?, NULL, ?, ?, ?)`,
		id, body, "audit-test", createdMs,
	); err != nil {
		t.Fatalf("insert note %s: %v", id, err)
	}
}

// watermarkBody renders a well-formed doc-audit watermark note body that both
// the SQL GLOB prefilter and the auditWatermarkNoteRe regex accept.
func watermarkBody(path, hash7 string) string {
	return fmt.Sprintf("doc-audit: %s @ %s ok", path, hash7)
}

// TestAuditWatermarks_GlobLooserThanRegexGuard pins the central reconciliation
// claim in auditWatermarksFindings: the SQL GLOB prefilter is deliberately
// looser than auditWatermarkNoteRe, so the Go-side regex re-parse — not the
// GLOB — defines "matched". A note that satisfies the GLOB's `... ok*` suffix
// but is rejected by the regex's `ok\b` word boundary (trailing junk, e.g.
// "okzzz") must NOT be counted in matched, and must NOT inflate superseded.
func TestAuditWatermarks_GlobLooserThanRegexGuard(t *testing.T) {
	db := newAuditTestDB(t)

	// Two genuine watermarks for the SAME path (so baselines==1, one superseded).
	insertWatermarkNote(t, db, "n1", watermarkBody("docs/a.md", "aaaaaaa"), 1000)
	insertWatermarkNote(t, db, "n2", watermarkBody("docs/a.md", "bbbbbbb"), 2000)

	// GLOB-matches (`doc-audit: ... @ <7hex> ok*`) but the regex's `ok\b` rejects
	// the trailing "zzz" (no word boundary between 'k' and 'z'). This is the
	// GLOB-looser-than-regex case the guard exists for.
	insertWatermarkNote(t, db, "n3", "doc-audit: docs/b.md @ ccccccc okzzz", 3000)

	// Belt-and-suspenders: "okay" is the same class of GLOB-loose junk.
	insertWatermarkNote(t, db, "n4", "doc-audit: docs/c.md @ ddddddd okay", 4000)

	// Verify the GLOB itself DOES admit the junk notes (so the regex re-parse is
	// what's actually doing the rejecting, not the prefilter). If the GLOB already
	// excluded them this test would be vacuous.
	var globCount int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM notes WHERE task_id IS NULL
		AND body GLOB 'doc-audit: * @ [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f] ok*'`,
	).Scan(&globCount); err != nil {
		t.Fatalf("glob count: %v", err)
	}
	if globCount != 4 {
		t.Fatalf("GLOB prefilter matched %d notes, want 4 (incl. the regex-rejected junk) — fixture no longer exercises the GLOB-looser guard", globCount)
	}

	r, err := auditWatermarksFindings(db)
	if err != nil {
		t.Fatalf("auditWatermarksFindings: %v", err)
	}

	// matched counts only the two regex-validated notes (n1, n2); n3/n4 are
	// GLOB-loose junk the regex re-parse drops.
	if r.Matched != 2 {
		t.Errorf("Matched = %d, want 2 (regex-validated only; GLOB-loose junk must not count)", r.Matched)
	}
	// One distinct path with a watermark (docs/a.md). The junk notes carried
	// other paths but never reached the regex parser, so they add no baselines.
	if r.Baselines != 1 {
		t.Errorf("Baselines = %d, want 1 (distinct regex-valid paths)", r.Baselines)
	}
	// superseded = matched(2) − baselines(1).
	if r.Superseded != 1 {
		t.Errorf("Superseded = %d, want 1 (matched−baselines, junk excluded)", r.Superseded)
	}
}

// TestAuditWatermarks_SupersededClampNeverNegative pins the defensive <0 clamp
// (cmd_audit.go ~line 366-368). Even if the GLOB COUNT and the regex baseline
// could disagree such that matched < baselines, superseded must report 0, never
// a negative. We construct the worst case: every GLOB-matched note is regex-
// rejected (matched==0) while there are genuine watermark baselines — wait, that
// can't happen since baselines also comes from the regex. The honest clamp test
// is the all-junk case: matched==0, baselines==0, superseded==0 (not negative),
// plus the GLOB seeing junk so matched is genuinely derived.
func TestAuditWatermarks_SupersededClampNeverNegative(t *testing.T) {
	db := newAuditTestDB(t)

	// All GLOB-matching but all regex-rejected (trailing junk). matched==0,
	// baselines==0 (auditWatermarks also uses the regex), so superseded would be
	// 0−0=0; the clamp guarantees it can never present negative.
	insertWatermarkNote(t, db, "j1", "doc-audit: docs/a.md @ aaaaaaa okZ", 1000)
	insertWatermarkNote(t, db, "j2", "doc-audit: docs/b.md @ bbbbbbb okq", 2000)
	insertWatermarkNote(t, db, "j3", "doc-audit: docs/c.md @ ccccccc ok9", 3000)

	r, err := auditWatermarksFindings(db)
	if err != nil {
		t.Fatalf("auditWatermarksFindings: %v", err)
	}
	if r.Matched != 0 {
		t.Errorf("Matched = %d, want 0 (all junk rejected by regex)", r.Matched)
	}
	if r.Baselines != 0 {
		t.Errorf("Baselines = %d, want 0", r.Baselines)
	}
	if r.Superseded != 0 {
		t.Errorf("Superseded = %d, want 0 (clamp must never present negative)", r.Superseded)
	}
	if r.Superseded < 0 {
		t.Fatalf("Superseded = %d is negative — the defensive clamp regressed", r.Superseded)
	}
	if r.Tripped {
		t.Errorf("Tripped = true with 0 superseded, want false")
	}
}

// TestAuditWatermarks_BaselinesNewestPerPath pins baselines == the distinct-path
// newest-per-path count (len(auditWatermarks())): seed multiple watermark
// versions for one doc path so superseded>0 while baselines stays at the count
// of distinct paths, not the count of notes. Also cross-checks that baselines
// agrees with auditWatermarks() directly (the function the gauge reuses).
func TestAuditWatermarks_BaselinesNewestPerPath(t *testing.T) {
	db := newAuditTestDB(t)

	// docs/a.md: three versions (newest aaaaaa3 by created_at). docs/b.md: one.
	insertWatermarkNote(t, db, "a1", watermarkBody("docs/a.md", "aaaaaa1"), 1000)
	insertWatermarkNote(t, db, "a2", watermarkBody("docs/a.md", "aaaaaa2"), 2000)
	insertWatermarkNote(t, db, "a3", watermarkBody("docs/a.md", "aaaaaa3"), 3000)
	insertWatermarkNote(t, db, "b1", watermarkBody("docs/b.md", "bbbbbb1"), 1500)

	wm, err := auditWatermarks(db)
	if err != nil {
		t.Fatalf("auditWatermarks: %v", err)
	}
	if len(wm) != 2 {
		t.Fatalf("auditWatermarks returned %d paths, want 2", len(wm))
	}
	// newest-per-path: docs/a.md must resolve to the highest created_at version.
	if got := wm["docs/a.md"].hash; got != "aaaaaa3" {
		t.Errorf("docs/a.md baseline hash = %q, want aaaaaa3 (newest wins)", got)
	}
	if got := wm["docs/b.md"].hash; got != "bbbbbb1" {
		t.Errorf("docs/b.md baseline hash = %q, want bbbbbb1", got)
	}

	r, err := auditWatermarksFindings(db)
	if err != nil {
		t.Fatalf("auditWatermarksFindings: %v", err)
	}
	if r.Matched != 4 {
		t.Errorf("Matched = %d, want 4 (all four notes regex-valid)", r.Matched)
	}
	if r.Baselines != len(wm) {
		t.Errorf("Baselines = %d, want %d (== len(auditWatermarks()))", r.Baselines, len(wm))
	}
	if r.Baselines != 2 {
		t.Errorf("Baselines = %d, want 2 distinct paths", r.Baselines)
	}
	// superseded = matched(4) − baselines(2) = the 2 older docs/a.md versions.
	if r.Superseded != 2 {
		t.Errorf("Superseded = %d, want 2 (the non-newest docs/a.md versions)", r.Superseded)
	}
}

// TestAuditWatermarks_TrippedTriggerBoundary pins Tripped == (superseded >=
// auditOQ5SupersededTrigger) exactly at the boundary: trigger−1 supersededs is
// NOT tripped, trigger supersededs IS tripped. Built by seeding one baseline
// path plus (trigger−1) and then (trigger) extra superseded versions of it.
func TestAuditWatermarks_TrippedTriggerBoundary(t *testing.T) {
	trigger := auditOQ5SupersededTrigger // single-sourced; test stays correct if the literal moves.

	t.Run("at trigger-1 not tripped", func(t *testing.T) {
		db := newAuditTestDB(t)
		// One path; (trigger-1)+1 total notes => superseded == trigger-1.
		seedSupersededVersions(t, db, "docs/boundary.md", trigger-1)

		r, err := auditWatermarksFindings(db)
		if err != nil {
			t.Fatalf("auditWatermarksFindings: %v", err)
		}
		if r.Superseded != trigger-1 {
			t.Fatalf("Superseded = %d, want %d (== trigger-1)", r.Superseded, trigger-1)
		}
		if r.Trigger != trigger {
			t.Errorf("Trigger = %d, want %d", r.Trigger, trigger)
		}
		if r.Tripped {
			t.Errorf("Tripped = true at superseded=%d (trigger=%d), want false (>= is strict at the boundary)", r.Superseded, trigger)
		}
	})

	t.Run("at trigger tripped", func(t *testing.T) {
		db := newAuditTestDB(t)
		// One path; trigger+1 total notes => superseded == trigger.
		seedSupersededVersions(t, db, "docs/boundary.md", trigger)

		r, err := auditWatermarksFindings(db)
		if err != nil {
			t.Fatalf("auditWatermarksFindings: %v", err)
		}
		if r.Superseded != trigger {
			t.Fatalf("Superseded = %d, want %d (== trigger)", r.Superseded, trigger)
		}
		if !r.Tripped {
			t.Errorf("Tripped = false at superseded=%d (trigger=%d), want true (>= boundary)", r.Superseded, trigger)
		}
	})
}

// seedSupersededVersions seeds (superseded+1) watermark notes for a single path
// — one newest baseline plus `superseded` older versions — so the gauge reports
// exactly `superseded` superseded and 1 baseline. Each note gets a distinct
// strictly-increasing created_at and a distinct 7-hex hash.
func seedSupersededVersions(t *testing.T, db *sql.DB, path string, superseded int) {
	t.Helper()
	total := superseded + 1
	base := timeToMs(time.Now().UTC())
	for i := 0; i < total; i++ {
		hash7 := fmt.Sprintf("%07x", i)
		id := fmt.Sprintf("%s-%d", path, i)
		insertWatermarkNote(t, db, id, watermarkBody(path, hash7), base+int64(i))
	}
}

// --- error-propagation coverage (auditWatermarksFindings) ------------------

// TestAuditWatermarksFindings_BaselineQueryErrorClosedDB pins that a baseline
// query failure is propagated, not swallowed: auditWatermarksFindings first calls
// auditWatermarks(), whose db.Query over `notes WHERE task_id IS NULL`
// (cmd_audit.go ~L273) fails on a closed *sql.DB. The error must surface and the
// readout must be nil — the gauge must never report a falsely-clean count when it
// could not even read the baseline.
func TestAuditWatermarksFindings_BaselineQueryErrorClosedDB(t *testing.T) {
	db := newAuditTestDB(t)
	db.Close() // every subsequent query returns "database is closed".

	r, err := auditWatermarksFindings(db)
	if err == nil {
		t.Fatalf("auditWatermarksFindings on a closed DB returned nil error — the baseline-query error was swallowed")
	}
	if r != nil {
		t.Errorf("readout = %+v on baseline-query error, want nil (no falsely-clean count)", r)
	}
}

// TestAuditWatermarksFindings_BaselineQueryErrorMissingNotesTable pins the same
// propagation through a different failure shape: a full-schema DB with the `notes`
// table dropped. The baseline query in auditWatermarks() then fails with
// "no such table: notes" and that error must propagate with a nil readout.
func TestAuditWatermarksFindings_BaselineQueryErrorMissingNotesTable(t *testing.T) {
	db := newAuditTestDB(t)
	if _, err := db.Exec(`DROP TABLE notes`); err != nil {
		t.Fatalf("drop notes: %v", err)
	}

	r, err := auditWatermarksFindings(db)
	if err == nil {
		t.Fatalf("auditWatermarksFindings with no notes table returned nil error — the baseline-query error was swallowed")
	}
	if r != nil {
		t.Errorf("readout = %+v with no notes table, want nil", r)
	}
	if !strings.Contains(err.Error(), "notes") {
		t.Errorf("error %q does not mention the missing notes table", err)
	}
}

// TestAuditWatermarksFindings_RowScanErrorSurfaces pins the rows.Scan iteration
// leg: a malformed row must produce an error, not a falsely-clean readout.
// auditWatermarks scans `created_at` into an int64; SQLite's INTEGER affinity
// stores a non-numeric string verbatim (typeof == text), so the driver's
// string->int64 conversion in rows.Scan (cmd_audit.go ~L284) fails. Because
// auditWatermarksFindings calls auditWatermarks() first, this scan error is the
// one that surfaces — assert it propagates with a nil readout.
func TestAuditWatermarksFindings_RowScanErrorSurfaces(t *testing.T) {
	db := newAuditTestDB(t)
	// A well-formed watermark body (so the row would parse) but a non-numeric
	// created_at that defeats the int64 Scan. Direct Exec, not insertWatermarkNote,
	// because that helper's signature only takes an int64 created_at.
	if _, err := db.Exec(
		`INSERT INTO notes(id, task_id, body, author, created_at) VALUES('bad', NULL, ?, 'audit-test', 'not-a-number')`,
		watermarkBody("docs/a.md", "aaaaaaa"),
	); err != nil {
		t.Fatalf("insert malformed note: %v", err)
	}
	// Sanity: the column really did store text (so the Scan is what fails, not the
	// query). If SQLite had coerced it to an integer this test would be vacuous.
	var typ string
	if err := db.QueryRow(`SELECT typeof(created_at) FROM notes WHERE id='bad'`).Scan(&typ); err != nil {
		t.Fatalf("typeof probe: %v", err)
	}
	if typ != "text" {
		t.Fatalf("created_at stored as %q, want text — fixture no longer exercises the Scan-error leg", typ)
	}

	r, err := auditWatermarksFindings(db)
	if err == nil {
		t.Fatalf("auditWatermarksFindings over a malformed row returned nil error — the rows.Scan error was swallowed (falsely-clean readout)")
	}
	if r != nil {
		t.Errorf("readout = %+v on rows.Scan error, want nil", r)
	}
}

// --- CLI-render coverage (auditWatermarksCmd stdout) -----------------------

// captureStdout redirects os.Stdout through an os.Pipe for the duration of fn and
// returns everything written. It restores os.Stdout even if fn panics. The pipe is
// drained on a goroutine so a write larger than the pipe buffer cannot deadlock.
// It mutates the global os.Stdout, so it is NOT safe under t.Parallel — callers
// (there are several across this file) must not run these captures concurrently.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan string, 1)
	go func() {
		var buf strings.Builder
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	defer func() {
		os.Stdout = orig
		_ = r.Close()
	}()
	func() {
		defer w.Close() // close the writer so io.Copy sees EOF, even on panic
		fn()
	}()
	return <-done
}

// TestAuditWatermarksCmd_DefaultHumanReadout pins the default (non-JSON) operator
// line: "watermarks: N matched, M baselines, K superseded (OQ5 trigger T)". Seed a
// known shape (one path, 2 superseded versions => 3 matched, 1 baseline) and assert
// the rendered counts. Below the trigger, the trigger-tripped line must be absent.
func TestAuditWatermarksCmd_DefaultHumanReadout(t *testing.T) {
	db := newAuditTestDB(t)
	seedSupersededVersions(t, db, "docs/a.md", 2) // 1 baseline + 2 superseded == 3 matched

	out := captureStdout(t, func() {
		if err := auditWatermarksCmd(db, nil); err != nil {
			t.Fatalf("auditWatermarksCmd: %v", err)
		}
	})

	want := fmt.Sprintf("watermarks: 3 matched, 1 baselines, 2 superseded (OQ5 trigger %d)", auditOQ5SupersededTrigger)
	if !strings.Contains(out, want) {
		t.Errorf("default readout missing summary line.\n got: %q\nwant substring: %q", out, want)
	}
	if strings.Contains(out, "trigger-tripped:") {
		t.Errorf("trigger-tripped line printed below the trigger (2 superseded < %d):\n%s", auditOQ5SupersededTrigger, out)
	}
}

// TestAuditWatermarksCmd_JSONShape pins the operator-facing JSON contract of the
// --json branch: the exact keys matched/baselines/superseded/trigger/tripped from
// auditWatermarksReadout (docs/22 §7-style stable shape). The values are checked
// against the same seeded fixture so a silent key rename or type change is caught.
func TestAuditWatermarksCmd_JSONShape(t *testing.T) {
	db := newAuditTestDB(t)
	seedSupersededVersions(t, db, "docs/a.md", 2) // 3 matched, 1 baseline, 2 superseded

	out := captureStdout(t, func() {
		if err := auditWatermarksCmd(db, []string{"--json"}); err != nil {
			t.Fatalf("auditWatermarksCmd --json: %v", err)
		}
	})

	// Decode into a generic map so a renamed or dropped key is caught, then assert
	// every documented operator-facing key is present with the right value/type.
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\nraw: %q", err, out)
	}
	for _, k := range []string{"matched", "baselines", "superseded", "trigger", "tripped"} {
		if _, ok := m[k]; !ok {
			t.Errorf("operator-facing JSON key %q missing (keys present: %v)", k, keysOf(m))
		}
	}
	// json numbers decode as float64; compare via that.
	wantNum := map[string]float64{
		"matched":    3,
		"baselines":  1,
		"superseded": 2,
		"trigger":    float64(auditOQ5SupersededTrigger),
	}
	for k, want := range wantNum {
		got, ok := m[k].(float64)
		if !ok {
			t.Errorf("JSON key %q is %T, want a number", k, m[k])
			continue
		}
		if got != want {
			t.Errorf("JSON %q = %v, want %v", k, got, want)
		}
	}
	if tripped, ok := m["tripped"].(bool); !ok {
		t.Errorf("JSON key \"tripped\" is %T, want bool", m["tripped"])
	} else if tripped {
		t.Errorf("JSON tripped = true with 2 superseded (< trigger %d), want false", auditOQ5SupersededTrigger)
	}

	// Belt-and-suspenders: round-trip back through the typed struct so the field
	// tags themselves (not just our key list) are what produced this output.
	var typed auditWatermarksReadout
	if err := json.Unmarshal([]byte(out), &typed); err != nil {
		t.Fatalf("--json output does not unmarshal into auditWatermarksReadout: %v", err)
	}
	if typed.Matched != 3 || typed.Baselines != 1 || typed.Superseded != 2 ||
		typed.Trigger != auditOQ5SupersededTrigger || typed.Tripped {
		t.Errorf("typed round-trip mismatch: %+v", typed)
	}
}

// keysOf returns the keys of a decoded JSON object for diagnostic messages.
func keysOf(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// TestAuditWatermarksCmd_TrippedBanner pins the reopen-trigger banner: once
// superseded watermarks reach auditOQ5SupersededTrigger, auditWatermarksCmd prints
// the "trigger-tripped:" line in the default (human) mode. The threshold is
// single-sourced from the exported const — NEVER a hardcoded 50 — so the test
// stays correct if the constant moves. Seed exactly `trigger` superseded versions
// of one path (1 baseline + trigger older), which is the >= boundary.
func TestAuditWatermarksCmd_TrippedBanner(t *testing.T) {
	db := newAuditTestDB(t)
	seedSupersededVersions(t, db, "docs/hot.md", auditOQ5SupersededTrigger)

	// Cross-check the fixture actually trips before asserting on the rendered line,
	// so a banner-absent failure can't be mistaken for a mis-seeded fixture.
	r, err := auditWatermarksFindings(db)
	if err != nil {
		t.Fatalf("auditWatermarksFindings: %v", err)
	}
	if r.Superseded != auditOQ5SupersededTrigger {
		t.Fatalf("fixture seeded %d superseded, want %d (== trigger)", r.Superseded, auditOQ5SupersededTrigger)
	}
	if !r.Tripped {
		t.Fatalf("fixture not tripped at superseded=%d trigger=%d", r.Superseded, auditOQ5SupersededTrigger)
	}

	out := captureStdout(t, func() {
		if err := auditWatermarksCmd(db, nil); err != nil {
			t.Fatalf("auditWatermarksCmd: %v", err)
		}
	})

	if !strings.Contains(out, "trigger-tripped:") {
		t.Errorf("trigger-tripped banner absent at superseded=%d (trigger %d):\n%s",
			auditOQ5SupersededTrigger, auditOQ5SupersededTrigger, out)
	}
	// The banner must interpolate the live count, not print a stale literal — at
	// the >= boundary superseded == trigger == auditOQ5SupersededTrigger, so the
	// parenthesized count must appear (a format change that drops it is caught).
	wantSup := fmt.Sprintf("(%d)", auditOQ5SupersededTrigger) // "superseded watermarks (T) >= ... (T)"
	if !strings.Contains(out, wantSup) {
		t.Errorf("trigger-tripped banner missing the interpolated count %q:\n%s", wantSup, out)
	}
}

// --- shared fixtures for the four sibling audit commands -------------------

// chdirTempRepo builds a hermetic synthetic repo root (a fake .git dir so
// repoRoot() stops here, plus an empty docs/ dir) and chdirs into it for the
// test's lifetime, restoring the prior CWD on cleanup. auditDriftFindings /
// auditAllCmd run syncDocs → docWalk → repoRoot(cwd), so the drift and all pins
// MUST run inside such a root — never the live checkout — or they would walk this
// repo's real docs/. Pattern mirrors cmd_stage_test.go:64-66.
func chdirTempRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{".git", "docs"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	if err := os.Chdir(root); err != nil {
		t.Fatalf("chdir %s: %v", root, err)
	}
	return root
}

// writeDoc writes a doc file (rel is a repo-relative forward-slash path) under
// the synthetic repo root, creating intermediate dirs.
func writeDoc(t *testing.T, root, rel string, content []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir for %s: %v", rel, err)
	}
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

// seedAuditTask inserts one task with the given id/status/body and a matching
// created_at/updated_at, the minimal shape the dag/stuck audits read.
func seedAuditTask(t *testing.T, db *sql.DB, id, status, body string, whenMs int64) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
		id, "t-"+id, body, status, whenMs, whenMs,
	); err != nil {
		t.Fatalf("seed task %s: %v", id, err)
	}
}

// insertDanglingDep inserts a task_deps edge whose depends_on names a task that
// does not exist — the "missing-dep" shape auditDagFindings surfaces. The test DB
// enforces foreign keys (DSN _pragma=foreign_keys(1)), which would reject such an
// edge, so this disables FK enforcement on a single dedicated pooled connection
// for the one write. FK checks run at write time only; the committed row is then
// visible to every reader, and thaw (which never re-validates the DAG) is exactly
// how such a dangling edge reaches the live DB in production.
func insertDanglingDep(t *testing.T, db *sql.DB, taskID, dependsOn string) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("acquire conn: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=OFF`); err != nil {
		t.Fatalf("disable FK: %v", err)
	}
	// Restore FK enforcement before the connection returns to the pool so a later
	// reuse of this exact conn never silently runs unchecked.
	defer func() { _, _ = conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`) }()
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO task_deps(task_id,depends_on) VALUES(?,?)`, taskID, dependsOn,
	); err != nil {
		t.Fatalf("insert dangling dep %s->%s: %v", taskID, dependsOn, err)
	}
}

// seedDriftFindings sets up a hermetic drift fixture and returns the drifted
// doc's current 7-hex hash plus the task/doc identity of the dangling citation.
// It relies on syncDocs' GATED task_sources rebuild (cmd_doc.go docRebuildSources):
// after an initial prime sync sets the docs table and the task-body fingerprint,
// neither the doc content nor any task body changes, so auditDriftFindings' own
// implicit sync skips the rebuild and the hand-inserted dangling task_sources edge
// survives to be reported. Must be called from a test that will run the audit with
// CWD already inside the returned root (chdirTempRepo does the chdir here).
func seedDriftFindings(t *testing.T, db *sql.DB) (cur7, danglingTask, danglingDoc string) {
	t.Helper()
	root := chdirTempRepo(t)
	content := []byte("# Drift doc\n\n## 1. Alpha\n\nbody text\n")
	writeDoc(t, root, "docs/50-drift.md", content)

	// The task that will carry the dangling citation must exist BEFORE the prime
	// sync so it is folded into the task-body fingerprint; only then does the
	// audit's own sync see an unchanged fingerprint and skip the rebuild.
	danglingTask = "01DRIFTDANGLER000000000AA"
	seedAuditTask(t, db, danglingTask, "open", "", timeToMs(time.Now().UTC()))

	if _, err := syncDocs(db, true); err != nil {
		t.Fatalf("prime syncDocs: %v", err)
	}

	// Stale watermark → the doc's current hash != baseline → "drifted".
	cur7 = auditShortHash(gitBlobSHA(content))
	stale := "0000000"
	if cur7 == stale {
		stale = "1111111"
	}
	insertWatermarkNote(t, db, "wm-drift", watermarkBody("docs/50-drift.md", stale), timeToMs(time.Now().UTC()))

	// A task_sources edge to a doc that is not on disk → "dangling". Inserted after
	// the prime so the rebuild (now skipped) cannot wipe it; parseSources would drop
	// an unresolvable citation, so a hand-inserted edge is the only way to pin it.
	danglingDoc = "docs/98-gone.md"
	if _, err := db.Exec(
		`INSERT INTO task_sources(task_id,doc_path,section) VALUES(?,?,'')`, danglingTask, danglingDoc,
	); err != nil {
		t.Fatalf("insert dangling task_source: %v", err)
	}
	return cur7, danglingTask, danglingDoc
}

// seedStuckFindings seeds one stale-lock task (locked past staleLockThreshold) and
// one idle in-progress task (unlocked, updated_at older than the 24h default age),
// the two auditStuck human lines that need no filesystem. Returns the two ids.
func seedStuckFindings(t *testing.T, db *sql.DB) (staleLockID, idleID string) {
	t.Helper()
	now := time.Now().UTC()
	staleLockID = "01STALELOCK00000000000000AA"
	lockedAt := timeToMs(now.Add(-2 * staleLockThreshold)) // well past the 30-min threshold
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,locked_by,locked_at,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?)`,
		staleLockID, "held task", "", "in-progress", "agent-x", lockedAt, lockedAt, lockedAt,
	); err != nil {
		t.Fatalf("seed stale-lock task: %v", err)
	}
	idleID = "01IDLEINPROG0000000000000AA"
	idleAt := timeToMs(now.Add(-48 * time.Hour)) // older than the 24h default --age
	seedAuditTask(t, db, idleID, "in-progress", "", idleAt)
	return staleLockID, idleID
}

// seedDagFindings seeds a 2-task dependency cycle (A→B→A) and one task with a dep
// on a nonexistent id, the "cycle" and "missing-dep" auditDag lines. Returns the
// three ids.
func seedDagFindings(t *testing.T, db *sql.DB) (cycleA, cycleB, missingSrc string) {
	t.Helper()
	now := timeToMs(time.Now().UTC())
	cycleA, cycleB = "01CYCLEAAAA00000000000000AA", "01CYCLEBBBB00000000000000AA"
	seedAuditTask(t, db, cycleA, "open", "", now)
	seedAuditTask(t, db, cycleB, "open", "", now)
	for _, e := range [][2]string{{cycleA, cycleB}, {cycleB, cycleA}} {
		if _, err := db.Exec(`INSERT INTO task_deps(task_id,depends_on) VALUES(?,?)`, e[0], e[1]); err != nil {
			t.Fatalf("insert cycle edge %s->%s: %v", e[0], e[1], err)
		}
	}
	missingSrc = "01MISSINGDEPSRC000000000AA"
	seedAuditTask(t, db, missingSrc, "open", "", now)
	insertDanglingDep(t, db, missingSrc, "01NOSUCHTASK00000000000AA")
	return cycleA, cycleB, missingSrc
}

// seedBrokenAnchorFindings seeds the broken_anchors arm of `audit drift`: a doc
// that IS on disk (so the citation is not "dangling") with a known count of
// numbered H2 sections, plus a hand-inserted task_sources edge citing a "§N"
// section past that count. It reuses seedDriftFindings' gated-rebuild trick — the
// citing task exists before the prime sync so the audit's own implicit sync sees
// an unchanged task-body fingerprint and skips docRebuildSources, letting the
// hand-inserted edge survive (parseSources would otherwise drop a §N fragment on
// an empty body). Chdirs into a synthetic repo; returns the citing task id, the
// doc path, the seeded section fragment, and the doc's numbered-H2 count.
func seedBrokenAnchorFindings(t *testing.T, db *sql.DB) (citingTask, docPath, section string, headingCount int) {
	t.Helper()
	root := chdirTempRepo(t)
	// Exactly two numbered top-level sections => auditNumberedH2 == 2. The §7
	// citation below (7 > 2) is the "anchor past the doc's sections" case.
	docPath = "docs/60-anchor.md"
	content := []byte("# Anchor doc\n\n## 1. Alpha\n\na\n\n## 2. Beta\n\nb\n")
	writeDoc(t, root, docPath, content)
	headingCount = 2

	// The citing task must exist BEFORE the prime sync so its (empty) body is folded
	// into the task-body fingerprint; the audit's re-sync then sees no change and
	// skips the source rebuild that would wipe the hand-inserted edge.
	citingTask = "01ANCHORCITER00000000000AA"
	seedAuditTask(t, db, citingTask, "open", "", timeToMs(time.Now().UTC()))

	if _, err := syncDocs(db, true); err != nil {
		t.Fatalf("prime syncDocs: %v", err)
	}

	// §7 > 2 numbered sections => a broken anchor. doc_path resolves to an on-disk
	// doc (LEFT JOIN docs is non-NULL) so this is the anchor arm, not the dangling
	// arm. Inserted after the prime so the now-skipped rebuild cannot drop it.
	section = "§7"
	if _, err := db.Exec(
		`INSERT INTO task_sources(task_id,doc_path,section) VALUES(?,?,?)`, citingTask, docPath, section,
	); err != nil {
		t.Fatalf("insert broken-anchor task_source: %v", err)
	}
	return citingTask, docPath, section, headingCount
}

// seedWorktreeFindings seeds the two worktree arms of `audit stuck`: one
// done_worktrees row (its task is done, its path still exists on disk, so it
// lands ONLY in DoneWorktrees) and one missing_worktrees row (its task is still
// in-progress but its path is gone, so it lands ONLY in MissingWorktrees). Kept
// deliberately disjoint — one row per arm with the other predicate false — so each
// arm pins to exactly one entry. Returns the two rows' (path, task, branch).
func seedWorktreeFindings(t *testing.T, db *sql.DB) (donePath, doneTask, doneBranch, missPath, missTask, missBranch string) {
	t.Helper()
	now := timeToMs(time.Now().UTC())

	// done_worktrees: task done, path present. Use a real subdir so auditPathExists
	// is true and the row does NOT also appear under missing_worktrees.
	doneTask = "01WTDONE000000000000000AA"
	seedAuditTask(t, db, doneTask, string(StatusDone), "", now)
	donePath = filepath.Join(t.TempDir(), "wt-done")
	if err := os.Mkdir(donePath, 0o755); err != nil {
		t.Fatalf("mkdir done worktree path: %v", err)
	}
	doneBranch = "wave/wt-done"

	// missing_worktrees: task NOT terminal (so it stays out of done_worktrees), path
	// absent. updated_at=now keeps it out of the idle-in-progress arm too.
	missTask = "01WTMISS000000000000000AA"
	seedAuditTask(t, db, missTask, string(StatusInProgress), "", now)
	missPath = filepath.Join(t.TempDir(), "wt-gone") // never created => stat fails
	missBranch = "wave/wt-miss"

	for _, w := range []struct{ path, task, branch string }{
		{donePath, doneTask, doneBranch},
		{missPath, missTask, missBranch},
	} {
		if _, err := db.Exec(
			`INSERT INTO worktrees(path,task_id,branch,base_ref,created_at,last_used_at)
			 VALUES(?,?,?,?,?,?)`,
			w.path, w.task, w.branch, "origin/main", now, now,
		); err != nil {
			t.Fatalf("insert worktree row %s: %v", w.path, err)
		}
	}
	return donePath, doneTask, doneBranch, missPath, missTask, missBranch
}

// --- default human-readout pins: stuck / dag ------------------------------

// TestAuditStuckCmd_DefaultHumanReadout pins the default (non-JSON) operator lines
// of `audit stuck`: the "stale-lock:" line for a lock held past staleLockThreshold
// and the "idle-in-progress:" line for an unlocked in-progress task idle past the
// default --age. Both prefixes are asserted at cmd_audit.go:489/:492.
func TestAuditStuckCmd_DefaultHumanReadout(t *testing.T) {
	db := newAuditTestDB(t)
	staleLockID, idleID := seedStuckFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditStuckCmd(db, nil); err != nil {
			t.Fatalf("auditStuckCmd: %v", err)
		}
	})

	if !strings.Contains(out, "stale-lock: ["+staleLockID+"]") {
		t.Errorf("stale-lock line missing for %s:\n%s", staleLockID, out)
	}
	if !strings.Contains(out, "held by agent-x") {
		t.Errorf("stale-lock line missing lock holder:\n%s", out)
	}
	if !strings.Contains(out, "idle-in-progress: ["+idleID+"]") {
		t.Errorf("idle-in-progress line missing for %s:\n%s", idleID, out)
	}
}

// TestAuditDagCmd_DefaultHumanReadout pins the default (non-JSON) operator lines of
// `audit dag`: the "cycle:" line for a 2-task dependency loop and the "missing-dep:"
// line for an edge onto a nonexistent id. Prefixes asserted at cmd_audit.go:683/:686.
func TestAuditDagCmd_DefaultHumanReadout(t *testing.T) {
	db := newAuditTestDB(t)
	cycleA, cycleB, missingSrc := seedDagFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditDagCmd(db, nil); err != nil {
			t.Fatalf("auditDagCmd: %v", err)
		}
	})

	if !strings.Contains(out, "cycle:") {
		t.Errorf("cycle line missing:\n%s", out)
	}
	// The rendered cycle names both members (order depends on the entry point, so
	// assert membership rather than a fixed arrow direction).
	if !strings.Contains(out, cycleA) || !strings.Contains(out, cycleB) {
		t.Errorf("cycle line does not name both members %s and %s:\n%s", cycleA, cycleB, out)
	}
	if !strings.Contains(out, "missing-dep: task "+missingSrc) {
		t.Errorf("missing-dep line missing for %s:\n%s", missingSrc, out)
	}
	if !strings.Contains(out, "01NOSUCHTASK00000000000AA") {
		t.Errorf("missing-dep line does not name the nonexistent dependency:\n%s", out)
	}
}

// --- default human-readout pins: drift / all (hermetic) -------------------

// TestAuditDriftCmd_DefaultHumanReadout pins the default (non-JSON) operator lines
// of `audit drift`: "drifted:" for a doc whose current hash != its watermark
// baseline, and "dangling:" for a task_sources edge to a doc that is not on disk.
// Runs inside a synthetic repo (seedDriftFindings chdirs) so auditDriftFindings'
// repoRoot(cwd) doc walk never touches the live checkout. Prefixes at
// cmd_audit.go:137/:143.
func TestAuditDriftCmd_DefaultHumanReadout(t *testing.T) {
	db := newAuditTestDB(t)
	cur7, danglingTask, danglingDoc := seedDriftFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditDriftCmd(db, nil); err != nil {
			t.Fatalf("auditDriftCmd: %v", err)
		}
	})

	wantDrift := "drifted: docs/50-drift.md (" + cur7
	if !strings.Contains(out, wantDrift) {
		t.Errorf("drifted line missing or wrong hash.\nwant substring: %q\n got: %q", wantDrift, out)
	}
	wantDangle := "dangling: task " + danglingTask + " cites missing " + danglingDoc
	if !strings.Contains(out, wantDangle) {
		t.Errorf("dangling line missing.\nwant substring: %q\n got: %q", wantDangle, out)
	}
}

// TestAuditAllCmd_DefaultHumanReadout pins that `audit all` concatenates every
// verb's plain lines: a drift line (via a stale watermark), a stuck line, and a
// dag line must all appear from one invocation. Hermetic: chdir into a synthetic
// repo first (auditAllCmd runs auditDriftFindings). Assert the combined output at
// cmd_audit.go:1104-1155.
func TestAuditAllCmd_DefaultHumanReadout(t *testing.T) {
	db := newAuditTestDB(t)

	// Drift arm: a doc + a stale watermark. No dangling edge here (that needs the
	// gated-rebuild prime), so this fixture stays simple — `audit all` re-syncs.
	root := chdirTempRepo(t)
	content := []byte("# All doc\n\n## 1. A\n\nbody\n")
	writeDoc(t, root, "docs/51-all.md", content)
	cur7 := auditShortHash(gitBlobSHA(content))
	stale := "0000000"
	if cur7 == stale {
		stale = "1111111"
	}
	insertWatermarkNote(t, db, "wm-all", watermarkBody("docs/51-all.md", stale), timeToMs(time.Now().UTC()))

	// Stuck + dag arms.
	staleLockID, _ := seedStuckFindings(t, db)
	cycleA, cycleB, _ := seedDagFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditAllCmd(db, nil); err != nil {
			t.Fatalf("auditAllCmd: %v", err)
		}
	})

	if !strings.Contains(out, "drifted: docs/51-all.md ("+cur7) {
		t.Errorf("audit all missing the drift line:\n%s", out)
	}
	if !strings.Contains(out, "stale-lock: ["+staleLockID+"]") {
		t.Errorf("audit all missing the stuck line:\n%s", out)
	}
	if !strings.Contains(out, "cycle:") || !strings.Contains(out, cycleA) || !strings.Contains(out, cycleB) {
		t.Errorf("audit all missing the dag cycle line:\n%s", out)
	}
}

// --- --json shape pins for all four commands ------------------------------

// TestAuditDriftCmd_JSONShape pins the `audit drift --json` contract: the three
// docs/22 §7 keys decode as a generic map, and the payload round-trips through the
// typed auditDrift struct with the seeded drifted-doc and dangling-link values.
func TestAuditDriftCmd_JSONShape(t *testing.T) {
	db := newAuditTestDB(t)
	cur7, danglingTask, danglingDoc := seedDriftFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditDriftCmd(db, []string{"--json"}); err != nil {
			t.Fatalf("auditDriftCmd --json: %v", err)
		}
	})

	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\nraw: %q", err, out)
	}
	for _, k := range []string{"docs", "dangling_links", "broken_anchors"} {
		if _, ok := m[k]; !ok {
			t.Errorf("contract key %q missing (present: %v)", k, keysOf(m))
		}
	}

	var typed auditDrift
	if err := json.Unmarshal([]byte(out), &typed); err != nil {
		t.Fatalf("--json does not unmarshal into auditDrift: %v", err)
	}
	var gotDrift bool
	for _, d := range typed.Docs {
		if d.Path == "docs/50-drift.md" {
			if d.State != "drifted" {
				t.Errorf("docs/50-drift.md State = %q, want drifted", d.State)
			}
			if d.CurrentHash != cur7 {
				t.Errorf("docs/50-drift.md CurrentHash = %q, want %q", d.CurrentHash, cur7)
			}
			gotDrift = true
		}
	}
	if !gotDrift {
		t.Errorf("drifted doc absent from typed Docs: %+v", typed.Docs)
	}
	var gotDangle bool
	for _, l := range typed.DanglingLinks {
		if l.TaskID == danglingTask && l.DocPath == danglingDoc {
			gotDangle = true
		}
	}
	if !gotDangle {
		t.Errorf("dangling link %s->%s absent from typed DanglingLinks: %+v", danglingTask, danglingDoc, typed.DanglingLinks)
	}
}

// TestAuditDriftCmd_BrokenAnchorValuePin turns the broken_anchors contract key
// (pinned shape-only in TestAuditDriftCmd_JSONShape) into a value pin: seed a doc
// on disk with two numbered sections plus a task citing "§7", then assert the
// --json payload decodes exactly one broken_anchors entry carrying the seeded
// task/doc/section and the doc's numbered-H2 count. A regression that stops
// flagging §N-past-the-doc, or that mis-reports the heading count, fails here.
func TestAuditDriftCmd_BrokenAnchorValuePin(t *testing.T) {
	db := newAuditTestDB(t)
	citingTask, docPath, section, headingCount := seedBrokenAnchorFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditDriftCmd(db, []string{"--json"}); err != nil {
			t.Fatalf("auditDriftCmd --json: %v", err)
		}
	})

	// Generic-map guard: the contract key must be present AND carry a non-empty
	// array (shape-only tests only checked presence).
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\nraw: %q", err, out)
	}
	arr, ok := m["broken_anchors"].([]any)
	if !ok {
		t.Fatalf("broken_anchors is %T, want a JSON array", m["broken_anchors"])
	}
	if len(arr) == 0 {
		t.Fatalf("broken_anchors decoded empty; want the seeded §7 finding (raw: %q)", out)
	}

	// Typed round-trip so the JSON field tags themselves produced the values.
	var typed auditDrift
	if err := json.Unmarshal([]byte(out), &typed); err != nil {
		t.Fatalf("--json does not unmarshal into auditDrift: %v", err)
	}
	var got *auditBrokenAnchor
	for i := range typed.BrokenAnchors {
		if typed.BrokenAnchors[i].TaskID == citingTask {
			got = &typed.BrokenAnchors[i]
			break
		}
	}
	if got == nil {
		t.Fatalf("no broken_anchors entry for citing task %s: %+v", citingTask, typed.BrokenAnchors)
	}
	if got.DocPath != docPath {
		t.Errorf("broken anchor DocPath = %q, want %q", got.DocPath, docPath)
	}
	if got.Section != section {
		t.Errorf("broken anchor Section = %q, want %q", got.Section, section)
	}
	if got.HeadingCount != headingCount {
		t.Errorf("broken anchor HeadingCount = %d, want %d (numbered H2s in the seeded doc)", got.HeadingCount, headingCount)
	}

	// The citation is on an on-disk doc, so it must NOT also surface as dangling —
	// that would mean the anchor arm and the dangling arm disagree on join state.
	for _, l := range typed.DanglingLinks {
		if l.TaskID == citingTask && l.DocPath == docPath {
			t.Errorf("on-disk anchor citation %s->%s wrongly reported dangling", citingTask, docPath)
		}
	}
}

// TestAuditStuckCmd_JSONShape pins the `audit stuck --json` contract keys and a
// typed round-trip carrying the seeded stale-lock and idle-in-progress ids.
func TestAuditStuckCmd_JSONShape(t *testing.T) {
	db := newAuditTestDB(t)
	staleLockID, idleID := seedStuckFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditStuckCmd(db, []string{"--json"}); err != nil {
			t.Fatalf("auditStuckCmd --json: %v", err)
		}
	})

	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\nraw: %q", err, out)
	}
	for _, k := range []string{"stale_locks", "idle_in_progress", "done_worktrees", "missing_worktrees"} {
		if _, ok := m[k]; !ok {
			t.Errorf("contract key %q missing (present: %v)", k, keysOf(m))
		}
	}

	var typed auditStuck
	if err := json.Unmarshal([]byte(out), &typed); err != nil {
		t.Fatalf("--json does not unmarshal into auditStuck: %v", err)
	}
	if len(typed.StaleLocks) != 1 || typed.StaleLocks[0].ID != staleLockID {
		t.Errorf("StaleLocks = %+v, want one entry for %s", typed.StaleLocks, staleLockID)
	}
	if typed.StaleLocks[0].LockedBy != "agent-x" {
		t.Errorf("StaleLocks[0].LockedBy = %q, want agent-x", typed.StaleLocks[0].LockedBy)
	}
	if len(typed.IdleInProgress) != 1 || typed.IdleInProgress[0].ID != idleID {
		t.Errorf("IdleInProgress = %+v, want one entry for %s", typed.IdleInProgress, idleID)
	}
}

// TestAuditStuckCmd_WorktreeValuePin turns the done_worktrees / missing_worktrees
// contract keys (pinned shape-only in TestAuditStuckCmd_JSONShape) into value
// pins: seed one worktree row whose task is done (path present) and one whose
// path is gone (task still in-progress), then assert each arm decodes exactly its
// one seeded row with the right path/task/branch/reason. Disjoint predicates keep
// each row in exactly one arm, so a regression that conflates the two — or drops
// the reason tag — fails here.
func TestAuditStuckCmd_WorktreeValuePin(t *testing.T) {
	db := newAuditTestDB(t)
	donePath, doneTask, doneBranch, missPath, missTask, missBranch := seedWorktreeFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditStuckCmd(db, []string{"--json"}); err != nil {
			t.Fatalf("auditStuckCmd --json: %v", err)
		}
	})

	// Generic-map guard: both keys present AND carrying a non-empty array.
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\nraw: %q", err, out)
	}
	for _, k := range []string{"done_worktrees", "missing_worktrees"} {
		arr, ok := m[k].([]any)
		if !ok {
			t.Fatalf("%s is %T, want a JSON array", k, m[k])
		}
		if len(arr) == 0 {
			t.Fatalf("%s decoded empty; want the seeded row (raw: %q)", k, out)
		}
	}

	var typed auditStuck
	if err := json.Unmarshal([]byte(out), &typed); err != nil {
		t.Fatalf("--json does not unmarshal into auditStuck: %v", err)
	}

	// done arm: exactly the done-task row, reason task-done, and NOT in the missing
	// arm (its path exists).
	if len(typed.DoneWorktrees) != 1 {
		t.Fatalf("DoneWorktrees = %+v, want exactly one (the done-task row)", typed.DoneWorktrees)
	}
	dw := typed.DoneWorktrees[0]
	if dw.Path != donePath || dw.TaskID != doneTask || dw.Branch != doneBranch {
		t.Errorf("DoneWorktrees[0] = %+v, want path=%q task=%q branch=%q", dw, donePath, doneTask, doneBranch)
	}
	if dw.Reason != "task-done" {
		t.Errorf("DoneWorktrees[0].Reason = %q, want task-done", dw.Reason)
	}

	// missing arm: exactly the gone-path row, reason missing-path, and NOT in the
	// done arm (its task is in-progress, not terminal).
	if len(typed.MissingWorktrees) != 1 {
		t.Fatalf("MissingWorktrees = %+v, want exactly one (the gone-path row)", typed.MissingWorktrees)
	}
	mw := typed.MissingWorktrees[0]
	if mw.Path != missPath || mw.TaskID != missTask || mw.Branch != missBranch {
		t.Errorf("MissingWorktrees[0] = %+v, want path=%q task=%q branch=%q", mw, missPath, missTask, missBranch)
	}
	if mw.Reason != "missing-path" {
		t.Errorf("MissingWorktrees[0].Reason = %q, want missing-path", mw.Reason)
	}
}

// TestAuditDagCmd_JSONShape pins the `audit dag --json` contract keys and a typed
// round-trip carrying the seeded cycle and missing-dep edge.
func TestAuditDagCmd_JSONShape(t *testing.T) {
	db := newAuditTestDB(t)
	cycleA, cycleB, missingSrc := seedDagFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditDagCmd(db, []string{"--json"}); err != nil {
			t.Fatalf("auditDagCmd --json: %v", err)
		}
	})

	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\nraw: %q", err, out)
	}
	for _, k := range []string{"cycles", "missing_deps", "stale_epics", "unsourced", "bad_sources", "poison", "roots"} {
		if _, ok := m[k]; !ok {
			t.Errorf("contract key %q missing (present: %v)", k, keysOf(m))
		}
	}

	var typed auditDag
	if err := json.Unmarshal([]byte(out), &typed); err != nil {
		t.Fatalf("--json does not unmarshal into auditDag: %v", err)
	}
	if len(typed.Cycles) != 1 {
		t.Fatalf("Cycles = %+v, want exactly one (the A↔B loop, deduped)", typed.Cycles)
	}
	members := map[string]bool{}
	for _, id := range typed.Cycles[0] {
		members[id] = true
	}
	if !members[cycleA] || !members[cycleB] {
		t.Errorf("cycle %v does not contain both %s and %s", typed.Cycles[0], cycleA, cycleB)
	}
	var gotMissing bool
	for _, e := range typed.MissingDeps {
		if e.TaskID == missingSrc && e.DependsOn == "01NOSUCHTASK00000000000AA" {
			gotMissing = true
		}
	}
	if !gotMissing {
		t.Errorf("missing-dep edge %s->01NOSUCHTASK absent from MissingDeps: %+v", missingSrc, typed.MissingDeps)
	}
}

// TestAuditAllCmd_JSONShape pins the top-level `audit all --json` contract
// (auditReport): the four keys drift/stuck/dag/workstreams decode as a generic map
// and round-trip through the typed struct with each nested audit populated from the
// seeded fixtures. Hermetic (chdir) because auditAllCmd runs auditDriftFindings.
func TestAuditAllCmd_JSONShape(t *testing.T) {
	db := newAuditTestDB(t)
	// Seed the stuck/dag tasks FIRST, then seedDriftFindings (which runs the prime
	// doc-sync) LAST. Its hand-inserted dangling task_sources edge only survives
	// auditAllCmd's own re-sync if the task-body fingerprint — count:max(updated_at)
	// — is unchanged afterward; a task inserted AFTER the prime would bust it and
	// trigger the source rebuild that drops the edge. Folding every task into the
	// fingerprint before the prime keeps the re-sync's rebuild skipped.
	staleLockID, _ := seedStuckFindings(t, db)
	cycleA, cycleB, _ := seedDagFindings(t, db)
	cur7, danglingTask, danglingDoc := seedDriftFindings(t, db)

	out := captureStdout(t, func() {
		if err := auditAllCmd(db, []string{"--json"}); err != nil {
			t.Fatalf("auditAllCmd --json: %v", err)
		}
	})

	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\nraw: %q", err, out)
	}
	for _, k := range []string{"drift", "stuck", "dag", "workstreams"} {
		if _, ok := m[k]; !ok {
			t.Errorf("contract key %q missing (present: %v)", k, keysOf(m))
		}
	}

	var typed auditReport
	if err := json.Unmarshal([]byte(out), &typed); err != nil {
		t.Fatalf("--json does not unmarshal into auditReport: %v", err)
	}
	if typed.Drift == nil || typed.Stuck == nil || typed.Dag == nil {
		t.Fatalf("auditReport has a nil sub-audit: %+v", typed)
	}
	// Drift arm carries the drifted doc.
	var gotDrift bool
	for _, d := range typed.Drift.Docs {
		if d.Path == "docs/50-drift.md" && d.State == "drifted" && d.CurrentHash == cur7 {
			gotDrift = true
		}
	}
	if !gotDrift {
		t.Errorf("drift arm missing the drifted doc (docs=%+v)", typed.Drift.Docs)
	}
	// Drift arm also carries the dangling link (seedDriftFindings seeds it): value-
	// pin it here, not just its shape, so `audit all` is proven to fold the drift
	// citation-integrity arm through — not only the per-doc state.
	var gotDangle bool
	for _, l := range typed.Drift.DanglingLinks {
		if l.TaskID == danglingTask && l.DocPath == danglingDoc {
			gotDangle = true
		}
	}
	if !gotDangle {
		t.Errorf("drift arm missing the dangling link %s->%s (links=%+v)", danglingTask, danglingDoc, typed.Drift.DanglingLinks)
	}
	// Stuck arm carries the stale lock.
	if len(typed.Stuck.StaleLocks) != 1 || typed.Stuck.StaleLocks[0].ID != staleLockID {
		t.Errorf("stuck arm StaleLocks = %+v, want one for %s", typed.Stuck.StaleLocks, staleLockID)
	}
	// Dag arm carries the cycle.
	if len(typed.Dag.Cycles) != 1 {
		t.Fatalf("dag arm Cycles = %+v, want one", typed.Dag.Cycles)
	}
	members := map[string]bool{}
	for _, id := range typed.Dag.Cycles[0] {
		members[id] = true
	}
	if !members[cycleA] || !members[cycleB] {
		t.Errorf("dag cycle %v missing a member", typed.Dag.Cycles[0])
	}

	// Workstreams grouping index (audit-all only): value-pin, not just key-present.
	// Every seeded task is its own root (no parent), so the grouping must be
	// non-empty, and the dangling-citation task's root must carry at least the one
	// finding auditGroupByRoot credited it (the dangling link). This proves the
	// grouping actually attributes findings to roots rather than emitting an empty
	// or all-zero index.
	if len(typed.Workstreams) == 0 {
		t.Fatalf("workstreams grouping is empty; want per-root findings for the seeded tasks")
	}
	var danglingWS *auditWorkstream
	for i := range typed.Workstreams {
		if typed.Workstreams[i].Root == danglingTask {
			danglingWS = &typed.Workstreams[i]
			break
		}
	}
	if danglingWS == nil {
		t.Fatalf("workstreams grouping has no root for the dangling-citation task %s: %+v", danglingTask, typed.Workstreams)
	}
	if danglingWS.Findings < 1 {
		t.Errorf("workstream root %s Findings = %d, want >= 1 (its dangling citation)", danglingTask, danglingWS.Findings)
	}
}

// seedChildTask inserts one task carrying an explicit parent_id — the shape the
// stale-epic arm reads (a container with children). seedAuditTask cannot set a
// parent, so the epic-child edge needs this direct Exec.
func seedChildTask(t *testing.T, db *sql.DB, id, parent, status, body string, whenMs int64) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,parent_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`,
		id, "t-"+id, body, status, parent, whenMs, whenMs,
	); err != nil {
		t.Fatalf("seed child task %s: %v", id, err)
	}
}

// seedPoisonRuns inserts n agent_runs rows for taskID in a failure state drawn
// from auditPoisonStatusList, the shape the poison arm counts (>= 3 → poison).
func seedPoisonRuns(t *testing.T, db *sql.DB, taskID string, n int) {
	t.Helper()
	now := timeToMs(time.Now().UTC())
	for i := 0; i < n; i++ {
		if _, err := db.Exec(
			`INSERT INTO agent_runs(id,task_id,session,status,started_at,finished_at)
			 VALUES(?,?,?,?,?,?)`,
			fmt.Sprintf("run-%s-%d", taskID, i), taskID, "sess", "error", now, now,
		); err != nil {
			t.Fatalf("seed poison run %d for %s: %v", i, taskID, err)
		}
	}
}

// dagRemainingArms is the identifying set the value-pin test asserts each of the
// five remaining `audit dag` arms decodes.
type dagRemainingArms struct {
	epicID, unsourcedID, badSrcID, badDocPath, poisonID string
	poisonFailures                                      int
	starvedRootID                                       string
}

// seedDagRemainingArms chdirs into a synthetic repo (so auditBadDocCitations'
// docs/NN-*.md glob resolves against an empty docs/ — the missing-doc citation
// stays "bad") and seeds exactly one identifying fixture per remaining dag arm:
//
//   - stale_epics: an OPEN epic whose only child is done (all children terminal).
//   - unsourced:   an open leaf with no Sources: line.
//   - bad_sources: an open leaf citing a doc-shaped path with no file on disk.
//   - poison:      an open leaf with >= 3 failed agent_runs.
//   - roots:       an in-progress root with no children — open (so it counts as an
//     open descendant) but never ready (readyWhere requires status='open'), so it
//     is starved.
//
// Arms deliberately overlap on the incidental checks (the epic's done child and
// the starved/poison leaves are themselves unsourced), so the test asserts each
// arm by identifying id, never by array length.
func seedDagRemainingArms(t *testing.T, db *sql.DB) dagRemainingArms {
	t.Helper()
	chdirTempRepo(t) // empty docs/ => the bad citation resolves to no file
	now := timeToMs(time.Now().UTC())

	a := dagRemainingArms{
		epicID:         "01DAGEPIC000000000000000AA",
		unsourcedID:    "01DAGUNSOURCED0000000000AA",
		badSrcID:       "01DAGBADSOURCE0000000000AA",
		badDocPath:     "docs/99-nope.md",
		poisonID:       "01DAGPOISON000000000000AA",
		poisonFailures: 3,
		starvedRootID:  "01DAGSTARVED000000000000AA",
	}

	// stale epic: open container + one done child (all children terminal).
	seedAuditTask(t, db, a.epicID, string(StatusOpen), "", now)
	seedChildTask(t, db, "01DAGEPICCHILD000000000AA", a.epicID, string(StatusDone), "", now)

	// unsourced leaf: open, no Sources: line.
	seedAuditTask(t, db, a.unsourcedID, string(StatusOpen), "just a body, no sources", now)

	// bad source: open leaf citing a doc-shaped path with no on-disk file. The
	// Sources: line keeps it OUT of the unsourced arm, isolating the bad-source pin.
	seedAuditTask(t, db, a.badSrcID, string(StatusOpen), "work item\n\nSources: "+a.badDocPath, now)

	// poison: open leaf with >= 3 failed runs.
	seedAuditTask(t, db, a.poisonID, string(StatusOpen), "", now)
	seedPoisonRuns(t, db, a.poisonID, a.poisonFailures)

	// starved root: in-progress leaf, no children => open descendant but not ready.
	seedAuditTask(t, db, a.starvedRootID, string(StatusInProgress), "", now)

	return a
}

// TestAuditDagCmd_RemainingArmsValuePin turns the five `audit dag --json` keys
// that TestAuditDagCmd_JSONShape only pins shape-only — stale_epics, unsourced,
// bad_sources, poison, roots — into VALUE pins: each arm must DECODE its seeded
// finding by identifying id (task/epic), so a regression returning an empty array
// for any one of them (which the shape-only test would still pass) fails here.
func TestAuditDagCmd_RemainingArmsValuePin(t *testing.T) {
	db := newAuditTestDB(t)
	a := seedDagRemainingArms(t, db)

	out := captureStdout(t, func() {
		if err := auditDagCmd(db, []string{"--json"}); err != nil {
			t.Fatalf("auditDagCmd --json: %v", err)
		}
	})

	// Generic-map guard: every remaining arm's key must be present AND carry a
	// non-empty array (shape-only tests only checked presence).
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("--json output is not valid JSON: %v\nraw: %q", err, out)
	}
	for _, k := range []string{"stale_epics", "unsourced", "bad_sources", "poison", "roots"} {
		arr, ok := m[k].([]any)
		if !ok {
			t.Fatalf("%s is %T, want a JSON array", k, m[k])
		}
		if len(arr) == 0 {
			t.Fatalf("%s decoded empty; want the seeded finding (raw: %q)", k, out)
		}
	}

	// Typed round-trip so the JSON field tags themselves produced the values.
	var typed auditDag
	if err := json.Unmarshal([]byte(out), &typed); err != nil {
		t.Fatalf("--json does not unmarshal into auditDag: %v", err)
	}

	// stale_epics: the open epic whose only child is done.
	var gotEpic bool
	for _, e := range typed.StaleEpics {
		if e.ID == a.epicID {
			gotEpic = true
		}
	}
	if !gotEpic {
		t.Errorf("stale_epics missing the seeded epic %s: %+v", a.epicID, typed.StaleEpics)
	}

	// unsourced: the open leaf with no Sources: line.
	var gotUnsourced bool
	for _, u := range typed.Unsourced {
		if u.ID == a.unsourcedID {
			gotUnsourced = true
		}
	}
	if !gotUnsourced {
		t.Errorf("unsourced missing the seeded leaf %s: %+v", a.unsourcedID, typed.Unsourced)
	}
	// The bad-source task carries a Sources: line, so it must NOT be unsourced —
	// otherwise the two arms disagree on what "has a citation" means.
	for _, u := range typed.Unsourced {
		if u.ID == a.badSrcID {
			t.Errorf("bad-source task %s wrongly reported unsourced (it has a Sources: line)", a.badSrcID)
		}
	}

	// bad_sources: the doc-shaped citation that resolves to no on-disk file, keyed
	// by both the citing task and the exact unresolved doc path.
	var gotBad bool
	for _, b := range typed.BadSources {
		if b.TaskID == a.badSrcID && b.DocPath == a.badDocPath {
			gotBad = true
		}
	}
	if !gotBad {
		t.Errorf("bad_sources missing %s->%s: %+v", a.badSrcID, a.badDocPath, typed.BadSources)
	}

	// poison: the leaf with exactly the seeded number of failed runs.
	var gotPoison bool
	for _, p := range typed.Poison {
		if p.ID == a.poisonID {
			gotPoison = true
			if p.Failures != a.poisonFailures {
				t.Errorf("poison %s Failures = %d, want %d", a.poisonID, p.Failures, a.poisonFailures)
			}
		}
	}
	if !gotPoison {
		t.Errorf("poison missing the seeded task %s: %+v", a.poisonID, typed.Poison)
	}

	// roots: the in-progress root must appear flagged starved (open descendant,
	// nothing ready). Pin the Starved flag on the identifying root, not just any
	// non-empty roots array.
	var gotStarved bool
	for _, r := range typed.Roots {
		if r.Root == a.starvedRootID {
			if !r.Starved {
				t.Errorf("root %s Starved = false, want true (in-progress, 0 ready)", a.starvedRootID)
			}
			gotStarved = true
		}
	}
	if !gotStarved {
		t.Errorf("roots missing the seeded starved root %s: %+v", a.starvedRootID, typed.Roots)
	}
}

// --- ContinueOnError unknown-flag error paths -----------------------------

// TestAuditCmd_UnknownFlagErrorPath pins the flag.ContinueOnError contract shared
// by every audit verb: an unrecognized flag makes fs.Parse return a non-nil error,
// which the command propagates, and nothing is written to stdout (flag writes its
// complaint to stderr). Covers auditWatermarksCmd plus a sibling (auditStuckCmd);
// the other verbs share the identical fs.Parse-then-return prologue.
func TestAuditCmd_UnknownFlagErrorPath(t *testing.T) {
	db := newAuditTestDB(t)

	cases := []struct {
		name string
		run  func([]string) error
	}{
		{"watermarks", func(a []string) error { return auditWatermarksCmd(db, a) }},
		{"stuck", func(a []string) error { return auditStuckCmd(db, a) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() { err = tc.run([]string{"--bogus"}) })
			if err == nil {
				t.Errorf("audit %s --bogus returned nil error; want the ContinueOnError parse error propagated", tc.name)
			}
			if out != "" {
				t.Errorf("audit %s --bogus wrote to stdout %q; the parse complaint must go to stderr only", tc.name, out)
			}
		})
	}
}
