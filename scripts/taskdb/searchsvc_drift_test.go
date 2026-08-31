// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"sort"
	"strings"
	"testing"
)

// TestFreshnessCheck_DriftCount asserts the freshnessResult drift COUNT (the
// changed-chunk count) tracks the symmetric difference between the last-pushed
// hash set and the current live corpus: every live chunk drifts on a never-pushed
// index, zero drift right after the stored hash set matches the corpus, and the
// exact add + prune count after the corpus moves.
func TestFreshnessCheck_DriftCount(t *testing.T) {
	db := openFullSchemaDB(t)
	hA := insertChunk(t, db, 1, "docs/a.md", "A", "alpha")
	insertChunk(t, db, 2, "docs/b.md", "B", "beta")

	// Never pushed: the stored hash set is empty, so BOTH live chunks count as
	// drifted (nothing absorbed yet) and Fresh is false.
	f0, err := freshnessCheck(db)
	if err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if f0.Fresh {
		t.Fatal("a never-pushed index must report stale")
	}
	if f0.Drift != 2 {
		t.Fatalf("never-pushed drift must equal the live chunk count (2), got %d", f0.Drift)
	}

	// Record the CURRENT corpus hash set + digest as "pushed" → fresh, zero drift.
	dig, err := corpusDigest(db)
	if err != nil {
		t.Fatalf("corpusDigest: %v", err)
	}
	if err := writePushedDigest(db, dig); err != nil {
		t.Fatalf("writePushedDigest: %v", err)
	}
	if err := writePushedHashes(db, sortedLiveHashes(t, db)); err != nil {
		t.Fatalf("writePushedHashes: %v", err)
	}
	f1, err := freshnessCheck(db)
	if err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if !f1.Fresh {
		t.Fatal("the index must be fresh once the stored hash set matches the corpus")
	}
	if f1.Drift != 0 {
		t.Fatalf("a fresh index must report zero drift, got %d", f1.Drift)
	}

	// Add one chunk (a drift of +1: one live chunk the push did not carry).
	insertChunk(t, db, 3, "docs/c.md", "C", "gamma")
	f2, err := freshnessCheck(db)
	if err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if f2.Fresh {
		t.Fatal("adding a chunk must make the index stale")
	}
	if f2.Drift != 1 {
		t.Fatalf("one added chunk must drift by 1, got %d", f2.Drift)
	}

	// Now also remove a previously-pushed chunk: its row leaves the corpus. The
	// drift is the SYMMETRIC difference — the added 'gamma' PLUS the pruned 'alpha'.
	if _, err := db.Exec(`DELETE FROM doc_chunks WHERE hash=?`, hA); err != nil {
		t.Fatalf("delete chunk: %v", err)
	}
	f3, err := freshnessCheck(db)
	if err != nil {
		t.Fatalf("freshness: %v", err)
	}
	if f3.Drift != 2 {
		t.Fatalf("one add + one prune must drift by 2 (symmetric diff), got %d", f3.Drift)
	}
}

// TestStaleBanner_QuantifiesDrift asserts the CLI stale banner QUANTIFIES the
// drift count when the freshnessResult carries one (singular vs plural unit), and
// falls back to the plain verdict+remedy wording for a zero/unknown drift.
func TestStaleBanner_QuantifiesDrift(t *testing.T) {
	// Plural: N>1 chunks changed.
	many := staleBanner(&freshnessResult{Fresh: false, Drift: 3})
	if !strings.Contains(many, "STALE") || !strings.Contains(many, "/reindex") {
		t.Fatalf("a quantified banner must still name STALE + the /reindex remedy, got %q", many)
	}
	if !strings.Contains(many, "3 chunks changed") {
		t.Fatalf("a drift of 3 must read %q, got %q", "3 chunks changed", many)
	}

	// Singular: exactly one chunk changed uses the singular noun.
	one := staleBanner(&freshnessResult{Fresh: false, Drift: 1})
	if !strings.Contains(one, "1 chunk changed") {
		t.Fatalf("a drift of 1 must read %q, got %q", "1 chunk changed", one)
	}
	if strings.Contains(one, "1 chunks changed") {
		t.Fatalf("a drift of 1 must NOT pluralize, got %q", one)
	}

	// Zero/unknown drift: the plain verdict+remedy banner (no count clause), but
	// still a STALE warning with the remedy.
	zero := staleBanner(&freshnessResult{Fresh: false, Drift: 0})
	if !strings.Contains(zero, "STALE") || !strings.Contains(zero, "/reindex") {
		t.Fatalf("a zero-drift stale banner must name STALE + remedy, got %q", zero)
	}
	if strings.Contains(zero, "changed") {
		t.Fatalf("a zero-drift banner must NOT claim a count, got %q", zero)
	}

	// A fresh index stays silent regardless of drift bookkeeping.
	if got := staleBanner(&freshnessResult{Fresh: true, Drift: 5}); got != "" {
		t.Fatalf("a fresh index must be silent, got %q", got)
	}
}

// sortedLiveHashes returns the current distinct doc_chunks hash set, sorted —
// the exact shape writePushedHashes stashes so a freshnessCheck against it reads
// zero drift.
func sortedLiveHashes(t *testing.T, db *sql.DB) []string {
	t.Helper()
	live, err := liveChunkBodies(db)
	if err != nil {
		t.Fatalf("liveChunkBodies: %v", err)
	}
	hashes := make([]string, 0, len(live))
	for h := range live {
		hashes = append(hashes, h)
	}
	sort.Strings(hashes)
	return hashes
}
