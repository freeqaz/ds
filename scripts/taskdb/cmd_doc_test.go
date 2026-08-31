// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestStaleBanner_VerdictMapping asserts the pure banner helper maps each
// verdict to the right surface: a fresh index is silent ("" — nothing to warn
// about), a stale index prints the "STALE … run /reindex" remedy, and a nil
// result (the check could not run) is treated as warnable, never silently fresh.
func TestStaleBanner_VerdictMapping(t *testing.T) {
	// Fresh → silent.
	if got := staleBanner(&freshnessResult{Fresh: true}); got != "" {
		t.Fatalf("a fresh index must produce NO banner, got %q", got)
	}

	// Stale → a banner naming the staleness AND the remedy.
	stale := staleBanner(&freshnessResult{Fresh: false})
	if stale == "" {
		t.Fatal("a stale index must produce a banner")
	}
	if !strings.Contains(stale, "STALE") {
		t.Errorf("stale banner must name the staleness, got %q", stale)
	}
	if !strings.Contains(stale, "/reindex") {
		t.Errorf("stale banner must name the /reindex remedy, got %q", stale)
	}

	// nil (check failed) → treated like stale, never silently fresh.
	if got := staleBanner(nil); got == "" {
		t.Fatal("a nil verdict (check failed) must warn, not imply fresh")
	}
	// A nil and a stale verdict warn identically (both unknown-or-stale).
	if staleBanner(nil) != stale {
		t.Errorf("nil and stale must produce the same banner; nil=%q stale=%q",
			staleBanner(nil), stale)
	}
}

// TestEmitFreshnessBanner_PrintsOnStaleSilentOnFresh drives the real
// freshnessCheck against a schema DB and asserts the banner appears EXACTLY when
// the corpus has drifted from the last-pushed digest, and is silent when fresh.
func TestEmitFreshnessBanner_PrintsOnStaleSilentOnFresh(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	// Never pushed: stored digest is empty → NOT fresh → a banner is emitted.
	emitFreshnessBanner(db)
	if !strings.Contains(buf.String(), "STALE") {
		t.Fatalf("a never-pushed index must emit a STALE banner, got %q", buf.String())
	}

	// Record the CURRENT corpus digest as "pushed" → now fresh → silent.
	cur, err := corpusDigest(db)
	if err != nil {
		t.Fatalf("corpusDigest: %v", err)
	}
	if err := writePushedDigest(db, cur); err != nil {
		t.Fatalf("writePushedDigest: %v", err)
	}
	buf.Reset()
	emitFreshnessBanner(db)
	if buf.String() != "" {
		t.Fatalf("a fresh index must be silent, got %q", buf.String())
	}

	// Drift the corpus (a new chunk the resident digest never saw) → stale again.
	insertChunk(t, db, 2, "docs/b.md", "B", "beta body")
	buf.Reset()
	emitFreshnessBanner(db)
	if !strings.Contains(buf.String(), "STALE") {
		t.Fatalf("a drifted corpus must re-emit the STALE banner, got %q", buf.String())
	}
}
