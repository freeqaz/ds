// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// pushBackfillService is an httptest server that records how many times the
// push/reindex/backfill routes were hit, so a test can assert the `doc embed`
// post-embed wiring (pushAndBackfill) calls /backfill_provenance EXACTLY when the
// --backfill-provenance flag is set — and never when it is not. It answers the
// push fast path (/ingest_batch), /reindex, and /backfill_provenance; any other
// path 404s to keep the surface minimal.
type pushBackfillService struct {
	mu        sync.Mutex
	ingestN   int
	reindexN  int
	backfillN int
	healed    int
}

func (rs *pushBackfillService) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		switch r.URL.Path {
		case "/ingest_batch":
			rs.ingestN++
			_, _ = w.Write([]byte(`{"ingested":0,"chunk_hashes":[]}`))
		case "/reindex":
			rs.reindexN++
			_, _ = w.Write([]byte(`{"reindexed":true,"dense_chunks":0,"sparse_chunks":0,"db":""}`))
		case "/backfill_provenance":
			rs.backfillN++
			_, _ = w.Write([]byte(`{"healed":` + itoaLocal(rs.healed) + `}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})
}

func (rs *pushBackfillService) backfillHits() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.backfillN
}

// TestPushAndBackfill_FlagTriggersBackfill asserts the `doc embed` post-embed
// wiring calls the EXISTING triggerBackfillProvenance (i.e. hits the service's
// /backfill_provenance route) when --backfill-provenance is set AND a service URL
// is configured, and pushes the changed set first.
func TestPushAndBackfill_FlagTriggersBackfill(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")

	rs := &pushBackfillService{healed: 3}
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	if err := pushAndBackfill(context.Background(), db, srv.URL, true /*backfill*/, true /*asJSON: silence stdout*/); err != nil {
		t.Fatalf("pushAndBackfill: %v", err)
	}
	if got := rs.backfillHits(); got != 1 {
		t.Fatalf("--backfill-provenance must trigger exactly one /backfill_provenance call, got %d", got)
	}
	// The push must run first (the backfill is the post-push heal step).
	if rs.reindexN == 0 {
		t.Errorf("the changed-set push must run before the backfill (no /reindex observed)")
	}
}

// TestPushAndBackfill_FlagOffSkipsBackfill asserts the backfill route is NEVER
// hit when --backfill-provenance is not set — the flag defaults off, so a plain
// push leaves the heal alone.
func TestPushAndBackfill_FlagOffSkipsBackfill(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")

	rs := &pushBackfillService{}
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	if err := pushAndBackfill(context.Background(), db, srv.URL, false /*backfill off*/, true); err != nil {
		t.Fatalf("pushAndBackfill: %v", err)
	}
	if got := rs.backfillHits(); got != 0 {
		t.Fatalf("backfill must NOT be triggered when the flag is off, got %d calls", got)
	}
}

// TestPushAndBackfill_NoServiceIsNoop asserts that with no --service-url the
// backfill flag is inert: nothing is pushed and nothing is healed, and the run
// succeeds (the local cache is authoritative). No banner is emitted on an unset
// URL — both the push and backfill are SILENT no-ops.
func TestPushAndBackfill_NoServiceIsNoop(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	if err := pushAndBackfill(context.Background(), db, "" /*no service*/, true /*backfill requested*/, true); err != nil {
		t.Fatalf("an unset service URL must be a silent no-op, got error: %v", err)
	}
	if buf.String() != "" {
		t.Fatalf("an unset service URL must emit NO banner, got %q", buf.String())
	}
}

// TestPushAndBackfill_FailsOpenOnUnreachable asserts the backfill is fail-open:
// an unreachable service degrades LOUDLY (a [searchsvc DEGRADED] banner) but the
// run still SUCCEEDS — an embed run against a down service is never failed by the
// optional backfill heal.
func TestPushAndBackfill_FailsOpenOnUnreachable(t *testing.T) {
	db := openFullSchemaDB(t)
	insertChunk(t, db, 1, "docs/a.md", "A", "alpha body")

	// A closed server: every route is unreachable.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	if err := pushAndBackfill(context.Background(), db, url, true /*backfill*/, true); err != nil {
		t.Fatalf("an unreachable service must fail OPEN (no hard error), got: %v", err)
	}
	if !strings.Contains(buf.String(), "DEGRADED") {
		t.Fatalf("an unreachable service must emit a DEGRADED banner, got %q", buf.String())
	}
}
