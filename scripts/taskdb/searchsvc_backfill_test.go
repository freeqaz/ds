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

// backfillRecordingService records how many times /backfill_provenance was hit
// and answers with a "healed" count, so a test can assert the Go trigger calls
// the route and surfaces the count. A 404 on any other path keeps the surface
// minimal (the trigger only calls /backfill_provenance).
type backfillRecordingService struct {
	mu     sync.Mutex
	hits   int
	healed int
}

func (rs *backfillRecordingService) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		if r.URL.Path != "/backfill_provenance" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		rs.hits++
		body := []byte(`{"healed":` + itoaLocal(rs.healed) + `}`)
		_, _ = w.Write(body)
	})
}

// itoaLocal is a tiny non-strconv int->string so the test fixture stays
// dependency-light alongside the rest of this file's literal bodies.
func itoaLocal(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestTriggerBackfillProvenance_CallsRouteAndReportsHealed asserts the Go trigger
// POSTs /backfill_provenance once and surfaces the service's "healed" count, with
// a non-degraded result on success.
func TestTriggerBackfillProvenance_CallsRouteAndReportsHealed(t *testing.T) {
	rs := &backfillRecordingService{healed: 3}
	srv := httptest.NewServer(rs.handler())
	defer srv.Close()

	res, err := triggerBackfillProvenance(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("triggerBackfillProvenance returned error: %v", err)
	}
	if res.Degraded {
		t.Fatalf("expected non-degraded result on a healthy service, got Degraded=true")
	}
	if res.Healed != 3 {
		t.Fatalf("expected Healed=3 (the service-reported count), got %d", res.Healed)
	}
	rs.mu.Lock()
	hits := rs.hits
	rs.mu.Unlock()
	if hits != 1 {
		t.Fatalf("expected exactly one /backfill_provenance call, got %d", hits)
	}
}

// TestTriggerBackfillProvenance_UnsetURLIsSilentNoop asserts an empty service URL
// is a silent, degraded no-op (no error) — fail-open: nothing configured, nothing
// to call, the embed run proceeds.
func TestTriggerBackfillProvenance_UnsetURLIsSilentNoop(t *testing.T) {
	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	res, err := triggerBackfillProvenance(context.Background(), "  ")
	if err != nil {
		t.Fatalf("unset URL must not error, got %v", err)
	}
	if !res.Degraded {
		t.Fatalf("expected Degraded=true for an unset URL")
	}
	if res.Healed != 0 {
		t.Fatalf("expected Healed=0 for an unset URL, got %d", res.Healed)
	}
	if buf.Len() != 0 {
		t.Fatalf("an unset URL must be a SILENT no-op (no banner), got %q", buf.String())
	}
}

// TestTriggerBackfillProvenance_UnreachableServiceFailsOpen asserts a reachable-
// but-failing service (here: a non-2xx) degrades LOUDLY (one banner) and returns
// a degraded result with NO error — a backfill never gates the embed run.
func TestTriggerBackfillProvenance_UnreachableServiceFailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	restore := searchWarnOut
	searchWarnOut = &buf
	defer func() { searchWarnOut = restore }()

	res, err := triggerBackfillProvenance(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("a failing service must fail OPEN (no error), got %v", err)
	}
	if !res.Degraded {
		t.Fatalf("expected Degraded=true on a non-2xx service")
	}
	if !strings.Contains(buf.String(), "[searchsvc DEGRADED]") {
		t.Fatalf("expected one loud DEGRADED banner, got %q", buf.String())
	}
}

// TestJoinBackfillProvenanceURL asserts the route join collapses a trailing slash
// and tolerates an over-specified base that already ends in the route.
func TestJoinBackfillProvenanceURL(t *testing.T) {
	cases := map[string]string{
		"http://x:8099":                      "http://x:8099/backfill_provenance",
		"http://x:8099/":                     "http://x:8099/backfill_provenance",
		"  http://x:8099  ":                  "http://x:8099/backfill_provenance",
		"http://x:8099/backfill_provenance":  "http://x:8099/backfill_provenance",
		"http://x:8099/backfill_provenance/": "http://x:8099/backfill_provenance",
	}
	for in, want := range cases {
		if got := joinBackfillProvenanceURL(in); got != want {
			t.Fatalf("joinBackfillProvenanceURL(%q) = %q, want %q", in, got, want)
		}
	}
}
