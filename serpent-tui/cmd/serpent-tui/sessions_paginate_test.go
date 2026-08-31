// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"strings"
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"
)

// pagedListResponder builds a ListSessions responder that serves a fixed sequence
// of pages keyed by the incoming page_token: an empty token returns pages[0], and
// each page i hands back token "p<i+1>" so the next call (carrying that token)
// returns pages[i+1]; the final page returns an empty next_page_token (the
// end-of-pages signal). Unknown tokens are a test bug → empty page, no token.
func pagedListResponder(pages [][]*orchestratorv1.Session) func(context.Context, *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
	tokenFor := func(i int) string {
		if i < 0 || i >= len(pages) {
			return ""
		}
		if i == len(pages)-1 {
			return "" // last page: no further token
		}
		return pageToken(i + 1)
	}
	indexFor := func(tok string) int {
		if tok == "" {
			return 0
		}
		for i := range pages {
			if pageToken(i) == tok {
				return i
			}
		}
		return -1
	}
	return func(_ context.Context, req *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
		i := indexFor(req.GetPageToken())
		if i < 0 || i >= len(pages) {
			return &orchestratorv1.ListSessionsResponse{}, nil
		}
		return &orchestratorv1.ListSessionsResponse{
			Sessions:      pages[i],
			NextPageToken: tokenFor(i),
		}, nil
	}
}

// pageToken is the synthetic cursor for page i used by the fake (page 0's token is
// "p0"; the empty incoming token also maps to page 0 — see pagedListResponder).
func pageToken(i int) string {
	return "p" + string(rune('0'+i))
}

// TestSessionsListAllAccumulatesAcrossPages: `sessions list --all` follows the
// fake's next_page_token across THREE pages and renders every row, newest-first
// order preserved (the store sorts CreatedAt desc; accumulation appends each page
// in turn, so the concatenation stays newest-first across the page boundaries).
func TestSessionsListAllAccumulatesAcrossPages(t *testing.T) {
	pages := [][]*orchestratorv1.Session{
		{
			sessionRow("sess-900", "host-a", attachv1.SessionStateName_SESSION_STATE_NAME_WORKING, 900),
			sessionRow("sess-800", "host-a", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 800),
		},
		{
			sessionRow("sess-700", "host-b", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 700),
			sessionRow("sess-600", "host-b", attachv1.SessionStateName_SESSION_STATE_NAME_WORKING, 600),
		},
		{
			sessionRow("sess-500", "host-c", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 500),
		},
	}
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = pagedListResponder(pages)
	dialFake(t, fake)
	out := captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1", "--all"}) }); got != 0 {
		t.Fatalf("sessions list --all = %d, want 0", got)
	}
	rendered := out.String()

	// Every row from every page renders.
	wantUUIDs := []string{"sess-900", "sess-800", "sess-700", "sess-600", "sess-500"}
	for _, u := range wantUUIDs {
		if !strings.Contains(rendered, u) {
			t.Errorf("--all table missing %q (single-page truncation regression?)\n--- table ---\n%s", u, rendered)
		}
	}

	// Newest-first preserved ACROSS page boundaries: each uuid renders before the
	// next-older one (900 > 800 > 700 > 600 > 500).
	for i := 0; i+1 < len(wantUUIDs); i++ {
		a, b := strings.Index(rendered, wantUUIDs[i]), strings.Index(rendered, wantUUIDs[i+1])
		if a < 0 || b < 0 || a > b {
			t.Errorf("rows not newest-first across pages: %q must render before %q\n%s", wantUUIDs[i], wantUUIDs[i+1], rendered)
		}
	}

	// The crawl made exactly one call per page (3), each carrying the prior page's
	// token: page 0 (empty token) → page 1 ("p1") → page 2 ("p2"), then stops on
	// the empty next_page_token.
	calls := fake.ListSessionsRecorded()
	if len(calls) != len(pages) {
		t.Fatalf("ListSessions called %d times, want %d (one per page)", len(calls), len(pages))
	}
	wantTokens := []string{"", "p1", "p2"}
	for i, c := range calls {
		if got := c.Req.GetPageToken(); got != wantTokens[i] {
			t.Errorf("call %d page_token = %q, want %q", i, got, wantTokens[i])
		}
	}
}

// TestSessionsListLimitCapsFirstPage: `sessions list --limit N` carries page_size=N
// on a SINGLE call and does NOT follow the next_page_token (it caps the first page).
func TestSessionsListLimitCapsFirstPage(t *testing.T) {
	// Two pages available, but --limit must take only the first.
	pages := [][]*orchestratorv1.Session{
		{
			sessionRow("sess-first-a", "host-a", attachv1.SessionStateName_SESSION_STATE_NAME_WORKING, 200),
			sessionRow("sess-first-b", "host-a", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 190),
		},
		{
			sessionRow("sess-second", "host-b", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 100),
		},
	}
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = pagedListResponder(pages)
	dialFake(t, fake)
	out := captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1", "--limit", "5"}) }); got != 0 {
		t.Fatalf("sessions list --limit 5 = %d, want 0", got)
	}
	rendered := out.String()

	// First page rendered; the second page (behind next_page_token) is NOT crawled.
	for _, u := range []string{"sess-first-a", "sess-first-b"} {
		if !strings.Contains(rendered, u) {
			t.Errorf("--limit table missing first-page row %q\n%s", u, rendered)
		}
	}
	if strings.Contains(rendered, "sess-second") {
		t.Errorf("--limit must NOT follow next_page_token; second page leaked:\n%s", rendered)
	}

	// Exactly one call, page_size=5, empty token (no crawl).
	calls := fake.ListSessionsRecorded()
	if len(calls) != 1 {
		t.Fatalf("ListSessions called %d times, want 1 (--limit is single-page)", len(calls))
	}
	if got := calls[0].Req.GetPageSize(); got != 5 {
		t.Errorf("--limit 5 → page_size = %d, want 5", got)
	}
	if got := calls[0].Req.GetPageToken(); got != "" {
		t.Errorf("--limit first call page_token = %q, want \"\"", got)
	}
}

// TestSessionsListDefaultSinglePageSizeZero: the DEFAULT (no --limit, no --all)
// makes exactly ONE ListSessions call with page_size=0 — the back-compat path:
// page_size<=0 returns all sessions in one page, so existing single-call clients
// are never silently truncated. It does NOT follow any next_page_token.
func TestSessionsListDefaultSinglePageSizeZero(t *testing.T) {
	// A non-empty next_page_token is present; the default must IGNORE it (no crawl).
	pages := [][]*orchestratorv1.Session{
		{
			sessionRow("sess-default", "host-a", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 300),
		},
		{
			sessionRow("sess-extra", "host-b", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 100),
		},
	}
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = pagedListResponder(pages)
	dialFake(t, fake)
	out := captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1"}) }); got != 0 {
		t.Fatalf("sessions list (default) = %d, want 0", got)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "sess-default") {
		t.Errorf("default list missing the first-page row:\n%s", rendered)
	}
	if strings.Contains(rendered, "sess-extra") {
		t.Errorf("default (no --all) must NOT crawl; second page leaked:\n%s", rendered)
	}

	calls := fake.ListSessionsRecorded()
	if len(calls) != 1 {
		t.Fatalf("ListSessions called %d times, want 1 (default is single-page)", len(calls))
	}
	if got := calls[0].Req.GetPageSize(); got != 0 {
		t.Errorf("default page_size = %d, want 0 (= all, back-compat)", got)
	}
	if got := calls[0].Req.GetPageToken(); got != "" {
		t.Errorf("default page_token = %q, want \"\"", got)
	}
}

// TestSessionsListAllWithLimitSetsPerPageBatch: `--all --limit N` crawls every page
// while carrying page_size=N as the per-page batch size on each call.
func TestSessionsListAllWithLimitSetsPerPageBatch(t *testing.T) {
	pages := [][]*orchestratorv1.Session{
		{sessionRow("sess-a", "host-a", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 200)},
		{sessionRow("sess-b", "host-b", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 100)},
	}
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = pagedListResponder(pages)
	dialFake(t, fake)
	out := captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1", "--all", "--limit", "2"}) }); got != 0 {
		t.Fatalf("sessions list --all --limit 2 = %d, want 0", got)
	}
	rendered := out.String()
	for _, u := range []string{"sess-a", "sess-b"} {
		if !strings.Contains(rendered, u) {
			t.Errorf("--all --limit table missing %q\n%s", u, rendered)
		}
	}

	calls := fake.ListSessionsRecorded()
	if len(calls) != 2 {
		t.Fatalf("ListSessions called %d times, want 2 (one per page)", len(calls))
	}
	for i, c := range calls {
		if got := c.Req.GetPageSize(); got != 2 {
			t.Errorf("call %d page_size = %d, want 2 (per-page batch)", i, got)
		}
	}
}

// TestSessionsListAllSinglePageStopsImmediately: `--all` against a control plane
// that returns no next_page_token makes exactly one call (the crawl terminates on
// the empty token, never loops).
func TestSessionsListAllSinglePageStopsImmediately(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = func(_ context.Context, _ *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
		return &orchestratorv1.ListSessionsResponse{Sessions: []*orchestratorv1.Session{
			sessionRow("sess-only", "host-a", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 100),
		}}, nil // no NextPageToken → end of pages
	}
	dialFake(t, fake)
	out := captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1", "--all"}) }); got != 0 {
		t.Fatalf("sessions list --all (single page) = %d, want 0", got)
	}
	if !strings.Contains(out.String(), "sess-only") {
		t.Errorf("--all single-page missing the row:\n%s", out.String())
	}
	if calls := fake.ListSessionsRecorded(); len(calls) != 1 {
		t.Errorf("--all on a single page called ListSessions %d times, want 1 (no over-fetch)", len(calls))
	}
}
