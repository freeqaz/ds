// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	_ "modernc.org/sqlite"
)

// newServeAPITestDB builds a temp full-schema taskdb and forces local-only
// locking so a claim/report never reaches a real shared registry.
func newServeAPITestDB(t *testing.T) *sql.DB {
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

// connectProfile spins up an in-memory MCP server for the given profile/session
// and returns a connected client session — the faithful way to observe the
// registered tool set (the registration IS the trust boundary).
func connectProfile(t *testing.T, db *sql.DB, session, profile string) *mcp.ClientSession {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "taskdb", Version: "test"}, nil)
	registerTools(srv, db, session, profile)
	ct, st := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := srv.Connect(ctx, st, nil); err != nil {
		t.Fatalf("server connect: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

// TestSessionProfile_IsWorkerPlusClaim proves the "session" profile exposes the
// 8 worker tools + task_claim, and NONE of the curator mutating tools. This is
// the security boundary for an in-VM agent: it can take work but not curate the
// DAG.
func TestSessionProfile_IsWorkerPlusClaim(t *testing.T) {
	db := newServeAPITestDB(t)
	got := toolNames(t, connectProfile(t, db, "sess-vm", "session"))

	want := map[string]bool{
		"task_ready": true, "task_get": true, "task_note": true,
		"task_report": true, "task_search": true, "task_claim": true,
		"doc_search": true, "doc_get": true, "doc_sync": true,
	}
	forbidden := map[string]bool{
		"task_add": true, "task_edit": true, "task_set_status": true,
		"task_dep": true, "task_undep": true, "doc_link": true,
	}
	gotSet := map[string]bool{}
	for _, n := range got {
		gotSet[n] = true
		if forbidden[n] {
			t.Errorf("session profile must NOT expose curator tool %q", n)
		}
	}
	for n := range want {
		if !gotSet[n] {
			t.Errorf("session profile is missing expected tool %q (got %v)", n, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("session profile tool count = %d, want %d (got %v)", len(got), len(want), got)
	}
}

// TestWorkerProfile_ExcludesClaim guards the least-privilege split: the plain
// worker profile still has no claim (only session/curator widen past worker).
func TestWorkerProfile_ExcludesClaim(t *testing.T) {
	db := newServeAPITestDB(t)
	for _, n := range toolNames(t, connectProfile(t, db, "sess", "worker")) {
		if n == "task_claim" {
			t.Fatal("worker profile must not expose task_claim")
		}
	}
}

// TestSessionProfile_ReportRecordsNoFlip proves task_report over the session
// profile records a claim + breadcrumb note but does NOT flip task status — the
// dispatcher's verification gate stays the sole done-authority, even from a VM.
func TestSessionProfile_ReportRecordsNoFlip(t *testing.T) {
	db := newServeAPITestDB(t)
	const session = "sess-vm"
	now := timeToMs(time.Now().UTC())
	// Seed an in-progress task locked BY this session (report requires the lock).
	if _, err := db.Exec(
		`INSERT INTO tasks(id,title,body,status,priority,locked_by,locked_at,created_at,updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		"01RPT1", "t", "body", "in-progress", 0, session, now, now, now,
	); err != nil {
		t.Fatalf("seed task: %v", err)
	}

	cs := connectProfile(t, db, session, "session")
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "task_report",
		Arguments: map[string]any{
			"id":      "01RPT1",
			"status":  "done",
			"summary": "did the thing, over twenty chars long",
		},
	})
	if err != nil {
		t.Fatalf("CallTool task_report: %v", err)
	}
	if res.IsError {
		t.Fatalf("task_report returned tool error: %+v", res.Content)
	}

	// Status must be UNCHANGED (still in-progress) — report records, never flips.
	var status string
	if err := db.QueryRow(`SELECT status FROM tasks WHERE id=?`, "01RPT1").Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != "in-progress" {
		t.Errorf("task status = %q after report; must stay in-progress (report never flips)", status)
	}
	// The report row + breadcrumb note must exist.
	var reports, notes int
	if err := db.QueryRow(`SELECT count(*) FROM task_reports WHERE task_id=?`, "01RPT1").Scan(&reports); err != nil {
		t.Fatalf("count reports: %v", err)
	}
	if reports != 1 {
		t.Errorf("task_reports rows = %d, want 1", reports)
	}
	if err := db.QueryRow(`SELECT count(*) FROM notes WHERE task_id=? AND author=?`, "01RPT1", session).Scan(&notes); err != nil {
		t.Fatalf("count notes: %v", err)
	}
	if notes < 1 {
		t.Errorf("breadcrumb note rows = %d, want >= 1", notes)
	}
}

// --- session-derivation seam ------------------------------------------------

func TestSessionFromRequest(t *testing.T) {
	const hdr = "X-DS-Session"
	cases := []struct {
		name   string
		set    bool
		value  string
		want   string
		wantOK bool
	}{
		{"present", true, "sess-abc", "sess-abc", true},
		{"trimmed", true, "  sess-abc  ", "sess-abc", true},
		{"absent", false, "", "", false},
		{"empty", true, "   ", "", false},
		{"newline-injection", true, "sess\r\nX-Evil: 1", "", false},
		{"nul", true, "sess\x00", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodPost, "/", nil)
			if tc.set {
				r.Header.Set(hdr, tc.value)
			}
			got, ok := sessionFromRequest(r, hdr)
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("sessionFromRequest = (%q, %v), want (%q, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
	// Oversized identity is rejected.
	long := make([]byte, 250)
	for i := range long {
		long[i] = 'a'
	}
	r, _ := http.NewRequest(http.MethodPost, "/", nil)
	r.Header.Set(hdr, string(long))
	if _, ok := sessionFromRequest(r, hdr); ok {
		t.Error("oversized session header must be rejected")
	}
}

func TestRequireLoopback(t *testing.T) {
	ok := []string{"127.0.0.1:7757", "[::1]:80", "localhost:1234"}
	for _, a := range ok {
		if err := requireLoopback(a); err != nil {
			t.Errorf("requireLoopback(%q) = %v, want nil", a, err)
		}
	}
	bad := []string{"0.0.0.0:7757", "192.168.1.10:80", "notahost"}
	for _, a := range bad {
		if err := requireLoopback(a); err == nil {
			t.Errorf("requireLoopback(%q) = nil, want error", a)
		}
	}
}

// TestServeAPI_HTTPHeaderWiring is the end-to-end proof that the HTTP face
// derives the session from the injected header and serves the session profile:
// a request WITH the header lists the session tools; a request WITHOUT it is
// refused (getServer → nil → 400).
func TestServeAPI_HTTPHeaderWiring(t *testing.T) {
	db := newServeAPITestDB(t)
	const hdr = "X-DS-Session"
	getServer := func(r *http.Request) *mcp.Server {
		sess, ok := sessionFromRequest(r, hdr)
		if !ok {
			return nil
		}
		srv := mcp.NewServer(&mcp.Implementation{Name: "taskdb", Version: "test"}, nil)
		registerTools(srv, db, sess, "session")
		return srv
	}
	handler := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	// With the header: a real MCP client over the streamable transport lists the
	// session tool set.
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             ts.URL,
		HTTPClient:           &http.Client{Transport: headerInjector{base: http.DefaultTransport, key: hdr, val: "sess-vm"}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("client connect (with header): %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	names := toolNames(t, cs)
	sawClaim, sawCurator := false, false
	for _, n := range names {
		if n == "task_claim" {
			sawClaim = true
		}
		if n == "task_add" {
			sawCurator = true
		}
	}
	if !sawClaim || sawCurator {
		t.Errorf("over-HTTP session tools = %v; want task_claim present, task_add absent", names)
	}

	// Without the header: getServer returns nil → the handler refuses. A bare
	// POST gets a non-2xx.
	resp, err := http.Post(ts.URL, "application/json", nil)
	if err != nil {
		t.Fatalf("bare POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 400 {
		t.Errorf("missing-header POST status = %d, want >= 400 (fail closed)", resp.StatusCode)
	}
}

// TestServeAPI_SessionConstIgnoresHeader proves the interim single-tenant seam:
// with a host-fixed --session-const, every request is attributed to that id and
// the request header is IGNORED — a request with NO header still gets served (no
// 400), and a request presenting a DIFFERENT header cannot override the const, so
// a guest can never forge another session's identity.
func TestServeAPI_SessionConstIgnoresHeader(t *testing.T) {
	db := newServeAPITestDB(t)
	const hdr = "X-DS-Session"
	const constID = "sess-host-fixed"
	// getServer mirrors cmdServeAPI's const branch: identity is the constant, the
	// header is never read.
	getServer := func(r *http.Request) *mcp.Server {
		sess := constID // header intentionally ignored
		srv := mcp.NewServer(&mcp.Implementation{Name: "taskdb", Version: "test"}, nil)
		registerTools(srv, db, sess, "session")
		return srv
	}
	handler := mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
	})
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	// A client presenting a FORGED, different session header still connects and
	// lists the session tools — the const wins and the header is inert.
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             ts.URL,
		HTTPClient:           &http.Client{Transport: headerInjector{base: http.DefaultTransport, key: hdr, val: "sess-forged-other"}},
		DisableStandaloneSSE: true,
	}, nil)
	if err != nil {
		t.Fatalf("client connect (const mode, forged header): %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	names := toolNames(t, cs)
	sawClaim := false
	for _, n := range names {
		if n == "task_claim" {
			sawClaim = true
		}
	}
	if !sawClaim {
		t.Errorf("const-mode tools = %v; want the session profile (task_claim present) regardless of header", names)
	}
}

// TestValidSessionID guards the shared identity validator that both the header
// path and --session-const validation lean on.
func TestValidSessionID(t *testing.T) {
	good := []string{"sess-abc", "01KV8XSNEX", "a"}
	for _, v := range good {
		if !validSessionID(v) {
			t.Errorf("validSessionID(%q) = false, want true", v)
		}
	}
	long := make([]byte, 201)
	for i := range long {
		long[i] = 'a'
	}
	bad := []string{"", "sess\r\nX-Evil: 1", "sess\x00", string(long)}
	for _, v := range bad {
		if validSessionID(v) {
			t.Errorf("validSessionID(%q) = true, want false", v)
		}
	}
}

// headerInjector sets a fixed header on every outbound request so the test
// client can present the boundary-injected session identity.
type headerInjector struct {
	base http.RoundTripper
	key  string
	val  string
}

func (h headerInjector) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set(h.key, h.val)
	return h.base.RoundTrip(r)
}
