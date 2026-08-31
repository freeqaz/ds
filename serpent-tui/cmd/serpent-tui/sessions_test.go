// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"
)

// captureStdout swaps the package stdout var for a buffer so the table-render
// tests can read what `sessions list`/`destroy` printed. It restores the prior
// writer on cleanup. (dialFake / runCmd live in main_test.go — same package.)
func captureStdout(t *testing.T) *bytes.Buffer {
	t.Helper()
	prev := stdout
	t.Cleanup(func() { stdout = prev })
	buf := &bytes.Buffer{}
	stdout = buf
	return buf
}

// sessionRow builds a Session wire record for the list-render tests.
func sessionRow(uuid, host string, name attachv1.SessionStateName, createdAt uint64) *orchestratorv1.Session {
	s := &orchestratorv1.Session{
		SessionUuid: uuid,
		HostId:      host,
		CreatedAt:   createdAt,
	}
	if name != attachv1.SessionStateName_SESSION_STATE_NAME_UNSPECIFIED {
		s.State = &attachv1.SessionState{Name: name}
	}
	return s
}

// TestSessionsListRendersRows: `sessions list` dials the fake, calls ListSessions,
// and renders a table whose header + each session's uuid/state/host/created cell
// appear in stdout. The rows are rendered in the order returned (newest-first; the
// store sorts CreatedAt desc) — this asserts that order is preserved, not re-sorted.
func TestSessionsListRendersRows(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = func(_ context.Context, _ *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
		return &orchestratorv1.ListSessionsResponse{Sessions: []*orchestratorv1.Session{
			sessionRow("sess-new", "host-a", attachv1.SessionStateName_SESSION_STATE_NAME_WORKING, 200),
			sessionRow("sess-old", "host-b", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 100),
		}}, nil
	}
	dialFake(t, fake)
	out := captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1"}) }); got != 0 {
		t.Fatalf("sessions list = %d, want 0", got)
	}
	rendered := out.String()
	for _, want := range []string{"UUID", "STATE", "HOST", "CREATED", "sess-new", "sess-old", "WORKING", "READY", "host-a", "host-b"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered table missing %q\n--- table ---\n%s", want, rendered)
		}
	}
	// State labels are the SHORT §3 names (the SESSION_STATE_NAME_ prefix stripped).
	if strings.Contains(rendered, "SESSION_STATE_NAME_") {
		t.Errorf("state column should strip the SESSION_STATE_NAME_ prefix, got:\n%s", rendered)
	}
	// Newest-first: sess-new (CreatedAt 200) must render before sess-old (CreatedAt 100).
	if i, j := strings.Index(rendered, "sess-new"), strings.Index(rendered, "sess-old"); i < 0 || j < 0 || i > j {
		t.Errorf("rows not rendered newest-first (sess-new before sess-old):\n%s", rendered)
	}
	// The ListSessions RPC was actually driven.
	if calls := fake.ListSessionsRecorded(); len(calls) != 1 {
		t.Errorf("ListSessions called %d times, want 1", len(calls))
	}
}

// TestSessionsListRendersWriterColumn: the WRITER column (Session.has_writer,
// U-WRITERCOL) renders "yes" for an attended session and "-" for a writer-less
// one, so an operator can see which sessions are reaper candidates.
func TestSessionsListRendersWriterColumn(t *testing.T) {
	attended := sessionRow("sess-attended", "host-a", attachv1.SessionStateName_SESSION_STATE_NAME_WORKING, 200)
	attended.HasWriter = true
	writerless := sessionRow("sess-idle", "host-b", attachv1.SessionStateName_SESSION_STATE_NAME_READY, 100)
	writerless.HasWriter = false

	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = func(_ context.Context, _ *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
		return &orchestratorv1.ListSessionsResponse{Sessions: []*orchestratorv1.Session{attended, writerless}}, nil
	}
	dialFake(t, fake)
	out := captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1"}) }); got != 0 {
		t.Fatalf("sessions list = %d, want 0", got)
	}
	rendered := out.String()
	if !strings.Contains(rendered, "WRITER") {
		t.Errorf("rendered table missing the WRITER header column:\n%s", rendered)
	}
	// The attended row carries "yes"; the writer-less row carries "-".
	attendedLine, idleLine := lineContaining(rendered, "sess-attended"), lineContaining(rendered, "sess-idle")
	if !strings.Contains(attendedLine, "yes") {
		t.Errorf("attended session row missing WRITER=yes: %q", attendedLine)
	}
	if !strings.Contains(idleLine, "-") {
		t.Errorf("writer-less session row missing WRITER=-: %q", idleLine)
	}
}

// lineContaining returns the first line of s that contains sub (or "").
func lineContaining(s, sub string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, sub) {
			return ln
		}
	}
	return ""
}

// TestSessionsListEmptyRendersHeaderOnly: an empty enumeration prints the header
// (a stable, scriptable shape) and exits 0 — not an error.
func TestSessionsListEmptyRendersHeaderOnly(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = func(_ context.Context, _ *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
		return &orchestratorv1.ListSessionsResponse{}, nil
	}
	dialFake(t, fake)
	out := captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1"}) }); got != 0 {
		t.Fatalf("sessions list (empty) = %d, want 0", got)
	}
	if rendered := out.String(); !strings.Contains(rendered, "UUID") {
		t.Errorf("empty list should still render the header, got %q", rendered)
	}
}

// TestSessionsListForwardsHostFilter: --host is carried on the ListSessions request
// (the fleet-narrowing filter).
func TestSessionsListForwardsHostFilter(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = func(_ context.Context, req *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
		return &orchestratorv1.ListSessionsResponse{}, nil
	}
	dialFake(t, fake)
	captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1", "--host", "host-z"}) }); got != 0 {
		t.Fatalf("sessions list --host = %d, want 0", got)
	}
	calls := fake.ListSessionsRecorded()
	if len(calls) != 1 {
		t.Fatalf("ListSessions called %d times, want 1", len(calls))
	}
	if got := calls[0].Req.GetHostId(); got != "host-z" {
		t.Errorf("ListSessions host_id = %q, want %q", got, "host-z")
	}
}

// TestSessionsListRPCError: a ListSessions RPC failure surfaces a non-zero exit.
func TestSessionsListRPCError(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.ListSessionsResponder = func(_ context.Context, _ *orchestratorv1.ListSessionsRequest) (*orchestratorv1.ListSessionsResponse, error) {
		return nil, errors.New("boom")
	}
	dialFake(t, fake)
	captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"list", "--orchestrator", "x:1"}) }); got != 1 {
		t.Errorf("sessions list (RPC error) = %d, want 1", got)
	}
}

// TestSessionsDestroyCallsDestroySession: `sessions destroy <uuid>` dials the fake
// and calls DestroySession with the exact uuid, exiting 0 on success.
func TestSessionsDestroyCallsDestroySession(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.DestroySessionResponder = func(_ context.Context, req *orchestratorv1.DestroySessionRequest) (*orchestratorv1.DestroySessionResponse, error) {
		return &orchestratorv1.DestroySessionResponse{}, nil
	}
	dialFake(t, fake)
	captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"destroy", "sess-xyz", "--orchestrator", "x:1"}) }); got != 0 {
		t.Fatalf("sessions destroy = %d, want 0", got)
	}
	calls := fake.DestroySessionRecorded()
	if len(calls) != 1 {
		t.Fatalf("DestroySession called %d times, want 1", len(calls))
	}
	if got := calls[0].Req.GetSessionUuid(); got != "sess-xyz" {
		t.Errorf("DestroySession session_uuid = %q, want %q", got, "sess-xyz")
	}
}

// TestSessionsDestroyRPCError: a DestroySession RPC failure surfaces a non-zero exit.
func TestSessionsDestroyRPCError(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.DestroySessionResponder = func(_ context.Context, _ *orchestratorv1.DestroySessionRequest) (*orchestratorv1.DestroySessionResponse, error) {
		return nil, errors.New("nope")
	}
	dialFake(t, fake)
	captureStdout(t)

	if got := runCmd(t, func() int { return cmdSessions([]string{"destroy", "sess-xyz", "--orchestrator", "x:1"}) }); got != 1 {
		t.Errorf("sessions destroy (RPC error) = %d, want 1", got)
	}
}

// TestSessionsDestroyMissingUUID: `sessions destroy` with no uuid is a usage error (2),
// without dialing.
func TestSessionsDestroyMissingUUID(t *testing.T) {
	if got := cmdSessions([]string{"destroy", "--orchestrator", "x:1"}); got != 2 {
		t.Errorf("sessions destroy (no uuid) = %d, want 2", got)
	}
}

// TestSessionsRequiresOrchestrator: both verbs require --orchestrator (or env) — a
// usage error (2) when unset, before any dial.
func TestSessionsRequiresOrchestrator(t *testing.T) {
	t.Setenv(orchestratorEnv, "")
	if got := cmdSessions([]string{"list"}); got != 2 {
		t.Errorf("sessions list (no --orchestrator) = %d, want 2", got)
	}
	if got := cmdSessions([]string{"destroy", "sess-x"}); got != 2 {
		t.Errorf("sessions destroy (no --orchestrator) = %d, want 2", got)
	}
}

// TestSessionsNoSubcommand: a bare `sessions` prints usage and returns 2.
func TestSessionsNoSubcommand(t *testing.T) {
	if got := cmdSessions(nil); got != 2 {
		t.Errorf("cmdSessions(nil) = %d, want 2", got)
	}
}

// TestSessionsUnknownSubcommand: a verb that is neither list nor destroy is a usage error (2).
func TestSessionsUnknownSubcommand(t *testing.T) {
	if got := cmdSessions([]string{"frobnicate"}); got != 2 {
		t.Errorf("cmdSessions frobnicate = %d, want 2", got)
	}
}

// TestSessionsHelp: `sessions -h|--help|help` prints usage and returns 0 (not an error).
func TestSessionsHelp(t *testing.T) {
	for _, h := range []string{"-h", "--help", "help"} {
		if got := cmdSessions([]string{h}); got != 0 {
			t.Errorf("cmdSessions %q = %d, want 0", h, got)
		}
	}
}

// TestSessionsRouting: `serpent-tui sessions …` is routed by the top-level run()
// dispatcher to cmdSessions (a no-uuid destroy → exit 2 proves the route reached
// cmdSessions rather than the unknown-command path, which is also 2 but via a
// different message; the empty-subcommand 2 is the unambiguous proof here).
func TestSessionsRouting(t *testing.T) {
	if got := run([]string{"sessions"}); got != 2 {
		t.Errorf("run([sessions]) = %d, want 2 (routed to cmdSessions usage)", got)
	}
}

// TestStateLabel: the state column strips the prefix and renders "-" for nil/unspecified.
func TestStateLabel(t *testing.T) {
	cases := []struct {
		in   *attachv1.SessionState
		want string
	}{
		{nil, "-"},
		{&attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_UNSPECIFIED}, "-"},
		{&attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_READY}, "READY"},
		{&attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYING}, "DESTROYING"},
	}
	for _, c := range cases {
		if got := stateLabel(c.in); got != c.want {
			t.Errorf("stateLabel(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCreatedLabel: 0 renders "-", a nonzero unix-seconds value renders a UTC RFC3339 stamp.
func TestCreatedLabel(t *testing.T) {
	if got := createdLabel(0); got != "-" {
		t.Errorf("createdLabel(0) = %q, want %q", got, "-")
	}
	if got := createdLabel(1); !strings.HasPrefix(got, "1970-01-01T00:00:01") {
		t.Errorf("createdLabel(1) = %q, want a 1970-01-01T00:00:01Z stamp", got)
	}
}
