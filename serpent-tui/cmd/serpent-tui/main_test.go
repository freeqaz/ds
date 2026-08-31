// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
)

// headless points the interactive loop at a non-TTY EOF input and a discard
// output so the offline live-path tests drive the real bubbletea program with no
// terminal. It restores the prior I/O on cleanup.
func headless(t *testing.T) {
	t.Helper()
	pin, pout := stdin, stdout
	t.Cleanup(func() { stdin, stdout = pin, pout })
	stdin = strings.NewReader("") // immediate EOF; the loop quits on the scripted stream end, not on input
	stdout = io.Discard
}

// runCmd runs fn (a cmd entrypoint) and bounds it so a regression that wedges the
// headless loop fails fast instead of hanging the suite.
func runCmd(t *testing.T, fn func() int) int {
	t.Helper()
	done := make(chan int, 1)
	go func() { done <- fn() }()
	select {
	case code := <-done:
		return code
	case <-time.After(30 * time.Second):
		t.Fatal("cmd entrypoint hung past 30s — a live-path regression wedged the loop")
		return -1
	}
}

// --- offline fake plumbing ---------------------------------------------------

// stateEvent builds a SESSION_STATE event at seq.
func stateEvent(seq uint64, name attachv1.SessionStateName) *orchestratorv1.WatchSessionResponse {
	return &orchestratorv1.WatchSessionResponse{Event: &attachv1.SessionEvent{
		Seq:     seq,
		Type:    attachv1.EventType_EVENT_TYPE_SESSION_STATE,
		Payload: &attachv1.SessionEvent_SessionState{SessionState: &attachv1.SessionState{Name: name}},
	}}
}

// destroyingLog is a short scripted stream that ends cleanly (a DESTROYED state
// is the terminal the subscriber drains on), so Run returns without a live VM.
func destroyingLog() []*orchestratorv1.WatchSessionResponse {
	return []*orchestratorv1.WatchSessionResponse{
		stateEvent(1, attachv1.SessionStateName_SESSION_STATE_NAME_READY),
		stateEvent(2, attachv1.SessionStateName_SESSION_STATE_NAME_WORKING),
		stateEvent(3, attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED),
	}
}

// logAfter filters a scripted log to the events strictly after fromSeq — the
// resume-from-LastSeq contract the WatchSession subscriber relies on. A
// reconnect after a clean mid-session end resubscribes from lastSeq; without
// honoring from_seq the fake would replay seq 1 again and the loop would (rightly)
// reject the out-of-order event (D79). The real terminator filters identically.
func logAfter(log []*orchestratorv1.WatchSessionResponse, fromSeq uint64) []*orchestratorv1.WatchSessionResponse {
	var out []*orchestratorv1.WatchSessionResponse
	for _, r := range log {
		if r.GetEvent().GetSeq() > fromSeq {
			out = append(out, r)
		}
	}
	return out
}

// dialFake serves the programmed fake on an in-process bufconn and points the
// package `dialer` var at a client over it — so cmdAttach/cmdUp dial the fake,
// never a live orchestrator. It restores dialer on cleanup.
func dialFake(t *testing.T, fake *orchestratorv1fake.SessionServiceFake) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	orchestratorv1fake.RegisterSessionService(gs, fake)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	prev := dialer
	t.Cleanup(func() { dialer = prev })
	dialer = func(endpoint string) (sessionClient, func() error, error) {
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, nil, err
		}
		return orchestratorv1.NewSessionServiceClient(conn), conn.Close, nil
	}
}

// readerOnlyHandle is an Attach reply whose handle carries NO servable direct
// endpoint (gap 3 not yet landed) — the attach runs reader-only (nil seat), which
// is the offline-correct path here: no real UDS exists in CI to dial.
func readerOnlyHandle(uuid string) *orchestratorv1.AttachResponse {
	return &orchestratorv1.AttachResponse{Handle: &attachv1.AttachHandle{
		SessionUuid: uuid,
		Role:        attachv1.Role_ROLE_WRITER,
		Auth:        &attachv1.AuthMaterial{Token: []byte("tok")},
		Endpoints:   nil, // no servable direct endpoint (gap 3)
	}}
}

// --- dispatcher tests --------------------------------------------------------

// TestRunDispatch covers the bare dispatcher: usage, unknown command, help. It
// must not dial (no orchestrator endpoint given), so each returns a flag error.
func TestRunDispatch(t *testing.T) {
	if got := run(nil); got != 2 {
		t.Errorf("run(nil) = %d, want 2 (usage)", got)
	}
	if got := run([]string{"bogus"}); got != 2 {
		t.Errorf("run(unknown) = %d, want 2", got)
	}
	if got := run([]string{"help"}); got != 0 {
		t.Errorf("run(help) = %d, want 0", got)
	}
}

// TestAttachRequiresFlags: attach without an orchestrator endpoint or session
// UUID refuses cleanly (exit 2) BEFORE any dial.
func TestAttachRequiresFlags(t *testing.T) {
	t.Setenv(orchestratorEnv, "") // ensure no env fallback
	if got := cmdAttach(nil); got != 2 {
		t.Errorf("attach (no flags) = %d, want 2", got)
	}
	if got := cmdAttach([]string{"--orchestrator", "x:1"}); got != 2 {
		t.Errorf("attach (no --session) = %d, want 2", got)
	}
}

// TestUpRequiresFlags: up requires both create keys (--repo + --env-config-ref)
// and an orchestrator endpoint; missing any refuses cleanly (exit 2).
func TestUpRequiresFlags(t *testing.T) {
	t.Setenv(orchestratorEnv, "")
	if got := cmdUp(nil); got != 2 {
		t.Errorf("up (no flags) = %d, want 2", got)
	}
	if got := cmdUp([]string{"--orchestrator", "x:1", "--repo", "r"}); got != 2 {
		t.Errorf("up (no --env-config-ref) = %d, want 2", got)
	}
}

// --- offline live-path tests (against the fake SessionService) ---------------

// TestAttachAgainstFake proves the `attach` path end-to-end OFFLINE: it dials the
// fake SessionService, resolves the AttachHandle via the Attach RPC, builds the
// live serpenttui.Config (Starter over the dialed client), and runs the
// interactive loop to a clean termination — with NO live orchestrator/VM. It
// also asserts the Attach RPC requested the WRITER seat (D61).
func TestAttachAgainstFake(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.AttachResponder = func(_ context.Context, req *orchestratorv1.AttachRequest) (*orchestratorv1.AttachResponse, error) {
		return readerOnlyHandle(req.GetSessionUuid()), nil
	}
	fake.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		return logAfter(destroyingLog(), req.GetFromSeq()), nil
	}
	dialFake(t, fake)
	headless(t)

	if got := runCmd(t, func() int {
		return cmdAttach([]string{"--orchestrator", "bufnet", "--session", "sess-1", "--color=false"})
	}); got != 0 {
		t.Fatalf("cmdAttach = %d, want 0 (clean attach + stream end)", got)
	}

	attachCalls := fake.AttachRecorded()
	if len(attachCalls) != 1 {
		t.Fatalf("Attach called %d times, want 1", len(attachCalls))
	}
	if got := attachCalls[0].Req.GetSessionUuid(); got != "sess-1" {
		t.Errorf("Attach session = %q, want sess-1", got)
	}
	if got := attachCalls[0].Req.GetRole(); got != attachv1.Role_ROLE_WRITER {
		t.Errorf("Attach role = %v, want WRITER (D61)", got)
	}
	// WatchSession is called at least once; the subscriber may reconnect-from-
	// frontier once after a clean mid-session end (it resubscribes from lastSeq,
	// gets an empty span, and stops) — that is the D79 resume contract, not a bug.
	if n := len(fake.WatchSessionRecorded()); n < 1 {
		t.Errorf("WatchSession called %d times, want >= 1", n)
	}
}

// TestUpAgainstFake proves the one-command `up` path OFFLINE: CreateSession
// provisions a session, the returned UUID is carried into Attach, and the same
// interactive loop runs to a clean end — provision + attach in one command, no
// live orchestrator/VM. It asserts CreateSession carried the two create keys and
// that Attach used the freshly-minted UUID.
func TestUpAgainstFake(t *testing.T) {
	const newUUID = "fresh-uuid-42"
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.CreateSessionResponder = func(_ context.Context, _ *orchestratorv1.CreateSessionRequest) (*orchestratorv1.CreateSessionResponse, error) {
		return &orchestratorv1.CreateSessionResponse{Session: &orchestratorv1.Session{SessionUuid: newUUID}}, nil
	}
	fake.AttachResponder = func(_ context.Context, req *orchestratorv1.AttachRequest) (*orchestratorv1.AttachResponse, error) {
		return readerOnlyHandle(req.GetSessionUuid()), nil
	}
	fake.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		return logAfter(destroyingLog(), req.GetFromSeq()), nil
	}
	dialFake(t, fake)
	headless(t)

	if got := runCmd(t, func() int {
		return cmdUp([]string{"--orchestrator", "bufnet", "--repo", "repo-x", "--env-config-ref", "ecr-y", "--launching-user", "u", "--color=false"})
	}); got != 0 {
		t.Fatalf("cmdUp = %d, want 0 (provision + clean attach)", got)
	}

	createCalls := fake.CreateSessionRecorded()
	if len(createCalls) != 1 {
		t.Fatalf("CreateSession called %d times, want 1", len(createCalls))
	}
	if got := createCalls[0].Req.GetRepoId(); got != "repo-x" {
		t.Errorf("CreateSession repo_id = %q, want repo-x", got)
	}
	if got := createCalls[0].Req.GetEnvConfigRef(); got != "ecr-y" {
		t.Errorf("CreateSession env_config_ref = %q, want ecr-y", got)
	}
	attachCalls := fake.AttachRecorded()
	if len(attachCalls) != 1 || attachCalls[0].Req.GetSessionUuid() != newUUID {
		t.Fatalf("Attach should target the provisioned UUID %q, got %+v", newUUID, attachCalls)
	}
}

// TestUpRmDestroysOnExit: `up --rm` makes the session EPHEMERAL — after the attach
// loop returns (a clean stream end here), DestroySession is called EXACTLY ONCE,
// with the freshly-provisioned UUID. The exit code is unaffected (a clean attach
// stays 0; --rm teardown is best-effort, layered on top).
func TestUpRmDestroysOnExit(t *testing.T) {
	const newUUID = "ephemeral-uuid-7"
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.CreateSessionResponder = func(_ context.Context, _ *orchestratorv1.CreateSessionRequest) (*orchestratorv1.CreateSessionResponse, error) {
		return &orchestratorv1.CreateSessionResponse{Session: &orchestratorv1.Session{SessionUuid: newUUID}}, nil
	}
	fake.AttachResponder = func(_ context.Context, req *orchestratorv1.AttachRequest) (*orchestratorv1.AttachResponse, error) {
		return readerOnlyHandle(req.GetSessionUuid()), nil
	}
	fake.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		return logAfter(destroyingLog(), req.GetFromSeq()), nil
	}
	fake.DestroySessionResponder = func(_ context.Context, _ *orchestratorv1.DestroySessionRequest) (*orchestratorv1.DestroySessionResponse, error) {
		return &orchestratorv1.DestroySessionResponse{Session: &orchestratorv1.Session{SessionUuid: newUUID}}, nil
	}
	dialFake(t, fake)
	headless(t)

	if got := runCmd(t, func() int {
		return cmdUp([]string{"--orchestrator", "bufnet", "--repo", "r", "--env-config-ref", "e", "--launching-user", "u", "--rm", "--color=false"})
	}); got != 0 {
		t.Fatalf("cmdUp --rm = %d, want 0 (clean attach; --rm teardown is best-effort)", got)
	}

	destroyCalls := fake.DestroySessionRecorded()
	if len(destroyCalls) != 1 {
		t.Fatalf("DestroySession called %d times with --rm, want exactly 1", len(destroyCalls))
	}
	if got := destroyCalls[0].Req.GetSessionUuid(); got != newUUID {
		t.Errorf("DestroySession session_uuid = %q, want the provisioned %q", got, newUUID)
	}
}

// TestUpNoRmNeverDestroys: WITHOUT --rm, `up` NEVER calls DestroySession — the
// default D61 persist-on-detach behavior is unchanged (the session keeps running
// for a later `attach --session`).
func TestUpNoRmNeverDestroys(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.CreateSessionResponder = func(_ context.Context, _ *orchestratorv1.CreateSessionRequest) (*orchestratorv1.CreateSessionResponse, error) {
		return &orchestratorv1.CreateSessionResponse{Session: &orchestratorv1.Session{SessionUuid: "persist-1"}}, nil
	}
	fake.AttachResponder = func(_ context.Context, req *orchestratorv1.AttachRequest) (*orchestratorv1.AttachResponse, error) {
		return readerOnlyHandle(req.GetSessionUuid()), nil
	}
	fake.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		return logAfter(destroyingLog(), req.GetFromSeq()), nil
	}
	// DestroySessionResponder intentionally LEFT UNSET — if the no--rm path called it,
	// the fake would record the call (and return Unimplemented), failing the assertion.
	dialFake(t, fake)
	headless(t)

	if got := runCmd(t, func() int {
		return cmdUp([]string{"--orchestrator", "bufnet", "--repo", "r", "--env-config-ref", "e", "--launching-user", "u", "--color=false"})
	}); got != 0 {
		t.Fatalf("cmdUp (no --rm) = %d, want 0", got)
	}

	if n := len(fake.DestroySessionRecorded()); n != 0 {
		t.Fatalf("DestroySession called %d times without --rm, want 0 (persist is the default, D61)", n)
	}
}

// TestUpRmDestroyErrorDoesNotMaskExit: a FAILED DestroySession on the --rm path is
// best-effort — it is logged and swallowed, and must NOT flip a clean attach (exit
// 0) into a failure. The destroy is still attempted exactly once.
func TestUpRmDestroyErrorDoesNotMaskExit(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.CreateSessionResponder = func(_ context.Context, _ *orchestratorv1.CreateSessionRequest) (*orchestratorv1.CreateSessionResponse, error) {
		return &orchestratorv1.CreateSessionResponse{Session: &orchestratorv1.Session{SessionUuid: "boom-1"}}, nil
	}
	fake.AttachResponder = func(_ context.Context, req *orchestratorv1.AttachRequest) (*orchestratorv1.AttachResponse, error) {
		return readerOnlyHandle(req.GetSessionUuid()), nil
	}
	fake.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		return logAfter(destroyingLog(), req.GetFromSeq()), nil
	}
	fake.DestroySessionResponder = func(_ context.Context, _ *orchestratorv1.DestroySessionRequest) (*orchestratorv1.DestroySessionResponse, error) {
		return nil, errors.New("control plane wedged")
	}
	dialFake(t, fake)
	headless(t)

	if got := runCmd(t, func() int {
		return cmdUp([]string{"--orchestrator", "bufnet", "--repo", "r", "--env-config-ref", "e", "--launching-user", "u", "--rm", "--color=false"})
	}); got != 0 {
		t.Fatalf("cmdUp --rm with a failing DestroySession = %d, want 0 (best-effort, must not mask the clean exit)", got)
	}
	if n := len(fake.DestroySessionRecorded()); n != 1 {
		t.Fatalf("DestroySession attempted %d times on a clean --rm exit, want exactly 1", n)
	}
}

// TestAttachRejectsRmFlag: --rm is an `up`-only flag (only `up` provisioned the
// session). `attach` does not register it, so attach --rm is a flag-parse error
// (exit 2) — attach never reaps a session it did not provision.
func TestAttachRejectsRmFlag(t *testing.T) {
	t.Setenv(orchestratorEnv, "")
	if got := cmdAttach([]string{"--orchestrator", "x:1", "--session", "s", "--rm"}); got != 2 {
		t.Errorf("attach --rm = %d, want 2 (--rm is an up-only flag)", got)
	}
}

// TestUpCreateSessionError: a CreateSession failure aborts `up` (exit 1) and
// NEVER attaches — provisioning is the gate.
func TestUpCreateSessionError(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	// CreateSessionResponder unset ⇒ the fake returns codes.Unimplemented.
	dialFake(t, fake)

	if got := cmdUp([]string{"--orchestrator", "bufnet", "--repo", "r", "--env-config-ref", "e", "--color=false"}); got != 1 {
		t.Errorf("cmdUp with a failing CreateSession = %d, want 1", got)
	}
	if n := len(fake.AttachRecorded()); n != 0 {
		t.Errorf("Attach called %d times after a CreateSession failure, want 0", n)
	}
}

// --- handle-mapping unit tests -----------------------------------------------

// TestLocalHandleReaderOnly: a proto handle with no endpoints maps to a local
// handle with no servable direct endpoint (servable=false) — the reader-only /
// gap-3 path.
func TestLocalHandleReaderOnly(t *testing.T) {
	h := &attachv1.AttachHandle{SessionUuid: "s", Role: attachv1.Role_ROLE_WRITER, Auth: &attachv1.AuthMaterial{Token: []byte("t")}}
	local, servable := localHandle(h)
	if servable {
		t.Error("a handle with no endpoints should NOT be servable")
	}
	if local.SessionUUID != "s" || local.Role != hostbridge.RoleWriter || local.Auth.Token != "t" {
		t.Errorf("localHandle mapped fields wrong: %+v", local)
	}
}

// TestLocalHandleServableDirect: a proto handle carrying a DIRECT endpoint maps
// to a servable local handle whose endpoint is the realized framed-UDS
// (TransportUnix) carrier the SocketTransport dials.
func TestLocalHandleServableDirect(t *testing.T) {
	h := &attachv1.AttachHandle{
		SessionUuid: "s",
		Role:        attachv1.Role_ROLE_WRITER,
		Auth:        &attachv1.AuthMaterial{Token: []byte("t")},
		Endpoints: []*attachv1.EndpointCandidate{
			{Transport: attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT, Address: "/run/ds/sess.sock"},
		},
	}
	local, servable := localHandle(h)
	if !servable {
		t.Fatal("a handle with a DIRECT endpoint with an address should be servable")
	}
	if len(local.Endpoints) != 1 || local.Endpoints[0].Transport != hostbridge.TransportUnix {
		t.Errorf("DIRECT should map to the realized TransportUnix carrier: %+v", local.Endpoints)
	}
	if local.Endpoints[0].Address != "/run/ds/sess.sock" {
		t.Errorf("endpoint address not carried: %+v", local.Endpoints[0])
	}
}

// TestLocalHandleRelayOnly: a relay-only handle (M2) is not servable here.
func TestLocalHandleRelayOnly(t *testing.T) {
	h := &attachv1.AttachHandle{
		SessionUuid: "s",
		Role:        attachv1.Role_ROLE_READER,
		Auth:        &attachv1.AuthMaterial{Token: []byte("t")},
		Endpoints: []*attachv1.EndpointCandidate{
			{Transport: attachv1.EndpointTransport_ENDPOINT_TRANSPORT_RELAY, Address: "wss://relay/x"},
		},
	}
	_, servable := localHandle(h)
	if servable {
		t.Error("a relay-only handle should NOT be servable by the direct/UDS transport (M2)")
	}
}

// TestRoleFromProtoFailsClosed: an unspecified/unknown proto role maps to READER
// (never fabricate a writer seat the server did not grant, D61).
func TestRoleFromProtoFailsClosed(t *testing.T) {
	if got := roleFromProto(attachv1.Role_ROLE_UNSPECIFIED); got != hostbridge.RoleReader {
		t.Errorf("unspecified role = %q, want READER (fail closed)", got)
	}
	if got := roleFromProto(attachv1.Role_ROLE_WRITER); got != hostbridge.RoleWriter {
		t.Errorf("WRITER role = %q, want WRITER", got)
	}
}

// TestExpiresAt: 0 unix seconds is the zero Time (no expiry pinned); a nonzero
// value reconstructs the instant.
func TestExpiresAt(t *testing.T) {
	if !expiresAt(0).IsZero() {
		t.Error("expiresAt(0) should be the zero Time")
	}
	if got := expiresAt(1_700_000_000); got.Unix() != 1_700_000_000 {
		t.Errorf("expiresAt round-trip = %d, want 1700000000", got.Unix())
	}
}

// TestSeatFromHandleReaderOnly: with no servable direct endpoint, seatFromHandle
// returns a nil seat, nil event stream, and nil closer (the reader-only attach),
// never an error and never a dial.
func TestSeatFromHandleReaderOnly(t *testing.T) {
	seat, events, closer, err := seatFromHandle(&attachv1.AttachHandle{SessionUuid: "s", Role: attachv1.Role_ROLE_WRITER})
	if err != nil {
		t.Fatalf("seatFromHandle reader-only err = %v, want nil", err)
	}
	if seat != nil {
		t.Error("reader-only attach should have a nil seat")
	}
	if events != nil {
		t.Error("reader-only attach should have a nil event stream")
	}
	if closer != nil {
		t.Error("reader-only attach should have a nil closer")
	}
}
