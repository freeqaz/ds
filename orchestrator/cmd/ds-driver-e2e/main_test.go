// SPDX-License-Identifier: Apache-2.0

// Focused unit coverage for the -mode orch-create control-plane path (runOrchCreate):
// it must drive SessionService.CreateSession + Attach(WRITER) against the in-tree
// controlplane fake (SessionServiceFake) over bufconn — NO live orchestrator, NO
// host-agent — and treat CreateSession as the CRITICAL verb (failure => false).
package main

import (
	"context"
	"net"
	"testing"
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// newFakeSessionClient stands up an in-memory bufconn gRPC server serving the
// supplied programmed SessionServiceFake and returns a real client wired to it
// (grpc.NewClient routed onto the bufconn dialer — no socket, the D50-style
// in-test transport). The cleanup tears the server + conn down.
func newFakeSessionClient(t *testing.T, fake *orchestratorv1fake.SessionServiceFake) orchestratorv1.SessionServiceClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	orchestratorv1.RegisterSessionServiceServer(srv, fake)
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return orchestratorv1.NewSessionServiceClient(conn)
}

// TestRunOrchCreate_HappyPath programs the fake to return a session record + a
// WRITER attach handle and asserts runOrchCreate (a) passes the D56 keys through
// to CreateSession, (b) requests the WRITER role on the created uuid, and (c)
// reports both verbs PASS with CreateSession critical-true.
func TestRunOrchCreate_HappyPath(t *testing.T) {
	const wantUUID = "sess-abc-123"
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.CreateSessionResponder = func(_ context.Context, _ *orchestratorv1.CreateSessionRequest) (*orchestratorv1.CreateSessionResponse, error) {
		return &orchestratorv1.CreateSessionResponse{
			Session: &orchestratorv1.Session{
				SessionUuid:      wantUUID,
				HostSessionIndex: 7,
				TapName:          "ds-sess7",
				LaunchingUser:    "mvp-user",
				State:            &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_READY},
			},
		}, nil
	}
	fake.AttachResponder = func(_ context.Context, _ *orchestratorv1.AttachRequest) (*orchestratorv1.AttachResponse, error) {
		return &orchestratorv1.AttachResponse{
			Handle: &attachv1.AttachHandle{
				SessionUuid: wantUUID,
				Role:        attachv1.Role_ROLE_WRITER,
				Endpoints: []*attachv1.EndpointCandidate{
					{Transport: attachv1.EndpointTransport_ENDPOINT_TRANSPORT_DIRECT, Address: "10.0.99.2:4242"},
				},
				Auth:      &attachv1.AuthMaterial{Token: []byte("seat-token"), ExpiresAt: 1234567890},
				ExpiresAt: 1234567890,
			},
		}, nil
	}

	c := newFakeSessionClient(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := &report{}
	if ok := runOrchCreate(ctx, c, "demo-repo", "demo-env", "mvp-user", r); !ok {
		t.Fatalf("runOrchCreate returned false on happy path; report=%+v", r.steps)
	}

	// CreateSession received the D56 keys.
	cs := fake.CreateSessionRecorded()
	if len(cs) != 1 {
		t.Fatalf("CreateSession called %d times, want 1", len(cs))
	}
	if got := cs[0].Req; got.GetRepoId() != "demo-repo" || got.GetEnvConfigRef() != "demo-env" || got.GetLaunchingUser() != "mvp-user" {
		t.Fatalf("CreateSession keys = repo=%q env=%q user=%q; want demo-repo/demo-env/mvp-user",
			got.GetRepoId(), got.GetEnvConfigRef(), got.GetLaunchingUser())
	}
	// Attach requested the WRITER role on the created uuid.
	at := fake.AttachRecorded()
	if len(at) != 1 {
		t.Fatalf("Attach called %d times, want 1", len(at))
	}
	if got := at[0].Req; got.GetSessionUuid() != wantUUID || got.GetRole() != attachv1.Role_ROLE_WRITER {
		t.Fatalf("Attach req = uuid=%q role=%v; want %q/WRITER", got.GetSessionUuid(), got.GetRole(), wantUUID)
	}
	// Both verbs reported PASS.
	assertStep(t, r, "CreateSession", true)
	assertStep(t, r, "Attach", true)
}

// TestRunOrchCreate_CreateSessionFails proves CreateSession is the CRITICAL verb:
// when it errors, runOrchCreate returns false (=> non-zero exit) and never calls
// Attach.
func TestRunOrchCreate_CreateSessionFails(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	// CreateSessionResponder left nil => the fake returns codes.Unimplemented,
	// standing in for a control-plane refusal (e.g. the D56 two-key structural
	// refusal). AttachResponder also nil — it must never be reached.

	c := newFakeSessionClient(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := &report{}
	if ok := runOrchCreate(ctx, c, "demo", "demo-env", "mvp-user", r); ok {
		t.Fatalf("runOrchCreate returned true despite CreateSession failure")
	}
	if got := len(fake.AttachRecorded()); got != 0 {
		t.Fatalf("Attach called %d times after CreateSession failure, want 0", got)
	}
	assertStep(t, r, "CreateSession", false)
}

// TestRunOrchCreate_EmptyUUID treats a record with no session_uuid as a critical
// failure (there is no record to keep the reconciler from quarantining).
func TestRunOrchCreate_EmptyUUID(t *testing.T) {
	fake := orchestratorv1fake.NewSessionServiceFake()
	fake.CreateSessionResponder = func(_ context.Context, _ *orchestratorv1.CreateSessionRequest) (*orchestratorv1.CreateSessionResponse, error) {
		return &orchestratorv1.CreateSessionResponse{Session: &orchestratorv1.Session{}}, nil
	}
	c := newFakeSessionClient(t, fake)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r := &report{}
	if ok := runOrchCreate(ctx, c, "demo", "demo-env", "mvp-user", r); ok {
		t.Fatalf("runOrchCreate returned true on empty session_uuid")
	}
	if got := len(fake.AttachRecorded()); got != 0 {
		t.Fatalf("Attach called %d times on empty uuid, want 0", got)
	}
}

func assertStep(t *testing.T, r *report, name string, wantOK bool) {
	t.Helper()
	for _, s := range r.steps {
		if s.name == name {
			if s.ok != wantOK {
				t.Fatalf("step %q ok=%v, want %v (detail=%q)", name, s.ok, wantOK, s.detail)
			}
			return
		}
	}
	t.Fatalf("step %q not recorded; have %+v", name, r.steps)
}
