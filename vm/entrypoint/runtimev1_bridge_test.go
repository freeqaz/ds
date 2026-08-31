// SPDX-License-Identifier: Apache-2.0

package entrypoint

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"

	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
	"google.golang.org/grpc"
)

// fakeEntrypointServer is a REAL in-process EntrypointService gRPC server. It
// records the requests it received so the test can assert the reporter's calls
// actually reached the server (proving the dial connected, not just that the
// client object was constructed).
type fakeEntrypointServer struct {
	runtimev1.UnimplementedEntrypointServiceServer

	mu       sync.Mutex
	gotReady []*runtimev1.ReportReadyRequest
	gotExit  []*runtimev1.ReportExitRequest
}

func (s *fakeEntrypointServer) ReportReady(_ context.Context, req *runtimev1.ReportReadyRequest) (*runtimev1.ReportReadyResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gotReady = append(s.gotReady, req)
	return &runtimev1.ReportReadyResponse{}, nil
}

func (s *fakeEntrypointServer) ReportExit(_ context.Context, req *runtimev1.ReportExitRequest) (*runtimev1.ReportExitResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gotExit = append(s.gotExit, req)
	return &runtimev1.ReportExitResponse{}, nil
}

func (s *fakeEntrypointServer) readyCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.gotReady)
}

func (s *fakeEntrypointServer) exitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.gotExit)
}

// startFakeEntrypointServer stands up the fake EntrypointService on a real unix
// listener in a t.TempDir() socket and returns the socket PATH (the form
// dialEntrypointService expects: a bare filesystem path, NOT a URI). It tears
// the server down via t.Cleanup.
func startFakeEntrypointServer(t *testing.T) (*fakeEntrypointServer, string) {
	t.Helper()

	// Keep the socket path short: the unix(7) sun_path limit (~108 bytes) is
	// easy to blow with a long t.TempDir() prefix, so use the base dir directly.
	sockPath := filepath.Join(t.TempDir(), "es.sock")

	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix %q: %v", sockPath, err)
	}

	fake := &fakeEntrypointServer{}
	srv := grpc.NewServer()
	runtimev1.RegisterEntrypointServiceServer(srv, fake)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()

	t.Cleanup(func() {
		srv.Stop()
		<-serveErr // drain Serve's return so the goroutine cannot leak.
	})

	return fake, sockPath
}

// TestDialEntrypointService_ReportReadyExit proves the guest->host-agent
// runtime/v1 application-report leg actually connects and delivers. It stands up
// a real EntrypointService server on a unix socket, dials it through
// dialEntrypointService (the production dial path), and asserts ReportReady and
// ReportExit succeed AND that the server observed both calls.
//
// This is the regression guard for the dead-on-arrival dial bug: with a custom
// WithContextDialer, gRPC handed the dialer the full "unix:/<path>" target, so
// net.Dial("unix", "unix:/<path>") failed and the channel sat in
// TRANSIENT_FAILURE — every report errored. This test FAILS against that code
// and PASSES once the dial lets gRPC's built-in unix: resolver dial the path.
func TestDialEntrypointService_ReportReadyExit(t *testing.T) {
	fake, sockPath := startFakeEntrypointServer(t)

	client, closeConn, err := dialEntrypointService(sockPath)
	if err != nil {
		t.Fatalf("dialEntrypointService(%q): %v", sockPath, err)
	}
	t.Cleanup(func() { _ = closeConn() })

	session := sessionRef{
		sessionUUID:      "sess-uuid-1",
		hostID:           "host-1",
		hostSessionIndex: 7,
		tapName:          "dstap-1",
	}
	reporter := newEntrypointServiceReporter(client, session)
	if reporter == nil {
		t.Fatal("newEntrypointServiceReporter returned nil for a non-nil client")
	}

	if err := reporter.ReportReady(); err != nil {
		t.Fatalf("ReportReady: %v", err)
	}
	if err := reporter.ReportExit(exitReasonCompleted, 0, "done"); err != nil {
		t.Fatalf("ReportExit: %v", err)
	}

	if got := fake.readyCount(); got != 1 {
		t.Errorf("server received %d ReportReady calls, want 1", got)
	}
	if got := fake.exitCount(); got != 1 {
		t.Errorf("server received %d ReportExit calls, want 1", got)
	}

	// The session join key must survive the round trip (the host agent joins
	// reports to the session record by it).
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if want, got := session.sessionUUID, fake.gotReady[0].GetSessionRef().GetSessionUuid(); want != got {
		t.Errorf("ReportReady SessionRef.SessionUuid = %q, want %q", got, want)
	}
	if want, got := runtimev1.ExitReason_EXIT_REASON_COMPLETED, fake.gotExit[0].GetReason(); want != got {
		t.Errorf("ReportExit Reason = %v, want %v", got, want)
	}
}
