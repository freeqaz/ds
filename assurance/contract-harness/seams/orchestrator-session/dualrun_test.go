// SPDX-License-Identifier: Apache-2.0

package orchestratorsession_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"
	orchestratorsession "github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/orchestrator-session"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1/orchestratorv1fake"
)

// TestSeam_RealVsGeneratedFake is the per-commit gate for the client/console <->
// orchestrator SessionService control-plane seam (doc 15 §5.3/§11, doc 06 §2.1):
// the seam's conformance suite runs against BOTH the real reference
// implementation AND the generated programmable fake, and the seam is green only
// if every scenario observes the same thing on both. The suite exercises every
// one of the SessionService verbs' success paths (CreateSession, DestroySession,
// SuspendSession, ResumeSession, SnapshotSession, ListSessions, WatchSession,
// Attach, CreateChildSession, RecordEnvConfig) plus idempotency, the §4.2
// teardown ordering, and the WatchSession event leg.
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := orchestratorsession.Suite().Run(context.Background(), orchestratorsession.RealDialer(), orchestratorsession.FakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("orchestrator SessionService seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_HarnessCatchesADriftedFake is the negative proof: a fake that drifts
// from the contract (here, a DestroySession that errors NotFound on the
// idempotent retry instead of succeeding — the doc 15 §4.2 idempotent-teardown
// violation) must fail the seam. Without this, a green dual-run would be
// meaningless — it could be passing because the gate never fires. The drift is
// injected only in this test's local fake, never in the committed generated fake.
func TestSeam_HarnessCatchesADriftedFake(t *testing.T) {
	res, err := orchestratorsession.Suite().Run(context.Background(), orchestratorsession.RealDialer(), driftedDestroyFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if res.OK() {
		t.Fatal("a drifted fake passed the seam — the dual-run gate is not firing")
	}
	if len(res.Divergences) == 0 && len(res.FakeErrors) == 0 {
		t.Fatalf("expected a divergence or fake error, got report:\n%s", res.Report())
	}
}

// TestIdempotency_RecordedViaFakeAccessors asserts the idempotency-on-session_uuid
// contract directly against the generated fake's per-verb *Recorded() call-
// capture accessors (doc 15 §4.1/§5.3). Re-issuing CreateSession / SnapshotSession
// with the same create keys is observably a no-op on the RESULT (same record /
// same uuid), and an idempotent DestroySession retry SUCCEEDS — AND the fake
// records EVERY call, so the test proves the recorder sees both issues while the
// contract collapses them to one effect. This is the assertion the dual-run alone
// cannot make: the dual-run compares end-observable outcomes; the recorded-call
// surface is what lets a downstream consumer verify "the control plane was asked
// twice and answered the same".
func TestIdempotency_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()
	f := orchestratorv1fake.NewSessionServiceFake()

	// Program just enough honest behavior to observe idempotency: a stable record
	// per create key, a stable snapshot state, and a no-op idempotent Destroy.
	records := map[string]*orchestratorv1.Session{}
	keyOf := func(req *orchestratorv1.CreateSessionRequest) string {
		return req.GetRepoId() + "/" + req.GetEnvConfigRef() + "/" + req.GetLaunchingUser()
	}
	f.CreateSessionResponder = func(_ context.Context, req *orchestratorv1.CreateSessionRequest) (*orchestratorv1.CreateSessionResponse, error) {
		k := keyOf(req)
		if rec, ok := records[k]; ok {
			return &orchestratorv1.CreateSessionResponse{Session: rec}, nil // idempotent re-issue -> same record
		}
		rec := &orchestratorv1.Session{
			SessionUuid:      "ses-synthetic-" + k,
			HostSessionIndex: uint64(len(records) + 1),
			TapName:          "dstap-synthetic",
			LaunchingUser:    req.GetLaunchingUser(),
			State:            &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_READY},
		}
		records[k] = rec
		return &orchestratorv1.CreateSessionResponse{Session: rec}, nil
	}
	f.SnapshotSessionResponder = func(_ context.Context, req *orchestratorv1.SnapshotSessionRequest) (*orchestratorv1.SnapshotSessionResponse, error) {
		return &orchestratorv1.SnapshotSessionResponse{
			Session: &orchestratorv1.Session{
				SessionUuid: req.GetSessionUuid(),
				State:       &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_SNAPSHOTTING},
			},
		}, nil
	}
	f.DestroySessionResponder = func(_ context.Context, req *orchestratorv1.DestroySessionRequest) (*orchestratorv1.DestroySessionResponse, error) {
		return &orchestratorv1.DestroySessionResponse{
			Session: &orchestratorv1.Session{
				SessionUuid: req.GetSessionUuid(),
				State:       &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED},
			},
		}, nil // idempotent: always succeeds
	}

	createReq := &orchestratorv1.CreateSessionRequest{
		RepoId:        "repo-synthetic-recorded",
		EnvConfigRef:  "envref-synthetic-recorded",
		LaunchingUser: "user-synthetic-recorded",
	}

	first, err := f.CreateSession(ctx, createReq)
	if err != nil {
		t.Fatalf("first CreateSession: %v", err)
	}
	second, err := f.CreateSession(ctx, createReq)
	if err != nil {
		t.Fatalf("second CreateSession: %v", err)
	}
	if first.GetSession().GetSessionUuid() != second.GetSession().GetSessionUuid() ||
		first.GetSession().GetHostSessionIndex() != second.GetSession().GetHostSessionIndex() {
		t.Fatalf("CreateSession not idempotent on session_uuid: %v vs %v", first.GetSession(), second.GetSession())
	}

	// The recorder must have captured BOTH issues, each carrying the same keys.
	createCalls := f.CreateSessionRecorded()
	if len(createCalls) != 2 {
		t.Fatalf("CreateSessionRecorded: want 2 captured calls, got %d", len(createCalls))
	}
	for i, c := range createCalls {
		if got := c.Req.GetRepoId(); got != createReq.GetRepoId() {
			t.Fatalf("CreateSessionRecorded[%d].repo_id = %q, want %q", i, got, createReq.GetRepoId())
		}
		if got := c.Req.GetEnvConfigRef(); got != createReq.GetEnvConfigRef() {
			t.Fatalf("CreateSessionRecorded[%d].env_config_ref = %q, want %q", i, got, createReq.GetEnvConfigRef())
		}
	}

	// Snapshot: re-issue returns the same record; the recorder captures both.
	uuid := first.GetSession().GetSessionUuid()
	snapReq := &orchestratorv1.SnapshotSessionRequest{SessionUuid: uuid}
	s1, _ := f.SnapshotSession(ctx, snapReq)
	s2, _ := f.SnapshotSession(ctx, snapReq)
	if s1.GetSession().GetSessionUuid() != s2.GetSession().GetSessionUuid() {
		t.Fatalf("Snapshot not idempotent: %q vs %q", s1.GetSession().GetSessionUuid(), s2.GetSession().GetSessionUuid())
	}
	if n := len(f.SnapshotSessionRecorded()); n != 2 {
		t.Fatalf("SnapshotSessionRecorded: want 2, got %d", n)
	}

	// Destroy: the idempotent retry succeeds; the recorder captures both.
	destroyReq := &orchestratorv1.DestroySessionRequest{SessionUuid: uuid}
	if _, err := f.DestroySession(ctx, destroyReq); err != nil {
		t.Fatalf("first DestroySession: %v", err)
	}
	if _, err := f.DestroySession(ctx, destroyReq); err != nil {
		t.Fatalf("idempotent DestroySession retry must succeed, got: %v", err)
	}
	if n := len(f.DestroySessionRecorded()); n != 2 {
		t.Fatalf("DestroySessionRecorded: want 2, got %d", n)
	}
}

// driftedDestroyFakeDialer programs the generated fake with a deliberately wrong
// DestroySession responder (errors NotFound on the second call, breaking the
// §4.2 idempotent-teardown contract) to prove the gate bites. All other verbs are
// programmed honestly so the divergence is attributable to the injected drift.
func driftedDestroyFakeDialer() dualrun.Dialer {
	f := orchestratorv1fake.NewSessionServiceFake()
	mirror := orchestratorsession.NewRefImpl()
	mirror.SeedSession("ses-aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa", 101, orchestratorsession.ReadyState())
	mirror.SeedSession("ses-bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb", 102, orchestratorsession.WorkingState())

	f.CreateSessionResponder = mirror.CreateSession
	f.SuspendSessionResponder = mirror.SuspendSession
	f.ResumeSessionResponder = mirror.ResumeSession
	f.SnapshotSessionResponder = mirror.SnapshotSession
	f.ListSessionsResponder = mirror.ListSessions
	f.AttachResponder = mirror.Attach
	f.CreateChildSessionResponder = mirror.CreateChildSession
	f.RecordEnvConfigResponder = mirror.RecordEnvConfig
	f.WatchSessionResponder = func(_ context.Context, req *orchestratorv1.WatchSessionRequest) ([]*orchestratorv1.WatchSessionResponse, error) {
		if req.GetSessionUuid() == "" {
			return nil, status.Error(codes.InvalidArgument, "WatchSessionRequest.session_uuid is required")
		}
		if !mirror.HasSession(req.GetSessionUuid()) {
			return nil, status.Error(codes.NotFound, "no such session")
		}
		var out []*orchestratorv1.WatchSessionResponse
		for _, ev := range orchestratorsession.WatchEventsFor(req.GetSessionUuid()) {
			if ev.GetEvent().GetSeq() <= req.GetFromSeq() {
				continue
			}
			out = append(out, ev)
		}
		return out, nil
	}

	var destroyCount int
	f.DestroySessionResponder = func(ctx context.Context, req *orchestratorv1.DestroySessionRequest) (*orchestratorv1.DestroySessionResponse, error) {
		destroyCount++
		if destroyCount > 1 {
			// DRIFT: an idempotent DestroySession retry must succeed, not error.
			return nil, status.Error(codes.NotFound, "no such session")
		}
		return mirror.DestroySession(ctx, req)
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		orchestratorv1fake.RegisterSessionService(s, f)
	})
}

// --- shared back-pressure driver delegation guard (seam-local) ----------------
//
// This seam's WatchSession lifecycle end (streaming.go) does NOT hand-roll the
// server-side producer loop: it builds a dualrun.BackPressurePlan and drives it
// through the SHARED dualrun.RunBackPressureStream, threading only this seam's
// WatchSession event builder. That delegation is the whole point of the fixture
// consolidation — the producer LOGIC (ctx-check / Send / park) lives ONCE in
// dualrun, so a back-pressure-semantics edit lands in one place instead of being
// re-forked per seam. The cross-seam half of this invariant is pinned centrally in
// dualrun/streaming_test.go (TestStreamingSeamsDelegateToSharedDriver); this is the
// seam-LOCAL trip-wire, so a developer editing only this package and running
// `go test ./seams/orchestrator-session/` still gets a failure the instant the
// producer loop is re-inlined back into WatchSession.
//
// It is a SOURCE-level structural assertion (the established go/ast idiom in this
// tree), hermetic (D50): it parses this seam's own streaming.go bytes — located
// relative to this test file at runtime — and opens no stream.
func TestWatchSessionDelegatesToSharedBackPressureDriver(t *testing.T) {
	const (
		method            = "WatchSession"
		recvType          = "watchStreamSession"
		sharedDriverPkg   = "dualrun"
		sharedDriverFunc  = "RunBackPressureStream"
		streamingFileName = "streaming.go"
	)

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) could not locate this test's source file — the back-pressure delegation guard cannot run")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), streamingFileName)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s for the back-pressure delegation guard: %v", srcPath, err)
	}

	var methodDecl *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, isFn := decl.(*ast.FuncDecl)
		if !isFn || fn.Recv == nil || fn.Name.Name != method || len(fn.Recv.List) != 1 {
			continue
		}
		rt := fn.Recv.List[0].Type
		if star, isStar := rt.(*ast.StarExpr); isStar {
			rt = star.X
		}
		id, isID := rt.(*ast.Ident)
		if !isID || id.Name != recvType {
			continue
		}
		if methodDecl != nil {
			t.Fatalf("found more than one %s.%s in %s — the back-pressure delegation guard's method lookup is ambiguous", recvType, method, srcPath)
		}
		methodDecl = fn
	}
	if methodDecl == nil {
		t.Fatalf("could not locate %s.%s in %s — the streaming end moved or was renamed; confirm it still delegates to %s.%s and update this guard",
			recvType, method, srcPath, sharedDriverPkg, sharedDriverFunc)
	}

	delegates := false
	ast.Inspect(methodDecl.Body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != sharedDriverFunc {
			return true
		}
		if pkg, isID := sel.X.(*ast.Ident); isID && pkg.Name == sharedDriverPkg {
			delegates = true
			return false
		}
		return true
	})
	if !delegates {
		t.Fatalf("%s.%s in %s does NOT delegate to %s.%s — the shared back-pressure producer loop appears re-inlined into the WatchSession end, re-forking the streaming-lifecycle semantics the fixture single-sources; restore the delegation or update this guard deliberately",
			recvType, method, srcPath, sharedDriverPkg, sharedDriverFunc)
	}
}
