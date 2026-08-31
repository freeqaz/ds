// SPDX-License-Identifier: Apache-2.0

package hypervisor_test

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
	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/seams/hypervisor"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1/hypervisorv1fake"
)

// --- recorder-layer cancel-masking guard (PREVENTIVE) ------------------------
//
// The dual-run gate (TestSeam_RealVsGeneratedFake) proves real and fake AGREE on
// every scenario's Observation. For a CLIENT-STREAMING cancel scenario that
// agreement is VACUOUS: if the client cancels mid-stream and the scenario folds
// the terminal status away (records nothing, or records a constant), then a real
// impl that SWALLOWS the cancellation and returns OK and a fake that also returns
// OK observe identically — the seam stays green while cancellation was silently
// masked. The recorder layer, not the diff, is where Canceled must be kept
// distinct from a spurious OK.
//
// The HypervisorDriverService has NO client-streaming verb today: nine verbs are
// unary and ExportDiskDelta is server-streaming (Streams[*].ClientStreams is
// false everywhere — see TestRecorderCancelMaskGuard_NoClientStreamingVerbYet).
// So this is a STANDING TRIP-WIRE: it asserts the recorder convention the seam
// already uses (statusObservation-style "status"=status.Code(err).String()) DOES
// distinguish Canceled from OK, and it fails the instant a client-streaming verb
// is added to the contract without a cancel scenario whose Observation makes that
// distinction. Synthetic codes only (D50); no real client-streaming verb is added
// (that would touch .proto / a CORE tree — forbidden for this unit).

// recorderCancelMaskRecorder is the recorder-layer contract a future
// client-streaming cancel scenario MUST satisfy: given the stream's terminal
// error, fold it into the comparable Observation the dual-run will diff. The seam
// already records terminal status exactly this way (suite.go statusObservation /
// deltaStreamObservation: obs.Set("status", status.Code(err).String())); a cancel
// scenario reuses the same convention so a masked cancel diverges loudly.
type recorderCancelMaskRecorder func(terminalErr error) *dualrun.Observation

// seamTerminalStatusRecorder mirrors the seam's own terminal-status recording
// convention (suite.go statusObservation): record ONLY the observable gRPC status
// code under "status". It is the recorder a client-streaming cancel scenario
// should fold its stream outcome through. Kept here (test-local) so this guard is
// self-contained and does not depend on any shared affordance landing first.
func seamTerminalStatusRecorder(terminalErr error) *dualrun.Observation {
	return dualrun.NewObservation().Set("status", status.Code(terminalErr).String())
}

// assertCancelNotMaskedAtRecorder is the load-bearing invariant: a recorder is
// cancel-mask-SAFE iff the Observation it produces for a Canceled terminal status
// is canonically DISTINCT from the one it produces for a spurious OK (a swallowed
// cancel surfacing as success). If the two canonical forms are equal, the
// recorder masks cancellation — dual-run agreement on it proves nothing.
func assertCancelNotMaskedAtRecorder(t *testing.T, name string, rec recorderCancelMaskRecorder) {
	t.Helper()
	canceledObs := rec(status.Error(codes.Canceled, "synthetic: client canceled mid-stream"))
	// A spurious OK is what a masking impl reports: the stream "completed" with no
	// error even though the client canceled. status.Code(nil) == codes.OK.
	spuriousOKObs := rec(nil)
	if canceledObs.Canonical() == spuriousOKObs.Canonical() {
		t.Fatalf("recorder %q MASKS cancellation: Canceled and a spurious OK record the same Observation %q — "+
			"a client-streaming cancel scenario folded through it would let a swallowed cancel pass the dual-run as green",
			name, canceledObs.Canonical())
	}
}

// TestRecorderCancelMaskGuard asserts the seam's terminal-status recorder
// convention keeps Canceled distinct from a spurious OK. This is the recorder a
// client-streaming cancel scenario must fold through; proving it here means the
// moment such a scenario is wired through the convention, a masked cancel
// (recorded OK) diverges from a true cancel rather than silently agreeing.
func TestRecorderCancelMaskGuard(t *testing.T) {
	assertCancelNotMaskedAtRecorder(t, "hypervisor/seamTerminalStatusRecorder", seamTerminalStatusRecorder)
}

// TestRecorderCancelMaskGuard_NoClientStreamingVerbYet is the trip-wire: it
// asserts the HypervisorDriverService contract has NO client-streaming verb, so
// the cancel-masking risk is latent, not live. The instant a .proto change adds
// one (regenerating the ServiceDesc with ClientStreams=true), this guard FAILS
// and forces the adder to wire a client-streaming cancel scenario whose
// Observation distinguishes Canceled from OK (via assertCancelNotMaskedAtRecorder
// against that scenario's recorder) before the build can go green again. The
// dual-run's cancel gate cannot be silently vacuous.
func TestRecorderCancelMaskGuard_NoClientStreamingVerbYet(t *testing.T) {
	desc := hypervisorv1.HypervisorDriverService_ServiceDesc
	for _, sd := range desc.Streams {
		if sd.ClientStreams {
			t.Fatalf("%s grew a client-streaming verb %q: wire a client-streaming cancel scenario whose "+
				"Observation distinguishes codes.Canceled from a spurious OK (fold its terminal status through a "+
				"recorder and assert it via assertCancelNotMaskedAtRecorder), then update this guard — dual-run "+
				"agreement alone is vacuous for client-streaming cancel",
				desc.ServiceName, sd.StreamName)
		}
	}
}

// TestSeam_RealVsGeneratedFake is the per-commit gate for the orchestrator <->
// host-agent HypervisorDriver seam (doc 15 §11, doc 06 §2.1): the seam's
// conformance suite runs against BOTH the real reference implementation AND the
// generated programmable fake, and the seam is green only if every scenario
// observes the same thing on both. The capable suite exercises every one of the
// ten verbs' success paths (including the capability-gated Migrate /
// ExportDiskDelta) plus idempotency, restart re-adoption, and the
// observed-state report shape.
func TestSeam_RealVsGeneratedFake(t *testing.T) {
	res, err := hypervisor.Suite().Run(context.Background(), hypervisor.RealDialer(), hypervisor.FakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("orchestrator<->hypervisor seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_CapabilityHonesty_RealVsFake is the second dual-run: the EC2-style
// INCAPABLE driver (all three D35 flags false). It proves the capability-flag
// honesty property (D32/D35) end-to-end — a driver advertising
// supports_migrate / supports_disk_delta_export = false REFUSES the gated verb
// (FailedPrecondition) rather than no-op-claiming success — and that the
// generated fake refuses identically.
func TestSeam_CapabilityHonesty_RealVsFake(t *testing.T) {
	res, err := hypervisor.CapabilityHonestySuite().Run(context.Background(), hypervisor.IncapableRealDialer(), hypervisor.IncapableFakeDialer())
	if err != nil {
		t.Fatalf("dual-run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("capability-honesty seam DIVERGED:\n%s", res.Report())
	}
	if res.Ran == 0 {
		t.Fatal("dual-run ran zero honesty scenarios — the suite is empty")
	}
	t.Logf("%s", res.Report())
}

// TestSeam_HarnessCatchesADriftedFake is the negative proof: a fake that drifts
// from the contract (here, a Destroy that errors NotFound on the idempotent
// retry instead of succeeding — the doc 15 §4.2/§5.1 idempotency violation) must
// fail the seam. Without this, a green dual-run would be meaningless — it could
// be passing because the gate never fires. The drift is injected only in this
// test's local fake, never in the committed generated fake.
func TestSeam_HarnessCatchesADriftedFake(t *testing.T) {
	res, err := hypervisor.Suite().Run(context.Background(), hypervisor.RealDialer(), driftedDestroyFakeDialer())
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
// capture accessors (doc 15 §5.1). Re-issuing CloneFromImage / Snapshot /
// Destroy with the same session_uuid is observably a no-op on the RESULT (same
// binding / same ref / success), AND the fake records EVERY call — so the test
// proves the recorder sees both issues while the contract collapses them to one
// effect. This is the assertion the dual-run alone cannot make: the dual-run
// compares end-observable outcomes; the recorded-call surface is what lets a
// downstream consumer verify "the driver was asked twice and answered the same".
func TestIdempotency_RecordedViaFakeAccessors(t *testing.T) {
	ctx := context.Background()
	f := hypervisorv1fake.NewHypervisorDriverServiceFake()

	// Program just enough honest behavior to observe idempotency: a stable
	// binding per session and a stable snapshot ref, a no-op idempotent Destroy.
	bindings := map[string]*hypervisorv1.CloneFromImageResponse{}
	f.CloneFromImageResponder = func(_ context.Context, req *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error) {
		uuid := req.GetSpec().GetSessionUuid()
		if b, ok := bindings[uuid]; ok {
			return b, nil // idempotent re-issue -> same binding
		}
		b := &hypervisorv1.CloneFromImageResponse{
			HostSessionIndex: uint64(len(bindings) + 1),
			TapName:          "dstap-synthetic",
			OverlayPath:      "/var/lib/dream-serpent/overlays/" + uuid + ".qcow2",
		}
		bindings[uuid] = b
		return b, nil
	}
	f.SnapshotResponder = func(_ context.Context, req *hypervisorv1.SnapshotRequest) (*hypervisorv1.SnapshotResponse, error) {
		return &hypervisorv1.SnapshotResponse{SnapshotRef: "snap-" + req.GetSessionUuid()}, nil
	}
	f.DestroyResponder = func(_ context.Context, _ *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
		return &hypervisorv1.DestroyResponse{}, nil // idempotent: always succeeds
	}

	const uuid = "ses-synthetic-idempotency-0000-4000-8000-000000000001"
	cloneReq := &hypervisorv1.CloneFromImageRequest{Spec: &hypervisorv1.VmSpec{SessionUuid: uuid}}

	first, err := f.CloneFromImage(ctx, cloneReq)
	if err != nil {
		t.Fatalf("first CloneFromImage: %v", err)
	}
	second, err := f.CloneFromImage(ctx, cloneReq)
	if err != nil {
		t.Fatalf("second CloneFromImage: %v", err)
	}
	if first.GetHostSessionIndex() != second.GetHostSessionIndex() || first.GetTapName() != second.GetTapName() {
		t.Fatalf("CloneFromImage not idempotent on session_uuid: %v vs %v", first, second)
	}

	// The recorder must have captured BOTH issues, each carrying the same uuid.
	cloneCalls := f.CloneFromImageRecorded()
	if len(cloneCalls) != 2 {
		t.Fatalf("CloneFromImageRecorded: want 2 captured calls, got %d", len(cloneCalls))
	}
	for i, c := range cloneCalls {
		if got := c.Req.GetSpec().GetSessionUuid(); got != uuid {
			t.Fatalf("CloneFromImageRecorded[%d].session_uuid = %q, want %q", i, got, uuid)
		}
	}

	// Snapshot: re-issue returns the same ref; the recorder captures both.
	snapReq := &hypervisorv1.SnapshotRequest{SessionUuid: uuid}
	s1, _ := f.Snapshot(ctx, snapReq)
	s2, _ := f.Snapshot(ctx, snapReq)
	if s1.GetSnapshotRef() != s2.GetSnapshotRef() {
		t.Fatalf("Snapshot not idempotent: %q vs %q", s1.GetSnapshotRef(), s2.GetSnapshotRef())
	}
	if n := len(f.SnapshotRecorded()); n != 2 {
		t.Fatalf("SnapshotRecorded: want 2, got %d", n)
	}

	// Destroy: the idempotent retry succeeds; the recorder captures both.
	destroyReq := &hypervisorv1.DestroyRequest{SessionUuid: uuid}
	if _, err := f.Destroy(ctx, destroyReq); err != nil {
		t.Fatalf("first Destroy: %v", err)
	}
	if _, err := f.Destroy(ctx, destroyReq); err != nil {
		t.Fatalf("idempotent Destroy retry must succeed, got: %v", err)
	}
	if n := len(f.DestroyRecorded()); n != 2 {
		t.Fatalf("DestroyRecorded: want 2, got %d", n)
	}
}

// driftedDestroyFakeDialer programs the generated fake with a deliberately wrong
// Destroy responder (errors NotFound on the second call, breaking the §4.2/§5.1
// idempotent-teardown contract) to prove the gate bites. All other verbs are
// programmed honestly so the divergence is attributable to the injected drift.
func driftedDestroyFakeDialer() dualrun.Dialer {
	f := hypervisorv1fake.NewHypervisorDriverServiceFake()
	mirror := hypervisor.NewRefImpl(true, true, true)
	mirror.SeedSession("ses-aaaaaaaa-0000-4000-8000-aaaaaaaaaaaa", 101, hypervisor.ReadyState())
	mirror.SeedSession("ses-bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb", 102, hypervisor.SuspendedState())

	f.GetCapabilitiesResponder = mirror.GetCapabilities
	f.CloneFromImageResponder = mirror.CloneFromImage
	f.IssueAttachHandleResponder = mirror.IssueAttachHandle
	f.SnapshotResponder = mirror.Snapshot
	f.SuspendResponder = mirror.Suspend
	f.ResumeResponder = mirror.Resume
	f.MigrateResponder = mirror.Migrate
	f.RecoverSessionsResponder = mirror.RecoverSessions
	f.ExportDiskDeltaResponder = func(_ context.Context, req *hypervisorv1.ExportDiskDeltaRequest) ([]*hypervisorv1.ExportDiskDeltaResponse, error) {
		return hypervisor.DeltaFramesFor(req.GetSessionUuid()), nil
	}

	var destroyCount int
	f.DestroyResponder = func(_ context.Context, _ *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
		destroyCount++
		if destroyCount > 1 {
			// DRIFT: an idempotent Destroy retry must succeed, not error.
			return nil, status.Error(codes.NotFound, "no such session")
		}
		return &hypervisorv1.DestroyResponse{}, nil
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hypervisorv1fake.RegisterHypervisorDriverService(s, f)
	})
}

// --- shared back-pressure driver delegation guard (seam-local) ----------------
//
// This seam's ExportDiskDelta lifecycle end (streaming.go) does NOT hand-roll the
// server-side producer loop: it builds a dualrun.BackPressurePlan and drives it
// through the SHARED dualrun.RunBackPressureStream, threading only this seam's
// ExportDiskDelta frame builder. That delegation is the whole point of the fixture
// consolidation — the producer LOGIC (ctx-check / Send / park) lives ONCE in
// dualrun, so a back-pressure-semantics edit lands in one place instead of being
// re-forked per seam. The cross-seam half of this invariant is pinned centrally in
// dualrun/streaming_test.go (TestStreamingSeamsDelegateToSharedDriver); this is the
// seam-LOCAL trip-wire, so a developer editing only this package and running
// `go test ./seams/hypervisor/` still gets a failure the instant the producer loop
// is re-inlined back into ExportDiskDelta.
//
// It is a SOURCE-level structural assertion (the established go/ast idiom in this
// tree), hermetic (D50): it parses this seam's own streaming.go bytes — located
// relative to this test file at runtime — and opens no stream.
func TestExportDiskDeltaDelegatesToSharedBackPressureDriver(t *testing.T) {
	const (
		method            = "ExportDiskDelta"
		recvType          = "deltaStreamServer"
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
		t.Fatalf("%s.%s in %s does NOT delegate to %s.%s — the shared back-pressure producer loop appears re-inlined into the ExportDiskDelta end, re-forking the streaming-lifecycle semantics the fixture single-sources; restore the delegation or update this guard deliberately",
			recvType, method, srcPath, sharedDriverPkg, sharedDriverFunc)
	}
}
