// SPDX-License-Identifier: Apache-2.0

package dualrun_test

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// This self-test proves the shared server-streaming affordance in streaming.go
// against a SYNTHETIC server-streaming service (D50: synthetic fixtures only).
// The synthetic service "synth.StreamFrames" is a hand-built grpc.ServiceDesc — a
// server-streaming RPC carrying an opaque synthetic frame (boundaryv1.PolicySnapshot,
// used purely as a (seq)-bearing wire message; no real policy semantics) — wired
// over the existing in-process bufconn Dialer. It is NOT a seam: it imports no
// seam package and depends only on grpc + proto/gen/go, exactly like the harness
// itself. Two responders drive it:
//
//   - the HONEST responder stops sending the instant the client context is
//     cancelled (back-pressure: it paces frames behind a per-frame gate the
//     client releases, so framing is deterministic, and it surfaces the
//     contracted Canceled terminal status); and
//   - the DRIFTED responder keeps sending after cancel (ignoring ctx.Done) — the
//     contract violation the affordance must catch.
//
// Dual-running the cancellation scenario HONEST-vs-HONEST is green; HONEST-vs-DRIFTED
// DIVERGES — that divergence is the bite, proving the affordance hardens the
// streaming seam exactly as doc 06 §2.1 hardens the unary one.

// --- synthetic server-streaming service (hand-built, no .proto) --------------

const synthStreamMethod = "/dreamserpent.dualrun.synth.v1.StreamSynth/StreamFrames"

// synthFrame is the opaque synthetic stream frame: a proto message carrying a
// monotonic seq. boundaryv1.PolicySnapshot is reused only as a convenient
// seq-bearing proto wire type — no policy meaning is implied (D50).
type synthFrame = boundaryv1.PolicySnapshot

// synthResponder drives the server side of one StreamFrames RPC. It receives the
// stream (whose Context() observes client cancellation) and returns the terminal
// error (nil => clean OK/io.EOF on the client).
type synthResponder func(stream grpc.ServerStreamingServer[synthFrame]) error

// synthServer registers one StreamFrames responder behind a hand-built
// ServiceDesc, so the affordance opens a real gRPC server-streaming RPC against
// it over the existing bufconn Dialer.
type synthServer struct {
	respond synthResponder
}

func (s *synthServer) register(sr grpc.ServiceRegistrar) {
	sr.RegisterService(&grpc.ServiceDesc{
		ServiceName: "dreamserpent.dualrun.synth.v1.StreamSynth",
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{
			{
				StreamName: "StreamFrames",
				Handler: func(_ any, stream grpc.ServerStream) error {
					// Server-streaming: a single (ignored synthetic) request, then
					// the responder owns the response stream.
					req := new(synthFrame)
					if err := stream.RecvMsg(req); err != nil {
						return err
					}
					return s.respond(&grpc.GenericServerStream[synthFrame, synthFrame]{ServerStream: stream})
				},
				ServerStreams: true,
			},
		},
		Metadata: "dreamserpent/dualrun/synth/v1/synth.proto", // synthetic; no such file exists (D50)
	}, &struct{}{})
}

// synthDialer stands the synthetic server up behind the existing in-process
// bufconn Dialer with the given responder.
func synthDialer(respond synthResponder) dualrun.Dialer {
	srv := &synthServer{respond: respond}
	return dualrun.InProcess(srv.register)
}

// openSynth is the StreamOpener for the synthetic RPC: it opens the
// server-streaming call against the dialed conn, threading the affordance's
// cancellable ctx into NewStream so a cancel/deadline propagates to the server.
func openSynth(ctx context.Context, conn *grpc.ClientConn) (grpc.ServerStreamingClient[synthFrame], error) {
	desc := &grpc.StreamDesc{StreamName: "StreamFrames", ServerStreams: true}
	cs, err := conn.NewStream(ctx, desc, synthStreamMethod)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[synthFrame, synthFrame]{ClientStream: cs}
	// Server-streaming: one request, then close the send side.
	if err := x.SendMsg(&synthFrame{Seq: 0}); err != nil {
		return nil, err
	}
	if err := x.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

func seqOf(f *synthFrame) uint64 { return f.GetSeq() }

// framePayloadBytes sizes the synthetic frame's opaque Document so that a modest
// number of frames exceeds the HTTP/2 stream flow-control window (default ~64 KiB)
// AND the in-process pipe buffer — that is what forces a faithful producer to
// BLOCK on Send (back-pressure) under a stalled consumer rather than racing the
// whole stream ahead. 16 KiB per frame: five frames already overflow the window.
const framePayloadBytes = 16 * 1024

// synthFrameAt builds the synthetic frame for a given seq, carrying a fixed-size
// opaque payload (the Document) so frames are large enough to trigger
// flow-control back-pressure. The payload content is irrelevant (synthetic, D50).
func synthFrameAt(seq uint64) *synthFrame {
	return &synthFrame{Seq: seq, Document: make([]byte, framePayloadBytes)}
}

// --- honest and drifted responders -------------------------------------------

// honestResponder sends seqs 1..total, one at a time, and STOPS the instant the
// client context is cancelled. It is deterministic under back-pressure: it sends
// each frame then blocks until either the client releases the next via the gate
// or the client cancels — so the affordance's "read k, then cancel" sees exactly
// k frames and zero after. A nil gate means "send as fast as the transport
// allows" (used by the slow-consumer scenario, which relies on the bounded pipe
// for back-pressure rather than the gate).
func honestResponder(total int) synthResponder {
	return func(stream grpc.ServerStreamingServer[synthFrame]) error {
		ctx := stream.Context()
		for i := 1; i <= total; i++ {
			if ctx.Err() != nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			if err := stream.Send(&synthFrame{Seq: uint64(i)}); err != nil {
				return err
			}
		}
		return nil
	}
}

// gatedHonestResponder is honestResponder with explicit per-frame pacing: it
// sends a frame, then blocks on the gate channel (or ctx.Done) before the next.
// The client releases exactly the frames it wants, making the post-cancel frame
// count deterministically zero on the honest end — no transport buffering race.
func gatedHonestResponder(total int, gate <-chan struct{}) synthResponder {
	return func(stream grpc.ServerStreamingServer[synthFrame]) error {
		ctx := stream.Context()
		for i := 1; i <= total; i++ {
			if err := stream.Send(&synthFrame{Seq: uint64(i)}); err != nil {
				return err
			}
			if i == total {
				return nil
			}
			select {
			case <-ctx.Done():
				return status.FromContextError(ctx.Err()).Err()
			case _, ok := <-gate:
				if !ok {
					// Gate closed: caller is done pulling; wait for cancel.
					<-ctx.Done()
					return status.FromContextError(ctx.Err()).Err()
				}
			}
		}
		return nil
	}
}

// boundedHonestResponder sends exactly k frames, then idles waiting for the
// client to either cancel or disconnect — modeling a drained catch-up tail (e.g.
// a WatchPolicies replay that has delivered every pending row and is now parked
// awaiting the next event). It is deterministic with NO transport race: the
// server never has a (k+1)th frame to race ahead with, so after the client reads
// k and cancels it observes exactly zero further frames and the Canceled terminal
// status. This is the ungated honest end used to drive the shared
// CancelAfterFrames scenario through the real dual-run Suite.Run.
func boundedHonestResponder(k int) synthResponder {
	return func(stream grpc.ServerStreamingServer[synthFrame]) error {
		ctx := stream.Context()
		for i := 1; i <= k; i++ {
			if ctx.Err() != nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			if err := stream.Send(&synthFrame{Seq: uint64(i)}); err != nil {
				return err
			}
		}
		// Drained: park until the consumer walks away (cancel/deadline).
		<-ctx.Done()
		return status.FromContextError(ctx.Err()).Err()
	}
}

// driftedResponder is the contract VIOLATION: it ignores ctx cancellation and
// keeps sending frames forever (well past the cancel point). The affordance must
// catch this — either it delivers frames after cancel (frames_after_cancel > 0)
// or it never surfaces the Canceled terminal status, and the dual-run against an
// honest end DIVERGES. Send eventually errors once the cancelled transport tears
// down; the responder returns that error then.
func driftedResponder() synthResponder {
	return func(stream grpc.ServerStreamingServer[synthFrame]) error {
		for i := 1; ; i++ {
			if err := stream.Send(&synthFrame{Seq: uint64(i)}); err != nil {
				return err
			}
		}
	}
}

// --- cancellation: the bite ---------------------------------------------------

// gatedCancelAfterFrames is CancelAfterFrames adapted to release the honest
// gate as it reads, so the gated honest responder paces deterministically. It is
// a thin scenario specialised to the self-test's synthetic, gated service; the
// production affordance (CancelAfterFrames) drives ungated real seams whose
// back-pressure comes from the transport, not a test gate.
func gatedCancelAfterFrames(name string, k int, gate chan<- struct{}) dualrun.Scenario {
	return dualrun.Scenario{
		Name: name,
		Run: func(parent context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			stream, err := openSynth(ctx, conn)
			if err != nil {
				obs := dualrun.NewObservation()
				obs.Set("terminal_status", status.Code(err).String())
				return obs, nil
			}
			obs := dualrun.NewObservation()
			before := 0
			for before < k {
				if _, rerr := stream.Recv(); rerr != nil {
					obs.Setf("frames_before_cancel", "%d", before)
					obs.Set("terminal_status", status.Code(rerr).String())
					return obs, nil
				}
				before++
				if before < k {
					// Release the next frame. Non-blocking: a drifted responder
					// that ignores the gate must not deadlock the reader (its
					// gate is irrelevant — it floods regardless).
					select {
					case gate <- struct{}{}:
					default:
					}
				}
			}
			obs.Setf("frames_before_cancel", "%d", before)
			cancel()
			after := 0
			var term string
			for {
				_, rerr := stream.Recv()
				if rerr == nil {
					after++
					if after >= 1<<16 {
						term = "flooded"
						break
					}
					continue
				}
				if rerr == io.EOF {
					term = codes.OK.String()
				} else {
					term = status.Code(rerr).String()
				}
				break
			}
			obs.Setf("frames_after_cancel", "%d", after)
			obs.Set("terminal_status", term)
			return obs, nil
		},
	}
}

func TestStreaming_CancelMidStream_HonestVsHonest_IsGreen(t *testing.T) {
	const k = 3
	// Two independent gates: each dialer's responder gets its own (the suite
	// runs the scenario against each end with a fresh stream, but the gate is
	// shared per dialer instance — give each end enough capacity to be safe).
	realGate := make(chan struct{}, k)
	fakeGate := make(chan struct{}, k)

	real := synthDialer(gatedHonestResponder(k+5, realGate))
	fake := synthDialer(gatedHonestResponder(k+5, fakeGate))

	// The scenario must pull from the right gate per end. Run two passes with a
	// per-end scenario, comparing via the affordance's Suite.Run is awkward when
	// the gate differs per dialer; instead assert each end independently produces
	// the contracted observation, then that they're equal.
	realObs := runScenario(t, real, gatedCancelAfterFrames("cancel-after-3", k, realGate))
	fakeObs := runScenario(t, fake, gatedCancelAfterFrames("cancel-after-3", k, fakeGate))

	if realObs != fakeObs {
		t.Fatalf("honest ends must agree on cancellation:\n real: %s\n fake: %s", realObs, fakeObs)
	}
	// The contracted observation: k frames before cancel, ZERO after, Canceled.
	wantSub := "frames_after_cancel=0"
	if !contains(realObs, wantSub) {
		t.Fatalf("honest end must deliver zero frames after cancel; got: %s", realObs)
	}
	if !contains(realObs, "terminal_status=Canceled") {
		t.Fatalf("honest end must surface Canceled terminal status; got: %s", realObs)
	}
	if !contains(realObs, "frames_before_cancel=3") {
		t.Fatalf("honest end must deliver exactly k=3 frames before cancel; got: %s", realObs)
	}
}

func TestStreaming_CancelMidStream_DriftedKeepsSending_IsCaught(t *testing.T) {
	const k = 3
	gate := make(chan struct{}, k)
	honest := synthDialer(gatedHonestResponder(k+5, gate))
	drifted := synthDialer(driftedResponder())

	honestObs := runScenario(t, honest, gatedCancelAfterFrames("cancel-after-3", k, gate))
	// The drifted responder ignores the gate entirely and floods; its gate is a
	// throwaway (the scenario's gate-release is non-blocking, so it never wedges).
	driftedObs := runScenario(t, drifted, gatedCancelAfterFrames("cancel-after-3", k, make(chan struct{}, k)))

	if honestObs == driftedObs {
		t.Fatalf("affordance FAILED TO BITE: drifted responder produced the same observation as honest:\n%s", honestObs)
	}
	// Prove WHY they diverge: the drifted end either delivered post-cancel frames
	// or did not surface Canceled — both are the bite.
	if contains(driftedObs, "frames_after_cancel=0") && contains(driftedObs, "terminal_status=Canceled") {
		t.Fatalf("drifted observation looks honest — the bite is unsound:\n%s", driftedObs)
	}
	t.Logf("bite proven — honest: %q  drifted: %q", honestObs, driftedObs)
}

// TestStreaming_CancelMidStream_DualRunDivergence wires the bite through the
// REAL dual-run Suite.Run machinery (the way a seam consumes the affordance):
// honest-vs-drifted must report a Divergence (not green), and honest-vs-honest
// must be green — proving the affordance composes with the harness, not just the
// hand-rolled per-end comparison above. It uses ungated responders so a single
// shared Scenario (CancelAfterFrames) drives both ends identically.
func TestStreaming_CancelMidStream_DualRunDivergence(t *testing.T) {
	const k = 3
	sc := dualrun.CancelAfterFrames("cancel-after-3", k, openSynth)
	suite := dualrun.Suite{Seam: "dualrun-synth(streaming-cancel)", Scenarios: []dualrun.Scenario{sc}}

	// honest-vs-honest: green. The bounded honest responder delivers exactly k
	// frames then parks awaiting cancel, so it observes Canceled with zero
	// post-cancel frames deterministically (no transport race) — and BOTH ends do
	// so identically.
	honestA := synthDialer(boundedHonestResponder(k))
	honestB := synthDialer(boundedHonestResponder(k))
	res, err := suite.Run(context.Background(), honestA, honestB)
	if err != nil {
		t.Fatalf("Run honest-vs-honest: %v", err)
	}
	if !res.OK() {
		t.Fatalf("honest-vs-honest must be green:\n%s", res.Report())
	}

	// honest-vs-drifted: MUST diverge (the bite, through the harness).
	honest := synthDialer(boundedHonestResponder(k))
	drifted := synthDialer(driftedResponder())
	res, err = suite.Run(context.Background(), honest, drifted)
	if err != nil {
		t.Fatalf("Run honest-vs-drifted: %v", err)
	}
	if res.OK() {
		t.Fatalf("honest-vs-drifted MUST diverge (drifted keeps sending after cancel); got green:\n%s", res.Report())
	}
}

// --- deadline sibling ---------------------------------------------------------

func TestStreaming_DeadlineAfterFrames_HonestVsDrifted_IsCaught(t *testing.T) {
	const k = 2
	sc := dualrun.DeadlineAfterFrames("deadline-after-2", k, openSynth)
	suite := dualrun.Suite{Seam: "dualrun-synth(streaming-deadline)", Scenarios: []dualrun.Scenario{sc}}

	honest := synthDialer(boundedHonestResponder(k))
	drifted := synthDialer(driftedResponder())
	res, err := suite.Run(context.Background(), honest, drifted)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK() {
		t.Fatalf("deadline affordance must catch a responder that ignores cancellation; got green:\n%s", res.Report())
	}
}

// --- back-pressure / no-unbounded-buffering -----------------------------------

// countingHonestResponder is honestResponder that records how many frames it has
// actually Sent. Under a slow consumer on a bounded in-process pipe, a faithful
// producer BLOCKS on Send (back-pressure) rather than racing ahead — so at the
// moment the slow consumer begins reading, the producer has NOT already pushed
// the whole stream. We assert the observable consequence: every frame still
// arrives, in order, exactly once, and the stream completes.
func countingHonestResponder(total int, sent *int32) synthResponder {
	return func(stream grpc.ServerStreamingServer[synthFrame]) error {
		ctx := stream.Context()
		for i := 1; i <= total; i++ {
			if ctx.Err() != nil {
				return status.FromContextError(ctx.Err()).Err()
			}
			// Large frames so the flow-control window stalls the producer under a
			// slow consumer — that stall is the back-pressure we assert.
			if err := stream.Send(synthFrameAt(uint64(i))); err != nil {
				return err
			}
			atomic.AddInt32(sent, 1)
		}
		return nil
	}
}

func TestStreaming_SlowConsumer_BackPressure_DeliversInOrderComplete(t *testing.T) {
	const total = 25
	sc := dualrun.SlowConsumer("slow-consumer", total, 25*time.Millisecond, openSynth, seqOf)
	suite := dualrun.Suite{Seam: "dualrun-synth(back-pressure)", Scenarios: []dualrun.Scenario{sc}}

	real := synthDialer(honestResponder(total))
	fake := synthDialer(honestResponder(total))
	res, err := suite.Run(context.Background(), real, fake)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("slow-consumer back-pressure scenario must be green real-vs-fake:\n%s", res.Report())
	}
	// Independently assert the contracted observation on one honest end: all
	// frames delivered, in order, complete.
	obs := runScenario(t, real, sc)
	for _, want := range []string{
		"frames_total=25",
		"frames_total_matches_expected=true",
		"drained_in_order=true",
		"completed=true",
		"terminal_status=OK",
	} {
		if !contains(obs, want) {
			t.Fatalf("back-pressure observation missing %q:\n%s", want, obs)
		}
	}
}

// TestStreaming_SlowConsumer_AppliesBackPressure asserts the producer does NOT
// race the whole stream ahead while the consumer stalls: with a bounded in-process
// pipe and a producer that Sends synchronously, the count Sent before the slow
// consumer starts reading is strictly less than the total (the producer is parked
// in Send applying back-pressure). This is the no-unbounded-buffering bite: a
// producer that buffered everything ahead would show sent == total during the stall.
func TestStreaming_SlowConsumer_AppliesBackPressure(t *testing.T) {
	const total = 200 // larger than any reasonable in-flight window for tiny frames
	var sent int32
	respond := countingHonestResponder(total, &sent)
	dialer := synthDialer(respond)

	// Open the stream, then stall WITHOUT reading and sample how many frames the
	// producer managed to Send. A back-pressured producer is blocked well before total.
	conn, stop, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := openSynth(ctx, conn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Stall: do not Recv. Give the producer ample wall-clock time to race ahead
	// if it were going to.
	time.Sleep(40 * time.Millisecond)
	parked := atomic.LoadInt32(&sent)
	if int(parked) >= total {
		t.Fatalf("producer raced the whole stream ahead under a stalled consumer "+
			"(sent=%d >= total=%d) — no back-pressure; unbounded buffering", parked, total)
	}

	// Now drain the rest in order, exactly once, to completion — back-pressure
	// stalls the producer, it does not drop or reorder.
	var have, prev uint64
	inOrder := true
	for {
		f, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		if have > 0 && f.GetSeq() != prev+1 {
			inOrder = false
		}
		prev = f.GetSeq()
		have++
	}
	if have != total {
		t.Fatalf("slow consumer must still receive every frame: got %d, want %d", have, total)
	}
	if !inOrder {
		t.Fatal("back-pressure must not reorder frames")
	}
}

// --- existing landed tests stay green: smoke that the affordance package still
// compiles and the synthetic service round-trips a trivial drain ---------------

func TestStreaming_SyntheticService_RoundTrips(t *testing.T) {
	const total = 4
	dialer := synthDialer(honestResponder(total))
	conn, stop, err := dialer.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer stop()
	stream, err := openSynth(context.Background(), conn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	var n uint64
	for {
		f, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("recv: %v", rerr)
		}
		n++
		if f.GetSeq() != n {
			t.Fatalf("frame %d out of order: seq=%d", n, f.GetSeq())
		}
	}
	if n != total {
		t.Fatalf("round-trip delivered %d frames, want %d", n, total)
	}
}

// --- helpers ------------------------------------------------------------------

// runScenario runs one scenario against a single dialer and returns its canonical
// Observation string, failing the test on a harness-level error.
func runScenario(t *testing.T, d dualrun.Dialer, sc dualrun.Scenario) string {
	t.Helper()
	conn, stop, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer stop()
	obs, err := sc.Run(context.Background(), conn)
	if err != nil {
		t.Fatalf("scenario %q: %v", sc.Name, err)
	}
	if obs == nil {
		t.Fatalf("scenario %q returned nil observation", sc.Name)
	}
	return obs.Canonical()
}

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

// --- streaming-seam delegation self-test --------------------------------------
//
// RunBackPressureStream (streaming.go) single-sources the server-side producer
// loop EVERY server-streaming seam shares: build a BackPressurePlan, then drive it
// through the one driver, threading a seam-local frame builder. The whole point of
// that consolidation is that a seam's gRPC method shrinks to "call the driver" —
// no per-seam producer loop to drift. Nothing structural keeps a future author from
// re-copying the loop body back INTO a seam's method (re-introducing the
// ctx-check / Send / park scaffolding the fixture exists to own), which would
// silently re-fork the back-pressure semantics this affordance hardens.
//
// This guard is the trip-wire: it source-parses the two server-streaming seams that
// consume the fixture (orchestrator-session WatchSession, hypervisor ExportDiskDelta)
// and asserts each seam's streaming method body DELEGATES to
// dualrun.RunBackPressureStream rather than hand-rolling the loop. It is a
// SOURCE-level structural assertion (the established idiom in this tree, cf. the
// identity-validate seam's go/ast guards), so it imports no seam package — it reads
// only the seams' own bytes, located relative to this test file at runtime, and
// stays hermetic (D50): no gRPC, no live stream, just the AST.
//
// It bites the instant a streaming seam's method stops calling the shared driver
// (e.g. an inlined `for _, i := range plan.Order { ... stream.Send ... }`), forcing
// the author to either keep the delegation or, if the fixture genuinely no longer
// fits, update this guard deliberately — the producer loop cannot silently re-fork.

// streamingSeamDelegation names one server-streaming seam's lifecycle method and
// the path (relative to this test file's dir) of the source file that must contain
// it. recvType is the method's receiver type (star-unwrapped) so the lookup is
// unambiguous when a file declares the same method name on several types.
type streamingSeamDelegation struct {
	label    string // human label for diagnostics
	relPath  string // seam streaming.go, relative to this test file's directory
	method   string // the server-streaming RPC method that must delegate
	recvType string // the method's receiver type name (star-unwrapped)
}

// sharedStreamDriver is the qualified call every streaming seam's method must make
// instead of hand-rolling the producer loop: dualrun.RunBackPressureStream.
const (
	sharedStreamDriverPkg  = "dualrun"
	sharedStreamDriverFunc = "RunBackPressureStream"
)

// assertMethodDelegatesToSharedDriver source-parses one seam's streaming.go and
// asserts its lifecycle method body contains a direct call to
// dualrun.RunBackPressureStream. Any structural failure (cannot locate the file,
// parse error, missing/ambiguous method, or a method that does NOT delegate) is a
// t.Fatalf — the consolidation has regressed and the producer loop may have
// re-forked.
func assertMethodDelegatesToSharedDriver(t *testing.T, baseDir string, d streamingSeamDelegation) {
	t.Helper()

	srcPath := filepath.Join(baseDir, d.relPath)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("%s: parsing %s for the streaming-delegation guard: %v", d.label, srcPath, err)
		return
	}

	var methodDecl *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, isFn := decl.(*ast.FuncDecl)
		if !isFn || fn.Recv == nil || fn.Name.Name != d.method || len(fn.Recv.List) != 1 {
			continue
		}
		rt := fn.Recv.List[0].Type
		if star, isStar := rt.(*ast.StarExpr); isStar {
			rt = star.X
		}
		id, isID := rt.(*ast.Ident)
		if !isID || id.Name != d.recvType {
			continue
		}
		if methodDecl != nil {
			t.Fatalf("%s: found more than one %s.%s in %s — the streaming-delegation guard's method lookup is ambiguous", d.label, d.recvType, d.method, srcPath)
			return
		}
		methodDecl = fn
	}
	if methodDecl == nil {
		t.Fatalf("%s: could not locate %s.%s in %s — the streaming seam is no longer where the delegation guard expects it (or its receiver/name changed); confirm the method still delegates to %s.%s and update this guard",
			d.label, d.recvType, d.method, srcPath, sharedStreamDriverPkg, sharedStreamDriverFunc)
		return
	}

	delegates := false
	ast.Inspect(methodDecl.Body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != sharedStreamDriverFunc {
			return true
		}
		pkg, isID := sel.X.(*ast.Ident)
		if isID && pkg.Name == sharedStreamDriverPkg {
			delegates = true
			return false
		}
		return true
	})
	if !delegates {
		t.Fatalf("%s: %s.%s in %s does NOT delegate to %s.%s — the shared back-pressure producer loop appears to have been re-inlined into the seam method, re-forking the streaming-lifecycle semantics %s.%s exists to single-source; restore the delegation or, if the fixture genuinely no longer fits, update this guard deliberately",
			d.label, d.recvType, d.method, srcPath, sharedStreamDriverPkg, sharedStreamDriverFunc, sharedStreamDriverPkg, sharedStreamDriverFunc)
	}
}

// TestStreamingSeamsDelegateToSharedDriver asserts that BOTH server-streaming seams
// consuming the shared fixture delegate their producer loop to
// dualrun.RunBackPressureStream rather than hand-rolling it. This is the standing
// guard against a future author re-copying the back-pressure producer loop this
// affordance consolidated: if either seam's lifecycle method stops calling the
// shared driver, the guard fails and names the offending seam. Source-level and
// hermetic (D50): it parses the seams' own bytes located relative to this test file,
// importing no seam package and opening no stream.
func TestStreamingSeamsDelegateToSharedDriver(t *testing.T) {
	// Locate THIS test file at runtime so the seam paths resolve independently of
	// the working directory (the scan reads only on-disk source bytes).
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) could not locate this test's source file — the streaming-delegation guard cannot run")
	}
	baseDir := filepath.Dir(thisFile) // .../assurance/contract-harness/dualrun

	seams := []streamingSeamDelegation{
		{
			label:    "orchestrator-session/WatchSession",
			relPath:  filepath.Join("..", "seams", "orchestrator-session", "streaming.go"),
			method:   "WatchSession",
			recvType: "watchStreamSession",
		},
		{
			label:    "hypervisor/ExportDiskDelta",
			relPath:  filepath.Join("..", "seams", "hypervisor", "streaming.go"),
			method:   "ExportDiskDelta",
			recvType: "deltaStreamServer",
		},
	}
	for _, d := range seams {
		assertMethodDelegatesToSharedDriver(t, baseDir, d)
	}
}
