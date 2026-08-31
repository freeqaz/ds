// SPDX-License-Identifier: Apache-2.0

package dualrun_test

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/dualrun"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1/hostagentv1fake"
)

// programmedFake stands up the generated host-agent fake with a responder that
// echoes the count of streamed beats — a minimal, deterministic contract behavior.
func programmedFake(beatsToBeatCount bool) dualrun.Dialer {
	f := hostagentv1fake.NewHostAgentServiceFake()
	f.ReportHeartbeatResponder = func(_ context.Context, reqs []*hostagentv1.ReportHeartbeatRequest) (*hostagentv1.ReportHeartbeatResponse, error) {
		n := uint64(len(reqs))
		if !beatsToBeatCount {
			// A "lying" variant: report a wrong count, to drive divergence.
			n = 999
		}
		return &hostagentv1.ReportHeartbeatResponse{BeatsReceived: n}, nil
	}
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hostagentv1fake.RegisterHostAgentService(s, f)
	})
}

// heartbeatSuite streams three beats and observes the reported count.
func heartbeatSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam: "orchestrator<->hostagent (dualrun self-test)",
		Scenarios: []dualrun.Scenario{
			{
				Name: "three-beats-then-close",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					cl := hostagentv1.NewHostAgentServiceClient(conn)
					stream, err := cl.ReportHeartbeat(ctx)
					if err != nil {
						return nil, err
					}
					for i := 0; i < 3; i++ {
						if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{
							Heartbeat: &hostagentv1.Heartbeat{HostId: "h1", AppliedSeq: uint64(i)},
						}); err != nil {
							return nil, err
						}
					}
					resp, err := stream.CloseAndRecv()
					obs := dualrun.NewObservation()
					if err != nil {
						obs.Set("status", status.Code(err).String())
						return obs, nil
					}
					obs.Set("status", codes.OK.String())
					obs.Setf("beats_received", "%d", resp.GetBeatsReceived())
					return obs, nil
				},
			},
		},
	}
}

func TestDualRun_AgreeIsGreen(t *testing.T) {
	res, err := heartbeatSuite().Run(context.Background(), programmedFake(true), programmedFake(true))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.OK() {
		t.Fatalf("expected green when both ends agree:\n%s", res.Report())
	}
	if res.Ran != 1 {
		t.Errorf("ran %d scenarios, want 1", res.Ran)
	}
}

func TestDualRun_DivergenceIsCaught(t *testing.T) {
	// One end reports the true beat count, the other lies — the harness must
	// catch it (this is the doc 06 §2.1 property: a lying fake or a drifted impl
	// fails the seam).
	res, err := heartbeatSuite().Run(context.Background(), programmedFake(true), programmedFake(false))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK() {
		t.Fatal("expected the harness to catch the divergence, got green")
	}
	if len(res.Divergences) != 1 {
		t.Fatalf("want exactly 1 divergence, got %d: %s", len(res.Divergences), res.Report())
	}
	if res.Divergences[0].Scenario != "three-beats-then-close" {
		t.Errorf("divergence on %q", res.Divergences[0].Scenario)
	}
}

func TestDualRun_UnprogrammedFakeIsHonestUnimplemented(t *testing.T) {
	// An unprogrammed fake must surface codes.Unimplemented, not a silent zero
	// value — so the dual-run against a real impl that DOES implement the method
	// diverges loudly rather than passing on a fiction.
	bare := dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hostagentv1fake.RegisterHostAgentService(s, hostagentv1fake.NewHostAgentServiceFake())
	})
	res, err := heartbeatSuite().Run(context.Background(), programmedFake(true), bare)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.OK() {
		t.Fatal("an unprogrammed fake vs a programmed impl must diverge")
	}
}

// --- Harness-level accessor edge-case pins (01KVS64C9Q) -----------------------
//
// The ObservationsFor / PerScenario accessors on *Result are exercised only
// indirectly by the seam suites (grantfetch_dualrun_test.go). The tests below
// pin their edge-case invariants directly at the harness level, independent of
// any one seam: nil-receiver safety, the unknown-scenario ok==false contract,
// the nil Observation on an errored end, and PerScenario copy-isolation. They
// are read-only against the accessors and never weaken the self-tests above.

// erroringHeartbeatSuite is a self-test suite whose single scenario surfaces a
// transport-level failure as a HARNESS-LEVEL error (it returns (nil, err) rather
// than recording the status into an Observation). Run against an end that does
// NOT service the method, this drives that end into Result.{Real,Fake}Errors
// with a nil Observation — exactly the errored-end shape the accessors must
// report honestly. No secret bytes are recorded (doc 16 §5.2); fixtures are
// synthetic (D50).
func erroringHeartbeatSuite() dualrun.Suite {
	return dualrun.Suite{
		Seam: "orchestrator<->hostagent (dualrun errored-end self-test)",
		Scenarios: []dualrun.Scenario{
			{
				Name: "beats-then-close-error-is-harness-level",
				Run: func(ctx context.Context, conn *grpc.ClientConn) (*dualrun.Observation, error) {
					cl := hostagentv1.NewHostAgentServiceClient(conn)
					stream, err := cl.ReportHeartbeat(ctx)
					if err != nil {
						return nil, err
					}
					if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{
						Heartbeat: &hostagentv1.Heartbeat{HostId: "h1", AppliedSeq: 0},
					}); err != nil {
						return nil, err
					}
					resp, err := stream.CloseAndRecv()
					if err != nil {
						// Treat the transport failure as a harness-level error so the
						// Observation on this end is nil and the error rides
						// Result.{Real,Fake}Errors.
						return nil, err
					}
					obs := dualrun.NewObservation()
					obs.Setf("beats_received", "%d", resp.GetBeatsReceived())
					return obs, nil
				},
			},
		},
	}
}

// bareFakeDialer dials an end that registers the host-agent fake with NO
// programmed responder, so ReportHeartbeat returns codes.Unimplemented.
func bareFakeDialer() dualrun.Dialer {
	return dualrun.InProcess(func(s grpc.ServiceRegistrar) {
		hostagentv1fake.RegisterHostAgentService(s, hostagentv1fake.NewHostAgentServiceFake())
	})
}

func TestResult_Accessors_NilReceiver(t *testing.T) {
	var r *dualrun.Result // nil receiver: must not panic.

	if got := r.PerScenario(); got != nil {
		t.Errorf("nil *Result PerScenario() = %v, want nil", got)
	}
	real, fake, ok := r.ObservationsFor("anything")
	if real != nil || fake != nil || ok {
		t.Errorf("nil *Result ObservationsFor() = (%v, %v, %v), want (nil, nil, false)", real, fake, ok)
	}
}

func TestResult_ObservationsFor_UnknownScenario(t *testing.T) {
	res, err := heartbeatSuite().Run(context.Background(), programmedFake(true), programmedFake(true))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Sanity: the run is green and the known scenario is present, so a miss below
	// is genuinely "not found" rather than an empty Result.
	if !res.OK() {
		t.Fatalf("expected green self-test run:\n%s", res.Report())
	}
	if _, _, ok := res.ObservationsFor("three-beats-then-close"); !ok {
		t.Fatal("known scenario must be found by ObservationsFor")
	}

	real, fake, ok := res.ObservationsFor("no-such-scenario")
	if ok {
		t.Error("ObservationsFor on an unknown scenario name must report ok==false")
	}
	if real != nil || fake != nil {
		t.Errorf("unknown scenario must yield nil Observations, got (%v, %v)", real, fake)
	}
}

func TestResult_ObservationsFor_ErroredEndIsNil(t *testing.T) {
	// Real end services the method; fake end is bare, so its scenario fails at the
	// harness level. The accessor must report the failed end's Observation as nil
	// while the surviving end is non-nil, and the failure must ride FakeErrors.
	res, err := erroringHeartbeatSuite().Run(context.Background(), programmedFake(true), bareFakeDialer())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	const scenario = "beats-then-close-error-is-harness-level"

	if len(res.FakeErrors) == 0 {
		t.Fatalf("expected the bare fake end to populate FakeErrors:\n%s", res.Report())
	}
	if _, ok := res.FakeErrors[scenario]; !ok {
		t.Errorf("FakeErrors missing the errored scenario %q: %v", scenario, res.FakeErrors)
	}
	if len(res.RealErrors) != 0 {
		t.Errorf("the programmed real end must not error: %v", res.RealErrors)
	}

	real, fake, ok := res.ObservationsFor(scenario)
	if !ok {
		t.Fatal("the scenario ran (against both ends) and must be found")
	}
	if fake != nil {
		t.Errorf("errored fake end must report a nil Observation, got %v", fake)
	}
	if real == nil {
		t.Error("the surviving real end must report a non-nil Observation")
	}

	// PerScenario must agree with ObservationsFor on the same nil/non-nil shape.
	per := res.PerScenario()
	if len(per) != 1 {
		t.Fatalf("PerScenario() len = %d, want 1", len(per))
	}
	if per[0].Scenario != scenario {
		t.Errorf("PerScenario()[0].Scenario = %q, want %q", per[0].Scenario, scenario)
	}
	if per[0].Fake != nil {
		t.Errorf("PerScenario errored fake end must be nil, got %v", per[0].Fake)
	}
	if per[0].Real == nil {
		t.Error("PerScenario surviving real end must be non-nil")
	}
}

func TestResult_PerScenario_CopyIsolation(t *testing.T) {
	res, err := heartbeatSuite().Run(context.Background(), programmedFake(true), programmedFake(true))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	first := res.PerScenario()
	if len(first) != 1 {
		t.Fatalf("PerScenario() len = %d, want 1", len(first))
	}
	origScenario := first[0].Scenario
	origRealCanonical := first[0].Real.Canonical()

	// Mutate the returned slice's header records: a different length via append on
	// a fresh re-read, and a clobbered element on this read. Neither must reach the
	// Result's bookkeeping.
	first[0].Scenario = "MUTATED"
	first[0].Real = nil
	first = append(first, dualrun.ScenarioObservation{Scenario: "INJECTED"})

	second := res.PerScenario()
	if len(second) != 1 {
		t.Errorf("PerScenario() must return a defensive copy; second read len = %d, want 1", len(second))
	}
	if second[0].Scenario != origScenario {
		t.Errorf("mutating the returned slice leaked into Result: Scenario = %q, want %q", second[0].Scenario, origScenario)
	}
	if second[0].Real == nil || second[0].Real.Canonical() != origRealCanonical {
		t.Error("mutating the returned slice's Real header leaked into Result bookkeeping")
	}

	// ObservationsFor reads the same untouched bookkeeping.
	real, _, ok := res.ObservationsFor(origScenario)
	if !ok {
		t.Fatalf("original scenario %q must still be present after slice mutation", origScenario)
	}
	if real == nil || real.Canonical() != origRealCanonical {
		t.Error("ObservationsFor must reflect untouched bookkeeping after caller slice mutation")
	}
}
