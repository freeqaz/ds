// SPDX-License-Identifier: Apache-2.0
package controlplane

// sessionservice_posture_test.go pins the per-session posture ACTIVATION seam (doc 13 §2):
// CreateSession threads the orchestrator-resolved runtime.v1 PermissionPosture through
// sessions.CreateRequest.Posture into the §4.1 step-4 hypervisor.v1.VmSpec.posture the host
// driver's CloneFromImage carries into the gap-1 EntrypointConfig producer. It proves the
// activation end to end at the control-plane boundary: a CONCRETE posture (from the request's
// forwarded field OR from the injected POL-1 resolver) reaches the captured step-4 VmSpec and
// WINS over the request seed per resolver-wins; a no-posture create yields an UNSPECIFIED
// VmSpec posture that is byte-identical to the pre-change wire (the daemon-pinned LOCKED
// fallback the producer applies — M0 default-deny — is exercised downstream by the libvirt
// posture_thread_test's ProduceConfig arms). All synthetic; no live VM/host-agent (D50).
//
// The step-4 VmSpec is captured off the fake host driver's CloneFromImage: the coordinator's
// step-4 HostAllocator seam drives the placed host's CloneFromImage(CloneFromImageRequest{Spec})
// with the SAME VmSpec sessioncreate.go built, so the captured spec IS the step-4 spec (the
// sessions-side assertion that the step-4 VmSpec carries req.Posture, proven through the real
// create coordinator rather than a hand-rolled spec).

import (
	"context"
	"testing"

	"google.golang.org/protobuf/proto"

	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
	runtimev1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/runtime/v1"
)

// fakePostureResolver is a synthetic POL-1 resolver: it returns a fixed posture (the resolved
// role/env posture) for every create, recording the request it was consulted with. A resolve
// value of PERMISSION_POSTURE_UNSPECIFIED models "no opinion" (defer to the request seed).
type fakePostureResolver struct {
	resolve runtimev1.PermissionPosture
	calls   int
	lastReq *orchestratorv1.CreateSessionRequest
}

func (r *fakePostureResolver) ResolvePosture(_ context.Context, req *orchestratorv1.CreateSessionRequest) runtimev1.PermissionPosture {
	r.calls++
	r.lastReq = req
	return r.resolve
}

// captureStep4Spec wraps the fixture driver fake's CloneFromImageResponder so the §4.1 step-4
// VmSpec the create coordinator drives is captured for assertion, while still returning the
// binding the happy-path create needs (it delegates to the fixture's original responder). The
// returned pointer is populated once CreateSession has run.
func captureStep4Spec(f *fixture) **hypervisorv1.VmSpec {
	orig := f.drv.CloneFromImageResponder
	var captured *hypervisorv1.VmSpec
	f.drv.CloneFromImageResponder = func(ctx context.Context, req *hypervisorv1.CloneFromImageRequest) (*hypervisorv1.CloneFromImageResponse, error) {
		captured = req.GetSpec()
		return orig(ctx, req)
	}
	return &captured
}

// TestCreateSession_RequestPostureReachesStep4VmSpec proves the request-forwarded posture path:
// with NO resolver wired, a CreateSessionRequest carrying a concrete posture forwards THAT
// posture into the step-4 VmSpec (the orchestrator carries the externally-resolved value as
// DATA — runtime-ignorant).
func TestCreateSession_RequestPostureReachesStep4VmSpec(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	specp := captureStep4Spec(f)

	req := validCreateReq()
	req.Posture = runtimev1.PermissionPosture_PERMISSION_POSTURE_OPEN

	if _, err := f.cp.Sessions.CreateSession(context.Background(), req); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if *specp == nil {
		t.Fatal("step-4 VmSpec was never captured (CloneFromImage not reached)")
	}
	if got := (*specp).GetPosture(); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_OPEN {
		t.Errorf("step-4 VmSpec posture = %v, want OPEN (the request-forwarded posture reaches the VmSpec)", got)
	}
}

// TestCreateSession_ResolverPostureReachesStep4VmSpec is the headline activation: a wired POL-1
// resolver's concrete posture reaches the step-4 VmSpec, overriding the (absent) request seed —
// this is the value the gap-1 producer honors OVER the daemon-pinned LOCKED fallback (the
// resolver posture WINS over LOCKED end to end).
func TestCreateSession_ResolverPostureReachesStep4VmSpec(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	specp := captureStep4Spec(f)

	resolver := &fakePostureResolver{resolve: runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD}
	f.cp.Sessions.SetPostureResolver(resolver)

	if _, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq()); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver consulted %d times, want 1", resolver.calls)
	}
	if *specp == nil {
		t.Fatal("step-4 VmSpec was never captured")
	}
	if got := (*specp).GetPosture(); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD {
		t.Errorf("step-4 VmSpec posture = %v, want STANDARD (the resolved POL-1 posture reaches the VmSpec and WINS over the daemon-LOCKED fallback)", got)
	}
}

// TestCreateSession_ResolverWinsOverRequestSeed proves the resolver-wins precedence: when BOTH
// the request carries a posture AND a resolver yields a concrete (different) posture, the
// resolver's value is the one that reaches the VmSpec.
func TestCreateSession_ResolverWinsOverRequestSeed(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	specp := captureStep4Spec(f)

	f.cp.Sessions.SetPostureResolver(&fakePostureResolver{resolve: runtimev1.PermissionPosture_PERMISSION_POSTURE_OPEN})

	req := validCreateReq()
	req.Posture = runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD // the seed the resolver overrides

	if _, err := f.cp.Sessions.CreateSession(context.Background(), req); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if got := (*specp).GetPosture(); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_OPEN {
		t.Errorf("step-4 VmSpec posture = %v, want OPEN (a concrete resolver posture WINS over the request seed)", got)
	}
}

// TestCreateSession_ResolverUnspecifiedDefersToRequestSeed proves the "no opinion" arm: a
// resolver that yields UNSPECIFIED leaves the request-seeded posture intact (it does NOT clobber
// a concrete request posture down to UNSPECIFIED).
func TestCreateSession_ResolverUnspecifiedDefersToRequestSeed(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	specp := captureStep4Spec(f)

	f.cp.Sessions.SetPostureResolver(&fakePostureResolver{resolve: runtimev1.PermissionPosture_PERMISSION_POSTURE_UNSPECIFIED})

	req := validCreateReq()
	req.Posture = runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD

	if _, err := f.cp.Sessions.CreateSession(context.Background(), req); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if got := (*specp).GetPosture(); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_STANDARD {
		t.Errorf("step-4 VmSpec posture = %v, want STANDARD (an UNSPECIFIED resolver defers to the request seed)", got)
	}
}

// TestCreateSession_NoPostureUnspecifiedByteIdentical is the M0 default-deny / byte-identity
// guard: a create with NO resolver and NO request posture yields an UNSPECIFIED step-4 VmSpec
// posture — the frozen no-posture create path. UNSPECIFIED is the proto3 zero enum, so it
// contributes ZERO wire bytes (the posture field is absent on the marshaled VmSpec exactly as
// before the additive field existed); a concrete posture, by contrast, adds bytes. So the
// no-posture path is byte-identical to the pre-change wire, and the downstream producer applies
// the daemon-pinned LOCKED fallback (M0 default-deny) — exercised by the libvirt
// posture_thread_test.
func TestCreateSession_NoPostureUnspecifiedByteIdentical(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	specp := captureStep4Spec(f)

	// No resolver wired, validCreateReq carries no posture (the frozen request path).
	if _, err := f.cp.Sessions.CreateSession(context.Background(), validCreateReq()); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	spec := *specp
	if spec == nil {
		t.Fatal("step-4 VmSpec was never captured")
	}
	if got := spec.GetPosture(); got != runtimev1.PermissionPosture_PERMISSION_POSTURE_UNSPECIFIED {
		t.Fatalf("no-posture step-4 VmSpec posture = %v, want UNSPECIFIED (M0 default-deny: the no-posture create forwards no posture)", got)
	}

	// Byte-identity: the UNSPECIFIED posture adds no bytes to the VmSpec wire. Marshal the
	// captured spec, then a deep clone with a CONCRETE posture; the concrete one MUST be longer
	// (it carries field 6) and the bytes MUST differ — proving the no-posture spec is
	// byte-for-byte what the pre-additive-field VmSpec encoded.
	noPosture, err := proto.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal no-posture spec: %v", err)
	}
	clone := proto.Clone(spec).(*hypervisorv1.VmSpec)
	clone.Posture = runtimev1.PermissionPosture_PERMISSION_POSTURE_LOCKED
	withPosture, err := proto.Marshal(clone)
	if err != nil {
		t.Fatalf("marshal posture-bearing spec: %v", err)
	}
	if len(withPosture) <= len(noPosture) {
		t.Errorf("posture-bearing VmSpec (%d bytes) is not longer than the no-posture VmSpec (%d bytes): the UNSPECIFIED field must add zero bytes", len(withPosture), len(noPosture))
	}
	if string(noPosture) == string(withPosture) {
		t.Error("no-posture and posture-bearing VmSpec marshal identically: the additive posture field is not being encoded when set")
	}
}
