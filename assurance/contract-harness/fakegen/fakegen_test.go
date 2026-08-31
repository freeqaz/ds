// SPDX-License-Identifier: Apache-2.0

package fakegen_test

import (
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/assurance/contract-harness/fakegen"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	orchestratorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1"
)

// hostAgentInput is the generator input for the first-seam service.
func hostAgentInput() fakegen.Input {
	return fakegen.Input{
		ServiceDesc:     &hostagentv1.HostAgentService_ServiceDesc,
		StubImportPath:  "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1",
		StubPackageName: "hostagentv1",
		GoServiceName:   "HostAgentService",
	}
}

// TestBuildModel_ReadsContractFromCompiledStubs proves the model is derived from
// the compiled gRPC contract — the grpc.ServiceDesc + the protobuf descriptor —
// not from a hand-maintained list. The host agent seam's one RPC is the
// client-streaming ReportHeartbeat (doc 15 §5.2).
func TestBuildModel_ReadsContractFromCompiledStubs(t *testing.T) {
	model, err := fakegen.BuildModel(hostAgentInput())
	if err != nil {
		t.Fatalf("BuildModel: %v", err)
	}
	if model.ServiceName != "dreamserpent.hostagent.v1.HostAgentService" {
		t.Errorf("ServiceName = %q", model.ServiceName)
	}
	if model.FakePackageName != "hostagentv1fake" {
		t.Errorf("FakePackageName = %q", model.FakePackageName)
	}
	if len(model.Methods) != 1 {
		t.Fatalf("got %d methods, want 1 (ReportHeartbeat)", len(model.Methods))
	}
	m := model.Methods[0]
	if m.Name != "ReportHeartbeat" {
		t.Errorf("method name = %q", m.Name)
	}
	if m.Kind != fakegen.ClientStream {
		t.Errorf("ReportHeartbeat kind = %v, want client-stream", m.Kind)
	}
	if m.InputGoType != "ReportHeartbeatRequest" || m.OutputGoType != "ReportHeartbeatResponse" {
		t.Errorf("types = %q/%q", m.InputGoType, m.OutputGoType)
	}
	if !model.NeedsIO() {
		t.Error("client-stream service should report NeedsIO()")
	}
}

// TestBuildModel_UnaryServiceOmitsIO covers the hypervisor driver, which is
// all-unary plus one server-stream (RecoverSessions is unary; none stream the
// client), so the emitted fake must not import io.
func TestBuildModel_UnaryServiceOmitsIO(t *testing.T) {
	model, err := fakegen.BuildModel(fakegen.Input{
		ServiceDesc:     &hypervisorv1.HypervisorDriverService_ServiceDesc,
		StubImportPath:  "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1",
		StubPackageName: "hypervisorv1",
		GoServiceName:   "HypervisorDriverService",
	})
	if err != nil {
		t.Fatalf("BuildModel: %v", err)
	}
	if len(model.Methods) == 0 {
		t.Fatal("hypervisor driver has no methods")
	}
	if model.NeedsIO() {
		t.Error("hypervisor driver has no client-stream/bidi method; NeedsIO() should be false")
	}
	src, err := fakegen.Emit(model)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if strings.Contains(string(src), `"io"`) {
		t.Error("all-unary/server-stream fake must not import io (unused-import compile error)")
	}
}

// TestEmit_Deterministic proves the generator is byte-deterministic, the
// property the codegen-drift gate relies on (proto/FREEZE.md).
func TestEmit_Deterministic(t *testing.T) {
	in := hostAgentInput()
	a, err := fakegen.Generate(in)
	if err != nil {
		t.Fatalf("Generate #1: %v", err)
	}
	b, err := fakegen.Generate(in)
	if err != nil {
		t.Fatalf("Generate #2: %v", err)
	}
	if string(a) != string(b) {
		t.Error("Generate is not deterministic: two runs produced different output")
	}
}

// TestEmit_ProgrammableNotNullStub asserts the emitted fake is a behavior-
// specified stand-in (doc 06 §2.1): a settable responder and a recorded-call
// accessor, never a silent zero-value stub.
func TestEmit_ProgrammableNotNullStub(t *testing.T) {
	src, err := fakegen.Generate(hostAgentInput())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	s := string(src)
	for _, want := range []string{
		"DO NOT EDIT",                      // generated marker
		"type HostAgentServiceFake struct", // service-namespaced type
		"ReportHeartbeatResponder",         // canned-response programming
		"ReportHeartbeatRecorded()",        // recorded-call accessor
		"RegisterHostAgentService(",        // drop-in registration
		"responder not programmed",         // honest Unimplemented default, not zero value
	} {
		if !strings.Contains(s, want) {
			t.Errorf("emitted fake missing %q", want)
		}
	}
}

// TestBuildModel_MultiServicePackageNoCollision proves the two orchestrator.v1
// services (SessionService, PolicyService) generate into one package without
// name collisions, because every type/func is service-namespaced.
func TestBuildModel_MultiServicePackageNoCollision(t *testing.T) {
	session, err := fakegen.Generate(fakegen.Input{
		ServiceDesc:     &orchestratorv1.SessionService_ServiceDesc,
		StubImportPath:  "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1",
		StubPackageName: "orchestratorv1",
		GoServiceName:   "SessionService",
	})
	if err != nil {
		t.Fatalf("Generate SessionService: %v", err)
	}
	policy, err := fakegen.Generate(fakegen.Input{
		ServiceDesc:     &orchestratorv1.PolicyService_ServiceDesc,
		StubImportPath:  "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1",
		StubPackageName: "orchestratorv1",
		GoServiceName:   "PolicyService",
	})
	if err != nil {
		t.Fatalf("Generate PolicyService: %v", err)
	}
	if !strings.Contains(string(session), "type SessionServiceFake struct") {
		t.Error("session fake type not service-namespaced")
	}
	if !strings.Contains(string(policy), "type PolicyServiceFake struct") {
		t.Error("policy fake type not service-namespaced")
	}
	// Neither generic name may appear — that would collide in the shared package.
	for _, src := range [][]byte{session, policy} {
		if strings.Contains(string(src), "type Fake struct") {
			t.Error("emitted a non-namespaced `type Fake struct` — collides in a shared package")
		}
		if strings.Contains(string(src), "func New() ") {
			t.Error("emitted a non-namespaced `func New()` — collides in a shared package")
		}
	}
}

// TestBuildModel_NilDesc is a guard: the generator refuses to invent a contract.
func TestBuildModel_NilDesc(t *testing.T) {
	if _, err := fakegen.BuildModel(fakegen.Input{GoServiceName: "X"}); err == nil {
		t.Error("BuildModel with nil ServiceDesc should error")
	}
}
