// SPDX-License-Identifier: Apache-2.0

// Caller-side D127 wiring (doc 23 §6): the operation→required-scope table and
// NewScopedValidateRequest that populate ValidateRequest.desired_scopes on the
// live path. server.go threads req.GetDesiredScopes() into ValidateScoped, but
// until this table nothing mapped a requested operation onto it — so Go-side
// scope enforcement was inert outside hand-built test requests. These tests pin
// the mapping AND drive a live-shaped Validate call (over the in-process grpc
// wire) carrying non-nil desired_scopes for a mapped operation, asserting the
// seam enforces the scope predicate on exactly that populated request.
// Everything synthetic (D50).
package mint

import (
	"context"
	"testing"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// TestScopesForOperation_MapsAndCopies pins the operation→scope table (doc 23
// §6): a mapped operation returns its required scope(s) NON-NIL, an unmapped or
// empty operation returns nil (scope-unqualified semantics), and the returned
// slice is a copy the caller cannot use to mutate the package table.
func TestScopesForOperation_MapsAndCopies(t *testing.T) {
	cases := []struct {
		op   Operation
		want string // single required scope for each mapped operation
	}{
		{OpEgressConnect, "v1:network:egress"},
		{OpWorkspaceWrite, "v1:code:write"},
		{OpWorkspaceRead, "v1:code:read"},
		{OpSecretsFetch, "v1:secrets:read"},
		{OpSubtokenMint, "v1:identity:mint"},
		{OpNotifyReceive, "v1:notify:receive"},
		{OpPolicyRead, "v1:policy:read"},
		{OpAuditWrite, "v1:audit:write"},
	}
	for _, tc := range cases {
		got := ScopesForOperation(tc.op)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("ScopesForOperation(%q) = %v, want [%q]", tc.op, got, tc.want)
		}
	}

	// Unmapped / empty → nil (no scope asserted).
	if got := ScopesForOperation(Operation("does:not:exist")); got != nil {
		t.Fatalf("ScopesForOperation(unmapped) = %v, want nil", got)
	}
	if got := ScopesForOperation(""); got != nil {
		t.Fatalf("ScopesForOperation(empty) = %v, want nil", got)
	}

	// The returned slice is a copy: mutating it must not corrupt the table.
	got := ScopesForOperation(OpEgressConnect)
	got[0] = "tampered"
	if again := ScopesForOperation(OpEgressConnect); again[0] != "v1:network:egress" {
		t.Fatalf("table mutated through returned slice: %v", again)
	}
}

// TestNewScopedValidateRequest_PopulatesDesiredScopes proves the request builder
// carries non-nil desired_scopes for a mapped operation while leaving the other
// D22 fields intact, and yields empty desired_scopes for an unmapped operation.
func TestNewScopedValidateRequest_PopulatesDesiredScopes(t *testing.T) {
	req := NewScopedValidateRequest(OpEgressConnect, []byte("cred"), testSession, testSvc)
	if got := req.GetDesiredScopes(); len(got) != 1 || got[0] != "v1:network:egress" {
		t.Fatalf("desired_scopes = %v, want [v1:network:egress]", got)
	}
	if req.GetSessionRef().GetSessionUuid() != testSession {
		t.Fatalf("session_uuid = %q, want %q", req.GetSessionRef().GetSessionUuid(), testSession)
	}
	if req.GetServiceId() != testSvc {
		t.Fatalf("service_id = %q, want %q", req.GetServiceId(), testSvc)
	}
	if string(req.GetPresentedCredential()) != "cred" {
		t.Fatalf("presented_credential = %q, want %q", req.GetPresentedCredential(), "cred")
	}

	// Unmapped operation → empty desired_scopes (frozen scope-unqualified path).
	if got := NewScopedValidateRequest(Operation("nope"), nil, testSession, testSvc).GetDesiredScopes(); len(got) != 0 {
		t.Fatalf("unmapped desired_scopes = %v, want empty", got)
	}
}

// TestScopedValidateRequest_LiveSeamEnforces drives the caller-built request
// through the REAL server adapter over the in-process grpc wire (dialInProcess).
// The request carries non-nil desired_scopes for a mapped operation
// (OpEgressConnect → v1:network:egress). A token that HOLDS the scope → ALLOW; a
// token that LACKS it → in-band DENY(scope_insufficient) — proving the populated
// desired_scopes actually reach and drive the seam predicate, not just a struct
// field. This is the live-shaped-call acceptance for the caller wiring.
func TestScopedValidateRequest_LiveSeamEnforces(t *testing.T) {
	shim := newTestShim(t)
	// Token holds v1:network:egress → an egress-connect operation is covered.
	bundle := mintScopedBase(t, shim, []string{"v1:network:egress"})
	client, _ := dialInProcess(t, shim)

	req := NewScopedValidateRequest(OpEgressConnect, bundle.Token, testSession, testSvc)
	if len(req.GetDesiredScopes()) == 0 {
		t.Fatal("precondition: caller-built request must carry non-nil desired_scopes")
	}
	resp, err := client.Validate(context.Background(), req)
	if err != nil {
		t.Fatalf("Validate returned a transport error, not an in-band verdict: %v", err)
	}
	if resp.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("held-scope egress connect: verdict = %v, want ALLOW (reason=%q)",
			resp.GetVerdict(), resp.GetMachineReadableReason())
	}

	// A workspace-write operation demands v1:code:write, which this token LACKS →
	// scope_insufficient. Same live wire, same populated desired_scopes path.
	denyReq := NewScopedValidateRequest(OpWorkspaceWrite, bundle.Token, testSession, testSvc)
	denyResp, err := client.Validate(context.Background(), denyReq)
	if err != nil {
		t.Fatalf("Validate returned a transport error, not an in-band verdict: %v", err)
	}
	if denyResp.GetVerdict() == identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatal("unheld-scope workspace write: verdict = ALLOW, want DENY(scope_insufficient)")
	}
	if denyResp.GetMachineReadableReason() != ReasonScopeInsufficient {
		t.Fatalf("deny reason = %q, want %q", denyResp.GetMachineReadableReason(), ReasonScopeInsufficient)
	}
}
