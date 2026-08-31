// SPDX-License-Identifier: Apache-2.0
package token

import "testing"

// TestScopesForOperation pins the operation→required-scope table (doc 23 §6):
// every mapped operation returns its D127 scope NON-NIL, an unmapped/empty
// operation returns nil (scope-unqualified semantics), and the returned slice is
// a copy that cannot mutate the package table.
func TestScopesForOperation(t *testing.T) {
	cases := []struct {
		op   Operation
		want string
	}{
		{OpWorkspaceRead, ScopeCodeRead},
		{OpWorkspaceWrite, ScopeCodeWrite},
		{OpSecretsFetch, ScopeSecretsRead},
		{OpEgressConnect, ScopeNetEgress},
		{OpSubtokenMint, ScopeIdentMint},
		{OpNotifyReceive, ScopeNotifyRecv},
		{OpPolicyRead, ScopePolicyRead},
		{OpAuditWrite, ScopeAuditWrite},
	}
	for _, tc := range cases {
		got := ScopesForOperation(tc.op)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("ScopesForOperation(%q) = %v, want [%q]", tc.op, got, tc.want)
		}
	}

	if got := ScopesForOperation(Operation("unmapped")); got != nil {
		t.Fatalf("ScopesForOperation(unmapped) = %v, want nil", got)
	}
	if got := ScopesForOperation(""); got != nil {
		t.Fatalf("ScopesForOperation(empty) = %v, want nil", got)
	}

	// Mutating the returned slice must not corrupt the table.
	got := ScopesForOperation(OpEgressConnect)
	got[0] = "tampered"
	if again := ScopesForOperation(OpEgressConnect); again[0] != ScopeNetEgress {
		t.Fatalf("table mutated through returned slice: %v", again)
	}
}

// TestOperationScopesCoverTaxonomy asserts the table maps onto only known D127
// scopes (every mapped scope is a member of AllScopes) — a typo'd scope string
// would be caught here rather than at a live Validate deny.
func TestOperationScopesCoverTaxonomy(t *testing.T) {
	known := make(map[string]bool, len(AllScopes))
	for _, s := range AllScopes {
		known[s] = true
	}
	for op, scopes := range OperationScopes {
		for _, s := range scopes {
			if !known[s] {
				t.Fatalf("operation %q maps to unknown scope %q (not in AllScopes)", op, s)
			}
		}
	}
}
