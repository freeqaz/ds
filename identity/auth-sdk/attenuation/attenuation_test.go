// SPDX-License-Identifier: Apache-2.0
package attenuation_test

import (
	"testing"

	"github.com/dream-serpent/dream-serpent/identity/auth-sdk/attenuation"
)

// synthNow is the synthetic "current time" used throughout the tests (Unix
// seconds, fixed so tests are deterministic).
const synthNow = int64(1_700_000_000)

// parentExp is the synthetic parent JWT exp: synthNow + 900 (15-minute TTL).
const parentExp = synthNow + 900

// parentJTI is the synthetic parent JWT jti.
const parentJTI = "test-parent-jti-001"

// parentScopes is the full scope set carried by the synthetic parent JWT.
var parentScopes = []string{"read:repos", "write:repos", "read:issues"}

// TestNewAttenuator verifies that a fresh Attenuator can be constructed and
// returns a non-nil instance with a non-empty public key.
func TestNewAttenuator(t *testing.T) {
	a, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator() error = %v", err)
	}
	if a == nil {
		t.Fatal("NewAttenuator() returned nil attenuator")
	}
	pub := a.PublicKeyDER()
	if len(pub) == 0 {
		t.Fatal("PublicKeyDER() returned empty key")
	}
}

// TestDeriveAgentToken_ValidSubsetScopes verifies the happy path: a derive
// request with scopes ⊆ parentScopes and a valid lifetime succeeds, and the
// returned bytes are non-empty.
func TestDeriveAgentToken_ValidSubsetScopes(t *testing.T) {
	a, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator: %v", err)
	}
	req := attenuation.DeriveRequest{
		HostSessionIndex: 0,
		RequestedScopes:  []string{"read:repos"},
		LifetimeSeconds:  300,
		DerivedJTI:       "derived-001",
	}
	tokenBytes, claims, err := a.DeriveAgentToken(parentJTI, parentScopes, parentExp, req, synthNow)
	if err != nil {
		t.Fatalf("DeriveAgentToken() unexpected error: %v", err)
	}
	if len(tokenBytes) == 0 {
		t.Fatal("DeriveAgentToken() returned empty token bytes")
	}
	if claims.ParentJTI != parentJTI {
		t.Errorf("claims.ParentJTI = %q, want %q", claims.ParentJTI, parentJTI)
	}
	if claims.DerivedJTI != req.DerivedJTI {
		t.Errorf("claims.DerivedJTI = %q, want %q", claims.DerivedJTI, req.DerivedJTI)
	}
	if claims.HostSessionIndex != req.HostSessionIndex {
		t.Errorf("claims.HostSessionIndex = %d, want %d", claims.HostSessionIndex, req.HostSessionIndex)
	}
	wantExp := synthNow + int64(req.LifetimeSeconds)
	if claims.ExpiresAt != wantExp {
		t.Errorf("claims.ExpiresAt = %d, want %d", claims.ExpiresAt, wantExp)
	}
}

// TestDeriveAgentToken_ScopeWidening verifies that a DeriveRequest whose
// RequestedScopes are not a subset of parentScopes is rejected with
// ErrScopeWidening.
func TestDeriveAgentToken_ScopeWidening(t *testing.T) {
	a, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator: %v", err)
	}
	req := attenuation.DeriveRequest{
		HostSessionIndex: 1,
		RequestedScopes:  []string{"read:repos", "admin:org"}, // admin:org not in parentScopes
		LifetimeSeconds:  300,
		DerivedJTI:       "derived-scope-widen",
	}
	_, _, err = a.DeriveAgentToken(parentJTI, parentScopes, parentExp, req, synthNow)
	if err != attenuation.ErrScopeWidening {
		t.Fatalf("DeriveAgentToken() error = %v, want ErrScopeWidening", err)
	}
}

// TestDeriveAgentToken_LifetimeWidening verifies that a DeriveRequest whose
// derived expiry (nowUnix + LifetimeSeconds) exceeds parentExp is rejected
// with ErrLifetimeWidening.
func TestDeriveAgentToken_LifetimeWidening(t *testing.T) {
	a, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator: %v", err)
	}
	req := attenuation.DeriveRequest{
		HostSessionIndex: 2,
		RequestedScopes:  []string{"read:repos"},
		LifetimeSeconds:  1000, // synthNow + 1000 > parentExp (synthNow + 900)
		DerivedJTI:       "derived-ttl-widen",
	}
	_, _, err = a.DeriveAgentToken(parentJTI, parentScopes, parentExp, req, synthNow)
	if err != attenuation.ErrLifetimeWidening {
		t.Fatalf("DeriveAgentToken() error = %v, want ErrLifetimeWidening", err)
	}
}

// TestVerifyAgentToken_RoundTrip verifies that VerifyAgentToken(DeriveAgentToken(...))
// returns the exact AgentClaims that were encoded into the token.
func TestVerifyAgentToken_RoundTrip(t *testing.T) {
	a, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator: %v", err)
	}
	req := attenuation.DeriveRequest{
		HostSessionIndex: 3,
		RequestedScopes:  []string{"read:repos", "read:issues"},
		LifetimeSeconds:  600,
		DerivedJTI:       "derived-roundtrip",
	}
	tokenBytes, wantClaims, err := a.DeriveAgentToken(parentJTI, parentScopes, parentExp, req, synthNow)
	if err != nil {
		t.Fatalf("DeriveAgentToken: %v", err)
	}

	gotClaims, err := a.VerifyAgentToken(tokenBytes)
	if err != nil {
		t.Fatalf("VerifyAgentToken: %v", err)
	}

	if gotClaims.ParentJTI != wantClaims.ParentJTI {
		t.Errorf("ParentJTI: got %q, want %q", gotClaims.ParentJTI, wantClaims.ParentJTI)
	}
	if gotClaims.DerivedJTI != wantClaims.DerivedJTI {
		t.Errorf("DerivedJTI: got %q, want %q", gotClaims.DerivedJTI, wantClaims.DerivedJTI)
	}
	if gotClaims.HostSessionIndex != wantClaims.HostSessionIndex {
		t.Errorf("HostSessionIndex: got %d, want %d", gotClaims.HostSessionIndex, wantClaims.HostSessionIndex)
	}
	if gotClaims.ExpiresAt != wantClaims.ExpiresAt {
		t.Errorf("ExpiresAt: got %d, want %d", gotClaims.ExpiresAt, wantClaims.ExpiresAt)
	}
	if len(gotClaims.Scopes) != len(wantClaims.Scopes) {
		t.Errorf("Scopes length: got %d, want %d", len(gotClaims.Scopes), len(wantClaims.Scopes))
	} else {
		for i, s := range wantClaims.Scopes {
			if gotClaims.Scopes[i] != s {
				t.Errorf("Scopes[%d]: got %q, want %q", i, gotClaims.Scopes[i], s)
			}
		}
	}
}

// TestVerifyAgentToken_WrongKey verifies that a token verified against a
// DIFFERENT Attenuator (different signing key) is rejected — the third-context
// isolation property (D99).
func TestVerifyAgentToken_WrongKey(t *testing.T) {
	signer, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator (signer): %v", err)
	}
	verifier, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator (verifier): %v", err)
	}

	req := attenuation.DeriveRequest{
		HostSessionIndex: 0,
		RequestedScopes:  []string{"read:repos"},
		LifetimeSeconds:  300,
		DerivedJTI:       "derived-wrongkey",
	}
	tokenBytes, _, err := signer.DeriveAgentToken(parentJTI, parentScopes, parentExp, req, synthNow)
	if err != nil {
		t.Fatalf("DeriveAgentToken: %v", err)
	}
	// The verifier holds a DIFFERENT public key — the chain check must fail.
	_, err = verifier.VerifyAgentToken(tokenBytes)
	if err == nil {
		t.Fatal("VerifyAgentToken() with wrong key returned nil error, want error")
	}
}

// TestLineageStore verifies Record, ListByParent, and CascadeRevoke interact
// correctly.
func TestLineageStore(t *testing.T) {
	store := attenuation.NewLineageStore()

	// Record two sub-tokens under the same parent.
	rec1 := attenuation.DerivedRecord{
		DerivedJTI:       "derived-A",
		ParentJTI:        parentJTI,
		HostSessionIndex: 0,
		Scopes:           []string{"read:repos"},
		IssuedAt:         synthNow,
		ExpiresAt:        synthNow + 300,
		Revoked:          false,
	}
	rec2 := attenuation.DerivedRecord{
		DerivedJTI:       "derived-B",
		ParentJTI:        parentJTI,
		HostSessionIndex: 1,
		Scopes:           []string{"read:issues"},
		IssuedAt:         synthNow,
		ExpiresAt:        synthNow + 600,
		Revoked:          false,
	}
	store.Record(rec1)
	store.Record(rec2)

	// Record a third sub-token under a DIFFERENT parent (must not appear in
	// ListByParent for parentJTI).
	rec3 := attenuation.DerivedRecord{
		DerivedJTI:       "derived-C",
		ParentJTI:        "other-parent-jti",
		HostSessionIndex: 0,
		Scopes:           []string{"write:repos"},
		IssuedAt:         synthNow,
		ExpiresAt:        synthNow + 900,
		Revoked:          false,
	}
	store.Record(rec3)

	// ListByParent with includeRevoked=true — should return rec1 and rec2.
	all := store.ListByParent(parentJTI, true)
	if len(all) != 2 {
		t.Fatalf("ListByParent(includeRevoked=true): got %d records, want 2", len(all))
	}

	// CascadeRevoke — should revoke both rec1 and rec2.
	n := store.CascadeRevoke(parentJTI)
	if n != 2 {
		t.Errorf("CascadeRevoke returned %d, want 2", n)
	}

	// ListByParent with includeRevoked=false — should now return 0 records.
	live := store.ListByParent(parentJTI, false)
	if len(live) != 0 {
		t.Errorf("ListByParent(includeRevoked=false) after revoke: got %d, want 0", len(live))
	}

	// ListByParent with includeRevoked=true — should still return 2 records
	// (the revoked ones).
	withRevoked := store.ListByParent(parentJTI, true)
	if len(withRevoked) != 2 {
		t.Errorf("ListByParent(includeRevoked=true) after revoke: got %d, want 2", len(withRevoked))
	}
	for _, r := range withRevoked {
		if !r.Revoked {
			t.Errorf("record %q not marked revoked after CascadeRevoke", r.DerivedJTI)
		}
	}

	// CascadeRevoke is idempotent — a second call on the same parent returns 0.
	n2 := store.CascadeRevoke(parentJTI)
	if n2 != 0 {
		t.Errorf("second CascadeRevoke returned %d, want 0", n2)
	}

	// rec3 under "other-parent-jti" must be unaffected.
	otherLive := store.ListByParent("other-parent-jti", false)
	if len(otherLive) != 1 {
		t.Errorf("other parent ListByParent: got %d, want 1", len(otherLive))
	}
}

// --- §5/§6 acceptance scenarios (D126) -------------------------------------
//
// The scopes below use the doc 23 §6 standard taxonomy (versioned at v1:) so the
// acceptance scenario reads exactly as specified: a parent holding code:read +
// code:write derives a child narrowed to code:read only. These are referenced as
// literal strings (not the token-package constants) to keep the attenuation
// package's test surface self-contained — the attenuation library is substrate,
// agnostic to the scope namespace it narrows.
const (
	scopeCodeRead  = "v1:code:read"
	scopeCodeWrite = "v1:code:write"
	scopeNetEgress = "v1:network:egress"
)

// TestDeriveAgentToken_ScopeNarrowing_CodeReadWrite proves the headline §5 rule
// (D126 rule 1): a parent granting code:read + code:write derives a child token
// scoped to code:read only. The narrowed scope set must round-trip through the
// minted Biscuit, and a request to KEEP code:write would also succeed (subset),
// while a request to ADD a scope the parent never held is rejected.
func TestDeriveAgentToken_ScopeNarrowing_CodeReadWrite(t *testing.T) {
	a, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator: %v", err)
	}
	parent := []string{scopeCodeRead, scopeCodeWrite}

	// Narrow code:read + code:write -> code:read only.
	req := attenuation.DeriveRequest{
		HostSessionIndex: 7,
		RequestedScopes:  []string{scopeCodeRead},
		LifetimeSeconds:  300,
		DerivedJTI:       "narrow-code-read",
	}
	tokenBytes, claims, err := a.DeriveAgentToken(parentJTI, parent, parentExp, req, synthNow)
	if err != nil {
		t.Fatalf("DeriveAgentToken (narrow): %v", err)
	}
	if len(claims.Scopes) != 1 || claims.Scopes[0] != scopeCodeRead {
		t.Fatalf("narrowed scopes = %v, want exactly [%q]", claims.Scopes, scopeCodeRead)
	}
	// aud (host_session_index) is set to the agent VM index (§5 rule 2).
	if claims.HostSessionIndex != 7 {
		t.Errorf("HostSessionIndex (aud) = %d, want 7", claims.HostSessionIndex)
	}
	// ds_parent_jti is set for lineage (§5 rule 4).
	if claims.ParentJTI != parentJTI {
		t.Errorf("ParentJTI (ds_parent_jti) = %q, want %q", claims.ParentJTI, parentJTI)
	}
	// The narrowed scope set round-trips through the minted Biscuit.
	got, err := a.VerifyAgentToken(tokenBytes)
	if err != nil {
		t.Fatalf("VerifyAgentToken: %v", err)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != scopeCodeRead {
		t.Errorf("verified scopes = %v, want exactly [%q]", got.Scopes, scopeCodeRead)
	}

	// Requesting a scope the parent never held (network:egress) is rejected —
	// narrowing is monotonic, never additive (§5 rule 1).
	widen := attenuation.DeriveRequest{
		HostSessionIndex: 8,
		RequestedScopes:  []string{scopeCodeRead, scopeNetEgress},
		LifetimeSeconds:  300,
		DerivedJTI:       "widen-net-egress",
	}
	if _, _, err := a.DeriveAgentToken(parentJTI, parent, parentExp, widen, synthNow); err != attenuation.ErrScopeWidening {
		t.Fatalf("DeriveAgentToken (widen) error = %v, want ErrScopeWidening", err)
	}
}

// TestDeriveAgentToken_NonExtendableExp proves §5 rule 3 (D126): a child's exp
// can equal the parent's but never exceed it. A lifetime landing exactly on the
// parent exp is accepted; one second past is rejected with ErrLifetimeWidening.
func TestDeriveAgentToken_NonExtendableExp(t *testing.T) {
	a, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator: %v", err)
	}
	parent := []string{scopeCodeRead}
	remaining := parentExp - synthNow // exact remaining lifetime of the parent

	// Lifetime == remaining -> derived exp lands exactly on parent exp (allowed).
	atBoundary := attenuation.DeriveRequest{
		HostSessionIndex: 0,
		RequestedScopes:  []string{scopeCodeRead},
		LifetimeSeconds:  int32(remaining),
		DerivedJTI:       "exp-at-boundary",
	}
	_, claims, err := a.DeriveAgentToken(parentJTI, parent, parentExp, atBoundary, synthNow)
	if err != nil {
		t.Fatalf("DeriveAgentToken (at boundary): %v", err)
	}
	if claims.ExpiresAt != parentExp {
		t.Errorf("ExpiresAt = %d, want parentExp %d (exp may equal parent)", claims.ExpiresAt, parentExp)
	}

	// Lifetime == remaining + 1 -> derived exp would exceed parent exp (rejected).
	overBoundary := attenuation.DeriveRequest{
		HostSessionIndex: 0,
		RequestedScopes:  []string{scopeCodeRead},
		LifetimeSeconds:  int32(remaining) + 1,
		DerivedJTI:       "exp-over-boundary",
	}
	if _, _, err := a.DeriveAgentToken(parentJTI, parent, parentExp, overBoundary, synthNow); err != attenuation.ErrLifetimeWidening {
		t.Fatalf("DeriveAgentToken (over boundary) error = %v, want ErrLifetimeWidening", err)
	}
}

// TestRevocationCascade_ViaParentJTILineage proves the §5 rule 4 / §8 cascade
// end-to-end (D126): derived sub-tokens carry ds_parent_jti, the lineage store is
// keyed by it, ListDerivedTokens surfaces only the live ones, and revoking the
// PARENT cascades to every child derived under that parent — while a sibling
// token derived under a different parent jti is untouched.
func TestRevocationCascade_ViaParentJTILineage(t *testing.T) {
	a, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator: %v", err)
	}
	store := attenuation.NewLineageStore()
	parent := []string{scopeCodeRead, scopeCodeWrite}

	// Derive three agent sub-tokens under the same parent jti (a D18 fan-out of
	// three VMs) and record each in the lineage store keyed by ds_parent_jti.
	derive := func(idx int32, jti string, scopes []string) {
		_, claims, err := a.DeriveAgentToken(parentJTI, parent, parentExp,
			attenuation.DeriveRequest{
				HostSessionIndex: idx,
				RequestedScopes:  scopes,
				LifetimeSeconds:  300,
				DerivedJTI:       jti,
			}, synthNow)
		if err != nil {
			t.Fatalf("DeriveAgentToken(%s): %v", jti, err)
		}
		// The lineage key IS the parent jti carried on the claim (ds_parent_jti).
		if claims.ParentJTI != parentJTI {
			t.Fatalf("derived %s ParentJTI = %q, want %q", jti, claims.ParentJTI, parentJTI)
		}
		store.Record(attenuation.DerivedRecord{
			DerivedJTI:       claims.DerivedJTI,
			ParentJTI:        claims.ParentJTI,
			HostSessionIndex: claims.HostSessionIndex,
			Scopes:           claims.Scopes,
			IssuedAt:         synthNow,
			ExpiresAt:        claims.ExpiresAt,
		})
	}
	derive(0, "child-0", []string{scopeCodeRead})
	derive(1, "child-1", []string{scopeCodeRead, scopeCodeWrite})
	derive(2, "child-2", []string{scopeCodeRead})

	// A sibling token under a DIFFERENT parent jti — must survive the cascade.
	_, sib, err := a.DeriveAgentToken("other-parent", parent, parentExp,
		attenuation.DeriveRequest{
			HostSessionIndex: 0,
			RequestedScopes:  []string{scopeCodeRead},
			LifetimeSeconds:  300,
			DerivedJTI:       "sibling-other-parent",
		}, synthNow)
	if err != nil {
		t.Fatalf("DeriveAgentToken(sibling): %v", err)
	}
	store.Record(attenuation.DerivedRecord{
		DerivedJTI:       sib.DerivedJTI,
		ParentJTI:        sib.ParentJTI,
		HostSessionIndex: sib.HostSessionIndex,
		Scopes:           sib.Scopes,
		IssuedAt:         synthNow,
		ExpiresAt:        sib.ExpiresAt,
	})

	// ListDerivedTokens (the named §9.2 surface) reports all three live children.
	live := store.ListDerivedTokens(parentJTI)
	if len(live) != 3 {
		t.Fatalf("ListDerivedTokens(parent) before revoke = %d, want 3", len(live))
	}

	// Revoke the PARENT — cascades to all three children.
	if n := store.CascadeRevoke(parentJTI); n != 3 {
		t.Fatalf("CascadeRevoke(parent) = %d, want 3", n)
	}

	// All children are now gone from the live view.
	if live := store.ListDerivedTokens(parentJTI); len(live) != 0 {
		t.Errorf("ListDerivedTokens(parent) after cascade = %d, want 0", len(live))
	}

	// The sibling under a different parent jti is untouched.
	if sibLive := store.ListDerivedTokens("other-parent"); len(sibLive) != 1 {
		t.Errorf("ListDerivedTokens(other-parent) after cascade = %d, want 1 (sibling untouched)", len(sibLive))
	}
}

// TestListDerivedTokens_ExcludesRevoked confirms the named ListDerivedTokens
// surface returns only live records — a point-revoked child drops out while its
// still-live siblings remain.
func TestListDerivedTokens_ExcludesRevoked(t *testing.T) {
	store := attenuation.NewLineageStore()
	for _, jti := range []string{"d-1", "d-2", "d-3"} {
		store.Record(attenuation.DerivedRecord{
			DerivedJTI: jti,
			ParentJTI:  parentJTI,
			IssuedAt:   synthNow,
			ExpiresAt:  synthNow + 300,
		})
	}
	if got := store.ListDerivedTokens(parentJTI); len(got) != 3 {
		t.Fatalf("ListDerivedTokens before revoke = %d, want 3", len(got))
	}
	if !store.Revoke("d-2") {
		t.Fatal("Revoke(d-2) = false, want true")
	}
	got := store.ListDerivedTokens(parentJTI)
	if len(got) != 2 {
		t.Fatalf("ListDerivedTokens after point-revoke = %d, want 2", len(got))
	}
	for _, r := range got {
		if r.DerivedJTI == "d-2" {
			t.Errorf("ListDerivedTokens returned revoked record %q", r.DerivedJTI)
		}
	}
}

// TestLineageStore_ZeroLifetime verifies that DeriveAgentToken with
// LifetimeSeconds=0 uses the parent expiry exactly.
func TestDeriveAgentToken_ZeroLifetime(t *testing.T) {
	a, err := attenuation.NewAttenuator()
	if err != nil {
		t.Fatalf("NewAttenuator: %v", err)
	}
	req := attenuation.DeriveRequest{
		HostSessionIndex: 0,
		RequestedScopes:  []string{"read:repos"},
		LifetimeSeconds:  0, // zero → inherit parent exp
		DerivedJTI:       "derived-zero-lifetime",
	}
	_, claims, err := a.DeriveAgentToken(parentJTI, parentScopes, parentExp, req, synthNow)
	if err != nil {
		t.Fatalf("DeriveAgentToken: %v", err)
	}
	if claims.ExpiresAt != parentExp {
		t.Errorf("ExpiresAt = %d, want parentExp %d", claims.ExpiresAt, parentExp)
	}
}
