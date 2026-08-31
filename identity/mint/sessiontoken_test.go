// SPDX-License-Identifier: Apache-2.0

// MintSessionToken contract + isolation + park/resume tests (doc 19 §3/§5/§13).
//
// The doc 19 §13 negative property is proved as EXECUTABLE assertions, mirroring
// the §13 isolation-test pattern already in mint_test.go: a session-token
// signature validates as NEITHER workload identity NOR interception material
// (the D82 separation property extended to the third signing context, doc 19 §3).
// Park/resume/expiry-remint (doc 16 §5.4) are all covered. Everything synthetic
// (D50); the shim clock is pinned so freshness/liveness branches are
// deterministic; the claim-set golden is synthetic.
package mint

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"
)

const (
	testLaunchingUser = "idp|launching-subject"
	testRoleRef       = "role:reviewer"
	testTaskRef       = "task:01KTWJ74V8"
)

// baseTokenReq is the synthetic base-token request mirroring the doc 16 §3.1
// claim inputs (D50 — no real subject/key material).
func baseTokenReq() MintSessionTokenReq {
	return MintSessionTokenReq{
		SessionUUID:   testSession,
		LaunchingUser: testLaunchingUser,
		Org:           testOrg,
		RepoBranch:    "acme/app@main",
		RoleRef:       testRoleRef,
		TaskRef:       testTaskRef,
		Services:      []string{"github", "npm"},
	}
}

// TestMintSessionToken_ClaimSetGolden pins the doc 19 §3 claim set on the base
// token (a SYNTHETIC golden, D50): the claims mirror the doc 16 §3.1
// workload-identity set, parent_session is EMPTY on the base token, and the TTL =
// session lifetime. It decodes the claims back through the substrate seam (the
// public-key verify path) and asserts the full record.
func TestMintSessionToken_ClaimSetGolden(t *testing.T) {
	shim := newTestShim(t)
	bundle, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.AttenuationDepth != 0 {
		t.Fatalf("base token depth = %d, want 0", bundle.AttenuationDepth)
	}
	if len(bundle.RevocationIDs) != 1 {
		t.Fatalf("base token revocation IDs = %d, want 1 (one block)", len(bundle.RevocationIDs))
	}
	wantExpiry := shim.now().Add(defaultSessionTTL)
	if !bundle.Expiry.Equal(wantExpiry) {
		t.Fatalf("expiry = %v, want session-lifetime %v", bundle.Expiry, wantExpiry)
	}

	claims, depth, err := shim.tokenSigner.Verify(bundle.Token)
	if err != nil {
		t.Fatalf("substrate verify: %v", err)
	}
	if depth != 0 {
		t.Fatalf("decoded depth = %d, want 0", depth)
	}
	// The SYNTHETIC claim-set golden (D50), mirroring the doc 16 §3.1 set.
	want := SessionTokenClaims{
		LaunchingUser: testLaunchingUser,
		SessionUUID:   testSession,
		Org:           testOrg,
		RepoBranch:    "acme/app@main",
		RoleRef:       testRoleRef,
		TaskRef:       testTaskRef,
		ParentSession: "", // EMPTY on the base token (doc 19 §3)
		Services:      []string{"github", "npm"},
		Expiry:        wantExpiry,
	}
	gotJSON, _ := json.Marshal(claims)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("claim-set golden mismatch:\n got=%s\nwant=%s", gotJSON, wantJSON)
	}
}

// TestMintSessionToken_PrincipalResolverSeam proves the launching_user resolution
// seam applies on the token path exactly as on MintWorkloadIdentity (doc 04 §5),
// so the two credentials carry the SAME root attribution and join in audit.
func TestMintSessionToken_PrincipalResolverSeam(t *testing.T) {
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	shim, err := NewShim(
		WithClock(func() time.Time { return fixed }),
		WithPrincipalResolver(func(sessionUUID, hint string) (string, error) {
			if hint == "alias@acme" {
				return "idp|canonical-subject", nil
			}
			return hint, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := baseTokenReq()
	req.LaunchingUser = "alias@acme"
	bundle, err := shim.MintSessionToken(req)
	if err != nil {
		t.Fatal(err)
	}
	claims, _, err := shim.tokenSigner.Verify(bundle.Token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.LaunchingUser != "idp|canonical-subject" {
		t.Fatalf("resolver not applied: launching_user = %q", claims.LaunchingUser)
	}
}

// TestSessionToken_ValidatesAtSeam proves the token rides the existing D22
// Validate seam unchanged (doc 19 §5): ALLOW when the session is live, has a
// grant for the service, and the service is within the token scope.
func TestSessionToken_ValidatesAtSeam(t *testing.T) {
	shim := newTestShim(t)
	bundle, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}
	if err := shim.GrantSession(testSession, testSvc, "g1"); err != nil {
		t.Fatal(err)
	}
	res := shim.Validate(bundle.Token, testSession, testSvc)
	if res.Verdict != VerdictAllow {
		t.Fatalf("want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	if res.GrantRef != "g1" {
		t.Fatalf("grant_ref = %q, want g1", res.GrantRef)
	}
}

// TestSessionToken_FailClosedBranches walks every DENY branch of the token leg —
// each fails closed with the right machine-readable reason (D77).
func TestSessionToken_FailClosedBranches(t *testing.T) {
	shim := newTestShim(t)
	bundle, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(testSession, testSvc, "g1")

	t.Run("cross-session binding", func(t *testing.T) {
		// A token minted for testSession presented under another session_ref. The
		// other session never had a base token, so the token leg keys liveness on
		// the token's own claim and the binding check fails closed.
		res := shim.Validate(bundle.Token, "00000000-0000-4000-8000-0000000000ff", testSvc)
		if res.Verdict != VerdictDeny || res.MachineReadableReason != ReasonSignatureInvalid {
			t.Fatalf("cross-session want DENY(%s), got %v(%s)", ReasonSignatureInvalid, res.Verdict, res.MachineReadableReason)
		}
	})
	t.Run("out of grant", func(t *testing.T) {
		res := shim.Validate(bundle.Token, testSession, "no-grant-svc")
		if res.Verdict != VerdictDeny || res.MachineReadableReason != ReasonOutOfGrant {
			t.Fatalf("out-of-grant want DENY(%s), got %v(%s)", ReasonOutOfGrant, res.Verdict, res.MachineReadableReason)
		}
	})
	t.Run("out of token scope", func(t *testing.T) {
		// The token's service scope is {github, npm}; a grant for "pypi" is outside
		// it, so even with a session grant the token cannot exercise it (doc 19 §8).
		_ = shim.GrantSession(testSession, "pypi", "gp")
		res := shim.Validate(bundle.Token, testSession, "pypi")
		if res.Verdict != VerdictDeny || res.MachineReadableReason != ReasonOutOfGrant {
			t.Fatalf("out-of-scope want DENY(%s), got %v(%s)", ReasonOutOfGrant, res.Verdict, res.MachineReadableReason)
		}
	})
}

// TestSessionToken_ForgedAndTamperedRejected proves the public-key signature is
// load-bearing: a token minted under a DIFFERENT third context (a forged signer)
// never verifies under this shim's signer, and any in-flight tampering breaks the
// chain check. Both fail closed (signature_invalid) at Validate.
func TestSessionToken_ForgedAndTamperedRejected(t *testing.T) {
	shim := newTestShim(t)
	good, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(testSession, testSvc, "g1")

	// Forged: minted under a fresh independent signer (a different third context).
	forgedSigner, err := newBiscuitSigner()
	if err != nil {
		t.Fatal(err)
	}
	forged, _, err := forgedSigner.Mint(SessionTokenClaims{SessionUUID: testSession, Services: []string{testSvc}, Expiry: shim.now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if res := shim.Validate(forged, testSession, testSvc); res.Verdict != VerdictDeny {
		t.Fatal("forged token want DENY, got ALLOW")
	}

	// Tampered: flip a byte mid-token — the chain signature check fails closed.
	tampered := append([]byte(nil), good.Token...)
	tampered[len(tampered)/2] ^= 0xFF
	res := shim.Validate(tampered, testSession, testSvc)
	if res.Verdict != VerdictDeny {
		t.Fatal("tampered token want DENY, got ALLOW")
	}
}

// TestSessionToken_RevokeFailsChainClosed proves RevokeSession on the session
// fails the token closed immediately (doc 16 §5.4 / doc 19 §7 — the whole chain
// keyed on the root session_uuid claim).
func TestSessionToken_RevokeFailsChainClosed(t *testing.T) {
	shim := newTestShim(t)
	bundle, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(testSession, testSvc, "g1")
	if res := shim.Validate(bundle.Token, testSession, testSvc); res.Verdict != VerdictAllow {
		t.Fatalf("pre-revoke want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	if err := shim.RevokeSession(testSession, "admin_kill"); err != nil {
		t.Fatal(err)
	}
	res := shim.Validate(bundle.Token, testSession, testSvc)
	if res.Verdict != VerdictDeny {
		t.Fatal("post-revoke want DENY, got ALLOW")
	}
	if res.MachineReadableReason != "admin_kill" {
		t.Fatalf("revoke reason not surfaced: %q", res.MachineReadableReason)
	}
}

// --- doc 19 §13 / §3: the third signing context never validates as either D82
// hierarchy ----------------------------------------------------------------

// TestSessionToken_NeverValidatesAsWorkloadIdentity proves the doc 19 §13
// negative property in the workload-identity direction: a session-token
// signature validates as NEITHER the workload JWT (it is not a JWS over the
// workload key) NOR the workload X.509 hierarchy (it is not a cert at all). And
// the reverse: a workload JWT never validates as a session token. The two are a
// different cryptosystem (Ed25519 Biscuit vs ECDSA/P-256), so the separation is
// structural.
func TestSessionToken_NeverValidatesAsWorkloadIdentity(t *testing.T) {
	shim := newTestShim(t)
	wl, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg, LaunchingUser: testLaunchingUser,
	})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}

	// (1) The session token must NOT verify as the workload JWT (wrong key, wrong
	// structure entirely).
	leaf, err := x509.ParseCertificate(wl.CertDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyJWT(leaf.PublicKey.(*ecdsa.PublicKey), string(tok.Token)); err == nil {
		t.Fatal("SEPARATION BREACH: session token verified as the workload JWT")
	}

	// (2) The session token must NOT parse/chain as a workload X.509 leaf.
	if _, err := x509.ParseCertificate(tok.Token); err == nil {
		t.Fatal("SEPARATION BREACH: session token parsed as an X.509 certificate")
	}
	if err := shim.workloadRoot.verifyLeaf(tok.Token, shim.now()); err == nil {
		t.Fatal("SEPARATION BREACH: session token chained to the workload root")
	}

	// (3) The reverse: the workload JWT must NOT verify as a session token.
	if _, _, err := shim.tokenSigner.Verify([]byte(wl.JWT)); err == nil {
		t.Fatal("SEPARATION BREACH: workload JWT verified as a session token")
	}
	if shim.IsSessionToken([]byte(wl.JWT)) {
		t.Fatal("SEPARATION BREACH: workload JWT routed as a session token")
	}
}

// TestSessionToken_NeverValidatesAsInterceptionMaterial proves the doc 19 §13
// negative property in the interception direction: a session-token signature
// validates as NEITHER an interception CA/leaf (it is not a DER cert, so it never
// chains to a per-session interception root) NOR — reverse — does interception
// material verify as a session token. Hierarchy 2 is ECDSA/P-256 X.509; the token
// is an Ed25519 Biscuit, so neither pool nor the substrate verifier accepts the
// other's bytes.
func TestSessionToken_NeverValidatesAsInterceptionMaterial(t *testing.T) {
	shim := newTestShim(t)
	ca, err := shim.mintInterceptionCA(testSession)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}

	// (1) The session token must NOT parse/chain as interception material.
	if _, err := x509.ParseCertificate(tok.Token); err == nil {
		t.Fatal("SEPARATION BREACH: session token parsed as an X.509 certificate")
	}
	interceptionPool := sessionVerifyOpts(t, shim.InterceptionRootDER(testSession), ca.CACertDER)
	// Building a leaf from token bytes is impossible (not a cert); the pool can
	// never anchor it. Assert the per-session interception root does not verify the
	// token-bytes-as-cert path (parse already fails, so this is belt-and-braces).
	if cert, perr := x509.ParseCertificate(tok.Token); perr == nil {
		if _, verr := cert.Verify(interceptionPool); verr == nil {
			t.Fatal("SEPARATION BREACH: session token validated against the interception root")
		}
	}

	// (2) The reverse: the interception CA cert (DER bytes) must NOT verify as a
	// session token.
	if _, _, err := shim.tokenSigner.Verify(ca.CACertDER); err == nil {
		t.Fatal("SEPARATION BREACH: interception CA verified as a session token")
	}
	if shim.IsSessionToken(ca.CACertDER) {
		t.Fatal("SEPARATION BREACH: interception CA routed as a session token")
	}
}

// TestSessionToken_PublicKeyIsThirdContext proves the token signing key is a
// THIRD context, structurally distinct from both D82 roots (doc 19 §3): its
// Ed25519 public key bytes equal neither root's public key, and it is not even
// the same algorithm (Ed25519 vs ECDSA).
func TestSessionToken_PublicKeyIsThirdContext(t *testing.T) {
	shim := newTestShim(t)
	_, err := shim.mintInterceptionCA(testSession)
	if err != nil {
		t.Fatal(err)
	}
	tokPub := shim.tokenSigner.PublicKeyDER()
	if len(tokPub) == 0 {
		t.Fatal("third-context public key is empty")
	}
	// The two D82 roots are ECDSA; marshal their public keys and confirm the
	// Ed25519 token key matches neither byte sequence.
	wlPub, _ := x509.MarshalPKIXPublicKey(shim.workloadRoot.key.Public())
	// The per-session interception intermediate CA key (hierarchy 2 leaf signer) and
	// the persistent interception root key must BOTH differ from the third-context
	// token key.
	icCAPub, _ := x509.MarshalPKIXPublicKey(shim.sessions[testSession].interceptionCA.key.Public())
	icRootPub, _ := x509.MarshalPKIXPublicKey(shim.interceptionRoot.key.Public())
	if string(tokPub) == string(wlPub) {
		t.Fatal("SEPARATION BREACH: token key equals the workload root key")
	}
	if string(tokPub) == string(icCAPub) {
		t.Fatal("SEPARATION BREACH: token key equals the per-session interception CA key")
	}
	if string(tokPub) == string(icRootPub) {
		t.Fatal("SEPARATION BREACH: token key equals the interception root key")
	}
}

// --- park/resume/expiry (doc 16 §5.4) --------------------------------------

// TestSessionToken_ParkResume proves the park/resume posture (doc 16 §5.4 /
// doc 19 §3): a token SURVIVES snapshot+park (the bytes are unchanged) and
// RESUME re-checks liveness against the live session record — a token that was
// minted, parked, and resumed still validates while the session is live.
func TestSessionToken_ParkResume(t *testing.T) {
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	clock := fixed
	shim, err := NewShim(WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(testSession, testSvc, "g1")

	// PARK: the token bytes are carried across snapshot unchanged (survives park).
	parked := append([]byte(nil), bundle.Token...)

	// RESUME at a later instant still inside the TTL: re-check liveness PASSES.
	clock = fixed.Add(2 * time.Hour)
	res := shim.Validate(parked, testSession, testSvc)
	if res.Verdict != VerdictAllow {
		t.Fatalf("resume within TTL want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
}

// TestSessionToken_ResumeRevokedFailsClosed proves resume re-checks liveness: a
// session revoked while parked fails the resumed token closed (doc 16 §5.4).
func TestSessionToken_ResumeRevokedFailsClosed(t *testing.T) {
	shim := newTestShim(t)
	bundle, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(testSession, testSvc, "g1")
	parked := append([]byte(nil), bundle.Token...)
	// Revoked while parked.
	_ = shim.RevokeSession(testSession, "parked_then_killed")
	res := shim.Validate(parked, testSession, testSvc)
	if res.Verdict != VerdictDeny || res.MachineReadableReason != "parked_then_killed" {
		t.Fatalf("resume-after-revoke want DENY(parked_then_killed), got %v(%s)", res.Verdict, res.MachineReadableReason)
	}
}

// TestSessionToken_ExpiredReMint proves the expiry path (doc 16 §5.4 / doc 19
// §3): an expired token fails closed, and re-minting through MintSessionToken
// produces a fresh token that validates — "expired tokens re-mint."
func TestSessionToken_ExpiredReMint(t *testing.T) {
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	clock := fixed
	shim, err := NewShim(WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	req := baseTokenReq()
	req.TTL = time.Hour
	bundle, err := shim.MintSessionToken(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(testSession, testSvc, "g1")
	parked := append([]byte(nil), bundle.Token...)

	// Past the TTL: the token fails closed (TTL-as-revocation, doc 16 §5.4).
	clock = fixed.Add(2 * time.Hour)
	res := shim.Validate(parked, testSession, testSvc)
	if res.Verdict != VerdictDeny {
		t.Fatalf("expired token want DENY, got ALLOW")
	}
	if res.MachineReadableReason != ReasonSessionExpired && res.MachineReadableReason != ReasonCredentialStale {
		t.Fatalf("expired reason = %q, want session_expired or credential_stale", res.MachineReadableReason)
	}

	// RE-MINT through MintSessionToken at the new instant: a fresh token validates.
	req2 := baseTokenReq()
	req2.TTL = time.Hour
	fresh, err := shim.MintSessionToken(req2)
	if err != nil {
		t.Fatal(err)
	}
	if res := shim.Validate(fresh.Token, testSession, testSvc); res.Verdict != VerdictAllow {
		t.Fatalf("re-minted token want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
}

// --- offline attenuation at fan-out (doc 19 §4) ----------------------------

// TestSessionToken_AttenuateNarrowsMonotonically proves the doc 19 §4 fan-out
// property: a child token derived OFFLINE (no mint call) carries the appended
// parent_session lineage hop, narrows the service scope (⊆ parent), and a
// widening attempt fails closed. The child validates for a service in its
// narrowed set and is denied for one outside it (even though the session grants
// it) — the grant ∩ token-scope intersection (doc 19 §8).
func TestSessionToken_AttenuateNarrowsMonotonically(t *testing.T) {
	shim := newTestShim(t)
	base, err := shim.MintSessionToken(baseTokenReq()) // scope {github, npm}
	if err != nil {
		t.Fatal(err)
	}
	childSession := "00000000-0000-4000-8000-0000000000c1"
	child, err := shim.AttenuateSessionToken(base, SessionTokenAttenuation{
		ChildSessionUUID: childSession,
		Services:         []string{"github"}, // ⊆ {github, npm}
		TaskRef:          "task:child",
	})
	if err != nil {
		t.Fatal(err)
	}
	if child.AttenuationDepth != 1 {
		t.Fatalf("child depth = %d, want 1", child.AttenuationDepth)
	}
	if len(child.RevocationIDs) != 2 {
		t.Fatalf("child revocation IDs = %d, want 2 (base + 1 hop)", len(child.RevocationIDs))
	}

	// The child's decoded claims: narrowed scope, the lineage hop, the child task.
	claims, depth, err := shim.tokenSigner.Verify(child.Token)
	if err != nil {
		t.Fatal(err)
	}
	if depth != 1 {
		t.Fatalf("decoded child depth = %d, want 1", depth)
	}
	if claims.SessionUUID != childSession {
		t.Fatalf("child session = %q, want %q", claims.SessionUUID, childSession)
	}
	if claims.ParentSession != testSession {
		t.Fatalf("child parent_session = %q, want lineage hop %q", claims.ParentSession, testSession)
	}
	if len(claims.Services) != 1 || claims.Services[0] != "github" {
		t.Fatalf("child services = %v, want [github]", claims.Services)
	}
	if claims.TaskRef != "task:child" {
		t.Fatalf("child task_ref = %q, want task:child", claims.TaskRef)
	}

	// The child validates under ITS session for the narrowed service ...
	_ = shim.GrantSession(childSession, "github", "cg")
	_ = shim.GrantSession(childSession, "npm", "cn")
	// Establish the child as a token-bearing session so the token leg keys liveness
	// on it (a real child VM's create choreography does this; here we mint a base
	// for the child session to register the record + hasSessionToken).
	if _, err := shim.MintSessionToken(MintSessionTokenReq{SessionUUID: childSession, Org: testOrg}); err != nil {
		t.Fatal(err)
	}
	if res := shim.Validate(child.Token, childSession, "github"); res.Verdict != VerdictAllow {
		t.Fatalf("child want ALLOW for github, got DENY(%s)", res.MachineReadableReason)
	}
	// ... but is DENIED for npm — outside the child's narrowed blocks (doc 19 §8).
	if res := shim.Validate(child.Token, childSession, "npm"); res.Verdict != VerdictDeny {
		t.Fatal("child want DENY for npm (outside narrowed scope), got ALLOW")
	}

	// A WIDENING attempt fails closed (monotonic narrowing, doc 19 §4): the child
	// cannot re-add npm.
	if _, err := shim.AttenuateSessionToken(child, SessionTokenAttenuation{
		Services: []string{"github", "npm"},
	}); err != errSessionTokenScope {
		t.Fatalf("widening want errSessionTokenScope, got %v", err)
	}
	// A later-expiry widening also fails closed.
	if _, err := shim.AttenuateSessionToken(child, SessionTokenAttenuation{
		Expiry: child.Expiry.Add(time.Hour),
	}); err != errSessionTokenScope {
		t.Fatalf("expiry-widening want errSessionTokenScope, got %v", err)
	}
}

// TestSessionToken_FanOutWithoutMint proves the doc 19 §4 killer-fit property:
// N child tokens derive from one base token with ZERO additional mints. We track
// mint calls through a counting substrate-signer wrapper and assert only the base
// mint hit it.
func TestSessionToken_FanOutWithoutMint(t *testing.T) {
	shim := newTestShim(t)
	inner := shim.tokenSigner
	counter := &countingSigner{SubstrateSigner: inner}
	shim.tokenSigner = counter

	base, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}
	if counter.mints != 1 {
		t.Fatalf("base mint count = %d, want 1", counter.mints)
	}
	// Fan out to 5 children — all via offline attenuation, no mint.
	for i := 0; i < 5; i++ {
		if _, err := shim.AttenuateSessionToken(base, SessionTokenAttenuation{
			Services: []string{"github"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if counter.mints != 1 {
		t.Fatalf("after fan-out mint count = %d, want 1 (zero mint RPCs at fan-out, doc 19 §4)", counter.mints)
	}
}

// countingSigner wraps a SubstrateSigner to count Mint calls (the fan-out
// no-mint assertion).
type countingSigner struct {
	SubstrateSigner
	mints int
}

func (c *countingSigner) Mint(claims SessionTokenClaims) ([]byte, [][]byte, error) {
	c.mints++
	return c.SubstrateSigner.Mint(claims)
}

// TestSessionToken_StdlibFallbackSeam proves the doc 19 §6 substrate seam is
// genuinely swappable: a deployment that cannot ship the Biscuit/Datalog default
// installs a stdlib-only signer via WithSubstrateSigner and MintSessionToken +
// Validate work unchanged. This is the fallback the brief mandates be present
// behind a clean seam.
func TestSessionToken_StdlibFallbackSeam(t *testing.T) {
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	fb, err := newStdlibSigner()
	if err != nil {
		t.Fatal(err)
	}
	shim, err := NewShim(WithClock(func() time.Time { return fixed }), WithSubstrateSigner(fb))
	if err != nil {
		t.Fatal(err)
	}
	if shim.tokenSigner.Name() != stdlibSubstrateName {
		t.Fatalf("substrate = %q, want %q", shim.tokenSigner.Name(), stdlibSubstrateName)
	}
	bundle, err := shim.MintSessionToken(baseTokenReq())
	if err != nil {
		t.Fatal(err)
	}
	_ = shim.GrantSession(testSession, testSvc, "g1")
	if res := shim.Validate(bundle.Token, testSession, testSvc); res.Verdict != VerdictAllow {
		t.Fatalf("stdlib-fallback token want ALLOW, got DENY(%s)", res.MachineReadableReason)
	}
	// The fallback token is STILL not workload identity / interception material.
	if _, err := x509.ParseCertificate(bundle.Token); err == nil {
		t.Fatal("SEPARATION BREACH: stdlib token parsed as an X.509 certificate")
	}
}
