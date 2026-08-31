// SPDX-License-Identifier: Apache-2.0

package main

// writerauth_live_test.go pins the two W2 writer-seat auth adapters main.go's liveDeps
// wires onto the WriterRelayService seams (controlplane.AttachAuthValidator +
// controlplane.IdentityAssertionValidator), against synthetic fixtures with no live edge
// (D50: no host-agent/SSO service). Each adapter is exercised on BOTH arms — accept and
// reject — so the fail-closed contract the live orchestrator depends on is nailed down.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/hypervisor/libvirt"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/trustpath"
)

// fakeTokenSource is a synthetic libvirt.AttachTokenSource: it returns a fixed token +
// expiry for one session, an error for a named faulting session, and mints a distinct
// (non-matching) token for any other session (the "no handle ever minted" arm).
type fakeTokenSource struct {
	sessionUUID string
	token       []byte
	expiresAt   time.Time
	faultUUID   string
	err         error
}

func (f fakeTokenSource) TokenFor(_ context.Context, sessionUUID string) ([]byte, time.Time, error) {
	if f.faultUUID != "" && sessionUUID == f.faultUUID {
		return nil, time.Time{}, f.err
	}
	if sessionUUID == f.sessionUUID {
		return f.token, f.expiresAt, nil
	}
	// A session the store never minted for: a fresh, non-matching token.
	return []byte("some-other-session-token"), time.Now().Add(time.Hour), nil
}

func TestAttachTokenAuthValidator_AcceptsMatchingLiveToken(t *testing.T) {
	src := fakeTokenSource{
		sessionUUID: "sess-1",
		token:       []byte("tok-abc"),
		expiresAt:   time.Now().Add(15 * time.Minute),
	}
	v := newAttachTokenAuthValidator(src)

	ok, err := v.ValidateAttachAuth(context.Background(), "sess-1", []byte("tok-abc"))
	if err != nil {
		t.Fatalf("ValidateAttachAuth returned err: %v", err)
	}
	if !ok {
		t.Fatal("ValidateAttachAuth = false for the matching live token; want true")
	}
}

func TestAttachTokenAuthValidator_RejectsMismatchedToken(t *testing.T) {
	src := fakeTokenSource{
		sessionUUID: "sess-1",
		token:       []byte("tok-abc"),
		expiresAt:   time.Now().Add(15 * time.Minute),
	}
	v := newAttachTokenAuthValidator(src)

	ok, err := v.ValidateAttachAuth(context.Background(), "sess-1", []byte("tok-WRONG"))
	if err != nil {
		t.Fatalf("ValidateAttachAuth returned err: %v", err)
	}
	if ok {
		t.Fatal("ValidateAttachAuth = true for a mismatched token; want false (fail-closed)")
	}
}

func TestAttachTokenAuthValidator_RejectsEmptyInputs(t *testing.T) {
	src := fakeTokenSource{sessionUUID: "sess-1", token: []byte("tok-abc"), expiresAt: time.Now().Add(time.Hour)}
	v := newAttachTokenAuthValidator(src)

	if ok, err := v.ValidateAttachAuth(context.Background(), "sess-1", nil); ok || err != nil {
		t.Fatalf("empty token: ok=%v err=%v; want false,nil (fail-closed)", ok, err)
	}
	if ok, err := v.ValidateAttachAuth(context.Background(), "", []byte("tok-abc")); ok || err != nil {
		t.Fatalf("empty session: ok=%v err=%v; want false,nil (fail-closed)", ok, err)
	}
}

func TestAttachTokenAuthValidator_RejectsExpiredStoredToken(t *testing.T) {
	// A fixture whose stored token already expired: the adapter's defense-in-depth expiry
	// gate refuses even a byte-matching token (never accepted past expiry).
	src := fakeTokenSource{
		sessionUUID: "sess-1",
		token:       []byte("tok-abc"),
		expiresAt:   time.Now().Add(-time.Minute),
	}
	v := newAttachTokenAuthValidator(src)

	ok, err := v.ValidateAttachAuth(context.Background(), "sess-1", []byte("tok-abc"))
	if err != nil {
		t.Fatalf("ValidateAttachAuth returned err: %v", err)
	}
	if ok {
		t.Fatal("ValidateAttachAuth = true for an expired stored token; want false (fail-closed)")
	}
}

func TestAttachTokenAuthValidator_SurfacesStoreFault(t *testing.T) {
	src := fakeTokenSource{faultUUID: "sess-x", err: errors.New("boom")}
	v := newAttachTokenAuthValidator(src)

	ok, err := v.ValidateAttachAuth(context.Background(), "sess-x", []byte("tok"))
	if ok {
		t.Fatal("ValidateAttachAuth = true on a store fault; want false")
	}
	if err == nil {
		t.Fatal("ValidateAttachAuth err = nil on a store fault; want a transient fault error")
	}
}

// dualTokenSource is a synthetic source implementing BOTH libvirt.AttachTokenSource
// (TokenFor — the MINT arm) and libvirt.AttachTokenPeeker (TokenPeek — the read-only arm),
// exactly as the production fileAttachTokenStore does. TokenPeek returns the live token;
// TokenFor records that it was reached and hands back a DISTINCT, non-matching token — so a
// validate that (wrongly) routed through the mint arm both trips the recorder AND fails the
// byte compare. It pins that newAttachTokenAuthValidator prefers the peek arm.
type dualTokenSource struct {
	sessionUUID   string
	peekToken     []byte
	peekExpiresAt time.Time
	tokenForCalls int
}

func (d *dualTokenSource) TokenPeek(_ context.Context, sessionUUID string) ([]byte, time.Time, bool, error) {
	if sessionUUID == d.sessionUUID {
		return d.peekToken, d.peekExpiresAt, true, nil
	}
	return nil, time.Time{}, false, nil
}

func (d *dualTokenSource) TokenFor(_ context.Context, _ string) ([]byte, time.Time, error) {
	// The MINT arm: must NOT be reached during a validate when the source is peek-capable.
	d.tokenForCalls++
	return []byte("minted-on-validate-should-never-happen"), time.Now().Add(time.Hour), nil
}

// TestAttachTokenAuthValidator_PrefersPeekerOverMint pins the type-assert preference: when
// the injected AttachTokenSource ALSO implements AttachTokenPeeker, newAttachTokenAuthValidator
// binds the read-only peek arm, so a validate resolves through TokenPeek and NEVER calls the
// mint arm (TokenFor). This is the structural guard that a future direct wiring of a real
// on-disk store through this constructor cannot silently reintroduce mint-on-validate.
//
// MUTATION CHECK: drop the type-assert preference in newAttachTokenAuthValidator (leave
// v.peek nil) and this test REDs — liveToken then routes to TokenFor, which returns the
// distinct "minted" token (byte compare fails ⇒ ok=false) and increments tokenForCalls
// (the mint-arm assertion fails). Verified RED under mutation, then reverted.
func TestAttachTokenAuthValidator_PrefersPeekerOverMint(t *testing.T) {
	src := &dualTokenSource{
		sessionUUID:   "sess-dual",
		peekToken:     []byte("tok-live"),
		peekExpiresAt: time.Now().Add(15 * time.Minute),
	}
	v := newAttachTokenAuthValidator(src)

	// The peek arm must be the one bound (not merely the mint arm).
	if v.peek == nil {
		t.Fatal("newAttachTokenAuthValidator did not bind the peek arm for a peek-capable source; want the type-assert preference")
	}

	ok, err := v.ValidateAttachAuth(context.Background(), "sess-dual", []byte("tok-live"))
	if err != nil {
		t.Fatalf("ValidateAttachAuth returned err: %v", err)
	}
	if !ok {
		t.Fatal("ValidateAttachAuth = false for the live peeked token; want true (peek arm used)")
	}
	if src.tokenForCalls != 0 {
		t.Fatalf("mint arm (TokenFor) called %d time(s) during validate; want 0 (peek arm must be preferred, never mint-on-validate)", src.tokenForCalls)
	}
}

// TestAttachTokenAuthValidatorForOverlay_RoundTripAgainstRealStore proves the production
// constructor validates against a REAL fileAttachTokenStore: mint a token for a session
// through the store (as the host-agent's IssueAttachHandle does), then the adapter accepts
// exactly that token and rejects a different one — end-to-end over the on-disk file.
func TestAttachTokenAuthValidatorForOverlay_RoundTripAgainstRealStore(t *testing.T) {
	dir := t.TempDir()

	store, err := libvirt.NewFileAttachTokenStore(dir, time.Hour)
	if err != nil {
		t.Fatalf("NewFileAttachTokenStore: %v", err)
	}
	minted, _, err := store.TokenFor(context.Background(), "sess-real")
	if err != nil {
		t.Fatalf("TokenFor mint: %v", err)
	}

	v, err := newAttachTokenAuthValidatorForOverlay(dir)
	if err != nil {
		t.Fatalf("newAttachTokenAuthValidatorForOverlay: %v", err)
	}

	ok, err := v.ValidateAttachAuth(context.Background(), "sess-real", minted)
	if err != nil {
		t.Fatalf("accept arm err: %v", err)
	}
	if !ok {
		t.Fatal("real-store accept arm = false; want true for the minted token")
	}

	ok, err = v.ValidateAttachAuth(context.Background(), "sess-real", []byte("not-the-minted-token"))
	if err != nil {
		t.Fatalf("reject arm err: %v", err)
	}
	if ok {
		t.Fatal("real-store reject arm = true; want false for a non-matching token")
	}
}

func TestAttachTokenAuthValidatorForOverlay_EmptyOverlayErrors(t *testing.T) {
	if _, err := newAttachTokenAuthValidatorForOverlay(""); err == nil {
		t.Fatal("newAttachTokenAuthValidatorForOverlay(\"\") err = nil; want a construction error")
	}
}

// TestAttachTokenAuthValidatorForOverlay_UnknownSessionRefusesWithoutMinting proves the
// read-only pre-gate: validating a session the host-agent never issued a handle for is a
// clean refusal that writes NO token file — a caller spraying RequestWriterSeat with
// arbitrary session UUIDs cannot fill the host overlay dir (TokenFor would mint+persist;
// the pre-gate keeps validation read-only for unknown sessions).
func TestAttachTokenAuthValidatorForOverlay_UnknownSessionRefusesWithoutMinting(t *testing.T) {
	dir := t.TempDir()

	v, err := newAttachTokenAuthValidatorForOverlay(dir)
	if err != nil {
		t.Fatalf("newAttachTokenAuthValidatorForOverlay: %v", err)
	}

	ok, err := v.ValidateAttachAuth(context.Background(), "sess-never-minted", []byte("some-token"))
	if err != nil {
		t.Fatalf("ValidateAttachAuth err: %v", err)
	}
	if ok {
		t.Fatal("ValidateAttachAuth = true for a session with no minted handle; want false (fail-closed)")
	}

	// The refusal must be read-only: no token file appeared under the store dir.
	entries, err := os.ReadDir(trustpath.AttachTokensSubdirPath(dir))
	if err != nil {
		t.Fatalf("read token store dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("validation of an unknown session minted token files %v; want none (read-only refusal)", names)
	}
}

// --- MVP identity assertion validator -------------------------------------------------

func TestMVPIdentityValidator_PassthroughAcceptsNonEmpty(t *testing.T) {
	v := newMVPIdentityAssertionValidator(nil)

	driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", "  alice@example.com  ")
	if err != nil {
		t.Fatalf("ValidateAssertion err: %v", err)
	}
	if !ok {
		t.Fatal("passthrough accept arm = false; want true for a non-empty assertion")
	}
	if driver != "alice@example.com" {
		t.Fatalf("passthrough driver = %q; want the trimmed principal %q", driver, "alice@example.com")
	}
}

func TestMVPIdentityValidator_PassthroughRejectsEmpty(t *testing.T) {
	v := newMVPIdentityAssertionValidator(nil)

	for _, assertion := range []string{"", "   ", "\t\n"} {
		driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", assertion)
		if err != nil {
			t.Fatalf("ValidateAssertion(%q) err: %v", assertion, err)
		}
		if ok || driver != "" {
			t.Fatalf("passthrough reject arm for %q: driver=%q ok=%v; want \"\",false (fail-closed)", assertion, driver, ok)
		}
	}
}

func TestMVPIdentityValidator_AllowMapAcceptsMappedRejectsUnmapped(t *testing.T) {
	v := newMVPIdentityAssertionValidator(map[string]string{"assert-a": "driver-a"})

	driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", "assert-a")
	if err != nil {
		t.Fatalf("accept arm err: %v", err)
	}
	if !ok || driver != "driver-a" {
		t.Fatalf("allow-map accept arm: driver=%q ok=%v; want driver-a,true", driver, ok)
	}

	// An assertion absent from the closed fixture set: refused (NOT passthrough).
	driver, ok, err = v.ValidateAssertion(context.Background(), "sess-1", "assert-unknown")
	if err != nil {
		t.Fatalf("reject arm err: %v", err)
	}
	if ok || driver != "" {
		t.Fatalf("allow-map reject arm: driver=%q ok=%v; want \"\",false (fail-closed)", driver, ok)
	}
}

func TestMVPIdentityValidator_EmptyAllowEntriesDropToPassthrough(t *testing.T) {
	// A map whose only entries are malformed (empty key/value) must NOT fabricate a
	// wildcard grant, and — having no usable entries — degrades to passthrough mode.
	v := newMVPIdentityAssertionValidator(map[string]string{"": "driver", "assert": ""})
	if len(v.allow) != 0 {
		t.Fatalf("allow map = %v; want empty (malformed entries dropped)", v.allow)
	}
	if _, ok, _ := v.ValidateAssertion(context.Background(), "s", "anything"); !ok {
		t.Fatal("degraded-passthrough accept arm = false; want true")
	}
}

func TestParseMVPIdentityAllow(t *testing.T) {
	// Empty => passthrough (nil map).
	if m, err := parseMVPIdentityAllow(""); err != nil || m != nil {
		t.Fatalf("empty: m=%v err=%v; want nil,nil (passthrough)", m, err)
	}
	// Well-formed pairs.
	m, err := parseMVPIdentityAllow(" a=driver-a , b=driver-b ")
	if err != nil {
		t.Fatalf("well-formed parse err: %v", err)
	}
	if m["a"] != "driver-a" || m["b"] != "driver-b" || len(m) != 2 {
		t.Fatalf("parsed map = %v; want {a:driver-a, b:driver-b}", m)
	}
	// Malformed pairs are LOUD (never a silent accept-any degrade).
	for _, bad := range []string{"noequals", "=driver", "assert=", "a=driver,malformed"} {
		if _, err := parseMVPIdentityAllow(bad); err == nil {
			t.Fatalf("parseMVPIdentityAllow(%q) err = nil; want a malformed-pair error", bad)
		}
	}
}

// --- liveDeps gate → seam resolution (the offline-testable wiring slice) --------------

// envMap is a synthetic getenv for resolveWriterIdentityValidator (no process env
// mutation, parallel-safe).
func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

// TestResolveWriterIdentityValidator_GateOffLeavesSeamNil pins the fail-closed wiring
// posture: without DS_ORCH_FAKE_IDENTITY=1 the seam resolves to the UNTYPED nil
// interface (never a typed-nil pointer), so the WriterRelayService's `identity == nil`
// check holds and RequestWriterSeat refuses Unauthenticated — the DS_ORCH_LIVE run
// without the fake gate grants no seat.
func TestResolveWriterIdentityValidator_GateOffLeavesSeamNil(t *testing.T) {
	for _, gate := range []string{"", "0", "true", "yes"} {
		v, mode, err := resolveWriterIdentityValidator(envMap(map[string]string{
			"DS_ORCH_FAKE_IDENTITY": gate,
			"DS_ORCH_MVP_IDENTITY":  "a=driver-a",
		}))
		if err != nil {
			t.Fatalf("gate=%q: err = %v; want nil", gate, err)
		}
		if v != nil {
			t.Fatalf("gate=%q: validator = %#v; want the untyped nil interface (fail-closed seam)", gate, v)
		}
		if mode != writerIdentityNone {
			t.Fatalf("gate=%q: mode = %v; want writerIdentityNone (gate off)", gate, mode)
		}
	}
}

// TestResolveWriterIdentityValidator_GateOnResolvesPassthrough pins the gate-on default:
// DS_ORCH_FAKE_IDENTITY=1 with no fixture set resolves the passthrough MVP validator.
func TestResolveWriterIdentityValidator_GateOnResolvesPassthrough(t *testing.T) {
	v, mode, err := resolveWriterIdentityValidator(envMap(map[string]string{
		"DS_ORCH_FAKE_IDENTITY": "1",
	}))
	if err != nil {
		t.Fatalf("resolveWriterIdentityValidator err: %v", err)
	}
	if v == nil {
		t.Fatal("gate on resolved a nil validator; want the MVP passthrough validator")
	}
	if mode != writerIdentityMVPPassthrough {
		t.Fatalf("mode = %v; want writerIdentityMVPPassthrough", mode)
	}
	driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", "alice@example.com")
	if err != nil || !ok || driver != "alice@example.com" {
		t.Fatalf("passthrough ValidateAssertion = %q,%v,%v; want alice@example.com,true,nil", driver, ok, err)
	}
}

// TestResolveWriterIdentityValidator_GateOnResolvesAllowMap pins the fixture-set arm:
// DS_ORCH_MVP_IDENTITY selects the CLOSED allow-map (mapped accepted, unmapped refused).
func TestResolveWriterIdentityValidator_GateOnResolvesAllowMap(t *testing.T) {
	v, mode, err := resolveWriterIdentityValidator(envMap(map[string]string{
		"DS_ORCH_FAKE_IDENTITY": "1",
		"DS_ORCH_MVP_IDENTITY":  "assert-a=driver-a",
	}))
	if err != nil {
		t.Fatalf("resolveWriterIdentityValidator err: %v", err)
	}
	if v == nil {
		t.Fatal("gate on resolved a nil validator; want the MVP allow-map validator")
	}
	if mode != writerIdentityMVPAllowMap {
		t.Fatalf("mode = %v; want writerIdentityMVPAllowMap", mode)
	}
	if driver, ok, _ := v.ValidateAssertion(context.Background(), "s", "assert-a"); !ok || driver != "driver-a" {
		t.Fatalf("mapped assertion = %q,%v; want driver-a,true", driver, ok)
	}
	if _, ok, _ := v.ValidateAssertion(context.Background(), "s", "assert-unknown"); ok {
		t.Fatal("unmapped assertion accepted under a closed allow-map; want refusal")
	}
}

// TestResolveWriterIdentityValidator_MalformedFixtureIsLoud pins the misconfiguration
// arm: a malformed DS_ORCH_MVP_IDENTITY under the gate is a construction error (liveDeps
// aborts) — never a silent degrade to accept-any.
func TestResolveWriterIdentityValidator_MalformedFixtureIsLoud(t *testing.T) {
	_, _, err := resolveWriterIdentityValidator(envMap(map[string]string{
		"DS_ORCH_FAKE_IDENTITY": "1",
		"DS_ORCH_MVP_IDENTITY":  "no-equals-sign",
	}))
	if err == nil {
		t.Fatal("malformed DS_ORCH_MVP_IDENTITY resolved without error; want a loud construction error")
	}
}

// --- dialed D55/SSO identity assertion validator --------------------------------------

// fakeAssertionVerifier is a synthetic assertionVerifier standing in for the real SSO/OIDC
// dial: it resolves one assertion to a principal (the accept arm), refuses everything else
// (ok=false — the reject arm), and faults for a named assertion (a transient dial fault).
// The assertions it keys on are SHAPE-VALID compact JWS strings (the pre-gate at the
// validator edge refuses anything else before the verifier is ever reached).
type fakeAssertionVerifier struct {
	wantAssertion string
	principal     string
	faultOn       string
	err           error
}

func (f fakeAssertionVerifier) Verify(_ context.Context, _ string, assertion string) (string, bool, error) {
	if f.faultOn != "" && assertion == f.faultOn {
		return "", false, f.err
	}
	if assertion == f.wantAssertion {
		return f.principal, true, nil
	}
	return "", false, nil
}

// b64 is the JOSE unpadded-base64url encoder.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mkJWS assembles a compact JWS from a header + claims map, signing the signing-input with
// sign (nil ⇒ a fixed non-cryptographic placeholder signature, for shape-only fixtures).
func mkJWS(t *testing.T, header, claims map[string]any, sign func([]byte) []byte) string {
	t.Helper()
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	signingInput := b64(hb) + "." + b64(cb)
	var sig []byte
	if sign != nil {
		sig = sign([]byte(signingInput))
	} else {
		sig = []byte("shape-only-placeholder-signature")
	}
	return signingInput + "." + b64(sig)
}

// shapeValidToken is a well-formed compact JWS (RS256 header + a sub claim) whose signature
// is a placeholder — enough to pass the edge shape pre-gate and reach a fixture verifier.
func shapeValidToken(t *testing.T) string {
	t.Helper()
	return mkJWS(t,
		map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"},
		map[string]any{"sub": "alice@org"},
		nil)
}

func TestSSOIdentityValidator_AcceptsVerifiedAssertion(t *testing.T) {
	tok := shapeValidToken(t)
	v := newSSOIdentityAssertionValidator(fakeAssertionVerifier{
		wantAssertion: tok,
		principal:     "alice@org",
	})
	driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", tok)
	if err != nil {
		t.Fatalf("accept arm err: %v", err)
	}
	if !ok || driver != "alice@org" {
		t.Fatalf("accept arm: driver=%q ok=%v; want alice@org,true (the SSO-resolved principal)", driver, ok)
	}
}

func TestSSOIdentityValidator_RejectsInvalidAssertion(t *testing.T) {
	// A shape-valid but DIFFERENT token: passes the pre-gate, then the verifier rejects it.
	want := shapeValidToken(t)
	forged := mkJWS(t,
		map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"},
		map[string]any{"sub": "mallory@org"}, nil)
	v := newSSOIdentityAssertionValidator(fakeAssertionVerifier{
		wantAssertion: want,
		principal:     "alice@org",
	})
	driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", forged)
	if err != nil {
		t.Fatalf("reject arm err: %v", err)
	}
	if ok || driver != "" {
		t.Fatalf("reject arm: driver=%q ok=%v; want \"\",false (Unauthenticated — SSO rejected)", driver, ok)
	}
}

func TestSSOIdentityValidator_FailClosedOnVerifyFault(t *testing.T) {
	// A transient dial/verify fault must be SURFACED (non-nil err ⇒ handler Unavailable),
	// never swallowed into an accept — no seat on an assertion the SSO face did not verify.
	tok := shapeValidToken(t)
	v := newSSOIdentityAssertionValidator(fakeAssertionVerifier{
		faultOn: tok,
		err:     errors.New("dial tcp sso: connection refused"),
	})
	driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", tok)
	if ok || driver != "" {
		t.Fatalf("fault arm accepted: driver=%q ok=%v; want \"\",false (fail-closed)", driver, ok)
	}
	if err == nil {
		t.Fatal("fault arm err = nil; want the dial/verify fault surfaced (handler → Unavailable)")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("fault arm err = %v; want the wrapped dial fault", err)
	}
}

func TestSSOIdentityValidator_RejectsEmptyWithoutDialing(t *testing.T) {
	// An empty/whitespace assertion is refused WITHOUT ever dialing the verifier (a blank
	// credential wastes no dial). A verifier that would panic if called proves it.
	v := newSSOIdentityAssertionValidator(panicVerifier{})
	for _, assertion := range []string{"", "   ", "\t\n"} {
		driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", assertion)
		if ok || driver != "" || err != nil {
			t.Fatalf("empty assertion %q: driver=%q ok=%v err=%v; want \"\",false,nil (no dial)", assertion, driver, ok, err)
		}
	}
}

// TestSSOIdentityValidator_RefusesMalformedShapeWithoutDialing pins the token-shape pre-gate
// AT THE VALIDATOR EDGE: a structurally-malformed identity_assertion (not a compact JWS) is
// refused with a CLEAN Unauthenticated (ok=false, nil err) BEFORE the verifier is dialed —
// a garbage credential wastes no verify. A panicking verifier proves no dial happened.
func TestSSOIdentityValidator_RefusesMalformedShapeWithoutDialing(t *testing.T) {
	v := newSSOIdentityAssertionValidator(panicVerifier{})
	malformed := []string{
		"not-a-jws",                      // no dots
		"only.two",                       // 2 segments
		"a.b.c.d",                        // 4 segments
		"a..c",                           // empty middle segment
		"!!!.###.$$$",                    // non-base64url
		b64([]byte("{}")) + ".x.y",       // header has no alg
		b64([]byte("not-json")) + ".x.y", // header is not JSON
	}
	for _, m := range malformed {
		driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", m)
		if ok || driver != "" || err != nil {
			t.Fatalf("malformed %q: driver=%q ok=%v err=%v; want \"\",false,nil (edge shape refusal, no dial)", m, driver, ok, err)
		}
	}
}

func TestSSOIdentityValidator_NilVerifierFailsClosed(t *testing.T) {
	// A nil verifier (SSO seam wired but no dial adapter) must fail CLOSED — every shape-valid
	// assertion is refused, never accepted.
	v := newSSOIdentityAssertionValidator(nil)
	driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", shapeValidToken(t))
	if ok || driver != "" || err != nil {
		t.Fatalf("nil verifier: driver=%q ok=%v err=%v; want \"\",false,nil (fail-closed)", driver, ok, err)
	}
}

func TestSSOIdentityValidator_EmptyResolvedPrincipalRefused(t *testing.T) {
	// SSO verified the assertion (ok=true) but resolved a blank principal — refuse (never an
	// empty driver attribution on a granted seat, D8/D55).
	tok := shapeValidToken(t)
	v := newSSOIdentityAssertionValidator(fakeAssertionVerifier{
		wantAssertion: tok,
		principal:     "   ",
	})
	driver, ok, err := v.ValidateAssertion(context.Background(), "sess-1", tok)
	if ok || driver != "" || err != nil {
		t.Fatalf("empty-principal arm: driver=%q ok=%v err=%v; want \"\",false,nil (refuse empty attribution)", driver, ok, err)
	}
}

// panicVerifier is an assertionVerifier that must never be dialed; it panics if Verify is
// reached, proving the empty/malformed pre-gates short-circuit before any dial.
type panicVerifier struct{}

func (panicVerifier) Verify(context.Context, string, string) (string, bool, error) {
	panic("assertionVerifier.Verify dialed for an empty/malformed assertion (should short-circuit)")
}

// --- liveSSOVerifier: real OIDC discovery + JWKS signature verification (offline) ------
//
// These arms exercise the PRODUCTION verify against a SYNTHETIC httptest issuer + JWKS (no
// live SSO — D50). Validation against a REAL production issuer is the operator-gated deferred
// manual step (recorded as a taskdb note on the liveedge2 live-validation task).

const testSSOKid = "test-key-1"

func signRS256(t *testing.T, priv *rsa.PrivateKey) func([]byte) []byte {
	t.Helper()
	return func(signingInput []byte) []byte {
		h := sha256.Sum256(signingInput)
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
		if err != nil {
			t.Fatalf("RS256 sign: %v", err)
		}
		return sig
	}
}

func signES256(t *testing.T, priv *ecdsa.PrivateKey) func([]byte) []byte {
	t.Helper()
	return func(signingInput []byte) []byte {
		h := sha256.Sum256(signingInput)
		r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
		if err != nil {
			t.Fatalf("ES256 sign: %v", err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig
	}
}

func rsaJWK(pub *rsa.PublicKey) map[string]any {
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return map[string]any{
		"kty": "RSA", "kid": testSSOKid, "alg": "RS256", "use": "sig",
		"n": b64(pub.N.Bytes()), "e": b64(eBytes),
	}
}

func ecJWK(pub *ecdsa.PublicKey) map[string]any {
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	return map[string]any{
		"kty": "EC", "kid": testSSOKid, "crv": "P-256", "alg": "ES256", "use": "sig",
		"x": b64(xb), "y": b64(yb),
	}
}

// startIssuer serves the OIDC discovery doc + JWKS for the given keys. The discovery doc's
// issuer is the server's own URL, so the verifier's issuerURL is set to it.
func startIssuer(t *testing.T, jwks []map[string]any) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": jwks})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fixedClock returns a now func pinned to base.
func ssoFixedClock(base time.Time) func() time.Time { return func() time.Time { return base } }

// TestLiveSSOVerifier_ArmedVerifiesRS256 is the HAPPY PATH: an RS256-signed OIDC ID token
// verified against the issuer's discovered JWKS resolves the subject as the principal.
func TestLiveSSOVerifier_ArmedVerifiesRS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen RSA: %v", err)
	}
	srv := startIssuer(t, []map[string]any{rsaJWK(&priv.PublicKey)})
	now := time.Unix(1_700_000_000, 0)
	tok := mkJWS(t,
		map[string]any{"alg": "RS256", "kid": testSSOKid, "typ": "JWT"},
		map[string]any{"iss": srv.URL, "sub": "alice@org", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()},
		signRS256(t, priv))

	v := &liveSSOVerifier{issuerURL: srv.URL, live: true, httpClient: srv.Client(), now: ssoFixedClock(now)}
	principal, ok, err := v.Verify(context.Background(), "sess-1", tok)
	if err != nil {
		t.Fatalf("happy-path verify err: %v", err)
	}
	if !ok || principal != "alice@org" {
		t.Fatalf("happy path: principal=%q ok=%v; want alice@org,true", principal, ok)
	}
}

// TestLiveSSOVerifier_ArmedVerifiesES256 covers the EC/P-256 signature arm.
func TestLiveSSOVerifier_ArmedVerifiesES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen EC: %v", err)
	}
	srv := startIssuer(t, []map[string]any{ecJWK(&priv.PublicKey)})
	now := time.Unix(1_700_000_000, 0)
	tok := mkJWS(t,
		map[string]any{"alg": "ES256", "kid": testSSOKid, "typ": "JWT"},
		map[string]any{"iss": srv.URL, "sub": "bob@org", "exp": now.Add(time.Hour).Unix()},
		signES256(t, priv))

	v := &liveSSOVerifier{issuerURL: srv.URL, live: true, httpClient: srv.Client(), now: ssoFixedClock(now)}
	principal, ok, err := v.Verify(context.Background(), "sess-1", tok)
	if err != nil || !ok || principal != "bob@org" {
		t.Fatalf("ES256 happy path: principal=%q ok=%v err=%v; want bob@org,true,nil", principal, ok, err)
	}
}

// TestLiveSSOVerifier_UnarmedFailsClosed pins the unarmed arm: DS_ORCH_SSO_LIVE unset ⇒ the
// verifier faults immediately (seam wired, dial not armed), so no seat is granted.
func TestLiveSSOVerifier_UnarmedFailsClosed(t *testing.T) {
	v := &liveSSOVerifier{issuerURL: "https://sso.example", live: false}
	_, ok, err := v.Verify(context.Background(), "sess-1", shapeValidToken(t))
	if ok || err == nil {
		t.Fatalf("unarmed: ok=%v err=%v; want false + an unarmed fault", ok, err)
	}
}

// TestLiveSSOVerifier_FailClosedArms sweeps EVERY fail-closed fault arm of the armed verify:
// a bad signature, a wrong-issuer claim, an expired token, a not-yet-valid token, a
// kid that resolves no key, alg:none, a disallowed alg, a typ-confusion, a crit header, and
// an audience mismatch — each must refuse (never grant a seat).
func TestLiveSSOVerifier_FailClosedArms(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen RSA: %v", err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen other RSA: %v", err)
	}
	srv := startIssuer(t, []map[string]any{rsaJWK(&priv.PublicKey)})
	now := time.Unix(1_700_000_000, 0)
	goodHdr := func() map[string]any {
		return map[string]any{"alg": "RS256", "kid": testSSOKid, "typ": "JWT"}
	}
	goodClaims := func() map[string]any {
		return map[string]any{"iss": srv.URL, "sub": "alice@org", "exp": now.Add(time.Hour).Unix()}
	}

	cases := []struct {
		name      string
		tok       string
		audience  string
		wantFault bool // true ⇒ a surfaced transient err; false ⇒ a clean ok=false,nil refusal
	}{
		{
			name: "bad-signature",
			tok:  mkJWS(t, goodHdr(), goodClaims(), signRS256(t, other)), // signed by a non-published key
		},
		{
			name: "wrong-issuer",
			// The signature is valid, but the iss claim mismatches the configured issuer.
			tok: mkJWS(t, goodHdr(), map[string]any{"iss": "https://evil.example", "sub": "a", "exp": now.Add(time.Hour).Unix()}, signRS256(t, priv)),
		},
		{
			name: "expired",
			tok:  mkJWS(t, goodHdr(), map[string]any{"iss": srv.URL, "sub": "a", "exp": now.Add(-time.Hour).Unix()}, signRS256(t, priv)),
		},
		{
			name: "not-yet-valid",
			tok:  mkJWS(t, goodHdr(), map[string]any{"iss": srv.URL, "sub": "a", "exp": now.Add(time.Hour).Unix(), "nbf": now.Add(time.Hour).Unix()}, signRS256(t, priv)),
		},
		{
			name: "kid-miss",
			tok:  mkJWS(t, map[string]any{"alg": "RS256", "kid": "unknown-kid", "typ": "JWT"}, goodClaims(), signRS256(t, priv)),
		},
		{
			name: "alg-none",
			tok:  mkJWS(t, map[string]any{"alg": "none", "kid": testSSOKid}, goodClaims(), nil),
		},
		{
			name: "disallowed-alg",
			tok:  mkJWS(t, map[string]any{"alg": "HS256", "kid": testSSOKid}, goodClaims(), func(b []byte) []byte { return []byte("mac") }),
		},
		{
			name: "typ-confusion",
			tok:  mkJWS(t, map[string]any{"alg": "RS256", "kid": testSSOKid, "typ": "at+jwt"}, goodClaims(), signRS256(t, priv)),
		},
		{
			name: "crit-header",
			tok:  mkJWS(t, map[string]any{"alg": "RS256", "kid": testSSOKid, "typ": "JWT", "crit": []string{"exp"}}, goodClaims(), signRS256(t, priv)),
		},
		{
			name: "missing-kid",
			tok:  mkJWS(t, map[string]any{"alg": "RS256", "typ": "JWT"}, goodClaims(), signRS256(t, priv)),
		},
		{
			name:     "audience-mismatch",
			tok:      mkJWS(t, goodHdr(), map[string]any{"iss": srv.URL, "sub": "a", "exp": now.Add(time.Hour).Unix(), "aud": "some-other-client"}, signRS256(t, priv)),
			audience: "the-expected-client",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := &liveSSOVerifier{issuerURL: srv.URL, live: true, httpClient: srv.Client(), now: ssoFixedClock(now), audience: tc.audience}
			principal, ok, err := v.Verify(context.Background(), "sess-1", tc.tok)
			if ok || principal != "" {
				t.Fatalf("%s accepted: principal=%q ok=%v; want a refusal (fail-closed)", tc.name, principal, ok)
			}
			if tc.wantFault && err == nil {
				t.Fatalf("%s: err = nil; want a surfaced transient fault", tc.name)
			}
			if !tc.wantFault && err != nil {
				t.Fatalf("%s: err = %v; want a clean ok=false refusal (nil err)", tc.name, err)
			}
		})
	}
}

// TestLiveSSOVerifier_EnforcesAudienceWhenConfigured pins the aud arm accepting side: with
// DS_ORCH_SSO_AUDIENCE configured, a token whose aud CONTAINS it is accepted (array form).
func TestLiveSSOVerifier_EnforcesAudienceWhenConfigured(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen RSA: %v", err)
	}
	srv := startIssuer(t, []map[string]any{rsaJWK(&priv.PublicKey)})
	now := time.Unix(1_700_000_000, 0)
	tok := mkJWS(t,
		map[string]any{"alg": "RS256", "kid": testSSOKid, "typ": "JWT"},
		map[string]any{"iss": srv.URL, "sub": "alice@org", "exp": now.Add(time.Hour).Unix(), "aud": []string{"other", "the-client"}},
		signRS256(t, priv))

	v := &liveSSOVerifier{issuerURL: srv.URL, live: true, httpClient: srv.Client(), now: ssoFixedClock(now), audience: "the-client"}
	principal, ok, err := v.Verify(context.Background(), "sess-1", tok)
	if err != nil || !ok || principal != "alice@org" {
		t.Fatalf("aud-array accept: principal=%q ok=%v err=%v; want alice@org,true,nil", principal, ok, err)
	}
}

// TestLiveSSOVerifier_DiscoveryFailureSurfacesFault pins the transient-fault arm: an
// unreachable/erroring issuer is a SURFACED fault (non-nil err ⇒ handler Unavailable), never
// a silent accept.
func TestLiveSSOVerifier_DiscoveryFailureSurfacesFault(t *testing.T) {
	// A server that 500s the discovery endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	now := time.Unix(1_700_000_000, 0)
	v := &liveSSOVerifier{issuerURL: srv.URL, live: true, httpClient: srv.Client(), now: ssoFixedClock(now)}
	_, ok, err := v.Verify(context.Background(), "sess-1", shapeValidToken(t))
	if ok {
		t.Fatal("discovery-failure arm accepted; want fail-closed")
	}
	if err == nil {
		t.Fatal("discovery-failure arm err = nil; want a surfaced transient fault")
	}
}

// TestLiveSSOVerifier_JWKSFetchFailureSurfacesFault pins the OTHER transient-fault arm:
// discovery succeeds but the JWKS endpoint faults — a SURFACED fault (non-nil err ⇒ handler
// Unavailable), never a silent accept (no key ⇒ no verified assertion ⇒ no seat).
func TestLiveSSOVerifier_JWKSFetchFailureSurfacesFault(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "jwks_uri": srv.URL + "/jwks"})
		default:
			http.Error(w, "jwks down", http.StatusInternalServerError)
		}
	}))
	t.Cleanup(srv.Close)
	now := time.Unix(1_700_000_000, 0)
	v := &liveSSOVerifier{issuerURL: srv.URL, live: true, httpClient: srv.Client(), now: ssoFixedClock(now)}
	_, ok, err := v.Verify(context.Background(), "sess-1", shapeValidToken(t))
	if ok {
		t.Fatal("JWKS-fetch-failure arm accepted; want fail-closed")
	}
	if err == nil {
		t.Fatal("JWKS-fetch-failure arm err = nil; want a surfaced transient fault")
	}
	if !strings.Contains(err.Error(), "JWKS") {
		t.Fatalf("JWKS-fetch-failure err = %v; want the JWKS fetch fault surfaced", err)
	}
}

// TestLiveSSOVerifier_DiscoveryIssuerMismatchFails pins the issuer-confusion defense: if the
// discovery doc's own issuer disagrees with the configured issuerURL, the verify faults.
func TestLiveSSOVerifier_DiscoveryIssuerMismatchFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://someone-else.example", "jwks_uri": "https://someone-else.example/jwks"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	now := time.Unix(1_700_000_000, 0)
	v := &liveSSOVerifier{issuerURL: srv.URL, live: true, httpClient: srv.Client(), now: ssoFixedClock(now)}
	_, ok, err := v.Verify(context.Background(), "sess-1", shapeValidToken(t))
	if ok || err == nil {
		t.Fatalf("issuer-mismatch arm: ok=%v err=%v; want false + a surfaced fault", ok, err)
	}
}

// TestResolveWriterIdentityValidator_SSOIssuerSelectsDialedValidator pins the wiring
// precedence: DS_ORCH_SSO_ISSUER selects the PRODUCTION dialed SSO validator (over the fake
// gate), it reports the typed writerIdentityDialedSSO mode (main.go's log discriminator), and
// — DS_ORCH_SSO_LIVE unset ⇒ unarmed — it fails CLOSED (a fault surfaced) on a shape-valid
// assertion rather than granting a seat.
func TestResolveWriterIdentityValidator_SSOIssuerSelectsDialedValidator(t *testing.T) {
	v, mode, err := resolveWriterIdentityValidator(envMap(map[string]string{
		"DS_ORCH_SSO_ISSUER": "https://sso.example/realm",
		// The fake gate is set too — the SSO issuer must take precedence (production intent).
		"DS_ORCH_FAKE_IDENTITY": "1",
	}))
	if err != nil {
		t.Fatalf("resolve err: %v", err)
	}
	if v == nil {
		t.Fatal("DS_ORCH_SSO_ISSUER resolved a nil validator; want the dialed SSO validator")
	}
	if mode != writerIdentityDialedSSO {
		// main.go's liveDeps dispatches its log line on this typed mode — keep them pinned
		// together so the loud dev-box MVP warning is never suppressed by a mode drift.
		t.Fatalf("mode = %v; want writerIdentityDialedSSO (main.go's log discriminator)", mode)
	}
	// Unarmed (DS_ORCH_SSO_LIVE unset): fail-closed with a surfaced fault on a shape-valid token.
	if _, ok, verr := v.ValidateAssertion(context.Background(), "sess-1", shapeValidToken(t)); ok || verr == nil {
		t.Fatalf("dialed SSO validator granted/soft-failed: ok=%v err=%v; want false + surfaced fault (unarmed)", ok, verr)
	}
}
