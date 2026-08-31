// SPDX-License-Identifier: Apache-2.0

// Contract tests for the TWO GENERATED Stage-0 grpc seams, exercised over an
// in-process grpc client exactly like identity/fakes/digest-publisher's
// publisher_test.go (the precedent). These prove the shim's server adapters
// satisfy the frozen IdentityValidationService / IdentityMintService interfaces
// and round-trip the frozen request/response shapes. Everything synthetic (D50).
package mint

import (
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// dialInProcess registers both generated servers on an in-memory bufconn.Listener
// and returns clients for them, mirroring the digest-publisher in-process
// pattern. The transport is an in-memory pipe (no real socket bind, never
// loopback TCP), so the seam round-trip runs in a hardened CI sandbox with no
// network namespace.
func dialInProcess(t *testing.T, shim *Shim) (identityv1.IdentityValidationServiceClient, identityv1.IdentityMintServiceClient) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	identityv1.RegisterIdentityValidationServiceServer(srv, NewValidationServer(shim))
	identityv1.RegisterIdentityMintServiceServer(srv, NewMintServer(shim))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return identityv1.NewIdentityValidationServiceClient(conn), identityv1.NewIdentityMintServiceClient(conn)
}

const (
	testOrg     = "acme"
	testSession = "00000000-0000-4000-8000-000000000a01"
	testSvc     = "github"
)

// TestMintInterceptionCASeam exercises the generated MintInterceptionCA seam
// over the in-process client and checks the frozen response shape: a non-empty
// CA cert + proxy-bound key + a session-lifetime expiry.
func TestMintInterceptionCASeam(t *testing.T) {
	shim := newTestShim(t)
	_, mintClient := dialInProcess(t, shim)

	resp, err := mintClient.MintInterceptionCA(context.Background(), &identityv1.MintInterceptionCARequest{
		SessionRef: &boundaryv1.SessionRef{SessionUuid: testSession},
	})
	if err != nil {
		t.Fatalf("MintInterceptionCA: %v", err)
	}
	if len(resp.GetCaCertificate()) == 0 {
		t.Fatal("empty ca_certificate")
	}
	if len(resp.GetCaPrivateKey()) == 0 {
		t.Fatal("empty ca_private_key (proxy-bound delivery material)")
	}
	// Expiry must be ahead of the shim's OWN clock (a session-lifetime horizon),
	// not the test process wall clock — the shim runs on a pinned fixture instant
	// (newTestShim), so comparing against time.Now() is a wall-clock time bomb that
	// flips RED once real time passes the fixture's TTL horizon.
	if resp.GetExpiryUnixSeconds() <= shim.now().Unix() {
		t.Fatalf("expiry not ahead of the shim clock: %d", resp.GetExpiryUnixSeconds())
	}
}

// TestValidateSeamAllowAndDeny exercises the generated Validate seam over the
// in-process client across the ALLOW path and the DENY (D77 in-band-403) path,
// checking the frozen ValidateResponse shape both ways.
func TestValidateSeamAllowAndDeny(t *testing.T) {
	shim := newTestShim(t)
	validateClient, _ := dialInProcess(t, shim)

	// Mint a workload identity (native) so a valid token exists, and grant the
	// service so the lookup passes.
	bundle, err := shim.MintWorkloadIdentity(WorkloadIdentityRequest{
		SessionUUID: testSession, Org: testOrg, RepoBranch: "main", Runtime: "claude-code",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := shim.GrantSession(testSession, testSvc, "grant-ref-1"); err != nil {
		t.Fatal(err)
	}

	// ALLOW.
	allow, err := validateClient.Validate(context.Background(), &identityv1.ValidateRequest{
		PresentedCredential: []byte(bundle.JWT),
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: testSession},
		ServiceId:           testSvc,
	})
	if err != nil {
		t.Fatalf("Validate(allow): %v", err)
	}
	if allow.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("want ALLOW, got %v (reason=%q)", allow.GetVerdict(), allow.GetMachineReadableReason())
	}
	if allow.GetGrantRef() != "grant-ref-1" {
		t.Fatalf("grant_ref lost: %q", allow.GetGrantRef())
	}

	// DENY: a service with no grant fails closed with a machine-readable reason,
	// carried in-band (never a transport error — the D77 403 shape).
	deny, err := validateClient.Validate(context.Background(), &identityv1.ValidateRequest{
		PresentedCredential: []byte(bundle.JWT),
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: testSession},
		ServiceId:           "unauthorized-service",
	})
	if err != nil {
		t.Fatalf("Validate(deny) returned a transport error, not an in-band 403: %v", err)
	}
	if deny.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY {
		t.Fatalf("want DENY, got %v", deny.GetVerdict())
	}
	if deny.GetMachineReadableReason() != ReasonOutOfGrant {
		t.Fatalf("want %q, got %q", ReasonOutOfGrant, deny.GetMachineReadableReason())
	}
}

// TestMintWorkloadIdentitySeam exercises the promoted MintWorkloadIdentity RPC
// (D111; doc 16 §3.1) over the in-process client and checks the response shape:
// a non-empty cert (hierarchy 1) + SPIFFE-compatible URI SAN + parallel JWT + a
// session-lifetime expiry. It also proves the wire-delivered JWT is usable at the
// Validate seam over the same wire (the mint registered the workload key on the
// session record), so the four-method surface composes.
func TestMintWorkloadIdentitySeam(t *testing.T) {
	shim := newTestShim(t)
	validateClient, mintClient := dialInProcess(t, shim)

	resp, err := mintClient.MintWorkloadIdentity(context.Background(), &identityv1.MintWorkloadIdentityRequest{
		SessionUuid:   testSession,
		LaunchingUser: "idp-subject-xyz",
		Org:           testOrg,
		RepoBranch:    "acme/app@main",
		Runtime:       "claude-code",
		ParentSession: "00000000-0000-4000-8000-0000000000pp",
	})
	if err != nil {
		t.Fatalf("MintWorkloadIdentity: %v", err)
	}
	if len(resp.GetCertDer()) == 0 {
		t.Fatal("empty cert_der (hierarchy-1 workload leaf)")
	}
	wantURI := "spiffe://" + testOrg + "/session/" + testSession
	if resp.GetSpiffeUri() != wantURI {
		t.Fatalf("spiffe_uri = %q, want %q", resp.GetSpiffeUri(), wantURI)
	}
	if len(resp.GetJwt()) == 0 {
		t.Fatal("empty jwt (parallel presentation)")
	}
	// Session-lifetime horizon ahead of the shim's pinned clock (not wall clock).
	if resp.GetExpiryUnixSeconds() <= shim.now().Unix() {
		t.Fatalf("expiry not ahead of the shim clock: %d", resp.GetExpiryUnixSeconds())
	}

	// The minted JWT validates over the wire once the service is granted — the
	// mint registered the workload key on the session record, so the D22 seam
	// accepts the parallel presentation.
	if err := shim.GrantSession(testSession, testSvc, "grant-ref-wl"); err != nil {
		t.Fatal(err)
	}
	allow, err := validateClient.Validate(context.Background(), &identityv1.ValidateRequest{
		PresentedCredential: []byte(resp.GetJwt()),
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: testSession},
		ServiceId:           testSvc,
	})
	if err != nil {
		t.Fatalf("Validate(wire-minted JWT): %v", err)
	}
	if allow.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("wire-minted workload JWT did not ALLOW: %v (reason=%q)", allow.GetVerdict(), allow.GetMachineReadableReason())
	}
}

// TestMintGrantsSeam exercises the promoted MintGrants RPC (D111; doc 16 §5.1)
// over the in-process client: it issues the deterministic grant set from the env
// spec intersected with the shim-installed registry and checks the wire GrantSet
// shape — the typed Grant (identity × service × scope × TTL), the SESSION scope
// (the enum zero-value shift: native iota-0 ScopeSession → proto value 1), the
// derived ISSUED{service_id} cred_class digest tag, and the per-service
// placeholder token. A service absent from the registry confers no grant
// (fail-closed). The minted placeholder then validates over the wire for ITS
// service and nothing else (the §5.1 grant-presentation contract over the seam).
func TestMintGrantsSeam(t *testing.T) {
	reg, err := NewServiceRegistry(ServiceRegistryEntry{
		ServiceID:          testSvc,
		Destinations:       []string{"github.com"},
		CredentialLocation: "Authorization",
		DefaultTTL:         time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	shim, err := NewShim(WithClock(func() time.Time { return fixed }), WithServiceRegistry(reg))
	if err != nil {
		t.Fatal(err)
	}
	validateClient, mintClient := dialInProcess(t, shim)

	// A workload identity first, so the grant's identity axis is the SPIFFE name
	// and the TTL can clamp to the session expiry (the IssueGrants contract).
	if _, err := mintClient.MintWorkloadIdentity(context.Background(), &identityv1.MintWorkloadIdentityRequest{
		SessionUuid: testSession, Org: testOrg,
	}); err != nil {
		t.Fatalf("MintWorkloadIdentity: %v", err)
	}

	set, err := mintClient.MintGrants(context.Background(), &identityv1.MintGrantsRequest{
		SessionUuid: testSession,
		Env:         &identityv1.EnvSpec{Services: []string{testSvc, "not-in-registry"}},
	})
	if err != nil {
		t.Fatalf("MintGrants: %v", err)
	}
	if len(set.GetGrants()) != 1 {
		t.Fatalf("want exactly 1 grant (the registry capability; the unregistered service fails closed), got %d", len(set.GetGrants()))
	}
	g := set.GetGrants()[0]
	if g.GetServiceId() != testSvc {
		t.Fatalf("grant service_id = %q, want %q", g.GetServiceId(), testSvc)
	}
	if g.GetScope() != identityv1.GrantScope_GRANT_SCOPE_SESSION {
		t.Fatalf("grant scope = %v, want GRANT_SCOPE_SESSION (the enum zero-value shift)", g.GetScope())
	}
	if want := "ISSUED{" + testSvc + "}"; g.GetCredClassDigestTag() != want {
		t.Fatalf("cred_class_digest_tag = %q, want %q (derived from the grant record)", g.GetCredClassDigestTag(), want)
	}
	if g.GetGrantRef() == "" {
		t.Fatal("empty grant_ref (the §9 fetch key)")
	}
	if len(set.GetPlaceholders()) != 1 {
		t.Fatalf("want 1 placeholder token, got %d", len(set.GetPlaceholders()))
	}
	ph := set.GetPlaceholders()[0]
	if ph.GetServiceId() != testSvc || len(ph.GetToken()) == 0 {
		t.Fatalf("placeholder malformed: service=%q token_len=%d", ph.GetServiceId(), len(ph.GetToken()))
	}

	// The wire placeholder validates for ITS service over the wire ...
	allow, err := validateClient.Validate(context.Background(), &identityv1.ValidateRequest{
		PresentedCredential: ph.GetToken(),
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: testSession},
		ServiceId:           testSvc,
	})
	if err != nil {
		t.Fatalf("Validate(placeholder): %v", err)
	}
	if allow.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("wire placeholder did not ALLOW for its service: %v (reason=%q)", allow.GetVerdict(), allow.GetMachineReadableReason())
	}
	if allow.GetGrantRef() != g.GetGrantRef() {
		t.Fatalf("placeholder grant_ref = %q, want %q", allow.GetGrantRef(), g.GetGrantRef())
	}
}

// TestRevokeSessionSeam exercises the promoted RevokeSession RPC (D111; doc 16
// §5.4) over the in-process client: an ALLOW-ing session is revoked over the
// wire, after which Validate over the SAME wire fails CLOSED with the
// operator-supplied machine-readable reason carried in-band (the D77 403 shape,
// never a transport error) — active eviction as revocation.
func TestRevokeSessionSeam(t *testing.T) {
	shim := newTestShim(t)
	validateClient, mintClient := dialInProcess(t, shim)

	bundle, err := mintClient.MintWorkloadIdentity(context.Background(), &identityv1.MintWorkloadIdentityRequest{
		SessionUuid: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatalf("MintWorkloadIdentity: %v", err)
	}
	if err := shim.GrantSession(testSession, testSvc, "grant-ref-revoke"); err != nil {
		t.Fatal(err)
	}

	// Pre-revoke: ALLOW.
	pre, err := validateClient.Validate(context.Background(), &identityv1.ValidateRequest{
		PresentedCredential: []byte(bundle.GetJwt()),
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: testSession},
		ServiceId:           testSvc,
	})
	if err != nil {
		t.Fatalf("Validate(pre-revoke): %v", err)
	}
	if pre.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_ALLOW {
		t.Fatalf("pre-revoke want ALLOW, got %v", pre.GetVerdict())
	}

	// Revoke over the wire — the ack is non-error, never a transport fault.
	const reason = "admin_evicted_for_test"
	if _, err := mintClient.RevokeSession(context.Background(), &identityv1.RevokeSessionRequest{
		SessionUuid: testSession, Reason: reason,
	}); err != nil {
		t.Fatalf("RevokeSession returned a transport error: %v", err)
	}

	// Post-revoke: Validate fails CLOSED with the verbatim reason, in-band.
	post, err := validateClient.Validate(context.Background(), &identityv1.ValidateRequest{
		PresentedCredential: []byte(bundle.GetJwt()),
		SessionRef:          &boundaryv1.SessionRef{SessionUuid: testSession},
		ServiceId:           testSvc,
	})
	if err != nil {
		t.Fatalf("Validate(post-revoke) returned a transport error, not an in-band 403: %v", err)
	}
	if post.GetVerdict() != identityv1.ValidateVerdict_VALIDATE_VERDICT_DENY {
		t.Fatalf("post-revoke want DENY (fail closed), got %v", post.GetVerdict())
	}
	if post.GetMachineReadableReason() != reason {
		t.Fatalf("post-revoke reason = %q, want the operator-supplied %q", post.GetMachineReadableReason(), reason)
	}
}

// TestPerSessionCAIsolationOverWire re-runs the doc 16 §13 per-session-CA-
// isolation property over the WIRE: two sessions each mint an interception CA via
// the grpc client, and a per-origin leaf built under one session's wire-delivered
// CA never validates against the other session's per-session root (and vice
// versa). The wire-delivered CA material preserves the isolation the native test
// (TestPerSessionCAIsolation) proves directly.
func TestPerSessionCAIsolationOverWire(t *testing.T) {
	shim := newTestShim(t)
	_, mintClient := dialInProcess(t, shim)
	sessionA := "00000000-0000-4000-8000-00000000000a"
	sessionB := "00000000-0000-4000-8000-00000000000b"

	respA, err := mintClient.MintInterceptionCA(context.Background(), &identityv1.MintInterceptionCARequest{
		SessionRef: &boundaryv1.SessionRef{SessionUuid: sessionA},
	})
	if err != nil {
		t.Fatalf("MintInterceptionCA(A): %v", err)
	}
	respB, err := mintClient.MintInterceptionCA(context.Background(), &identityv1.MintInterceptionCARequest{
		SessionRef: &boundaryv1.SessionRef{SessionUuid: sessionB},
	})
	if err != nil {
		t.Fatalf("MintInterceptionCA(B): %v", err)
	}

	// Build a per-origin leaf under each session's WIRE-delivered CA material.
	caA := &InterceptionCABundle{CACertDER: respA.GetCaCertificate(), CAKeyDER: respA.GetCaPrivateKey()}
	caB := &InterceptionCABundle{CACertDER: respB.GetCaCertificate(), CAKeyDER: respB.GetCaPrivateKey()}
	leafA := mintOriginLeaf(t, caA, "github.com")
	leafB := mintOriginLeaf(t, caB, "github.com")

	poolA := sessionVerifyOpts(t, shim.InterceptionRootDER(sessionA), caA.CACertDER)
	poolB := sessionVerifyOpts(t, shim.InterceptionRootDER(sessionB), caB.CACertDER)

	if _, err := leafA.Verify(poolA); err != nil {
		t.Fatalf("session-A leaf should verify under session-A pool: %v", err)
	}
	if _, err := leafB.Verify(poolB); err != nil {
		t.Fatalf("session-B leaf should verify under session-B pool: %v", err)
	}
	if _, err := leafA.Verify(poolB); err == nil {
		t.Fatal("ISOLATION BREACH (over wire): session-A leaf validated against session-B CA")
	}
	if _, err := leafB.Verify(poolA); err == nil {
		t.Fatal("ISOLATION BREACH (over wire): session-B leaf validated against session-A CA")
	}
}

// TestHierarchySeparationOverWire re-runs the doc 16 §13 hierarchy-separation
// property (D82) over the WIRE: the workload leaf (from MintWorkloadIdentity over
// the wire, hierarchy 1) and the interception CA (from MintInterceptionCA over
// the wire, hierarchy 2) are structurally disjoint — neither pool accepts the
// other's wire-delivered material. This is the four-method surface's strongest
// assurance row, proven over the grpc seam rather than against the in-process
// shim.
func TestHierarchySeparationOverWire(t *testing.T) {
	shim := newTestShim(t)
	_, mintClient := dialInProcess(t, shim)

	wlResp, err := mintClient.MintWorkloadIdentity(context.Background(), &identityv1.MintWorkloadIdentityRequest{
		SessionUuid: testSession, Org: testOrg,
	})
	if err != nil {
		t.Fatalf("MintWorkloadIdentity: %v", err)
	}
	caResp, err := mintClient.MintInterceptionCA(context.Background(), &identityv1.MintInterceptionCARequest{
		SessionRef: &boundaryv1.SessionRef{SessionUuid: testSession},
	})
	if err != nil {
		t.Fatalf("MintInterceptionCA: %v", err)
	}

	ca := &InterceptionCABundle{CACertDER: caResp.GetCaCertificate(), CAKeyDER: caResp.GetCaPrivateKey()}
	interceptionLeaf := mintOriginLeaf(t, ca, "github.com")

	workloadPool := poolFromDER(t, shim.WorkloadRootDER())
	interceptionPool := sessionVerifyOpts(t, shim.InterceptionRootDER(testSession), ca.CACertDER)

	// An interception-hierarchy leaf must NEVER validate as workload identity.
	if _, err := interceptionLeaf.Verify(x509.VerifyOptions{
		Roots:       workloadPool,
		CurrentTime: shim.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		t.Fatal("SEPARATION BREACH (over wire): interception-hierarchy cert validated as workload identity")
	}

	// The wire-delivered workload leaf must NEVER validate against the interception root.
	wlLeaf, err := x509.ParseCertificate(wlResp.GetCertDer())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wlLeaf.Verify(interceptionPool); err == nil {
		t.Fatal("SEPARATION BREACH (over wire): workload leaf validated against the interception root")
	}

	// The wire-delivered interception CA cert must not chain to the workload root.
	caCert, err := x509.ParseCertificate(ca.CACertDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := caCert.Verify(x509.VerifyOptions{
		Roots:       workloadPool,
		CurrentTime: shim.now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err == nil {
		t.Fatal("SEPARATION BREACH (over wire): interception CA chained to the workload root")
	}
}

// TestMintSessionTokenSeam exercises the promoted MintSessionToken RPC (D111; doc
// 19 §3, D99/D97) over the in-process client and checks the SessionTokenBundle
// response shape: a non-empty format-opaque token, a session-lifetime expiry ahead
// of the shim's PINNED clock (not wall clock — newTestShim runs on a fixture
// instant), the echoed root session_uuid, attenuation_depth == 0 for the base
// token, and at least one §7 fleet revocation_id. newTestShim's NewShim
// auto-installs the default Biscuit substrate signer, so no extra setup is needed.
func TestMintSessionTokenSeam(t *testing.T) {
	shim := newTestShim(t)
	_, mintClient := dialInProcess(t, shim)

	resp, err := mintClient.MintSessionToken(context.Background(), &identityv1.MintSessionTokenRequest{
		SessionUuid:   testSession,
		LaunchingUser: "idp-subject-token",
		Org:           testOrg,
		RepoBranch:    "acme/app@main",
		Services:      []string{testSvc},
	})
	if err != nil {
		t.Fatalf("MintSessionToken: %v", err)
	}
	if len(resp.GetToken()) == 0 {
		t.Fatal("empty token (the format-opaque presented credential, doc 19 §5)")
	}
	// Session-lifetime horizon ahead of the shim's pinned clock (not wall clock —
	// the pinned-fixture rule: comparing against time.Now() is a wall-clock time
	// bomb that flips RED once real time passes the fixture's TTL horizon).
	if resp.GetExpiryUnixSeconds() <= shim.now().Unix() {
		t.Fatalf("expiry not ahead of the shim clock: %d", resp.GetExpiryUnixSeconds())
	}
	if resp.GetSessionUuid() != testSession {
		t.Fatalf("session_uuid echo = %q, want %q (the root scoping claim)", resp.GetSessionUuid(), testSession)
	}
	if resp.GetAttenuationDepth() != 0 {
		t.Fatalf("attenuation_depth = %d, want 0 for the base token (doc 19 §4)", resp.GetAttenuationDepth())
	}
	if len(resp.GetRevocationIds()) == 0 {
		t.Fatal("empty revocation_ids (the §7 fleet revocation identifiers; one for the base token)")
	}
}
