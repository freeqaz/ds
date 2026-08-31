package main

// identity_mtls_test.go pins the orchestrator→Identity dial's transport posture wired by
// liveDeps (main.go): the SAME env-driven mTLS selection the host-driver dial uses now
// threads onto controlplane.NewIdentityClients's variadic DialOption tail (D22/D82 — the
// Identity service is the separate D22 service, the edge carries D82 mint/CA traffic). It
// proves BOTH branches with SYNTHETIC in-test certs and NO live dial (D50: grpc.NewClient is
// lazy, so liveDeps constructs the Identity clients without opening a socket):
//
//   - UNSET default: with NONE of DS_ORCH_TLS_CERT/KEY/CA set, liveDeps threads an EMPTY
//     dial-option tail, so NewIdentityClients keeps its internal, network-isolated INSECURE
//     transport (doc 15 §2 — the orchestrator↔Identity link runs inside the isolated
//     control-plane network); the live path still constructs end-to-end.
//   - SET mTLS: with the full DS_ORCH_TLS_CERT/KEY/CA triplet set (the same triplet the
//     host-driver dial reads), liveDeps builds the transport-credentials DialOption via
//     liveDialOpts and threads it onto NewIdentityClients — so a deployment fronting
//     the edge with TLS-termination/mTLS gets the mutually-authenticated transport rather
//     than the insecure default, additively (no constructor-signature break).
//
// The synthetic cert helper (writeSyntheticMTLS) + the mismatch helpers live in mtls_test.go
// (same package main); no real certs/keys ever touch the tree (D50).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
)

// bufconnMTLSServerName is the dial authority + the server cert's SAN the bufconn mutual-TLS
// handshake tests pin against: the orchestrator's RootCAs verification matches the server cert
// to this name, exactly as a real internal-fabric peer's server cert would carry its name.
const bufconnMTLSServerName = "bufnet"

// startBufconnMTLSServer stands up an in-memory bufconn gRPC server that REQUIRES mutual TLS:
// it presents serverCert (signed by the synthetic CA) and pins the client cert against caPool
// (tls.RequireAndVerifyClientCert) — so only a client presenting a cert chaining to that CA
// completes the handshake. The standard gRPC health service is registered so a test can drive
// a real RPC over the wire (the RPC is what forces the TLS handshake to actually negotiate end
// to end; the connection is lazy until the first call). Returns the listener for context-dialed
// clients; the server is stopped on cleanup. No socket / port bind (D50 — in-memory only).
func startBufconnMTLSServer(t *testing.T, serverCert tls.Certificate, caPool *x509.CertPool) *bufconn.Listener {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srvCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	})
	srv := grpc.NewServer(grpc.Creds(srvCreds))
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis
}

// dialBufconnMTLS dials the bufconn listener with the supplied transport-credentials DialOption
// (the orchestrator's live-dial mTLS option, built by liveDialOpts/MTLSDialOptionFromEnv from
// the synthetic env triplet) and drives a real Health/Check RPC, returning its error — nil iff
// the mutual-TLS handshake negotiated end to end. The dial target authority is
// bufconnMTLSServerName so the client's RootCAs verification matches the server cert's SAN; the
// context-dialer routes onto the in-memory bufconn (no socket, D50). grpc.NewClient is lazy, so
// the handshake happens on the RPC, not the dial — the RPC is what proves the handshake.
func dialBufconnMTLS(t *testing.T, lis *bufconn.Listener, dialOpt grpc.DialOption) error {
	t.Helper()
	conn, err := grpc.NewClient(
		"passthrough:///"+bufconnMTLSServerName,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		dialOpt,
	)
	if err != nil {
		t.Fatalf("construct bufconn mTLS client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, rpcErr := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return rpcErr
}

// liveDepsWithStubEnv runs liveDeps with a configured (un-dialed) Identity endpoint + a
// single host-driver endpoint and the in-memory store (no Postgres DSN), so the live path
// constructs without ever opening a socket (grpc.NewClient is lazy; NewDialRegistry does not
// dial eagerly — D50). The mTLS triplet is left to the caller's t.Setenv. It returns the
// resolved Deps so a test can assert the Identity seams were built; the closer tears the
// (un-dialed) edges down.
func liveDepsWithStubEnv(t *testing.T) controlplane.Deps {
	t.Helper()
	// A configured (un-dialed) Identity endpoint so liveDeps's empty-endpoint guard passes;
	// grpc.NewClient is lazy so no socket opens. A single host-driver endpoint so the registry
	// has a resolvable host (still never dialed). No Postgres DSN → the in-memory store.
	t.Setenv("DS_ORCH_IDENTITY_ENDPOINT", "passthrough:///identity-stub")
	t.Setenv("DS_ORCH_HOST_DRIVERS", "host-a=host:9000")
	t.Setenv("DS_ORCH_PG_DSN", "")

	deps, closeEdges, err := liveDeps(context.Background())
	if err != nil {
		t.Fatalf("liveDeps with stub identity endpoint: %v", err)
	}
	t.Cleanup(func() {
		if cerr := closeEdges(); cerr != nil {
			t.Errorf("close live edges: %v", cerr)
		}
	})
	return deps
}

// TestLiveDeps_IdentityDialUnsetKeepsInsecureDefault pins the UNSET-default branch of the
// orchestrator→Identity dial: with NONE of the DS_ORCH_TLS_* triplet set, liveDeps threads
// an empty dial-option tail into NewIdentityClients, so the internal, network-isolated link
// keeps its insecure default (doc 15 §2). The Identity seams are still constructed (the live
// path closes), proving the unset path is the unchanged default — NOT a fail-closed refusal.
func TestLiveDeps_IdentityDialUnsetKeepsInsecureDefault(t *testing.T) {
	t.Setenv(controlplane.EnvDialTLSCert, "")
	t.Setenv(controlplane.EnvDialTLSKey, "")
	t.Setenv(controlplane.EnvDialTLSCA, "")

	deps := liveDepsWithStubEnv(t)

	// The Identity seams were built over the (insecure-default) dial — a nil Mint seam would
	// mean liveDeps half-wired the control plane (the unset path must still close the live
	// path, just over the insecure internal-network transport).
	if deps.Mint == nil || deps.Digest == nil || deps.Revoke == nil {
		t.Fatalf("liveDeps left an Identity seam nil with the mTLS env unset: mint=%v digest=%v revoke=%v — the insecure-default path did not construct the Identity clients",
			deps.Mint != nil, deps.Digest != nil, deps.Revoke != nil)
	}
	if deps.Inject == nil || deps.Boot == nil {
		t.Fatalf("liveDeps left a host-folded seam nil with the mTLS env unset: inject=%v boot=%v",
			deps.Inject != nil, deps.Boot != nil)
	}
}

// TestLiveDeps_IdentityDialSetAppliesMTLS pins the SET-mTLS branch: with the full
// DS_ORCH_TLS_CERT/KEY/CA triplet set (synthetic in-test certs, D50), liveDeps builds the
// transport-credentials DialOption via liveDialOpts (the SAME helper + triplet the
// host-driver dial uses) and threads it onto NewIdentityClients — so the Identity edge
// carries the mutually-authenticated transport rather than the insecure default. The clients
// construct WITHOUT a live dial (grpc.NewClient is lazy); the closer tears the un-dialed conn
// down. The host-driver dial option is built from the same triplet, so threading it onto the
// Identity dial is the additive, mirrored posture (no constructor break).
func TestLiveDeps_IdentityDialSetAppliesMTLS(t *testing.T) {
	certPath, keyPath, caPath := writeSyntheticMTLS(t)
	t.Setenv(controlplane.EnvDialTLSCert, certPath)
	t.Setenv(controlplane.EnvDialTLSKey, keyPath)
	t.Setenv(controlplane.EnvDialTLSCA, caPath)

	// The same env triplet must yield a non-empty (mTLS) dial-option tail — this is exactly
	// what liveDeps threads onto NewIdentityClients for the Identity edge.
	identityDialOpts, err := liveDialOpts()
	if err != nil {
		t.Fatalf("liveDialOpts with the synthetic triplet: %v", err)
	}
	if len(identityDialOpts) != 1 || identityDialOpts[0] == nil {
		t.Fatalf("env-driven Identity dial tail = %d options, want exactly 1 non-nil mTLS transport option (the same the host-driver dial threads)", len(identityDialOpts))
	}

	// liveDeps must thread that option in and construct the Identity seams WITHOUT a live dial
	// (the credentials are built from the synthetic certs; grpc.NewClient does not dial eagerly).
	deps := liveDepsWithStubEnv(t)
	if deps.Mint == nil || deps.Digest == nil || deps.Revoke == nil {
		t.Fatalf("liveDeps left an Identity seam nil with the mTLS triplet set: mint=%v digest=%v revoke=%v — the mTLS path did not construct the Identity clients",
			deps.Mint != nil, deps.Digest != nil, deps.Revoke != nil)
	}
}

// TestLiveDeps_IdentityDialPartialIsHardError proves a HALF-configured triplet (cert set,
// key/CA missing) surfaces as a hard error from liveDeps for the Identity edge too — a live
// run fails loudly at construction rather than silently downgrading the orchestrator→Identity
// transport to insecure. This mirrors the host-driver edge's fail-loud contract (the SAME
// liveDialOpts misconfiguration check guards both dials).
func TestLiveDeps_IdentityDialPartialIsHardError(t *testing.T) {
	certPath, _, _ := writeSyntheticMTLS(t)
	t.Setenv(controlplane.EnvDialTLSCert, certPath)
	t.Setenv(controlplane.EnvDialTLSKey, "")
	t.Setenv(controlplane.EnvDialTLSCA, "")
	// A configured Identity endpoint + host-driver endpoint so the failure is the mTLS
	// triplet, not a missing endpoint; no Postgres DSN → in-memory store.
	t.Setenv("DS_ORCH_IDENTITY_ENDPOINT", "passthrough:///identity-stub")
	t.Setenv("DS_ORCH_HOST_DRIVERS", "host-a=host:9000")
	t.Setenv("DS_ORCH_PG_DSN", "")

	_, closeEdges, err := liveDeps(context.Background())
	if err == nil {
		if closeEdges != nil {
			_ = closeEdges()
		}
		t.Fatal("liveDeps with a partial mTLS triplet: expected a hard error (loud fail at construction), got nil")
	}
}

// TestBufconnMTLS_OrchestratorDialNegotiatesHandshake is the load-bearing pin this unit adds:
// it proves the orchestrator's UNIFIED live-dial mTLS source — liveDialOpts (which composes
// controlplane.MTLSDialOptionFromEnv from the DS_ORCH_TLS_* triplet, the SAME option liveDeps
// threads into BOTH the Identity D22/D82 dial and the host-driver registry dial) — actually
// NEGOTIATES a mutual-TLS handshake end to end, not merely that the DialOption is constructed.
// A bufconn gRPC server REQUIRING mutual TLS (server cert + RequireAndVerifyClientCert against
// the same synthetic CA) is stood up; the orchestrator dial option drives a real Health/Check
// RPC over the in-memory transport; the RPC succeeding proves the handshake completed — the
// client presented its cert, the server's cert verified against the client's pinned RootCAs,
// and the server verified the client's cert against its clientauth pool. Synthetic certs only,
// no live network edge (D50). This closes the residual gap the identity-dial-mtls-posture work
// flagged: grpc exposes no accessor for an un-dialed conn's transport creds, so only a real
// handshake can confirm the option negotiates mTLS rather than just being present.
func TestBufconnMTLS_OrchestratorDialNegotiatesHandshake(t *testing.T) {
	m := writeSyntheticMTLSHandshake(t, bufconnMTLSServerName)
	// Point the env at the synthetic client triplet so the orchestrator's ONE unified dial
	// source builds exactly the client credentials used here — the Identity and host-driver
	// dials draw from this same liveDialOpts source.
	t.Setenv(controlplane.EnvDialTLSCert, m.clientCertPath)
	t.Setenv(controlplane.EnvDialTLSKey, m.clientKeyPath)
	t.Setenv(controlplane.EnvDialTLSCA, m.caPath)

	opts, err := liveDialOpts()
	if err != nil {
		t.Fatalf("liveDialOpts with the synthetic triplet: %v", err)
	}
	if len(opts) != 1 || opts[0] == nil {
		t.Fatalf("liveDialOpts = %d options, want exactly 1 non-nil mTLS transport option (the unified dial source)", len(opts))
	}

	lis := startBufconnMTLSServer(t, m.serverCert, m.caPool)
	if rpcErr := dialBufconnMTLS(t, lis, opts[0]); rpcErr != nil {
		t.Fatalf("orchestrator unified mTLS dial option failed the mutual-TLS handshake against a server requiring mTLS: %v — want the handshake to negotiate end to end", rpcErr)
	}
}

// TestBufconnMTLS_NoClientCertRejectedAtHandshake proves the server requiring mutual TLS
// REJECTS a client presenting NO certificate at the handshake: the client trusts the server's
// CA (so server-cert verification would pass) but offers no client cert, so the server's
// RequireAndVerifyClientCert aborts the handshake and the RPC fails. This proves the mutual
// (not one-way) requirement is live — a peer that does not present the orchestrator's client
// identity cannot complete the dial.
func TestBufconnMTLS_NoClientCertRejectedAtHandshake(t *testing.T) {
	m := writeSyntheticMTLSHandshake(t, bufconnMTLSServerName)

	// A client that pins the server's CA (so it would accept the server cert) but presents NO
	// client certificate — the mutual half is missing.
	noCertCreds := credentials.NewTLS(&tls.Config{
		RootCAs:    m.caPool,
		ServerName: bufconnMTLSServerName,
		MinVersion: tls.VersionTLS12,
	})

	lis := startBufconnMTLSServer(t, m.serverCert, m.caPool)
	if rpcErr := dialBufconnMTLS(t, lis, grpc.WithTransportCredentials(noCertCreds)); rpcErr == nil {
		t.Fatal("a no-client-cert dial completed the handshake against a server requiring mutual TLS — want the handshake REJECTED (RequireAndVerifyClientCert)")
	}
}

// TestBufconnMTLS_UntrustedClientCARejectedAtHandshake proves the server REJECTS a client whose
// cert is signed by a CA the server does NOT trust: the client presents a well-formed clientauth
// leaf, but it chains to an independent (untrusted) CA, so the server's clientauth pool
// verification fails and the handshake is aborted. This proves the CA pinning is live, not
// cosmetic — only a client whose cert chains to the pinned CA negotiates mTLS.
func TestBufconnMTLS_UntrustedClientCARejectedAtHandshake(t *testing.T) {
	m := writeSyntheticMTLSHandshake(t, bufconnMTLSServerName)
	untrustedCertPath, untrustedKeyPath, _ := writeSyntheticUntrustedClient(t)

	untrustedCert, err := tls.LoadX509KeyPair(untrustedCertPath, untrustedKeyPath)
	if err != nil {
		t.Fatalf("load synthetic untrusted client keypair: %v", err)
	}
	// The untrusted client still pins the server's (trusted) CA so the failure is the SERVER
	// rejecting the client cert at clientauth, isolating the untrusted-client-CA arm.
	untrustedClientCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{untrustedCert},
		RootCAs:      m.caPool,
		ServerName:   bufconnMTLSServerName,
		MinVersion:   tls.VersionTLS12,
	})

	lis := startBufconnMTLSServer(t, m.serverCert, m.caPool)
	rpcErr := dialBufconnMTLS(t, lis, grpc.WithTransportCredentials(untrustedClientCreds))
	if rpcErr == nil {
		t.Fatal("a client cert signed by an untrusted CA completed the handshake — want the handshake REJECTED (server clientauth pool pins the CA)")
	}
	// Sanity: the rejection is a transport/handshake failure, not a missing-RPC error (the
	// health service is registered; only the handshake should block the call).
	if strings.Contains(rpcErr.Error(), "Unimplemented") {
		t.Fatalf("untrusted-CA dial failed with Unimplemented (RPC reached the server), want a handshake rejection: %v", rpcErr)
	}
}

// TestBufconnMTLS_UntrustedServerCARejectedAtHandshake is the SERVER-side mirror of
// TestBufconnMTLS_UntrustedClientCARejectedAtHandshake: it proves the orchestrator's
// CLIENT-side server-cert verification (the RootCAs/caPath pin built by liveDialOpts from the
// DS_ORCH_TLS_* triplet) is LIVE, not inert. The orchestrator dials with its TRUSTED client
// triplet (so its RootCAs pin the trusted CA), but the bufconn server presents a leaf chaining
// to an INDEPENDENT (untrusted) CA the orchestrator's caPath does NOT contain — so the client's
// RootCAs verification must REJECT the server cert and abort the handshake. The server cert
// carries the matching SAN and the server pins the orchestrator's client cert against the
// TRUSTED clientauth pool (so the client cert still verifies server-side), isolating the failure
// to the client's RootCAs check (the server's untrusted chain), not a SAN mismatch or a rejected
// client cert. Synthetic certs only, no live network (D50). Closes the one-way
// server-auth-pinning mirror gap: nothing else proved caPath/RootCAs pinning rejects an
// untrusted server.
func TestBufconnMTLS_UntrustedServerCARejectedAtHandshake(t *testing.T) {
	m := writeSyntheticMTLSHandshake(t, bufconnMTLSServerName)
	// The orchestrator dials with its TRUSTED client triplet — its RootCAs (loaded from caPath)
	// pin the trusted handshake CA, exactly as the host-driver and Identity dials do.
	t.Setenv(controlplane.EnvDialTLSCert, m.clientCertPath)
	t.Setenv(controlplane.EnvDialTLSKey, m.clientKeyPath)
	t.Setenv(controlplane.EnvDialTLSCA, m.caPath)

	opts, err := liveDialOpts()
	if err != nil {
		t.Fatalf("liveDialOpts with the trusted synthetic triplet: %v", err)
	}
	if len(opts) != 1 || opts[0] == nil {
		t.Fatalf("liveDialOpts = %d options, want exactly 1 non-nil mTLS transport option (the unified dial source)", len(opts))
	}

	// The bufconn server presents a leaf chaining to an INDEPENDENT untrusted CA (carrying the
	// matching SAN so the ONLY failure is the untrusted chain), but pins the client cert against
	// the TRUSTED clientauth pool so the orchestrator's client cert still verifies server-side —
	// isolating the failure to the orchestrator's client-side RootCAs check.
	untrustedServerCert := writeSyntheticUntrustedServer(t, bufconnMTLSServerName)
	lis := startBufconnMTLSServer(t, untrustedServerCert, m.caPool)
	rpcErr := dialBufconnMTLS(t, lis, opts[0])
	if rpcErr == nil {
		t.Fatal("the orchestrator dial completed the handshake against a server whose cert chains to an UNTRUSTED CA — want the handshake REJECTED (client RootCAs/caPath pin the trusted CA)")
	}
	// Sanity: the rejection is a transport/handshake failure, not a missing-RPC artifact (the
	// health service is registered; only the handshake should block the call).
	if strings.Contains(rpcErr.Error(), "Unimplemented") {
		t.Fatalf("untrusted-server-CA dial failed with Unimplemented (RPC reached the server), want a handshake rejection: %v", rpcErr)
	}
	// The rejection must surface the DISTINCT untrusted-chain cause (the client's RootCAs
	// verification), not merely be non-nil — a bare err!=nil would also fire on a SAN mismatch
	// or a rejected client cert, so it would not prove THIS arm's specific failure. Asserting
	// the cause substring pins that the orchestrator's caPath/RootCAs pinning is what rejected
	// the untrusted server chain.
	if !strings.Contains(rpcErr.Error(), "certificate signed by unknown authority") {
		t.Fatalf("untrusted-server-CA dial did not surface the distinct untrusted-chain cause: got %q, want it to contain %q (the client's RootCAs verification of the untrusted server chain)", rpcErr.Error(), "certificate signed by unknown authority")
	}
}

// TestBufconnMTLS_ServerSANMismatchRejectedAtHandshake proves the orchestrator's client-side
// server verification checks the NAME, not merely the chain: today every handshake case uses
// bufconnMTLSServerName ("bufnet") as BOTH the cert SAN and the dial authority, so name
// verification trivially passes. Here the bufconn server presents a cert that chains correctly
// to the orchestrator's pinned CA (RootCAs verification of the chain would PASS) but carries a
// SAN that does NOT match the dial authority — so the client's name verification (against the
// dial authority bufconnMTLSServerName, hardcoded in dialBufconnMTLS) must REJECT the server
// cert and abort the handshake. This catches a future config that pins the CA but skips
// hostname verification (a silent within-CA MITM risk on the internal fabric). The server still
// pins the orchestrator's client cert against the same CA's clientauth pool (so the client cert
// verifies server-side), isolating the failure to the SAN mismatch. Synthetic certs only, no
// live network (D50).
func TestBufconnMTLS_ServerSANMismatchRejectedAtHandshake(t *testing.T) {
	const mismatchedServerSAN = "not-bufnet"
	// The server leaf carries mismatchedServerSAN as its SAN, but the client triplet (CA, cert,
	// key) all chain to the SAME handshake CA — so the chain verifies and the ONLY divergence is
	// the SAN vs the dial authority. The orchestrator dials with this material's TRUSTED client
	// triplet (its RootCAs pin the handshake CA).
	m := writeSyntheticMTLSHandshake(t, mismatchedServerSAN)
	t.Setenv(controlplane.EnvDialTLSCert, m.clientCertPath)
	t.Setenv(controlplane.EnvDialTLSKey, m.clientKeyPath)
	t.Setenv(controlplane.EnvDialTLSCA, m.caPath)

	opts, err := liveDialOpts()
	if err != nil {
		t.Fatalf("liveDialOpts with the trusted synthetic triplet: %v", err)
	}
	if len(opts) != 1 || opts[0] == nil {
		t.Fatalf("liveDialOpts = %d options, want exactly 1 non-nil mTLS transport option (the unified dial source)", len(opts))
	}

	// dialBufconnMTLS hardcodes the dial authority to bufconnMTLSServerName ("bufnet"), which the
	// server cert's SAN (mismatchedServerSAN) does NOT match — so the client's name verification
	// rejects the otherwise-chain-valid server cert.
	lis := startBufconnMTLSServer(t, m.serverCert, m.caPool)
	rpcErr := dialBufconnMTLS(t, lis, opts[0])
	if rpcErr == nil {
		t.Fatal("the orchestrator dial completed the handshake against a server whose cert SAN does not match the dial authority — want the handshake REJECTED (client name verification)")
	}
	// Sanity: the rejection is a transport/handshake failure, not a missing-RPC artifact (the
	// health service is registered; only the handshake should block the call).
	if strings.Contains(rpcErr.Error(), "Unimplemented") {
		t.Fatalf("SAN-mismatch dial failed with Unimplemented (RPC reached the server), want a handshake rejection: %v", rpcErr)
	}
	// The rejection must surface the DISTINCT name-verification cause ("certificate is valid
	// for <san>, not <authority>"), not merely be non-nil — a bare err!=nil would also fire on
	// an untrusted chain. Asserting the cause substring pins that the orchestrator's client-side
	// NAME verification (against the dial authority) is what rejected the otherwise-chain-valid
	// cert, distinguishing this arm from the untrusted-CA arm above.
	if !strings.Contains(rpcErr.Error(), "certificate is valid for") {
		t.Fatalf("SAN-mismatch dial did not surface the distinct name-verification cause: got %q, want it to contain %q (the client's name check against the dial authority)", rpcErr.Error(), "certificate is valid for")
	}
}

// TestBufconnMTLS_ServerCertTemporalValidityRejectedAtHandshake proves the orchestrator's
// client-side server verification checks the cert's TEMPORAL VALIDITY window (NotBefore/
// NotAfter), not merely the chain and the name: every other handshake case uses a cert valid
// NOW, so the temporal check trivially passes. Here the bufconn server presents a cert that
// chains correctly to the orchestrator's pinned CA AND carries the matching SAN (so both the
// RootCAs chain check and the name check would PASS) but whose validity window is in the past
// (EXPIRED) or wholly in the future (NOT-YET-VALID) — so the client's temporal validity check
// must REJECT the server cert and abort the handshake. This catches a future config or a clock
// skew that silently accepts an expired/not-yet-valid server leaf on the internal fabric. The
// server pins the orchestrator's client cert against the same CA's clientauth pool (so the
// client cert verifies server-side), isolating the failure to the server leaf's window. The
// rejection must surface the DISTINCT temporal cause, not merely be non-nil. Synthetic certs
// only, no live network (D50).
func TestBufconnMTLS_ServerCertTemporalValidityRejectedAtHandshake(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name            string
		serverNotBefore time.Time
		serverNotAfter  time.Time
	}{
		{
			// EXPIRED: the window closed an hour ago.
			name:            "expired",
			serverNotBefore: now.Add(-2 * time.Hour),
			serverNotAfter:  now.Add(-time.Hour),
		},
		{
			// NOT-YET-VALID: the window opens an hour from now.
			name:            "not-yet-valid",
			serverNotBefore: now.Add(time.Hour),
			serverNotAfter:  now.Add(2 * time.Hour),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The server leaf chains to the trusted CA and carries the matching SAN, but its
			// validity window is temporally invalid — the ONLY divergence is the window.
			m := writeSyntheticExpiredServer(t, bufconnMTLSServerName, tc.serverNotBefore, tc.serverNotAfter)
			// The orchestrator dials with this material's TRUSTED client triplet (its RootCAs pin
			// the same CA), so chain + name verification would pass and only the window fails.
			t.Setenv(controlplane.EnvDialTLSCert, m.clientCertPath)
			t.Setenv(controlplane.EnvDialTLSKey, m.clientKeyPath)
			t.Setenv(controlplane.EnvDialTLSCA, m.caPath)

			opts, err := liveDialOpts()
			if err != nil {
				t.Fatalf("liveDialOpts with the trusted synthetic triplet: %v", err)
			}
			if len(opts) != 1 || opts[0] == nil {
				t.Fatalf("liveDialOpts = %d options, want exactly 1 non-nil mTLS transport option (the unified dial source)", len(opts))
			}

			lis := startBufconnMTLSServer(t, m.serverCert, m.caPool)
			rpcErr := dialBufconnMTLS(t, lis, opts[0])
			if rpcErr == nil {
				t.Fatalf("the orchestrator dial completed the handshake against a server whose cert is %s — want the handshake REJECTED (client temporal-validity check)", tc.name)
			}
			// Sanity: the rejection is a transport/handshake failure, not a missing-RPC artifact.
			if strings.Contains(rpcErr.Error(), "Unimplemented") {
				t.Fatalf("%s server-cert dial failed with Unimplemented (RPC reached the server), want a handshake rejection: %v", tc.name, rpcErr)
			}
			// The rejection must surface the DISTINCT temporal cause — Go's x509 reports both an
			// expired and a not-yet-valid leaf with "certificate has expired or is not yet valid",
			// distinguishing this arm from the untrusted-CA and SAN-mismatch arms above.
			if !strings.Contains(rpcErr.Error(), "certificate has expired or is not yet valid") {
				t.Fatalf("%s server-cert dial did not surface the distinct temporal-validity cause: got %q, want it to contain %q (the client's NotBefore/NotAfter check)", tc.name, rpcErr.Error(), "certificate has expired or is not yet valid")
			}
		})
	}
}

// TestBufconnMTLS_ClientCertTemporalValidityRejectedAtHandshake is the BILATERAL mirror of
// TestBufconnMTLS_ServerCertTemporalValidityRejectedAtHandshake: that one pins the orchestrator's
// CLIENT-side check of the SERVER cert's temporal window; this one pins the SERVER-side check of
// the orchestrator's CLIENT cert's temporal window. The orchestrator dials with its OWN unified
// dial source (liveDialOpts, built from the DS_ORCH_TLS_* triplet — exactly the option liveDeps
// threads into both the Identity D22/D82 dial and the host-driver registry dial), but the client
// cert behind that triplet is temporally INVALID (EXPIRED or NOT-YET-VALID). The client leaf
// chains to the SAME CA the server's clientauth pool pins AND the server leaf is valid + carries
// the matching SAN — so the chain verifies, the server-cert (RootCAs + name) check passes, and
// the ONLY divergence is the client leaf's NotBefore/NotAfter window. The server's
// RequireAndVerifyClientCert temporal check must therefore REJECT the client cert and abort the
// handshake. This catches a future config or a clock skew that silently accepts an expired/
// not-yet-valid CLIENT identity on the internal fabric — the bilateral half the server-side
// temporal test does not reach. Synthetic certs only, no live network (D50).
func TestBufconnMTLS_ClientCertTemporalValidityRejectedAtHandshake(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name            string
		clientNotBefore time.Time
		clientNotAfter  time.Time
	}{
		{
			// EXPIRED: the orchestrator's client cert window closed an hour ago.
			name:            "expired",
			clientNotBefore: now.Add(-2 * time.Hour),
			clientNotAfter:  now.Add(-time.Hour),
		},
		{
			// NOT-YET-VALID: the orchestrator's client cert window opens an hour from now.
			name:            "not-yet-valid",
			clientNotBefore: now.Add(time.Hour),
			clientNotAfter:  now.Add(2 * time.Hour),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The client leaf chains to the trusted CA and the server leaf is valid + carries the
			// matching SAN — the ONLY divergence is the orchestrator client cert's window.
			m := writeSyntheticExpiredClient(t, bufconnMTLSServerName, tc.clientNotBefore, tc.clientNotAfter)
			// The orchestrator dials with this material's (temporally-invalid) client triplet via
			// its OWN unified dial source, so the dial presents exactly that client cert.
			t.Setenv(controlplane.EnvDialTLSCert, m.clientCertPath)
			t.Setenv(controlplane.EnvDialTLSKey, m.clientKeyPath)
			t.Setenv(controlplane.EnvDialTLSCA, m.caPath)

			opts, err := liveDialOpts()
			if err != nil {
				t.Fatalf("liveDialOpts with the temporally-invalid client triplet: %v", err)
			}
			if len(opts) != 1 || opts[0] == nil {
				t.Fatalf("liveDialOpts = %d options, want exactly 1 non-nil mTLS transport option (the unified dial source)", len(opts))
			}

			// The server is valid + pins the client cert against the trusted clientauth pool, so
			// the ONLY failure is the server rejecting the temporally-invalid client leaf.
			lis := startBufconnMTLSServer(t, m.serverCert, m.caPool)
			rpcErr := dialBufconnMTLS(t, lis, opts[0])
			if rpcErr == nil {
				t.Fatalf("the orchestrator dial completed the handshake presenting a client cert that is %s — want the handshake REJECTED (server RequireAndVerifyClientCert temporal check)", tc.name)
			}
			// Sanity: the rejection is a transport/handshake failure, not a missing-RPC artifact.
			if strings.Contains(rpcErr.Error(), "Unimplemented") {
				t.Fatalf("%s client-cert dial failed with Unimplemented (RPC reached the server), want a handshake rejection: %v", tc.name, rpcErr)
			}
			// The rejection must carry a TLS-layer cause, not merely be non-nil. When the server's
			// clientauth verification finds the client leaf outside its NotBefore/NotAfter window it
			// aborts with a TLS alert; Go's crypto/tls reports BOTH an expired AND a not-yet-valid
			// client leaf with the same alertCertificateExpired ("tls: expired certificate") — the
			// server-side wire-form of the x509 temporal failure (the verbose
			// "certificate has expired or is not yet valid" string is a CLIENT-side verify message
			// and never crosses the wire). We require that distinct "tls: expired certificate" cause
			// — separating this arm from the no-cert / untrusted-CA / SAN arms — but tolerate the
			// rare teardown race where the server closes the pipe before the alert is read back
			// (surfacing a generic transport write error); in that race the handshake still failed,
			// which is the bilateral pin.
			errStr := rpcErr.Error()
			if !strings.Contains(errStr, "tls: expired certificate") &&
				!strings.Contains(errStr, "read/write on closed pipe") {
				t.Fatalf("%s client-cert dial did not surface the distinct TLS temporal-rejection cause: got %q, want it to contain %q (the server's NotBefore/NotAfter clientauth alert) or the teardown-race transport error", tc.name, errStr, "tls: expired certificate")
			}
		})
	}
}
