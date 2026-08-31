package controlplane

// dialregistry_test.go drives leg (a): the production dialing DriverRegistry resolves a
// host_id to a per-host hypervisor.v1 driver client, CACHES the dialed connection (a
// second resolve reuses it), MISSES an unconfigured host with ErrNoDriverForHost, and
// CLOSES every connection at shutdown. The dial is exercised over an in-memory bufconn
// listener serving the GENERATED hypervisor.v1 fake — a real gRPC dial + connection with
// NO live socket / port bind / live host-agent (D50). The DialOption seam threads the
// bufconn context-dialer in, so the registry's real grpc.NewClient + ClientShim path runs
// end to end against the fake.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/testpki"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
	"github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1/hypervisorv1fake"
)

// serveDriverFakeBufconn stands up the generated hypervisor.v1 fake on an in-memory
// bufconn gRPC server and returns a DialOption set that dials it (the context-dialer +
// insecure transport). It is the no-socket dial target the dialRegistry resolves against
// (D50: a real gRPC connection, no live host-agent). The server is stopped on cleanup.
func serveDriverFakeBufconn(t *testing.T, fake *hypervisorv1fake.HypervisorDriverServiceFake) []DialOption {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	hypervisorv1fake.RegisterHypervisorDriverService(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})
	return []DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
}

// TestDialRegistry_ResolvesAndCachesDriver proves the dialing registry resolves a
// configured host to a working driver client (a CloneFromImage round-trips to the fake
// over the dialed connection) and CACHES the connection — a second DriverFor on the same
// host reuses the one dial (the conns map holds exactly one entry). Close then tears it
// down (the cache empties) and is idempotent.
func TestDialRegistry_ResolvesAndCachesDriver(t *testing.T) {
	ctx := context.Background()
	fake := newDriverFake()
	reg := NewDialRegistry(HostEndpoints{testHostID: "passthrough:///bufnet"}, serveDriverFakeBufconn(t, fake)...)

	// First resolve dials + caches; the returned client round-trips to the fake.
	drv, err := reg.DriverFor(ctx, testHostID)
	if err != nil {
		t.Fatalf("DriverFor(%s): %v", testHostID, err)
	}
	resp, err := drv.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{SessionUuid: "sess-dial-1"},
	})
	if err != nil {
		t.Fatalf("CloneFromImage over dialed client: %v", err)
	}
	if resp.GetHostSessionIndex() != 7 || resp.GetTapName() != "dstap-7" {
		t.Errorf("dialed CloneFromImage binding = (index %d, tap %q), want (7, dstap-7)", resp.GetHostSessionIndex(), resp.GetTapName())
	}
	if got := len(fake.CloneFromImageRecorded()); got != 1 {
		t.Errorf("fake CloneFromImage calls = %d, want 1 (the dialed verb reached the fake)", got)
	}

	// Second resolve reuses the cached connection — exactly one dialed conn.
	if _, err := reg.DriverFor(ctx, testHostID); err != nil {
		t.Fatalf("second DriverFor(%s): %v", testHostID, err)
	}
	reg.mu.Lock()
	cached := len(reg.conns)
	reg.mu.Unlock()
	if cached != 1 {
		t.Errorf("cached connections = %d, want 1 (the dial is cached, not re-dialed)", cached)
	}

	// Close tears down the cache and is idempotent.
	if err := reg.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	reg.mu.Lock()
	afterClose := len(reg.conns)
	reg.mu.Unlock()
	if afterClose != 0 {
		t.Errorf("cached connections after Close = %d, want 0", afterClose)
	}
	if err := reg.Close(); err != nil {
		t.Errorf("second Close (idempotent): %v", err)
	}
}

// TestDialRegistry_MissesUnconfiguredHost proves an unknown host (no configured endpoint)
// is ErrNoDriverForHost — the create rolls back from its host-side step, the reconciler
// absorbs it into a degraded/alarm path (seams.go's contract). No dial is attempted.
func TestDialRegistry_MissesUnconfiguredHost(t *testing.T) {
	reg := NewDialRegistry(HostEndpoints{testHostID: "bufnet"})
	_, err := reg.DriverFor(context.Background(), "host-not-configured")
	if err == nil {
		t.Fatal("DriverFor on an unconfigured host: expected ErrNoDriverForHost")
	}
	if !errors.Is(err, ErrNoDriverForHost) {
		t.Errorf("error = %v, want ErrNoDriverForHost", err)
	}
}

// TestDialRegistry_HostsReportsConfiguredSet proves Hosts enumerates the configured
// endpoint set (the fleet-broadcast input the reconciler's host-agnostic verbs use),
// whether or not each host is dialed yet.
func TestDialRegistry_HostsReportsConfiguredSet(t *testing.T) {
	reg := NewDialRegistry(HostEndpoints{"host-a": "a:9000", "host-b": "b:9000"})
	hosts, err := reg.Hosts(context.Background())
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("Hosts = %v, want 2 configured hosts", hosts)
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h] = true
	}
	if !seen["host-a"] || !seen["host-b"] {
		t.Errorf("Hosts = %v, want host-a + host-b", hosts)
	}
}

// --------------------------------------------------------------------------
// mTLS DialOption path (under DS_ORCH_LIVE) — proven with SYNTHETIC in-test certs (D50).
//
// The orchestrator→host-agent dial is the internal D35 link (doc 15 §2); a deployment
// fronting it with mutual TLS supplies the client cert/key/CA paths via the env. These
// tests prove MTLSDialOptionFromEnv builds the transport-credentials option FROM THE ENV
// PATHS — loading a throwaway in-test CA + client keypair written to temp files — without
// ever opening a socket (no live dial). They also pin the none-set insecure default and
// the partial-set hard-misconfiguration error.
// --------------------------------------------------------------------------

// writeSyntheticMTLS generates a throwaway self-signed CA + a client keypair signed by it,
// writes them as PEM files under the test's temp dir, and returns (certPath, keyPath,
// caPath). It is the D50 synthetic-cert source for the mTLS env tests: real PEM material
// that crypto/tls + x509 load and verify, generated in-process — no checked-in keys, no
// live CA. The keys are ephemeral P-256 ECDSA keypairs (fast, no RSA keygen cost).
func writeSyntheticMTLS(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()
	dir := t.TempDir()

	// A self-signed CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ds-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create synthetic CA cert: %v", err)
	}

	// A client cert signed by the CA (the orchestrator's identity on the dial).
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate synthetic client key: %v", err)
	}
	clientTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ds-orchestrator-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse synthetic CA cert: %v", err)
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create synthetic client cert: %v", err)
	}
	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	if err != nil {
		t.Fatalf("marshal synthetic client key: %v", err)
	}

	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	caPath = filepath.Join(dir, "ca.crt")
	writePEM(t, certPath, "CERTIFICATE", clientDER)
	writePEM(t, keyPath, "PRIVATE KEY", clientKeyDER)
	writePEM(t, caPath, "CERTIFICATE", caDER)
	return certPath, keyPath, caPath
}

// writePEM encodes der under blockType and writes it to path (a test helper for the
// synthetic-cert files).
func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestDialRegistry_MTLSDialOptionFromEnv_BuildsFromEnv proves the mTLS DialOption is built
// from the env-named cert/key/CA paths (synthetic in-test certs, D50): with the triplet
// set, MTLSDialOptionFromEnv reports configured=true and returns a non-nil transport-
// credentials option, and NewDialRegistry threads it onto the registry's dialOpts — all
// WITHOUT opening a socket (the credentials are constructed, not dialed). The constructed
// option is the mutually-authenticated transport the live orchestrator→host-agent dial
// would carry under DS_ORCH_LIVE=1 (doc 15 §2, D35).
func TestDialRegistry_MTLSDialOptionFromEnv_BuildsFromEnv(t *testing.T) {
	certPath, keyPath, caPath := writeSyntheticMTLS(t)
	t.Setenv(EnvDialTLSCert, certPath)
	t.Setenv(EnvDialTLSKey, keyPath)
	t.Setenv(EnvDialTLSCA, caPath)

	opt, configured, err := MTLSDialOptionFromEnv()
	if err != nil {
		t.Fatalf("MTLSDialOptionFromEnv with full synthetic triplet: %v", err)
	}
	if !configured {
		t.Fatal("mTLS reported not configured, want configured (full cert/key/CA triplet set)")
	}
	if opt == nil {
		t.Fatal("mTLS DialOption is nil, want a transport-credentials option built from env")
	}

	// The option threads onto the registry's dialOpts additively (the variadic tail) — the
	// registry the live edge constructs under DS_ORCH_LIVE=1 carries the mTLS transport, not
	// the insecure default.
	reg := NewDialRegistry(HostEndpoints{testHostID: "host:9000"}, opt)
	if len(reg.dialOpts) != 1 {
		t.Fatalf("registry dialOpts = %d, want 1 (the env-built mTLS option, replacing the insecure default)", len(reg.dialOpts))
	}
}

// TestDialRegistry_MTLSDialOptionFromEnv_NoneSetKeepsInsecureDefault proves that with NONE
// of the env vars set, MTLSDialOptionFromEnv reports configured=false and a nil option —
// the internal, network-isolated link keeps the insecure default (doc 15 §2). The caller
// then constructs NewDialRegistry with no transport option and the insecure default applies.
func TestDialRegistry_MTLSDialOptionFromEnv_NoneSetKeepsInsecureDefault(t *testing.T) {
	t.Setenv(EnvDialTLSCert, "")
	t.Setenv(EnvDialTLSKey, "")
	t.Setenv(EnvDialTLSCA, "")

	opt, configured, err := MTLSDialOptionFromEnv()
	if err != nil {
		t.Fatalf("MTLSDialOptionFromEnv with no env set: %v", err)
	}
	if configured {
		t.Error("mTLS reported configured with no env set, want not configured (insecure default)")
	}
	if opt != nil {
		t.Error("mTLS DialOption non-nil with no env set, want nil (no transport override)")
	}
}

// TestDialRegistry_MTLSDialOptionFromEnv_PartialIsHardError proves a HALF-configured mTLS
// edge (cert set, key/CA missing) is a hard misconfiguration — a live run must fail loudly
// at construction rather than silently downgrade transport security. MTLSDialOptionFromEnv
// returns an error naming the missing var; no option is produced.
func TestDialRegistry_MTLSDialOptionFromEnv_PartialIsHardError(t *testing.T) {
	certPath, _, _ := writeSyntheticMTLS(t)
	t.Setenv(EnvDialTLSCert, certPath)
	t.Setenv(EnvDialTLSKey, "")
	t.Setenv(EnvDialTLSCA, "")

	opt, configured, err := MTLSDialOptionFromEnv()
	if err == nil {
		t.Fatal("MTLSDialOptionFromEnv with a partial triplet: expected a hard error, got nil")
	}
	if configured || opt != nil {
		t.Errorf("partial triplet produced configured=%v opt=%v, want (false, nil)", configured, opt != nil)
	}
}

// TestDialRegistry_MTLSDialOptionFromEnv_BadCAIsError proves a CA path that holds no PEM
// certificate is an error (a misconfigured CA bundle fails the credentials build, not the
// first dial) — the credentials are validated at construction from the env path (D50: an
// in-test non-PEM file, no live dial).
func TestDialRegistry_MTLSDialOptionFromEnv_BadCAIsError(t *testing.T) {
	certPath, keyPath, _ := writeSyntheticMTLS(t)
	badCA := filepath.Join(t.TempDir(), "not-a-ca.pem")
	if err := os.WriteFile(badCA, []byte("not pem at all\n"), 0o600); err != nil {
		t.Fatalf("write bad CA: %v", err)
	}
	t.Setenv(EnvDialTLSCert, certPath)
	t.Setenv(EnvDialTLSKey, keyPath)
	t.Setenv(EnvDialTLSCA, badCA)

	if _, _, err := MTLSDialOptionFromEnv(); err == nil {
		t.Fatal("MTLSDialOptionFromEnv with a non-PEM CA file: expected an error, got nil")
	}
}

// writeMismatchedClientKey generates a FRESH, independent synthetic P-256 ECDSA key
// (D50 — in-process, never committed) that does NOT correspond to any cert, marshals it
// PKCS#8, and writes it as a PRIVATE KEY PEM under the test's temp dir. Paired with a
// real client cert from writeSyntheticMTLS (whose key it is NOT), it makes
// tls.LoadX509KeyPair's "private key does not match public key" arm fire — the
// mismatched-key construction error the dial registry must surface at build time.
func writeMismatchedClientKey(t *testing.T) string {
	t.Helper()
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate mismatched client key: %v", err)
	}
	otherKeyDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatalf("marshal mismatched client key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "mismatched.key")
	writePEM(t, keyPath, "PRIVATE KEY", otherKeyDER)
	return keyPath
}

// TestDialRegistry_MTLSDialOptionFromEnv_BadKeypairIsErrorAtConstruction proves the
// orchestrator client KEYPAIR load (tls.LoadX509KeyPair, the cert/key arm of the mTLS
// credentials build) is validated at CONSTRUCTION — MTLSDialOptionFromEnv fails fast with
// an error naming the keypair load, BEFORE any dial — for two distinct misconfigurations:
//
//   - a malformed / non-PEM client CERT (the cert file does not parse as a PEM
//     certificate), and
//   - a client KEY that does not match the cert (a well-formed PEM key for a DIFFERENT
//     keypair than the cert's public key).
//
// The full-triplet (BuildsFromEnv), none-set, partial, and non-PEM-CA arms above pin the
// other construction outcomes; this fills the gap of the cert/key LoadX509KeyPair failure
// arm, which was only reached transitively. Both cases use SYNTHETIC in-test material
// (D50: keys generated in-process, written to temp files, never committed) and assert the
// failure surfaces from MTLSDialOptionFromEnv itself — no socket is opened (the credentials
// are built, never dialed), and the error mentions the keypair load so the operator sees
// the cert/key (not the CA) as the cause. The valid CA from writeSyntheticMTLS is supplied
// in both cases so the keypair load is the ONLY failing step (isolating the assertion to
// the cert/key arm, not the CA arm the BadCAIsError test already covers). D35, doc 15 §2.
func TestDialRegistry_MTLSDialOptionFromEnv_BadKeypairIsErrorAtConstruction(t *testing.T) {
	// A valid CA file (and, for the mismatched-key case, a valid cert) shared by the
	// sub-cases — so the keypair load is the only step that can fail.
	goodCertPath, goodKeyPath, goodCAPath := writeSyntheticMTLS(t)

	t.Run("non-PEM-client-cert", func(t *testing.T) {
		// A client cert file holding no PEM certificate, paired with the cert's own valid
		// key + a valid CA — only the cert is malformed, so LoadX509KeyPair fails on it.
		badCert := filepath.Join(t.TempDir(), "not-a-cert.pem")
		if err := os.WriteFile(badCert, []byte("definitely not pem\n"), 0o600); err != nil {
			t.Fatalf("write bad client cert: %v", err)
		}
		t.Setenv(EnvDialTLSCert, badCert)
		t.Setenv(EnvDialTLSKey, goodKeyPath)
		t.Setenv(EnvDialTLSCA, goodCAPath)

		opt, configured, err := MTLSDialOptionFromEnv()
		if err == nil {
			t.Fatal("MTLSDialOptionFromEnv with a non-PEM client cert: expected a construction error, got nil")
		}
		if configured || opt != nil {
			t.Errorf("non-PEM client cert produced configured=%v opt=%v, want (false, nil) — no option on a keypair-load failure", configured, opt != nil)
		}
		if !strings.Contains(err.Error(), "client keypair") {
			t.Errorf("non-PEM client cert error = %q, want it to name the keypair load (mentions %q) so the cert/key is fingered as the cause, not the CA", err.Error(), "client keypair")
		}
		// Also pin the DISTINCT wrapped stdlib cause (the %w-wrapped tls.LoadX509KeyPair
		// error): a cert file that holds no PEM block fails the PEM-decode step, whose
		// stdlib text is "tls: failed to find any PEM data in certificate input". A
		// version-tolerant strings.Contains on the substring "failed to find any PEM data"
		// distinguishes this PEM-decode failure from the key-mismatch arm below — so the
		// two keypair-load failure modes can never be conflated and a future refactor that
		// swallowed the underlying cause (or surfaced the wrong one) regresses HERE.
		if !strings.Contains(err.Error(), "failed to find any PEM data") {
			t.Errorf("non-PEM client cert error = %q, want it to carry the wrapped stdlib PEM-decode cause (contains %q) so the malformed-cert mode is distinguishable from a key mismatch", err.Error(), "failed to find any PEM data")
		}
	})

	t.Run("key-does-not-match-cert", func(t *testing.T) {
		// A well-formed PEM cert (from writeSyntheticMTLS) paired with a well-formed PEM key
		// for a DIFFERENT keypair — LoadX509KeyPair parses both but rejects the mismatch.
		mismatchedKey := writeMismatchedClientKey(t)
		t.Setenv(EnvDialTLSCert, goodCertPath)
		t.Setenv(EnvDialTLSKey, mismatchedKey)
		t.Setenv(EnvDialTLSCA, goodCAPath)

		opt, configured, err := MTLSDialOptionFromEnv()
		if err == nil {
			t.Fatal("MTLSDialOptionFromEnv with a key that does not match the cert: expected a construction error, got nil")
		}
		if configured || opt != nil {
			t.Errorf("mismatched key produced configured=%v opt=%v, want (false, nil) — no option on a keypair-load failure", configured, opt != nil)
		}
		if !strings.Contains(err.Error(), "client keypair") {
			t.Errorf("mismatched-key error = %q, want it to name the keypair load (mentions %q) so the cert/key mismatch is fingered as the cause, not the CA", err.Error(), "client keypair")
		}
		// Also pin the DISTINCT wrapped stdlib cause: a well-formed PEM cert + a well-formed
		// PEM key for a DIFFERENT keypair parses both blocks but fails the public-key match,
		// whose stdlib text is "tls: private key does not match public key". A
		// version-tolerant strings.Contains on the substring "private key does not match
		// public key" distinguishes this match-check failure from the non-PEM-decode arm
		// above — so the two keypair-load failure modes stay separable and a future refactor
		// that surfaced the wrong underlying cause regresses HERE.
		if !strings.Contains(err.Error(), "private key does not match public key") {
			t.Errorf("mismatched-key error = %q, want it to carry the wrapped stdlib match-check cause (contains %q) so the key-mismatch mode is distinguishable from a malformed cert", err.Error(), "private key does not match public key")
		}
	})
}

// --------------------------------------------------------------------------
// Dial-cache leak baseline: the DriverRegistry's mTLS / dial-cache leg (D35).
//
// The dialing DriverRegistry resolves a host_id to a per-host hypervisor.v1 driver client
// by DIALING the host endpoint, then CACHES the *grpc.ClientConn (dial-once, reuse) and
// CLOSES every cached connection at shutdown (dialregistry.go's lifecycle contract). Each
// cached conn owns long-lived HTTP/2 transport goroutines (the conn-scoped read/write
// loops); Close must reclaim them. orch26 landed an ABSOLUTE goroutine-leak baseline
// (stdlib runtime.NumGoroutine, goleak-style, no go.uber.org/goleak dep) on the slow-Observe
// heartbeat-stream leg; this is its counterpart on the DIAL-CACHE leg. A leak here — a cached
// client connection not closed, an mTLS handshake / transport goroutine not torn down past
// Close/ctx-cancel — keeps the settled goroutine count above the pre-dial floor and fails.
//
// The dial runs over the in-memory bufconn hypervisor.v1 fake (D50: a real grpc.NewClient +
// HTTP/2 connection, NO live socket / port bind / live host-agent). Under DS_ORCH_LIVE=1 the
// mTLS leg additionally builds the transport-credentials DialOption from SYNTHETIC in-test
// certs via MTLSDialOptionFromEnv (D50, doc 15 §2, D35) and proves that credential-build +
// registry Close leaves no handshake goroutine behind either.
// --------------------------------------------------------------------------

// TestDialRegistry_DialCacheClosesToBaselineNoLeak proves the DriverRegistry's dial-cache leg
// returns the goroutine count to/below an ABSOLUTE pre-dial baseline after Close (stdlib
// runtime.NumGoroutine, goleak-style — no go.uber.org/goleak dep; the orchestrator go.mod
// stays proto+grpc-only). It opens a dialing registry over the bufconn hypervisor.v1 fake,
// snapshots the SETTLED goroutine floor with the fake server up but BEFORE any dial, then
// resolves + caches a Driver for the host (a real grpc.NewClient connection whose round-tripped
// CloneFromImage warms the HTTP/2 transport's long-lived goroutines up). Close tears the cache
// down; the settled count must return to AT-OR-BELOW the pre-dial baseline within a bound. A
// regression that leaks a cached conn / transport goroutine past Close never returns to the
// floor and fails here (an absolute assertion, not a relative delta). D35: the internal
// orchestrator→host-agent dial (doc 15 §2) must tear its cached connections down cleanly.
func TestDialRegistry_DialCacheClosesToBaselineNoLeak(t *testing.T) {
	ctx := context.Background()
	fake := newDriverFake()
	dialOpts := serveDriverFakeBufconn(t, fake)

	// ABSOLUTE pre-dial baseline (goleak-style, stdlib runtime.NumGoroutine). Snapshot the
	// settled goroutine count with the bufconn fake SERVER already up (its long-lived server
	// goroutines belong in the floor) but BEFORE the registry dials anything — so the only
	// goroutines above this floor are the dial-cache's per-conn transport goroutines, which a
	// clean Close must reclaim. A cached-conn / handshake goroutine leaked past Close keeps the
	// settled count above this floor and fails the absolute assertion below.
	baseline := stableGoroutineCount()

	reg := NewDialRegistry(HostEndpoints{testHostID: "passthrough:///bufnet"}, dialOpts...)

	// Resolve + cache the host driver: a real grpc.NewClient connection is dialed and cached
	// (dial-once). Round-trip CloneFromImage over it so the lazily-dialed HTTP/2 transport (and
	// its long-lived conn-scoped read/write goroutines) is forced UP and READY — those are the
	// goroutines Close must reclaim, peaking the count above the pre-dial floor.
	drv, err := reg.DriverFor(ctx, testHostID)
	if err != nil {
		t.Fatalf("DriverFor(%s): %v", testHostID, err)
	}
	if _, err := drv.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{SessionUuid: "sess-dial-leak"},
	}); err != nil {
		t.Fatalf("CloneFromImage warming the dialed conn: %v", err)
	}

	// The dial-cache holds exactly one conn (the cached connection whose goroutines must unwind).
	reg.mu.Lock()
	cached := len(reg.conns)
	reg.mu.Unlock()
	if cached != 1 {
		t.Fatalf("cached connections before Close = %d, want 1 (the dialed conn under test)", cached)
	}

	// Snapshot the settled count WHILE the dialed conn is cached + warmed — the per-conn
	// transport goroutines are all up now, so this peak sits strictly above the pre-dial floor.
	peak := stableGoroutineCount()
	if peak <= baseline {
		t.Fatalf("dialed/warmed conn did not raise the goroutine count above the pre-dial floor (baseline %d, peak %d) — the conn was not actually warmed, so the leak assertion is vacuous", baseline, peak)
	}

	// Close tears down every cached connection (dialregistry.go's graceful-shutdown contract).
	if err := reg.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	reg.mu.Lock()
	afterClose := len(reg.conns)
	reg.mu.Unlock()
	if afterClose != 0 {
		t.Errorf("cached connections after Close = %d, want 0 (every dialed conn torn down)", afterClose)
	}

	// ABSOLUTE leak assertion: the settled count must return to AT-OR-BELOW the pre-dial
	// baseline — the cached conn's HTTP/2 transport goroutines all unwound on Close, leaving only
	// the long-lived bufconn-server goroutines that were already in the floor. settleToGoroutineCount
	// polls within a bound to let the gRPC conn teardown finish; if the count never returns to the
	// baseline, a cached client connection / transport goroutine leaked past Close and this fails
	// (a goleak-style absolute assertion, stdlib runtime.NumGoroutine, no goleak dep). D35.
	if settled, ok := settleToGoroutineCount(baseline, 3*time.Second); !ok {
		t.Errorf("goroutine count did not return to the pre-dial baseline after Close (baseline %d, settled %d) — a cached host-driver connection / transport goroutine leaked past Close", baseline, settled)
	}
}

// TestDialRegistry_MTLSDialCacheClosesToBaselineNoLeak proves the SAME absolute goroutine-baseline
// teardown on the mTLS leg of the dial-cache. Under DS_ORCH_LIVE=1 it builds the mutual-TLS
// transport-credentials DialOption from SYNTHETIC in-test certs via MTLSDialOptionFromEnv (D50:
// real PEM material loaded in-process, no checked-in keys, no live CA), threads it onto a dialing
// registry over the bufconn dialer, snapshots the absolute pre-construction goroutine floor, then
// resolves + caches the host driver and Close-s the registry — proving that constructing the mTLS
// credentials, caching the dialed conn, and tearing it down returns the goroutine count to/below
// the floor with no mTLS-credential / cached-conn goroutine left behind (doc 15 §2, D35). It is
// SKIPPED unless DS_ORCH_LIVE=1: the mTLS leg is the live-edge posture (the dial mutually
// authenticates), so the env gates it exactly as the live edge is gated, while the insecure
// dial-cache leg above always runs. No live socket is opened: the dial target is the in-memory
// bufconn fake and grpc.NewClient is lazy (the conn stays idle — the mTLS handshake is never
// driven over the insecure-served fake, so no RPC is issued; the leak floor covers the credential
// build + the cached-conn Close teardown) (D50).
func TestDialRegistry_MTLSDialCacheClosesToBaselineNoLeak(t *testing.T) {
	if os.Getenv("DS_ORCH_LIVE") != "1" {
		t.Skip("mTLS dial-cache leak leg is live-edge gated (DS_ORCH_LIVE=1); the insecure dial-cache leg covers the always-run path (D50)")
	}

	// Synthetic in-test client cert/key/CA (D50) pointed at by the env — the same triplet the
	// live orchestrator→host-agent dial reads (doc 15 §2). MTLSDialOptionFromEnv constructs the
	// transport-credentials option from these PATHS without opening a socket.
	certPath, keyPath, caPath := writeSyntheticMTLS(t)
	t.Setenv(EnvDialTLSCert, certPath)
	t.Setenv(EnvDialTLSKey, keyPath)
	t.Setenv(EnvDialTLSCA, caPath)

	// Stand up the bufconn fake-server dialer FIRST — its long-lived Accept/Serve goroutine
	// belongs in the floor (it persists until t.Cleanup, exactly like the live host-agent server
	// would), so it must be counted in the baseline below, not mistaken for a per-conn leak.
	bufDialer := newBufconnDriverFakeDialer(t)

	// ABSOLUTE pre-dial baseline: snapshot the settled floor with the fake server up but before
	// the mTLS credentials are built or any conn is dialed, so the only goroutines above it are
	// the mTLS dial-cache's per-conn goroutines, which a clean Close must reclaim.
	baseline := stableGoroutineCount()

	mtlsOpt, configured, err := MTLSDialOptionFromEnv()
	if err != nil {
		t.Fatalf("MTLSDialOptionFromEnv with full synthetic triplet: %v", err)
	}
	if !configured || mtlsOpt == nil {
		t.Fatalf("mTLS reported configured=%v opt=%v, want a built transport-credentials option (full synthetic triplet set)", configured, mtlsOpt != nil)
	}

	// Build a dialing registry carrying the mTLS transport-credentials option PLUS the bufconn
	// context-dialer, so the mutually-authenticated DriverRegistry leg is constructed against the
	// in-memory fake (D50: no live host-agent / port bind). DriverFor caches a lazily-dialed conn
	// (grpc.NewClient is lazy: idle until an RPC, which is never issued — the insecure-served fake
	// could not complete the mTLS handshake, so the leg proves the credential build + cached-conn
	// Close teardown, not a live handshake). Close tears the cached conn down.
	dialOpts := []DialOption{bufDialer, mtlsOpt}
	reg := NewDialRegistry(HostEndpoints{testHostID: "passthrough:///bufnet"}, dialOpts...)
	if _, err := reg.DriverFor(context.Background(), testHostID); err != nil {
		t.Fatalf("DriverFor over mTLS dial-cache: %v", err)
	}
	reg.mu.Lock()
	cached := len(reg.conns)
	reg.mu.Unlock()
	if cached != 1 {
		t.Fatalf("cached connections before Close = %d, want 1 (the mTLS-credentialed conn under test)", cached)
	}

	if err := reg.Close(); err != nil {
		t.Errorf("Close (mTLS dial-cache): %v", err)
	}

	// ABSOLUTE leak assertion on the mTLS leg: the settled count must return to AT-OR-BELOW the
	// pre-construction floor after Close — no mTLS credential / cached-conn / transport goroutine
	// leaks past the teardown (stdlib runtime.NumGoroutine, no goleak dep). D35.
	if settled, ok := settleToGoroutineCount(baseline, 3*time.Second); !ok {
		t.Errorf("goroutine count did not return to the pre-construction baseline after Close on the mTLS leg (baseline %d, settled %d) — an mTLS credential / cached-conn goroutine leaked past Close", baseline, settled)
	}
}

// newBufconnDriverFakeDialer stands up the generated hypervisor.v1 fake on an in-memory bufconn
// gRPC server and returns ONLY the context-dialer DialOption (no transport-credentials option), so
// a caller can pair it with its OWN transport credentials — e.g. the mTLS leg above threading the
// env-built mTLS option onto the registry. It is the credentials-free counterpart to
// serveDriverFakeBufconn (D50: no live host-agent / port bind); the server is stopped on cleanup.
func newBufconnDriverFakeDialer(t *testing.T) DialOption {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	hypervisorv1fake.RegisterHypervisorDriverService(srv, newDriverFake())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})
	return grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	})
}

// --------------------------------------------------------------------------
// Slow-Observe heartbeat stream: backpressure + cancellation teardown (D35).
//
// The orch20 leg-(c) heartbeat ingest routes each inbound frame through the reconcile
// loop's Observe under the D35 level-triggered model. These tests prove the two halves of
// that contract under a SLOW/BLOCKED Observe consumer:
//   (1) BACKPRESSURE / level-triggered drop: a full inbound buffer makes Observe DROP the
//       reconcile submission (non-blocking) rather than stall the ingest goroutine — the
//       feed still records, the resync re-converges (reconcileLoop.Observe's contract).
//   (2) CANCELLATION TEARDOWN: with a slow Observe blocking the server-side Recv loop, a
//       context cancel cleanly tears the dialed ReportHeartbeat stream down — the server
//       handler returns, the client's CloseAndRecv unblocks, and no goroutine leaks.
// Driven over a real bufconn gRPC dial of the generated hostagent.v1 server (D50: no live
// host-agent, no port bind).
// --------------------------------------------------------------------------

// blockingObserver is a heartbeatObserver double that BLOCKS each Observe until the stream
// context is cancelled — the "slow/blocked reconcile consumer" that drives the
// backpressure + cancellation path. It signals when an Observe call has entered (so the
// test can cancel exactly while a consumer is stuck mid-Observe) and counts entries.
// Returning ctx.Err() on cancel is exactly the ingest's "stream's context was cancelled
// mid-submit → end the stream" path (heartbeatingest.go).
type blockingObserver struct {
	entered chan struct{} // buffered entry signal: one send per Observe entry

	mu   sync.Mutex
	seen int
}

func newBlockingObserver() *blockingObserver {
	return &blockingObserver{entered: make(chan struct{}, 16)}
}

func (o *blockingObserver) Observe(ctx context.Context, _ *hostagentv1.Heartbeat) error {
	o.mu.Lock()
	o.seen++
	o.mu.Unlock()
	select {
	case o.entered <- struct{}{}:
	default:
	}
	// Block until the stream context is cancelled — a slow consumer that never completes on
	// its own, so only the cancel tears it down.
	<-ctx.Done()
	return ctx.Err()
}

func (o *blockingObserver) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.seen
}

// serveHeartbeatIngestBufconn stands up the orch20 heartbeat ingest (over the given
// observer) on an in-memory bufconn gRPC server and returns a dialed hostagent.v1 client +
// the dialed conn. It reuses the dialRegistry's own dial posture (insecure transport over
// the bufconn context-dialer) so the slow-Observe test exercises a real gRPC dial + stream
// with NO live host-agent / port bind (D50). The server + conn are torn down on cleanup.
func serveHeartbeatIngestBufconn(t *testing.T, obs heartbeatObserver) (hostagentv1.HostAgentServiceClient, *grpc.ClientConn) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	hostagentv1.RegisterHostAgentServiceServer(srv, newHeartbeatIngest(obs, nil))
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial heartbeat ingest bufconn: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return hostagentv1.NewHostAgentServiceClient(conn), conn
}

// TestReconcileLoop_ObserveBackpressureDropsNotBlocks proves the level-triggered backpressure
// half (D35): when the reconcile loop's inbound buffer is FULL and Run is not draining (a
// slow/blocked consumer), Observe DROPS the reconcile submission rather than blocking the
// ingest path — every Observe returns promptly, the feed still records the latest snapshot,
// and the dropped submits are recovered by re-observing / the periodic resync. We fill the
// buffer past capacity from one goroutine; a blocking Observe (which would deadlock the
// ingest) would hang this test, so completing is itself the backpressure proof.
func TestReconcileLoop_ObserveBackpressureDropsNotBlocks(t *testing.T) {
	loop := newReconcileLoop(nil, NewHeartbeatStore(nil), DefaultResyncInterval, nil)
	// Run is NOT started — nothing drains l.inbound, so it fills at inboundCap and every
	// further Observe takes the non-blocking drop path. Submit well past capacity.
	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		for i := 0; i < loop.inboundCap*3; i++ {
			if err := loop.Observe(ctx, freshHeartbeat("host-a", uint64(i), 1)); err != nil {
				t.Errorf("Observe returned error on the drop path: %v", err)
			}
		}
		close(done)
	}()
	select {
	case <-done:
		// Completed without blocking: the over-capacity submits took the drop path (the
		// ingest goroutine is never stalled by a full reconcile buffer).
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked on a full inbound buffer — backpressure must DROP, not block (D35 level-triggered)")
	}
	// The feed recorded the latest snapshot for the host (the drop is of the reconcile
	// SUBMIT, never the feed write — the resync re-converges over this).
	if _, ok := loop.feed.ObservedByHost()["host-a"]; !ok {
		t.Error("feed did not record host-a despite dropped reconcile submits (feed write is unconditional)")
	}
}

// TestHeartbeatIngest_SlowObserveCancellationTearsDownNoLeak proves the cancellation half
// (D35): with a SLOW Observe blocking the server-side Recv loop (backpressure stalling the
// dialed ReportHeartbeat stream), cancelling the client context cleanly tears the stream
// down — the server handler returns, CloseAndRecv unblocks, and NO goroutine leaks. The
// stream is driven over a real bufconn gRPC dial of the orch20 ingest (D50: no live
// host-agent).
func TestHeartbeatIngest_SlowObserveCancellationTearsDownNoLeak(t *testing.T) {
	obs := newBlockingObserver()
	client, conn := serveHeartbeatIngestBufconn(t, obs)

	// Warm the dialed connection to READY before snapshotting the absolute baseline. grpc.NewClient
	// is lazy — the HTTP/2 transport (and its long-lived read/write goroutines) only spins up on the
	// first RPC or an explicit Connect. We force it up now so those LONG-LIVED, conn-scoped
	// goroutines (torn down at cleanup, not at per-stream cancel) are counted IN the baseline — the
	// absolute floor must include everything that legitimately persists for the connection's life,
	// leaving only the per-stream goroutines to be reclaimed by the cancel under test.
	warmConnToReady(t, conn)

	// ABSOLUTE leak baseline (goleak-style, stdlib runtime.NumGoroutine — no go.uber.org/goleak
	// dep; the orchestrator go.mod stays proto+grpc-only). Snapshot the SETTLED goroutine count
	// with the bufconn server + dialed conn READY but BEFORE any stream is opened — the long-lived
	// server/conn/transport goroutines are counted here, the per-stream ones are not. A clean
	// cancel-teardown must reclaim exactly the per-stream goroutines, so after the stream is opened,
	// stalled, and cancelled the settled count must return to AT-OR-BELOW this absolute floor within
	// a bound. A regression that leaks a dialed stream/handler goroutine past the cancel never
	// returns to the baseline and fails here (an absolute assertion, not just a relative delta off
	// the active-stream peak below).
	baseline := stableGoroutineCount()

	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.ReportHeartbeat(ctx)
	if err != nil {
		t.Fatalf("open ReportHeartbeat stream: %v", err)
	}

	// Send one frame; the server routes it into the SLOW Observe, which blocks — the Recv
	// loop is stalled there (backpressure). Wait until the consumer is stuck mid-Observe.
	if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{Heartbeat: freshHeartbeat("host-a", 0, 1)}); err != nil {
		t.Fatalf("send heartbeat frame: %v", err)
	}
	select {
	case <-obs.entered:
		// The server is now blocked inside Observe — the stream is under backpressure.
	case <-time.After(5 * time.Second):
		t.Fatal("Observe was never entered — the frame did not reach the slow consumer")
	}
	if obs.count() != 1 {
		t.Errorf("Observe entered %d times, want 1 (the one sent frame, stalled mid-submit)", obs.count())
	}

	// Snapshot the goroutine count WHILE the stream is active and stalled — the server's
	// per-stream Recv goroutine + the blocked Observe + the dial's transport goroutines are
	// all up now. A clean cancel-teardown must reclaim the per-stream goroutines, so the
	// settled count after cancel must DROP to at-or-below this peak — never grow (a grown or
	// non-shrinking count would mean the stream/handler goroutine leaked past the cancel).
	peak := stableGoroutineCount()

	// Cancel the client context: this must tear the stream down cleanly. The server handler
	// unblocks (Observe returns ctx.Err()), the handler returns, and CloseAndRecv returns a
	// cancellation error rather than hanging.
	cancel()
	if _, err := stream.CloseAndRecv(); err == nil {
		t.Error("CloseAndRecv after cancel returned nil error, want a cancellation error (the stream was torn down)")
	}

	// No goroutine leak (relative): the per-stream goroutines reclaim on cancel, so the settled
	// count is strictly below the active-stream peak (the stalled Observe handler returned, its
	// Recv goroutine wound down). The long-lived server/conn goroutines persist until cleanup;
	// only the per-stream ones are reclaimed here.
	if after := stableGoroutineCount(); after >= peak {
		t.Errorf("goroutine count did not drop after cancel teardown (peak %d, after %d) — the stream/handler goroutine leaked past cancel", peak, after)
	}

	// No goroutine leak (ABSOLUTE baseline): the settled count must return to AT-OR-BELOW the
	// pre-stream floor captured above — the per-stream goroutines (the dialed ReportHeartbeat
	// transport stream, the server-side Recv loop, the blocked Observe handler) all unwound on
	// cancel, leaving only the long-lived server/conn/transport goroutines that were already in
	// the baseline. settleToGoroutineCount polls within a bound to let teardown finish; if the
	// count never returns to the baseline, a dial/stream goroutine leaked past the cancel and
	// this fails (a goleak-style absolute assertion, stdlib runtime.NumGoroutine, no goleak dep).
	// D35: the heartbeat ingest's level-triggered stream must tear down cleanly on cancel.
	if settled, ok := settleToGoroutineCount(baseline, 3*time.Second); !ok {
		t.Errorf("goroutine count did not return to the pre-stream baseline after cancel teardown (baseline %d, settled %d) — a dialed stream/handler goroutine leaked past cancel", baseline, settled)
	}
}

// stableGoroutineCount returns the goroutine count once it has settled (it polls until the
// count is unchanged across a short window or a deadline elapses), so the leak comparison
// is not fooled by transient gRPC teardown goroutines still unwinding.
func stableGoroutineCount() int {
	deadline := time.Now().Add(3 * time.Second)
	prev := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		runtime.GC()
		n := runtime.NumGoroutine()
		if n == prev {
			return n
		}
		prev = n
	}
	return prev
}

// warmConnToReady forces the lazily-dialed gRPC connection's HTTP/2 transport up and waits until
// it reports READY (bounded), so the conn-scoped transport goroutines are established BEFORE the
// absolute goroutine baseline is snapshotted. Without this, grpc.NewClient stays Idle until the
// first RPC and those long-lived transport goroutines would spin up after the baseline — wrongly
// counting them as a per-stream leak. It is a test-only warmup over the bufconn dial (D50: no live
// host-agent), not a production path.
func warmConnToReady(t *testing.T, conn *grpc.ClientConn) {
	t.Helper()
	conn.Connect()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for conn.GetState() != connectivity.Ready {
		if !conn.WaitForStateChange(ctx, conn.GetState()) {
			t.Fatalf("connection did not reach READY before baseline (last state %s): %v", conn.GetState(), ctx.Err())
		}
	}
}

// settleToGoroutineCount polls runtime.NumGoroutine() until it returns to AT-OR-BELOW target
// (the absolute pre-stream baseline) or the bound elapses, allowing in-flight gRPC teardown
// goroutines to unwind first. It returns the final observed count and whether it reached the
// target within the bound — the stdlib, goleak-style absolute-baseline check (no
// go.uber.org/goleak dep): a clean cancel-teardown reclaims every per-stream goroutine and
// returns to the baseline, while a leaked dial/stream goroutine keeps the count above it and
// reports ok=false. It is the absolute counterpart to stableGoroutineCount's relative peak
// snapshot.
func settleToGoroutineCount(target int, bound time.Duration) (int, bool) {
	deadline := time.Now().Add(bound)
	n := runtime.NumGoroutine()
	for {
		runtime.GC()
		if n = runtime.NumGoroutine(); n <= target {
			return n, true
		}
		if !time.Now().Before(deadline) {
			return n, false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// --------------------------------------------------------------------------
// mTLS negotiation-failure (wrong-CA client rejected at handshake).
//
// The dial registry's mTLS path (doc 15 §2, D35) requires the client to
// present a certificate signed by a CA the server trusts. These tests prove
// that a client presenting a cert from an INDEPENDENT CA (NOT the server's
// trusted clientauth CA) is REJECTED at the TLS handshake — not at the
// application layer. The assertion is proven non-vacuous by a companion
// positive-control that shows the same wrong-CA client SUCCEEDS when the
// server is reconfigured to skip client-cert verification — if the assertion
// were vacuous (e.g. the server accepted any cert), the negative case would
// also pass, and the positive control detects that.
//
// Driven over an in-memory bufconn gRPC server that requires mutual TLS
// (grpc.Creds with tls.RequireAndVerifyClientCert), using the standard gRPC
// health service to force the handshake to actually run (grpc.NewClient is
// lazy; the RPC is what drives the TLS negotiation end to end). SYNTHETIC
// in-test P-256 ECDSA keypairs only — no checked-in keys, no live CA (D50).
// --------------------------------------------------------------------------

// wrongCAMaterial bundles the synthetic PKI for the wrong-CA negotiation-failure
// test: the TRUSTED CA (which signs the server cert and the client CA pool), the
// server's tls.Certificate, the trusted CA pool used for server client-auth, the
// wrong CA's independent certificate, and the wrong-client cert/key. All material
// is generated in-process, throwaway P-256 ECDSA — no real keys (D50).
type wrongCAMaterial struct {
	// serverCert is the bufconn gRPC server's tls.Certificate (signed by trustedCA).
	serverCert tls.Certificate
	// trustedCAPool is the server's clientauth pool — it pins the TRUSTED CA only, so
	// only a client cert chaining to trustedCA can complete the mTLS handshake.
	trustedCAPool *x509.CertPool
	// wrongClientCert is the client cert (signed by an INDEPENDENT, untrusted CA).
	// Presenting it to the server must fail at the TLS handshake.
	wrongClientCert tls.Certificate
	// trustedClientCert is the "good" client cert (signed by trustedCA). It is used
	// for the positive control: if the TRUSTED client passes but the WRONG one fails,
	// the rejection is CA-pinning, not something generic about TLS.
	trustedClientCert tls.Certificate
	// trustedCAForClient is the CA pool the client loads to verify the server cert.
	// Both the wrong-CA and trusted clients pin this so server-side TLS passes —
	// isolating the failure to the server's client-cert verification.
	trustedCAForClient *x509.CertPool
}

// buildWrongCAMaterial generates two independent synthetic CAs (A = trusted, B = wrong)
// and, from them:
//   - a server cert signed by CA-A (the server presents this in the TLS handshake)
//   - a "trusted" client cert signed by CA-A (the positive-control client)
//   - a "wrong" client cert signed by CA-B (the negative-case client that must be rejected)
//
// The server's clientauth pool contains ONLY CA-A, so CA-B-signed client certs are rejected.
// The serverDNSName is embedded as the server cert's SAN so the client's RootCAs pin
// resolves correctly (name mismatch is not the cause of failure — only the client CA is).
func buildWrongCAMaterial(t *testing.T, serverDNSName string) wrongCAMaterial {
	t.Helper()

	// Two independent synthetic CAs, minted through the ONE shared internal/testpki factory
	// (D50 — real P-256 ECDSA in-process, no checked-in keys, no live CA).
	//   - CA-A: the TRUSTED CA (signs the server cert + the trusted client cert).
	//   - CA-B: the WRONG CA (signs the wrong-CA client cert; the server does NOT trust it).
	caA := testpki.NewCA(t, "ds-negtest-trusted-ca", 400)
	caB := testpki.NewCA(t, "ds-negtest-wrong-ca", 401)

	// Server cert: ServerAuth leaf signed by CA-A, with serverDNSName as SAN.
	serverCert := caA.SignedLeaf(t, serverDNSName, 402, x509.ExtKeyUsageServerAuth)
	// Trusted client cert: ClientAuth leaf signed by CA-A (the positive control).
	trustedClientCert := caA.SignedLeaf(t, "ds-negtest-trusted-client", 403, x509.ExtKeyUsageClientAuth)
	// Wrong client cert: ClientAuth leaf signed by CA-B (NOT in the server's clientauth pool).
	wrongClientCert := caB.SignedLeaf(t, "ds-negtest-wrong-client", 404, x509.ExtKeyUsageClientAuth)

	// The server's clientauth pool and the client's RootCAs both pin CA-A only (caA.Pool is a
	// one-cert pool). Both the wrong-CA and trusted clients pin CA-A for server-cert
	// verification, so the ONLY failure in the negative case is the server rejecting the
	// CA-B-signed client cert — not the client rejecting the server cert.
	return wrongCAMaterial{
		serverCert:         serverCert,
		trustedCAPool:      caA.Pool,
		wrongClientCert:    wrongClientCert,
		trustedClientCert:  trustedClientCert,
		trustedCAForClient: caA.Pool,
	}
}

// dialTestMTLSServerName is the SAN embedded in the server cert and the dial authority used by
// the bufconn mutual-TLS negotiation-failure tests. It must match for the client's RootCAs
// verification to pass (isolating each negative arm's failure to its intended cause: the server's
// clientauth check for the wrong-CLIENT-CA arm, the client's RootCAs check for the wrong-SERVER-CA
// arm).
const dialTestMTLSServerName = "ds-negtest-server"

// startBufconnMTLSHealthServer stands up a gRPC health server over an in-memory bufconn listener
// requiring mutual TLS (RequireAndVerifyClientCert against caPool). The health service is
// registered so a caller can drive a real Health/Check RPC — the RPC is what forces the lazy gRPC
// connection to actually negotiate the TLS handshake (grpc.NewClient is lazy until the first RPC).
// The server is stopped on cleanup. No socket / port bind (D50 — in-memory only). This is the ONE
// shared bufconn mTLS server stand-up the controlplane bilateral-CA arms route through (no per-arm
// duplication). The PKI material it carries is minted by the shared internal/testpki factory.
func startBufconnMTLSHealthServer(t *testing.T, serverCert tls.Certificate, caPool *x509.CertPool) *bufconn.Listener {
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

// dialBufconnMTLSHealth dials the bufconn listener with the supplied client transport credentials
// and drives a real Health/Check RPC, returning the error. A nil error means the TLS handshake
// succeeded and the RPC reached the server; a non-nil error from a TLS mismatch surfaces as a
// connection/transport failure before any RPC dispatch. The dial authority is
// dialTestMTLSServerName so the client's RootCAs pin resolves against the server cert's SAN
// (eliminating name mismatch as a confounding failure cause for the CA-pinning arms).
func dialBufconnMTLSHealth(t *testing.T, lis *bufconn.Listener, clientCreds credentials.TransportCredentials) error {
	t.Helper()
	conn, err := grpc.NewClient(
		"passthrough:///"+dialTestMTLSServerName,
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(clientCreds),
	)
	if err != nil {
		t.Fatalf("dialBufconnMTLSHealth: construct client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, rpcErr := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return rpcErr
}

// TestMTLS_WrongCAClientRejectedAtHandshake proves that a client presenting a certificate
// signed by the WRONG CA (an independent CA NOT in the server's clientauth pool) is REJECTED
// at the TLS handshake — not at the application layer. This tests the server-side
// RequireAndVerifyClientCert enforcement on the mutual-TLS leg of the dial registry (doc 15
// §2, D35): the orchestrator→host-agent dial carries mTLS; a peer whose cert does not chain
// to the pinned CA must be rejected at the transport boundary, before any gRPC method dispatch.
//
// The test is proven non-vacuous by a companion positive control (t.Run "positive-control"):
// the SAME server reconfigured to skip client-cert verification (tls.NoClientCert) allows
// the wrong-CA client through — so the server CA check IS the gate, not something else. If
// the gate were absent (the server accepted any CA), the negative case would also succeed and
// the positive control would detect that the assertion is vacuous. Both sub-tests run over
// an in-memory bufconn gRPC server using SYNTHETIC P-256 ECDSA keypairs (D50: no live
// host-agent, no socket bind, no real keys).
func TestMTLS_WrongCAClientRejectedAtHandshake(t *testing.T) {
	m := buildWrongCAMaterial(t, dialTestMTLSServerName)

	// The wrong-CA client: its cert is signed by CA-B, which the server does NOT trust.
	// It still pins CA-A for server-cert verification (so the server cert passes the
	// client's check), isolating the failure to the SERVER's clientauth rejection of
	// the CA-B-signed client cert.
	wrongCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{m.wrongClientCert},
		RootCAs:      m.trustedCAForClient,
		ServerName:   dialTestMTLSServerName,
		MinVersion:   tls.VersionTLS12,
	})

	t.Run("wrong-CA-client-rejected", func(t *testing.T) {
		// Stand up a server that requires mutual TLS, pinning ONLY the trusted CA
		// (CA-A) for client-cert verification. The wrong-CA client (signed by CA-B)
		// must be rejected at the TLS handshake.
		lis := startBufconnMTLSHealthServer(t, m.serverCert, m.trustedCAPool)
		rpcErr := dialBufconnMTLSHealth(t, lis, wrongCreds)
		if rpcErr == nil {
			t.Fatal("wrong-CA client completed the handshake — want the server to REJECT the client cert at the TLS handshake (the client cert chains to an untrusted CA)")
		}
		// The error must be a connection/transport failure (handshake rejected), NOT an
		// application-layer error such as Unimplemented. An Unimplemented error would
		// mean the RPC reached the gRPC dispatcher, proving the handshake passed —
		// which would mean the CA check is not enforced.
		if strings.Contains(rpcErr.Error(), "Unimplemented") {
			t.Fatalf("wrong-CA client rejection surfaced as Unimplemented (the RPC reached the server dispatcher, so the handshake passed) — want a connection/transport failure: %v", rpcErr)
		}
	})

	t.Run("positive-control-trusted-CA-accepted", func(t *testing.T) {
		// The TRUSTED client (signed by CA-A, which the server DOES trust) must succeed.
		// This isolates the failure above to CA pinning, not a generic TLS setup error.
		trustedCreds := credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{m.trustedClientCert},
			RootCAs:      m.trustedCAForClient,
			ServerName:   dialTestMTLSServerName,
			MinVersion:   tls.VersionTLS12,
		})
		lis := startBufconnMTLSHealthServer(t, m.serverCert, m.trustedCAPool)
		if rpcErr := dialBufconnMTLSHealth(t, lis, trustedCreds); rpcErr != nil {
			t.Fatalf("trusted-CA client rejected unexpectedly — the server should accept a cert signed by its trusted CA: %v", rpcErr)
		}
	})

	t.Run("positive-control-vacuity-check", func(t *testing.T) {
		// NON-VACUITY PROOF: when the server is reconfigured to skip client-cert
		// verification (NoClientCert), the SAME wrong-CA client SUCCEEDS. This proves
		// that RequireAndVerifyClientCert is the gate: if the gate were not enforced,
		// both the negative case AND this vacuity check would look the same, and a
		// tester would not be able to tell the difference. With the gate present the
		// negative case fails; with the gate removed (NoClientCert) the same client
		// passes — the assertion is not vacuous.
		lis := bufconn.Listen(1 << 20)
		noAuthSrvCreds := credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{m.serverCert},
			ClientAuth:   tls.NoClientCert, // gate removed — accepts any client
			MinVersion:   tls.VersionTLS12,
		})
		noAuthSrv := grpc.NewServer(grpc.Creds(noAuthSrvCreds))
		healthpb.RegisterHealthServer(noAuthSrv, health.NewServer())
		go func() { _ = noAuthSrv.Serve(lis) }()
		t.Cleanup(func() {
			noAuthSrv.Stop()
			_ = lis.Close()
		})
		// The wrong-CA client does NOT present a client cert to a NoClientCert server
		// (the server does not request one). The client still verifies the server cert
		// against its RootCAs (CA-A), which passes (the server cert is signed by CA-A).
		wrongCredsNoMutual := credentials.NewTLS(&tls.Config{
			RootCAs:    m.trustedCAForClient,
			ServerName: dialTestMTLSServerName,
			MinVersion: tls.VersionTLS12,
		})
		if rpcErr := dialBufconnMTLSHealth(t, lis, wrongCredsNoMutual); rpcErr != nil {
			t.Fatalf("vacuity check: wrong-CA client rejected even with NoClientCert server — want it to SUCCEED (proving RequireAndVerifyClientCert is the gate, not something else): %v", rpcErr)
		}
	})
}

// TestMTLS_WrongServerCARejectedAtHandshake is the SERVER-side mirror of
// TestMTLS_WrongCAClientRejectedAtHandshake: it proves the CLIENT's server-cert verification
// (RootCAs pinning) on the dial registry's mTLS leg (doc 15 §2, D35) is LIVE, not inert,
// giving controlplane BILATERAL CA-pinning coverage (wrong-CLIENT-CA above + wrong-SERVER-CA
// here). The client dials with its TRUSTED client cert (signed by CA-A) and pins ONLY CA-A in
// its RootCAs, but the bufconn server presents a leaf chaining to an INDEPENDENT (untrusted)
// CA-B the client does NOT trust — so the client's RootCAs verification must REJECT the server
// cert and abort the handshake. The server's clientauth pool is CA-A (so the client's TRUSTED
// cert still verifies server-side), isolating the failure to the client's RootCAs check (the
// untrusted server chain), not a rejected client cert or a SAN mismatch (the untrusted server
// leaf carries the matching SAN). The error must name the distinct "signed by unknown
// authority" cause, not merely be non-nil.
//
// A companion positive control (t.Run "positive-control") shows the SAME client SUCCEEDS when
// the server presents a TRUSTED (CA-A) leaf — so the client's RootCAs check IS the gate, not a
// generic TLS setup error: if the gate were absent the negative case would also pass and the
// control would detect the vacuity. Both run over an in-memory bufconn gRPC server using
// SYNTHETIC P-256 ECDSA keypairs (D50: no live host-agent, no socket bind, no real keys).
func TestMTLS_WrongServerCARejectedAtHandshake(t *testing.T) {
	// CA-A: the TRUSTED CA the client pins in RootCAs and the server pins for clientauth.
	caA := testpki.NewCA(t, "ds-negtest-server-trusted-ca", 500)
	// CA-B: an INDEPENDENT untrusted CA the client does NOT pin — the wrong-server-CA chain.
	caB := testpki.NewCA(t, "ds-negtest-server-wrong-ca", 501)

	// The client's TRUSTED dial identity (signed by CA-A) so the server's clientauth check
	// passes — isolating the negative failure to the client's RootCAs rejection of the server.
	trustedClientCert := caA.SignedLeaf(t, "ds-negtest-trusted-client", 502, x509.ExtKeyUsageClientAuth)
	clientCreds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{trustedClientCert},
		RootCAs:      caA.Pool, // pins ONLY CA-A — a CA-B server leaf is untrusted.
		ServerName:   dialTestMTLSServerName,
		MinVersion:   tls.VersionTLS12,
	})

	t.Run("wrong-server-CA-rejected", func(t *testing.T) {
		// The server presents a leaf chaining to CA-B (untrusted by the client) carrying the
		// matching SAN — so the ONLY divergence is the untrusted chain, not the name. The server
		// pins CA-A for clientauth so the client's TRUSTED cert still verifies server-side.
		wrongServerCert := caB.SignedLeaf(t, dialTestMTLSServerName, 503, x509.ExtKeyUsageServerAuth)
		lis := startBufconnMTLSHealthServer(t, wrongServerCert, caA.Pool)
		rpcErr := dialBufconnMTLSHealth(t, lis, clientCreds)
		if rpcErr == nil {
			t.Fatal("the client completed the handshake against a server whose cert chains to an UNTRUSTED CA — want the client to REJECT the server cert at the TLS handshake (RootCAs pin CA-A only)")
		}
		// The rejection must be the DISTINCT untrusted-chain cause (the client's RootCAs check),
		// not a generic non-nil error — and NOT Unimplemented (which would mean the RPC reached
		// the dispatcher, proving the handshake passed).
		if strings.Contains(rpcErr.Error(), "Unimplemented") {
			t.Fatalf("wrong-server-CA rejection surfaced as Unimplemented (the RPC reached the dispatcher, so the handshake passed) — want a transport/handshake failure: %v", rpcErr)
		}
		if !strings.Contains(rpcErr.Error(), "certificate signed by unknown authority") {
			t.Fatalf("wrong-server-CA rejection did not surface the distinct untrusted-chain cause: got %q, want it to contain %q (the client's RootCAs verification of the untrusted server chain)", rpcErr.Error(), "certificate signed by unknown authority")
		}
	})

	t.Run("positive-control-trusted-server-accepted", func(t *testing.T) {
		// A TRUSTED server leaf (signed by CA-A, which the client DOES pin) must be accepted —
		// isolating the failure above to the untrusted server chain, not a generic TLS error.
		trustedServerCert := caA.SignedLeaf(t, dialTestMTLSServerName, 504, x509.ExtKeyUsageServerAuth)
		lis := startBufconnMTLSHealthServer(t, trustedServerCert, caA.Pool)
		if rpcErr := dialBufconnMTLSHealth(t, lis, clientCreds); rpcErr != nil {
			t.Fatalf("trusted-server-CA leaf rejected unexpectedly — the client should accept a server cert signed by its pinned CA: %v", rpcErr)
		}
	})
}

// --------------------------------------------------------------------------
// BRING-COMPUTE inbound (host-agent-dials-OUT) driver registry (doc 15 §2.1; D19
// outbound-only mTLS, no inbound holes). The hosted tier above is
// orchestrator-dials-host; these tests prove the INVERTED dial direction — the host
// agent dials OUT and the orchestrator routes the frozen HypervisorDriver verbs back
// over that inbound-established connection (no separate outbound dial, no inbound hole).
//
// The inbound connection is modeled exactly as in production: a *grpc.ClientConn the
// orchestrator holds over an established link. Here the link is a bufconn whose SERVER
// side runs the generated hypervisor.v1 fake (standing in for the HypervisorDriverService
// the customer's host agent serves on its side of the connection it dialed). The
// orchestrator-side *grpc.ClientConn is Registered on the inbound registry and the verbs
// route over it — a REAL gRPC connection + round-trip, NO live host-agent and NO inbound
// listener opened in the test (D50). *grpc.ClientConn satisfies the InboundConn seam.
// --------------------------------------------------------------------------

// dialInboundFakeConn stands up the generated hypervisor.v1 fake on an in-memory bufconn
// server (the host-agent side of a bring-compute connection) and returns the
// orchestrator-side *grpc.ClientConn over that link — the inbound, host-agent-initiated
// connection the inbound registry routes verbs back over. The server + the connection are
// torn down on cleanup. It is the no-socket inbound link the inboundDriverRegistry resolves
// against (D50: a real gRPC connection, no live host-agent, no inbound hole).
func dialInboundFakeConn(t *testing.T, fake *hypervisorv1fake.HypervisorDriverServiceFake) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	hypervisorv1fake.RegisterHypervisorDriverService(srv, fake)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("build inbound *grpc.ClientConn over bufconn: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return conn
}

// TestInboundDriverRegistry_RoutesVerbsOverInboundConn is the core dial-direction proof:
// a host agent dials OUT (modeled by Registering the orchestrator-side *grpc.ClientConn of
// an established link), and the orchestrator routes the frozen HypervisorDriver verbs BACK
// over that inbound connection — no separate outbound dial. A CloneFromImage resolved via
// DriverFor round-trips to the fake the host agent serves, proving the verbs travel over
// the host-agent-initiated link.
func TestInboundDriverRegistry_RoutesVerbsOverInboundConn(t *testing.T) {
	ctx := context.Background()
	fake := newDriverFake()
	reg := NewInboundDriverRegistry()

	// Before any host dials in the registry is empty — DriverFor misses (the hosted-tier
	// miss contract: the create rolls back, the reconciler alarms).
	if _, err := reg.DriverFor(ctx, testHostID); !errors.Is(err, ErrNoDriverForHost) {
		t.Fatalf("DriverFor before Register = %v, want ErrNoDriverForHost (no inbound link yet)", err)
	}

	// The host agent dials OUT; the orchestrator captures + Registers the inbound conn.
	if err := reg.Register(testHostID, dialInboundFakeConn(t, fake)); err != nil {
		t.Fatalf("Register inbound host conn: %v", err)
	}

	// The HypervisorDriver verbs now route BACK over the inbound connection.
	drv, err := reg.DriverFor(ctx, testHostID)
	if err != nil {
		t.Fatalf("DriverFor(%s) after Register: %v", testHostID, err)
	}
	resp, err := drv.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{SessionUuid: "sess-inbound-1"},
	})
	if err != nil {
		t.Fatalf("CloneFromImage over inbound connection: %v", err)
	}
	if resp.GetHostSessionIndex() != 7 || resp.GetTapName() != "dstap-7" {
		t.Errorf("inbound CloneFromImage binding = (index %d, tap %q), want (7, dstap-7)", resp.GetHostSessionIndex(), resp.GetTapName())
	}
	if got := len(fake.CloneFromImageRecorded()); got != 1 {
		t.Errorf("fake CloneFromImage calls = %d, want 1 (the verb routed over the inbound link to the host-agent-served fake)", got)
	}

	// A second verb (Destroy) also routes over the SAME inbound connection.
	if _, err := drv.Destroy(ctx, &hypervisorv1.DestroyRequest{SessionUuid: "sess-inbound-1"}); err != nil {
		t.Fatalf("Destroy over inbound connection: %v", err)
	}
	if got := len(fake.DestroyRecorded()); got != 1 {
		t.Errorf("fake Destroy calls = %d, want 1 (routed over the inbound link)", got)
	}
}

// TestInboundDriverRegistry_MissesUndialedHost proves a host that has NOT dialed in (no
// registered inbound connection) is ErrNoDriverForHost — the same miss the hosted tier
// surfaces for an unconfigured host, so the create rolls back / the reconciler absorbs it
// (the bring-compute degraded-mode posture: a host that has not connected is on the
// missed-heartbeat recovery path, doc 15 §2.1).
func TestInboundDriverRegistry_MissesUndialedHost(t *testing.T) {
	fake := newDriverFake()
	reg := NewInboundDriverRegistry()
	if err := reg.Register(testHostID, dialInboundFakeConn(t, fake)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, err := reg.DriverFor(context.Background(), "host-never-dialed-in")
	if !errors.Is(err, ErrNoDriverForHost) {
		t.Errorf("DriverFor on an un-dialed host = %v, want ErrNoDriverForHost", err)
	}
}

// TestInboundDriverRegistry_ReconnectSupersedesAndClosesStale proves a host that re-dials
// (a reconnect after a blip) supersedes its prior inbound connection: the OLD connection is
// closed and replaced so a stale half-open link does not leak, and DriverFor resolves over
// the FRESH link (the verbs are idempotent on session_uuid, so a verb retried across the
// reconnect re-adopts — the frozen hypervisor.v1 contract).
func TestInboundDriverRegistry_ReconnectSupersedesAndClosesStale(t *testing.T) {
	ctx := context.Background()
	reg := NewInboundDriverRegistry()

	stale := &recordingInboundConn{ClientConn: dialInboundFakeConn(t, newDriverFake())}
	if err := reg.Register(testHostID, stale); err != nil {
		t.Fatalf("Register stale: %v", err)
	}

	// The same host re-dials with a fresh connection (reconnect).
	freshFake := newDriverFake()
	fresh := dialInboundFakeConn(t, freshFake)
	if err := reg.Register(testHostID, fresh); err != nil {
		t.Fatalf("Register fresh (reconnect): %v", err)
	}

	// The stale connection was closed on supersede (no leak).
	if !stale.closed() {
		t.Error("stale inbound connection was NOT closed on reconnect-supersede (it would leak)")
	}

	// DriverFor now routes over the FRESH link (the new fake records the verb).
	drv, err := reg.DriverFor(ctx, testHostID)
	if err != nil {
		t.Fatalf("DriverFor after reconnect: %v", err)
	}
	if _, err := drv.CloneFromImage(ctx, &hypervisorv1.CloneFromImageRequest{
		Spec: &hypervisorv1.VmSpec{SessionUuid: "sess-reconnect"},
	}); err != nil {
		t.Fatalf("CloneFromImage over fresh inbound conn: %v", err)
	}
	if got := len(freshFake.CloneFromImageRecorded()); got != 1 {
		t.Errorf("fresh fake CloneFromImage calls = %d, want 1 (the verb routed over the post-reconnect link)", got)
	}

	// Exactly one live connection is held (the fresh one); the stale one is gone.
	if got, err := reg.Hosts(ctx); err != nil || len(got) != 1 {
		t.Errorf("Hosts after reconnect = %v (err %v), want exactly [%s]", got, err, testHostID)
	}
}

// TestInboundDriverRegistry_DeregisterDropsAndCloses proves Deregister drops + closes a
// host's inbound connection (the orchestrator-side teardown when a host's outbound link
// closes): after Deregister the host misses with ErrNoDriverForHost until it re-dials, and
// the connection is closed. Deregistering an unknown host is an idempotent no-op.
func TestInboundDriverRegistry_DeregisterDropsAndCloses(t *testing.T) {
	ctx := context.Background()
	reg := NewInboundDriverRegistry()
	conn := &recordingInboundConn{ClientConn: dialInboundFakeConn(t, newDriverFake())}
	if err := reg.Register(testHostID, conn); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := reg.Deregister(testHostID); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if !conn.closed() {
		t.Error("Deregister did not close the inbound connection")
	}
	if _, err := reg.DriverFor(ctx, testHostID); !errors.Is(err, ErrNoDriverForHost) {
		t.Errorf("DriverFor after Deregister = %v, want ErrNoDriverForHost", err)
	}
	// Idempotent: deregistering an unknown / already-gone host is a no-op.
	if err := reg.Deregister(testHostID); err != nil {
		t.Errorf("Deregister of an already-removed host: %v, want nil (idempotent)", err)
	}
	if err := reg.Deregister("host-never-registered"); err != nil {
		t.Errorf("Deregister of an unknown host: %v, want nil (idempotent)", err)
	}
}

// TestInboundDriverRegistry_HostsReportsConnectedFleet proves Hosts enumerates the LIVE
// connected fleet — the hosts whose outbound connections have dialed in (unlike the hosted
// tier's static configured set). It is the fleet-broadcast input the reconciler's
// host-agnostic verbs use; a host that has not dialed in is not enumerated (no link to
// route over).
func TestInboundDriverRegistry_HostsReportsConnectedFleet(t *testing.T) {
	ctx := context.Background()
	reg := NewInboundDriverRegistry()
	if got, _ := reg.Hosts(ctx); len(got) != 0 {
		t.Errorf("Hosts on an empty registry = %v, want none (no host has dialed in)", got)
	}
	if err := reg.Register("host-a", dialInboundFakeConn(t, newDriverFake())); err != nil {
		t.Fatalf("Register host-a: %v", err)
	}
	if err := reg.Register("host-b", dialInboundFakeConn(t, newDriverFake())); err != nil {
		t.Fatalf("Register host-b: %v", err)
	}
	hosts, err := reg.Hosts(ctx)
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		seen[h] = true
	}
	if len(hosts) != 2 || !seen["host-a"] || !seen["host-b"] {
		t.Errorf("Hosts = %v, want the connected fleet [host-a host-b]", hosts)
	}
}

// TestInboundDriverRegistry_RejectsBadRegistration proves Register rejects an empty host_id
// and a nil connection (a registration must carry a real host + link), and that a rejected
// registration leaves the registry unchanged.
func TestInboundDriverRegistry_RejectsBadRegistration(t *testing.T) {
	reg := NewInboundDriverRegistry()
	if err := reg.Register("", dialInboundFakeConn(t, newDriverFake())); err == nil {
		t.Error("Register with an empty host_id: expected an error")
	}
	if err := reg.Register(testHostID, nil); err == nil {
		t.Error("Register with a nil connection: expected an error")
	}
	if got, _ := reg.Hosts(context.Background()); len(got) != 0 {
		t.Errorf("registry after rejected registrations = %v, want empty", got)
	}
}

// TestInboundDriverRegistry_CloseTearsDownAllAndIdempotent proves Close tears down every
// registered inbound connection at graceful shutdown and is idempotent (a second Close over
// the emptied set is a no-op).
func TestInboundDriverRegistry_CloseTearsDownAllAndIdempotent(t *testing.T) {
	reg := NewInboundDriverRegistry()
	a := &recordingInboundConn{ClientConn: dialInboundFakeConn(t, newDriverFake())}
	b := &recordingInboundConn{ClientConn: dialInboundFakeConn(t, newDriverFake())}
	if err := reg.Register("host-a", a); err != nil {
		t.Fatalf("Register host-a: %v", err)
	}
	if err := reg.Register("host-b", b); err != nil {
		t.Fatalf("Register host-b: %v", err)
	}
	if err := reg.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if !a.closed() || !b.closed() {
		t.Errorf("Close did not tear down every inbound connection (a closed=%v, b closed=%v)", a.closed(), b.closed())
	}
	if got, _ := reg.Hosts(context.Background()); len(got) != 0 {
		t.Errorf("Hosts after Close = %v, want empty", got)
	}
	if err := reg.Close(); err != nil {
		t.Errorf("second Close (idempotent): %v", err)
	}
}

// recordingInboundConn wraps a real bufconn-backed *grpc.ClientConn and records whether
// Close was called — so the supersede/deregister/close tests can assert the stale/torn-down
// inbound link is actually closed (no leak). It embeds *grpc.ClientConn so it satisfies the
// InboundConn seam natively (the ClientConnInterface verb-invoke methods forward to the real
// connection; only Close is observed). The underlying conn is still cleaned up by
// dialInboundFakeConn's t.Cleanup, so a double-close (registry Close + cleanup) is the
// idempotent *grpc.ClientConn.Close — exactly the shutdown overlap production tolerates.
type recordingInboundConn struct {
	*grpc.ClientConn
	mu       sync.Mutex
	closeHit bool
}

func (c *recordingInboundConn) Close() error {
	c.mu.Lock()
	c.closeHit = true
	c.mu.Unlock()
	return c.ClientConn.Close()
}

func (c *recordingInboundConn) closed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeHit
}

// Compile-time proof the test's inbound-conn double satisfies the InboundConn seam (the
// production *grpc.ClientConn does too — these tests register both shapes).
var _ InboundConn = (*recordingInboundConn)(nil)
var _ InboundConn = (*grpc.ClientConn)(nil)
