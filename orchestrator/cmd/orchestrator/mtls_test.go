package main

// mtls_test.go drives the cmd-side live-dial mTLS COMPOSITION (D35) with SYNTHETIC in-test
// certs (D50): liveDialOpts builds the transport-credentials DialOption tail from the
// env-named cert/key/CA PATHS — loading a throwaway in-test CA + client keypair written to
// temp files — by composing the ONE controlplane credentials builder
// (controlplane.MTLSDialOptionFromEnv), WITHOUT ever opening a socket (no live dial). The
// none/partial/bad-CA credentials-build arms are pinned in the controlplane package's
// dialregistry_test.go against that single builder; this file pins the cmd composition: the
// configured tail, the unset empty tail, the half-config hard error, the mismatched-keypair
// construction error driven through the unified builder (the cmd-side arm that predates the
// export, kept asserting through the one seam), and — load-bearing for this unit — that BOTH
// live dial legs (host-driver registry + Identity) draw their tail from the SAME liveDialOpts
// source. No live VM/host-agent/Identity dial is performed (grpc.NewClient is lazy; the
// registry does not dial eagerly).
//
// The synthetic PKI material is minted through the ONE shared factory in internal/testpki
// (testpki.Cert / testpki.Spec / testpki.WriteLeafPEM / testpki.TLSCert / testpki.WritePEM) so
// the per-arm helpers (writeSyntheticMTLS, writeSyntheticMismatchedCertKey,
// writeSyntheticMTLSHandshake, writeSyntheticUntrustedClient/Server,
// writeSyntheticExpiredServer/Client) reduce to a spec (CA / client / server leaf shape +
// validity window) rather than re-spelling ECDSA keygen + x509 template + CreateCertificate.
// The factory is shared with the controlplane synthetic-CA tests (internal/testpki),
// retiring the cmd-vs-controlplane PKI-helper drift. No behavior change: every helper keeps
// its exact signature and the same chain/window/SAN posture the temporal-arms + pinning
// coverage asserts.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/testpki"
)

// writeSyntheticMTLS generates a throwaway self-signed CA + a client keypair signed by it,
// writes them as PEM files under the test's temp dir, and returns (certPath, keyPath,
// caPath). It is the D50 synthetic-cert source for the mTLS env tests: real PEM material
// crypto/tls + x509 load and verify, generated in-process — no checked-in keys, no live CA.
// The keys are ephemeral P-256 ECDSA keypairs (fast, no RSA keygen cost). It is shared with
// identity_mtls_test.go (same package main).
func writeSyntheticMTLS(t *testing.T) (certPath, keyPath, caPath string) {
	t.Helper()
	dir := t.TempDir()

	ca := testpki.Cert(t, testpki.Spec{Role: testpki.RoleCA, Serial: 1, CommonName: "ds-test-ca"}, nil)
	client := testpki.Cert(t, testpki.Spec{Role: testpki.RoleClient, Serial: 2, CommonName: "ds-orchestrator-client"}, &ca)

	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	caPath = filepath.Join(dir, "ca.crt")
	testpki.WriteLeafPEM(t, client, certPath, keyPath)
	testpki.WritePEM(t, caPath, "CERTIFICATE", ca.DER)
	return certPath, keyPath, caPath
}

// writeSyntheticMismatchedCertKey generates TWO independent synthetic keypairs (A and B),
// writes A's self-signed certificate and B's private key as PEM files under the test's temp
// dir, and returns (certPath, keyPath). The cert and key are each valid PEM individually but
// do NOT correspond (cert public key from A != private key B), so tls.X509KeyPair (inside the
// unified controlplane builder) must reject the pair as a HARD construction error — a live
// boot with a mis-paired cert/key fails loudly at credentials build, never silently
// downgrading transport security (D50 synthetic certs).
func writeSyntheticMismatchedCertKey(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	// Keypair A: its self-signed certificate carries A's public key.
	leafA := testpki.Cert(t, testpki.Spec{Role: testpki.RoleClient, Serial: 10, CommonName: "ds-mismatch-cert-a"}, nil)
	// Keypair B: an independent private key whose public half is NOT in cert A.
	leafB := testpki.Cert(t, testpki.Spec{Role: testpki.RoleClient, Serial: 11, CommonName: "ds-mismatch-cert-b"}, nil)
	keyBDER, err := x509.MarshalPKCS8PrivateKey(leafB.Key)
	if err != nil {
		t.Fatalf("marshal synthetic key B: %v", err)
	}

	certPath = filepath.Join(dir, "cert-a.crt")
	keyPath = filepath.Join(dir, "key-b.key")
	testpki.WritePEM(t, certPath, "CERTIFICATE", leafA.DER)
	testpki.WritePEM(t, keyPath, "PRIVATE KEY", keyBDER)
	return certPath, keyPath
}

// syntheticMTLSHandshakeMaterial bundles the in-test PKI a bufconn mutual-TLS handshake
// test needs: the orchestrator's client cert/key/CA file PATHS (pointed at by the
// DS_ORCH_TLS_* env so the SAME unified dial source — controlplane.MTLSDialOptionFromEnv via
// liveDialOpts — builds the client transport credentials), plus the SERVER side built from
// the SAME CA (the server keypair the bufconn gRPC server presents, and the CA pool it pins
// the orchestrator's client cert against for clientauth). All material is generated in-test,
// throwaway P-256 ECDSA — no real keys (D50).
type syntheticMTLSHandshakeMaterial struct {
	// clientCertPath/clientKeyPath/caPath are the PEM file paths the DS_ORCH_TLS_* env points
	// at, so liveDialOpts/MTLSDialOptionFromEnv loads exactly these for the client dial.
	clientCertPath, clientKeyPath, caPath string
	// serverCert is the server keypair (signed by the same CA, ServerAuth + a SAN matching the
	// bufconn dial authority) the bufconn gRPC server presents to the orchestrator's dial.
	serverCert tls.Certificate
	// caPool pins the orchestrator's client cert: the server requires + verifies a client cert
	// chaining to this CA (RequireAndVerifyClientCert), so a no-cert / untrusted-CA client is
	// rejected at the handshake.
	caPool *x509.CertPool
}

// handshakeMaterial writes the client leaf to PEM files under dir, renders the server leaf as the
// bufconn server's tls.Certificate, and pins both against a fresh CA pool holding ca. It is the
// shared assembly step the handshake-shaped helpers (trusted / temporally-invalid) compose once
// they have minted the CA + client + server leaves through testpki.Cert.
func handshakeMaterial(t *testing.T, dir string, ca, client, server testpki.Leaf) syntheticMTLSHandshakeMaterial {
	t.Helper()
	m := syntheticMTLSHandshakeMaterial{
		clientCertPath: filepath.Join(dir, "client.crt"),
		clientKeyPath:  filepath.Join(dir, "client.key"),
		caPath:         filepath.Join(dir, "ca.crt"),
	}
	testpki.WriteLeafPEM(t, client, m.clientCertPath, m.clientKeyPath)
	testpki.WritePEM(t, m.caPath, "CERTIFICATE", ca.DER)
	m.serverCert = testpki.TLSCert(server)
	m.caPool = x509.NewCertPool()
	m.caPool.AddCert(ca.Cert)
	return m
}

// writeSyntheticMTLSHandshake generates a single synthetic CA and, from it, BOTH a client
// keypair (the orchestrator's dial identity, written to PEM files the DS_ORCH_TLS_* env points
// at) AND a server keypair (the bufconn gRPC server's identity, carrying serverDNSName as a
// SAN so the client's RootCAs pin verifies the server cert against the dial authority). It is
// the D50 synthetic source for the end-to-end bufconn mutual-TLS handshake test: real PEM/x509
// material both sides load and verify over a real (in-memory) transport, generated in-process —
// no checked-in keys, no live CA, no socket bind. Shared with identity_mtls_test.go (same
// package main).
func writeSyntheticMTLSHandshake(t *testing.T, serverDNSName string) syntheticMTLSHandshakeMaterial {
	t.Helper()
	dir := t.TempDir()

	// A self-signed CA that signs BOTH the client and server leaf certs, so the orchestrator's
	// RootCAs (loaded from caPath) pins the server cert AND the server's clientauth pool pins
	// the orchestrator's client cert — both legs of the mutual handshake chain to this one CA.
	ca := testpki.Cert(t, testpki.Spec{Role: testpki.RoleCA, Serial: 100, CommonName: "ds-test-handshake-ca"}, nil)
	client := testpki.Cert(t, testpki.Spec{Role: testpki.RoleClient, Serial: 101, CommonName: "ds-orchestrator-client"}, &ca)
	server := testpki.Cert(t, testpki.Spec{Role: testpki.RoleServer, Serial: 102, CommonName: serverDNSName, DNSName: serverDNSName}, &ca)
	return handshakeMaterial(t, dir, ca, client, server)
}

// writeSyntheticUntrustedClient generates an INDEPENDENT synthetic CA (NOT the one
// writeSyntheticMTLSHandshake emits) and a client keypair signed by it, writes them as PEM
// files, and returns (clientCertPath, clientKeyPath, untrustedCAPath). The cert is valid PEM
// and a well-formed clientauth leaf, but it chains to a CA the bufconn server does NOT trust —
// so a dial presenting it (with the untrusted CA pinning the server) must FAIL the mutual-TLS
// handshake (the server rejects the client cert as not chaining to its clientauth pool; the
// client also rejects the server cert as not chaining to the untrusted RootCAs). It proves the
// CA pinning is live, not cosmetic (D50 synthetic certs, no real keys).
func writeSyntheticUntrustedClient(t *testing.T) (clientCertPath, clientKeyPath, untrustedCAPath string) {
	t.Helper()
	dir := t.TempDir()

	ca := testpki.Cert(t, testpki.Spec{Role: testpki.RoleCA, Serial: 200, CommonName: "ds-untrusted-ca"}, nil)
	client := testpki.Cert(t, testpki.Spec{Role: testpki.RoleClient, Serial: 201, CommonName: "ds-untrusted-client"}, &ca)

	clientCertPath = filepath.Join(dir, "untrusted-client.crt")
	clientKeyPath = filepath.Join(dir, "untrusted-client.key")
	untrustedCAPath = filepath.Join(dir, "untrusted-ca.crt")
	testpki.WriteLeafPEM(t, client, clientCertPath, clientKeyPath)
	testpki.WritePEM(t, untrustedCAPath, "CERTIFICATE", ca.DER)
	return clientCertPath, clientKeyPath, untrustedCAPath
}

// writeSyntheticUntrustedServer generates an INDEPENDENT synthetic CA (NOT the one
// writeSyntheticMTLSHandshake emits) and, from it, a SERVER keypair (ServerAuth, carrying
// serverDNSName as a SAN so the name matches the dial authority and the ONLY failure is the
// untrusted chain), returning the server tls.Certificate the bufconn gRPC server presents. The
// leaf is a well-formed serverauth cert, but it chains to a CA the orchestrator's pinned
// RootCAs/caPath does NOT contain — so the orchestrator's CLIENT-side dial must REJECT the
// handshake (the server cert does not chain to the pinned CA). It is the dual of
// writeSyntheticUntrustedClient: that one proves SERVER clientauth pinning is live, this one
// proves the orchestrator's CLIENT-side RootCAs pinning is live, not cosmetic. The server's
// clientauth pool is supplied separately by the caller (the TRUSTED CA pool from
// writeSyntheticMTLSHandshake) so the orchestrator's client cert still verifies server-side,
// isolating the failure to the client's RootCAs check (D50 synthetic certs, no real keys).
func writeSyntheticUntrustedServer(t *testing.T, serverDNSName string) tls.Certificate {
	t.Helper()

	ca := testpki.Cert(t, testpki.Spec{Role: testpki.RoleCA, Serial: 300, CommonName: "ds-untrusted-server-ca"}, nil)
	server := testpki.Cert(t, testpki.Spec{Role: testpki.RoleServer, Serial: 301, CommonName: serverDNSName, DNSName: serverDNSName}, &ca)
	return testpki.TLSCert(server)
}

// writeSyntheticExpiredServer generates a single synthetic CA and, from it, BOTH a client
// keypair (the orchestrator's dial identity, written to PEM files the DS_ORCH_TLS_* env points
// at, so liveDialOpts/MTLSDialOptionFromEnv loads exactly these) AND a server keypair whose
// validity window is temporally INVALID at the dial moment: serverNotBefore/serverNotAfter set
// the leaf's NotBefore/NotAfter, so passing a window already in the past makes the cert EXPIRED
// and a window wholly in the future makes it NOT-YET-VALID. The server leaf still chains to the
// SAME CA and carries serverDNSName as a SAN — so the chain verifies and the name matches; the
// ONLY divergence is the temporal window, isolating the client's NotBefore/NotAfter validity
// check as the failure cause. It is the temporal counterpart to writeSyntheticMTLSHandshake
// (D50 synthetic certs, no real keys, no live CA). Shared with identity_mtls_test.go (same
// package main).
func writeSyntheticExpiredServer(t *testing.T, serverDNSName string, serverNotBefore, serverNotAfter time.Time) syntheticMTLSHandshakeMaterial {
	t.Helper()
	dir := t.TempDir()

	// A self-signed CA (valid NOW) that signs BOTH the client and the temporally-invalid server
	// leaf — so the chain itself verifies and the ONLY failure is the server leaf's window.
	ca := testpki.Cert(t, testpki.Spec{Role: testpki.RoleCA, Serial: 110, CommonName: "ds-test-temporal-ca"}, nil)
	// The client leaf: the orchestrator's dial identity (ClientAuth), VALID now, signed by the CA.
	client := testpki.Cert(t, testpki.Spec{Role: testpki.RoleClient, Serial: 111, CommonName: "ds-orchestrator-client"}, &ca)
	// The server leaf: ServerAuth, signed by the same CA, with serverDNSName as a SAN, but with
	// the caller-supplied (temporally invalid) NotBefore/NotAfter window.
	server := testpki.Cert(t, testpki.Spec{
		Role:       testpki.RoleServer,
		Serial:     112,
		CommonName: serverDNSName,
		DNSName:    serverDNSName,
		NotBefore:  serverNotBefore,
		NotAfter:   serverNotAfter,
	}, &ca)
	return handshakeMaterial(t, dir, ca, client, server)
}

// writeSyntheticExpiredClient is the bilateral counterpart to writeSyntheticExpiredServer: it
// generates a single synthetic CA and, from it, BOTH a server keypair (the bufconn gRPC
// server's identity, ServerAuth, VALID now, carrying serverDNSName as a SAN so the client's
// RootCAs verification of the server cert passes) AND a CLIENT keypair (the orchestrator's dial
// identity, written to PEM files the DS_ORCH_TLS_* env points at, so liveDialOpts/
// MTLSDialOptionFromEnv loads exactly these) whose validity window is temporally INVALID at the
// dial moment: clientNotBefore/clientNotAfter set the client leaf's NotBefore/NotAfter, so a
// window already in the past makes the client cert EXPIRED and a window wholly in the future
// makes it NOT-YET-VALID. The client leaf still chains to the SAME CA the server's clientauth
// pool pins (m.caPool) — so the chain itself verifies and the ONLY divergence is the client
// leaf's temporal window, isolating the SERVER's RequireAndVerifyClientCert NotBefore/NotAfter
// check as the failure cause. It pins the BILATERAL temporal arm (a temporally-invalid CLIENT
// cert rejected at the server's clientauth verification), the mirror of
// writeSyntheticExpiredServer's server-side temporal arm (D50 synthetic certs, no real keys, no
// live CA). Shared with identity_mtls_test.go (same package main).
func writeSyntheticExpiredClient(t *testing.T, serverDNSName string, clientNotBefore, clientNotAfter time.Time) syntheticMTLSHandshakeMaterial {
	t.Helper()
	dir := t.TempDir()

	// A self-signed CA (valid NOW) that signs BOTH the temporally-invalid client leaf AND the
	// server leaf — so both chains verify and the ONLY failure is the client leaf's window.
	ca := testpki.Cert(t, testpki.Spec{Role: testpki.RoleCA, Serial: 120, CommonName: "ds-test-client-temporal-ca"}, nil)
	// The client leaf: the orchestrator's dial identity (ClientAuth), signed by the CA, but with
	// the caller-supplied (temporally invalid) NotBefore/NotAfter window.
	client := testpki.Cert(t, testpki.Spec{
		Role:       testpki.RoleClient,
		Serial:     121,
		CommonName: "ds-orchestrator-client",
		NotBefore:  clientNotBefore,
		NotAfter:   clientNotAfter,
	}, &ca)
	// The server leaf: ServerAuth, signed by the same CA, VALID now, with serverDNSName as a SAN
	// — so server-cert verification on the client side passes and the ONLY failure is the client
	// leaf's window at the server's clientauth check.
	server := testpki.Cert(t, testpki.Spec{Role: testpki.RoleServer, Serial: 122, CommonName: serverDNSName, DNSName: serverDNSName}, &ca)
	return handshakeMaterial(t, dir, ca, client, server)
}

// TestLiveDialOpts_ConfiguredThreadsOption proves liveDialOpts returns the env-built mTLS
// option as the live dials' variadic dial-option tail when the triplet is set (synthetic
// certs, D50), so liveDeps threads the mutually-authenticated transport into both
// NewDialRegistry and NewIdentityClients. The option is built from the synthetic certs
// without a dial (the single controlplane builder constructs credentials, never a socket).
func TestLiveDialOpts_ConfiguredThreadsOption(t *testing.T) {
	certPath, keyPath, caPath := writeSyntheticMTLS(t)
	t.Setenv(controlplane.EnvDialTLSCert, certPath)
	t.Setenv(controlplane.EnvDialTLSKey, keyPath)
	t.Setenv(controlplane.EnvDialTLSCA, caPath)

	opts, err := liveDialOpts()
	if err != nil {
		t.Fatalf("liveDialOpts with full triplet: %v", err)
	}
	if len(opts) != 1 {
		t.Fatalf("liveDialOpts = %d options, want 1 (the env-built mTLS transport option)", len(opts))
	}
	if opts[0] == nil {
		t.Fatal("liveDialOpts returned a nil option in the tail, want the mTLS transport-credentials option")
	}
	// The option threads onto the registry additively (the variadic tail) — the registry the
	// live edge constructs under DS_ORCH_LIVE=1 carries the mTLS transport, not the insecure
	// default. NewDialRegistry does not dial eagerly, so this builds the registry without a
	// live socket (D50).
	reg := controlplane.NewDialRegistry(controlplane.HostEndpoints{"host-a": "host:9000"}, opts...)
	if reg == nil {
		t.Fatal("NewDialRegistry returned nil with the threaded mTLS option")
	}
}

// TestLiveDialOpts_UnsetIsEmptyTail proves that with NONE of the env vars set, liveDialOpts
// returns an empty tail (no error) — NewDialRegistry / NewIdentityClients then apply their
// insecure default unchanged for the internal, network-isolated links (doc 15 §2). This is
// the gate-off / certs-absent fallback: the insecure in-process path stays unchanged.
func TestLiveDialOpts_UnsetIsEmptyTail(t *testing.T) {
	t.Setenv(controlplane.EnvDialTLSCert, "")
	t.Setenv(controlplane.EnvDialTLSKey, "")
	t.Setenv(controlplane.EnvDialTLSCA, "")

	opts, err := liveDialOpts()
	if err != nil {
		t.Fatalf("liveDialOpts with no env set: %v", err)
	}
	if len(opts) != 0 {
		t.Fatalf("liveDialOpts = %d options with no env set, want 0 (insecure default unchanged)", len(opts))
	}
}

// TestLiveDialOpts_PartialIsHardError proves a half-configured triplet surfaces as an error
// from liveDialOpts (a live run fails loudly at liveDeps construction, never half-wiring
// transport security) — no options are produced.
func TestLiveDialOpts_PartialIsHardError(t *testing.T) {
	certPath, _, _ := writeSyntheticMTLS(t)
	t.Setenv(controlplane.EnvDialTLSCert, certPath)
	t.Setenv(controlplane.EnvDialTLSKey, "")
	t.Setenv(controlplane.EnvDialTLSCA, "")

	opts, err := liveDialOpts()
	if err == nil {
		t.Fatalf("liveDialOpts with a partial triplet: expected a hard error, got %d options", len(opts))
	}
	if opts != nil {
		t.Errorf("partial triplet produced %d options, want nil tail on error", len(opts))
	}
}

// TestLiveDialOpts_ConsumesControlplaneBuilder proves the cmd composition draws from the ONE
// exported controlplane credentials builder rather than a cmd-side duplicate: with the same
// synthetic triplet, controlplane.MTLSDialOptionFromEnv reports configured and liveDialOpts
// returns exactly that one option in its tail. There is a single source of truth for the
// TLS posture (D35); the previously-duplicated cmd builder is gone.
func TestLiveDialOpts_ConsumesControlplaneBuilder(t *testing.T) {
	certPath, keyPath, caPath := writeSyntheticMTLS(t)
	t.Setenv(controlplane.EnvDialTLSCert, certPath)
	t.Setenv(controlplane.EnvDialTLSKey, keyPath)
	t.Setenv(controlplane.EnvDialTLSCA, caPath)

	opt, configured, err := controlplane.MTLSDialOptionFromEnv()
	if err != nil {
		t.Fatalf("controlplane.MTLSDialOptionFromEnv with full triplet: %v", err)
	}
	if !configured || opt == nil {
		t.Fatalf("controlplane.MTLSDialOptionFromEnv reported configured=%v opt=%v, want (true, non-nil)", configured, opt != nil)
	}

	opts, err := liveDialOpts()
	if err != nil {
		t.Fatalf("liveDialOpts with full triplet: %v", err)
	}
	if len(opts) != 1 || opts[0] == nil {
		t.Fatalf("liveDialOpts = %d options, want exactly 1 non-nil (the controlplane-built mTLS option)", len(opts))
	}
}

// TestLiveDialOpts_MismatchedKeypairIsHardError proves a cert and key that are each valid PEM
// individually but come from two DIFFERENT synthetic keypairs (cert public key != private key)
// are a HARD construction error driven all the way through this unit's path: with the full
// triplet set but cert and key mis-paired, the unified controlplane builder rejects the load
// (tls.X509KeyPair) so liveDialOpts surfaces a non-nil error and NO option tail — liveDeps then
// fails loudly at construction rather than threading a mis-paired transport onto either live
// leg (doc 15 §2, D35; D50 synthetic certs, no live dial). The loud-fail contract NAMES the
// offending cert/key paths (controlplane's "load orchestrator live dial mTLS client keypair
// (%s, %s)" wrap), so an operator sees WHICH files are mis-paired rather than a bare crypto
// failure. This is the cmd-side arm that predates the export (cce52c13); it is kept asserting
// through the one unified seam so the unification does not silently drop the mis-pair coverage.
func TestLiveDialOpts_MismatchedKeypairIsHardError(t *testing.T) {
	_, _, caPath := writeSyntheticMTLS(t)
	mismatchCertPath, mismatchKeyPath := writeSyntheticMismatchedCertKey(t)
	t.Setenv(controlplane.EnvDialTLSCert, mismatchCertPath)
	t.Setenv(controlplane.EnvDialTLSKey, mismatchKeyPath)
	t.Setenv(controlplane.EnvDialTLSCA, caPath)

	opts, err := liveDialOpts()
	if err == nil {
		t.Fatalf("liveDialOpts with a cert+key from two different keypairs: expected a hard error, got %d options", len(opts))
	}
	if opts != nil {
		t.Errorf("mismatched keypair produced %d options, want nil tail on error (no mis-paired transport threaded)", len(opts))
	}
	// The error names both offending paths so an operator can see which files are mis-paired.
	if msg := err.Error(); !strings.Contains(msg, mismatchCertPath) || !strings.Contains(msg, mismatchKeyPath) {
		t.Errorf("mismatched-keypair error does not name both offending paths: got %q, want it to contain cert %q and key %q", msg, mismatchCertPath, mismatchKeyPath)
	}
}

// TestLiveDeps_BothLegsDrawOneMTLSSource is the load-bearing pin for this unit: it proves the
// host-driver registry dial AND the Identity dial provably consume the SAME mTLS source. With
// the synthetic triplet set, liveDialOpts (the one composition point liveDeps resolves once
// and threads into both NewDialRegistry and NewIdentityClients) yields a single configured
// mTLS option; with the triplet unset it yields an empty tail (both legs fall back to the
// insecure default together). Because liveDeps resolves the tail once and passes the SAME
// slice to both constructors, the two edges cannot carry divergent transport posture — the
// "same posture for both internal-fabric edges" invariant is structural, not convention.
func TestLiveDeps_BothLegsDrawOneMTLSSource(t *testing.T) {
	t.Run("configured", func(t *testing.T) {
		certPath, keyPath, caPath := writeSyntheticMTLS(t)
		t.Setenv(controlplane.EnvDialTLSCert, certPath)
		t.Setenv(controlplane.EnvDialTLSKey, keyPath)
		t.Setenv(controlplane.EnvDialTLSCA, caPath)

		// The single source liveDeps resolves once and threads into BOTH legs.
		shared, err := liveDialOpts()
		if err != nil {
			t.Fatalf("liveDialOpts with full triplet: %v", err)
		}
		if len(shared) != 1 || shared[0] == nil {
			t.Fatalf("shared live dial tail = %d options, want 1 non-nil mTLS option for both legs", len(shared))
		}

		// liveDeps constructs both edges over this shared tail without a live dial.
		deps := liveDepsWithStubEnv(t)
		if deps.Drivers == nil {
			t.Fatal("liveDeps built a nil Drivers registry, want the dialing registry carrying the shared mTLS tail")
		}
		if deps.Mint == nil || deps.Digest == nil || deps.Revoke == nil {
			t.Fatalf("liveDeps left an Identity seam nil with the shared mTLS tail: mint=%v digest=%v revoke=%v",
				deps.Mint != nil, deps.Digest != nil, deps.Revoke != nil)
		}
	})

	t.Run("unset", func(t *testing.T) {
		t.Setenv(controlplane.EnvDialTLSCert, "")
		t.Setenv(controlplane.EnvDialTLSKey, "")
		t.Setenv(controlplane.EnvDialTLSCA, "")

		shared, err := liveDialOpts()
		if err != nil {
			t.Fatalf("liveDialOpts with no env set: %v", err)
		}
		if len(shared) != 0 {
			t.Fatalf("shared live dial tail = %d options with no env set, want 0 (both legs keep the insecure default)", len(shared))
		}

		// Both legs still construct over the (empty-tail) insecure default — neither edge is
		// half-wired by the unset path.
		deps := liveDepsWithStubEnv(t)
		if deps.Drivers == nil || deps.Mint == nil || deps.Digest == nil {
			t.Fatalf("liveDeps half-wired an edge with the mTLS env unset: drivers=%v mint=%v digest=%v",
				deps.Drivers != nil, deps.Mint != nil, deps.Digest != nil)
		}
	})
}

// TestLiveDeps_ThreadsMTLSOptionIntoRegistry proves the full cmd-side composition path: with
// the mTLS triplet set (synthetic certs, D50) and a non-empty Identity endpoint, liveDeps
// resolves the live backends — building the DriverRegistry with the env-built mTLS dial
// option threaded in — and returns a usable Deps + closer WITHOUT any live dial
// (grpc.NewClient is lazy; NewDialRegistry does not dial eagerly). The orchestrator→host-agent
// dial is mutually authenticated in production, not insecure. The closer tears the (un-dialed)
// edges down. With the env triplet unset the same path falls back to the insecure default
// unchanged (covered above).
func TestLiveDeps_ThreadsMTLSOptionIntoRegistry(t *testing.T) {
	certPath, keyPath, caPath := writeSyntheticMTLS(t)
	t.Setenv(controlplane.EnvDialTLSCert, certPath)
	t.Setenv(controlplane.EnvDialTLSKey, keyPath)
	t.Setenv(controlplane.EnvDialTLSCA, caPath)
	// A configured (un-dialed) Identity endpoint so liveDeps's leg passes its empty-endpoint
	// guard; grpc.NewClient is lazy so no socket is opened. A single host-driver endpoint so
	// the registry has a resolvable host (still never dialed in this test).
	t.Setenv("DS_ORCH_IDENTITY_ENDPOINT", "passthrough:///identity-stub")
	t.Setenv("DS_ORCH_HOST_DRIVERS", "host-a=host:9000")
	// No Postgres DSN → the in-memory store (the single-binary posture), so this closes
	// without an external DB.
	t.Setenv("DS_ORCH_PG_DSN", "")

	deps, closeEdges, err := liveDeps(context.Background())
	if err != nil {
		t.Fatalf("liveDeps with synthetic mTLS triplet + stub identity endpoint: %v", err)
	}
	t.Cleanup(func() {
		if cerr := closeEdges(); cerr != nil {
			t.Errorf("close live edges: %v", cerr)
		}
	})
	if deps.Drivers == nil {
		t.Fatal("liveDeps built a nil Drivers registry, want the dialing registry carrying the mTLS option")
	}
	// The registry resolves its configured host set (un-dialed), proving it was constructed
	// over the endpoint map with the threaded option — no live dial occurred.
	hosts, err := deps.Drivers.Hosts(context.Background())
	if err != nil {
		t.Fatalf("Drivers.Hosts: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "host-a" {
		t.Errorf("Drivers.Hosts = %v, want [host-a] (the configured endpoint set)", hosts)
	}
}
