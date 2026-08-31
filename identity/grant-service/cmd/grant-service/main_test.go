// SPDX-License-Identifier: Apache-2.0

// Entrypoint wiring tests for cmd/grant-service (doc 16 §11.3 per-tier backend
// swap; §5.1/§9 grant-fetch seam; D39/D50/D55/D80/D85).
//
// WHAT THESE PROVE. The entrypoint is the one place the deploy-time selector chain
// runs as a process: LoadConfigEnv/BindFlags -> SelectBackend -> New -> NewServer
// -> RegisterGrantFetchServiceServer -> bind+serve. These tests exercise that
// wiring WITHOUT a live store (D50):
//
//   - TestBuildServer_BackendModeSelection: each GRANT_BACKEND_* mode selects the
//     expected Backend via the SAME SelectorConfig the entrypoint consumes — file
//     mode against a synthetic temp fixture succeeds, an unknown mode fails closed
//     (no default-allow), and an incomplete file/kv config is rejected before any
//     server is built.
//   - TestRun_ServesAndShutsDownCleanly: the assembled server is bound to an
//     EPHEMERAL loopback listener (port 0 — no fixed port, no off-box transport), a
//     real GrantFetchServiceClient dials it, a Fetch returns the IN-BAND reason for
//     the synthetic fixture (a transport-level nil error, the deny/stall split
//     riding GrantFetchResponse.reason per open-question default #2), and a context
//     cancel drains the server cleanly with no Serve error.
//   - TestResolveCreds_TLSGate: the config-gated TLS posture — neither cert nor key
//     is the loopback-insecure default (credential boundary at the egress-gateway /
//     ds-tlsproxy TLS-termination edge), both set yields server credentials, and
//     exactly one set fails CLOSED (a half-configured TLS posture never silently
//     downgrades to insecure).
//   - TestRun_HealthServingBeforeFetch: a grpc.health client Checks the served
//     surface and sees SERVING BEFORE issuing a Fetch — the liveness probe the swap
//     executor relies on.
//   - TestBuildServer_KVModeOverHTTPTestFake: the FULL entrypoint chain in kv mode
//     (GRANT_BACKEND_MODE=kv) assembled and served over an httptest KV-v2 fake via
//     kvclient.WithHTTPClient (D50) — the process-level kv-mode wiring matching the
//     file-mode coverage, never a live store.
//
// SYNTHETIC ONLY (D50). The backend is the OSS local file/KV fake loaded from a
// per-test temp JSON fixture, or an httptest KV-v2 fake reached only through
// kvclient.WithHTTPClient; the transport is a loopback TCP socket bound on an
// ephemeral port and torn down by the test — never a live OpenBao/Vault/KVM/host
// and never a fixed externally-reachable port. The TLS-gate test generates an
// EPHEMERAL self-signed keypair in a temp dir; no real key material anywhere.
// ADDITIVE: this file adds coverage only; it weakens no existing grant-service
// assertion and constructs nothing the selector/server tests do not already cover.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	grantservice "github.com/dream-serpent/dream-serpent/identity/grant-service"
	kvclient "github.com/dream-serpent/dream-serpent/identity/kv-client"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// synthSession/synthService/synthRef are the synthetic binding the temp fixture is
// keyed on (D50 — synthetic UUID, secret appears only in the fixture). synthRef is
// the FormatGrantRef handle the store is keyed by, matching the committed golden
// shape "grant:<session>:<service>".
const (
	synthSession = "00000000-0000-4000-8000-0000000000a1"
	synthService = "github"
	synthSecret  = "SYNTHETIC-PAT-DO-NOT-USE-d50-entrypoint-fixture"
)

func synthRef() string { return grantservice.FormatGrantRef(synthSession, synthService) }

// listenLoopback binds an EPHEMERAL loopback TCP listener (127.0.0.1:0 — the
// kernel assigns a free port) the test owns and tears down (D50: a real socket,
// but loopback-only and never a fixed/external port). It mirrors the real
// net.Listen("tcp", addr) main() does, so run() drives the identical serve path.
func listenLoopback(t *testing.T) (net.Listener, error) {
	t.Helper()
	return net.Listen("tcp", "127.0.0.1:0")
}

// writeSyntheticStore writes a synthetic grant_ref -> {secret, location} JSON
// fixture to a per-test temp file (D50) and returns its path. It is the local
// file/KV fake's on-disk shape (backend.go fileEntry): a JSON object keyed by
// grant_ref. No real key material — the secret is a labelled synthetic.
func writeSyntheticStore(t *testing.T) string {
	t.Helper()
	store := map[string]map[string]string{
		synthRef(): {"secret": synthSecret, "location": "Authorization"},
	}
	raw, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		t.Fatalf("marshal synthetic store: %v", err)
	}
	path := filepath.Join(t.TempDir(), "synthetic-store.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write synthetic store: %v", err)
	}
	return path
}

// TestBuildServer_BackendModeSelection pins the deploy-time selector behavior the
// entrypoint relies on: file mode over a synthetic fixture assembles a server, an
// unknown mode fails CLOSED (no default-allow), and incomplete file/kv configs are
// rejected as ErrInvalidConfig before any server is built. It drives buildServer
// with the SAME SelectorConfig main() folds from the GRANT_BACKEND_* env + flags,
// so the env surface is exercised by construction. No store I/O happens here —
// SelectBackend constructs only (D50).
func TestBuildServer_BackendModeSelection(t *testing.T) {
	storePath := writeSyntheticStore(t)

	cases := []struct {
		name    string
		cfg     grantservice.SelectorConfig
		wantErr bool
		// invalidCfg asserts the error is the fail-closed ErrInvalidConfig, not some
		// other failure.
		invalidCfg bool
	}{
		{
			name: "file mode with fixture assembles a server",
			cfg:  grantservice.SelectorConfig{Mode: grantservice.ModeFile, FilePath: storePath},
		},
		{
			name: "empty mode defaults to file and assembles a server",
			cfg:  grantservice.SelectorConfig{FilePath: storePath},
		},
		{
			name:       "file mode without a fixture fails closed",
			cfg:        grantservice.SelectorConfig{Mode: grantservice.ModeFile},
			wantErr:    true,
			invalidCfg: true,
		},
		{
			name:       "unknown mode fails closed (no default-allow)",
			cfg:        grantservice.SelectorConfig{Mode: grantservice.BackendMode("postgres")},
			wantErr:    true,
			invalidCfg: true,
		},
		{
			name:       "kv mode without addr/mount/auth fails closed",
			cfg:        grantservice.SelectorConfig{Mode: grantservice.ModeKV},
			wantErr:    true,
			invalidCfg: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := buildServer(tc.cfg, tlsConfig{}) // loopback-insecure default
			if tc.wantErr {
				if err == nil {
					t.Fatalf("buildServer(%+v): want error, got nil server=%v", tc.cfg, srv != nil)
				}
				if tc.invalidCfg && !errors.Is(err, grantservice.ErrInvalidConfig) {
					t.Fatalf("buildServer(%+v): want ErrInvalidConfig, got %v", tc.cfg, err)
				}
				if srv != nil {
					t.Fatalf("buildServer(%+v): a failed selection must yield no server", tc.cfg)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildServer(%+v): unexpected error: %v", tc.cfg, err)
			}
			if srv == nil {
				t.Fatalf("buildServer(%+v): nil server on success", tc.cfg)
			}
			srv.Stop()
		})
	}
}

// TestRealMain_RejectsUnknownFlag pins that realMain surfaces a flag parse error
// (e.g. an unknown flag) as a returned error rather than a silent default — the
// flag.ContinueOnError contract the entrypoint relies on so main() owns the exit.
// No server is bound on a parse failure.
func TestRealMain_RejectsUnknownFlag(t *testing.T) {
	if err := realMain([]string{"-no-such-flag"}); err == nil {
		t.Fatal("realMain: an unknown flag must return a parse error, not bind a server")
	}
}

// TestRealMain_BadBackendConfigFailsClosed pins that realMain folds the
// GRANT_BACKEND_* flags through SelectBackend and fails CLOSED on a config that
// cannot name a backend — here an unknown -grant-backend-mode — returning
// ErrInvalidConfig before any listen. This proves the BindFlags -> finalize ->
// SelectBackend chain runs in the entrypoint (not just selector_test.go), with no
// store I/O and no socket bound.
func TestRealMain_BadBackendConfigFailsClosed(t *testing.T) {
	err := realMain([]string{"-grant-backend-mode", "postgres", "-listen", "127.0.0.1:0"})
	if err == nil {
		t.Fatal("realMain: an unknown backend mode must fail closed before listening")
	}
	if !errors.Is(err, grantservice.ErrInvalidConfig) {
		t.Fatalf("realMain: want ErrInvalidConfig for an unknown mode, got %v", err)
	}
}

// TestRun_ServesAndShutsDownCleanly drives the FULL entrypoint serve path with no
// live store (D50): buildServer (file backend over a synthetic temp fixture) ->
// run over an EPHEMERAL loopback listener -> a real GrantFetchServiceClient dials
// it -> a Fetch returns the IN-BAND reason for the synthetic binding (a nil
// transport error; the deny/stall split rides GrantFetchResponse.reason per
// open-question default #2) -> a context cancel drains the server cleanly.
//
// The session is not registered through this entrypoint (RegisterSession is
// orchestrator-driven over another seam, NOT on the fetch wire — wire.go
// open-question default #1), so the Fetch fails CLOSED in-band with
// SESSION_NOT_LIVE: a valid, transport-clean fetch OUTCOME that exercises the
// served RPC end to end without a live store. The point is the WIRING — bind,
// serve, in-band reason, clean shutdown — not a successful credential fetch.
func TestRun_ServesAndShutsDownCleanly(t *testing.T) {
	storePath := writeSyntheticStore(t)
	srv, err := buildServer(grantservice.SelectorConfig{Mode: grantservice.ModeFile, FilePath: storePath}, tlsConfig{})
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}

	// Ephemeral loopback bind (port 0): a real socket the test owns and tears down,
	// never a fixed/external port (D50).
	lis, err := listenLoopback(t)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, srv, lis) }()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		<-runErr
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	client := identityv1.NewGrantFetchServiceClient(conn)

	fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fetchCancel()
	resp, err := client.Fetch(fetchCtx, &identityv1.GrantFetchRequest{
		SessionUuid: synthSession,
		ServiceId:   synthService,
		GrantRef:    synthRef(),
	})
	if err != nil {
		cancel()
		<-runErr
		t.Fatalf("served Fetch returned a transport error; the outcome must ride the in-band reason: %v", err)
	}
	// In-band reason for the synthetic binding: the session was never registered on
	// this entrypoint, so the fetch fails closed in-band as SESSION_NOT_LIVE — a
	// definitive deny, never a transport error (open-question default #2).
	if resp.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE {
		t.Fatalf("want in-band SESSION_NOT_LIVE for the unregistered synthetic session, got %v", resp.GetReason())
	}
	if !grantservice.ReasonIsDeny(resp.GetReason()) {
		t.Fatal("an unregistered-session fetch must classify as a deny")
	}
	if resp.GetCredential() != nil && len(resp.GetCredential().GetSecret()) != 0 {
		t.Fatal("a denied fetch must carry no secret")
	}

	// Clean shutdown: cancelling ctx makes run() GracefulStop and return nil.
	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run returned a non-nil error on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after context cancel (graceful shutdown hung)")
	}
}

// TestResolveListenAddr pins the bind-address precedence the entrypoint uses: an
// explicit flag/env value wins, an empty value falls back to the loopback default
// (off any external interface until a deployment opts in).
func TestResolveListenAddr(t *testing.T) {
	if got := resolveListenAddr("10.0.0.5:9000"); got != "10.0.0.5:9000" {
		t.Fatalf("explicit addr: got %q", got)
	}
	if got := resolveListenAddr(""); got != defaultListenAddr {
		t.Fatalf("empty addr: got %q, want default %q", got, defaultListenAddr)
	}
}

// writeEphemeralTLSKeypair generates a self-signed ECDSA keypair in a per-test
// temp dir and returns the cert + key PEM paths (D50: ephemeral, generated in
// process, never a real/committed key). It exists so the TLS gate can be exercised
// with a credentials.NewServerTLSFromFile-loadable keypair without any external
// fixture or a live CA.
func writeEphemeralTLSKeypair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "grant-service-synthetic"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// credentialsFromCert builds client transport credentials that trust the
// synthetic server cert as a root (D50), using "localhost" as the server-name
// override to match the cert's DNS SAN over a 127.0.0.1 dial. It is the test-side
// counterpart that lets a client complete the server-TLS handshake the entrypoint
// terminates.
func credentialsFromCert(certPath string) (credentials.TransportCredentials, error) {
	return credentials.NewClientTLSFromFile(certPath, "localhost")
}

// TestResolveCreds_TLSGate pins the config-gated TLS posture the entrypoint
// enforces (doc 16 §8.2 / D8/D39 — the credential boundary is the TLS-terminating
// egress gateway by default, and TLS may instead terminate AT this process):
//
//	neither cert nor key -> no creds (loopback-insecure default), secure=false
//	both set             -> server credentials applied, secure=true
//	exactly one set      -> fail CLOSED (never downgrade a half-configured posture)
//
// This is the load-bearing fail-closed assertion: a partially-configured TLS
// posture must error, not silently serve insecure.
func TestResolveCreds_TLSGate(t *testing.T) {
	certPath, keyPath := writeEphemeralTLSKeypair(t)

	t.Run("neither set is the loopback-insecure default", func(t *testing.T) {
		opts, secure, err := resolveCreds(tlsConfig{})
		if err != nil {
			t.Fatalf("resolveCreds(none): unexpected error: %v", err)
		}
		if secure {
			t.Fatal("resolveCreds(none): want insecure default, got secure")
		}
		if len(opts) != 0 {
			t.Fatalf("resolveCreds(none): want no creds option, got %d", len(opts))
		}
	})

	t.Run("both set applies server TLS", func(t *testing.T) {
		opts, secure, err := resolveCreds(tlsConfig{certFile: certPath, keyFile: keyPath})
		if err != nil {
			t.Fatalf("resolveCreds(both): unexpected error: %v", err)
		}
		if !secure {
			t.Fatal("resolveCreds(both): want secure, got insecure")
		}
		if len(opts) != 1 {
			t.Fatalf("resolveCreds(both): want one creds option, got %d", len(opts))
		}
	})

	t.Run("cert only fails closed", func(t *testing.T) {
		if _, secure, err := resolveCreds(tlsConfig{certFile: certPath}); err == nil || secure {
			t.Fatalf("resolveCreds(cert-only): want fail-closed error, got secure=%v err=%v", secure, err)
		}
	})

	t.Run("key only fails closed", func(t *testing.T) {
		if _, secure, err := resolveCreds(tlsConfig{keyFile: keyPath}); err == nil || secure {
			t.Fatalf("resolveCreds(key-only): want fail-closed error, got secure=%v err=%v", secure, err)
		}
	})

	t.Run("a bad keypair fails closed", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "nope.pem")
		if _, secure, err := resolveCreds(tlsConfig{certFile: bad, keyFile: bad}); err == nil || secure {
			t.Fatalf("resolveCreds(bad): want load error, got secure=%v err=%v", secure, err)
		}
	})
}

// TestBuildServer_TLSWiresServerCredentials proves a both-set TLS posture flows
// through buildServer end to end: the assembled server carries server credentials,
// a client dialing with the same cert as a TLS root completes a Fetch (the in-band
// SESSION_NOT_LIVE deny — the wiring, not a successful fetch), and the server drains
// cleanly. The transport is loopback-only over an ephemeral port (D50).
func TestBuildServer_TLSWiresServerCredentials(t *testing.T) {
	storePath := writeSyntheticStore(t)
	certPath, keyPath := writeEphemeralTLSKeypair(t)
	srv, err := buildServer(
		grantservice.SelectorConfig{Mode: grantservice.ModeFile, FilePath: storePath},
		tlsConfig{certFile: certPath, keyFile: keyPath},
	)
	if err != nil {
		t.Fatalf("buildServer(tls): %v", err)
	}

	lis, err := listenLoopback(t)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, srv, lis) }()

	clientCreds, err := credentialsFromCert(certPath)
	if err != nil {
		cancel()
		<-runErr
		t.Fatalf("client creds: %v", err)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(clientCreds))
	if err != nil {
		cancel()
		<-runErr
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fetchCancel()
	resp, err := identityv1.NewGrantFetchServiceClient(conn).Fetch(fetchCtx, &identityv1.GrantFetchRequest{
		SessionUuid: synthSession,
		ServiceId:   synthService,
		GrantRef:    synthRef(),
	})
	if err != nil {
		cancel()
		<-runErr
		t.Fatalf("Fetch over server-TLS returned a transport error: %v", err)
	}
	if resp.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE {
		t.Fatalf("want in-band SESSION_NOT_LIVE over TLS, got %v", resp.GetReason())
	}

	cancel()
	if err := <-runErr; err != nil {
		t.Fatalf("run returned non-nil on graceful shutdown: %v", err)
	}
}

// TestRun_HealthServingBeforeFetch proves the swap executor can probe liveness
// BEFORE issuing Fetches: the served surface answers a grpc.health Check with
// SERVING (overall service ""), and the same connection then completes a Fetch.
// Health reflects "RPC surface up" under the lazy-login posture (D50) — no live
// store is reachable, yet the probe is SERVING.
func TestRun_HealthServingBeforeFetch(t *testing.T) {
	storePath := writeSyntheticStore(t)
	srv, err := buildServer(grantservice.SelectorConfig{Mode: grantservice.ModeFile, FilePath: storePath}, tlsConfig{})
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	lis, err := listenLoopback(t)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, srv, lis) }()
	defer func() {
		cancel()
		<-runErr
	}()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	checkCtx, checkCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer checkCancel()
	// Liveness probe BEFORE any Fetch.
	hresp, err := healthpb.NewHealthClient(conn).Check(checkCtx, &healthpb.HealthCheckRequest{Service: ""})
	if err != nil {
		t.Fatalf("health Check returned an error before any Fetch: %v", err)
	}
	if hresp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("want SERVING before Fetch, got %v", hresp.GetStatus())
	}

	// Only after the probe says SERVING does the executor issue a Fetch — proving the
	// ordering the executor relies on works on the same served surface.
	resp, err := identityv1.NewGrantFetchServiceClient(conn).Fetch(checkCtx, &identityv1.GrantFetchRequest{
		SessionUuid: synthSession, ServiceId: synthService, GrantRef: synthRef(),
	})
	if err != nil {
		t.Fatalf("Fetch after SERVING probe returned a transport error: %v", err)
	}
	if resp.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE {
		t.Fatalf("want in-band SESSION_NOT_LIVE, got %v", resp.GetReason())
	}
}

// --- process-level kv-mode wiring (folded FU4) ---

// synthKVFake is a minimal httptest OpenBao/Vault KV-v2 fake (D50) speaking the
// documented wire shapes the kv-client uses — auth/<mount>/login ->
// {"auth":{"client_token":...}} and <mount>/data/<path> ->
// {"data":{"data":...}}. It is the package-main analogue of grantservice's
// in-package fakeOpenBao (which is a grantservice-package test type, unreachable
// from package main), kept deliberately small: enough to drive the kv-mode
// entrypoint chain over kvclient.WithHTTPClient, never a live store.
type synthKVFake struct {
	srv         *httptest.Server
	role, jwt   string
	mintToken   string
	secrets     map[string]map[string]any // "<mount>/<path>" -> KV-v2 data
	methodsSeen map[string]int
}

func newSynthKVFake(t *testing.T) *synthKVFake {
	t.Helper()
	f := &synthKVFake{
		role:        "ds-synth-platform-role",
		jwt:         "ds-synth-platform-jwt",
		mintToken:   "ds-synth-vault-token-entrypoint",
		secrets:     map[string]map[string]any{},
		methodsSeen: map[string]int{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.methodsSeen[r.Method]++
		p := strings.TrimPrefix(r.URL.Path, "/v1/")
		switch {
		case strings.HasPrefix(p, "auth/") && strings.HasSuffix(p, "/login"):
			if r.Method != http.MethodPost {
				writeKVErr(w, http.StatusMethodNotAllowed, "login is POST")
				return
			}
			var body map[string]string
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
				writeKVErr(w, http.StatusBadRequest, "bad login body")
				return
			}
			if body["jwt"] != f.jwt || body["role"] != f.role {
				writeKVErr(w, http.StatusBadRequest, "invalid jwt/role")
				return
			}
			writeKVJSON(w, http.StatusOK, map[string]any{
				"auth": map[string]any{"client_token": f.mintToken, "lease_duration": 3600, "renewable": true},
			})
		case strings.Contains(p, "/data/"):
			if r.Method != http.MethodGet {
				writeKVErr(w, http.StatusMethodNotAllowed, "read is GET")
				return
			}
			key := strings.Replace(p, "/data/", "/", 1)
			data, ok := f.secrets[key]
			if !ok {
				writeKVErr(w, http.StatusNotFound, "no secret")
				return
			}
			writeKVJSON(w, http.StatusOK, map[string]any{
				"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}},
			})
		default:
			writeKVErr(w, http.StatusNotFound, "unsupported path: "+p)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func writeKVJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeKVErr(w http.ResponseWriter, status int, msg string) {
	writeKVJSON(w, status, map[string]any{"errors": []string{msg}})
}

// TestBuildServer_KVModeOverHTTPTestFake is the folded FU4 process-level kv-mode
// wiring test: GRANT_BACKEND_MODE=kv assembled through the SAME buildServer the
// entrypoint uses, served over an EPHEMERAL loopback listener, with the kv-client
// pointed at an httptest KV-v2 fake via kvclient.WithHTTPClient (D50). It matches
// the file-mode TestRun coverage — same served Fetch, same in-band reason, same
// clean shutdown — proving the kv tier is selectable end to end at the process
// boundary without a live store.
//
// The default KV path derivation is grants/<session>/<service> (selector.go /
// kvbackend.go defaultKVPath), so the fake is seeded at "secret/grants/<s>/<svc>".
// The session is unregistered on this entrypoint (RegisterSession is
// orchestrator-driven, not on the fetch wire), so the fetch fails closed in-band
// with SESSION_NOT_LIVE BEFORE the backend is consulted — a transport-clean deny
// that exercises the kv wiring chain (config -> SelectBackend(kv) -> New ->
// NewServer -> bind+serve) end to end.
func TestBuildServer_KVModeOverHTTPTestFake(t *testing.T) {
	f := newSynthKVFake(t)
	// Seed the credential at the path defaultKVPath derives, so a live fetch (were
	// the session registered) would resolve — the kv chain is fully wired even
	// though this entrypoint's unregistered session denies in-band first.
	f.secrets["secret/grants/"+synthSession+"/"+synthService] = map[string]any{
		"secret":   "ds-synth-kv-entrypoint-cred",
		"location": "Authorization",
	}

	cfg := grantservice.SelectorConfig{
		Mode:  grantservice.ModeKV,
		Addr:  f.srv.URL,
		Mount: "secret",
		Auth:  grantservice.AuthJWTOIDC,
		Role:  f.role,
		JWT:   f.jwt,
	}
	// The httptest fake's client is the ONLY transport — no live store (D50).
	srv, err := buildServer(cfg, tlsConfig{}, kvclient.WithHTTPClient(f.srv.Client()))
	if err != nil {
		t.Fatalf("buildServer(kv): %v", err)
	}

	lis, err := listenLoopback(t)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- run(ctx, srv, lis) }()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		cancel()
		<-runErr
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	fetchCtx, fetchCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer fetchCancel()
	resp, err := identityv1.NewGrantFetchServiceClient(conn).Fetch(fetchCtx, &identityv1.GrantFetchRequest{
		SessionUuid: synthSession,
		ServiceId:   synthService,
		GrantRef:    synthRef(),
	})
	if err != nil {
		cancel()
		<-runErr
		t.Fatalf("kv-mode served Fetch returned a transport error: %v", err)
	}
	if resp.GetReason() != identityv1.GrantFetchReason_GRANT_FETCH_REASON_SESSION_NOT_LIVE {
		t.Fatalf("want in-band SESSION_NOT_LIVE for the unregistered synthetic session, got %v", resp.GetReason())
	}
	if !grantservice.ReasonIsDeny(resp.GetReason()) {
		t.Fatal("an unregistered-session fetch must classify as a deny")
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("run returned non-nil on graceful shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after context cancel (kv-mode shutdown hung)")
	}
}

// --- process-level realMain SIGTERM-drain smoke (env-gated) ---

// processSmokeGateEnv gates the process-level smoke. The realMain bind+serve+
// SIGTERM seam — the actual signal.NotifyContext(SIGINT/SIGTERM) drain in
// main.go — is the one path the in-process run()/buildServer tests above cannot
// reach (they drive run() over a context cancel, never realMain's own signal
// handler). Exercising it requires delivering a real SIGTERM to THIS test
// process, which signal.NotifyContext installs a handler for; absent the gate
// the test process must never self-signal, so this defaults to SKIP, matching
// the other deferred legs in this package.
const processSmokeGateEnv = "DS_GRANT_PROCESS_SMOKE"

// freeLoopbackAddr binds an ephemeral 127.0.0.1:0 listener, records its address,
// and closes it — returning a concrete host:port the kernel just confirmed free.
// realMain owns its own net.Listen (it never hands the test a listener), so the
// test must name a concrete address up front to dial back; this is the standard
// hermetic discovery of a free loopback port (D50: loopback-only, never a fixed
// or external port — the port is kernel-assigned per run). A vanishingly small
// reuse window between close and realMain's re-listen is acceptable for a
// deliberately env-gated smoke.
func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe a free loopback port: %v", err)
	}
	addr := lis.Addr().String()
	if err := lis.Close(); err != nil {
		t.Fatalf("close probe listener: %v", err)
	}
	return addr
}

// waitHealthServing dials addr and polls the grpc.health Check until the overall
// service ("") reports SERVING or the deadline passes, returning whether it came
// up. It is how the smoke confirms realMain genuinely BOUND and is SERVING (the
// liveness probe the swap executor itself uses) before delivering SIGTERM.
func waitHealthServing(t *testing.T, addr string, within time.Duration) bool {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()
	hc := healthpb.NewHealthClient(conn)
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		cctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		hresp, err := hc.Check(cctx, &healthpb.HealthCheckRequest{Service: ""})
		cancel()
		if err == nil && hresp.GetStatus() == healthpb.HealthCheckResponse_SERVING {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

// TestRealMain_ProcessSmoke_SIGTERMDrains is the env-gated process-level smoke
// for the last untested realMain seam: bind + serve + the actual
// signal.NotifyContext(SIGINT/SIGTERM) graceful drain (main.go realMain). The
// in-process tests above drive run() over a context cancel and buildServer over
// the SAME wiring, but none delivers a genuine signal through realMain's own
// handler — this does.
//
// It runs realMain end to end against the OSS file backend over a synthetic temp
// fixture (D50 — no live OpenBao/Vault/KVM/host/store; the store login is lazy so
// startup dials nothing), on a kernel-assigned loopback port (no fixed/external
// port), confirms it BOUND + SERVING via a grpc.health Check, delivers SIGTERM to
// THIS process (which signal.NotifyContext routes into the drain), and asserts
// realMain returns nil — a clean graceful drain + exit — within a timeout.
//
// SKIP by default (gate unset) AND when signal delivery is unavailable
// (e.g. GOOS without SIGTERM), so it never self-signals the test process outside
// a deliberate opt-in. ADDITIVE: it weakens no existing assertion.
func TestRealMain_ProcessSmoke_SIGTERMDrains(t *testing.T) {
	if os.Getenv(processSmokeGateEnv) == "" {
		t.Skipf("process-level realMain SIGTERM smoke is gated: set %s=1 to run (it self-delivers SIGTERM)", processSmokeGateEnv)
	}
	// SIGTERM is a POSIX signal; on a GOOS without it (notably windows) the smoke
	// cannot deliver one, so skip rather than fail.
	if runtime.GOOS == "windows" {
		t.Skipf("SIGTERM delivery is unavailable on %s; skipping the process smoke", runtime.GOOS)
	}
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Skipf("cannot resolve this process for signal delivery (%v); skipping the process smoke", err)
	}

	// Synthetic file backend over a temp fixture — the OSS local KV fake, never a
	// live store (D50). realMain reads it through the GRANT_BACKEND_* env surface,
	// exactly as a deployment would.
	storePath := writeSyntheticStore(t)
	t.Setenv("GRANT_BACKEND_MODE", string(grantservice.ModeFile))
	t.Setenv("GRANT_BACKEND_FILE_PATH", storePath)
	// Ensure no stray TLS env from the harness flips realMain into the half- or
	// fully-configured TLS posture: this leg asserts the loopback-insecure drain.
	t.Setenv(tlsCertEnv, "")
	t.Setenv(tlsKeyEnv, "")

	addr := freeLoopbackAddr(t)

	// realMain owns the signal.NotifyContext + the genuine net.Listen + serve loop;
	// drive it exactly as main() would, with -listen naming the kernel-confirmed
	// free loopback port (env GRANT_LISTEN_ADDR would work identically).
	mainErr := make(chan error, 1)
	go func() { mainErr <- realMain([]string{"-listen", addr}) }()

	// Confirm it genuinely BOUND and is SERVING before signalling — this is the
	// bind+serve half of the seam.
	if !waitHealthServing(t, addr, 5*time.Second) {
		// realMain may have failed to bind (e.g. the tiny reuse race); surface its
		// error if it already returned, else fail on the missing readiness.
		select {
		case err := <-mainErr:
			t.Fatalf("realMain returned before serving: %v", err)
		default:
			t.Fatalf("realMain did not reach SERVING on %s within the deadline", addr)
		}
	}

	// Deliver SIGTERM to THIS process. signal.NotifyContext (installed by realMain)
	// catches it and cancels its ctx, which run() turns into a GracefulStop drain —
	// the process is NOT killed because a handler is installed. This is the exact
	// path main() relies on for an operator's `kill -TERM`.
	if err := self.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("deliver SIGTERM to self: %v", err)
	}

	// Assert a clean graceful drain + return (nil error) within a timeout — the
	// drain half of the seam.
	select {
	case err := <-mainErr:
		if err != nil {
			t.Fatalf("realMain returned non-nil after SIGTERM; want a clean graceful drain: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("realMain did not return after SIGTERM (graceful drain hung)")
	}
}
