// SPDX-License-Identifier: Apache-2.0

// The runnable grant-service entrypoint — the thin wiring that makes the
// config-driven Backend selector reachable at DEPLOY time (doc 16 §11.3 per-tier
// backend swap; §5.1/§9 grant-fetch seam; D39/D50/D55/D80/D85).
//
// WHAT THIS IS. selector.go landed the deploy-time FACTORY
// (LoadConfigEnv/BindFlags -> SelectBackend) and server.go landed the
// GrantFetchServiceServer adapter (NewServer), but nothing invoked them: the
// GRANT_BACKEND_* surface was exercised only by selector_test.go and the served
// RPC only by server_test.go. This entrypoint closes the "selectable at deploy
// time" story end to end — it is the one place the whole chain runs as a process:
//
//	LoadConfigEnv() + BindFlags(fs)  ->  SelectorConfig          (env, then flag override)
//	SelectBackend(cfg)               ->  Backend                 (the tier swap, by CONFIG)
//	New(backend)                     ->  *Service                (session caches over the D39 store)
//	NewServer(svc)                   ->  *Server                 (the frozen GrantFetchService bind)
//	RegisterGrantFetchServiceServer  ->  grpc.Server             (the served RPC the swap executor calls)
//
// A deployment picks its store backend with CONFIG, never a code change (D19/D51;
// D80 — the tier boundary is a BACKEND boundary, never a flag toggling privileged
// behavior inside one binary). The OSS hosted tier runs the local file/KV fake
// (GRANT_BACKEND_MODE=file); bring-compute/on-prem points at the customer's
// OpenBao-compatible KV (GRANT_BACKEND_MODE=kv) — both behind the same Backend
// seam, so this entrypoint is identical for either.
//
// NO LIVE STORE AT STARTUP (D50). SelectBackend constructs a backend but performs
// NO network I/O: the file mode reads a synthetic JSON fixture, and the kv mode's
// login is lazy on first read (selector.go). So startup never dials a live
// OpenBao/Vault/KVM/host — the process binds a gRPC listener and serves; the first
// real store round-trip happens only when the swap executor issues a Fetch. The
// genuine listen+serve is factored into run() over a caller-supplied net.Listener,
// so main_test.go drives the exact same wiring over an ephemeral loopback socket
// (no fixed port, no off-box transport) and asserts a clean serve + shutdown
// against the file backend, never a real store.
//
// READ-ONLY POSTURE PRESERVED (§11.3). This entrypoint only ever wires the
// read-only fetch path (Service.Fetch / FetchWire / ReadSecret); it introduces no
// write/lease/dynamic surface — it constructs and serves, it does not mint.
//
// DEPLOYMENT HARDENING (this wave). The wave-1 entrypoint bound an INSECURE
// grpc.Server on loopback. Two additive hardenings make it deployable without
// reopening the seam:
//
//   - TRANSPORT CREDENTIALS, config-gated. The credential boundary for the served
//     grant-fetch RPC is the TLS-terminating egress gateway / off-host TLS
//     TERMINATION posture: in the default deployment the swap executor reaches the
//     grant service over a private, off-VM transport whose TLS is terminated at the
//     ds-tlsproxy / boundary edge, so the grant service itself binds LOOPBACK +
//     insecure as the explicit, gated default (fail-closed: off no external
//     interface until a deployment opts in). A deployment that instead terminates
//     TLS AT this process supplies GRANT_TLS_CERT + GRANT_TLS_KEY (env or
//     -grant-tls-cert/-grant-tls-key flag); the entrypoint then binds
//     grpc.Creds(credentials.NewServerTLSFromFile(...)) — server-authenticated TLS
//     directly on the served RPC. The gate is symmetric and explicit: NEITHER set
//     -> loopback-insecure (documented edge-terminated boundary); BOTH set -> TLS;
//     exactly one set -> fail closed (a half-configured TLS posture never silently
//     downgrades to insecure). No private key ever sits in this process beyond the
//     PEM the operator mounts; the long-lived store credentials are off-host (D8/D39
//     — see the backend seam), never on this binary.
//   - HEALTH / READINESS. A grpc.health server (google.golang.org/grpc/health +
//     grpc_health_v1, both subpackages of the grpc dep already required — NO new
//     third-party dependency) is registered alongside GrantFetchService so the swap
//     executor can probe liveness with Check/Watch BEFORE issuing Fetches. The
//     overall service is marked SERVING once the server is assembled and bound; the
//     lazy-login posture (no store I/O at startup, D50) means SERVING reflects "the
//     RPC surface is up", and a store outage stalls only NEW grant fetches in-band
//     (§5.1), never the liveness probe.
//
// proto/gen/go is the one legal cross-tree import (D80), arriving via the module's
// require+replace; this file consumes the generated registration only and touches
// no proto body. STDLIB + grpc (transitive with the generated types, incl. its
// credentials + health subpackages) only — no new third-party dependency. This
// module stays GOWORK=off (standalone).
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	grantservice "github.com/dream-serpent/dream-serpent/identity/grant-service"
	kvclient "github.com/dream-serpent/dream-serpent/identity/kv-client"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// defaultListenAddr is the loopback bind the entrypoint listens on absent an
// explicit -listen/GRANT_LISTEN_ADDR. Loopback-by-default keeps the served RPC
// off any external interface until a deployment opts in — fail-closed posture for
// the swap-credential seam (the credential never leaves the off-host grant
// service, D8/D39).
const defaultListenAddr = "127.0.0.1:8443"

// listenAddrEnv is the environment override for the bind address; a -listen flag
// (registered in main) takes precedence over it.
const listenAddrEnv = "GRANT_LISTEN_ADDR"

// TLS-credential env overrides. Set BOTH to terminate server-authenticated TLS at
// this process; set NEITHER for the loopback-insecure default (TLS terminated at
// the egress-gateway / ds-tlsproxy boundary). Setting exactly one fails closed.
const (
	tlsCertEnv = "GRANT_TLS_CERT"
	tlsKeyEnv  = "GRANT_TLS_KEY"
)

// tlsConfig is the resolved server-TLS posture for the entrypoint. The zero value
// (both fields empty) selects loopback-insecure with the off-host
// TLS-termination boundary as the credential boundary; both fields set selects
// in-process server TLS; exactly one set is rejected (resolveCreds) so a
// half-configured TLS posture can never silently downgrade to insecure.
type tlsConfig struct {
	certFile string
	keyFile  string
}

// resolveCreds turns the TLS config into the grpc.ServerOption set buildServer
// applies. It is the explicit, symmetric gate:
//
//	neither cert nor key -> no creds option (loopback-insecure default; the
//	                        credential boundary is the TLS-terminating egress
//	                        gateway / off-host TLS termination, D8/D39)
//	both set             -> grpc.Creds(NewServerTLSFromFile(cert, key)) — server
//	                        TLS terminated AT this process
//	exactly one set      -> error (fail closed: never downgrade a half-configured
//	                        TLS posture to insecure)
//
// secure reports whether transport credentials were applied, so callers can log
// the posture without re-deriving it.
func resolveCreds(tc tlsConfig) (opts []grpc.ServerOption, secure bool, err error) {
	switch {
	case tc.certFile == "" && tc.keyFile == "":
		return nil, false, nil
	case tc.certFile == "" || tc.keyFile == "":
		return nil, false, fmt.Errorf(
			"grant-service: TLS is half-configured (need BOTH %s and %s, or neither) — refusing to bind",
			tlsCertEnv, tlsKeyEnv)
	default:
		creds, err := credentials.NewServerTLSFromFile(tc.certFile, tc.keyFile)
		if err != nil {
			return nil, false, fmt.Errorf("grant-service: load server TLS keypair: %w", err)
		}
		return []grpc.ServerOption{grpc.Creds(creds)}, true, nil
	}
}

// buildServer wires the deploy-time selector chain into a registered grpc.Server,
// WITHOUT binding any socket or doing any store I/O. It is the pure assembly half
// of the entrypoint — LoadConfigEnv-shaped cfg -> SelectBackend -> New -> NewServer
// -> RegisterGrantFetchServiceServer — factored out so main() and the test drive
// the identical wiring. SelectBackend performs no network I/O (selector.go), so
// this never dials a live store (D50); a config that cannot name a backend fails
// closed here with ErrInvalidConfig, never a partial/silently-wrong server.
//
// TLS posture (tc) is resolved into server credentials BEFORE any backend work, so
// a half-configured TLS posture fails closed without touching the selector. The
// trailing httpOpts are forwarded verbatim to SelectBackend: production passes
// none (the kv-client uses HTTPS), and the process-level kv-mode test passes
// kvclient.WithHTTPClient over an httptest fake (D50) so the entire entrypoint
// chain runs in-process against a synthetic store — never a live one.
//
// A grpc.health server (health.NewServer + RegisterHealthServer) is registered
// alongside GrantFetchService and the overall service ("") is marked SERVING once
// the surface is assembled — the liveness probe the swap executor checks BEFORE
// issuing Fetches. SERVING reflects "the RPC surface is up"; the store login is
// lazy (D50) so a store outage stalls only NEW fetches in-band (§5.1), not health.
func buildServer(cfg grantservice.SelectorConfig, tc tlsConfig, httpOpts ...kvclient.Option) (*grpc.Server, error) {
	opts, _, err := resolveCreds(tc)
	if err != nil {
		return nil, err
	}
	backend, err := grantservice.SelectBackend(cfg, httpOpts...)
	if err != nil {
		return nil, fmt.Errorf("select backend: %w", err)
	}
	svc := grantservice.New(backend)
	srv := grpc.NewServer(opts...)
	identityv1.RegisterGrantFetchServiceServer(srv, grantservice.NewServer(svc))

	// Health/readiness: the swap executor probes liveness before Fetches. Mark the
	// overall service SERVING once the RPC surface is assembled (lazy store login,
	// D50 — SERVING is "surface up", not "store reachable").
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(srv, hs)

	return srv, nil
}

// run binds the assembled server to lis and serves until ctx is cancelled, then
// gracefully drains and returns. It owns the genuine listen/serve loop but takes
// the listener from its caller, so a test supplies an in-process/ephemeral
// listener and main supplies a real net.Listen on the configured address — the
// same serve path either way (D50: the test never binds a fixed port or dials a
// real store).
//
// Shutdown is cooperative: when ctx is cancelled (a SIGINT/SIGTERM in main, or the
// test's cancel), GracefulStop drains in-flight Fetches and unblocks Serve, which
// returns nil on a clean GracefulStop. A genuine Serve error (a broken listener)
// propagates.
func run(ctx context.Context, srv *grpc.Server, lis net.Listener) error {
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(lis) }()

	select {
	case <-ctx.Done():
		// Cooperative shutdown: drain in-flight RPCs, then collect Serve's return.
		srv.GracefulStop()
		// Serve returns nil after a GracefulStop; surface any genuine error.
		if err := <-serveErr; err != nil && err != grpc.ErrServerStopped {
			return err
		}
		return nil
	case err := <-serveErr:
		// Serve returned on its own (listener failure); stop and surface it.
		srv.GracefulStop()
		if err != nil && err != grpc.ErrServerStopped {
			return err
		}
		return nil
	}
}

// resolveListenAddr returns the effective bind address: the explicit flag/env
// value when set, else the loopback default. The flag (main wires it seeded from
// the env) is the override; an empty value falls back to the default.
func resolveListenAddr(flagAddr string) string {
	if flagAddr != "" {
		return flagAddr
	}
	return defaultListenAddr
}

// realMain is the testable body of main: it reads config from the environment,
// folds in flag overrides, assembles the registered server (no store I/O), binds a
// real listener, and serves until a termination signal. It returns an error
// instead of exiting so main() owns the process-exit policy and a future caller
// could drive it. The listen address comes from -listen (seeded from
// GRANT_LISTEN_ADDR), the backend from the GRANT_BACKEND_* surface.
func realMain(args []string) error {
	// Env first (the deployment default), then flags as the override — the
	// combine-env-then-flags pattern BindFlags is built for (selector.go).
	cfg := grantservice.LoadConfigEnv()
	fs := flag.NewFlagSet("grant-service", flag.ContinueOnError)
	finalize := grantservice.BindFlags(fs, &cfg)
	listenAddr := os.Getenv(listenAddrEnv)
	fs.StringVar(&listenAddr, "listen", listenAddr, "gRPC bind address for the grant-fetch service (env GRANT_LISTEN_ADDR)")
	tc := tlsConfig{certFile: os.Getenv(tlsCertEnv), keyFile: os.Getenv(tlsKeyEnv)}
	fs.StringVar(&tc.certFile, "grant-tls-cert", tc.certFile, "server TLS certificate PEM; with -grant-tls-key terminates TLS at this process (env GRANT_TLS_CERT)")
	fs.StringVar(&tc.keyFile, "grant-tls-key", tc.keyFile, "server TLS private-key PEM; with -grant-tls-cert terminates TLS at this process (env GRANT_TLS_KEY)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	finalize() // fold the string-valued mode/auth flags back onto cfg's typed fields

	// Resolve the TLS posture for logging; buildServer re-resolves and is the
	// authoritative gate. A half-configured TLS posture fails closed here too,
	// before any listen.
	_, secure, err := resolveCreds(tc)
	if err != nil {
		return err
	}

	// Production passes no kvclient.Option (the kv-client uses HTTPS); the
	// process-level kv-mode test injects its httptest fake via buildServer directly.
	srv, err := buildServer(cfg, tc)
	if err != nil {
		return err
	}

	addr := resolveListenAddr(listenAddr)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	transport := "loopback-insecure (TLS terminated at the egress-gateway / ds-tlsproxy boundary)"
	if secure {
		transport = "server-TLS (terminated at this process)"
	}
	fmt.Fprintf(os.Stderr, "grant-service: serving GrantFetchService + health on %s (backend mode %q, transport %s)\n", lis.Addr(), cfg.Mode, transport)

	// Serve until a termination signal; the signal cancels ctx, which run()
	// turns into a graceful drain.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return run(ctx, srv, lis)
}

func main() {
	if err := realMain(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "grant-service: %v\n", err)
		os.Exit(1)
	}
}
