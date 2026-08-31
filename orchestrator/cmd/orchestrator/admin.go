package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
)

// adminAddrEnv is the env var that ARMS the operability admin surface: an HTTP
// listen address (e.g. "127.0.0.1:6060") that serves the stdlib expvar /debug/vars
// payload. It is read inside the DS_ORCH_LIVE=1 bootstrap (run), so a non-live run —
// and every default test — never binds it (D50: the live edge stays env-gated). When
// the var is UNSET the admin server is not started at all (no surface), so the
// orchestrator's default posture exposes no /debug/vars socket.
const adminAddrEnv = "DS_ORCH_ADMIN_ADDR"

// adminTokenEnv is the OPTIONAL shared-secret env var that arms a bearer-token guard
// on the admin surface. When it is set to a non-empty value, every /debug/vars request
// must carry a matching `Authorization: Bearer <token>` header or it is refused 401 —
// the D77 fail-closed posture for an authenticated surface (no header / wrong token =
// no read). When it is UNSET the surface relies on the loopback bind alone (the
// dev-default posture: a 127.0.0.1-bound surface is reachable only from the host). The
// secret is ENV-SOURCED ONLY and never committed (D50): synthetic tokens in tests, the
// real secret supplied by the operator at the binary boundary.
const adminTokenEnv = "DS_ORCH_ADMIN_TOKEN"

// adminAllowNonLoopbackEnv is the explicit opt-out that lets the admin surface bind a
// NON-loopback address. By default the surface refuses any non-loopback
// DS_ORCH_ADMIN_ADDR at construction (the surface exposes internal metric names/values
// — the step-9 degrade totals, the per-host degrade map keyed by host_id, the resolved
// cap — so a world-reachable bind is a fail-closed refusal, not a silent default). An
// operator who deliberately fronts the surface (e.g. behind a TLS-terminating reverse
// proxy that itself authenticates) sets this to a truthy value AND should arm
// DS_ORCH_ADMIN_TOKEN; binding a public interface unauthenticated is the operator's
// explicit choice, never an accidental default (D77).
const adminAllowNonLoopbackEnv = "DS_ORCH_ADMIN_ALLOW_NONLOOPBACK"

// adminShutdownGrace bounds the graceful-stop window for the admin HTTP server when
// the bootstrap ctx cancels — long enough to drain an in-flight /debug/vars scrape,
// short enough not to stall shutdown. The admin surface carries only the expvar
// payload (no long-lived streams), so the drain is effectively instantaneous; the
// bound exists so a wedged client connection can never hold shutdown open.
const adminShutdownGrace = 5 * time.Second

// livenessVarName is the expvar var the admin surface publishes the per-host liveness
// readout under (rendered inside the /debug/vars JSON object alongside the D72 step-9
// degrade counters). It carries the marshalled reconciler.HealthSnapshot() — the
// queryable "which hosts are LIVE / UNKNOWN right now?" view (doc 15 §3 / §5.2; D35/D72)
// an operator otherwise has to scrape the AlarmHostUnknown log for. It is registered
// ONLY when a HealthSnapshotter is threaded into the admin surface; with none threaded
// the var is absent and /debug/vars is byte-for-byte the pre-existing degrade-only
// payload (the surface is purely ADDITIVE).
const livenessVarName = "orchestrator_host_liveness"

// livenessPath is the dedicated guarded sub-handler that renders the SAME
// reconciler.HealthSnapshot() readout as a standalone JSON document (the same private
// mux, behind the SAME optional bearer guard as /debug/vars). It is a convenience face
// for an operator who wants the liveness view alone rather than buried in the full
// expvar object; like the expvar var it is mounted ONLY when a HealthSnapshotter is
// threaded in, so the default posture (no snapshotter) exposes exactly the historical
// /debug/vars route and nothing more.
const livenessPath = "/debug/liveness"

// HealthSnapshotter is the read-only seam the admin surface renders the per-host
// liveness view from: the reconciler's HealthSnapshot() accessor (internal/reconciler,
// health.go), which derives LIVE/UNKNOWN per host from heartbeat recency WITHOUT adding
// a §3 state name or mutating any record (D35/D72). *reconciler.Reconciler satisfies
// this interface directly; the admin surface depends on the narrow interface (not the
// concrete reconciler) so the dependency is one-directional and the readout is trivially
// fakeable in a test.
//
// CONCURRENCY (load-bearing — read before wiring a live reconciler). HealthSnapshot is a
// SINGLE-GOROUTINE reader of the reconciler's lastBeat map (health.go / reconciler.go:
// "safe to call from one goroutine; the driving loop owns concurrency"). The reconciler
// holds NO mutex; the controlplane reconcileLoop is the sole goroutine that touches
// lastBeat (via Observe/Resync). Calling HealthSnapshot() directly from the admin HTTP
// handler goroutine while that loop is running is a concurrent map read against the
// loop's writes — a DATA RACE. A live wiring MUST therefore supply a snapshotter that is
// SERIALIZED with the reconcile loop (a loop-marshalled query seam, or a snapshotter
// whose HealthSnapshot is otherwise synchronized with the lastBeat writer); a raw
// *reconciler.Reconciler is safe to thread here ONLY when nothing writes its lastBeat
// concurrently (e.g. a test that drives it on one goroutine, or before any loop starts).
type HealthSnapshotter interface {
	HealthSnapshot() []reconciler.HostHealth
}

// startAdminServer mounts the stdlib expvar /debug/vars admin surface on an HTTP
// listener so the §4.1 step-9 freshness-degrade observables (D72) — the fleet
// degrade total `orchestrator_sessions_step9_freshness_degrade_total`, the per-host
// degrade map `orchestrator_sessions_step9_freshness_degrade_by_host` (with its
// `__other__` overflow bucket), and the resolved cap
// `orchestrator_sessions_step9_degrade_host_cap` — are READABLE in production. Those
// counters are published on the process-global stdlib expvar registry by
// internal/sessions, but nothing SERVES that registry, so an operator could not pull
// them; this is the one socket that renders the /debug/vars payload the runbook curls.
//
// It is env-gated (D50): with DS_ORCH_ADMIN_ADDR unset the function is a no-op — no
// listener binds, no goroutine starts, and the returned shutdown closer is a no-op —
// so the default posture (and every test that does not set the var) exposes no admin
// surface. When the var is set it binds a TCP listener on that address and serves a
// dedicated mux with expvar.Handler() at /debug/vars (a private mux, not
// http.DefaultServeMux, so the surface is exactly /debug/vars and independent of any
// other package's default-mux registrations). The listener is bound SYNCHRONOUSLY
// (a bad address fails the bootstrap loudly), then served on a background goroutine.
//
// The returned closer performs the graceful stop: it is registered into the
// bootstrap's shutdown path (a deferred close in run, fired when the bootstrap ctx
// cancels and serve returns) so the admin server drains and closes alongside the rest
// of the run() lifecycle (the gRPC serve + the live-edge closers). The closer itself
// drives the drain on its own bounded context, so it does not depend on the bootstrap
// ctx still being live.
//
// The returned address is the BOUND listen address (resolved from the listener, so a
// ":0" or "127.0.0.1:0" request reports the OS-assigned port) when a surface was
// armed, or "" when it was not — letting a caller (and the unit test) discover where
// the surface is actually reachable.
//
// Hardening (D77 fail-closed posture). Two env-driven guards harden the default
// posture before a listener is ever bound:
//   - LOOPBACK BIND DEFAULT. A non-loopback DS_ORCH_ADMIN_ADDR is REFUSED at
//     construction (the surface leaks internal metric names/values, so it must not be
//     world-reachable by accident) unless the operator sets the explicit opt-out
//     DS_ORCH_ADMIN_ALLOW_NONLOOPBACK. A loopback (127.0.0.0/8, ::1, or a bare-port
//     ":N" / "localhost" host) bind always passes.
//   - OPTIONAL BEARER TOKEN. When DS_ORCH_ADMIN_TOKEN is set, every /debug/vars request
//     must carry a matching `Authorization: Bearer <token>` (constant-time compared via
//     crypto/subtle); a missing/mismatched header is 401. When the token is unset on a
//     loopback bind the surface serves unauthenticated (the dev-default).
//
// The refusal is returned BEFORE net.Listen so a misconfigured public bind fails the
// bootstrap loudly rather than opening an unauthenticated world-reachable metrics
// socket.
//
// LIVENESS READOUT (additive, D35/D72). When health is non-nil the surface ALSO publishes
// the per-host LIVE/UNKNOWN view derived from reconciler.HealthSnapshot() — both as the
// expvar var `orchestrator_host_liveness` (rendered inside the /debug/vars object) and as a
// dedicated /debug/liveness JSON sub-handler, BOTH behind the same optional bearer guard.
// When health is nil neither is registered, so /debug/vars stays byte-for-byte the
// historical degrade-only payload and the default posture is unchanged. The snapshotter is
// rendered ON the admin HTTP handler goroutine; per the HealthSnapshotter doc, a LIVE
// reconciler must be supplied through a loop-serialized snapshotter (never a raw reconciler
// whose lastBeat the reconcile loop is concurrently writing) to stay race-clean.
func startAdminServer(addr string, health HealthSnapshotter) (boundAddr string, closeFn func() error, err error) {
	addr = trimAdminAddr(addr)
	if addr == "" {
		// Unset/blank: no admin surface. Return a no-op closer so the caller can
		// register it unconditionally.
		return "", func() error { return nil }, nil
	}

	// Fail-closed: a non-loopback bind is refused at construction unless the operator
	// armed the explicit opt-out (D77). This runs before net.Listen so a misconfigured
	// public bind never opens a socket.
	if !adminAllowNonLoopback() {
		if err := refuseNonLoopbackAddr(addr); err != nil {
			return "", nil, err
		}
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return "", nil, fmt.Errorf("bind %s %q: %w", adminAddrEnv, addr, err)
	}

	mux, unarmLiveness := adminMux(adminToken(), health)
	srv := &http.Server{Handler: mux}

	served := make(chan error, 1)
	go func() {
		// Serve returns ErrServerClosed on a graceful Shutdown; that is the normal
		// stop path, not an error.
		err := srv.Serve(lis)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		served <- err
	}()

	bound := lis.Addr().String()
	slog.Default().Info("ds orchestrator: admin /debug/vars surface serving expvar (D72 step-9 degrade observables)",
		"addr", bound, "path", "/debug/vars", "bearer_token", adminToken() != "", "liveness_readout", health != nil)

	// A single shutdown guarded by sync.Once so the closer is IDEMPOTENT: the bootstrap
	// registers it as a deferred close, and a second invocation (or a test asserting
	// idempotency) is a harmless no-op rather than a second Shutdown that would block
	// forever on the already-drained `served` channel.
	var once sync.Once
	var shutErr error
	closer := func() error {
		once.Do(func() {
			// Un-arm this surface's snapshotter from the process-global liveness var FIRST,
			// so a stopped surface decrements the live-surface count and (when it was the
			// last) clears the global var rather than leaving a stale reconciler pointed at it.
			unarmLiveness()
			ctx, cancel := context.WithTimeout(context.Background(), adminShutdownGrace)
			defer cancel()
			if err := srv.Shutdown(ctx); err != nil {
				// Best-effort: a Shutdown deadline forces a Close so the listener is
				// always released, then surfaces the deadline as the error.
				_ = srv.Close()
				shutErr = fmt.Errorf("admin server shutdown: %w", err)
				return
			}
			// Shutdown returned: the Serve goroutine has unblocked. Surface any serve
			// error (other than the expected ErrServerClosed, already mapped to nil).
			shutErr = <-served
		})
		return shutErr
	}
	return bound, closer, nil
}

// adminMux is the dedicated /debug/vars router for the admin surface. It mounts the
// stdlib expvar.Handler() — which renders the process-global expvar registry (the
// same registry internal/sessions publishes the D72 degrade counters onto) as JSON —
// on a PRIVATE mux rather than http.DefaultServeMux, so the served surface is exactly
// /debug/vars and never inherits unrelated default-mux registrations.
//
// When token is non-empty the expvar handler is wrapped by requireBearer, so every
// request must present a matching `Authorization: Bearer <token>` or get 401 (D77
// fail-closed). An empty token leaves the handler unguarded (the dev-default on a
// loopback bind).
//
// When health is non-nil the mux ALSO (additively) renders the per-host liveness readout:
// the `orchestrator_host_liveness` expvar var is pointed at this snapshotter (so it appears
// inside the /debug/vars object), and a dedicated guarded /debug/liveness sub-handler is
// mounted that marshals the same reconciler.HealthSnapshot() to a standalone JSON document.
// Both ride the SAME bearer guard as /debug/vars. When health is nil neither is added, so
// the mux is exactly the historical /debug/vars-only surface (unchanged default posture).
// It returns an UN-ARM closer the caller fires on shutdown: when a snapshotter was armed onto
// the process-global expvar var, the closer decrements the live-surface count and clears the
// global var once no surface is left holding it (so a stopped surface does not leave a stale
// reconciler pointed at the global var). When no snapshotter was armed (health nil) the closer
// is a harmless no-op.
func adminMux(token string, health HealthSnapshotter) (*http.ServeMux, func()) {
	mux := http.NewServeMux()
	mux.Handle("/debug/vars", requireBearer(token, expvar.Handler()))
	if health != nil {
		// Point the process-global liveness expvar var at this snapshotter so its value
		// renders inside the /debug/vars object alongside the D72 degrade counters. The
		// returned unarm closer is fired on this surface's shutdown (single-surface-safe).
		unarm := setLivenessSnapshotter(health)
		// A dedicated guarded face for the liveness view alone. It closes over THIS surface's
		// snapshotter directly (never the process-global var), so it stays correct even if a
		// second surface re-points the global var.
		mux.Handle(livenessPath, requireBearer(token, livenessHandler(health)))
		return mux, unarm
	}
	// No snapshotter on THIS surface: clear any previously-pointed snapshotter so the
	// process-global liveness var renders null (never a stale prior reconciler) — but
	// do NOT publish the var if it was never armed, keeping a never-armed surface's
	// /debug/vars byte-for-byte the historical degrade-only payload. The /debug/liveness
	// route is simply not mounted (a request 404s on the private mux).
	clearLivenessSnapshotter()
	return mux, func() {}
}

// livenessRegistry holds the single process-global expvar.Func for the per-host liveness
// readout and the CURRENT snapshotter it renders. expvar names are process-global and a
// name can be published only ONCE, but startAdminServer may run many times in one process
// (every admin test, and a re-armed surface): so the Func is published once under a
// sync.Once and reads a swappable snapshotter guarded by a mutex, rather than re-publishing
// the name (which would panic). The mutex makes the swap and the Func's read race-clean with
// respect to EACH OTHER; it does NOT synchronize the snapshotter's own HealthSnapshot()
// against the reconcile loop — that serialization is the snapshotter's contract (see
// HealthSnapshotter).
//
// SINGLE-SURFACE-SAFE (the latent footgun, guarded). The `orchestrator_host_liveness` expvar
// VAR is process-GLOBAL: there is exactly ONE name in the process registry, so it can render
// exactly ONE snapshotter at a time. The production bootstrap arms a SINGLE admin surface
// (run() calls startAdminServer once), so in production there is only ever one snapshotter and
// the var renders it unambiguously. But nothing structurally stops a second concurrent
// startAdminServer (a misconfiguration, or a future second surface) from arming a DIFFERENT
// reconciler's snapshotter onto the SAME global var — the second arm would SILENTLY clobber the
// first, so the expvar would render the wrong fleet's liveness with no signal. `armed` counts
// the live (set-not-yet-cleared) snapshotters so a second concurrent arm is DETECTED and logged
// as a warning rather than swapping silently; the dedicated per-surface `/debug/liveness`
// sub-handler is unaffected (it closes over ITS surface's snapshotter directly, never the global
// var), so each surface's own route still renders ITS own reconciler correctly regardless.
var livenessRegistry struct {
	once      sync.Once
	mu        sync.Mutex
	snap      HealthSnapshotter
	published bool
	armed     int // live (set-not-cleared) snapshotters; >1 means a second surface armed the global var
}

// publishLivenessVar registers the `orchestrator_host_liveness` expvar.Func exactly once
// per process (the name is process-global and can be published only once). The Func reads
// the CURRENT snapshotter under the registry mutex each time expvar marshals the registry,
// so a /debug/vars scrape always reflects the live per-host LIVE/UNKNOWN view (not a value
// frozen at registration). A nil current snapshotter renders JSON null.
func publishLivenessVar() {
	livenessRegistry.once.Do(func() {
		expvar.Publish(livenessVarName, expvar.Func(func() any {
			livenessRegistry.mu.Lock()
			snap := livenessRegistry.snap
			livenessRegistry.mu.Unlock()
			if snap == nil {
				return nil
			}
			return livenessView(snap.HealthSnapshot())
		}))
		livenessRegistry.mu.Lock()
		livenessRegistry.published = true
		livenessRegistry.mu.Unlock()
	})
}

// setLivenessSnapshotter publishes the liveness expvar var (once) and points it at snap, so
// the var rendered inside /debug/vars reflects this surface's reconciler. It returns an
// UN-ARM closer the caller registers on its shutdown path so a re-armed-then-stopped surface
// decrements the armed count and clears the global var when no surface is left holding it.
//
// SINGLE-SURFACE GUARD. The expvar var is process-global, so it can render only ONE
// snapshotter; the production bootstrap arms exactly one surface. If a SECOND surface arms
// while a first is still live (armed already >0), this logs a warning — the global var will
// from now reflect THIS (second) surface, silently clobbering the first — so the footgun is
// VISIBLE rather than silent. The per-surface /debug/liveness route is unaffected (it closes
// over its own snapshotter), so each surface's dedicated route stays correct regardless.
func setLivenessSnapshotter(snap HealthSnapshotter) (unarm func()) {
	publishLivenessVar()
	livenessRegistry.mu.Lock()
	if livenessRegistry.armed > 0 {
		slog.Default().Warn("ds orchestrator: a second admin surface armed the process-global orchestrator_host_liveness expvar var — it can render only ONE surface, so /debug/vars now reflects the latest-armed reconciler (the per-surface /debug/liveness route is unaffected). The production bootstrap arms exactly one admin surface; more than one is a misconfiguration",
			"already_armed", livenessRegistry.armed)
	}
	livenessRegistry.armed++
	livenessRegistry.snap = snap
	livenessRegistry.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			livenessRegistry.mu.Lock()
			if livenessRegistry.armed > 0 {
				livenessRegistry.armed--
			}
			// Only clear the global var when THIS was the last surface holding it, so a
			// surviving surface keeps rendering its own snapshotter.
			if livenessRegistry.armed == 0 {
				livenessRegistry.snap = nil
			}
			livenessRegistry.mu.Unlock()
		})
	}
}

// clearLivenessSnapshotter points the liveness var at nil (so it renders null rather than a
// stale prior reconciler) WITHOUT publishing it: a process that has NEVER armed a
// snapshotter leaves the var unpublished entirely, so a never-armed surface's /debug/vars
// stays byte-for-byte the historical degrade-only payload. It is the no-snapshotter arm of
// adminMux — it never DECREMENTS the armed count (it did not arm anything) and only nils the
// pointer when no surface is currently armed, so it never steps on a live surface's var.
func clearLivenessSnapshotter() {
	livenessRegistry.mu.Lock()
	defer livenessRegistry.mu.Unlock()
	if livenessRegistry.published && livenessRegistry.armed == 0 {
		livenessRegistry.snap = nil
	}
}

// livenessHandler renders reconciler.HealthSnapshot() (via the threaded snapshotter) as a
// standalone JSON document for the /debug/liveness face. It is a pure reader: it calls the
// snapshotter on the request goroutine and marshals the result. A marshal fault is a 500
// (it should never happen for the value-typed liveness view, but is handled rather than
// panicking). GET/HEAD only — any other method is 405 (the surface is read-only).
func livenessHandler(health HealthSnapshotter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
		default:
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := json.Marshal(livenessView(health.HealthSnapshot()))
		if err != nil {
			http.Error(w, "marshal liveness", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write(body)
	})
}

// livenessHostView is the JSON shape one host's liveness renders as on the admin surface:
// the host key, the derived LIVE/UNKNOWN annotation, and the heartbeat-recency facts the
// derivation is built from, so an operator reads the reason ("silent 18s, window 15s")
// without re-deriving it. Durations are emitted as whole seconds (a stable, human-curlable
// unit) rather than the raw nanosecond Duration ints. It carries NO §3 state and NO record
// identity — it is the non-state liveness annotation (reconciler.HostHealth), nothing more.
type livenessHostView struct {
	HostID         string `json:"host_id"`
	Liveness       string `json:"liveness"`
	EverSeen       bool   `json:"ever_seen"`
	LastBeatUnix   int64  `json:"last_beat_unix,omitempty"`
	SinceLastBeatS int64  `json:"since_last_beat_seconds"`
	SilenceWindowS int64  `json:"silence_window_seconds"`
}

// livenessView maps the reconciler's value-typed per-host health into the JSON-render
// shape. It is a pure projection (no I/O, no reconciler read) so it is trivially testable
// and the marshalled surface stays decoupled from the reconciler's in-memory type.
func livenessView(hosts []reconciler.HostHealth) []livenessHostView {
	out := make([]livenessHostView, 0, len(hosts))
	for _, h := range hosts {
		v := livenessHostView{
			HostID:         h.HostID,
			Liveness:       string(h.Liveness),
			EverSeen:       h.EverSeen,
			SinceLastBeatS: int64(h.SinceLastBeat / time.Second),
			SilenceWindowS: int64(h.SilenceWindow / time.Second),
		}
		if h.EverSeen {
			v.LastBeatUnix = h.LastBeat.Unix()
		}
		out = append(out, v)
	}
	return out
}

// requireBearer is the optional bearer-token middleware. With an empty token it is a
// pass-through (the unauthenticated dev-default). With a non-empty token it refuses any
// request whose `Authorization` header is not exactly `Bearer <token>` with a 401 — the
// comparison is constant-time (crypto/subtle) so the guard does not leak the token
// length or a matching prefix through timing. Fail-closed: a missing header, a
// non-Bearer scheme, or a mismatched secret all get 401 (D77).
func requireBearer(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := "Bearer " + token
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		// ConstantTimeCompare requires equal-length inputs to compare the bytes; a
		// length mismatch already means non-match, and the explicit length check keeps
		// the comparison constant-time within a length class without short-circuiting on
		// content.
		if len(got) != len(want) || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refuseNonLoopbackAddr returns a non-nil error when addr resolves to a non-loopback
// host, so a public DS_ORCH_ADMIN_ADDR is refused at construction unless the operator
// armed DS_ORCH_ADMIN_ALLOW_NONLOOPBACK. A bare-port address (":6060"), an explicit
// loopback IP (127.0.0.0/8, ::1), or the "localhost" host all pass; any other host
// (a routable IP, "0.0.0.0", "::", or a non-localhost name) is refused. The error
// names the env var and the opt-out so the operator learns how to proceed.
func refuseNonLoopbackAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port shaped — let net.Listen surface the bind error rather than
		// guessing; the loopback guard only judges a parseable host.
		return nil
	}
	if isLoopbackHost(host) {
		return nil
	}
	return fmt.Errorf("%s %q binds a non-loopback host %q: the admin /debug/vars surface exposes internal metrics and must not be world-reachable; bind a loopback address (e.g. 127.0.0.1:6060) or set %s to opt out explicitly (and arm %s)",
		adminAddrEnv, addr, host, adminAllowNonLoopbackEnv, adminTokenEnv)
}

// isLoopbackHost reports whether host is a loopback target for the admin bind: an empty
// host (bare-port ":N", which net.Listen binds to all interfaces but is treated as the
// dev-loopback intent here only when paired with an explicit loopback) — NO: a bare/empty
// host is NOT loopback (":6060" listens on every interface), so it must be refused. A
// "localhost" name and any IP in 127.0.0.0/8 or ::1 are loopback.
func isLoopbackHost(host string) bool {
	if host == "" {
		// ":6060" binds all interfaces — not loopback.
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	// A non-IP, non-localhost hostname is not provably loopback — refuse it.
	return false
}

// trimAdminAddr resolves the configured admin listen address: the raw env value with
// surrounding whitespace removed (a blank value disarms the surface, matching the rest
// of the bootstrap's env handling where os.Getenv returns "" when unset).
func trimAdminAddr(addr string) string { return strings.TrimSpace(addr) }

// adminAddr reads the admin listen address from the environment (DS_ORCH_ADMIN_ADDR).
// It is the single resolution point the bootstrap calls so the gate lives in one place.
func adminAddr() string { return os.Getenv(adminAddrEnv) }

// adminToken reads the optional bearer secret (DS_ORCH_ADMIN_TOKEN), whitespace-trimmed
// so a stray trailing newline from an env-file does not become part of the secret. An
// empty result leaves the surface unauthenticated (the loopback dev-default).
func adminToken() string { return strings.TrimSpace(os.Getenv(adminTokenEnv)) }

// adminAllowNonLoopback reports whether the operator armed the explicit opt-out that
// lets the admin surface bind a non-loopback address (DS_ORCH_ADMIN_ALLOW_NONLOOPBACK).
// Any of the conventional truthy spellings (1/true/yes/on, case-insensitive) arms it;
// anything else (including unset) keeps the fail-closed loopback-only default.
func adminAllowNonLoopback() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(adminAllowNonLoopbackEnv))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
