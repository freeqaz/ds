package main

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestStartAdminServer_ServesDebugVars proves the operability capstone: with an admin
// address configured, startAdminServer binds a real listener and serves the stdlib
// expvar /debug/vars payload, so the §4.1 step-9 freshness-degrade observables (D72) —
// published on the process-global expvar registry by internal/sessions — are READABLE
// in production. We publish a uniquely-named expvar.Int (the same seam the degrade
// counters use), then assert it appears in the JSON the admin surface renders. Bound to
// 127.0.0.1:0 so the test takes an OS-assigned port and never collides with a parallel
// run (D50: a real listener over a synthetic fixture, no live edge).
// publishOnceInt returns the process-global *expvar.Int registered under name,
// reusing an already-published one instead of re-registering it. expvar.NewInt
// panics ("Reuse of exported var name") on a second registration of the same
// name, which would abort `go test -count>1` / soak runs over this package; the
// Get-or-New here keeps the registration idempotent across iterations while still
// exercising the real process-global registry the admin surface renders.
func publishOnceInt(name string) *expvar.Int {
	if v := expvar.Get(name); v != nil {
		if iv, ok := v.(*expvar.Int); ok {
			return iv
		}
	}
	return expvar.NewInt(name)
}

func TestStartAdminServer_ServesDebugVars(t *testing.T) {
	// A uniquely-named published var standing in for the real D72 degrade counters,
	// registered on the SAME process-global registry expvar.Handler() renders. expvar
	// names are process-global and cannot be re-registered, so qualify by test name AND
	// publish-once (reuse on re-entry) so -count>1 / soak runs do not panic.
	varName := "test_admin_debug_vars_" + t.Name()
	published := publishOnceInt(varName)
	published.Set(7)

	bound, closeAdmin, err := startAdminServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("startAdminServer: %v", err)
	}
	t.Cleanup(func() {
		if err := closeAdmin(); err != nil {
			t.Errorf("close admin surface: %v", err)
		}
	})
	if bound == "" {
		t.Fatal("startAdminServer returned an empty bound address for a configured admin addr")
	}

	body := getDebugVars(t, bound)

	// The payload is the expvar JSON object; the published var must be present with the
	// value we set, proving the admin surface renders the live registry (not a stub).
	var vars map[string]json.RawMessage
	if err := json.Unmarshal(body, &vars); err != nil {
		t.Fatalf("unmarshal /debug/vars JSON: %v\nbody=%q", err, string(body))
	}
	raw, ok := vars[varName]
	if !ok {
		t.Fatalf("/debug/vars did not expose published expvar %q; keys=%v", varName, keysOf(vars))
	}
	if got := strings.TrimSpace(string(raw)); got != "7" {
		t.Fatalf("/debug/vars published %q = %q, want 7", varName, got)
	}
}

// TestStartAdminServer_GracefulShutdown proves the closer graceful-stops the admin
// server: after it returns the surface is no longer reachable (the listener is
// released), and a second close is harmless. This is the shutdown leg wired into the
// run() lifecycle.
func TestStartAdminServer_GracefulShutdown(t *testing.T) {
	bound, closeAdmin, err := startAdminServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("startAdminServer: %v", err)
	}

	// Reachable while serving.
	_ = getDebugVars(t, bound)

	if err := closeAdmin(); err != nil {
		t.Fatalf("graceful close: %v", err)
	}
	// After a graceful stop the surface is gone: a fresh dial must fail (the listener
	// was released). Use a short-lived client so the failed connect returns promptly.
	if resp, err := http.Get(fmt.Sprintf("http://%s/debug/vars", bound)); err == nil {
		resp.Body.Close()
		t.Fatalf("admin surface still reachable after graceful shutdown")
	}
	// A second close is idempotent (no panic, no error from a fresh Shutdown on an
	// already-stopped server).
	if err := closeAdmin(); err != nil {
		t.Fatalf("second close not idempotent: %v", err)
	}
}

// TestStartAdminServer_UnsetNoListener proves the env gate (D50): an empty/blank admin
// address arms NO surface — the returned bound address is empty and the no-op closer is
// harmless — so the orchestrator's default posture (and every test that does not set
// DS_ORCH_ADMIN_ADDR) exposes no /debug/vars socket.
func TestStartAdminServer_UnsetNoListener(t *testing.T) {
	for _, addr := range []string{"", "   ", "\t\n"} {
		bound, closeAdmin, err := startAdminServer(addr, nil)
		if err != nil {
			t.Fatalf("startAdminServer(%q): unexpected error %v", addr, err)
		}
		if bound != "" {
			t.Fatalf("startAdminServer(%q) bound %q, want no surface (empty addr)", addr, bound)
		}
		if closeAdmin == nil {
			t.Fatalf("startAdminServer(%q) returned a nil closer", addr)
		}
		if err := closeAdmin(); err != nil {
			t.Fatalf("no-op closer for %q returned %v", addr, err)
		}
	}
}

// TestStartAdminServer_BadAddrErrors proves a misconfigured admin address fails the
// bootstrap loudly (an unbindable address surfaces as an error, not a silent no-op), so
// an operator who set DS_ORCH_ADMIN_ADDR to garbage learns at startup.
func TestStartAdminServer_BadAddrErrors(t *testing.T) {
	bound, closeAdmin, err := startAdminServer("not-a-valid-addr:::", nil)
	if err == nil {
		if closeAdmin != nil {
			_ = closeAdmin()
		}
		t.Fatalf("startAdminServer(bad addr) returned nil error (bound=%q)", bound)
	}
	if !strings.Contains(err.Error(), adminAddrEnv) {
		t.Errorf("bind error %q does not name the env var %q", err, adminAddrEnv)
	}
}

// TestStartAdminServer_RefusesNonLoopbackBind proves the fail-closed loopback default
// (D77): a non-loopback DS_ORCH_ADMIN_ADDR is REFUSED at construction (no listener
// binds) unless the explicit opt-out is armed, so the metrics surface is never
// world-reachable by accident. We assert the refusal for a routable bind and the
// all-interfaces "0.0.0.0", that the error names the env var + the opt-out, and that
// arming DS_ORCH_ADMIN_ALLOW_NONLOOPBACK lets the same address through (bound on
// 0.0.0.0:0 so the test never opens a routable fixed port).
func TestStartAdminServer_RefusesNonLoopbackBind(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.0.2.1:6060", "example.invalid:6060"} {
		bound, closeAdmin, err := startAdminServer(addr, nil)
		if err == nil {
			if closeAdmin != nil {
				_ = closeAdmin()
			}
			t.Fatalf("startAdminServer(%q) bound %q without refusing a non-loopback bind", addr, bound)
		}
		if bound != "" {
			t.Errorf("startAdminServer(%q) returned a non-empty bound %q on refusal", addr, bound)
		}
		for _, want := range []string{adminAddrEnv, adminAllowNonLoopbackEnv} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("startAdminServer(%q) error %q does not name %q", addr, err, want)
			}
		}
	}

	// Loopback binds always pass without the opt-out.
	for _, addr := range []string{"127.0.0.1:0", "[::1]:0"} {
		bound, closeAdmin, err := startAdminServer(addr, nil)
		if err != nil {
			t.Fatalf("startAdminServer(%q) refused a loopback bind: %v", addr, err)
		}
		t.Cleanup(func() { _ = closeAdmin() })
		if bound == "" {
			t.Errorf("startAdminServer(%q) returned an empty bound for a loopback addr", addr)
		}
	}

	// With the explicit opt-out armed, a non-loopback bind is allowed (bound on an
	// OS-assigned port so we never open a routable fixed port in the test).
	t.Setenv(adminAllowNonLoopbackEnv, "1")
	bound, closeAdmin, err := startAdminServer("0.0.0.0:0", nil)
	if err != nil {
		t.Fatalf("startAdminServer(0.0.0.0:0) with opt-out armed: %v", err)
	}
	t.Cleanup(func() { _ = closeAdmin() })
	if bound == "" {
		t.Fatal("startAdminServer(0.0.0.0:0) with opt-out returned an empty bound")
	}
}

// TestStartAdminServer_BearerTokenGuard proves the optional shared-secret guard (D77
// fail-closed): with DS_ORCH_ADMIN_TOKEN set, a /debug/vars request with no bearer or a
// wrong bearer is 401 and a request with the matching bearer is 200; on a loopback bind
// with NO token the surface serves (the dev-default). All over a real 127.0.0.1:0
// listener with a synthetic token (D50 — no live edge, never a committed secret).
func TestStartAdminServer_BearerTokenGuard(t *testing.T) {
	const token = "synthetic-admin-token-01KV0TBG"
	t.Setenv(adminTokenEnv, token)

	bound, closeAdmin, err := startAdminServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("startAdminServer: %v", err)
	}
	t.Cleanup(func() {
		if err := closeAdmin(); err != nil {
			t.Errorf("close admin surface: %v", err)
		}
	})

	// No Authorization header → 401.
	if code := getDebugVarsStatus(t, bound, ""); code != http.StatusUnauthorized {
		t.Errorf("no-bearer request status = %d, want 401", code)
	}
	// Wrong token → 401.
	if code := getDebugVarsStatus(t, bound, "Bearer wrong-token"); code != http.StatusUnauthorized {
		t.Errorf("wrong-bearer request status = %d, want 401", code)
	}
	// Non-Bearer scheme → 401.
	if code := getDebugVarsStatus(t, bound, "Basic "+token); code != http.StatusUnauthorized {
		t.Errorf("non-Bearer scheme status = %d, want 401", code)
	}
	// Matching bearer → 200.
	if code := getDebugVarsStatus(t, bound, "Bearer "+token); code != http.StatusOK {
		t.Errorf("matching-bearer request status = %d, want 200", code)
	}
}

// TestStartAdminServer_LoopbackNoTokenServes proves the dev-default: a loopback bind
// with DS_ORCH_ADMIN_TOKEN unset serves /debug/vars unauthenticated (no Authorization
// header required), so a developer curl against the local surface works out of the box.
func TestStartAdminServer_LoopbackNoTokenServes(t *testing.T) {
	bound, closeAdmin, err := startAdminServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("startAdminServer: %v", err)
	}
	t.Cleanup(func() {
		if err := closeAdmin(); err != nil {
			t.Errorf("close admin surface: %v", err)
		}
	})
	if code := getDebugVarsStatus(t, bound, ""); code != http.StatusOK {
		t.Fatalf("loopback no-token /debug/vars status = %d, want 200", code)
	}
}

// TestRequireBearer_Unit unit-tests the middleware in isolation: an empty token is a
// pass-through (the next handler is reached), and a set token gates on an exact
// constant-time match.
func TestRequireBearer_Unit(t *testing.T) {
	served := func(token, authz string) bool {
		reached := false
		h := requireBearer(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/debug/vars", nil)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		return reached
	}
	if !served("", "") {
		t.Error("empty token must pass through to the next handler")
	}
	if served("secret", "") {
		t.Error("set token with no header must NOT reach the handler")
	}
	if served("secret", "Bearer wrong") {
		t.Error("set token with wrong bearer must NOT reach the handler")
	}
	if !served("secret", "Bearer secret") {
		t.Error("set token with matching bearer must reach the handler")
	}
}

// getDebugVarsStatus GETs /debug/vars off the bound admin address with an optional
// Authorization header and returns the status code, failing only on a transport error
// (the caller asserts the code).
func getDebugVarsStatus(t *testing.T, bound, authz string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/debug/vars", bound), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /debug/vars: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// getDebugVars GETs /debug/vars off the bound admin address and returns the body,
// failing the test on any transport or non-200 outcome.
func getDebugVars(t *testing.T, bound string) []byte {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://%s/debug/vars", bound))
	if err != nil {
		t.Fatalf("GET /debug/vars: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /debug/vars status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /debug/vars body: %v", err)
	}
	return body
}

func keysOf(m map[string]json.RawMessage) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// ---- liveness readout (D35/D72): the admin surface exposes reconciler.HealthSnapshot() ----

// fixedClock is a test clock the liveness tests drive deterministically: Observe stamps
// lastBeat at now(), and HealthSnapshot judges recency against now(), so advancing the
// clock between observe + read makes a host cross the silence window predictably. All
// access is serialized on the test goroutine (the same single-goroutine contract the
// reconcile loop holds in production), so the reconciler read is race-clean.
type fixedClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fixedClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// noopDriver satisfies reconciler.Driver with inert Suspend/Destroy — the liveness tests
// observe heartbeats with no observed sessions, so the driver is never exercised; it
// exists only to satisfy the non-nil New() requirement.
type noopDriver struct{}

func (noopDriver) Suspend(context.Context, *hypervisorv1.SuspendRequest) (*hypervisorv1.SuspendResponse, error) {
	return &hypervisorv1.SuspendResponse{}, nil
}

func (noopDriver) Destroy(context.Context, *hypervisorv1.DestroyRequest) (*hypervisorv1.DestroyResponse, error) {
	return &hypervisorv1.DestroyResponse{}, nil
}

// newLivenessReconciler builds a real reconciler over the in-memory store driven by clk,
// with the default missed-beat window (3 * 5s = 15s). The reconciler itself satisfies
// HealthSnapshotter, so the test threads it straight into the admin surface — and because
// the test drives Observe + the admin scrape on ONE goroutine (clk-stamped, no concurrent
// reconcile loop), the HealthSnapshot read honors the single-goroutine lastBeat contract
// and stays race-clean under `go test -race`.
func newLivenessReconciler(t *testing.T, clk *fixedClock) *reconciler.Reconciler {
	t.Helper()
	st := store.NewMemoryClock(clk.Now)
	r, err := reconciler.New(st, noopDriver{}, nil, nil, clk.Now, reconciler.Config{})
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	return r
}

// observeBeat records a single synthetic heartbeat for hostID at the clock's current time
// (no observed sessions — the liveness signal keys only on lastBeat recency).
func observeBeat(t *testing.T, r *reconciler.Reconciler, hostID string) {
	t.Helper()
	if err := r.Observe(context.Background(), &hostagentv1.Heartbeat{HostId: hostID}); err != nil {
		t.Fatalf("Observe(%q): %v", hostID, err)
	}
}

// findLivenessHost returns the rendered view entry for hostID and whether it was present.
func findLivenessHost(view []livenessHostView, hostID string) (livenessHostView, bool) {
	for _, h := range view {
		if h.HostID == hostID {
			return h, true
		}
	}
	return livenessHostView{}, false
}

// TestStartAdminServer_LivenessReadout_ReflectsReconciler is the capstone: with a
// reconciler threaded into the admin surface, /debug/vars (and /debug/liveness) expose the
// per-host LIVE/UNKNOWN view DERIVED from reconciler.HealthSnapshot() — a host that beat
// inside the silence window renders LIVE, a host gone silent beyond the window renders
// UNKNOWN. The surface keeps the loopback bind + the default no-extra-route posture; this
// pins that the readout tracks the reconciler, not a stub. Driven on one goroutine with a
// clock-stamped reconciler so it is race-clean under `go test -race` (D50: synthetic
// heartbeats, a real 127.0.0.1:0 listener, no live edge).
func TestStartAdminServer_LivenessReadout_ReflectsReconciler(t *testing.T) {
	clk := &fixedClock{now: time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)}
	r := newLivenessReconciler(t, clk)

	// host-stale beat first; advance PAST the 15s window so it is now silent (UNKNOWN).
	observeBeat(t, r, "host-stale")
	clk.advance(30 * time.Second)
	// host-live beats now (inside the window relative to the read time) → LIVE.
	observeBeat(t, r, "host-live")

	bound, closeAdmin, err := startAdminServer("127.0.0.1:0", r)
	if err != nil {
		t.Fatalf("startAdminServer: %v", err)
	}
	t.Cleanup(func() {
		if err := closeAdmin(); err != nil {
			t.Errorf("close admin surface: %v", err)
		}
	})

	// (1) The liveness view is rendered inside the /debug/vars expvar object under the
	// published var name, reflecting the CURRENT reconciler snapshot.
	body := getDebugVars(t, bound)
	var vars map[string]json.RawMessage
	if err := json.Unmarshal(body, &vars); err != nil {
		t.Fatalf("unmarshal /debug/vars: %v\nbody=%q", err, string(body))
	}
	raw, ok := vars[livenessVarName]
	if !ok {
		t.Fatalf("/debug/vars missing liveness var %q; keys=%v", livenessVarName, keysOf(vars))
	}
	var viaVars []livenessHostView
	if err := json.Unmarshal(raw, &viaVars); err != nil {
		t.Fatalf("unmarshal liveness var: %v\nraw=%q", err, string(raw))
	}
	assertLivenessShape(t, viaVars)

	// (2) The dedicated /debug/liveness face renders the SAME view as a standalone doc.
	var viaHandler []livenessHostView
	if err := json.Unmarshal(getLiveness(t, bound, ""), &viaHandler); err != nil {
		t.Fatalf("unmarshal /debug/liveness: %v", err)
	}
	assertLivenessShape(t, viaHandler)
}

// assertLivenessShape pins the LIVE/UNKNOWN derivation: host-live is LIVE, host-stale is
// UNKNOWN, and the self-describing window is carried — the view reflects the reconciler.
func assertLivenessShape(t *testing.T, view []livenessHostView) {
	t.Helper()
	live, ok := findLivenessHost(view, "host-live")
	if !ok {
		t.Fatalf("host-live absent from liveness view %+v", view)
	}
	if live.Liveness != string(reconciler.HostLive) {
		t.Errorf("host-live liveness = %q, want %q", live.Liveness, reconciler.HostLive)
	}
	if !live.EverSeen {
		t.Errorf("host-live EverSeen = false, want true")
	}
	if live.SilenceWindowS != 15 {
		t.Errorf("host-live silence_window_seconds = %d, want 15 (3*5s default)", live.SilenceWindowS)
	}

	stale, ok := findLivenessHost(view, "host-stale")
	if !ok {
		t.Fatalf("host-stale absent from liveness view %+v", view)
	}
	if stale.Liveness != string(reconciler.HostUnknown) {
		t.Errorf("host-stale liveness = %q, want %q (silent beyond the window)", stale.Liveness, reconciler.HostUnknown)
	}
	if stale.SinceLastBeatS < 15 {
		t.Errorf("host-stale since_last_beat_seconds = %d, want > window (15)", stale.SinceLastBeatS)
	}
}

// TestStartAdminServer_LivenessReadout_BehindBearerGuard proves the liveness readout rides
// the SAME D77 bearer guard as /debug/vars: with a token set, /debug/liveness is 401
// without the matching bearer and 200 with it — so the readout is never reachable behind a
// guard the operator armed. Synthetic token, loopback listener (D50).
func TestStartAdminServer_LivenessReadout_BehindBearerGuard(t *testing.T) {
	const token = "synthetic-admin-token-liveness-01KV1NK1"
	t.Setenv(adminTokenEnv, token)

	clk := &fixedClock{now: time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)}
	r := newLivenessReconciler(t, clk)
	observeBeat(t, r, "host-live")

	bound, closeAdmin, err := startAdminServer("127.0.0.1:0", r)
	if err != nil {
		t.Fatalf("startAdminServer: %v", err)
	}
	t.Cleanup(func() {
		if err := closeAdmin(); err != nil {
			t.Errorf("close admin surface: %v", err)
		}
	})

	if code := getLivenessStatus(t, bound, ""); code != http.StatusUnauthorized {
		t.Errorf("/debug/liveness no-bearer status = %d, want 401", code)
	}
	if code := getLivenessStatus(t, bound, "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("/debug/liveness wrong-bearer status = %d, want 401", code)
	}
	if code := getLivenessStatus(t, bound, "Bearer "+token); code != http.StatusOK {
		t.Errorf("/debug/liveness matching-bearer status = %d, want 200", code)
	}
}

// TestStartAdminServer_NoSnapshotter_NoLivenessRoute proves the surface is ADDITIVE: with
// NO snapshotter threaded (the production default until the loop-serialized seam lands),
// /debug/vars carries no liveness var and the dedicated /debug/liveness route is absent
// (404) — so the historical degrade-only posture is byte-for-byte unchanged.
func TestStartAdminServer_NoSnapshotter_NoLivenessRoute(t *testing.T) {
	bound, closeAdmin, err := startAdminServer("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("startAdminServer: %v", err)
	}
	t.Cleanup(func() {
		if err := closeAdmin(); err != nil {
			t.Errorf("close admin surface: %v", err)
		}
	})

	// /debug/liveness is not mounted → 404.
	if code := getLivenessStatus(t, bound, ""); code != http.StatusNotFound {
		t.Errorf("/debug/liveness with no snapshotter status = %d, want 404", code)
	}

	// /debug/vars still serves; if the liveness var was ever published by a prior test in
	// this process its value renders null (no snapshotter pointed at it) rather than the
	// per-host view — proving a nil-snapshotter surface exposes no host liveness.
	body := getDebugVars(t, bound)
	var vars map[string]json.RawMessage
	if err := json.Unmarshal(body, &vars); err != nil {
		t.Fatalf("unmarshal /debug/vars: %v", err)
	}
	if raw, ok := vars[livenessVarName]; ok {
		if got := strings.TrimSpace(string(raw)); got != "null" {
			t.Errorf("liveness var with no snapshotter = %q, want null", got)
		}
	}
}

// getLiveness GETs /debug/liveness off the bound admin address with an optional bearer and
// returns the body, failing on a transport or non-200 outcome.
func getLiveness(t *testing.T, bound, authz string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s%s", bound, livenessPath), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", livenessPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200", livenessPath, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s body: %v", livenessPath, err)
	}
	return body
}

// getLivenessStatus GETs /debug/liveness with an optional bearer and returns the status
// code (the caller asserts the code), failing only on a transport error.
func getLivenessStatus(t *testing.T, bound, authz string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s%s", bound, livenessPath), nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", livenessPath, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// ---- composed never-seen pin: cp.LivenessSnapshotterIncluding → /debug/liveness over the
//      real admin HTTP surface (subtask 3 of the never-seen wiring) ----

// TestStartAdminServer_NeverSeenIncluding_ExpectedSilentHostRendersUnknownOverAdminHTTP is the
// ONE composed end-to-end pin this unit adds: it threads the PRODUCTION never-seen snapshotter
// — cp.LivenessSnapshotterIncluding(ctx, supplier) where the supplier (storeExpectedHosts's
// shape) names an EXPECTED-but-silent host — into startAdminServer, then GETs /debug/liveness
// over the REAL admin HTTP surface and asserts the expected-but-silent host renders
// EverSeen=false / UNKNOWN with a zero LastBeat ALONGSIDE a host that beat over the wire
// rendering LIVE (EverSeen=true).
//
// The snapshotter-render leg (controlplane/serve_test.go) and the HTTP-handler-render leg
// (admin_test.go above) are each pinned independently, but never before in ONE composed test
// through the real admin mux + the real loop-serialized reconcile path. This pins the property
// an operator depends on: a placed host that NEVER came up is VISIBLE on /debug/liveness, not
// silently absent (doc 15 §3/§5.2; D35/D72).
//
// The control plane is the production one (controlplane.NewControlPlane over the stub-env
// liveDeps — un-dialed, lazy gRPC, in-memory store, D50), its reconcile loop is driven by the
// real controlplane.Serve over a LOOPBACK listener (127.0.0.1:0 — a real socket, no live edge),
// and the beating host's heartbeat is ingested over the real hostagent.v1 ReportHeartbeat wire.
// So the read is the genuine loop-serialized HealthSnapshotIncluding the production bootstrap
// arms, not a hand-built snapshotter.
func TestStartAdminServer_NeverSeenIncluding_ExpectedSilentHostRendersUnknownOverAdminHTTP(t *testing.T) {
	const (
		beatingHost = "host-beating-over-wire"
		silentHost  = "host-expected-but-never-heard"
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The production control plane over the stub-env live deps (un-dialed, in-memory store, D50).
	cp, err := controlplane.NewControlPlane(liveDepsWithStubEnv(t))
	if err != nil {
		t.Fatalf("NewControlPlane over stub-env live deps: %v", err)
	}

	// Drive the reconcile loop with the real serve path over a loopback listener (a real socket,
	// no live edge). Serve registers the hostagent.v1 heartbeat ingest + starts the loop.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("loopback listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- controlplane.Serve(ctx, cp, lis) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("controlplane.Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("controlplane.Serve did not return after shutdown")
		}
	})

	// The production never-seen supplier shape: it names BOTH the host that beats (also
	// heard-from) AND an expected host that NEVER beats — so the loop-serialized snapshot must
	// fold the silent one in as a never-seen UNKNOWN while reporting the beating one from its
	// real wire beat. This is exactly the set storeExpectedHosts would enumerate from a fleet
	// holding both a placed-and-reporting host and a placed-but-never-reported host.
	supplier := func() []string { return []string{silentHost, beatingHost} }
	snapshotter := cp.LivenessSnapshotterIncluding(ctx, supplier)

	// Arm the REAL admin surface with the production never-seen snapshotter and serve it on a
	// loopback HTTP listener.
	bound, closeAdmin, err := startAdminServer("127.0.0.1:0", snapshotter)
	if err != nil {
		t.Fatalf("startAdminServer with the including-snapshotter: %v", err)
	}
	t.Cleanup(func() {
		if err := closeAdmin(); err != nil {
			t.Errorf("close admin surface: %v", err)
		}
	})

	// Ingest a heartbeat for the beating host over the real hostagent.v1 ReportHeartbeat wire so
	// the reconcile loop Observes it → LIVE. The silent host is never sent — it comes ONLY from
	// the supplier.
	ingestHeartbeatOverWire(t, ctx, lis.Addr().String(), beatingHost)

	// Poll /debug/liveness over the real admin HTTP surface until BOTH hosts render as required:
	// the beating host LIVE/EverSeen (its Observe is async), and the expected-silent host folded
	// in as UNKNOWN/never-seen with a zero LastBeat. The loop-serialized read is race-clean.
	var sawLive, sawSilent bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var view []livenessHostView
		if err := json.Unmarshal(getLiveness(t, bound, ""), &view); err != nil {
			t.Fatalf("unmarshal /debug/liveness: %v", err)
		}

		// The expected-but-silent host is folded into EVERY snapshot (it comes from the supplier,
		// not the wire) as a never-seen UNKNOWN.
		if silent, ok := findLivenessHost(view, silentHost); ok {
			sawSilent = true
			if silent.EverSeen {
				t.Fatalf("expected-silent host EverSeen = true over /debug/liveness, want false (never heartbeated)")
			}
			if silent.Liveness != string(reconciler.HostUnknown) {
				t.Fatalf("expected-silent host liveness = %q over /debug/liveness, want %q (UNKNOWN)", silent.Liveness, reconciler.HostUnknown)
			}
			if silent.LastBeatUnix != 0 {
				t.Fatalf("expected-silent host last_beat_unix = %d over /debug/liveness, want 0 (no beat)", silent.LastBeatUnix)
			}
		}

		// The beating host renders from its real wire beat as LIVE / EverSeen.
		if beating, ok := findLivenessHost(view, beatingHost); ok && beating.EverSeen {
			if beating.Liveness != string(reconciler.HostLive) {
				t.Fatalf("beating host liveness = %q over /debug/liveness, want %q (LIVE)", beating.Liveness, reconciler.HostLive)
			}
			sawLive = true
		}

		if sawLive && sawSilent {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawSilent {
		t.Fatalf("/debug/liveness never folded in the expected-but-silent host %q (the never-seen enrichment did not render it)", silentHost)
	}
	if !sawLive {
		t.Fatalf("/debug/liveness never reported the wire-beating host %q as LIVE", beatingHost)
	}
}

// ingestHeartbeatOverWire dials the control plane's loopback gRPC listener and sends a single
// synthetic heartbeat for hostID over the real hostagent.v1 ReportHeartbeat stream, so the
// reconcile loop Observes it (→ LIVE). Insecure transport over a 127.0.0.1 loopback socket — a
// real wire, no live edge (D50). grpc.NewClient is lazy; the CloseAndRecv forces the stream.
func ingestHeartbeatOverWire(t *testing.T, ctx context.Context, addr, hostID string) {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial control plane %q: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	stream, err := hostagentv1.NewHostAgentServiceClient(conn).ReportHeartbeat(ctx)
	if err != nil {
		t.Fatalf("open ReportHeartbeat stream: %v", err)
	}
	hb := &hostagentv1.Heartbeat{
		HostId:   hostID,
		Capacity: &hostagentv1.HostCapacity{RunningSessions: 1},
	}
	if err := stream.Send(&hostagentv1.ReportHeartbeatRequest{Heartbeat: hb}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}
}
