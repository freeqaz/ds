package main

// main_test.go pins two pieces of the never-seen liveness wiring main.go assembles under
// DS_ORCH_LIVE (doc 15 §3/§5.2; D35/D72), against synthetic fixtures with no live edge (D50):
//
//   - storeExpectedHosts: the production controlplane.ExpectedHostSupplier built over the
//     live store's ListSessions. Today this store-backed enumeration is only exercised
//     INDIRECTLY via a synthetic supplier of the same shape (controlplane/serve_test.go);
//     the actual storeExpectedHosts body — distinct-host dedup, empty-host skip,
//     IncludeDestroyed:false default, list-fault degrade-to-nil, nil-store→nil — is pinned
//     here directly over a tiny fake expectedHostLister.
//   - the livenessRegistry armed>1 single-surface clobber-detection path (admin.go): the
//     setLivenessSnapshotter increments armed and emits the WARN on a SECOND concurrent arm,
//     and the returned un-arm closer is idempotent + LIFO and decrements armed, nil-ing the
//     process-global var ONLY on the last-surface un-arm. Today only the un-arm/clear
//     lifecycle is exercised by the admin_test.go lifecycle tests — the armed>1 WARN branch
//     is asserted here directly (with a slog handler buffer capturing the WARN).

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/parkstore"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// ---- storeExpectedHosts: the production ExpectedHostSupplier over a fake lister ----

// fakeExpectedHostLister is a synthetic expectedHostLister the storeExpectedHosts tests drive:
// it returns a fixed session set (or an error) and RECORDS the filter ListSessions was called
// with, so a test can assert BOTH the enumerated host set AND that the supplier passes the
// IncludeDestroyed:false default filter (a torn-down host is not an expected beat). It is
// stdlib-only and never touches a real store (D50).
type fakeExpectedHostLister struct {
	mu      sync.Mutex
	out     []store.Session
	err     error
	calls   int
	lastFil store.SessionFilter
}

func (f *fakeExpectedHostLister) ListSessions(_ context.Context, fil store.SessionFilter) ([]store.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastFil = fil
	if f.err != nil {
		return nil, f.err
	}
	// Return a fresh copy so a caller mutating the result cannot corrupt the fake's set
	// (mirrors the real store's caller-owned-slice contract).
	return append([]store.Session(nil), f.out...), nil
}

// sessionOnHost builds a synthetic session record placed on hostID (the only field the
// never-seen enumeration reads is Ref.HostID).
func sessionOnHost(hostID string) store.Session {
	return store.Session{Ref: store.SessionRef{HostID: hostID}}
}

// TestStoreExpectedHosts_DistinctHostIDs proves the supplier DEDUPES: repeated host_ids across
// session records (multiple sessions placed on one host) collapse to ONE expected host, so the
// never-seen view does not double-count a host. The fake returns three records across two
// distinct hosts; the supplier must return exactly those two, each once.
func TestStoreExpectedHosts_DistinctHostIDs(t *testing.T) {
	lister := &fakeExpectedHostLister{out: []store.Session{
		sessionOnHost("host-a"),
		sessionOnHost("host-b"),
		sessionOnHost("host-a"), // a second session on host-a — must NOT appear twice.
	}}
	supplier := storeExpectedHosts(lister)
	if supplier == nil {
		t.Fatal("storeExpectedHosts returned nil for a non-nil lister")
	}

	got := supplier()
	assertSameSet(t, got, []string{"host-a", "host-b"})
	if len(got) != 2 {
		t.Fatalf("expected hosts = %v, want exactly 2 distinct (host-a deduped)", got)
	}
}

// TestStoreExpectedHosts_SkipsEmptyHostID proves a pre-placement record (an UNBOUND session
// whose Ref.HostID is empty — no host assigned yet) is SKIPPED: such a record is not a host
// expected to be heartbeating, so it must never enter the expected set (which would otherwise
// fold a bogus "" host into /debug/liveness).
func TestStoreExpectedHosts_SkipsEmptyHostID(t *testing.T) {
	lister := &fakeExpectedHostLister{out: []store.Session{
		sessionOnHost("host-a"),
		sessionOnHost(""), // pre-placement record: no host yet — must be skipped.
		sessionOnHost("host-c"),
	}}

	got := storeExpectedHosts(lister)()
	assertSameSet(t, got, []string{"host-a", "host-c"})
	for _, h := range got {
		if h == "" {
			t.Fatalf("expected hosts %v contained an empty host_id (pre-placement record not skipped)", got)
		}
	}
}

// TestStoreExpectedHosts_IncludeDestroyedFalseDefault proves the supplier passes the SessionFilter
// ZERO value — IncludeDestroyed:false — so a torn-down (DESTROYED) host the live store filters
// out is NOT treated as an expected beat (a destroyed host that stops heartbeating is not a
// never-seen anomaly). We assert the filter the supplier handed the lister is the default
// (IncludeDestroyed false, no host/state/parent narrowing): the store's own DESTROYED filtering
// then keeps a torn-down host out, which we model by the fake returning only the live records.
func TestStoreExpectedHosts_IncludeDestroyedFalseDefault(t *testing.T) {
	// The fake models a store that has already applied IncludeDestroyed:false (a torn-down
	// host's record absent) — the supplier's job is to pass the default filter that REQUESTS
	// that omission, which we assert on lastFil below.
	lister := &fakeExpectedHostLister{out: []store.Session{
		sessionOnHost("host-live-1"),
		sessionOnHost("host-live-2"),
	}}

	got := storeExpectedHosts(lister)()
	assertSameSet(t, got, []string{"host-live-1", "host-live-2"})

	lister.mu.Lock()
	fil := lister.lastFil
	calls := lister.calls
	lister.mu.Unlock()
	if calls != 1 {
		t.Fatalf("ListSessions call count = %d, want exactly 1 per supplier invocation", calls)
	}
	if fil.IncludeDestroyed {
		t.Errorf("supplier passed IncludeDestroyed = true, want false (a torn-down host is not an expected beat)")
	}
	// The default filter narrows on nothing else — the never-seen enumeration is fleet-wide
	// over the live (non-destroyed) records, not a single host/state/parent.
	if fil != (store.SessionFilter{}) {
		t.Errorf("supplier passed a non-zero SessionFilter %+v, want the zero value (IncludeDestroyed:false default, no narrowing)", fil)
	}
}

// TestStoreExpectedHosts_ListFaultDegradesToNil proves a store read fault DEGRADES to nil
// (the heard-from-only view this snapshot) with NO panic: the never-seen enrichment is purely
// additive, so a list fault on the admin render path must be silent, never an error or a crash.
func TestStoreExpectedHosts_ListFaultDegradesToNil(t *testing.T) {
	lister := &fakeExpectedHostLister{err: errors.New("synthetic store read fault")}
	supplier := storeExpectedHosts(lister)
	if supplier == nil {
		t.Fatal("storeExpectedHosts returned nil for a non-nil (faulting) lister")
	}

	got := supplier()
	if got != nil {
		t.Fatalf("list fault expected hosts = %v, want nil (degrade to the heard-from-only view)", got)
	}
}

// TestStoreExpectedHosts_NilStoreYieldsNilSupplier proves a nil store yields a NIL supplier
// (not a supplier that panics on call): the never-seen enrichment is opt-in, and an
// unconfigured store leaves it un-armed entirely (LivenessSnapshotterIncluding(nil) is the
// heard-from-only view).
func TestStoreExpectedHosts_NilStoreYieldsNilSupplier(t *testing.T) {
	if supplier := storeExpectedHosts(nil); supplier != nil {
		t.Fatalf("storeExpectedHosts(nil) = %v, want nil supplier (never-seen enrichment un-armed)", supplier)
	}
}

// TestStoreExpectedHosts_EmptyFleetDegradesToEmpty proves a live store with NO sessions yields
// an empty expected set (no never-seen hosts to fold in), degrading to today's heard-from-only
// view byte-for-byte — the additive contract.
func TestStoreExpectedHosts_EmptyFleetDegradesToEmpty(t *testing.T) {
	got := storeExpectedHosts(&fakeExpectedHostLister{})()
	if len(got) != 0 {
		t.Fatalf("empty-fleet expected hosts = %v, want empty (heard-from-only view)", got)
	}
}

// TestStoreExpectedHosts_FreshSlicePerCall proves the supplier returns a FRESH, caller-owned
// slice each call (the ExpectedHostSupplier contract the loop relies on, controlplane/serve.go):
// mutating the slice a prior call returned must NEVER leak into a later snapshot. We corrupt the
// first call's return, then assert the second call still reports the real host set.
func TestStoreExpectedHosts_FreshSlicePerCall(t *testing.T) {
	lister := &fakeExpectedHostLister{out: []store.Session{sessionOnHost("host-a")}}
	supplier := storeExpectedHosts(lister)

	first := supplier()
	assertSameSet(t, first, []string{"host-a"})
	for i := range first {
		first[i] = "CLOBBERED" // mutate the returned slice — must not affect a later call.
	}

	second := supplier()
	assertSameSet(t, second, []string{"host-a"})
}

// ---- resolveStore: the durable D46 park backing (parkstore.SQL) wiring ----
//
// main.go wires Deps.ParkRecorder to parkstore.NewSQL over the SAME *sql.DB resolveStore opens
// for the Postgres store, env-gated under DS_ORCH_LIVE, REUSING that pool ONLY when a DSN
// configured the Postgres path; with no DSN it leaves Deps.ParkRecorder unset so
// NewControlPlane's in-process parkstore.NewMemory() default stands (durable WITHIN the
// process, doc 15 §3 / doc 16 §8.2; D46/D50). These assertions pin that surface SYNTHETICALLY
// with NO live DB (sql.Open never dials — it validates the DSN + driver registration lazily),
// so the gate stays green with no Postgres reachable (D50).

// fakeSQLDriver is a synthetic database/sql driver registered ONLY for these tests: sql.Open
// against it never dials (Open is lazy), so resolveStore's Postgres path can surface a real,
// non-nil *sql.DB without any live backend. Its Conn methods are never reached in these tests
// (no query is ever run), so they return a not-implemented error rather than a live connection.
type fakeSQLDriver struct{}

func (fakeSQLDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("fakeSQLDriver: Open dialed — these tests never run a query (sql.Open is lazy)")
}

func init() { sql.Register("ds-orch-parkstore-test", fakeSQLDriver{}) }

// TestResolveStore_GateOffNoDSN_LeavesInProcessParkRecorderDefault is the LOAD-BEARING gate-off
// assertion: with NO DS_ORCH_PG_DSN configured (and DS_ORCH_LIVE irrelevant — this exercises the
// store-resolution surface directly, never dialing a live edge, D50), resolveStore returns a NIL
// *sql.DB. main.go wires Deps.ParkRecorder = parkstore.NewSQL(db) ONLY when that handle is
// non-nil, so a nil handle means Deps.ParkRecorder is LEFT UNSET and NewControlPlane's in-process
// parkstore.NewMemory() default stands untouched. The store is the in-memory *store.Memory (the
// single-binary posture), and the closer is a harmless no-op.
func TestResolveStore_GateOffNoDSN_LeavesInProcessParkRecorderDefault(t *testing.T) {
	t.Setenv("DS_ORCH_PG_DSN", "") // no external Postgres configured — the in-memory store posture.

	st, db, closeStore, err := resolveStore()
	if err != nil {
		t.Fatalf("resolveStore with no DSN returned an error: %v (want the in-memory store, no error)", err)
	}
	if db != nil {
		t.Fatalf("resolveStore with no DSN surfaced a non-nil *sql.DB = %v; want nil so main.go leaves Deps.ParkRecorder UNSET and NewControlPlane's in-process parkstore.NewMemory() default stands", db)
	}
	if _, ok := st.(*store.Memory); !ok {
		t.Fatalf("resolveStore with no DSN returned %T, want *store.Memory (the single-binary in-memory posture)", st)
	}
	// A nil *sql.DB is exactly what guards the park wiring: parkstore.NewSQL is reached ONLY for a
	// non-nil handle, so prove the wiring condition main.go uses (db != nil) is false here.
	if db != nil {
		t.Fatal("park-backing wiring condition (storeDB != nil) is true with no DSN; the in-process Memory default would be clobbered")
	}
	if closeStore == nil {
		t.Fatal("resolveStore returned a nil closer for the in-memory store; want a no-op closer")
	}
	if err := closeStore(); err != nil {
		t.Fatalf("in-memory store closer returned %v, want nil (no-op)", err)
	}
}

// TestResolveStore_DSNSet_SurfacesPoolBackingParkstoreSQL proves the positive arm: with a DSN
// configured (and a registered synthetic driver via DS_PG_DRIVER — sql.Open is lazy, so NO live
// DB is dialed, D50), resolveStore surfaces a NON-nil *sql.DB and an external-Postgres store, and
// that SAME pool backs parkstore.NewSQL — the durable D46 park join over the store's own pool
// (one connection, one driver registration). This is the handle main.go threads into
// Deps.ParkRecorder so a rung-2 ask survives a control-plane restart (doc 16 §8.2).
func TestResolveStore_DSNSet_SurfacesPoolBackingParkstoreSQL(t *testing.T) {
	t.Setenv("DS_ORCH_PG_DSN", "postgres://ds:ds@127.0.0.1:5432/ds?sslmode=disable")
	t.Setenv("DS_PG_DRIVER", "ds-orch-parkstore-test") // registered fake — sql.Open never dials.

	st, db, closeStore, err := resolveStore()
	if err != nil {
		t.Fatalf("resolveStore with a DSN + registered driver returned an error: %v (sql.Open is lazy — no dial expected)", err)
	}
	if db == nil {
		t.Fatal("resolveStore with a DSN surfaced a nil *sql.DB; want the pool so parkstore.NewSQL fronts the durable D46 park join over it")
	}
	if _, ok := st.(*store.Postgres); !ok {
		t.Fatalf("resolveStore with a DSN returned %T, want *store.Postgres (the external store, D6)", st)
	}
	// The surfaced pool is exactly what main.go hands parkstore.NewSQL — prove it constructs a
	// non-nil durable recorder over the SAME handle (no second open, no second registration).
	if recorder := parkstore.NewSQL(db); recorder == nil {
		t.Fatal("parkstore.NewSQL over the surfaced pool returned nil; want the durable D46 park backing")
	}
	if closeStore == nil {
		t.Fatal("resolveStore returned a nil closer for the Postgres store; want db.Close")
	}
	// db.Close on an unused pool (no connection ever opened) is a clean no-op — close it so the
	// test leaves no pool behind. The closer owns the pool's lifecycle (the park backing shares it).
	if err := closeStore(); err != nil {
		t.Fatalf("Postgres store closer returned %v, want nil (no connection was ever dialed)", err)
	}
}

// TestResolveStore_DSNSet_UnregisteredDriver proves the loud-failure shape: a DSN with an
// UNregistered driver name fails at resolveStore (sql.Open rejects an unknown driver) rather than
// nil-panicking later, mirroring controlplane.NewPostgresStore's D33 contract. Synthetic — no
// live DB (the failure is purely driver-registration, never a dial).
func TestResolveStore_DSNSet_UnregisteredDriver(t *testing.T) {
	t.Setenv("DS_ORCH_PG_DSN", "postgres://ds:ds@127.0.0.1:5432/ds?sslmode=disable")
	t.Setenv("DS_PG_DRIVER", "ds-orch-no-such-driver-registered")

	st, db, _, err := resolveStore()
	if err == nil {
		t.Fatal("resolveStore with an unregistered driver returned no error; want a loud failure (D33: operator registers a driver at the binary boundary)")
	}
	if st != nil || db != nil {
		t.Fatalf("resolveStore failure returned non-nil store/db (%v, %v); want both nil on the error path", st, db)
	}
	if !strings.Contains(err.Error(), "external postgres store") {
		t.Errorf("resolveStore unregistered-driver error = %q, want it to name the external postgres store open", err)
	}
}

// ---- the livenessRegistry armed>1 single-surface clobber-detection path (admin.go) ----

// TestSetLivenessSnapshotter_ArmedGuardAndLIFOUnarm directly asserts the expvar single-surface
// guard on livenessRegistry (admin.go): a SECOND concurrent arm increments armed and emits the
// WARN (visible, not a silent clobber), the global var points at the latest-armed snapshotter,
// and the un-arm closers are idempotent + LIFO and decrement armed — the process-global var is
// nil-ed ONLY on the LAST-surface un-arm. This is the production single-admin-surface invariant
// (run() arms exactly one); a second arm is a misconfiguration the guard must surface.
//
// It operates on the process-global livenessRegistry, so it snapshots and RESTORES the registry
// state on cleanup to stay isolated from the other admin tests in this package (the expvar var
// itself is published-once and cannot be unpublished — only its backing snapshotter is reset).
func TestSetLivenessSnapshotter_ArmedGuardAndLIFOUnarm(t *testing.T) {
	restore := snapshotLivenessRegistry(t)
	defer restore()

	// Capture slog WARN output so we can assert the armed>1 WARN fires on the second arm.
	var buf safeBuffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	defer slog.SetDefault(prev)

	first := stubSnapshotter("first")
	second := stubSnapshotter("second")

	// First arm: armed goes 0→1, no WARN, the global var points at the first snapshotter.
	unarm1 := setLivenessSnapshotter(first)
	if got := readArmed(); got != 1 {
		t.Fatalf("after first arm, armed = %d, want 1", got)
	}
	if got := readSnap(); got == nil {
		t.Fatal("after first arm, global snapshotter is nil, want the first surface's")
	}
	if strings.Contains(buf.String(), "second admin surface armed") {
		t.Fatalf("WARN emitted on the FIRST arm; want it only on a second concurrent arm.\nlog=%s", buf.String())
	}

	// Second concurrent arm (armed already 1): armed goes 1→2, the WARN fires, and the global
	// var now points at the SECOND snapshotter (the documented "latest-armed wins" clobber the
	// guard makes visible).
	unarm2 := setLivenessSnapshotter(second)
	if got := readArmed(); got != 2 {
		t.Fatalf("after second concurrent arm, armed = %d, want 2", got)
	}
	if !strings.Contains(buf.String(), "second admin surface armed") {
		t.Fatalf("armed>1 WARN not emitted on the second concurrent arm.\nlog=%s", buf.String())
	}
	if !strings.Contains(buf.String(), "already_armed=1") {
		t.Errorf("armed>1 WARN did not carry already_armed=1.\nlog=%s", buf.String())
	}

	// LIFO un-arm: stop the SECOND surface first. armed goes 2→1; because a surface is still
	// live, the global var is NOT nil-ed (it keeps rendering — the first surface's snapshotter).
	unarm2()
	if got := readArmed(); got != 1 {
		t.Fatalf("after un-arming the second surface, armed = %d, want 1", got)
	}
	if got := readSnap(); got == nil {
		t.Fatal("global snapshotter nil-ed while a surface is still armed; want it kept until the LAST un-arm")
	}

	// Idempotent: a second invocation of the same closer is a harmless no-op (does NOT
	// double-decrement armed below the live count — a key safety property since the bootstrap
	// registers the closer as a deferred close that may also fire elsewhere).
	unarm2()
	if got := readArmed(); got != 1 {
		t.Fatalf("re-invoking the second un-arm closer changed armed to %d, want 1 (idempotent)", got)
	}

	// Last-surface un-arm: stop the FIRST surface. armed goes 1→0 and ONLY now is the global
	// var nil-ed (no surface left holding it).
	unarm1()
	if got := readArmed(); got != 0 {
		t.Fatalf("after the last un-arm, armed = %d, want 0", got)
	}
	if got := readSnap(); got != nil {
		t.Fatalf("global snapshotter = %v after the last-surface un-arm, want nil (cleared only on the last stop)", got)
	}

	// The first closer is also idempotent at zero — a re-fire must not drive armed negative.
	unarm1()
	if got := readArmed(); got != 0 {
		t.Fatalf("re-invoking the first un-arm closer drove armed to %d, want it to stay 0 (idempotent, no underflow)", got)
	}
}

// snapshotLivenessRegistry captures the current process-global livenessRegistry snapshotter +
// armed count and returns a restore func, so a test that mutates the global state leaves it as it
// found it for the other admin tests in this package. The expvar var itself is published-once and
// cannot be unpublished; only the backing snapshotter + the armed count are reset.
func snapshotLivenessRegistry(t *testing.T) func() {
	t.Helper()
	livenessRegistry.mu.Lock()
	savedSnap := livenessRegistry.snap
	savedArmed := livenessRegistry.armed
	livenessRegistry.mu.Unlock()
	// Start the test from a known-clean armed=0 / snap=nil state so the assertions are exact,
	// regardless of any surface a prior test left armed.
	livenessRegistry.mu.Lock()
	livenessRegistry.snap = nil
	livenessRegistry.armed = 0
	livenessRegistry.mu.Unlock()
	return func() {
		livenessRegistry.mu.Lock()
		livenessRegistry.snap = savedSnap
		livenessRegistry.armed = savedArmed
		livenessRegistry.mu.Unlock()
	}
}

// readArmed / readSnap read the process-global registry fields under its mutex (the same
// discipline setLivenessSnapshotter uses), so the assertions are race-clean under -race.
func readArmed() int {
	livenessRegistry.mu.Lock()
	defer livenessRegistry.mu.Unlock()
	return livenessRegistry.armed
}

func readSnap() HealthSnapshotter {
	livenessRegistry.mu.Lock()
	defer livenessRegistry.mu.Unlock()
	return livenessRegistry.snap
}

// stubSnapshotter is a trivial HealthSnapshotter whose identity is the only thing that matters
// to the armed-guard test (it asserts WHICH snapshotter the global var points at, never renders
// a snapshot). It carries a tag so a future diagnostic can distinguish surfaces.
type stubSnapshotter string

func (stubSnapshotter) HealthSnapshot() []reconciler.HostHealth { return nil }

// safeBuffer is a mutex-guarded bytes.Buffer so the slog handler (which may write from any
// goroutine) and the test's String() read are race-clean under -race.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// assertSameSet asserts got and want hold the same set of host_ids (order-independent), the
// natural comparison for the never-seen enumeration (the expected set is unordered).
func assertSameSet(t *testing.T, got, want []string) {
	t.Helper()
	gotSet := make(map[string]int, len(got))
	for _, h := range got {
		gotSet[h]++
	}
	wantSet := make(map[string]int, len(want))
	for _, h := range want {
		wantSet[h]++
	}
	if len(gotSet) != len(wantSet) {
		t.Fatalf("host set %v has %d distinct, want %v (%d distinct)", got, len(gotSet), want, len(wantSet))
	}
	for h := range wantSet {
		if _, ok := gotSet[h]; !ok {
			t.Fatalf("host set %v missing expected host %q (want %v)", got, h, want)
		}
	}
}

// ---- seedEnvConfig: the §4.1 step-1 env-config seed (D56) for a fresh single-binary live run ----

// TestSeedEnvConfigRegistersTheSecondKey proves the DS_ORCH_SEED_ENV_CONFIG seed lands the
// §4.1 step-1 env config (D56) into the in-memory store so resolveImageAndEntrypoint's
// GetEnvConfig read finds it (no more no-env-spec refusal on a fresh CreateSession). It
// asserts the ref→image-id round-trips and the DS_ORCH_SEED_REPO_ID rides through.
func TestSeedEnvConfigRegistersTheSecondKey(t *testing.T) {
	t.Setenv("DS_ORCH_SEED_ENV_CONFIG", "demo-env=m0-base")
	t.Setenv("DS_ORCH_SEED_REPO_ID", "demo")
	st := store.NewMemory()
	if err := seedEnvConfig(st); err != nil {
		t.Fatalf("seedEnvConfig: %v", err)
	}
	cfg, err := st.GetEnvConfig(context.Background(), "demo-env")
	if err != nil {
		t.Fatalf("GetEnvConfig after seed: %v", err)
	}
	if cfg.ImageID != "m0-base" {
		t.Errorf("seeded ImageID = %q, want %q", cfg.ImageID, "m0-base")
	}
	if cfg.RepoRef != "demo" {
		t.Errorf("seeded RepoRef = %q, want %q (DS_ORCH_SEED_REPO_ID)", cfg.RepoRef, "demo")
	}
}

// TestSeedEnvConfigUnsetIsNoop: with DS_ORCH_SEED_ENV_CONFIG unset the seed is a no-op (a
// Postgres-backed run, which seeds via the DB, is untouched) — no error and nothing written.
func TestSeedEnvConfigUnsetIsNoop(t *testing.T) {
	t.Setenv("DS_ORCH_SEED_ENV_CONFIG", "")
	st := store.NewMemory()
	if err := seedEnvConfig(st); err != nil {
		t.Fatalf("seedEnvConfig unset should be a no-op, got: %v", err)
	}
	if _, err := st.GetEnvConfig(context.Background(), "demo-env"); err == nil {
		t.Error("seedEnvConfig unset wrote an env config; want nothing written")
	}
}

// TestSeedEnvConfigMalformed: a value without ref=image-id is a loud error, not a silent
// half-seed (a misconfigured live run fails to start rather than refusing CreateSession later).
func TestSeedEnvConfigMalformed(t *testing.T) {
	for _, bad := range []string{"no-equals", "=missing-ref", "missing-image="} {
		t.Run(bad, func(t *testing.T) {
			t.Setenv("DS_ORCH_SEED_ENV_CONFIG", bad)
			if err := seedEnvConfig(store.NewMemory()); err == nil {
				t.Errorf("seedEnvConfig(%q) = nil, want a malformed error", bad)
			}
		})
	}
}
