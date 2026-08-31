// SPDX-License-Identifier: Apache-2.0
package main

// landq_test_helpers_test.go is the OPT-IN hermetic-Postgres scaffolding for the
// landq *Live tests in cmd_landq_test.go.
//
// THE PROBLEM. Every landq *Live test (TestLandqEnqueueListRoundTripLive,
// TestLandqRunnerMethodsLive, TestLandqCancelLive, TestLandqRequeueLive,
// TestLandqReapLive, TestLandqReapDryRunLive, TestLandqEnqueueGateRoundTripLive)
// needs a real Postgres land_queue. In the default CI/wave gate there is none, so
// every one of them SKIPS via resolveLockConfig()/openLockServer()'s guards
// (cfg.Enabled==false, or the server is unreachable). The deterministic fixes
// from bgem3w10 made them correct WHEN they run — but they never run.
//
// THE OPT-IN PATH (this file). When the operator sets DS_LANDQ_EPHEMERAL_PG=1 the
// *Live tests run against a THROWAWAY Postgres that is provisioned for the test
// process and torn down at the end. Two provisioning sources, in order:
//
//  1. DS_LANDQ_EPHEMERAL_DSN — a caller-provided lib/pq DSN (keyword/value or URL)
//     for an ephemeral instance the CALLER owns and tears down (e.g. a
//     `testcontainers`/`docker run --rm postgres` the wave harness already spun
//     up, or an embedded-pg cluster a wrapper script launched). Used verbatim.
//
//  2. AUTO-SPIN — if no DSN is given, locate `initdb`/`pg_ctl`/`postgres` on PATH
//     (or under PG_BINDIR) and bring up a private, throwaway cluster in a
//     t.TempDir() data directory on a loopback-only unix socket, create a fresh
//     database, hand back its DSN, and `pg_ctl stop` + remove it on teardown.
//     This is the embedded-pg pattern WITHOUT a new Go module dependency: it
//     shells out to whatever Postgres binaries the host already has. If those
//     binaries are absent the gated path FAILS LOUDLY (the operator explicitly
//     asked for the ephemeral path), it does NOT silently skip.
//
// HOW IT REACHES THE TESTS. Provisioning sets TASKDB_LOCK_DSN (via t.Setenv) to
// the ephemeral DSN, which is exactly the override resolveLockConfig() already
// honors (TASKDB_LOCK_DSN wins over the Postgres block and forces Enabled=true).
// So the *Live tests need NO change to their resolve/open logic beyond routing
// their setup through landqServerForTest(t): when the gate is OFF they SKIP at the
// very top (before any connection); when it is ON they connect to the throwaway PG.
//
// DEFAULT-GATE INVARIANT. With DS_LANDQ_EPHEMERAL_PG unset (the CI/wave default),
// landqServerForTest SKIPS IMMEDIATELY — it does not resolve config or open a
// connection at all. This is the isolation guard: in the normal environment
// lockserver.json has "enabled":true and the SSH tunnel (127.0.0.1:5433) is up,
// so the old resolve→"disabled?"→"unreachable?" skip path never fired and the
// *Live tests silently ran against the SHARED PRODUCTION lock server (deleting
// real land_queue rows and force-releasing the live leader's __land_leader__
// sentinel). Skipping up front means the suite stays green with every *Live test
// SKIPPED, and NO new dependency enters the default gate (no module import, no
// binary requirement — the auto-spin code only shells out, and only when the
// gate is on).

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// ephemeralGateEnv is the opt-in switch. Set DS_LANDQ_EPHEMERAL_PG=1 to make the
// landq *Live tests run against a throwaway Postgres instead of skipping.
const ephemeralGateEnv = "DS_LANDQ_EPHEMERAL_PG"

// ephemeralDSNEnv lets the caller supply a ready ephemeral DSN (they own its
// lifecycle); when set it is used verbatim and auto-spin is skipped.
const ephemeralDSNEnv = "DS_LANDQ_EPHEMERAL_DSN"

// pgBinDirEnv optionally points auto-spin at a Postgres bin directory (where
// initdb/pg_ctl/postgres live) when they are not on PATH.
const pgBinDirEnv = "PG_BINDIR"

// ephemeralOnce guards a single auto-spun cluster for the whole package: many
// *Live tests run in the same process, and standing up one throwaway cluster
// (shared, read/write, each test isolates by its own unique branch + cleanup) is
// far cheaper than one initdb per test. The cluster is started lazily on the
// first gated *Live test and stopped via t.Cleanup on that same first test, so it
// outlives sibling tests within the run. A caller-provided DSN bypasses this
// entirely.
var (
	ephemeralOnce sync.Once
	ephemeralDSN  string
	ephemeralErr  error
)

// allowSharedEnv is the explicit, deliberate escape hatch for the
// defense-in-depth backstop below: it lets a (hypothetical, future) test
// knowingly route landqServerForTest at a NON-ephemeral / shared server. It is
// NEVER needed for the normal ephemeral path (auto-spin or a caller's throwaway
// DSN) and exists only so the backstop can refuse a shared endpoint by default
// while staying overridable for a conscious operator.
const allowSharedEnv = "DS_LANDQ_ALLOW_SHARED"

// landqServerForTest is the single chokepoint every landq *Live test routes its
// setup through, and the ONE place that decides whether a *Live test may touch a
// real lock server. Behavior:
//
//   - DS_LANDQ_EPHEMERAL_PG unset  → SKIP IMMEDIATELY, before resolving any config
//     or opening any connection. This is the must-have isolation guard: in the
//     normal environment lockserver.json has "enabled":true and the SSH tunnel
//     (127.0.0.1:5433) is up, so the old resolve→"disabled?"→"unreachable?" skip
//     path NEVER fired and these *Live tests ran against the SHARED PRODUCTION
//     lock server — deleting real land_queue rows (deleteLandByBranch cleanup) and
//     force-releasing the live leader's __land_leader__ sentinel. Skipping here at
//     the very top means no landq *Live test can mutate prod state in the default
//     (shared-DB) environment. It mirrors the existing precedent at
//     cmd_landq_test.go's TestLandLeaderSentinelSurvivesReap gate.
//
//   - DS_LANDQ_EPHEMERAL_PG set    → provision a throwaway Postgres (caller DSN or
//     auto-spin), point TASKDB_LOCK_DSN at it for THIS test (t.Setenv, auto-
//     restored), then run resolveLockConfig→openLockServer→migrate.
//     resolveLockConfig() reads TASKDB_LOCK_DSN and returns Enabled=true with that
//     DSN, so the rest of the flow is unchanged. A provisioning failure on the
//     explicitly-requested path is a t.Fatal, never a silent skip. As a
//     defense-in-depth backstop, if the resolved DSN nonetheless points at the
//     SHARED production server it refuses (t.Skip) unless DS_LANDQ_ALLOW_SHARED=1.
//
// It mirrors landqLiveServer's cleanup ordering exactly: ls.close is registered
// before the caller registers its per-branch row delete, so close runs after the
// delete.
func landqServerForTest(t *testing.T) *lockServer {
	t.Helper()

	if !truthyEnv(ephemeralGateEnv) {
		// MUST-HAVE isolation gate. Skip before ANY config resolution or connection
		// so no landq *Live test can touch the shared production lock server in the
		// normal environment (lockserver.json enabled + tunnel up).
		t.Skip("landq live test needs an ephemeral Postgres; set " + ephemeralGateEnv +
			" to run — refusing to touch the shared production lock server")
	}

	dsn := provisionEphemeralPG(t)
	// Route the unchanged resolveLockConfig() at the throwaway instance for the
	// duration of this test; t.Setenv restores the prior value on cleanup.
	t.Setenv(ephemeralDSNEnv, "") // avoid confusing a nested resolve; harmless if unset
	t.Setenv("TASKDB_LOCK_DSN", dsn)
	// A gate that also pins TASKDB_LOCK_DISABLE would be self-contradictory —
	// clear it so resolveLockConfig() does not short-circuit to disabled.
	t.Setenv("TASKDB_LOCK_DISABLE", "")

	cfg, err := resolveLockConfig()
	if err != nil {
		t.Skipf("no lock config: %v", err)
	}
	if !cfg.Enabled {
		// Should be unreachable: we just pinned an ephemeral TASKDB_LOCK_DSN.
		t.Skip("lock server disabled (TASKDB_LOCK_DISABLE or config) — skipping landq live test " +
			"(set " + ephemeralGateEnv + "=1 to run hermetically against a throwaway Postgres)")
	}
	// DEFENSE-IN-DEPTH BACKSTOP. Even on the ephemeral path, refuse to proceed if
	// the resolved DSN actually points at the SHARED production server (the SSH
	// tunnel endpoint / production dbname). This guards against a future
	// regression where provisioning silently hands back a non-throwaway DSN; the
	// primary gate above is the must-have, this is belt-and-suspenders.
	if dsnLooksShared(cfg.dsn()) && !truthyEnv(allowSharedEnv) {
		t.Skip("resolved DSN points at the SHARED production lock server, not a throwaway — " +
			"refusing (set " + allowSharedEnv + "=1 to override deliberately)")
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		// Provisioning already pinged the DB, so an open failure here is a real
		// bug, not the "no tunnel" skip — surface it.
		t.Fatalf("ephemeral lock server unreachable after provisioning: %v", err)
	}
	t.Cleanup(ls.close) // registered FIRST → runs LAST (after the caller's row delete)
	if err := ls.migrate(); err != nil {
		t.Fatalf("migrate() failed: %v", err)
	}
	return ls
}

// dsnLooksShared reports whether a resolved lib/pq DSN appears to target the
// SHARED production lock server rather than an ephemeral throwaway. The
// throwaway DSNs this file mints connect over a unix-socket directory
// (host=<filesystem path>) to dbname=landq_ephemeral; the production server is
// the SSH-tunnel TCP endpoint 127.0.0.1:5433 with dbname=taskdb (lockserver.json).
// We flag a DSN as shared if it both names the production database and reaches it
// over the production TCP tunnel endpoint — a conservative match that never trips
// on the auto-spun unix-socket throwaway, while a caller-provided ephemeral DSN
// on its own host/db is likewise unaffected.
func dsnLooksShared(dsn string) bool {
	d := strings.ToLower(dsn)
	hasProdDB := strings.Contains(d, "dbname='taskdb'") || strings.Contains(d, "dbname=taskdb")
	hasProdHost := strings.Contains(d, "host='127.0.0.1'") || strings.Contains(d, "host=127.0.0.1")
	hasProdPort := strings.Contains(d, "port=5433")
	return hasProdDB && hasProdHost && hasProdPort
}

// provisionEphemeralPG returns a DSN for a throwaway Postgres, fataling on any
// failure (the operator explicitly opted into the ephemeral path). Source order:
// a caller-provided DSN (DS_LANDQ_EPHEMERAL_DSN), else an auto-spun cluster.
func provisionEphemeralPG(t *testing.T) string {
	t.Helper()

	if dsn := strings.TrimSpace(os.Getenv(ephemeralDSNEnv)); dsn != "" {
		// Caller owns the lifecycle; we only verify reachability so the *Live
		// assertions don't fail with a confusing connect error mid-test.
		if err := pingDSN(dsn, 10*time.Second); err != nil {
			t.Fatalf("%s is set but unreachable: %v", ephemeralDSNEnv, err)
		}
		return dsn
	}

	dsn, err := autoSpinEphemeralPG(t)
	if err != nil {
		t.Fatalf("%s=1 but could not provision a throwaway Postgres: %v\n"+
			"  ⇒ install Postgres (initdb/pg_ctl on PATH or under %s),\n"+
			"  ⇒ OR provide a ready ephemeral DSN via %s (e.g. a docker `postgres` you tear down).",
			ephemeralGateEnv, err, pgBinDirEnv, ephemeralDSNEnv)
	}
	return dsn
}

// pingDSN opens and pings a lib/pq DSN within a bounded timeout, then closes.
func pingDSN(dsn string, timeout time.Duration) error {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return db.PingContext(ctx)
}

// autoSpinEphemeralPG brings up a private throwaway Postgres cluster for the test
// process using the host's own initdb/pg_ctl binaries (the embedded-pg pattern
// with no Go dependency), and returns a DSN for a fresh database on it. The
// cluster is memoized for the package (one per run) and torn down via t.Cleanup
// on the first gated test that spins it. It listens ONLY on a private unix socket
// in the data dir (listen_addresses=”), so nothing leaks onto a TCP port.
func autoSpinEphemeralPG(t *testing.T) (string, error) {
	t.Helper()
	ephemeralOnce.Do(func() { ephemeralDSN, ephemeralErr = startEphemeralCluster(t) })
	return ephemeralDSN, ephemeralErr
}

// startEphemeralCluster does the real work behind autoSpinEphemeralPG's once.
func startEphemeralCluster(t *testing.T) (string, error) {
	t.Helper()

	initdb, err := findPGBinary("initdb")
	if err != nil {
		return "", err
	}
	pgctl, err := findPGBinary("pg_ctl")
	if err != nil {
		return "", err
	}

	// A throwaway cluster lives under the test's TempDir, which the test framework
	// removes after the run. We additionally pg_ctl stop it so the postmaster does
	// not outlive the process.
	base := t.TempDir()
	dataDir := filepath.Join(base, "pgdata")
	// The unix socket dir must be SHORT (sun_path is ~107 bytes) and writable; the
	// data dir itself is a safe, private choice that initdb already permits.
	sockDir := dataDir

	const user = "landq"
	const dbname = "landq_ephemeral"

	pwFile := filepath.Join(base, "pw")
	if err := os.WriteFile(pwFile, []byte("landq"), 0o600); err != nil {
		return "", fmt.Errorf("write pw file: %w", err)
	}

	// initdb: trust auth on the local socket is fine for a private throwaway, but
	// we set a superuser to keep the DSN explicit and portable.
	initArgs := []string{
		"-D", dataDir,
		"-U", user,
		"-A", "trust",
		"--no-sync", // throwaway: durability is irrelevant, this is much faster
		"--pwfile", pwFile,
	}
	if out, err := runPGCmd(initdb, initArgs, 90*time.Second); err != nil {
		return "", fmt.Errorf("initdb failed: %v\n%s", err, out)
	}

	// Start the postmaster on a private unix socket only (no TCP). pg_ctl -w waits
	// for it to accept connections before returning.
	startArgs := []string{
		"-D", dataDir,
		"-w",
		"-o", fmt.Sprintf("-k %s -c listen_addresses='' -c fsync=off -c full_page_writes=off -c synchronous_commit=off", sockDir),
		"start",
	}
	if out, err := runPGCmd(pgctl, startArgs, 90*time.Second); err != nil {
		return "", fmt.Errorf("pg_ctl start failed: %v\n%s", err, out)
	}

	// Stop the cluster when the spinning test's cleanups run; -m immediate is fine
	// for a throwaway and is the fastest shutdown.
	t.Cleanup(func() {
		_, _ = runPGCmd(pgctl, []string{"-D", dataDir, "-m", "immediate", "-w", "stop"}, 30*time.Second)
	})

	// Connect to the bootstrap "postgres"/template via the socket and create the
	// dedicated throwaway database. host=<sockDir> tells lib/pq to use the unix
	// socket directory.
	adminDSN := fmt.Sprintf("host=%s port=5432 user=%s dbname=postgres sslmode=disable connect_timeout=10", sockDir, user)
	admin, err := sql.Open("postgres", adminDSN)
	if err != nil {
		return "", fmt.Errorf("open admin conn: %w", err)
	}
	defer admin.Close()
	if err := waitReady(admin, 30*time.Second); err != nil {
		return "", fmt.Errorf("cluster never became ready: %w", err)
	}
	if _, err := admin.Exec("CREATE DATABASE " + dbname); err != nil {
		// A leftover from a prior aborted run in the SAME tempdir is impossible
		// (fresh TempDir each run), so any error here is genuine.
		return "", fmt.Errorf("create database %q: %w", dbname, err)
	}

	dsn := fmt.Sprintf("host=%s port=5432 user=%s dbname=%s sslmode=disable connect_timeout=10", sockDir, user, dbname)
	if err := pingDSN(dsn, 10*time.Second); err != nil {
		return "", fmt.Errorf("ping throwaway db: %w", err)
	}
	return dsn, nil
}

// findPGBinary locates a Postgres binary: PG_BINDIR/<name> if PG_BINDIR is set,
// else <name> on PATH.
func findPGBinary(name string) (string, error) {
	if dir := strings.TrimSpace(os.Getenv(pgBinDirEnv)); dir != "" {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("%s set to %q but %s not found there", pgBinDirEnv, dir, name)
	}
	p, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s not on PATH (set %s to the Postgres bin dir): %w", name, pgBinDirEnv, err)
	}
	return p, nil
}

// runPGCmd runs a Postgres tool with a timeout, returning combined output for
// diagnostics. PGDATA-style tools are noisy; we capture everything.
func runPGCmd(bin string, args []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// waitReady polls until the cluster accepts a trivial query or the deadline
// passes. pg_ctl -w already waits for socket readiness, but a follow-up SELECT
// confirms the connection is genuinely usable.
func waitReady(db *sql.DB, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, lastErr = db.ExecContext(ctx, "SELECT 1")
		cancel()
		if lastErr == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timed out after %s", timeout)
	}
	return lastErr
}
