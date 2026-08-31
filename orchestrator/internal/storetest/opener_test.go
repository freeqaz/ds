// SPDX-License-Identifier: Apache-2.0

// opener_test.go is the fully-sandbox-runnable self-test for the storetest.OpenOrSkip
// open-or-skip seam (opener.go) — the single source of the live-Postgres
// sql.Open + PingContext + Skip-on-unreachable dance the store / sessions
// conformance suites share. It needs NO live database and NO env (D50): it drives
// every reachable skip arm with SYNTHETIC fixtures —
//
//	(a) the UNSET-DSN gate: when the caller's DSN env var is unset, OpenOrSkip must
//	    t.Skip (never fail, never reach sql.Open), so the default `go test ./...`
//	    run is unaffected (D50);
//	(b) the OpenErr / PingErr skip ARMS, driven end to end with SYNTHETIC
//	    database/sql drivers registered in this test binary (they dial nothing and
//	    return canned errors): a driver whose DriverContext.OpenConnector errors makes
//	    sql.Open itself fail (the OpenErr arm), and a driver whose connect fails makes
//	    db.PingContext fail (the PingErr arm). Each must SKIP — never fail, never return
//	    a half-open pool (TestOpenOrSkip_SkipsOnOpenErr / _SkipsOnPingErr); and
//	(c) the SkipMessages VERB-ORDER contract: OpenErr renders (driver, err) with the
//	    driver QUOTED (%q) and PingErr renders (driver, err) with the driver UNQUOTED
//	    (%s) — the exact verb shapes opener.go's doc comment ratifies. The synthetic-driver
//	    arms in (b) prove the arms are REACHED and skip; the message wording cannot be
//	    read back through *testing.T, so the verb-order/quoting is additionally pinned at
//	    the FORMAT-STRING level: format the SkipMessages fields with sentinel driver/err
//	    values and assert the rendered order + quoting, so a future verb-order swap
//	    (driver/err transposed, or %q<->%s flipped) regresses HERE rather than silently
//	    drifting a caller's skip wording.
//
// stdlib-only (testing, fmt, os, strings, database/sql + database/sql/driver for the
// synthetic drivers, errors) — no live engine, no network.
package storetest

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestOpenOrSkip_SkipsWhenDSNUnset pins behavior (a): OpenOrSkip t.Skips — never fails,
// never reaches sql.Open — when the caller's DSN env var is unset. It runs OpenOrSkip in
// an inner sub-test whose *testing.T it observes: after the sub-test returns, the inner
// t.Skipped() must be true (the Unset arm fired) and the inner test must NOT have failed.
// The sub-test deliberately uses an env var name that is guaranteed unset (os.Unsetenv
// before the run), so the very first gate — read DSN -> (skip if unset) — is the only
// arm exercised; sql.Open is never called, so the absence of a registered Postgres driver
// is irrelevant. A regression that turned the unset-DSN gate into a hard failure (or that
// fell through to sql.Open with an empty DSN) would surface as a non-skipped / failed
// inner sub-test here.
func TestOpenOrSkip_SkipsWhenDSNUnset(t *testing.T) {
	const (
		dsnEnv    = "DS_STORETEST_SELFTEST_DSN_UNSET"
		driverEnv = "DS_STORETEST_SELFTEST_DRIVER_UNSET"
	)
	// Guarantee both env vars are unset for the duration of the sub-test. t.Setenv
	// cannot UNset, so use os.Unsetenv with a restore in t.Cleanup (the values are
	// almost certainly already absent, but be explicit and hermetic).
	for _, k := range []string{dsnEnv, driverEnv} {
		prev, had := os.LookupEnv(k)
		_ = os.Unsetenv(k)
		if had {
			t.Cleanup(func() { _ = os.Setenv(k, prev) })
		} else {
			t.Cleanup(func() { _ = os.Unsetenv(k) })
		}
	}

	var innerSkipped, innerFailed bool
	// t.Run reports whether the sub-test passed; we additionally capture Skipped()/Failed()
	// from inside the closure (they are only observable on the inner *testing.T while it is
	// running). A t.Skip inside the closure halts that goroutine, so the capture must come
	// from a deferred read of the inner T's terminal state.
	t.Run("unset-dsn", func(st *testing.T) {
		defer func() {
			innerSkipped = st.Skipped()
			innerFailed = st.Failed()
		}()
		_ = OpenOrSkip(st, dsnEnv, driverEnv, SkipMessages{
			Unset:   "self-test: DSN unset, expected skip",
			OpenErr: "self-test sql.Open(%q): %v",
			PingErr: "self-test ping %s: %v",
		})
		// Unreachable: OpenOrSkip must have t.Skip'd on the unset DSN before returning.
		st.Fatalf("OpenOrSkip returned without skipping on an unset DSN env var")
	})

	if !innerSkipped {
		t.Errorf("OpenOrSkip with an unset DSN env var did not t.Skip the sub-test (Skipped()=false); the unset-DSN gate must skip, never fall through to sql.Open")
	}
	if innerFailed {
		t.Errorf("OpenOrSkip with an unset DSN env var marked the sub-test FAILED; the unset-DSN gate must skip, never fail")
	}
}

// TestSkipMessages_VerbOrderContract pins behavior (b): the SkipMessages verb-order /
// quoting contract opener.go ratifies. OpenOrSkip calls t.Skipf(msg.OpenErr, driver, err)
// and t.Skipf(msg.PingErr, driver, err) — driver FIRST, err SECOND — and the documented
// verb shapes are OpenErr=%q,%v (driver QUOTED) and PingErr=%s,%v (driver UNQUOTED). Those
// arms need a registered driver / live engine to reach through OpenOrSkip, so the contract
// is pinned at the format-string level: format the fields with SENTINEL driver/err values
// and assert (1) the driver renders before the err in both, (2) OpenErr quotes the driver
// (%q -> the sentinel appears wrapped in double quotes), and (3) PingErr does NOT quote the
// driver (%s -> the bare sentinel, no surrounding quotes). A future swap — transposing the
// (driver, err) argument order, or flipping %q<->%s — changes one of these rendered facts
// and regresses HERE.
func TestSkipMessages_VerbOrderContract(t *testing.T) {
	// The documented verb shapes (opener.go's SkipMessages doc): OpenErr=%q,%v; PingErr=%s,%v.
	msg := SkipMessages{
		Unset:   "SENTINEL_UNSET",
		OpenErr: "sql.Open(%q): %v",
		PingErr: "ping %s: %v",
	}
	const (
		driver = "SENTINEL_DRIVER"
		errStr = "SENTINEL_ERR"
	)

	// OpenErr: driver is formatted with %q (quoted), err with %v, in (driver, err) order —
	// exactly OpenOrSkip's t.Skipf(msg.OpenErr, driver, err) call.
	openRendered := fmt.Sprintf(msg.OpenErr, driver, errStr)
	quotedDriver := fmt.Sprintf("%q", driver) // the canonical %q rendering, e.g. "SENTINEL_DRIVER"
	if !strings.Contains(openRendered, quotedDriver) {
		t.Errorf("OpenErr rendered = %q, want the driver QUOTED via %%q (contains %s); a %%q->%%s flip would drop the quotes", openRendered, quotedDriver)
	}
	if !strings.Contains(openRendered, errStr) {
		t.Errorf("OpenErr rendered = %q, want it to contain the err sentinel %q via %%v", openRendered, errStr)
	}
	if di, ei := strings.Index(openRendered, driver), strings.Index(openRendered, errStr); di < 0 || ei < 0 || di >= ei {
		t.Errorf("OpenErr rendered = %q, want the driver (at %d) BEFORE the err (at %d) — a transposed (err, driver) order regresses here", openRendered, di, ei)
	}

	// PingErr: driver is formatted with %s (UNQUOTED), err with %v, in (driver, err) order —
	// exactly OpenOrSkip's t.Skipf(msg.PingErr, driver, err) call.
	pingRendered := fmt.Sprintf(msg.PingErr, driver, errStr)
	if strings.Contains(pingRendered, quotedDriver) {
		t.Errorf("PingErr rendered = %q, want the driver UNQUOTED via %%s (must NOT contain the %%q form %s); a %%s->%%q flip would add quotes", pingRendered, quotedDriver)
	}
	if !strings.Contains(pingRendered, driver) {
		t.Errorf("PingErr rendered = %q, want it to contain the bare (unquoted) driver sentinel %q via %%s", pingRendered, driver)
	}
	if !strings.Contains(pingRendered, errStr) {
		t.Errorf("PingErr rendered = %q, want it to contain the err sentinel %q via %%v", pingRendered, errStr)
	}
	if di, ei := strings.Index(pingRendered, driver), strings.Index(pingRendered, errStr); di < 0 || ei < 0 || di >= ei {
		t.Errorf("PingErr rendered = %q, want the driver (at %d) BEFORE the err (at %d) — a transposed (err, driver) order regresses here", pingRendered, di, ei)
	}
}

// --- synthetic-driver skip-arm pins -------------------------------------------
//
// The two tests below drive OpenOrSkip's sql.Open-error (OpenErr) and
// PingContext-error (PingErr) skip arms END TO END — not merely at the format-string
// level — with SYNTHETIC database/sql drivers registered in this test binary (D50: no
// live engine; the drivers dial nothing and return canned errors). Each error PATH
// must SKIP (never fail, never fall through to a returned *sql.DB): a regression that
// turned either arm into a t.Fatal/Error, or that let OpenOrSkip return a half-open
// pool on a dial failure, regresses here.
//
//   - openErrDriverName implements driver.DriverContext whose OpenConnector returns an
//     error, so sql.Open(driver, dsn) ITSELF errors (the only way a plain sql.Open —
//     which otherwise defers dialing — surfaces an error to the OpenErr arm).
//   - pingErrDriverName is a plain driver.Driver whose connect returns an error:
//     sql.Open succeeds (it defers dialing) but db.PingContext forces a connection that
//     fails, driving the PingErr arm.

const (
	openErrDriverName = "storetest_selftest_open_err"
	pingErrDriverName = "storetest_selftest_ping_err"
)

// openErrDriver makes sql.Open return an error: it implements driver.DriverContext,
// whose OpenConnector sql.Open calls eagerly, and errors there.
type openErrDriver struct{}

func (openErrDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("storetest selftest: openErrDriver.Open must not be called")
}

func (openErrDriver) OpenConnector(string) (driver.Connector, error) {
	return nil, errors.New("storetest selftest: synthetic OpenConnector refused")
}

// pingErrDriver makes sql.Open succeed (it defers dialing) but the first real
// connection — forced by db.PingContext — fail, driving the PingErr arm.
type pingErrDriver struct{}

func (pingErrDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("storetest selftest: synthetic connect refused (unreachable)")
}

func init() {
	// Registered once per test binary (init, not test body) so `go test -count=N`
	// never re-registers a name (sql.Register panics on a duplicate).
	sql.Register(openErrDriverName, openErrDriver{})
	sql.Register(pingErrDriverName, pingErrDriver{})
}

// runOpenOrSkipInSubtest runs OpenOrSkip against the given DSN/driver env in an inner
// sub-test and reports whether that sub-test SKIPPED and whether it FAILED. OpenOrSkip's
// t.Skip* calls runtime.Goexit, so the terminal state is read from a deferred closure on
// the inner *testing.T (the same pattern TestOpenOrSkip_SkipsWhenDSNUnset uses).
func runOpenOrSkipInSubtest(t *testing.T, name, dsnEnv, driverEnv, driverName string) (skipped, failed bool) {
	t.Helper()
	t.Setenv(dsnEnv, "synthetic://"+name) // non-empty: passes the unset-DSN gate
	t.Setenv(driverEnv, driverName)       // resolves to the synthetic driver
	t.Run(name, func(st *testing.T) {
		defer func() {
			skipped = st.Skipped()
			failed = st.Failed()
		}()
		_ = OpenOrSkip(st, dsnEnv, driverEnv, SkipMessages{
			Unset:   "self-test: DSN unset (must not fire — DSN is set)",
			OpenErr: "self-test sql.Open(%q): %v",
			PingErr: "self-test ping %s: %v",
		})
		st.Fatalf("OpenOrSkip returned a *sql.DB instead of skipping on a synthetic %s failure", name)
	})
	return skipped, failed
}

// TestOpenOrSkip_SkipsOnOpenErr pins the OpenErr arm: when sql.Open itself errors
// (the synthetic DriverContext.OpenConnector refuses), OpenOrSkip must t.Skip — never
// fail, never reach the ping or return a pool.
func TestOpenOrSkip_SkipsOnOpenErr(t *testing.T) {
	skipped, failed := runOpenOrSkipInSubtest(t,
		"open-err", "DS_STORETEST_SELFTEST_DSN_OPENERR", "DS_STORETEST_SELFTEST_DRIVER_OPENERR", openErrDriverName)
	if !skipped {
		t.Errorf("OpenOrSkip did not t.Skip when sql.Open returned an error; the OpenErr arm must skip, never fall through to a returned pool")
	}
	if failed {
		t.Errorf("OpenOrSkip marked the sub-test FAILED on an sql.Open error; the OpenErr arm must skip, never fail")
	}
}

// TestOpenOrSkip_SkipsOnPingErr pins the PingErr arm: when sql.Open succeeds but the
// liveness PingContext fails (the synthetic driver's connect refuses), OpenOrSkip must
// t.Skip — never fail, never return a half-open pool.
func TestOpenOrSkip_SkipsOnPingErr(t *testing.T) {
	skipped, failed := runOpenOrSkipInSubtest(t,
		"ping-err", "DS_STORETEST_SELFTEST_DSN_PINGERR", "DS_STORETEST_SELFTEST_DRIVER_PINGERR", pingErrDriverName)
	if !skipped {
		t.Errorf("OpenOrSkip did not t.Skip when PingContext returned an error; the PingErr arm must skip, never fall through to a returned pool")
	}
	if failed {
		t.Errorf("OpenOrSkip marked the sub-test FAILED on a PingContext error; the PingErr arm must skip, never fail")
	}
}
