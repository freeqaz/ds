// SPDX-License-Identifier: Apache-2.0

// Package storetest is the single-source test-support seam for the live-Postgres
// open-or-skip dance the store / sessions conformance suites share. After wave-1
// there were FOUR near-identical re-implementations of the same sql.Open +
// PingContext + Skip-on-unreachable gate (openPostgresOrSkip @ store/inventory_test.go,
// openSessionsPostgresOrSkip @ sessions/parkresume_postgres_test.go,
// openOrchPostgresOrSkip @ store/postgres_open_conformance_test.go, and the inline
// copy in TestLiveDenyMemos_Postgres @ store/denymemo_test.go), so a gate-plumbing
// change (driver fallback name, ping timeout, skip-message wording) had to be made in
// four places or it drifted. This package exports ONE opener every caller delegates to.
//
// It is TEST-SUPPORT (imported only by _test.go files), stdlib-only (database/sql,
// os, testing, context, time), and SYNTHETIC-only (D50): it dials nothing of its own,
// reads only the caller-named DSN env var, and SKIPS — never fails — when the env is
// unset, the driver is unregistered, or the database is unreachable, so the default
// `go test ./...` run is unaffected and a live run stays a deferred manual step.
//
// Each caller keeps its OWN env var (DS_PG_DSN vs DS_ORCH_PG_DSN), its OWN default
// driver-env var (DS_PG_DRIVER vs DS_ORCH_PG_DRIVER), and its OWN three skip-message
// strings (passed via SkipMessages), so the observable skip/run behavior is
// byte-identical to each caller's prior hand-rolled dance. The shared part is the
// mechanism: read DSN → (skip if unset) → resolve driver (default "postgres") →
// sql.Open → (skip on err) → t.Cleanup(db.Close) → PingContext(5s) → (skip on err).
package storetest

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

// DefaultDriver is the conventional Postgres driver name a caller falls back to when
// its driver-env var is unset (the operator registers a driver under this name at the
// binary boundary, D33). It is the same default all four prior hand-rolled openers used.
const DefaultDriver = "postgres"

// pingTimeout is the dial budget for the liveness probe — the same 5s every prior
// hand-rolled opener used, single-sourced here so a timeout change lands once.
const pingTimeout = 5 * time.Second

// SkipMessages carries a caller's three exact skip-message contracts so OpenOrSkip
// reproduces each caller's prior wording byte-for-byte. The format strings keep the
// verb shapes the callers used:
//
//   - Unset    is a plain t.Skip string (no format verbs): logged when the DSN env
//     var is unset.
//   - OpenErr  is a t.Skipf format with verbs (%q, %v): the driver name then the
//     sql.Open error — e.g. "sql.Open(%q): %v — register a Postgres driver ...".
//   - PingErr  is a t.Skipf format with verbs (%s, %v): the driver name then the
//     PingContext error — e.g. "ping %s: %v — Postgres unreachable; deferred ...".
type SkipMessages struct {
	Unset   string // t.Skip when the DSN env var is unset (no format verbs)
	OpenErr string // t.Skipf(OpenErr, driver, err) when sql.Open fails
	PingErr string // t.Skipf(PingErr, driver, err) when PingContext fails
}

// OpenOrSkip is the single source of the live-Postgres open-or-skip dance the store /
// sessions conformance suites share. It reads the DSN from envVar, resolves the driver
// name from driverEnvVar (defaulting to DefaultDriver), sql.Open's the pool, registers
// t.Cleanup(db.Close), and PingContext(5s)-probes liveness. It SKIPS — never fails —
// when the env is unset, the driver is unregistered, or the database is unreachable,
// using the caller's own SkipMessages so each caller's skip wording is byte-identical
// to its prior hand-rolled opener.
//
// Callers that need typed wrapping (e.g. store.NewPostgresClock, the per-test truncate)
// do that on the returned *sql.DB at the call site — this helper owns only the shared
// open/ping/skip mechanism, never the post-open steps.
func OpenOrSkip(t *testing.T, envVar, driverEnvVar string, msg SkipMessages) *sql.DB {
	t.Helper()
	dsn := os.Getenv(envVar)
	if dsn == "" {
		t.Skip(msg.Unset)
	}
	driver := os.Getenv(driverEnvVar)
	if driver == "" {
		driver = DefaultDriver
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Skipf(msg.OpenErr, driver, err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf(msg.PingErr, driver, err)
	}
	return db
}
