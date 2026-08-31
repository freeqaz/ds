// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"os"
	"regexp"
	"testing"
)

// MigrationNamePattern is the orchestrator/migrations apply-ordering convention's
// regexp: a zero-padded 4-digit sequence prefix, an underscore, a lower-snake name,
// and the .sql suffix (NNNN_name.sql). The zero-padding is what makes LEXICAL
// filename order == NUMERIC apply order.
//
// SINGLE SOURCE. This pattern used to be mirrored verbatim as three separate
// unexported copies (orchestrator/migrations/apply_smoke_test.go: migrationName;
// orchestrator/internal/store/postgres_open_conformance_test.go:
// orchPGMigrationName; orchestrator/internal/policylog/askrouting_test.go:
// policylogMigrationName) because those test-only packages shared no importable
// home. internal/storetest is that home — the migrations, store, and policylog
// suites already import it for OpenOrSkip/DSNOrSkip — so this is now the ONE
// place the literal is written; every caller imports this symbol instead of
// mirroring the pattern.
//
// It is TEST-SUPPORT (imported only by _test.go files today), stdlib-only
// (regexp), and SYNTHETIC-only (D50): it dials nothing and reads nothing, it only
// classifies filenames.
var MigrationNamePattern = regexp.MustCompile(`^([0-9]{4})_[a-z0-9_]+\.sql$`)

// DSNOrSkip is the env-read + Skip-on-unset HALF of the open-or-skip dance, for the
// callers that cannot delegate the open to OpenOrSkip because a typed constructor owns
// the sql.Open themselves (e.g. controlplane.NewPostgresStore, which does its own
// sql.Open + store.NewPostgres internally and returns the typed *PostgresStore + a
// closer). Those callers still share the SAME first two steps — read the DSN env var,
// and SKIP (never fail) when it is unset — so this exports just that shared prefix:
// it reads envVar and t.Skip(unsetMsg)'s with the caller's own wording when the DSN is
// empty, otherwise returns the DSN string for the caller to hand to its own constructor.
//
// It is TEST-SUPPORT (imported only by _test.go files), stdlib-only (os, testing), and
// SYNTHETIC-only (D50): it dials nothing, reads only the caller-named DSN env var, and
// SKIPS — never fails — when the env is unset, so the default `go test ./...` run is
// unaffected and a live run stays a deferred manual step. The caller keeps its OWN env
// var name and its OWN unset skip wording (passed via unsetMsg, byte-identical to its
// prior hand-rolled dance); the constructor it then drives keeps its OWN open/skip.
func DSNOrSkip(t *testing.T, envVar, unsetMsg string) string {
	t.Helper()
	dsn := os.Getenv(envVar)
	if dsn == "" {
		t.Skip(unsetMsg)
	}
	return dsn
}
