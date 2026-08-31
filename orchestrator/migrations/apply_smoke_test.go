// Package migrations holds the control-plane Postgres schema as raw NNNN_*.sql
// files plus the reference apply runner (apply.sh). There is NO non-test Go in
// this package: the apply helper is the shell script, which lives OUTSIDE the
// orchestrator module's stdlib-only import graph (D6/D33, doc 15 §10 — migration
// tooling is free). This file is the package's ONLY Go and is test-only, so the
// orchestrator build never compiles or imports the helper.
//
// These are NO-DATABASE smoke checks: they assert the apply CONTRACT documented
// in README.md (lexical ordering, the runner's syntax/plan) against the files on
// disk, and run in the normal `go test ./...` pass with no DS_PG_DSN, no psql,
// and no Postgres. Live application stays the env-gated deferred manual step
// (TestPostgres_Conformance in internal/store).
package migrations

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// migrationName is the apply-ordering convention's regexp, single-sourced from
// internal/storetest.MigrationNamePattern (the shared open-or-skip home this
// suite already imports for DSNOrSkip-style helpers): a zero-padded 4-digit
// sequence prefix, an underscore, a lower-snake name, and the .sql suffix. The
// zero-padding is what makes LEXICAL filename order == NUMERIC apply order.
//
// SINGLE-SOURCE CONTRACT. This used to be a per-file mirrored literal; it is now
// the SAME *regexp.Regexp the store suite
// (internal/store/postgres_open_conformance_test.go) and the policylog suite
// (internal/policylog/askrouting_test.go) import, so the accept/reject SEMANTICS
// (pinned here by TestMigrationNamePattern_Contract) cannot diverge across the
// three suites by construction — there is exactly one literal left to edit.
var migrationName = storetest.MigrationNamePattern

// migrationFiles returns the migration filenames (basenames) in lexical order.
func migrationFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if migrationName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // lexical order == apply order
	return names
}

// TestMigrationNamePattern_Contract pins the accept/reject SEMANTICS of
// storetest.MigrationNamePattern so a careless edit to the single-sourced
// pattern regresses here rather than silently letting a non-conforming
// basename in (or excluding a valid one). The SAME table is asserted against
// the store suite's copy of this test
// (TestOrchPGMigrationName_Contract in internal/store/postgres_open_conformance_test.go)
// — both now assert the identical *regexp.Regexp value, so there is nothing
// left to diverge. No DB, no env, no skip — it runs in the default
// `go test ./...` pass.
func TestMigrationNamePattern_Contract(t *testing.T) {
	// ACCEPT: the NNNN_lower_snake.sql convention (zero-padded 4-digit prefix).
	for _, name := range []string{
		"0001_init.sql",
		"0042_add_principal_roles.sql",
		"9999_z.sql",
	} {
		if !migrationName.MatchString(name) {
			t.Errorf("migration-name pattern %q must ACCEPT %q (the NNNN_name.sql convention)", migrationName.String(), name)
		}
	}
	// REJECT: every off-convention shape that would silently break LEXICAL==NUMERIC
	// apply order or admit a stray file.
	for _, name := range []string{
		"001_init.sql",      // 3-digit prefix (padding drift)
		"00001_init.sql",    // 5-digit prefix (padding drift)
		"0001init.sql",      // missing the underscore separator
		"0001_Init.sql",     // uppercase in the name (the class is [a-z0-9_])
		"0001_init.txt",     // wrong extension
		"0001_.sql",         // empty name segment
		"_0001_init.sql",    // leading underscore (no NNNN prefix)
		"0001_init.sql.bak", // trailing suffix past .sql
	} {
		if migrationName.MatchString(name) {
			t.Errorf("migration-name pattern %q must REJECT %q", migrationName.String(), name)
		}
	}
}

// TestApplyOrderingIsLexicalAndDense asserts the ordering posture from the
// README: files apply in lexical filename order, and the zero-padded sequence
// prefixes are dense and unique starting at 0001 — so "lexical" is unambiguous
// and no gap hides a dropped migration.
func TestApplyOrderingIsLexicalAndDense(t *testing.T) {
	names := migrationFiles(t)
	if len(names) == 0 {
		t.Fatal("no NNNN_*.sql migrations found; the schema set must not be empty")
	}

	var seqs []int
	for _, n := range names {
		m := migrationName.FindStringSubmatch(n)
		if m == nil {
			t.Fatalf("migration %q does not match the NNNN_name.sql convention", n)
		}
		seq, err := strconv.Atoi(m[1])
		if err != nil {
			t.Fatalf("migration %q has a non-numeric sequence prefix: %v", n, err)
		}
		seqs = append(seqs, seq)
	}

	// Lexical order (how the shell glob and the runner enumerate) must equal
	// numeric order; with zero-padded prefixes the two coincide, which is the
	// property the apply contract relies on.
	if !sort.IntsAreSorted(seqs) {
		t.Fatalf("lexical filename order does not match numeric sequence order: %v -> %v", names, seqs)
	}
	for i, seq := range seqs {
		if want := i + 1; seq != want {
			t.Fatalf("migration sequences must be dense from 0001: got %v, gap/dup at position %d (have %04d, want %04d)", seqs, i, seq, want)
		}
	}
}

// TestMigration0007And0008CoLand enforces the principal-roles ↔ context-store
// merge group: migrations 0007 (principal-roles) and 0008 (session-context) must
// be BOTH PRESENT or BOTH ABSENT on disk, never exactly one. This is the
// mechanical RED gate behind the co-land coordination note in README.md ("Merge
// group: 0007↔0008 co-land").
//
// WHY this shape, not an ordering assert. 0008 lands on the 0007 schema (the
// session-context store references the principal-roles rows it attributes to);
// a tree that carries 0008 without 0007 is a broken cherry-pick. The
// dense-from-0001 invariant in TestApplyOrderingIsLexicalAndDense ALREADY fails
// such a tree (0008 present, 0007 absent ⇒ a gap at 0007), as verified
// empirically. This test makes the SAME failure explicit and named at the
// migration-pair level, and additionally catches the mirror gap (0007 present,
// 0008 absent) — which is allowed by dense-ordering (0007 is then the dense
// tail) but is still a half-landed merge group.
//
// It is co-presence, not co-presence-implies-anything-else: enumerate the
// migrations dir by FILENAME (it imports neither .sql), so it is green once both
// wave-1 migrations are present in the merged integration tree (and green in the
// pre-merge base where both are absent), and RED for any cherry-pick that drops
// exactly one. The fixed expected names are the owner-landed filenames from the
// two wave-1 units; this test never edits or reads their contents.
func TestMigration0007And0008CoLand(t *testing.T) {
	const (
		principalRoles = "0007_principal_roles.sql" // principal-roles unit (01KTWJ3SDR4ZNZXS4N2JVXJQ68)
		sessionContext = "0008_session_context.sql" // context-store unit (01KTWJ3REG6CRPNBS6KVJ77Z87)
	)

	present := make(map[string]bool, 2)
	for _, n := range migrationFiles(t) {
		if n == principalRoles || n == sessionContext {
			present[n] = true
		}
	}

	have0007, have0008 := present[principalRoles], present[sessionContext]
	if have0007 == have0008 {
		return // both present (merged tree) or both absent (pre-merge base): co-land holds.
	}

	// Exactly one is present: a half-landed merge group. Name which leg is
	// missing so a dropped-migration cherry-pick fails loud and self-explaining.
	switch {
	case have0008 && !have0007:
		t.Fatalf("co-land violation: %s is present but %s is missing — 0008 (context-store) "+
			"must not land without 0007 (principal-roles); see README.md \"Merge group: 0007↔0008 co-land\". "+
			"This is the same dense-ordering gap-at-0007 that TestApplyOrderingIsLexicalAndDense fails on.",
			sessionContext, principalRoles)
	default: // have0007 && !have0008
		t.Fatalf("co-land violation: %s is present but %s is missing — the 0007↔0008 merge group "+
			"is half-landed (principal-roles without context-store); see README.md "+
			"\"Merge group: 0007↔0008 co-land\".",
			principalRoles, sessionContext)
	}
}

// TestApplyRunnerSyntax runs `sh -n apply.sh`: a no-database syntax check of the
// reference runner. The test EXEC's the shell — it does not (and cannot) import
// the helper into the Go build, keeping the module's import graph stdlib-only.
func TestApplyRunnerSyntax(t *testing.T) {
	const runner = "apply.sh"
	if _, err := os.Stat(runner); err != nil {
		t.Fatalf("reference runner %s missing: %v", runner, err)
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no POSIX sh on PATH: %v (syntax check is a host capability, not a unit gate)", err)
	}
	out, err := exec.Command(sh, "-n", runner).CombinedOutput()
	if err != nil {
		t.Fatalf("sh -n %s failed: %v\n%s", runner, err, out)
	}
}

// TestApplyRunnerDryRunPlan runs `DRY_RUN=1 apply.sh` and asserts it prints the
// migration set in lexical order, touching no database (DS_PG_DSN unset). This
// pins the runner's enumeration to the same order this package's tests assert,
// so the script and the documented contract cannot drift apart.
func TestApplyRunnerDryRunPlan(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("no POSIX sh on PATH: %v", err)
	}
	cmd := exec.Command(sh, "apply.sh")
	// Explicitly DRY_RUN with NO DS_PG_DSN: proves the runner never reaches psql.
	cmd.Env = append(os.Environ(), "DRY_RUN=1")
	cmd.Env = filterEnv(cmd.Env, "DS_PG_DSN")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("DRY_RUN=1 apply.sh failed: %v\n%s", err, out)
	}

	want := migrationFiles(t)
	plan := extractPlan(string(out))
	if len(plan) != len(want) {
		t.Fatalf("dry-run plan has %d entries, want %d\nplan: %v\nfiles: %v", len(plan), len(want), plan, want)
	}
	for i := range want {
		if filepath.Base(plan[i]) != want[i] {
			t.Fatalf("dry-run plan order mismatch at %d: runner says %q, lexical files say %q\nfull plan: %v", i, plan[i], want[i], plan)
		}
	}
}

// extractPlan pulls the indented "  NNNN_*.sql" lines from the dry-run output.
func extractPlan(out string) []string {
	var got []string
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if migrationName.MatchString(trimmed) {
			got = append(got, trimmed)
		}
	}
	return got
}

// filterEnv drops every "<drop>=..." entry so the dry-run runs with DS_PG_DSN
// explicitly unset, proving the no-database path never reaches psql.
func filterEnv(env []string, drop string) []string {
	prefix := drop + "="
	kept := env[:0:0]
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			continue
		}
		kept = append(kept, kv)
	}
	return kept
}
