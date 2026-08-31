// SPDX-License-Identifier: Apache-2.0

package storetest

import (
	"testing"
)

// TestDSNOrSkip_ReturnsDSNWhenSet proves the set-path: with the env var present,
// DSNOrSkip returns the DSN verbatim and does NOT skip the (sub)test. The env var
// name is unique to this test so it never collides with a live DS_PG_DSN / DS_ORCH_PG_DSN
// an operator may have exported (D50: this self-test dials nothing — a string round-trip).
func TestDSNOrSkip_ReturnsDSNWhenSet(t *testing.T) {
	const env = "DS_STORETEST_DSNORSKIP_SELFTEST_SET"
	const want = "postgres://synthetic/selftest?sslmode=disable"
	t.Setenv(env, want)

	if got := DSNOrSkip(t, env, "unset message that must not fire"); got != want {
		t.Fatalf("DSNOrSkip returned %q, want the verbatim DSN %q", got, want)
	}
	if t.Skipped() {
		t.Fatalf("DSNOrSkip skipped the test even though %s was set", env)
	}
}

// TestDSNOrSkip_SkipsWhenUnset proves the unset-path WITHOUT aborting this test: it runs
// DSNOrSkip in a child *testing.T (via t.Run) and asserts the child SKIPPED. A direct call
// would call runtime.Goexit on the calling goroutine (t.Skip), so the subtest isolates it.
// The env var is unique and explicitly cleared so the unset branch is exercised regardless
// of the ambient environment.
//
// t.Run reports the subtest OUTCOME: it returns true when the child does not FAIL (a skip
// counts as not-failed) and false when the child fails. So if DSNOrSkip correctly skipped,
// the child never reached the unreachable ct.Fatal and t.Run returns true; if DSNOrSkip
// failed to skip, the child hit ct.Fatal and t.Run returns false. We also assert the child
// observed itself as Skipped() from inside, pinning a SKIP (not merely a non-failure).
func TestDSNOrSkip_SkipsWhenUnset(t *testing.T) {
	const env = "DS_STORETEST_DSNORSKIP_SELFTEST_UNSET"
	t.Setenv(env, "") // guarantee the unset branch even if the ambient env carries it

	ok := t.Run("child", func(ct *testing.T) {
		_ = DSNOrSkip(ct, env, "DSN unset: skipping (deferred manual step)")
		// Unreachable when DSNOrSkip skips (t.Skip calls runtime.Goexit); reaching here
		// means it returned a DSN for an unset env — a contract violation.
		ct.Fatalf("DSNOrSkip returned without skipping when %s was unset", env)
	})
	if !ok {
		t.Fatalf("expected the child subtest to SKIP via DSNOrSkip (env %s unset), but it failed", env)
	}
}
