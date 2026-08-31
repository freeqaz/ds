// SPDX-License-Identifier: Apache-2.0

// ambient_linux_test.go pins the three load-bearing properties of the ONE
// capability-mutating primitive in the helper (ambient_linux.go), all in the
// DEFAULT cgo-free build (the bracket carries no build tag, only the filename's
// implicit `linux` constraint):
//
//  1. FAIL CLOSED — a failed PR_CAP_AMBIENT_RAISE must refuse the privileged
//     call outright, never run the backend with children that would be stranded
//     unprivileged.
//  2. The ROOT SKIP decision (euid 0 ⇒ no raise; nonzero ⇒ raise) — the rule the
//     `unshare -rn` rehearsal depends on, where a fresh userns has an EMPTY
//     inheritable set and the raise itself is impossible.
//  3. The LOWER is best-effort — a failing lower must never mask (or
//     manufacture) the backend's own result.

package main

import (
	"errors"
	"os"
	"testing"
)

// TestWithAmbientNetAdminFailsClosedWhenRaiseImpossible exercises the REAL
// kernel path as an unprivileged uid: PR_CAP_AMBIENT_RAISE(CAP_NET_ADMIN) fails
// (CAP_NET_ADMIN is neither permitted nor inheritable for an ordinary process),
// and the wrapped backend must PROVABLY never be invoked.
func TestWithAmbientNetAdminFailsClosedWhenRaiseImpossible(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("euid 0: the bracket skips the raise entirely (root children inherit via the kernel's root rule)")
	}
	if probeCaps().AmbientRaiseOK {
		t.Skip("this process CAN raise CAP_NET_ADMIN into the ambient set (cap_net_admin+eip is armed here); the fail-closed leg is unreachable")
	}

	invoked := false
	err := withAmbientNetAdmin(func() error {
		invoked = true
		return nil
	})
	if err == nil {
		t.Fatal("withAmbientNetAdmin returned nil despite an impossible ambient raise; the bracket MUST fail closed")
	}
	if invoked {
		t.Error("the backend ran after a FAILED ambient raise: its ip/nft children would be stranded unprivileged (fail-closed violated)")
	}
	if !containsAll(err.Error(), "PR_CAP_AMBIENT_RAISE", "cap_net_admin+eip") {
		t.Errorf("raise failure must carry the setcap remediation, got %q", err)
	}
}

// TestWithAmbientNetAdminFailsClosedInjected is the deterministic twin of the
// above (no dependence on this host's capability posture): a raise that errors
// must refuse before f, and the lower must NOT be attempted for a window that
// was never opened.
func TestWithAmbientNetAdminFailsClosedInjected(t *testing.T) {
	raiseErr := errors.New("synthetic EPERM")
	var ops []uintptr
	invoked := false

	err := withAmbientNetAdminUsing(1000, func(op, capBit uintptr) error {
		ops = append(ops, op)
		if capBit != capNetAdminBit {
			t.Errorf("bracket raised capability bit %d, want CAP_NET_ADMIN (%d)", capBit, capNetAdminBit)
		}
		return raiseErr
	}, func() error {
		invoked = true
		return nil
	})

	if !errors.Is(err, raiseErr) {
		t.Fatalf("raise failure must be wrapped and returned, got %v", err)
	}
	if invoked {
		t.Error("backend invoked after a failed raise (fail-closed violated)")
	}
	if len(ops) != 1 || ops[0] != prCapAmbientRaise {
		t.Errorf("prctl sequence = %v, want exactly one RAISE (%d) and no LOWER", ops, prCapAmbientRaise)
	}
}

// TestAmbientRaiseNeededDecision pins the root-skip rule as a table: euid 0 is
// the ONLY case that skips the raise.
func TestAmbientRaiseNeededDecision(t *testing.T) {
	tests := []struct {
		name string
		euid int
		want bool
	}{
		{name: "root skips the raise (children inherit via the kernel root rule; a fresh userns cannot raise)", euid: 0, want: false},
		{name: "the dogfood agent uid raises", euid: 1000, want: true},
		{name: "any other nonzero uid raises", euid: 65534, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ambientRaiseNeeded(tc.euid); got != tc.want {
				t.Errorf("ambientRaiseNeeded(%d) = %v, want %v", tc.euid, got, tc.want)
			}
		})
	}
}

// TestAmbientRaiseSkippedForRootNeverPrctls proves the euid-0 leg touches NO
// capability state at all — the rehearsal (netns-validate.sh part D, uid 0
// in-ns) depends on the bracket not attempting an impossible raise.
func TestAmbientRaiseSkippedForRootNeverPrctls(t *testing.T) {
	invoked := false
	err := withAmbientNetAdminUsing(0, func(op, _ uintptr) error {
		t.Errorf("euid 0 must issue NO prctl, got op %d", op)
		return nil
	}, func() error {
		invoked = true
		return nil
	})
	if err != nil {
		t.Fatalf("root path should pass the backend result through, got %v", err)
	}
	if !invoked {
		t.Error("root path must still invoke the backend")
	}
}

// TestAmbientLowerIsBestEffortAfterBackend: a LOWER that fails must never mask
// the backend's own result — neither by turning a success into an error nor by
// replacing a backend error.
func TestAmbientLowerIsBestEffortAfterBackend(t *testing.T) {
	backendErr := errors.New("ds-nft flush_session failed")
	lowerErr := errors.New("synthetic lower failure")

	prctl := func(op, _ uintptr) error {
		if op == prCapAmbientLower {
			return lowerErr
		}
		return nil
	}

	t.Run("backend success survives a failing lower", func(t *testing.T) {
		if err := withAmbientNetAdminUsing(1000, prctl, func() error { return nil }); err != nil {
			t.Errorf("a failing LOWER manufactured an error out of a successful backend call: %v", err)
		}
	})

	t.Run("backend error is returned verbatim through a failing lower", func(t *testing.T) {
		err := withAmbientNetAdminUsing(1000, prctl, func() error { return backendErr })
		if !errors.Is(err, backendErr) {
			t.Errorf("backend error must reach the caller unmasked, got %v", err)
		}
		if errors.Is(err, lowerErr) {
			t.Errorf("the lower failure leaked into the caller's error: %v", err)
		}
	})
}

// TestAmbientBracketOrdersRaiseBeforeBackendBeforeLower pins the window shape:
// the ambient bit is up ONLY across the backend call.
func TestAmbientBracketOrdersRaiseBeforeBackendBeforeLower(t *testing.T) {
	var seq []string
	err := withAmbientNetAdminUsing(1000, func(op, _ uintptr) error {
		switch op {
		case prCapAmbientRaise:
			seq = append(seq, "raise")
		case prCapAmbientLower:
			seq = append(seq, "lower")
		default:
			t.Errorf("unexpected PR_CAP_AMBIENT subcommand %d", op)
		}
		return nil
	}, func() error {
		seq = append(seq, "backend")
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"raise", "backend", "lower"}
	if len(seq) != len(want) {
		t.Fatalf("bracket sequence = %v, want %v", seq, want)
	}
	for i := range want {
		if seq[i] != want[i] {
			t.Fatalf("bracket sequence = %v, want %v", seq, want)
		}
	}
}

// containsAll reports whether s contains every substring.
func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
