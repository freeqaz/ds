// SPDX-License-Identifier: Apache-2.0

// ambient_linux.go is the ONE capability-MUTATING primitive in the helper (the
// probe in caps.go is read-only by construction): the narrow
// PR_CAP_AMBIENT_RAISE(CAP_NET_ADMIN) bracket the live backend wraps each
// ds-nft call in. It carries no build tag — the filename's `_linux` suffix is
// the constraint — so it compiles and is unit-testable in the DEFAULT (cgo-free)
// build, where nothing calls it.
//
// WHY AN AMBIENT RAISE AT ALL. ds-nft performs its work by EXEC'ing `ip`/`nft`.
// File capabilities do NOT survive execve into a binary that carries none of its
// own: the kernel derives a child's sets from the parent's INHERITABLE and
// AMBIENT sets. A `+ep`-only helper is therefore effective-green in its own
// probe yet hands every child an empty capability set (the half-configured-host
// trap, README "Capability Propagation"). The install pins `+eip`, and this
// bracket raises the capability into the ambient set so the fork inherits it.
//
// WHY runtime.LockOSThread IS LOAD-BEARING. Ambient capabilities are PER-THREAD
// kernel state, and the Go runtime migrates goroutines between OS threads at any
// preemption point. Without pinning, the raise could land on thread A while
// ds-nft's synchronous std::process::Command fork happens on thread B — the
// children silently unprivileged again, i.e. exactly the bug the raise exists to
// prevent. The bracket therefore pins the goroutine to its thread for the whole
// raise → call → lower window.
//
// FAIL-CLOSED. A failed raise NEVER runs the backend: the privileged call is
// refused with a remediation-carrying error rather than attempted with stranded
// children (the failure would otherwise surface as an opaque ds-nft EPERM). The
// LOWER is best-effort and its error is deliberately discarded — it must never
// mask (or manufacture) the backend's own result; the process exits within
// milliseconds regardless.
//
// ROOT SKIP. When the helper already runs as euid 0 the raise is both
// unnecessary and, in a fresh user namespace, impossible (an empty inheritable
// set makes PR_CAP_AMBIENT_RAISE fail with EPERM). Root children inherit
// capabilities via the kernel's root rule, so the bracket calls the backend
// directly there — this is what keeps the `unshare -rn` rehearsal (netns-validate.sh
// part D) usable.

package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// withAmbientNetAdmin runs f with CAP_NET_ADMIN raised into this THREAD's
// ambient set (so ds-nft's exec'd ip/nft children inherit it), lowering it
// afterwards. Fail-closed: if the raise fails, f is NEVER invoked.
func withAmbientNetAdmin(f func() error) error {
	return withAmbientNetAdminUsing(os.Geteuid(), ambientPrctl, f)
}

// withAmbientNetAdminUsing is the injectable core (the prctl leg and the euid
// are parameters purely so the bracket's decision table + fail-closed ordering
// are testable without a privileged host). Callers use withAmbientNetAdmin.
func withAmbientNetAdminUsing(euid int, prctl func(op, capBit uintptr) error, f func() error) error {
	// Pin BEFORE the raise: the ambient bit must land on the same OS thread
	// ds-nft forks ip/nft from (see the file header).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if !ambientRaiseNeeded(euid) {
		// euid 0: children inherit via the kernel's root rule; a raise in a
		// fresh userns would fail on the empty inheritable set.
		return f()
	}

	if err := prctl(prCapAmbientRaise, capNetAdminBit); err != nil {
		// FAIL CLOSED — f is never called. A raise failure means the install is
		// `+ep`-only (or setcap never landed), so the backend's ip/nft children
		// would run unprivileged and fail opaquely.
		return fmt.Errorf("ds-nethelper: PR_CAP_AMBIENT_RAISE(CAP_NET_ADMIN) failed: %w "+
			"(the installed helper needs `setcap cap_net_admin+eip` — `+ep` alone cannot cross the ip/nft execve; "+
			"re-run orchestrator/cmd/ds-nethelper/scripts/install-ds-nethelper.sh)", err)
	}
	// Best-effort lower; its error is DISCARDED so it can never mask f's result.
	defer func() { _ = prctl(prCapAmbientLower, capNetAdminBit) }()

	return f()
}

// ambientRaiseNeeded reports whether the ambient raise must be attempted for
// the given effective uid. Pure, so the root-skip decision is table-tested.
func ambientRaiseNeeded(euid int) bool { return euid != 0 }

// ambientPrctl issues PR_CAP_AMBIENT with the given subcommand for one
// capability bit. arg4/arg5 are 0 as the ABI requires.
func ambientPrctl(op, capBit uintptr) error {
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetCapAmbient, op, capBit, 0, 0, 0); errno != 0 {
		return errno
	}
	return nil
}
