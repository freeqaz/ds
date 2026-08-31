// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import "syscall"

// prctl option + subcommand constants (<linux/prctl.h>). Fixed across arches.
// IS_SET is the probe's read-only query (caps.go); RAISE/LOWER are the live
// backend's per-call bracket (ambient_linux.go) and are the ONLY capability
// MUTATION anywhere in this helper.
const (
	prSetCapAmbient   = 47 // PR_CAP_AMBIENT
	prCapAmbientIsSet = 1  // PR_CAP_AMBIENT_IS_SET (query — no mutation)
	prCapAmbientRaise = 2  // PR_CAP_AMBIENT_RAISE (backend bracket only)
	prCapAmbientLower = 3  // PR_CAP_AMBIENT_LOWER (backend bracket only)
)

// capsAmbientIsSet issues PR_CAP_AMBIENT / PR_CAP_AMBIENT_IS_SET for the given
// capability bit. It is a pure QUERY — it never raises or lowers any ambient
// bit (the live backend owns PR_CAP_AMBIENT_RAISE, scoped to its own call).
// Any error (old kernel without ambient caps, EINVAL) is reported as "not
// set", fail-closed. arg3/arg4 are 0 as the ABI requires for IS_SET.
func capsAmbientIsSet(capBit uintptr) bool {
	r, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetCapAmbient, prCapAmbientIsSet, capBit, 0, 0, 0)
	if errno != 0 {
		return false
	}
	return r == 1
}
