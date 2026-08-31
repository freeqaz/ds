// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strconv"
	"strings"
)

// caps.go is the OpProbe capability introspection — the bring-up self-check
// that makes the `+eip`-vs-`+ep` half-configuration of the setcap'd helper
// distinguishable BEFORE any session is admitted.
//
// WHY THREE FIELDS, NOT ONE. The pinned setcap mechanism for this helper is
// `cap_net_admin+eip` (effective + permitted + INHERITABLE), NOT the naive
// `+ep`: the live ds-nft backend execs `ip`/`nft`, and file capabilities do
// NOT survive execve — an `+ep`-only helper would hold CAP_NET_ADMIN in-process
// yet hand its `ip`/`nft` children an empty capability set, so the tap/nft
// write silently fails at the child. The live backend therefore raises the
// capability into the AMBIENT set (PR_CAP_AMBIENT_RAISE) scoped to the backend
// call so the exec'd children inherit it; that raise SUCCEEDS only if
// CAP_NET_ADMIN is in both the permitted AND inheritable sets. So the probe
// reports the effective bit (did setcap land at all), the inheritable bit
// (is `+i` present so an ambient raise is even possible), and whether an
// ambient raise is expected to work (the permitted∧inheritable precondition) —
// three distinct answers, so a `+ep`-only host fails LOUD at bring-up instead
// of at the first child exec.
//
// READ-ONLY. This probe never MUTATES process capability state: it reads
// /proc/self/status and issues only PR_CAP_AMBIENT_IS_SET (a query) — never
// PR_CAP_AMBIENT_RAISE (which the live backend owns, scoped to its own call).
// ambientRaiseOK is a PREDICTION from the permitted∧inheritable precondition,
// not a trial raise, so the probe leaves no ambient bit set behind it.

// capNetAdminBit is CAP_NET_ADMIN's bit position in the capability bitmask
// (<linux/capability.h> CAP_NET_ADMIN = 12).
const capNetAdminBit = 12

// capState is the OpProbe capability snapshot for CAP_NET_ADMIN.
type capState struct {
	// Effective: CAP_NET_ADMIN is in this process's EFFECTIVE set — setcap
	// `+e` landed on the installed binary (the rebuilt-binary-loses-xattr
	// footgun surfaces here).
	Effective bool
	// Inheritable: CAP_NET_ADMIN is in the INHERITABLE set — setcap `+i`
	// landed, the precondition for an ambient raise across the ds-nft exec.
	Inheritable bool
	// Permitted: CAP_NET_ADMIN is in the PERMITTED set — the other half of
	// the ambient-raise precondition. Not surfaced on its own; folded into
	// AmbientRaiseOK.
	Permitted bool
	// AmbientAlreadySet: CAP_NET_ADMIN is ALREADY in the ambient set
	// (PR_CAP_AMBIENT_IS_SET) — informational; the live backend raises it
	// per-call, so at bring-up this is normally false.
	AmbientAlreadySet bool
	// AmbientRaiseOK: an ambient raise of CAP_NET_ADMIN is EXPECTED to
	// succeed — Permitted AND Inheritable, the kernel's documented
	// precondition for PR_CAP_AMBIENT_RAISE. Predicted, never trial-raised.
	AmbientRaiseOK bool
}

// probeCaps reads the CAP_NET_ADMIN posture of the current process. It is
// side-effect free (reads /proc + a PR_CAP_AMBIENT_IS_SET query only). On a
// platform without /proc/self/status the cap-set fields report false
// (fail-closed: the probe never claims a capability it cannot prove); see
// capsAmbientIsSet (build-tagged) for the prctl leg.
func probeCaps() capState {
	eff, inh, prm := parseProcCaps(readProcSelfStatus())
	amb := capsAmbientIsSet(capNetAdminBit)
	return capState{
		Effective:         eff,
		Inheritable:       inh,
		Permitted:         prm,
		AmbientAlreadySet: amb,
		// The kernel permits PR_CAP_AMBIENT_RAISE(cap) only when cap is in
		// BOTH the permitted and inheritable sets (capabilities(7)).
		AmbientRaiseOK: prm && inh,
	}
}

// readProcSelfStatus returns /proc/self/status contents, or "" when it cannot
// be read (non-Linux / no procfs) — parseProcCaps then reports all-false.
func readProcSelfStatus() string {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ""
	}
	return string(b)
}

// parseProcCaps extracts (effective, inheritable, permitted) for
// CAP_NET_ADMIN from the CapEff/CapInh/CapPrm hex masks in a
// /proc/<pid>/status body. A missing/malformed line yields false for that set
// (fail-closed). Exported-shape kept small + pure so it is fully table-tested
// without touching the kernel.
func parseProcCaps(status string) (effective, inheritable, permitted bool) {
	effective = capBitSet(status, "CapEff:")
	inheritable = capBitSet(status, "CapInh:")
	permitted = capBitSet(status, "CapPrm:")
	return
}

// capBitSet reports whether capNetAdminBit is set in the hex mask on the
// status line prefixed by `prefix` (e.g. "CapEff:"). Returns false when the
// line is absent or the mask does not parse.
func capBitSet(status, prefix string) bool {
	for _, line := range strings.Split(status, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		hexs := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		v, err := strconv.ParseUint(hexs, 16, 64)
		if err != nil {
			return false
		}
		return v&(1<<capNetAdminBit) != 0
	}
	return false
}
