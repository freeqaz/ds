// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// admissionshm_other.go is the non-Linux compile target of the host-agent-owned
// DNS-2b admission-map segment lifecycle. POSIX shm (shm_open/shm_unlink over
// /dev/shm) is Linux-only in this tree, so there is no real body off Linux — but the
// package must still COMPILE on other platforms (CODEOWNERS/CI may build them),
// exactly the posture sessiontokenvsock_other.go takes for AF_VSOCK.
//
// FAIL-CLOSED off Linux under the gate: newLiveAdmissionSegment returns an error so a
// host that sets DS_HOSTAGENT_LIVE on a non-Linux platform REFUSES the live path
// rather than silently serving with no host-owned segment (docs/sessions/13
// §Rollout-ordering: an attach/create failure is fail-closed). Off the gate
// NewAdmissionSegment never reaches here — it returns the no-touch stand-in (defined
// in admissionshm.go, platform-independent) — so the default path is unchanged on
// every platform.

package libvirt

import (
	"fmt"
	"runtime"
)

// newLiveAdmissionSegment fails closed on non-Linux: the live segment lifecycle needs
// POSIX shm (Linux-only). It is reached ONLY under DS_HOSTAGENT_LIVE (NewAdmissionSegment
// takes the no-touch stand-in off the gate), so an offline build on any platform is
// unaffected; only an operator who arms the live gate on a non-Linux host hits this
// fail-closed refusal. _ keeps the signature byte-identical to the Linux body.
func newLiveAdmissionSegment(_ string) (AdmissionSegment, error) {
	return nil, fmt.Errorf("admission shm: host-owned POSIX shm segment is unsupported on %s (Linux-only; DS_HOSTAGENT_LIVE)", runtime.GOOS)
}
