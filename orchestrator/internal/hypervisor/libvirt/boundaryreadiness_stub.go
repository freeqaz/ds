// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// boundaryreadiness_stub.go is the non-Linux compile target of the host-WIDE
// BoundaryReadiness probe. The LIVE probe (a read-only `nft list table inet <name>`
// shell-out + boundary-service dials) is the Linux operator-host posture, so there
// is no real body off Linux — but the package must still COMPILE on other platforms
// (CODEOWNERS/CI may build them), exactly the posture admissionshm_other.go takes.
//
// Off Linux under the gate, newLiveReadiness returns the no-touch deferredReadiness
// (always-ready): the nft-list/dial mechanism does not exist there, and the
// host-boundary fencing this probe attests is a Linux+nft concept, so a non-Linux
// build folds to the offline no-touch path (NewBoundaryReadiness compiles everywhere).
// The production operator host is Linux; an offline (gate-off) build on any platform
// never reaches this anyway (NewBoundaryReadiness returns deferredReadiness off the
// gate). Mirrors the admissionshm _linux/_stub split — except this one is always-ready
// off Linux (the probe is informational/admission, not a kernel-object lifecycle).

package libvirt

// newLiveReadiness on non-Linux returns the no-touch always-ready deferredReadiness:
// the nft-list/dial probe is Linux-only, so there is nothing to fence off Linux. _
// keeps the signature byte-identical to the Linux body so NewBoundaryReadiness
// compiles on every platform.
func newLiveReadiness(_ LiveReadinessConfig) (BoundaryReadiness, error) {
	return deferredReadiness{}, nil
}
