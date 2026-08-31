// SPDX-License-Identifier: Apache-2.0

//go:build nftgatelive

// backend_live.go is the LIVE half of the helper's ONE privileged seam: a
// zero-adaptation pass-through to the ds-nft cgo write edge
// (orchestrator/internal/nftbridge writeedge.go → libds_nft.a), compiled ONLY
// under `-tags nftgatelive`. It is the cgo-edge RELOCATION ratified as D148
// (2026-07-30): the doc 14 §6 linker set is now {ds-dnsgate, ds-nethelper} and
// the host agent builds untagged forever (see cmd/host-agent/nftgatelive_refuse.go).
//
// AMBIENT CAPABILITY BRACKET. Every method wraps its nftbridge call in
// withAmbientNetAdmin (ambient_linux.go): ds-nft does its work by EXEC'ing
// `ip`/`nft`, and file capabilities do NOT survive execve — the capability must
// be in the AMBIENT set at the moment of the fork or the children are stranded
// unprivileged (README "Capability Propagation"). The bracket raises
// CAP_NET_ADMIN into the ambient set immediately around the backend call and
// lowers it after, so the helper's default posture stays minimal and the
// privileged window is auditable. The bracket also PINS the OS thread: ambient
// capabilities are per-THREAD state and the Go runtime freely migrates
// goroutines between threads, so the raise must land on the very thread ds-nft
// forks from.
//
// The `#cgo CFLAGS/LDFLAGS` anchors live in nftbridge's own directory
// (${SRCDIR}-relative), so importing that package from here needs no path
// change — the archive still resolves at dataplane/target/release/libds_nft.a.

package main

import (
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/nftbridge"
)

// built reports that this build links the privileged backend (Probe surfaces
// it; the stub build's const is false).
const built = true

// liveBackend is the privileged backend: each method is the SAME verb the
// nftbridge write edge exposes, bracketed by the ambient CAP_NET_ADMIN raise.
// It carries NO state — the helper is one process per operation.
type liveBackend struct{}

// Compile-time assertion against the backend.go signature pin: the live
// pass-through cannot drift from the nftbridge write-edge surface (the drift
// guard the cgo-edge relocation rides on).
var _ backend = liveBackend{}

func newBackend() backend { return liveBackend{} }

func (liveBackend) CreateTap(name string, ownerUID uint32, hasUID bool, hostSessionIndex uint32, guestMAC string) error {
	return withAmbientNetAdmin(func() error {
		return nftbridge.CreateTap(name, ownerUID, hasUID, hostSessionIndex, guestMAC)
	})
}

func (liveBackend) DeleteTap(name string) error {
	return withAmbientNetAdmin(func() error {
		return nftbridge.DeleteTap(name)
	})
}

func (liveBackend) InstantiateSession(tapName string, hostSessionIndex uint32) error {
	return withAmbientNetAdmin(func() error {
		return nftbridge.InstantiateSession(tapName, hostSessionIndex)
	})
}

func (liveBackend) FlushSession(tapName string, hostSessionIndex uint32) error {
	return withAmbientNetAdmin(func() error {
		return nftbridge.FlushSession(tapName, hostSessionIndex)
	})
}

func (liveBackend) TeardownSession(tapName string, hostSessionIndex uint32) error {
	return withAmbientNetAdmin(func() error {
		return nftbridge.TeardownSession(tapName, hostSessionIndex)
	})
}
