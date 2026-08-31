// SPDX-License-Identifier: Apache-2.0

//go:build !nftgatelive

// writeedge_stub.go is the OFFLINE-default (cgo-free) half of the ds-nft write
// edge: it carries the SAME Go surface as the live cgo binding (writeedge.go)
// but links nothing, so `go build ./...` and CI stay cgo-free / no-link (the
// package's standing posture, doc.go). Every entry point fails closed with a
// clear "not compiled" error; the real AttachPrimitive gates on Built so the
// offline host agent takes its no-touch fake (D50) rather than reaching here.
// The box arms the live edge with `-tags nftgatelive` once libds_nft.a exists.

package nftbridge

import "errors"

// Built reports that this binary was NOT compiled with the nftgatelive cgo edge
// (the live binding sets it true). Callers gate the real AttachPrimitive on it.
const Built = false

// errNotBuilt is the fail-closed sentinel every stub entry point returns — a
// caller that reaches the write edge in an offline binary is a wiring error, not
// a silent no-op (the no-touch fake lives in the host-agent seam, not here).
var errNotBuilt = errors.New("nftbridge: ds-nft cgo write edge not compiled " +
	"(build with -tags nftgatelive and link dataplane/target/release/libds_nft.a)")

// CreateTap fails closed: the cgo edge is not linked in this build.
func CreateTap(name string, ownerUID uint32, hasUID bool, hostSessionIndex uint32, guestMAC string) error {
	return errNotBuilt
}

// DeleteTap fails closed: the cgo edge is not linked in this build.
func DeleteTap(name string) error { return errNotBuilt }

// FlushSession fails closed: the cgo edge is not linked in this build.
func FlushSession(tapName string, hostSessionIndex uint32) error { return errNotBuilt }

// InstantiateSession fails closed: the cgo edge is not linked in this build.
func InstantiateSession(tapName string, hostSessionIndex uint32) error { return errNotBuilt }

// TeardownSession fails closed: the cgo edge is not linked in this build.
func TeardownSession(tapName string, hostSessionIndex uint32) error { return errNotBuilt }
