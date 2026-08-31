// SPDX-License-Identifier: Apache-2.0

//go:build nftgatelive

// writeedge.go is the LIVE cgo binding to the ds-nft C-ABI staticlib — the one
// Go↔Rust write edge (doc 14 §6). It is compiled ONLY under the `nftgatelive`
// build tag (the cgo half of the DS_NFTGATE_LIVE gate): the default build and CI
// take writeedge_stub.go instead, so the offline tree stays cgo-free / no-link
// (the package's standing posture, doc.go). The box builds this with
// `-tags nftgatelive` after `cargo build -p ds-nft --release` has produced
// dataplane/target/release/libds_nft.a (the staticlib crate-type) + the
// already-checked-in include/ds_nft.h.
//
// The link paths are anchored at ${SRCDIR} (the package dir) so they resolve
// from any clone/worktree without an absolute path: the header is read from the
// in-tree ds-nft crate, the archive from the cargo release target dir. ds-nft
// execs `ip`/`nft` (mechanism only, no libnetlink linkage), so the only extra
// link deps are the Rust staticlib's libc transitive set (pthread/dl/m).
//
// Contract: every wrapper returns nil on DS_NFT_OK (0) and otherwise an error
// carrying the negative code + ds_nft_last_error() (the thread-local message,
// copied immediately per the header's borrow contract). The C-ABI signatures
// these wrappers bind are pinned + guarded offline by writeedge_contract_test.go
// against include/ds_nft.h (doc 15 OQ3 / doc 13 OQ2) so the edge cannot drift.

package nftbridge

/*
#cgo CFLAGS:  -I${SRCDIR}/../../../dataplane/crates/ds-nft/include
#cgo LDFLAGS: -L${SRCDIR}/../../../dataplane/target/release -lds_nft -lpthread -ldl -lm
#include <stdlib.h>
#include "ds_nft.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Built reports that this binary was compiled with the nftgatelive cgo edge
// linked (the stub reports false). Callers gate the real AttachPrimitive on it.
const Built = true

// lastError copies the calling thread's last ds-nft message immediately (the
// header lends it only until this thread's next ds-nft call — never freed here).
func lastError() string { return C.GoString(C.ds_nft_last_error()) }

// check maps the C return convention (0 = OK; negative = error) to a Go error,
// folding in the thread-local last-error message for the failing op.
func check(op string, rc C.int32_t) error {
	if rc == 0 {
		return nil
	}
	if msg := lastError(); msg != "" {
		return fmt.Errorf("ds-nft %s failed (rc=%d): %s", op, int(rc), msg)
	}
	return fmt.Errorf("ds-nft %s failed (rc=%d)", op, int(rc))
}

// CreateTap creates the per-session `dstap-<idx>` tap netdev AND programs its
// routed addressing (D2, doc 11 §2.4): the host-side gateway
// 10.77.<hostSessionIndex>.0/31, the on-link /32 route to the guest .1, and —
// when guestMAC is non-empty — a static `ip neigh replace`. When hasUID, the tap
// is owned by ownerUID. An empty guestMAC is mapped to a C NULL (the MAC is
// unknown → the static-neigh leg is skipped host-side, a recoverable gap, never
// a failure). Still writes NO nft rules (the glob floor owns those). Idempotent.
func CreateTap(name string, ownerUID uint32, hasUID bool, hostSessionIndex uint32, guestMAC string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	var hu C.int
	if hasUID {
		hu = 1
	}
	// An empty guestMAC is NOT C.CString("") — a non-NULL empty string would
	// reach `ip neigh replace ... lladdr ''` and the kernel rejects it. Hand the
	// Rust side a NULL pointer so it takes the None (skip-neigh) branch.
	var cmac *C.char
	if guestMAC != "" {
		cmac = C.CString(guestMAC)
		defer C.free(unsafe.Pointer(cmac))
	}
	return check("create_tap", C.ds_nft_create_tap(cname, C.uint32_t(ownerUID), hu, C.uint32_t(hostSessionIndex), cmac))
}

// DeleteTap removes the tap netdev `name`. Idempotent (absent tap = success).
func DeleteTap(name string) error {
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	return check("delete_tap", C.ds_nft_delete_tap(cname))
}

// FlushSession runs the unconditional NFT-6 teardown flush_session(legs=all,
// dst=all) for the session keyed by tapName / hostSessionIndex (doc 15 §4.2).
func FlushSession(tapName string, hostSessionIndex uint32) error {
	cname := C.CString(tapName)
	defer C.free(unsafe.Pointer(cname))
	return check("flush_session", C.ds_nft_flush_session(cname, C.uint32_t(hostSessionIndex)))
}

// InstantiateSession creates the EMPTY per-session allow4_<idx>/allow6_<idx>
// admit sets in the existing `inet ds_filter` table (Model A, D1/D3/D4) — the
// admit SURFACE only, no floor enforcement. Idempotent.
func InstantiateSession(tapName string, hostSessionIndex uint32) error {
	cname := C.CString(tapName)
	defer C.free(unsafe.Pointer(cname))
	return check("instantiate_session", C.ds_nft_instantiate_session(cname, C.uint32_t(hostSessionIndex)))
}

// TeardownSession removes the per-session allow-sets InstantiateSession created
// (the named-set half of NFT-6; a full teardown calls FlushSession THEN this).
func TeardownSession(tapName string, hostSessionIndex uint32) error {
	cname := C.CString(tapName)
	defer C.free(unsafe.Pointer(cname))
	return check("teardown_session", C.ds_nft_teardown_session(cname, C.uint32_t(hostSessionIndex)))
}
