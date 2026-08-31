// SPDX-License-Identifier: Apache-2.0

// Package vm is the root of the VM & runtime workstream tree.
//
// Thin at M0 by design: the hypervisor driver this tree does NOT contain
// lives in the host agent (orchestrator/internal/hypervisor/libvirt,
// doc 15 §5.1). What lives here is the guest side of the D38 runtime
// seam (entrypoint/) and the host-side disk-delta tooling (disk/, D29).
//
// This file exists only so the module compiles before any real package
// lands. See README.md for the charter, the open tap-create RACI row,
// and the list of things that must not live here.
package vm
