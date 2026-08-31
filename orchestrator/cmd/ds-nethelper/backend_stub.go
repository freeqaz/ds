// SPDX-License-Identifier: Apache-2.0

//go:build !nftgatelive

// backend_stub.go is the DEFAULT (cgo-free) backend: every privileged verb
// fails closed with errNotBuilt, so `go build ./...` / CI / this skeleton
// never link libds_nft.a and never touch the kernel — the exact
// writeedge_stub.go posture, carried into the helper. The live half
// (backend_live.go, `//go:build nftgatelive`, a pass-through to
// orchestrator/internal/nftbridge wrapped in the ambient CAP_NET_ADMIN bracket)
// is the cgo-edge relocation — ratified D148 2026-07-30; live half =
// backend_live.go.

package main

// notBuiltBackend is the fail-closed default backend. Its methods mirror the
// nftbridge write edge field-for-field (see backend.go's signature pin,
// including the CreateTap hasUID bool) so the compile-time `var _ backend`
// assertion — and the future live pass-through — cannot drift.
type notBuiltBackend struct{}

// Compile-time assertion: the stub backend implements the pinned surface
// (backend.go). backend_live.go carries the symmetric assertion for the cgo
// pass-through.
var _ backend = (*notBuiltBackend)(nil)

// built reports whether the privileged backend is linked (Probe surfaces it).
const built = false

func newBackend() backend { return notBuiltBackend{} }

func (notBuiltBackend) CreateTap(string, uint32, bool, uint32, string) error { return errNotBuilt }
func (notBuiltBackend) DeleteTap(string) error                               { return errNotBuilt }
func (notBuiltBackend) InstantiateSession(string, uint32) error              { return errNotBuilt }
func (notBuiltBackend) FlushSession(string, uint32) error                    { return errNotBuilt }
func (notBuiltBackend) TeardownSession(string, uint32) error                 { return errNotBuilt }
