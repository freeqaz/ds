// SPDX-License-Identifier: Apache-2.0

package main

import "errors"

// backend is the ONE privileged seam inside the helper: the five ds-nft write
// verbs, invoked only AFTER trust-boundary validation passed. Its live body is
// the SAME cgo binding the host-agent used to link
// (orchestrator/internal/nftbridge writeedge.go, `-tags nftgatelive` →
// libds_nft.a): backend_live.go is a thin pass-through to that package and the
// host-agent no longer builds with the tag at all (the doc 14 §6 linker set
// moved from {host-agent, ds-dnsgate} to {ds-nethelper, ds-dnsgate} — ratified
// D148 2026-07-30; live half = backend_live.go).
//
// SIGNATURE PIN. The five methods below mirror the nftbridge write edge
// FIELD-FOR-FIELD so backend_live.go can be a zero-adaptation pass-through:
//
//	nftbridge.CreateTap(name string, ownerUID uint32, hasUID bool, hostSessionIndex uint32, guestMAC string) error
//	nftbridge.DeleteTap(name string) error
//	nftbridge.InstantiateSession(tapName string, hostSessionIndex uint32) error
//	nftbridge.FlushSession(tapName string, hostSessionIndex uint32) error
//	nftbridge.TeardownSession(tapName string, hostSessionIndex uint32) error
//
// (source, do NOT import or modify here:
// orchestrator/internal/nftbridge/writeedge.go). The `hasUID bool` on CreateTap
// is carried through deliberately: nftbridge maps hasUID=false to a C NULL uid
// (an unowned tap), so the pass-through must be able to express it — even
// though THIS skeleton's caller always sets hasUID=true (owner_uid==caller is
// validated upstream in nethelperproto.ValidateCreateTap). The compile-time
// `var _ backend` assertion below fails the BUILD the instant the stub — or a
// future live pass-through — drifts from this surface: the drift guard the
// cgo-edge relocation rides on.
type backend interface {
	CreateTap(name string, ownerUID uint32, hasUID bool, hostSessionIndex uint32, guestMAC string) error
	DeleteTap(name string) error
	InstantiateSession(tapName string, hostSessionIndex uint32) error
	FlushSession(tapName string, hostSessionIndex uint32) error
	TeardownSession(tapName string, hostSessionIndex uint32) error
}

// Each build's backend body carries its OWN compile-time `var _ backend`
// assertion beside its definition — backend_stub.go for the cgo-free default,
// backend_live.go for the `-tags nftgatelive` cgo pass-through — so BOTH bodies
// are checked against the nftbridge signatures at compile time in the build
// that actually contains them, and neither can drift silently. (The assertion
// must live with the type: a build-tag-free assertion here would name a type
// absent from the other build and break it.)

// errNotBuilt is the fail-closed sentinel the stub backend returns — mapped to
// ExitNotBuilt/ENOTBUILT so the agent can tell "helper present but built
// without the privileged edge" from a real backend failure. Mirrors
// nftbridge/writeedge_stub.go's posture exactly.
var errNotBuilt = errors.New("ds-nethelper: privileged ds-nft backend not compiled in this build (build with -tags nftgatelive — the cgo edge relocation is ratified as D148)")
