// Package nftbridge is THE explicit Go↔Rust edge of the repository: the
// host agent's cgo binding to the ds-nft C-ABI staticlib
// (dataplane/crates/ds-nft — the one nft/netlink API). No other Go code
// may touch nftables, and no other Go package may link Rust.
//
// Why a bridge and not a port: ds-nft is the SINGLE writer crate for
// session NFT objects (doc 14 §6); the host agent and ds-dnsgate are its
// only two linkers (D68 keeps both kernel refresh paths in one tested
// crate). Reimplementing flush_session in Go would fork the teardown
// semantics that NFT-6 freezes.
//
// What crosses this edge:
//   - flush_session(session, legs=all) — invoked UNCONDITIONALLY at
//     destroy step 2 (doc 15 §4.2), and on create-rollback from step 4
//     onward; ordering (interface rules → named sets + DNS-2b map →
//     conntrack by mark) is ds-nft's, frozen by D68/D72/D76
//   - per-session NFT object instantiation at create step 4 (chains,
//     empty allow{4,6}_<session> sets)
//   - the signature itself is a frozen constant in ds-contracts; this
//     package mirrors it, never redefines it
//
// CONTRACT-TEST HOME: the Go↔Rust contract tests live here (doc 06 §2.1),
// including the canonical content_hash serialization test — the same
// policy snapshot bytes must hash identically from internal/policylog
// (Go) and ds-contracts (Rust). That canonicalization is open as
// doc 15 OQ3 / doc 13 OQ2 (proposed default: canonical deterministic
// serialization with the contract test in ds-contracts); it must close
// before the snapshot format freezes. Until then this package carries no
// cgo — the skeleton builds offline with zero non-stdlib deps; the cgo
// binding lands with the first ds-nft staticlib artifact.
//
// Governing decisions: D68, D72, D76. Primary docs:
// docs/15-orchestrator-design.md §4.2, OQ3; docs/13-policy-and-host-config-schema.md OQ2;
// docs/14-boundary-shared-contracts.md §5–§6.
package nftbridge
