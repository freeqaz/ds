//! `contract-tests` — a TEST-ONLY workspace member. No production code lives
//! here; every assertion is an integration test under `tests/`.
//!
//! # Why this crate exists
//!
//! The frozen `ds_contracts::flush::FlushSession` contract has TWO consumers
//! that must agree on the shape of one opaque value, the
//! `ds_contracts::flush::DstKey`:
//!
//! - **ds-nft**'s `NftWriter` — the conntrack/netlink half of the sweep, which
//!   narrows a revocation with `DstFilter::Only([key])` and hands each `key`
//!   straight to `conntrack -D --dst <key>`;
//! - **ds-tlsproxy**'s `SeveringRegistry` — the userspace twin, which stores the
//!   `key` at register time and severs a live tunnel / pooled upstream socket
//!   only when a later sweep passes back an EXACTLY-equal `key`.
//!
//! Both consumers compare the key by string equality. If the representation used
//! at register time differs from the one the revocation sweep passes in
//! `DstFilter::Only` (e.g. `"203.0.113.10:443"` vs `"203.0.113.10"`), the sweep
//! silently severs NOTHING on BOTH sides — a guardrail no-op with no error. That
//! is the documented failure mode this crate's tests exist to catch (wave-4
//! planner note on task `01KTXJG7R3T6EN5D3K03D0NQGC`).
//!
//! D76 (doc 12 §4.2, doc 14 §5) forbids either consumer from depending on the
//! other, so neither can host a cross-consumer test. This downstream test-only
//! member is the one place that path-depends on both — without adding any edge
//! between them.
//!
//! See `README.md` for the pinned canonical key shape.

// Intentionally empty: a test-only member exposes no library surface.

// The LOG-4 policy-skew conformance test (POL-4 / D72; doc 12 §8, doc 13 §5,
// doc 06 §5): `version(TLS decision) >= version(DNS admission)` holds CONTINUOUSLY
// through a policy apply — driven across BOTH real consumers (this crate is the
// one place that may path-depend on `ds-tlsproxy` AND `ds-dnsgate` at once, D76).
// It lives in a crate-internal `#[cfg(test)]` module (not under `tests/`) so the
// `--lib pol4_skew` conformance gate filter resolves it.
#[cfg(test)]
mod pol4_skew_test;
