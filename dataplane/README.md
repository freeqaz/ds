# dataplane/ — the production Rust data plane

**Owner workstream:** Boundary (doc 05 §3) — CODEOWNERS `@dream-serpent/boundary`.
**License:** OSS — the entire tree is Apache-2.0 and listed in `oss-manifest.yaml`;
the data plane is open by decision, not accident (D15/D25).

This tree is **one cargo workspace** holding every production data-plane crate and
service. The workspace, not any framework, is the anti-skew mechanism (D67,
doc 14 §6): `ds-tlsproxy` is built on
pingora-core, `ds-dnsgate` on hickory — what keeps their behavior aligned is that both
embed the same workspace crates (`policy-core`, `ds-contracts`, `ds-policy-snapshot`,
`ds-telemetry`). The `boundary/` Go harness is the executable specification this tree
must satisfy (D26), wired in from the outside via `assurance/conformance-adapter/`.

## Crate/service map

Each entry is the ratified Rust home of one `boundary/` Go island (the same table,
seen from the other side — [boundary/README.md](../boundary/README.md);
doc 14 §6 crate map):

| Rust home | Go island | Notes |
|---|---|---|
| [`crates/policy-core/`](crates/policy-core/) | `boundary/policycore/` | the one evaluation engine (POL-3) + SecretMatcher trait; no `ds-` prefix |
| [`services/ds-dnsgate/`](services/ds-dnsgate/) | `boundary/dnsgate/` | hickory-based per D67 — plain tokio, **not** Pingora |
| [`services/ds-tlsproxy/`](services/ds-tlsproxy/) | `boundary/tlsproxy/` | pingora-core (D40) |
| [`crates/ds-nft/`](crates/ds-nft/) | `boundary/nft/` | the one nft/netlink API; `flush_session` impl |
| [`services/ds-flowlog/`](services/ds-flowlog/) | `boundary/flowlog/` | LOG-1 wire types live in [`crates/ds-contracts/`](crates/ds-contracts/), emission in `ds-telemetry` |
| [`crates/ds-contracts/`](crates/ds-contracts/) | `boundary` (root) shared constants | SessionRef, RejectReason, `flush_session` signature, mark layout, POL-1 schema |
| [`crates/ds-policy-snapshot/`](crates/ds-policy-snapshot/) | — | the host policy snapshot loader (D72 admitter-last barrier) |
| [`crates/ds-telemetry/`](crates/ds-telemetry/) | — | the LOG-1 emitter both proxies and ds-flowlog share |
| [`artifacts/`](artifacts/) | — | nft rulesets, host baseline, policy packs (doc 14 §11) |

## Pin policy

Dependencies are **pinned and moved deliberately** — with a migration budget, never
floated (D40/D67; recorded in [`Cargo.toml`](Cargo.toml) and locked by
[`Cargo.lock`](Cargo.lock) — resolved from crates.io, not source-vendored, per D146):

- `pingora-core` **0.8.x** (D40) — `ds-tlsproxy` only
- `hickory` **0.26.x** (D67) — `ds-dnsgate` only
- `tokio` — **one pinned major** across the whole workspace (doc 14 §6)

The Rust toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml); the CI
data-plane lane ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) builds with
exactly that version.

## What must NOT live here

- **`.proto` files** — `proto/` is the single contract home; the Rust codegen output
  lands in `crates/ds-contracts/src/gen/`, never hand-written messages here.
- **Approval UI / ask-user surfaces** (D18/D53) — approvals live in `client/`; the
  data plane emits the ask event and holds the socket, nothing more.
- **Cloud SDKs** (D33, enforced by [`deny.toml`](deny.toml)) — cloud-agnosticism is
  CI-enforced, not aspirational.
- **Raw mark literals outside `ds-contracts`** (D76) — mark constants and
  `DS_MARK_MASK` are defined once; everything else imports them (mask discipline,
  doc 14 §5).
- **A merged `ds-proxy`** (D63) — the DNS gate and TLS proxy stay two services; the
  shared-engine workspace crates are the alignment mechanism, not a merge.
- **hickory or pingora types crossing `ds-contracts`** (D67/D40) — no framework type
  may appear in any cross-service interface; contracts are framework-free.

## Governing decisions

D15 (open data plane), D40 (pingora-core 0.8.x pin), D63 (two-service split),
D67 (hickory + the workspace as anti-skew mechanism), D76 (mark layout / mask
discipline) — log of record: doc 04 §6;
design: doc 11,
doc 12,
doc 13,
doc 14; build plan:
doc 09.
