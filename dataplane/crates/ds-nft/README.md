# ds-nft

**The one nft/netlink writing API.** NFTables has no policy brain of its own — the DNS
gate programs it (D3, doc 09 §3) — and this crate is the only code anywhere that is
allowed to write nftables objects. Putting every netlink write behind one internal API
is what makes the single-writer discipline, the dual kernel paths, and the mark-mask
discipline enforceable
(doc 14 §6).

- **Owner workstream:** Boundary (doc 05 §3)
- **License:** OSS — Apache-2.0 (D25/D15)
- **Governing decisions:** D68 (both kernel refresh paths in CI; lockstep deadlines,
  doc 14 §3),
  D76 (mask discipline, capability posture, doc 14 §5),
  D72/D53 (rung-conditional revocation flush, doc 13 §5)

## Frozen invariants

| Invariant | Source |
|---|---|
| **Single-writer discipline: linked ONLY by `ds-dnsgate` and the host agent.** `ds-tlsproxy` never appears in this crate's reverse-dependency graph — it runs with CAP_NET_RAW only, never CAP_NET_ADMIN, so a compromised proxy cannot rewrite the ruleset that contains it (doc 12 §4.2; doc 14 §5) | D76 |
| Both kernel refresh paths behind the same API, both in CI: ≥6.12 in-place element-timeout update (commit 4201f3938914) and the delete+add fallback | D68; doc 14 §11 |
| `flush_session(session, dst_filter, legs)` implemented here, once — DS_MARK_MASK-aware (a bare-index match never fires against the composite layout), spanning leg nibbles `0x1`/`0x2` when the rung severs. Callers: D68 revocation (rung-conditional per D53), D72 sweep (same rule), NFT-6 teardown (unconditional, `legs=all`, final byte counts into ds-flowlog) | doc 14 §5; doc 11 §5.4 |
| Mask discipline: every set/match uses an explicit mask; full-register mark writes are forbidden (the Tailscale PR-5606 lesson); constants come **only** from `ds-contracts` — CI lint forbids local mark literals | D76; doc 13 §4 |
| Effectiveness precondition consumed from the host baseline: `nf_conntrack_tcp_loose=0`, else the flush is a no-op | D68; doc 14 §11 |

## C-ABI for cgo

The Go host agent consumes this crate as a **C-ABI staticlib** through
`orchestrator/internal/nftbridge/` — the one explicit Go↔Rust edge, covered by
`content_hash` contract tests (doc 13 OQ2, doc 15 OQ3). The `staticlib` crate-type is
added when that bridge lands; see the note in `Cargo.toml`.

## Free (firm up during build)

Netlink mechanism (nftnl-rs vs spawned `nft -f`), batching under fleet pushes,
gc interval (doc 11 §4).

## What must NOT live here

- **Policy decisions** — this crate executes verdicts; `policy-core` makes them.
- **The `flush_session` signature or mark constants** — `ds-contracts` owns the
  shapes; this crate only implements against them.
- **Any linkage from `ds-tlsproxy`** — see above; this is a frozen non-edge, not a
  convention.

## Module map (NFT-5/6 implementation)

The one internal API is split into mechanism modules; nothing here is policy.

| Module | Role |
|---|---|
| `flush` | `impl FlushSession` on `NftWriter<B>` — the one `flush_session` body all three callers share; resolves legs, composes the masked match, narrows per `dst_filter`, aggregates per-entry destroy records. Returns the frozen `FlushOutcome`; `flush_session_report` exposes the richer internal report for NFT-6 → ds-flowlog. |
| `mark_match` | Composes the `value/mask` conntrack match from `(Leg, index)` using only `ds_contracts::mark` (compose / `DS_MARK_MASK`). A bare-index match never fires. No raw DS-mark literal lives anywhere in this crate. |
| `backend` | The `NftBackend` trait hiding the mechanism; `RecordingBackend` (unit tests) and `SpawnBackend` (production spawned `nft -f` / `conntrack -D`). |
| `refresh` | BOTH kernel refresh paths behind one API (D68): the ≥6.12 in-place element-timeout update and the pre-6.12 delete+add-in-one-batch fallback, selected by `KernelProbe` with an explicit test override. Both batch shapes are asserted in CI on any kernel. |
| `outcome` | The richer internal `FlushReport` — per-entry destroy records with byte counts parsed from conntrack accounting output (`nf_conntrack_acct=1`). The frozen `FlushOutcome` stays untouched. |
| `alarm` | The doc 14 §4 wrap/exhaustion alarm predicate (live retention-window indices per host approaching 2^14 → page), threshold parameterized. Emission wiring is later NFT-5 integration. |
| `precondition` | The `nf_conntrack_tcp_loose=0` effectiveness probe (consumed from the host baseline, not set here): without it the flush is a no-op. Returns `Unknown` when the sysctl path is absent. |

**Rung-conditionality is the caller's decision (D53).** ds-nft executes mechanism
only — `flush_session` does exactly what its `dst_filter`/`legs` arguments say;
the "flush when rung ≥ block" choice (doc 14 §5; doc 11 §5.4) lives in the
caller, never here.

## Neighbors

`ds-dnsgate` (sole in-workspace writer), `orchestrator/cmd/host-agent/` (via the cgo
staticlib), `ds-contracts` (constants + signatures), `dataplane/artifacts/nft/`
(the bootstrap ruleset this crate's writes layer onto).
