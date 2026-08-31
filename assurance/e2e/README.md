# assurance/e2e/ — the (b) session-lifecycle suite

The end-to-end tier of the D24 pyramid: drive the **full session lifecycle on a real (or
nested) hypervisor** — `create → attach → work → snapshot → suspend → resume → destroy` —
and assert the three things that make the product real
(doc 06 §3b). This suite is cross-cutting by
nature (orchestrator, host agent, data plane, VM runtime, and attach all participate), so
it lives here rather than in any one workstream's tree.

**Owner:** Orchestrator (CODEOWNERS); VM & runtime contributes scenarios — and every
workstream contributes assertions for its lifecycle step.

**Licensing:** OSS (Apache-2.0, in `oss-manifest.yaml`).

## The assertions that matter (doc 06 §3b)

1. **"Seconds to start."** create→attach is timed against a budget using the doc 15 §8
   segment decomposition. Per **D81**: *instrument from M0, gate from M2* — the strawman
   numbers are planning aids, not assertions, until dogfood data sets them. Once gated, a
   regression is a release blocker — this number is the product.
2. **Clean teardown.** destroy leaves no orphaned VM, no leaked nftables rules or
   allow-set entries, no dangling CoW overlay, no stranded proxy session, no leftover
   minted identity. Includes the N-loop byte-identical-ruleset check (NFT-6,
   doc 15 §11).
3. **Pause-budget invisibility (D46).** A pause within budget is *operationally invisible*
   (the deliberate D46 rewording of "the agent can't tell it was paused"): in-flight
   tooling — git push over HTTPS, npm install, LLM streaming — completes or transparently
   resumes. Tested at **60 s / 5 min / 15 min** against the tiered budget: ≤5 min fully
   transparent, 5–15 min best-effort, >15 min snapshot+park with **no transparency claim**.

## Where it runs: fidelity tags (D31/D34)

Every assertion carries a fidelity tag; the tag decides the gate, not the calendar:

| Tag | Meaning | Gate |
|---|---|---|
| `nested-ok` | functional/logical assertions nested KVM can prove honestly | per-commit CI on nested QEMU/libvirt |
| `metal-only` | timing, snapshot/CoW semantics, storage behavior | nightly / pre-release on real hardware |

With D31 (virtual metal), per-commit CI runs the *same* QEMU/libvirt stack as the
prototype host, so the nested-vs-real delta mostly closes itself; any
nested-green/metal-red divergence **auto-files as a test-environment bug** (D34,
doc 06 OQ1) — a fidelity gap in the test
substrate to close, never a product regression.

That filer is executable: `divergence_filer.go` is the pure, offline decision +
record-builder core. Given the two lanes' assertion results (`LaneResults`),
`DetectDivergences` returns one `DivergenceRecord` — a taskdb-file-able
title/body/priority/dedup-key payload — for each assertion that is **green nested
but red on metal**, and nothing else (lanes that agree, a metal-green/nested-red
product bug, or a single-lane-only assertion never file). It carries no live/metal
dependency: the metal results come from the separately-tracked, deferred
metal-nightly lane (parent `01KV6VHSGH` — the `[self-hosted, virtual-metal]`
runner provisioning and the `e2e.yml` Lane-2 schedule flip stay operator/infra
work, out of scope here). `divergence_filer_test.go` proves the trigger and every
non-trigger against synthetic fixtures on the nested-ok lane.

M0 seeds this suite with a single create→attach→destroy smoke test — "even one … is a
load-bearing smoke test" (doc 06 §5).

## Governing decisions

- **D24** — (b) is the lifecycle tier (doc 06 §3b)
- **D31** — virtual-metal substrate: nested CI runs the production KVM stack
- **D34** — `nested-ok` / `metal-only` fidelity tags
- **D46** — tiered pause budget and the "operationally invisible" rewording
- **D81** — create→attach budget: measure from M0, gate from M2 (doc 15 §8)

## What must NOT live here

- **Guardrail claims** — bypass-fails assertions are (c) rows in `guardrail-conformance/`, not lifecycle steps.
- **Module contract tests** — (a) tier, owner-resident.
- **Performance/scale measurement** — the knee, fan-out latency, and throughput belong to the (d) rig (the internal scale rig and `benchmarks/`); this suite asserts budgets, it doesn't search for limits.
- **Hard-coded gate timing values** — D81 forbids asserting strawman numbers before M2 dogfood.

## Neighbors

- `orchestrator/` — drives the lifecycle; owns the segment decomposition this suite times.
- `vm/` — entrypoint and disk tooling exercised by snapshot/resume steps.
- The operator-provisioned real-substrate environment — the nightly real-hardware leg.
- The internal scale rig — same lifecycle under fan-out, different question (limits, not correctness).
