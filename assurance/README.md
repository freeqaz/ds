# assurance/ — cross-cutting test suites

This tree holds the test suites that span more than one workstream: the dual-run contract
harness, the conformance adapter that puts the real Rust data plane behind the `boundary/`
executable spec, the public guardrail-conformance package, the end-to-end lifecycle suite,
and the customer-facing benchmarks. It exists because a handful of
suites genuinely belong to a *seam* or to the *whole platform* rather than to one module —
and nothing else is allowed to live here.

**Owner:** per-subdirectory, via CODEOWNERS (this tree is deliberately multi-owner — see
each subdirectory's README).

**Licensing:** Every subdirectory published here is OSS (Apache-2.0, listed in
`oss-manifest.yaml`). The internal scale/fan-out rig is excluded from the manifest (D51)
and is not part of this repository.

## The one admission rule (doc 06 §3a)

Module-owned tests stay in the module. The (a)-tier contract/component suites are "owned by
the workstream that owns the module" (doc 06 §3a) —
they live in `orchestrator/`, `dataplane/`, `client/`, etc., next to the code they test.
Only suites that are *genuinely cross-cutting* — exercising a seam between two owners, the
full lifecycle, or a platform-wide claim — are admitted here. If you are about to add a
test for code your workstream owns, it goes in your tree, not this one.

## Vocabulary rule (doc 06 §3c)

We deliberately avoid red-team / attack / intrusion framing. These are **assurance tests
for properties we advertise** — "the same way a database ships tests that prove it doesn't
lose committed writes" (doc 06 §3c language note).
Directory names, package names, test names, and prose in this tree say
*guardrail-assurance* and *conformance*, never attack/redteam. This is enforced in review.

## Map

| Dir | Tier (D24) | License | What it is |
|---|---|---|---|
| [`contract-harness/`](contract-harness/) | (a) | OSS | Fake-generation pipeline + the run-the-suite-against-real-AND-fake harness (doc 06 §2.1) |
| [`conformance-adapter/`](conformance-adapter/) | (a)/(c) | OSS | Go module wiring the real Rust data plane behind the `boundary/` harness seams (doc 06 §2.2) + proxy wire-conformance |
| [`guardrail-conformance/`](guardrail-conformance/) | (c) | OSS | The D51 versioned public claims package — every advertised guardrail, runnable anywhere |
| [`e2e/`](e2e/) | (b) | OSS | Full session-lifecycle suite, fidelity-tagged per D34 |
| [`benchmarks/`](benchmarks/) | (d) output | OSS | D48 reproducible benchmark harness + raw published results |

## Governing decisions

- **D24** — the four assurance levels (a)–(d) (doc 06 §3)
- **D26/D51** — the (c) suite ships publicly; the public subset is the *complete* §3c claims table (doc 06 OQ5)
- **D47** — fail-closed `guardrail-map.yaml` (repo root, Boundary-owned) scopes the per-PR (c) subset
- **D34** — fidelity tags `nested-ok` / `metal-only` gate where each assertion may run
- **D48** — benchmark methodology; harness + raw results ship OSS
- **D50** — if a fixture is in git, it is synthetic

## What must NOT live here

- **Module-owned (a) tests** — they stay with their module (doc 06 §3a); this tree is not a test dumping ground.
- **The `boundary/` harness itself** — it is the executable spec (D26) and stays RED by design; this tree *satisfies* it (via `conformance-adapter/`), it never absorbs it.
- **Production code or fakes** — generated fakes live in `proto/gen/go`; behavioral fakes live in `<workstream>/fakes/`.
- **Attack/redteam-named anything** (doc 06 §3c).
- **Non-synthetic fixtures** (D50) — recorded fixtures live in the segregated internal store, never in git.

## Neighbors

- `boundary/` — the RED Go TDD harness this tree's adapter turns green; spec lives there, wiring lives here.
- `dataplane/` — the Rust system under test for the adapter and the conformance package.
- `proto/` + `proto/gen/go` — the contracts and generated fakes the contract-harness pipeline produces and the suites consume.
- `orchestrator/fakes/`, `identity/fakes/` — owner-resident behavioral fakes the dual-run harness exercises against real implementations.
