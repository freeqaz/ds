# assurance/benchmarks/ — the published benchmark suite (D48)

The customer-facing performance numbers, produced the only way they're worth publishing:
as a **published, reproducible harness whose raw results ship in this OSS repo** (D48).
The docs have been promising performance "on credit" — the "<5%" / "1–2% of NVMe"
anecdotes (doc 01 §2, doc 02 §4) — and D48's contract is that **the anecdote retires on
first publication** from this suite. "A benchmark customers can re-run is the only kind
worth publishing"; "an untrustworthy benchmark is worse than none"
(doc 06 OQ3).

**Owner:** Orchestrator (stewards the (d) rig and this harness; CODEOWNERS
`/assurance/benchmarks/`); methodology changes are reviewed like contract
changes — published numbers are commitments.

**Licensing:** OSS (Apache-2.0, in `oss-manifest.yaml`) — harness **and raw results**, per
D48. The rig that *executes* scheduled runs is internal (D51); what it
measures with, and what it measured, is public here.

## The D48 methodology (three tiers, two honesty axes)

| Tier | What |
|---|---|
| Headline | real-repo build times + the PTS kernel-compile benchmark |
| Micro | SNIA-methodology `fio` storage micro-benchmarks |
| Axes | **cold vs warm cache** and **idle vs loaded host** — both reported, never cherry-picked |

Run against three substrates: **EBS gp3 + io2**, **loaded multi-tenant local NVMe** (the
product claim — floors held under oversubscription, doc 01 §2), and a **current MacBook
Pro** (the developer's mental baseline).

Storage and timing numbers are inherently `metal-only` (D34): nested virtualization
"can't measure storage/throughput honestly" (doc 06 §3d),
so benchmark runs execute on real hardware, scheduled and pre-release.

## Layout (as content lands)

- harness definitions + pinned workload versions (kernel version for PTS, repo pins for
  real-repo builds, fio job files)
- `results/` — raw, timestamped run output with full environment manifests; results are
  append-only and never edited after publication

## Governing decisions

- **D48** — the methodology, the substrate matrix, OSS publication of harness + raw results (doc 06 OQ3)
- **D34** — `metal-only` fidelity for storage/timing measurement
- **D24 (d)** — benchmark production is an explicit output of the load/scale tier (doc 06 §3d)

## What must NOT live here

- **Scale-rig machinery** — fan-out orchestration, fleet simulation, and their infra are internal (D51).
- **Massaged or summarized-only results** — raw output with environment manifests, or it isn't published.
- **Anecdotal numbers in prose** — the entire point is replacing those; numbers cited in docs/ must trace to a run in `results/`.
- **Customer-shaped data** — workloads are synthetic/public repos only (D50).

## Neighbors

- The internal scale rig — executes scheduled (d) runs; this suite defines *what* is measured and holds the publishable output.
- `e2e/` — asserts budgets per-run; benchmarks characterize the envelope those budgets live in.
- `docs/01`/`docs/02` — the claims this suite makes defensible.
