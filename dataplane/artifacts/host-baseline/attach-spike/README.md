# host-baseline/attach-spike — the D66 per-session attachment-primitive spike

The **reproducible procedure** for the re-scoped OQ1/D66 Linux attachment-primitive
spike — Stage 1's *first* task because it freezes NFT-2's interface design and §7's
attribution key
(doc 09 §2 placement note, §8 Stage 1;
OQ1/D66;
research + decision rationale in
sessions/round2/01).

The committed artifact is the **procedure**, not a captured blob: a runnable,
auto-detecting harness plus golden ruleset text. Findings live in
[`FINDINGS.md`](FINDINGS.md) (**proposed — bind nothing; mint no D-number**; D66
already ratified the dissolution, this spike only picks the FREE implementation
detail among the three primitives D66 named).

- **Owner workstream:** Boundary (Stage 1, ahead of NFT-2)
- **License:** OSS — Apache-2.0 (D15/D25)
- **Governing decisions:** D66 (structural/flag-audited no-L2-path; `br_netfilter`
  forbidden; three sound primitives), D69 (interface-anchored addressing — the
  three-keys-agree precondition), D44 (tap is the unforgeable attachment point),
  D34 (nested = recorded, metal = asserted), D76 (mark layout adopted by NFT-5
  from Stage 1 — out of this spike's scope, named for the join-key relationship)

## What the spike decides

D66 dissolved the ESXi half and left **one** FREE choice — which native Linux
primitive presents the per-session tap `dstap-<idx>` with no L2 path between agent
VMs. The three sound candidates, exercised by the harness and weighed in
`FINDINGS.md`:

| # | Primitive | No-L2-path proof | Default lean |
|---|---|---|---|
| 1 | **Routed tap** (libvirt `type='ethernet'`, host route + neigh per tap) | **Structural** — no bridge object exists | ✅ recommended (proposed) |
| 2 | **Per-session bridge** (one bridge, one tap) | **Structural** — one agent member per bridge | ✅ equally sound (proposed) |
| 3 | **Shared bridge + `BR_ISOLATED`** (`<port isolated='yes'/>`) | **Flag-audited** — continuous blocking assert | accepted only under the audit |

## Files

- **`run-attach-spike.sh`** — the harness. Three tiers, honestly tagged:
  - **PHASE A** (anywhere): naming-contract width, golden rule text, the
    structural-audit logic, `br_netfilter`-forbidden check.
  - **PHASE B** (sandbox-OK, `unshare -rn`): tuntap create + `iifname`/`ip saddr`
    rule **application** against a real netfilter path.
  - **PHASE C** (HOST-ONLY): the three-primitive build, the live L2-isolation
    traffic proof, `ct state` rules, and the uplink-throughput measurement —
    **skipped with a loud banner and the verbatim host procedure printed** when
    the substrate is absent (the dev sandbox kernel has no loadable `bridge`/`veth`
    and no netns conntrack hooks — see `FINDINGS.md` §"Sandbox-verified vs host-only").
  - `--self-test` — adversarial, non-vacuous: the auditor must reject the shared
    non-isolated bridge and the golden-drift detector must trip on a mutated
    ruleset (house precedent: `scripts/check-fixture-provenance.sh --self-test`).
- **`gen-attach-rules.sh`** — deterministic generator for the per-session forward
  anchors (`iifname "dstap-<idx>" ip saddr <own /31 guest IP>`), derived purely
  from the frozen contract. Drift-pinned by the golden files.
- **`golden/attach-rules-n3.nft`** — host-shape golden (with the `ct state` line).
- **`golden/attach-rules-n3-noct.nft`** — the conntrack-free subset PHASE B applies
  inside the sandbox netns (proves the `iifname`/`ip saddr` match against the kernel).

## How to run

```sh
./run-attach-spike.sh             # auto-detect: A+B run, C prints its host procedure
./run-attach-spike.sh --self-test # non-vacuous CI gate (no kernel needed)
./run-attach-spike.sh --host      # on the virtual-metal VM: demand the substrate
```

Neighbors: `../README.md` (the host-baseline artifact this spike feeds — version
floors, sysctls, capability posture), `../../nft/nft-1-bootstrap.nft` (the NFT-1
ruleset whose `iifname "dstap-*"` match this spike's primitive makes unforgeable),
`crates/ds-contracts/src/session.rs` (the `dstap-<idx>` / `SessionRef` contract).
