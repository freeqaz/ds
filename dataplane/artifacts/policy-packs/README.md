# artifacts/policy-packs — the D64/D74 baseline policy packs

Home of the **versioned, named policy packs shipped with the open data plane** so a
fresh install is useful *and* bounded out of the box (D64): the developer-value test is
that a fresh session can call the Anthropic API, clone/push GitHub, and install npm
packages with zero configuration — and can reach nothing else (doc 09 §1).

- **Owner workstream:** Boundary (POL-2 step owner)
- **License:** OSS — Apache-2.0 (D15/D25 — the pack ships with the OSS data plane)
- **Governing decisions:** D64 (system default baseline), **D74** (tiered pack v2 +
  provenance + promotion rule,
  doc 13 §3
  and the "Baseline pack contents v2" table), D17/D74 (pass-through ships empty),
  D53 (rung on every rule)

## Frozen pack rules (D74; full schema: doc 13 §2–3)

- **Tier structure:** `core` / `vcs` / `packages` **enabled**; `telemetry` /
  `binary-cdn` / `ghcr` / `lfs` **disabled-by-default**. Flipping a tier is ordinary
  org policy.
- **Mandatory provenance:** every entry carries `provenance_source_url` + evidence;
  CI rejects entries without them. The staleness lesson is named:
  `statsig.anthropic.com` sat in Anthropic's own firewall script while NXDOMAIN.
- **The pass-through list ships EMPTY** — an entry requires attached reproduction
  evidence of a pinning failure under TLS-3 inspection (D74/D17).
- **Wildcard policy:** exact FQDNs only, except vendor-published + vendor-exclusive
  wildcards; host-wide `storage.googleapis.com` is permanently rejected (path-scoped
  + `requires: http-policy`, inert until TLS-6).
- **Promotion is never automatic:** observed flow → candidate (evidence thresholds) →
  vendor-family classification → human review for out-of-family (D74 three-stage rule).
- Pack **values** are tunable via POL-4 live push without a release; the schema fields
  themselves freeze with POL-1 v0 in `ds-contracts` (doc 14 §8).

## Shipped pack

`pol2-system-baseline.pol1.yaml` — the POL-2 system default baseline (D64 / D74 v2,
doc 09 §6). It is an ordinary POL-1 v0 `system-baseline` **layer document**: the
`ds-contracts` stdlib reader (`pol1::parse_layer`) consumes it with zero
`PolicyError`s, `policy-core` composes it, and the doc 09 §1 developer-value
reachability set admits through the ONE shared evaluator the three boundary
consumers embed (POL-3 — no consumer reimplements a rule). It is data, not code:
a team can empty, extend, or replace any of it through the same engine.

Contents (D74 v2; doc 13 §3 "Baseline pack contents v2"):

- **enabled** — `core` (`api.anthropic.com`, `claude.ai`, `platform.claude.com`;
  `downloads.claude.ai` deliberately excluded, the CC-pin coupled invariant),
  `vcs` (`github.com`, `api.github.com`, `codeload.github.com`, the
  `raw`/`objects`/`release-assets`/`github-releases`/`github-registry-files`
  `.githubusercontent.com` subdomains), `packages` (`registry.npmjs.org`,
  `registry.yarnpkg.com`, `nodejs.org`).
- **disabled-by-default** — `telemetry` (`sentry.io` + the vendor-published
  `*.sentry.io` wildcard exception), `binary-cdn` (Playwright /
  Chrome-for-Testing / Cypress hosts; `storage.googleapis.com` only ever
  path-scoped behind `requires: http-policy`, inert until TLS-6), `ghcr`, `lfs`.
- The D17/D74 **pass-through list ships empty**; the known public **DoH/DoT
  resolver** domains ship in the **blocklist** (block-or-higher rung, so a
  revocation severs established flows, §5); the host-side-only **upstream
  resolvers** (`1.1.1.1` / `8.8.8.8`) are ds-dnsgate's own egress (in-VM packets
  at those IPs still redirect, NFT-4). Every entry carries mandatory provenance.

The shipped pack's reachability contract is proven by the
`policy-core` integration test `tests/pol2_baseline.rs`, which loads THIS file
from the artifacts path and exercises the public consumer surface
(`policy_core::consumer::dns_admission_decision`): every enabled-family endpoint
admits, every disabled-family endpoint and an arbitrary unlisted domain does not,
the pass-through list is empty, the DoH/DoT resolvers deny, and a
provenance-stripped entry is rejected by the parse-time validators.

The same contract is cross-checked from **outside the Rust workspace** by
`assurance/conformance-adapter/pol2reachability` (Go, stdlib-only, Apache-2.0):
a table-driven reachability matrix whose **offline half** asserts the frozen
D74 v2 contents — tier defaults, `downloads.claude.ai` excluded, the empty
pass-through list, mandatory provenance, a canary non-pack domain matching
nothing, and the `storage.googleapis.com` entry held domain-inert behind
`requires: http-policy` until TLS-6 — against a clearly-labeled synthetic
transcription of the spec (the D26/D51 posture: the suite is the spec made
runnable; its reader is data-source-agnostic, so pointing it at the shipped
YAML bytes is a cheap follow-on). Its **live half** — real client flows through
a fresh-install egress gateway, canary refusal at DNS-3 and TLS-1, the
zero-flows-outside-pack audit, and the TLS-6 present/absent capability-gate
paths — is env-gated behind `DS_POL2_LIVE=1`, skipped by default, and remains a
**deferred manual** conformance pass. Two halves of this story are still open
in taskdb: completing the live done-when run on the boundary rig, and the TLS-1
SNI parity assertions for the DoH/DoT resolver blocklist
(`policy_core::consumer::tls_connect_decision` must deny and sever exactly as
the DNS-3 half does — filed, currently blocked on a test-file rename so the
suites stay disjoint).

**Historical (pre-POL-2):** POL-1 v0 content was on the anti-scaffold list while
the schema landed in `crates/ds-contracts/`; this directory was pinned (glob,
CODEOWNERS, CI checks) before the first pack PR so the pack could land as data on
a frozen contract — which it now has.

Neighbors: `crates/ds-contracts/` (POL-1 schema + validation), `crates/policy-core/`
(evaluates composed layers), `../host-baseline/` (deliberately separate lifecycle —
that artifact is never pushed over the policy stream).

## Poller contract — the D74 vcs-family staleness guard

The vcs family carries the pack's only machine-readable vendor source
(`machine_source: api.github.com/meta`, doc 13 §3). `scripts/policy-packs/vcs_meta_poller.py`
(python3, stdlib-only) is the staleness guard that keeps the shipped vcs FQDNs
honest against that source. It guards the inverse of the named lesson: where
`statsig.anthropic.com` sat *in* a firewall script while NXDOMAIN, this poller
catches the vendor *adding* a domain the pack has not yet authorized.

- **Cadence: daily.** One diff per day against `api.github.com/meta`. The nightly
  staleness canary (below) is a separate, finer alarm; the poller is the
  domain-set differ.
- **It NEVER writes the pack.** The poller reads the vcs entries + `machine_source`
  and emits a **unified diff + PR-body markdown as a proposal**. Nothing is
  auto-applied: out-of-family and wildcard candidates land in the D74 three-stage
  human review queue and are **never auto-promoted**. Merging a proposal is a human
  act with the mandatory `provenance_source_url` + evidence attached per entry.
- **IP arrays are ignored.** `/meta` ships top-level IP/CIDR arrays (`hooks`, `web`,
  `api`, `git`, `packages` …) — diagnostics only, **never** used for authorization.
  The poller consults **only** the `domains` object (service → `[domain …]`).
- **Wildcard policy (D74).** Exact FQDNs only. A host-wide / leading-`*.` domain in
  `/meta` is **reported for human attention, never proposed** into the FQDN set
  (`*.githubusercontent.com`, `*.core.windows.net`, host-wide `storage.googleapis.com`
  are permanently rejected). A vendor-published + vendor-exclusive narrowing is a
  human decision, not an auto-add.
- **Missing source is a hard error.** A vcs family with no resolvable
  `machine_source` (every entry `null`, no family-level source) errors rather than
  guessing where to poll. A failed lookup is a blocker, never a fabricated answer.
- **Fixtures-first; live fetch is a deferred manual step.** By default the `/meta`
  document is loaded from `--fixture` (the shipped synthetic
  `scripts/policy-packs/fixtures/github-meta.json`, in the documented shape). Live
  fetch is gated behind `DS_META_POLLER_LIVE=1` and is opt-in only; a failed live
  lookup raises (never a guess). No default path touches the network.
- **Pack format note.** The shipped pack is YAML and the stdlib has no YAML parser,
  so the poller consumes a **JSON projection** of the `baseline_pack` object (a
  strict subset of YAML). When the YAML pack lands, a thin yaml→json projection step
  feeds the poller; the YAML remains the authoritative pack format.

Exit status: `0` = no drift (explicit no-op when the fixture mirrors the pack);
`1` = drift (a proposal was emitted on stdout); `2` = error.

### Deferred infra: nightly staleness canary

The nightly **staleness canary** (a DNS-resolution probe of every enabled-family
entry, flagging NXDOMAIN/long-stale FQDNs — the statsig signal) is **deferred
infra**, wired as a scheduled job that runs the poller in `--format pr-body` mode
plus a per-entry resolution check, and opens a review issue/PR on any flag. It is
intentionally not stood up here: it needs scheduler + repo-write credentials that
live outside this artifact and outside the agent VM, and it is part of the parent
baseline-pack-automation task (poller → source watchers → canary). Until that
infra lands, run the poller manually with `--fixture` for review and reserve the
`DS_META_POLLER_LIVE=1` path for an operator with deliberate network access.
