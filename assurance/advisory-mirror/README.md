# assurance/advisory-mirror/ — the supply-chain advisory-mirroring process

One advisory-mirroring **process**, four subscriptions, one owner (doc 14 §9).
This tree is the config-as-code home of that process: the intake cadence, the four subscription
descriptors, and the seed mirrored-as-tests for the two RUSTSEC advisories that already seed the
ds-dnsgate regression corpus.

The four pinned/vendored dependencies share **identical machinery**: pin + vendor, advisory
mirroring into the doc 06 (a)/(c) suites, a named re-evaluation trigger. The process is one thing
applied four times; this README states it once.

## Charter, owner, mark

- **Charter:** mirror every upstream advisory for the four watched dependencies into the
  doc 06 (a) contract/component and (c)
  guardrail-assurance suites as a regression test — so a guardrail we depend on never regresses
  silently — and fire the per-row re-evaluation triggers when an upstream stalls or breaks format.
- **Ownership.** The **Boundary workstream** owns the one process; it already owns three of the
  four pins (Pingora D40, hickory-dns D67, the gitleaks-compatible ruleset format D73). The **Yjs
  subscription (D86) is executed by Canvas** under this same process. A named individual is
  assigned when the component graduates, at **Stage-1 start** (doc 14 §9 / OQ2) — see **Handover**
  below. Until then this tree is **handover-ready**: every subscription and trigger is
  config-as-code, so the named owner inherits a running process, not a blank page.
- **Licensing / mark.** This subdirectory is OSS (Apache-2.0): `assurance/` is Apache-2.0 except the
  internal scale rig (D51) per the `oss-manifest.yaml` per-tree license map. Adding the explicit
  `assurance/advisory-mirror/` entry to the manifest's `oss_paths` allowlist (and the CODEOWNERS glob)
  is the cross-tree component-registration step deferred to the named owner — see **Handover** — since
  it edits files outside this tree. Any shell that ships here carries the
  `SPDX-License-Identifier: Apache-2.0` header (assurance/ is in the SPDX-checked trees).

## Governing decisions

These already exist in the doc 04 §6 decision log; **no
D-number is minted here**.

- **D40** — Pingora pinned + vendored; re-eval on stall >12 months (or Envoy ships stable TLS bumping + ext_proc and Pingora has concretely failed us).
- **D67** — hickory-dns pinned + vendored at 0.26.x, migration budget per minor until 1.0; RUSTSEC mirroring mandatory; re-eval on >12 months without a release.
- **D70** — the trigger at which the Pingora HTTP/3 PRs #514/#524 + issue #95 are re-checked.
- **D73** — the gitleaks-compatible generic ruleset format; rule-quality regressions ride POL-4, never a proxy release.
- **D76** — the SO_MARK insertion point named in the Pingora API-watch row.
- **D86** — Yjs ecosystem pinned + vendored (house pattern per D40/D67); re-eval on core-yjs stall >12 months or a stored-format-breaking change without a migration path.

## The one process

### 1. Intake cadence

| Watch | Source stream | Cadence |
|---|---|---|
| **Pingora** | GHSA + RUSTSEC advisory stream (the `CVE-2025-4366` class) + GitHub releases | advisory stream **continuous**; API-watch-point review on every minor release and at the **D70 trigger** for the HTTP/3 items |
| **hickory-dns** | hickory GitHub releases **+ RUSTSEC** (mirroring mandatory) | advisory stream **continuous** — this is the fleet's only resolver, so an unpatched parsing/encoding-DoS window is a **fleet availability incident**, not a backlog item |
| **gitleaks-compatible ruleset format** | upstream format + curated-ruleset import cadence | **format-change watch** + periodic curated-ruleset import; rule-quality (FP-class) regressions feed pack updates via **POL-4** |
| **Yjs ecosystem** | GHSA + npm advisory stream (yjs + y-protocols + provider/persistence packages) | advisory stream **continuous**, executed by Canvas |

Each stream is read as one intake queue. A new advisory is triaged into: (a) **mirror as a test**
(the default — see step 2), (b) **migration event** (if the fix moves a pin — see step 3), or (c)
**re-eval trigger fired** (if it signals upstream stall or format break — see step 4). These are not
exclusive: a compression-bomb advisory both mirrors as a test and may bump the pin.

### 2. Advisory → mirrored-as-test (the default)

Every advisory's reproduction is **mirrored into the doc 06 (a)/(c) suites** as a regression test —
this is operational, not aspirational. The flow:

1. Capture the advisory's input shape, the expected post-fix behavior/verdict, and the citation.
2. Author a structured spec (see `advisories/` for the format) that pins **suite destination**:
   - **(a)** — contract/component, fast/per-commit, lives next to the module it tests (e.g. the
     ds-dnsgate parsing/encoding regression corpus). A malformed-query reproduction that the
     resolver must survive is an **(a)** test.
   - **(c)** — guardrail-assurance, the advertised-property suite. An advisory whose reproduction
     asserts a **guardrail we claim** (e.g. "no unbounded resource consumption can take the fleet's
     only resolver down") joins the (c) matrix.
   - An advisory may seed **both** (a) reproduction and a (c) availability assertion — the spec
     names every destination it lands in.
3. Wire the spec into the named corpus. For the two hickory seeds the destination corpus is the
   **ds-dnsgate** regression corpus (doc 11 §6 obligation 8:
   "RUSTSEC-2026-0118 (NSEC3 loop) and RUSTSEC-2026-0119 (compression-bomb encoding) reproductions
   run against the pinned hickory; malformed-query fuzz corpus gates DNS-5"). **NOTE:** the
   `ds-dnsgate` crate does not exist yet, so the specs in `advisories/` are **specs/fixtures only** —
   the corpus-wiring step is a tracked follow-up (see Handover).

The discipline: the conformance suite drives **wire behavior** (dig / getaddrinfo / stub clients),
never upstream library APIs (doc 11 §6 obligation 10) — so a
mirrored test survives the option-C library migration that D40/D67 keep open.

### 3. The pins-move-only-with-migration-budget rule

A pin **never** moves silently to chase an advisory. A version bump that crosses a minor (the
0.25→0.26 hickory restructure — proto→net split, `Authority`→`ZoneHandler` — is the proof the budget
is real) spends a **migration budget**: the bump lands with its churn-class test updates in the same
change, and the mirrored advisory tests must stay green across the move. hickory carries a migration
budget **per minor until 1.0** (D67); Yjs an update-encoding break is a **stored-document migration
event** (D86 — the doc 17 §4.3 golden-trace corpus
pins the encoding). No pin moves outside this rule; an advisory that demands a bump the budget can't
absorb is escalated, not rushed.

For the **gitleaks-compatible ruleset format** the analogue is sharper: rule-quality regressions
(FP-class) feed **pack updates via POL-4** (doc 13
§2: generic rules are a versioned policy artifact riding POL-4, "no proxy release") — **never a proxy
release**. The format-compatibility pin (the TOML fields) moves only on a real upstream format change
that breaks pack import.

### 4. Per-row named re-evaluation triggers

Each subscription carries its own named trigger; firing one opens a **decision row against the
governing D-number** — it does not change behavior here:

| Row | Re-eval trigger (verbatim from doc 14 §9) |
|---|---|
| **Pingora** | D40: stall **>12 months without a release**, or Envoy ships stable TLS bumping + ext_proc **and** Pingora has concretely failed us. The HTTP/3 PRs #514/#524 + issue #95 are re-checked at the **D70 trigger** (separate from the stall trigger). |
| **hickory-dns** | D67: **>12 months without a release** (symmetric with D40). |
| **gitleaks-compatible ruleset format** | **format divergence that breaks pack import** (the format-compatibility pin). |
| **Yjs ecosystem** | D86: core yjs **stalls >12 months**, **or** a stored-format-breaking change lands without a migration path → fallback evaluation (Automerge-class or bespoke server-authoritative) requires a **decision row against D86**. |

A fired trigger is filed as a taskdb note **proposing** the relevant decision-log row; it never mints
a D-number in this tree and never edits the §6 log directly (doc 14's change-control rule).

## Files in this tree

- **`README.md`** — this file: the one process.
- **`subscriptions.yaml`** — config-as-code for the four subscriptions, with the doc 14 §9 API-watch
  points carried verbatim. A `check.sh` validates its shape.
- **`advisories/`** — seed mirrored-advisory **test specs** for RUSTSEC-2026-0118 and -0119
  (input shape, expected resolver behavior/verdict, suite destination (a)/(c), citation). Specs and
  fixtures only — the ds-dnsgate corpus they wire into does not exist yet.
- **`check.sh`** — stdlib-only, env-independent validator for `subscriptions.yaml` shape (SPDX-headed).

## Handover

This tree is built **handover-ready** so the named owner (assigned at Stage-1 start) inherits a
running process. On assignment:

1. **Claim ownership + register the component.** Add the named individual to `CODEOWNERS` for
   `assurance/advisory-mirror/**`, add the explicit `assurance/advisory-mirror/` entry to the
   `oss-manifest.yaml` `oss_paths` allowlist (the CI separability gate reads that list, not the
   per-tree map), and resolve the open assignment TODO in
   doc 14 §9 ("Assign the supply-chain
   advisory-mirroring owner") and the §9 OQ2 row.
2. **Stand up the four subscriptions** before Stage 1 exits (the doc 14 TODO's "before Stage 1 exits"
   deadline): turn each `subscriptions.yaml` descriptor into a live intake feed.
3. **Wire the corpus.** When the **ds-dnsgate** crate lands, wire the `advisories/` seed specs into
   its regression corpus (doc 11 §6 obligation 8) — this is the **proposed follow-up** this tree
   files, because the corpus does not exist yet.
4. **Canvas leg.** Confirm Canvas owns the live Yjs-ecosystem subscription execution under this
   process (doc 17 §4.3); the descriptor and trigger live here, the execution is Canvas's.

Until step 1, this tree carries no named owner — only the proposed default — and the assignment TODO
stays open.

## Neighbors

- [`../README.md`](../README.md) — the `assurance/` admission rule and vocabulary rule (this tree
  says *advisory-mirroring* / *guardrail-assurance*, never attack/redteam framing — doc 06 §3c).
- doc 14 §9 — the
  four-row supply-chain watch table this tree implements; §9 OQ2 is the open owner question.
- doc 11 §6/§7 — the hickory
  subscription detail and the §6 obligation-8 destination corpus for the two seeds.
- doc 13 §2/§5 — the gitleaks-compatible generic ruleset format and the POL-4 pack-update path.
