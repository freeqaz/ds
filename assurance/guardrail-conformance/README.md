# assurance/guardrail-conformance/ — the public guardrail claims package (D51)

Every guardrail the docs promise becomes a test that tries to make the guardrail fail and
asserts it doesn't (doc 06 §3c). This directory
packages those (c)-tier claims as a **versioned, public `guardrail-conformance` package
runnable against any data-plane deployment** — D51's amendment of D26: the public subset
is the *complete* §3c claims table, because "every advertised property is publicly
verifiable; what stays internal is scale machinery and embargoes, not claims."

## Version

The package version is single-sourced in the top-level `VERSION` file (semver, currently
`v0.1.0`). D51 makes the *complete* §3c claims table a published commitment (and per D65 a
warranty surface), so the package carries a version an external deployment can pin to: the
membership table below, the runnability split, and the home-lab invocation are the contract
that version names. Bump it when a claims row is added, retired, or its runnability changes
— the same way a published API version moves. The `VERSION` file is plain text (no Go
package coupling), ships in `oss-manifest.yaml` by inclusion of the
`assurance/guardrail-conformance/` tree, and is the single source for any tooling or release
that needs the package version.

**Owner:** Boundary workstream (claims are contributed by the workstream that owns each
guarantee; Boundary owns the package and the fail-closed scoping map, D47).

**Licensing:** OSS (Apache-2.0, in `oss-manifest.yaml`). This is the assurance behind the
"run unattended, bounded blast radius" promise — and per D65 it is also the warranty
surface in design-partner terms, so its rows are treated as published commitments.

## Vocabulary (doc 06 §3c, binding)

Never attack / redteam / intrusion. These are **assurance tests for properties we
advertise**. The claims table rows include (see doc 06 §3c for the full, authoritative
table): default-deny outbound (D4), DNS rebinding and DoH/DoT bypass fail, interface-match
not source-IP, the long-lived credential never enters the VM (D8), cert-pinned
pass-through (D17), suspend-on-breach fires (D77 taxonomy), controls unreachable from
inside the VM, the four canvas rows (doc 17 §13), and the re-filed read-only-spectate row.

## The row split: OSS-runnable vs paid-dependent

D51 ships the complete table, but not every row is runnable on a bare OSS install. Each
row in this package therefore carries a runnability marker:

- **`oss-runnable`** — executes against any OSS data-plane deployment (orchestrator-lite +
  `dataplane/` services); this is the default and the bulk of the table. D85 deliberately
  placed the KV client, minimal CA, swap mechanics, and digest producer in OSS precisely
  so the cred-never-in-VM and canary-never-egresses rows stay in this set.
- **`paid-dependent`** — requires paid-layer machinery (e.g. canvas rows that need the
  web client surface, per doc 06 §3c's round-3 note). These rows still *ship* in the public
  package — the claim text and assertion are public — but are split out so an OSS run
  reports them as not-applicable rather than failed (doc 17 §13).

Internal-only and therefore **not** in this package (D51): the load rig, paid-layer test
internals, non-synthetic fixtures, and per-incident regressions under embargo (graduated
public after the fix).

## When it runs (doc 06 §3c/§4)

Nightly full matrix; per-PR the diff-scoped subset selected by the repo-root
`guardrail-map.yaml` (D47, fail-closed: unmapped paths run the full matrix). A boundary
change with a red (c) suite does not merge.

## Home-lab quickstart (zero-egress, OSS-runnable)

D51 ships this table so an external / home-lab OSS deployment can verify every advertised
guardrail itself. The package is self-contained: standard-library-only, synthetic fixtures
in git (D50, zero data egress), no `paid/`, `dataplane/`, `identity/`, or proto dependency,
and deliberately **outside** the repo `go.work` `use` list — like the `identity/*` modules,
it builds and runs standalone under `GOWORK=off`. From a checkout (no network, no live
`dataplane/` services, no credentials):

```sh
cd assurance/guardrail-conformance
GOWORK=off go test ./...
```

A green run is the complete §3c claims table asserting itself against synthetic fixtures —
every owning package in the membership table below runs `oss-runnable`, so the whole suite
passes on a bare OSS install with no paid-layer machinery and nothing leaving the host. The
package version it ran is in `./VERSION`. `GOWORK=off` is load-bearing: it isolates the
module from production build state so the run never depends on anything outside this tree.

The *live* halves of the network rows (`nftgate`, `netisolation`, `resolverhardening`
`live_test.go`) are a separate, **deferred-manual** matter: they are env-gated
(`DS_*_LIVE=1`), SKIPPED by default, and require a real boundary — they are NOT part of the
zero-egress quickstart and do not run in CI. Driving a real deployment end to end is
`conformance-adapter/`'s job (see Neighbors), not this package's.

## D51 public-claims membership (owning packages → single-sourced tags)

D51 ships the *complete* §3c claims table, so this table covers **all thirteen landed owning
packages**. Each package single-sources the identifier(s) that name its row(s) in the
package source itself, pinned by that package's own `TestTagStable` / `TestTagsStable`
guard:

- **`const Tag` / `var Tags`** — the `orchctl`, `suspendbreach`, `passthrough`,
  `secretegress`, `credswap`, `canvas`, `writerseat`, `netisolation`, `identityrows`, and
  `resolverhardening` packages each declare a `const Tag = "<tag>"` (single row) or a `var
  Tags = []string{…}` (multi-row), and the `goldenfreshness` precedent single-sources its
  tag in a doc.go REGISTRATION `guardrail tag:` line. Where a package also carries a
  per-package `assurance/guardrail-conformance/<pkg>/**` row in the repo-root
  `guardrail-map.yaml` (today `orchctl`, `suspendbreach`, `passthrough`, `secretegress`,
  `goldenfreshness`, `canvas`, and `writerseat`), that row names the SAME tag(s) and the §3c
  claims table, the package, and the map thereby name the one row — the seam
  `check-guardrail-map-tags.sh` gates both ways. The remaining const-Tag/var-Tags packages
  (`credswap`, `netisolation`, `identityrows`, `resolverhardening`) single-source their
  tag(s) in the package source but are not yet seeded as per-package map rows (they fall
  under the broader boundary / `dataplane/**` / resolver globs); that additive per-package
  seeding is the gmap-rows work, not this package's.
- **typed `Row` / claim identity (no `const Tag`)** — two M0/onboarding packages predate the
  per-claim `const Tag` discipline and single-source their row identity differently:
  `nftgate` enumerates its rows as a typed `Row` set (`RowDefaultDeny`, … — its five
  `Row = "<row>"` literals), and `appinstall`'s single row is the package's doc 16 §13
  "App-install read-level subset" claim itself, with its failure modes typed as
  `ViolationClass` constants rather than a row tag. Their executable claims ship in the
  public package today; they are mapped through the broader boundary / `dataplane/**` /
  resolver globs in `guardrail-map.yaml` (the map's own comment block records that
  `nftgate`'s `Row` model carries no `const Tag` to seed a per-package row, and the gmap-rows
  work tracks any additive per-package seeding). Because they single-source no `const Tag`,
  they are **not** subject to the `check-guardrail-map-tags.sh` package↔map tag cross-check.

Every package below is `oss-runnable` (synthetic fixtures, D50; no `paid/`, `dataplane/`,
`identity/`, or proto dependency), so each row also ships in `oss-manifest.yaml` by inclusion
of the `assurance/guardrail-conformance/` tree, and a bare OSS run executes the whole table
green — no per-row paid split is active. The `canvas` rows carry the
`RunnabilityPaidDependent` split *mechanism* (an OSS run would report a paid-dependent canvas
row NOT-APPLICABLE rather than FAILED, doc 17 §13), but as modeled all five canvas rows are
`oss-runnable`, so the mechanism is present and exercised yet currently dormant.

| Owning package | Rows | Runnability | Single-sourced tag(s) |
| --- | --- | --- | --- |
| `orchctl/` | 5 | oss-runnable | `orch-suspend-on-breach`, `orch-ask-grant-atomicity`, `orch-skew-widening-scheduler-refusal`, `orch-revocation-of-derived-state-clock`, `orch-pack-staleness-canary-evidence-feed` (doc 15 §11; D77/D72/D68/D74) |
| `suspendbreach/` | 1 | oss-runnable | `suspend-on-breach-fires` (doc 06 §3c; D77/D46 — the boundary-enforcement half of suspend-on-breach) |
| `passthrough/` | 1 | oss-runnable | `pass-through-empty-by-default` (doc 20 §4 claim (3); D17/D74/D82) |
| `secretegress/` | 1 | oss-runnable | `secret-egress-canary-blocked` (doc 20 §4 claim (4); D73/D84) |
| `goldenfreshness/` | 1 | oss-runnable | `golden-rotation-freshness` (doc 03 §6 "Nightly golden images"; D12/D29) |
| `appinstall/` | 1 | oss-runnable | *(no `const Tag`)* — the doc 16 §13 "App-install read-level subset" claim; failure modes typed as `ViolationClass` (`onboarding-path-above-read-level`, `write-scope-on-onboarding-read-path`, `permission-absent-from-inventory`) (doc 16 §5.2/§13; D83/D56/D115) |
| `nftgate/` | 5 | oss-runnable | *(typed `Row` set, no `const Tag`)* — `default-deny-outbound`, `dns-rebinding-fails`, `doh-dot-bypass-fails`, `port-53-redirect-holds`, `quic-udp443-reject-not-drop` (doc 06 §3c M0 rows; doc 09 §9 NFT-1/NFT-3/NFT-4/DNS-4/POL-2; D4/D68/D70) |
| `credswap/` | 1 | oss-runnable | `cred-swap-never-leaks` (doc 06 §3c "Credential swap never leaks long-lived secrets"; doc 16 §13 + the inject-class split per doc 20 §7.3; D8/D39/D83) |
| `canvas/` | 5 | oss-runnable | `canvas-edits-never-reach-vm`, `canvas-not-an-input-channel`, `canvas-control-rpc-attribution`, `canvas-respects-directory-rights`, `spectator-cannot-inject` (doc 17 §13(c)(1–4) + the re-filed doc 06 §3c read-only-spectate row; D8/D61/D86/D87) |
| `writerseat/` | 5 | oss-runnable | `writerseat-exactly-one-live-seat`, `writerseat-no-drive-without-live-grant`, `writerseat-handoff-attributed-and-observable`, `writerseat-reader-cannot-reach-writer-relay`, `writerseat-attendedness-honest-when-detached` (sessions/10 §5 W5 browser-writer-seat claims, incl. the D137 re-green of the `01KTWJ64M0` no-inject barrier with the `attach.v1` `WriterRelay` write path present; D136/D137/D138/D61/D78/D8/D55) |
| `netisolation/` | 5 | oss-runnable | `netiso-in-vm-spoofing-fails`, `netiso-ech-https-svcb-suppression`, `netiso-session-a-not-b-no-l2-path`, `netiso-ipv6-closure-dormant-fe80-probe`, `netiso-controls-unreachable-from-vm` (doc 06 §3c Stage-2 rows; doc 09 §8–§9 NFT-1/NFT-2/DNS-4/TLS-1; D66/D68/D75) |
| `resolverhardening/` | 1 | oss-runnable | `resolver-hardening-holds-as-unit` (doc 20 §4 claim (1) "resolver hardening holds as a unit"; doc 06 §3c "DNS-gated allow-sets, no bypass"; doc 09 §9 NFT-4/DNS-4 + TLS-1; D42/D68/D70) |
| `identityrows/` | 10 | oss-runnable | `identity-mint-before-attach`, `identity-per-session-ca-isolation`, `identity-issued-cred-routing-asymmetry`, `identity-fleet-revocation-clock`, `identity-validation-failure-structured-403`, `identity-socket-hold-paths`, `identity-attendedness-flip`, `identity-git-https-pin`, `identity-log5-join`, `identity-park-resume-tiers` (doc 16 §13 identity (c) rows; D85) |

The map↔package seam is gated structurally by `scripts/check-guardrail-map-tags.sh` (run
under `make repo-lints`): for every package that single-sources a `const Tag` / `var Tags`
and has a `assurance/guardrail-conformance/<pkg>/**` row in the map, it fails closed on a tag
renamed package-only, renamed map-only, or an orphaned map row whose package dropped the tag
— the seam the per-package `TestTagStable` / `TestTagsStable` guards cannot see (each pins
its package against itself, not the map).

## Governing decisions

- **D26 → D51** — ship publicly; subset = the complete claims table (doc 06 OQ5)
- **D47** — fail-closed guardrail-map scoping
- **D34** — fidelity tags decide nested vs metal execution per row
- **D50** — synthetic fixtures only
- **D85** — OSS identity components exist so the credential claims are OSS-runnable (doc 16 §2)

## What must NOT live here

- **Load/scale machinery** — internal scale-rig tree, not published (D51).
- **Module-private tests** — only advertised-property claims belong in the table.
- **Attack/redteam naming** anywhere in this tree.
- **Embargoed per-incident regressions** — internal until fixed, then graduated here.
- **Wiring to drive real services** — that is `conformance-adapter/`'s job; this package states and asserts claims.

## Neighbors

- `boundary/` — the TDD-time executable spec; as claims go green there, their durable public form lands here as versioned rows.
- `conformance-adapter/` — how this package reaches a real deployment.
- `guardrail-map.yaml` (repo root) — maps diffs to the rows that must gate them.
