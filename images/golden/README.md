# images/golden/ — golden-image build definitions & nightly pipeline

**Owner:** Image & cache builder · **OSS** (D25) · **Decisions:** D12, D17, D23, D29, D49

Build definitions and the nightly pipeline for golden images
(doc 03 §6):
CI runs ahead of time and snapshots — latest master, dependencies running,
node_modules on disk, server built — **per repo/branch**, cached for next
time. Pre-seeding is opt-in per repo. The image is the raw base disk under
every session's qcow2 overlay (D29) and the supply-chain integrity statement
for everything baked into it. On-ramp: reuse the customer's existing CI
(D23, primary on-ramp).

## The CI → golden-image pre-bake (doc 03 §6, D12)

`prebake.sh` is the bake orchestration for the doc 03 §6 pre-bake path: CI
snapshots node_modules + build artifacts into the golden VM image **per
repo/branch**, so a session created from that branch boots with dependencies
already on disk — no network stampede, no cold build (the doc 05 §5 M2
"instant start" headline). The bake is shell over the D29 disk stack:

1. **clone** a throwaway golden overlay from the raw base (driving
   `../../vm/cow/overlay-create.sh` — the same raw-base + per-session-qcow2
   stack the session create path uses);
2. **warm** the overlay by running the repo's install/build steps inside it
   (node_modules on disk, build cache warm);
3. **commit** the warmed overlay as the per-repo golden image (one per
   repo+branch), written to the configured output dir.

### Opt-in, default OFF (D12)

Pre-seeding is **optional and per-repo configurable** — "most users don't want
every repo baked into every box; an org standardizing on a monorepo absolutely
does" (doc 03 §6). v0 environments stay **dynamic** (no golden-image
requirement); pre-bake is the M2 optimization, not the default (D12). A
(repo, branch) is baked ONLY when the config has BOTH a top-level
`enabled: true` AND a `repos[]` entry with `prebake: true`. An unconfigured
repo — absent, opted out, or with the global switch off — is left **untouched**:
`prebake.sh` prints a skip and exits 0 without invoking any bake step. The
schema is documented in [`prebake.config.example.yaml`](prebake.config.example.yaml);
the default example config ships with `enabled: false`.

```sh
# Print the plan a configured (repo, branch) would drive — no live tools:
images/golden/prebake.sh --config <cfg.yaml> --repo <repo> --branch <branch> --dry-run
# Plan every opted-in (repo, branch) in a config:
images/golden/prebake.sh --config <cfg.yaml> --all --dry-run
# CI/sandbox config-gating regression against committed synthetic fixtures:
images/golden/prebake.sh --self-test
```

### The `DS_GOLDEN_BAKE_LIVE` gate — deferred manual step

The clone/warm/commit legs touch real on-disk images and (for the warm step)
spin a libguestfs/qemu appliance, so they run **only** when
`DS_GOLDEN_BAKE_LIVE=1`:

```sh
# LIVE bake (operator host, with the raw base image present) — a deferred manual step:
DS_GOLDEN_BAKE_LIVE=1 images/golden/prebake.sh \
    --config images/golden/prebake.config.yaml --repo <repo> --branch <branch>
```

Without `DS_GOLDEN_BAKE_LIVE=1` (CI, the sandbox) `prebake.sh` invokes **no**
live tools: it resolves the config, decides configured-vs-unconfigured, and
(with `--dry-run`) prints the PLAN it would execute. There is **no** live
`claude` / `qemu` (VM-run) / `podman` invocation anywhere in this tree. The
CI lane that runs the pre-bake for configured repos is
`.github/workflows/golden-image.yml`:
`workflow_dispatch` + config-gated, plan-only, and **never** sets
`DS_GOLDEN_BAKE_LIVE`, so it cannot fire a live bake by default. That "never
sets the gate" promise is mechanized by
[`lint-no-live-bake.sh`](lint-no-live-bake.sh) (run by `make repo-lints`), which
fails closed if any committed workflow or composite Action actually assigns the
gate. Its check is **per-file** (a setter in any one file), not a
`workflow_call` call-graph proof — sound today because no committed reusable
workflow threads the gate; see the script header's *Scope boundary* note.

### Tests & fixtures

`prebake.sh --self-test` proves the config-gating logic offline: a configured
repo drives the bake (a dry-run plan is emitted), an unconfigured/opted-out
repo is skipped/untouched, and the global kill-switch short-circuits an
otherwise-opted-in repo. It also asserts that **both** live legs — the bake and
the optional `--smoke` end-to-end check below — **refuse without
`DS_GOLDEN_BAKE_LIVE=1`**, so neither can fire in CI/sandbox. The synthetic
config fixtures it drives live in `prebake_selftest/` (all `synthetic` per D50,
each with a `.provenance` sidecar and a directory `PROVENANCE.md`).

### The `DS_GOLDEN_BAKE_LIVE` bake smoke — operator-host-only runbook (PROVEN)

`prebake.sh --smoke` is the **optional, operator-host-only** end-to-end check
that the clone → warm → commit → publish procedure actually produces a
**session-cloneable** golden. It is gated exactly like the bake: it **refuses
without `DS_GOLDEN_BAKE_LIVE=1`** and **never auto-runs** in CI or the sandbox
(the `--self-test` pins that refusal). It is a **deferred manual step** an
operator runs on the M0 operator host, where a real raw base image exists.

> **Provenance.** This procedure was **run and PROVEN on the M0 operator host**.
> The smoke drives the *same* `live_bake()` the production/snapshot/nightly
> paths defer to, against a real `m0-base.raw`, with a **trivial** `warm_steps`
> of `["true"]` (a no-op warm — we are proving the clone/warm/commit/publish
> plumbing and the self-contained-raw invariant, not a real dependency warm).

The proven legs, in order:

1. **clone** — `overlay-create.sh` clones a throwaway golden overlay from the raw
   `m0-base.raw` base (qcow2 whose read-only backing file is the raw base; the
   backing invariant is asserted and the base is chmod'd `0444`).
2. **warm in-overlay** — `virt-customize` runs the `["true"]` warm step **inside
   that overlay** via the libguestfs appliance — it mounts the overlay's
   filesystems and execs the step against them, then unmounts. **No VM is
   booted.** This warm leg runs in the **operator-host** network context, *not*
   a per-session VM behind the egress gateway — see the egress note below.
3. **commit (rebase -u + commit)** — the warmed overlay is a delta on top of the
   read-only raw base, so we materialize the golden as `base ⊕ warmed-delta`:
   `cp` the raw base to a private copy, `qemu-img rebase -u -F raw -b <copy>`
   re-labels the overlay's backing pointer (no data rewrite — the bytes are
   identical), and `qemu-img commit` folds the overlay delta down onto the copy.
4. **atomic publish** — the materialized golden is built at a temp path and
   `mv`'d into place, so a reader/rotation-stat never sees a half-written golden.
   The published golden is a **self-contained raw image** with the (here no-op)
   warm marker baked in — it carries **no qcow2 backing chain of its own**.
5. **assert session-cloneable** — the smoke then drives `overlay-create.sh
   --base <published-golden> -F raw` to clone a fresh per-session overlay from
   the published golden. A successful clone **is** the proof of the
   self-contained-raw invariant: a session overlay can back onto the golden with
   `-F raw`, with no missing backing chain. (The probe overlay is removed.)

```sh
# Operator host only, real raw base present. REFUSES without the gate.
DS_GOLDEN_BAKE_LIVE=1 images/golden/prebake.sh --smoke \
    --base /var/lib/ds/golden/m0-base.raw \
    --out  /var/lib/ds/golden/prebaked

# --base / --out default to DS_GOLDEN_BASE_IMAGE / DS_GOLDEN_OUTPUT_DIR.
# A synthetic (repo, branch) of ds-smoke/smoke @ smoke keeps the smoke golden
# from colliding with any real opted-in golden.
```

**Egress (operator-host context, NOT the per-session boundary).** The warm leg
(step 2) runs in the libguestfs **appliance on the operator host** — it is *not*
a boundary-gated session VM behind `ds-dnsgate` / `ds-tlsproxy`, and it inherits
the operator host's network context. Any network a warm step needs must be
fronted by the **operator host's own egress policy** and pointed at the same
**D41 Nexus pull-through cache** URLs the golden bakes in; the warm leg
**bypasses** the per-session egress gateway entirely. (The `["true"]` smoke
makes no network call, so this is moot for the smoke itself — but it is the
binding constraint for any real warm_steps; see
doc 03 §6.)

## The GitHub Actions snapshot step (D55, doc 07 §1/§3)

D55 makes GitHub the first integration bundle (Actions + source host + token
swap). The way a team adopts pre-baking is to hang a snapshot step off the
**end of its existing build job** — the doc 03 §6 / doc 07 §2a-spec CI-to-golden
loop: the build they already trust (deps installed, caches warm, artifacts
built in the workspace) becomes the workspace a "session from this branch"
boots from. Teams never re-describe their build.

Two pieces ship for this:

- **`.github/actions/golden-snapshot/action.yml`** — a composite GitHub Action a
  team adds after its build job. It resolves the `(repo, branch)` (from inputs
  or the runner's `GITHUB_REPOSITORY_URL` / `GITHUB_REF_NAME`) and invokes the
  snapshot for it. **Dry-run by default** (`dry-run: "true"`), so wiring it in
  fires no live bake. The Action locates `snapshot-step.sh` by a **fixed 3-level
  relative climb** from `GITHUB_ACTION_PATH`
  (`…/golden-snapshot/../../../images/golden/snapshot-step.sh`), so it is
  coupled to this repo's layout: if the action directory's depth or
  `snapshot-step.sh`'s location moves, that climb must be updated. The Action
  asserts the resolved target **exists** before touching it, so a layout drift
  fails the step **loudly** rather than exec-ing a wrong path (see the inline
  `::error::` in `action.yml`).
- **`snapshot-step.sh`** — the entry the Action calls. It is a thin
  `(repo, branch) → config → prebake.sh` adapter: it **delegates** all gating
  and the bake legs to `prebake.sh` (the config-gating and the
  `DS_GOLDEN_BAKE_LIVE` gate are reused, never duplicated). It can also run
  standalone (`--repo`/`--branch`) and ships a `--self-test`.

### How a team adds it

Append the Action to the CI job that already builds, after the build steps:

```yaml
# .github/workflows/<their-pipeline>.yml — in the existing build job:
      - name: Build
        run: npm ci && npm run build
      # Hang the Dream Serpent snapshot step off the end of the build:
      - name: Dream Serpent golden-image snapshot
        uses: dream-serpent/dream-serpent/.github/actions/golden-snapshot@<pinned>
        with:
          config: images/golden/prebake.config.yaml   # the team's opt-in config
          # repo/branch default to the runner env; dry-run defaults to "true".
```

The Action (and its snapshot step) are reviewed and version-pinned in the §2b
onboarding PR exactly like any other CI action (doc 07 §2a-spec). It adds no new
authority — it reads a committed config and, in CI, only prints a plan.

### Opt-in config (default OFF, D12)

The Action bakes **nothing** by itself. `snapshot-step.sh` → `prebake.sh` bakes
a `(repo, branch)` ONLY when the `config` has BOTH the global `enabled: true`
AND a `repos[]` entry for that repo carrying `prebake: true` (schema:
[`prebake.config.example.yaml`](prebake.config.example.yaml)). A repo that is
absent, opted out, or under a globally-disabled config is left **untouched** —
the step prints a skip and exits 0. A team opts a repo in by editing the
committed config; until then the wired-in Action is a clean no-op. With no
`config` input, the Action defaults to the example config (global `enabled:
false`), so the step is a no-op rather than an error.

### Dry-run vs `DS_GOLDEN_BAKE_LIVE`

```sh
# What the Action runs in CI (dry-run): print the plan, fire NO live bake.
images/golden/snapshot-step.sh --config images/golden/prebake.config.yaml --dry-run
# Inside GitHub Actions, --repo/--branch default to GITHUB_REPOSITORY_URL /
# GITHUB_REPOSITORY and GITHUB_REF_NAME, so a team passes neither.

# Self-test the adapter offline against the committed synthetic fixtures:
images/golden/snapshot-step.sh --self-test

# LIVE bake — a DEFERRED MANUAL operator-host step (NOT CI): set the gate AND
# turn the Action/script off dry-run. snapshot-step.sh passes the gate through
# to prebake.sh; the composite Action NEVER sets DS_GOLDEN_BAKE_LIVE itself.
DS_GOLDEN_BAKE_LIVE=1 images/golden/snapshot-step.sh \
    --config images/golden/prebake.config.yaml --repo <repo> --branch <branch>
```

The live qemu/libguestfs clone/warm/commit legs run **only** under
`DS_GOLDEN_BAKE_LIVE=1` (the same gate as `prebake.sh` — see above). The
composite Action's `dry-run` input defaults to `"true"` and the Action never
sets `DS_GOLDEN_BAKE_LIVE`, so the CI default path is plan-only and a real bake
is an explicit operator decision off the CI default. The CI lane
`.github/workflows/golden-image.yml`
carries a `golden-snapshot-action-sample` job that invokes the composite Action
in dry-run against a configured synthetic sample repo (and shows an
unconfigured repo skipping) — proving the wiring without ever baking.

## The nightly golden-image rebuild + rotation policy (doc 03 §6 "Nightly golden images")

> A nightly job rebuilds the image all devs work from. Combined with short-lived
> environments, this *dissolves* the patching problem for dev boxes: when a CVE
> drops you roll the image, and no instance lives long enough to drift. (The
> five-year-old unpatched dev box stops existing.) — doc 03 §6 "Package & build
> caching",
> "Nightly golden images" bullet

This is the Image & cache builder's **nightly rebuild cadence**
(doc 05 §3, M1). Where `snapshot-step.sh`
re-bakes on a team's *build*, the nightly job re-bakes on a *clock*, so the
golden every session clones (D29) carries the latest patched master + warmed
deps without waiting for a push. It ships as:

- **`nightly-rebuild.sh`** — the rebuild orchestration. It does NOT re-implement
  the bake: it delegates the re-bake of every opted-in `(repo, branch)` to
  `prebake.sh --all` (the global `enabled:`/per-repo `prebake:` config-gating and
  the `DS_GOLDEN_BAKE_LIVE` gate are **reused, never duplicated**). It adds
  exactly two things on top: the nightly framing (the thing the cron fires) and
  the **rotation policy** below.
- **`.github/workflows/golden-image-nightly.yml`** — the scheduled lane:
  `schedule` (cron) + `workflow_dispatch`, `permissions: contents: read`,
  **dry-run/plan by default**, and it **never** sets `DS_GOLDEN_BAKE_LIVE`, so a
  scheduled run can only report rotation + print a plan, never fire a live bake.

### The rotation policy — the CVE-roll SLA

The doc 03 §6 "Package & build caching"
"Nightly golden images" bullet turns CVE response into image rotation: *no
instance lives long enough to drift*. "CVE-roll SLA" is this tree's name for the
enforceable form of that bullet — it is not a doc 03 section title — a
**freshness / max-age check**: a golden a session clones from is never older than
the **rotation window**.

- **Rotation window** = `DS_GOLDEN_MAX_AGE_HOURS` (default **24h** — the nightly
  cadence). A golden whose mtime is older than the window is **STALE** and MUST
  be rolled (re-baked) before any new session clones from it.
- An opted-in `(repo, branch)` whose golden does not exist on disk is **MISSING**
  — it cannot back a session until the first bake produces it.
- A present golden whose mtime is in the **future** (so `now − mtime` is negative
  and the freshness arithmetic is undecidable) is **UNROTATABLE**: an undecidable
  golden is a breach, never a silent `FRESH`. This is the same verdict the public
  conformance claim models (`assurance/guardrail-conformance/goldenfreshness`
  `ViolationUnrotatable`), so the runtime classification matches the published
  claim (runtime == claim).
- The check is offline and deterministic (a filesystem `stat` + arithmetic over
  the per-`(repo, branch)` golden under the config's `output_dir`); it never
  opens an image. A breach (any STALE, MISSING, or UNROTATABLE golden) returns a
  non-zero rotation code (`3`) so a monitor/operator acts — the **CVE-roll SLA**
  is *roll within one rotation window*; combined with short-lived sessions, a
  patched re-bake means no live instance can outlive the window on a stale base.

### Dry-run vs `DS_GOLDEN_BAKE_LIVE`

```sh
# Nightly rotation report + dry-run re-bake plan for every opted-in golden:
images/golden/nightly-rebuild.sh --config images/golden/prebake.config.yaml --dry-run
# Just the rotation/freshness verdict (exit 3 on a breach — e.g. for a monitor):
images/golden/nightly-rebuild.sh --config images/golden/prebake.config.yaml --check-rotation
# Override the rotation window (hours):
DS_GOLDEN_MAX_AGE_HOURS=12 images/golden/nightly-rebuild.sh --config <cfg> --check-rotation

# Self-test the rebuild + rotation logic offline (synthesizes stale/fresh/missing
# goldens in a temp dir — no committed fixtures, no live tooling):
images/golden/nightly-rebuild.sh --self-test

# LIVE nightly re-bake — a DEFERRED MANUAL operator-host / self-hosted-runner
# step (NOT hosted CI): set the gate. nightly-rebuild.sh passes it THROUGH to
# prebake.sh --all; the scheduled workflow NEVER sets DS_GOLDEN_BAKE_LIVE itself.
DS_GOLDEN_BAKE_LIVE=1 images/golden/nightly-rebuild.sh --config images/golden/prebake.config.yaml
```

The live qemu/libguestfs clone/warm/commit legs run **only** under
`DS_GOLDEN_BAKE_LIVE=1` (the same gate as `prebake.sh`). With the default
example config (global `enabled: false`) the nightly run is a no-op: it reports
"no goldens to rotate" and bakes nothing, demonstrating the opt-in posture (D12
dynamic default). An org that has committed a `prebake.config.yaml` with
opted-in repos sees its goldens' freshness reported every night, and rolls a
stale one with the deferred `DS_GOLDEN_BAKE_LIVE=1` operator step.

### Tests & fixtures

`nightly-rebuild.sh --self-test` proves the policy offline: a configured config
drives the re-bake plan through `prebake.sh --all`; a synthetic **STALE** golden
(mtime backdated past the window) is flagged and returns non-zero; a **FRESH**
golden is within the window; a **MISSING** golden (opted in, never baked) is
flagged; an **UNROTATABLE** golden (mtime in the future ⇒ negative age) is
flagged and the runtime verdict token is asserted byte-for-byte equal to the
public claim's `ViolationUnrotatable` (runtime == claim); an **awk-reader fuzz
matrix** varies the config readers' key order, indentation depth, and benign
whitespace across several synthetic configs and asserts every reader extracts the
same values (parsing hardened against format drift); the globally-disabled config
is a clean rotation no-op; and the live re-bake refuses without
`DS_GOLDEN_BAKE_LIVE=1`. It synthesizes the goldens in a temp directory (the way
`vm/cow/overlay-create.sh --self-test` synthesizes its base+overlay), so it needs
no committed fixtures and drives the same synthetic opt-in configs in
`prebake_selftest/` (D50).

**Image identity × role layers (doc 18 OQ3):** the content-addressed image ID
is computed here. Whether a session role's tool layers (doc 18 §2 axis a) join
that identity is settled — freeze-gate waived (no `CloneFromImage` field, D107),
composition **PROPOSED** in [`IMAGE-IDENTITY.md`](IMAGE-IDENTITY.md): the
role-layer set folds into the content-addressed ID
(`(repo, ref, env-spec hash, role-layer-set hash)`), sharing the doc 15 OQ3
`content_hash` canonicalizer; skills stay an overlay input, never in the ID.
Proposed, pending ratification.

## D17 hook: per-session CA trust-store injection — fail-closed

TLS interception is full-visibility egress by default via a **per-session CA in the
golden-image trust store** (D17). The image build leaves a defined injection
hook; at session create the host agent injects the session's CA bundle
(doc 15 §4.1 step 7, `SessionMaterial` in `VmSpec`) — **fail-closed**: no
injected trust anchor, no session. The mint lives in `identity/mint/`
(D82, two hierarchies); this pipeline never generates CA material, it only
provides the injection point. Cert-pinned clients ride the D17 pass-through
list (opaque tunnel, no cred swap) rather than a trust-store hack.
Trust-store injection is a doc 06 level-(c) guardrail-assurance row — the
hook's behavior is conformance-tested, not just documented.

## D49 pin: the Claude Code version

The image pins the CC version (D49) so unreviewed protocol drift cannot reach
production. Bumping the pin is coupled to a golden-trace cassette review in
`client/goldentrace/` (nightly CC-latest canary surfaces drift on schedule).
Pin lives in the image definition; the adapter and the pin move together.

Other baked-in config: package-manager cache URLs pointing at `../cache/`
(D41), HTTPS-pinned git remotes (D83's "may pin" allowance, doc 05 §3).
