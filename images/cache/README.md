# images/cache/ — site-local pull-through cache (deploy config ONLY)

**Owner:** Image & cache builder · **OSS** (D25) · **Decision:** D41

**D41 is a buy, not a build.** Registry caching ships as ONE site-local
pull-through cache — **Nexus Repository CE** by default, with per-ecosystem
OSS fallbacks (Verdaccio / devpi / Athens) if CE limits bite — landing at M2
(doc 05 §5, M2 "host-local package
cache so a fleet pulling deps doesn't stampede a registry"). This directory
holds **deployment configuration only**: the Nexus deploy definition, the
declarative proxy-repository manifest, and the package-manager client config
baked into golden images (`../golden/`) so sessions resolve through the cache.

**Zero registry-protocol code, ever.** The doc 03 §6
idea that "the proxy can implement registry semantics" was evaluated and
rejected (D41): every ecosystem has a maintained off-the-shelf cache, and
daemon protocol work buys nothing the golden image + cache combo doesn't
already deliver. The repo skeleton's anti-scaffold list bans registry-protocol
code repo-wide; a PR implementing npm/PyPI/Go-proxy semantics — here, in
`dataplane/`, anywhere — is wrong by construction. Pre-bake (D12, `../golden/`)
stays the primary mechanism; this cache catches the long tail. A proxy-native
blob cache is deferred pending stampede-simulation data (D41).

## Layout

| Path | What it is |
|---|---|
| `deploy/nexus.container` | Podman Quadlet unit — runs stock Nexus CE on the cache host; pinned image: `docker.io/sonatype/nexus3:3.70.1@sha256:00ecf29c4a3a43d677aec9ff07966e942c4356d9c16a275d94110f6e1e5aca94` |
| `deploy/compose.yaml` | podman-compose / docker-compose equivalent (pick one deploy path) |
| `deploy/repos.yaml` | Declarative per-ecosystem **proxy-repo** manifest (the desired state) |
| `deploy/bootstrap.sh` | Applies `repos.yaml` to a running Nexus via its REST API (idempotent) |
| `wiring/npmrc` · `wiring/pip.conf` · `wiring/go.env` · `wiring/registries.conf` | Client config `../golden/` bakes so sessions resolve through the cache |
| `lint-image-drift.sh` | Drift lint: asserts the stock Nexus image literal is byte-identical between the two deploy paths (`deploy/nexus.container` `Image=` vs `deploy/compose.yaml` `image:`). Exits non-zero printing both values on mismatch, `2` on a missing file/key. Pass `--self-test` to run the internal regression harness (copies `deploy/` to a temp sandbox, verifies the clean copy exits `0`, then injects each recognized drift one at a time and verifies the expected non-zero rc per injection — a diverging `Image=`/`image:` literal drives `1`, a dropped image key or removed deploy file drives `2`; injections are anchored to image-key patterns and the harness aborts non-zero if an anchor is gone, so an upstream line reformat can never silently turn an injection into a no-op). |
| `smoke.sh` | Host-only (`DS_CACHE_SMOKE=1`) cache-hit/miss round-trip test |

### Keeping the two deploy paths in lockstep — `lint-image-drift.sh`

`deploy/nexus.container` and `deploy/compose.yaml` are two definitions of one
desired state: the same stock Nexus CE image, same ports, same volumes. The
image reference is a **hand-synced literal** in each file — the quadlet's
`[Container]` `Image=` line and the compose service's `image:` line — because
neither format can interpolate the other. That hand-sync is the one gap where
the two paths can silently drift to different Nexus versions; a host that picks
the quadlet path and a host that picks compose would then deploy different
images for the same site.

`lint-image-drift.sh` closes that gap: it reads both files and asserts the two
image literals are byte-identical, exiting non-zero and printing both values on
mismatch (and `2` if a file or the image key is missing). Run it after editing
either deploy file:

```sh
sh images/cache/lint-image-drift.sh
```

Pass `--self-test` to run the internal regression harness: it copies `deploy/`
into a temp sandbox (alongside a copy of the lint, so the lint's deploy
resolution points at the sandbox, never the real tree), verifies the clean copy
exits `0`, then injects each of the **`6 recognized drifts`** one at a time and
asserts the lint catches each with the expected exit code — a diverging
`Image=` (quadlet) or `image:` (compose) literal must drive `1` (the two paths
disagree); a dropped image key, or a removed deploy file, must drive `2`.
`--self-test` is dispatched **before** any file-existence check, so it never
reads the real `deploy/` for its own pass/fail and never edits a tracked file
(the sandbox is a copy, cleaned up via an `EXIT` trap). The injections are
**anchored to image-key patterns** (not byte-exact whole lines): if an anchor is
gone — because an upstream line was reformatted — the harness aborts non-zero
instead of silently turning the injection into a no-op.

After the injection arms, `--self-test` runs a **README-token guard** via the
shared `scripts/lint-readme-tokens.sh` helper (the same guard
`images/mirror/lint-env-drift.sh` adopted), which holds several load-bearing
literals in this README in lockstep with their ground truth: (i) the pinned
Nexus image ref in the `deploy/nexus.container` component-table row, with truth
read from that file's `[Container]` `Image=` line; (ii) the drift count quoted
just above, recomputed from the script's `# --- injection` blocks; and
(iii)–(v) the three pull-through **endpoint URLs** in the
"Ecosystem → endpoint → wiring" registry table below (npm / PyPI / Go), each
recomputed from the `wiring/` client config the golden images bake —
`wiring/npmrc` (`registry=`), `wiring/pip.conf` (`index-url =`), and
`wiring/go.env` (`GOPROXY=`) respectively; and (x) the **OCI / containers** row's
`cache.ds.local:5000` endpoint, recomputed from the `[[registry.mirror]]`
location anchored to the `prefix = "docker.io"` `[[registry]]` block in
`wiring/registries.conf` (the extraction enters on that block and captures the
next mirror location, not positional-first — so an enabled ghcr.io / quay.io
mirror ordered before docker.io cannot mis-reconcile). Each token is keyed on a phrase that
must appear on exactly one README line (the endpoint guards anchor on the unique
ecosystem label at the start of each registry-table row), so every value stays
recomputed on every run (never literal-frozen): a one-sided edit to either side
— renaming a proxy repo, bumping the `:8081` port, or bumping the docker.io
mirror location's `:5000` in the README *or* a wiring file alone — fails the
self-test, and a missing or duplicated anchor is itself a structural failure
rather than a silent pass.

`--self-test` is exercised under the standing gate. `make check-image-drift`
runs the lint in its **clean** mode (no flag) to validate the real tree, and a
sibling `make check-image-drift-selftest` leg re-runs every glob-discovered
`images/*/lint-*.sh` under `--self-test` — so the injection arms AND the
README-token guards fire in CI, not only on an on-demand invocation. Both legs
are prerequisites of `make repo-lints` (the `gate-wire-lints` / lintgate wiring
that closed this follow-on); a one-sided README/source token drift now fails CI.
You can still run `sh images/cache/lint-image-drift.sh --self-test` by hand after
editing this script to confirm every drift arm fires.

It reads both files and edits neither; it asserts only that the two literals
agree (not that the ref is digest-pinned — production pins to a digest, see the
`deploy/nexus.container` header). It is self-contained and runnable standalone,
and it is also wired into the standing gate: `make check-image-drift`
glob-discovers and runs every `images/*/lint-*.sh`, so this script and the
mirror drift lint enroll automatically with no Makefile edit (a zero-match glob
fails closed, D47 spirit). `make repo-lints` aggregates that with the doc-links,
SPDX, and fixture-provenance lints, and `.github/workflows/repo-lints.yml` runs
`make repo-lints` directly on every push to main and PR — so the CI and local
gates are the same command and cannot drift. The script itself is owned by this
image tree and only invoked from there — never edited by the gate wiring.

### Lint-script naming convention — `images/*/lint-*.sh`

Every drift-lint script that `make check-image-drift` should discover **must**
be named `lint-*.sh` and live **directly** in its image subdirectory (i.e. match
the glob `images/*/lint-*.sh`). This tree's script, `images/cache/lint-image-drift.sh`,
follows that convention; `images/mirror/lint-env-drift.sh` follows it too.

Rules that keep the gate sound:

- **Name it `lint-*.sh`**: any other name (e.g. `check-drift.sh`, `validate.sh`)
  is silently invisible to the gate.
- **Place it directly under `images/<tree>/`**: scripts in subdirectories are
  not discovered.
- **Zero-match is a hard failure** (D47): if all lint scripts in the tree are
  deleted or renamed away from the `lint-*.sh` pattern, `make check-image-drift`
  exits non-zero immediately rather than treating a missing gate as a pass.
  This property is verified by the hermetic harness in
  `scripts/dispatch/test_image_drift_glob.py`.

Adding a new image tree with a lint script therefore requires only a correctly
named file; no Makefile edit, no `repo-lints` wiring change.

### A related guard — README-vs-source token drift

`lint-image-drift.sh` guards a **deploy-path literal** (the Nexus image
reference, hand-synced between two `deploy/` files). A *different* drift class
is a **load-bearing literal quoted in a README** falling out of sync with the
source it documents (e.g. an accepted-address set or a count derived from
script ground truth). That class has a shared helper,
[`scripts/lint-readme-tokens.sh`](../../scripts/lint-readme-tokens.sh): a lint
script declares each guarded token (name, source-of-truth extraction command,
README anchor regex, value-extraction expr), and the helper does unique-match
anchoring (zero or multiple anchor hits is itself a failure), set
reconciliation, and a drift report — `images/mirror/lint-env-drift.sh` adopts
it in its `--self-test`. This README *does* now quote one source-derived token —
the injection-arm count in the lint-table row above, which `lint-image-drift.sh
--self-test` guards with an **inline** count check (the two wave17b units were
built in parallel, so the script could not yet source the helper).

**wave17b composition status.** Folding that inline guard into the shared
helper (taskdb `01KTZ6GZQR77A4GGV3S6QVKV6E`) was deferred this wave for
files-overlap with the `--self-test` unit itself and re-filed as re-scope task
`01KTZ824SEF3B1S2GRVQA5J4C9`; it now dispatches against the landed script. Two
things to know when adopting: the helper's normal caller path is **sourcing**
(`lrt_set_readme` + `lrt_register` + `lrt_check_all`, exit codes 0 = match /
1 = drift / 2 = structural, structural overrides drift) plus a standalone
`--self-test`; a thin `--check README ANCHOR TRUTH_CMD EXTRACT [NAME]` CLI also
now exists for ad-hoc single-token runs (it registers one token and calls
`lrt_check_all`, same exit codes) — image-tree lint scripts still source and
register directly. The external exit-code contract pin
(`scripts/dispatch/test_lint_readme_tokens.py`, taskdb
`01KTZ6GQGRZP7KNDXR1JW7JPVX`) was dropped at wave17b composition for assuming an
unimplemented CLI; it has since **landed, realigned to the sourcing API**, and
drives the helper through a `bash -c` shim that sources it and calls `lrt_*`, so
a helper refactor cannot silently weaken the rc 0/1/2 contract.

## Ecosystem → endpoint → wiring

The cache fronts the ecosystems the golden images need. Host alias
`cache.ds.local` resolves, **inside the session VM**, to the cache host via the
egress boundary's allow-set (`ds-dnsgate` / `ds-tlsproxy`, D63); ports are
consistent across `deploy/` and `wiring/`.

| Ecosystem | Upstream (reached only on miss) | Host-local endpoint | Wiring snippet |
|---|---|---|---|
| **npm** | `registry.npmjs.org` | `http://cache.ds.local:8081/repository/npm-proxy/` | `wiring/npmrc` |
| **PyPI** | `pypi.org` | `http://cache.ds.local:8081/repository/pypi-proxy/simple/` | `wiring/pip.conf` |
| **Go modules** | `proxy.golang.org` | `http://cache.ds.local:8081/repository/go-proxy/` | `wiring/go.env` |
| **OCI / containers** | `registry-1.docker.io` (Docker Hub) | `cache.ds.local:5000` | `wiring/registries.conf` |

Only live endpoints are in the table above. The two pre-declared,
disabled-by-default OCI upstreams have their reserved endpoints tabled below so
the lint can hold doc and wiring in lockstep — see the OCI note below.

| Pre-declared upstream (disabled by default) | Upstream | Reserved host-local endpoint | Wiring snippet |
|---|---|---|---|
| **OCI / ghcr.io** | `ghcr.io` | `cache.ds.local:5001` | `wiring/registries.conf` (commented stanza) |
| **OCI / quay.io** | `quay.io` | `cache.ds.local:5002` | `wiring/registries.conf` (commented stanza) |

Each `wiring/` snippet is what `../golden/` bakes; each repo in
`deploy/repos.yaml` is a **proxy (pull-through)** repository, never a hosted or
private one — the desired state is "front these upstreams," nothing more.

All four **host-local endpoint** cells above are **guarded**:
`lint-image-drift.sh --self-test` recomputes each from its `wiring/` source and
fails if a row drifts from the config the golden images bake. The npm / PyPI / Go
rows reconcile their whole URL against a single config line — `wiring/npmrc`
(`registry=`), `wiring/pip.conf` (`index-url =`), `wiring/go.env` (`GOPROXY=`).
The **OCI row** reconciles its `cache.ds.local:5000` endpoint against the
`[[registry.mirror]]` location anchored to the `prefix = "docker.io"`
`[[registry]]` block in `wiring/registries.conf` — the extraction enters on that
block and captures the next mirror location (not positional-first), so an
enabled ghcr.io (`:5001`) / quay.io (`:5002`) mirror ordered before docker.io
cannot mis-reconcile, and while those stanzas stay commented they never
false-trip the guard. Edit an endpoint cell here **and** its wiring source
together — a one-sided change (renaming a proxy repo, bumping `:8081`, or
bumping the docker.io mirror location's `:5000`) fails the self-test.

The two pre-declared **ghcr.io** / **quay.io** OCI upstreams get their own
per-upstream guards, each gated on its `wiring/registries.conf` stanza being
active: while commented the guard skips (the shipped default), and once a
stanza is uncommented the guard reconciles that upstream's reserved-endpoint row
(in the disabled-by-default table above) against its now-active mirror location.

Every row's **endpoint `:PORT`** is *additionally* guarded per-row against the
deploy source of truth — the `PublishPort=` host ports in
`deploy/nexus.container` (`8081` for the npm/PyPI/Go core face, `5000` for the
OCI connector). This narrower guard backs the OCI row's full-endpoint guard
above: the full-endpoint arm catches a drifted host or a one-sided edit of the
`registries.conf` mirror location, while the port arm independently catches a
`PublishPort=` / README port bump on the deploy side — so the OCI row no longer
has any un-reconciled endpoint cell.

Two further OCI upstreams — **ghcr.io** (GitHub Container Registry) on connector
port `:5001` and **quay.io** on `:5002` — are pre-declared in
`deploy/repos.yaml` and `wiring/registries.conf` but ship **disabled by
default** (commented out): no golden image currently pulls from either, so the
definitions stay defined-but-unopened rather than holding live unused ports.
Each follows the docker-proxy convention — one distinct connector per upstream
(`:5000` Docker Hub / `:5001` ghcr.io / `:5002` quay.io, one mirror fronts one
upstream) with the same cache-everything-pulled (D41) pull-through semantics.
Enabling one means uncommenting its `repos.yaml` repo plus its `registries.conf`
mirror pair **and** adding the matching `create_proxy` call to
`deploy/bootstrap.sh` (which today hardcodes the repo set rather than reading
`repos.yaml`); all three must agree on the connector port. Uncommenting a stanza
also **activates its per-upstream lint guard**: clean-mode `lint-image-drift.sh`
then reconciles the reserved-endpoint row above against the now-active
`[[registry.mirror]]` location (a one-sided edit of either fails the gate) —
while the stanza stays commented the guard prints a clean skip, and
`--self-test` pins the commented stanza and its row in lockstep via
stanza-activation arms.

## The cache-miss upstream path

1. A session VM client (npm / pip / `go` / podman) resolves a package against
   its baked wiring snippet — a **host-local** endpoint, plain HTTP, behind the
   boundary. The VM never names a public registry.
2. **Cache hit:** Nexus serves the stored blob. No upstream traffic. This is the
   steady state once an image generation's deps are warm.
3. **Cache miss:** Nexus (on the cache host, not the VM) fetches from the
   declared upstream over TLS, stores the blob, and serves it. The cache host —
   not the session — is the only component that holds upstream registry
   reachability. **Upstream is touched only on a miss**, which is the whole
   point: a fleet of VMs pulling the same deps stampedes the cache once, not the
   public registry N times (doc 05 §5).
4. Module/package **integrity is preserved**: Go's checksum-db passthrough
   (`GOSUMDB=sum.golang.org`) rides through the proxy; npm/PyPI metadata is
   served verbatim from upstream on the miss that populates it.

Pre-bake (D12, `../golden/`) stays primary — most deps are already on disk in
the golden image; the cache is the fallback for what isn't baked and for the
nightly-rebuild pulls.

## The D41 boundary: no registry semantics in the proxy

The egress boundary (`ds-tlsproxy` / `ds-dnsgate`, D63) **does not** implement
registry semantics — §6 D41 and the
boundary scope row are explicit: "No registry semantics (D41 — package caching
is an external pull-through cache wired via golden-image config)." The boundary
treats the cache host as an ordinary allowed endpoint; all caching logic lives
in the stock Nexus instance this directory deploys. Nothing here, and nothing in
`dataplane/`, parses or serves a registry protocol. That line is structural, not
a preference — it is why this tree is **deploy config + client wiring only**.

## Fallback decision point: Verdaccio / devpi / Athens

Nexus CE is the **default** because one instance fronts all four ecosystems with
one deploy and one declarative manifest (D41). The per-ecosystem OSS stack is the
**fallback, taken only if CE limits bite** — concretely, the decision point is:

- **npm → [Verdaccio](https://verdaccio.org/)**, **PyPI → [devpi](https://www.devpi.net/)**,
  **Go → [Athens](https://docs.gomods.io/)**, OCI → a registry mirror
  (e.g. the CNCF `distribution` registry in pull-through mode).
- **Trigger to switch:** a hard CE constraint that the single-host buy can't
  carry — e.g. CE concurrent-connection or storage ceilings throttling a real
  fleet, or a licensing/operational limit surfaced at M2 load. The trigger is a
  measured limit, not a preference; absent one, the buy stands (D41).
- **Cost of switching:** trades one deploy + one manifest for **four** smaller
  per-ecosystem services, each with its own deploy unit and wiring. The wiring
  snippets stay the same *shape* (registry/index/GOPROXY/mirror URLs) — only the
  host-local endpoints change — so `../golden/` consumes the same contract either
  way. That decoupling is deliberate: the fallback is a deploy swap, never a
  golden-image rewrite.

Still buy-not-build under the fallback: Verdaccio/devpi/Athens are off-the-shelf
caches too. The D41 invariant (no registry-protocol code of ours) holds on both
paths.

## Deploy (single host)

The cache runs on one site-local infrastructure host (not a session VM):

```sh
# Quadlet path (systemd):
cp images/cache/deploy/nexus.container /etc/containers/systemd/
systemctl daemon-reload && systemctl start nexus

# ...or compose path (pick ONE, not both):
podman-compose -f images/cache/deploy/compose.yaml up -d

# Once the status endpoint is green, provision the proxy repos:
NEXUS_PASS=$(podman exec ds-cache-nexus cat /nexus-data/admin.password) \
  images/cache/deploy/bootstrap.sh

# Verify on the host (never in CI):
DS_CACHE_SMOKE=1 images/cache/smoke.sh
```

`smoke.sh` is **fail-closed**: without `DS_CACHE_SMOKE=1` it exits without
touching anything, so CI and stray invocations are no-ops. It drives the cache
through stock clients/curl — it asserts a warm cache hit per ecosystem; it
implements no registry protocol (there is none, D41).

The order is load-bearing: start the container, wait for
`/service/rest/v1/status` to go green (the deploy unit's `HealthCmd` /
compose `healthcheck` gate this), retrieve the first-boot admin password,
then run `bootstrap.sh` (it also re-polls `status` before provisioning) and
finally `smoke.sh`. Running `bootstrap.sh` before the status endpoint is up
just retries until it gives up; `smoke.sh` before `bootstrap.sh` reports
misses with no warm hit. Both scripts are idempotent and host-only.

## Neighbors

| Tree | Relation |
|---|---|
| `../golden/` | Bakes the `wiring/` snippets into golden images (D12 pre-bake primary; cache is the long-tail fallback) |
| `dataplane/` (Boundary, D63) | Treats the cache host as an allowed endpoint; implements **no** registry semantics (D41) |
| `../README.md` | Image & cache builder charter (owner, OSS D25, D17/D23/D41/D49) |
