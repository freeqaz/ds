# images/mirror/ — host-local git mirror (deploy config + helper scripts ONLY)

**Owner workstream:** Image & cache builder (doc 05 §3) ·
**License:** OSS tooling (Apache-2.0, **D25**) ·
**Governing decisions:** D12, D17, D25, D29, D49, D83 (doc 04 §6);
source design doc 01 §3 (host feature row),
doc 04 §2 host sketch ("Local git mirror · image & package cache"),
doc 03 §6.

## Charter

The **host-local git mirror**: bare mirror clones of the repos a host's
sessions work on, kept warm on local disk and served **read-only,
host-locally** so that session creates and per-VM git worktrees clone from the
host instead of stampeding the upstream source host. This is the named row in
the doc 01 §3 "Host capabilities
(target feature set)" table ("Local git mirror on the host"), and the left half
of the doc 04 §2 host sketch line
*"Local git mirror · image & package cache."*

This directory holds **deployment configuration and operator helper scripts
only** — there is **zero daemon/service code here** (no new Go module, no Rust
crate, no long-running process we wrote). The refresh loop is a systemd
timer + oneshot; the read-only serve face is stock `git-http-backend` behind a
minimal HTTP server, run as a podman quadlet. Everything in `deploy/` is
config-as-code in the same spirit as `../cache/` (D41 buy-not-build): we wire
and schedule off-the-shelf git, we do not reimplement it.

### Why it exists — the stampede the mirror absorbs

- **M2 instant-start** ("create a session from this branch",
  doc 03 §6):
  session-create resolves a `(repo, branch, build_commit, env_spec_hash)` tuple
  and boots from a golden/base image
  (doc 07 "Golden-image resolution policy"),
  but the
  source the agent works against **comes from a repo clone at the requested
  branch tip** — doc 07's onboarding/precondition rule that "the branch tip
  governs" and the clone is "at the requested branch" (the create choreography
  that consumes it is doc 15 §4.1).
  Sourcing that clone from a warm host-local mirror removes a network round-trip
  to the upstream source host from the critical path of every create.
- **M3 subagent fan-out** (doc 05 §5 M3):
  the D18 wrapper "launches subagent / workflow calls in their
  **own VMs with git worktrees** instead of same-box subprocesses — this is how
  we scale compute," and "each fanned-out subagent gets its own VM + identity."
  One human prompt can therefore become *N* fresh worktree clones on one host
  within seconds. Without a mirror, that fan-out is a clone stampede against the
  upstream source host (the same shape doc 03 §6 names for "local git worktrees
  slamming the CPU with five fresh rebuilds"). The host-local mirror turns *N*
  upstream clones into **one** periodic mirror fetch plus *N* fast local clones.

## The session-create clone path

```
                          ┌──────────────────── Bare-metal host ─────────────────────┐
                          │                                                          │
upstream source host      │   git-mirror (this tree)                                 │
(github.com, GHE, …)      │   ┌──────────────────────────────────────────────┐       │
        ▲                 │   │  mirror root  $DS_MIRROR_ROOT                 │       │
        │ periodic fetch  │   │    <repo>.git   (bare --mirror clone)        │       │
        │  (timer; rides  │   │  refreshed by ds-mirror-refresh.timer        │       │
        │  the egress     │◄──┼──┐                                           │       │
        │  gateway)       │   │  │ served read-only on                       │       │
        └─────────────────┼───┘  │ http://127.0.0.1:$DS_MIRROR_PORT/<repo>.git│      │
                          │      │ (git-http-backend, GET/upload-pack only)  │       │
                          │      └────────────┬──────────────────────────────┘       │
                          │  ┌─ Agent VM (per session / per subagent worktree) ─┐    │
                          │  │  git clone http://<host-local>/<repo>.git …       │    │
                          │  └───────────────────────────────────────────────────┘   │
                          └──────────────────────────────────────────────────────────┘
```

1. **Refresh (host → upstream).** `ds-mirror-refresh.timer` fires
   `mirror.sh refresh-all`, which runs `git -C <repo>.git remote update --prune`
   for every bare mirror under the root. First-time enrolment is
   `mirror.sh add <upstream-url>`, a `git clone --mirror`.
2. **Serve (host-local, read-only).** `git-http-backend` exports the mirror root
   over `http://127.0.0.1:$DS_MIRROR_PORT` with only the fetch verbs enabled
   (`git-upload-pack` / dumb GET); `receive-pack` (push) is never exported. The
   listener binds **host-loopback only** — the `lint-env-drift.sh` bind
   assertion requires the serve `PublishPort=` address to be a loopback
   address from the accepted set {`127.0.0.1`, `[::1]`} and rejects anything
   wider (e.g. `0.0.0.0`); the VMs reach it on
   their host-local gateway address, never the public internet.
3. **Clone (VM → host).** session-create (and, at M3, each subagent worktree
   spawn) clones the requested branch from the host-local mirror URL instead of
   the upstream. Cold mirror miss (repo not yet enrolled, or a ref newer than
   the last refresh) falls through to an on-demand `mirror.sh add` / refresh,
   which is the *only* path that touches upstream.

The exact wiring of *which* URL session-create hands the VM (mirror vs.
upstream passthrough, and the env-spec field that selects it) is the
orchestrator's to record (doc 15); this
tree owns the mirror endpoint and its contents, not the create choreography.

## In-VM mirror alias — `mirror.ds.local` (this tree's registered alias class)

doc 15 §4.1
and doc 15 §9
say the in-VM clone URL reaches this serve face "by the same host-alias-class
mechanism the package cache uses, `images/cache/`'s `cache.ds.local`, on the
mirror's own endpoint," and leave **the exact in-VM alias to this tree to own**;
doc 13 §4 `git_mirror.serve_addr`
records the host-side serve-face fact and points here for that alias. This
section is that registration — the named **`mirror.ds.local`-class** alias is
**owned here**, distinct from the cache's `cache.ds.local` and on its own
endpoint/port.

| Service | In-VM host alias | Host-local serve face | Scheme / verbs |
|---|---|---|---|
| **git mirror** (this tree) | `mirror.ds.local` | `$DS_MIRROR_ADDR:$DS_MIRROR_PORT` (`127.0.0.1:8418`) | `http://mirror.ds.local:8418/<repo>.git` — `git-upload-pack` / smart GET only |

How the alias resolves — the same shape as the cache's `cache.ds.local`:

- **Inside the session VM**, `mirror.ds.local` resolves through the egress
  boundary's allow-set (`ds-dnsgate` / `ds-tlsproxy`, **D63** — the two-service
  boundary split) to **this host's** git-mirror serve face on the per-session
  guest's host-local gateway address. The VM never names a public address and
  never reaches the host loopback directly; the boundary, not the bind address,
  is the network-control authority.
- The serve face itself binds **host-loopback only** (`PublishPort=127.0.0.1:8418`,
  lint assertion 6 — see below), so the alias is the *only* way a VM reaches it.
  This is the loopback-bind posture the doc 03 §6
  cache serve-face bind-posture audit records as the mirror's deliberate
  asymmetry from the shared cache (the mirror serves only its own host).
- The alias names a **fetch-only, read-only** target: `git-upload-pack` and dumb
  GET are reachable; `git-receive-pack` (push) is never exported
  (`GIT_HTTP_RECEIVE_PACK=0`) and the mount is `:ro` (**D83** boundary/egress
  posture; mirror is structurally pull-only).
- It is a **distinct alias class** from the package cache's `cache.ds.local`
  (**D41** — the cache is buy-not-build registry semantics; this is git-repo
  mirroring, complementary, no overlap) on its **own endpoint/port** (`:8418`,
  not the cache's `:8081`/`:5000`). The in-VM clone is plain **`http://`** to the
  loopback serve face (TLS terminates at the boundary, not at this CGI — the same
  `http://cache.ds.local`-class shape the package cache uses); it differs from an
  upstream clone only by host (`mirror.ds.local` vs. `github.com`), not by verb —
  both are fetch-only (`git-upload-pack`). The **upstream** remote the mirror
  fetches from is the one pinned to HTTPS (**D83**, HTTPS-remote pinning; no
  `ssh://`), so the credential-swap and scanning planes always apply.

The per-session choice of *whether* a VM is handed `mirror.ds.local` vs. the
upstream URL is the orchestrator's `mirror_source` env-spec selector (doc 15 §9,
PROPOSED) — not this tree's; this tree owns the alias target, not the selection.

## Credential / egress posture — the mirror holds no long-lived upstream creds

Mirror-to-upstream **fetch traffic rides the boundary credential-swap path**
(the TLS-terminating **egress gateway**, `ds-tlsproxy`;
doc 16 §5, **D83** — the
generic Authorization-header swap seam). The mirror refresh runs as an ordinary
on-host workload whose egress is gated and credential-swapped exactly like a
session's: it presents a short-lived workload credential, and the egress
gateway substitutes the real upstream credential outside the trust boundary.

Consequences, asserted not hoped:

- **The mirror stores no long-lived upstream credentials of its own.** There is
  no PAT, no SSH key, no `.netrc`, no `credential.helper` secret on the mirror
  host. If the mirror host is compromised, nothing worth rotating leaks — the
  same property the platform sells for session VMs.
- **Mirror remotes are pinned to HTTPS** so the fetch is inspectable and the
  swap applies. git-over-SSH structurally cannot ride the egress gateway and
  would silently bypass both the swap and scanning planes
  (doc 16 §5.3, D83); the
  SSH remote-signing seam is a designed-for path built post-v0, so until then
  the mirror, like the v0 golden image (D83 "may pin"), uses HTTPS remotes
  only. `mirror.sh` refuses to add an `ssh://`/`git@` remote.
- This is **egress-gateway / TLS-termination** vocabulary throughout — never
  "MITM."

## Boundary enrollment — what the D63 boundary + D83 swap path owe this tree

The mirror is wired into the egress boundary on **two distinct legs**, and this
section states the contract each owes `images/mirror/` so the wiring is not left
implicit. Both are **config + docs** here — no crate code lives in this tree
(D63's policy-engine + the two boundary services ship in `dataplane/`); this
section records the obligation, the boundary fulfills it.

**Leg 1 — reachability (inbound to the serve face), the D63 admission path.**
The session VM reaches `mirror.ds.local:8418` (the registered alias above), and
the package cache's `cache.ds.local`, by **policy admission**, not by a public
route. What the boundary owes:

- The boundary's policy engine (the one shared `policy-core` crate, D63) must
  carry the two serve names as an explicit **host-local allow-set family**:
  doc 13 §2/§3 registers the
  enabled-by-default `host-local` baseline-pack family with the **exact FQDNs**
  `mirror.ds.local` (port `8418`) and `cache.ds.local` (ports `8081`, `5000`) —
  **no wildcards** (the doc 13 wildcard policy), each provenance-noted to the
  tree that ships it (`images/mirror/` and `images/cache/` respectively).
- `ds-dnsgate` resolves the alias to **this host's** git-mirror serve face on the
  per-session guest's host-local gateway address; `ds-tlsproxy` / the NFT leg
  admits the resulting flow. The serve face binds **host-loopback only**
  (`PublishPort=127.0.0.1:8418`, lint assertion 6), so this admitted alias is the
  *only* way a VM reaches it.
- The in-VM clone is plain `http://` to the loopback serve face — **TLS
  terminates at the boundary**, not at this CGI (egress-gateway / TLS-termination
  vocabulary throughout; never "MITM").

**Leg 2 — egress enrollment (outbound to upstream), the D83 swap path.** The
`ds-mirror-refresh.service` oneshot is a **gated egress workload**: its
mirror→upstream fetches ride the TLS-terminating egress gateway with a
short-lived credential swapped in via the generic Authorization-header seam, so
**long-lived upstream credentials never enter this unit**. What the boundary owes
is recorded as the enrollment env in `deploy/ds-mirror-refresh.service`, and the
literals in the table below are kept in lockstep with that file **by hand** — the
same hand-kept-literal discipline the quadlet generator keys follow (the
`lint-env-drift.sh` token guard asserts the five *other* load-bearing tokens
listed under "Concrete defaults" below, **not** these egress-enrollment env
literals; keep this table and the `.service` in agreement by convention until a
guard is added — see the follow-up):

| Env (in `deploy/ds-mirror-refresh.service`) | Value | What the boundary owes |
|---|---|---|
| `DS_MIRROR_EGRESS_GATEWAY` | `ds-tlsproxy` | The TLS-terminating egress gateway (D63) the refresh's egress traverses; nothing else routes upstream. |
| `DS_MIRROR_EGRESS_SWAP` | `authorization-header-swap` | The generic D83 `Authorization`-header credential-swap seam: the gateway substitutes the real upstream credential outside the trust boundary. |
| `DS_MIRROR_EGRESS_CRED_REF` | `workload:ds-mirror-refresh` | A **reference** to a short-lived workload credential minted per refresh — never a stored secret; the host holds no PAT / SSH key / `.netrc`. |
| `DS_MIRROR_EGRESS_UPSTREAMS` | `github.com,api.github.com,codeload.github.com` | The allowed upstream set the swap applies to; the gateway swaps for these hosts only. |

The host-side proxy listener (`HTTPS_PROXY` / `HTTP_PROXY` → the egress gateway,
with `NO_PROXY` exempting loopback and the two `*.ds.local` host-local serve
names so a cache/mirror-local hop is never sent upstream) completes the
enrollment. The `DS_MIRROR_EGRESS_CRED_REF` minting and the upstream-credential
store are **Identity's** to own (D39, off-host); this tree only references the
short-lived credential, never holds it.

The doc 16 credential-inventory cross-reference (recording `workload:ds-mirror-refresh`
in the Identity credential inventory) is **deferred to the Identity owner** and
is deliberately **not** edited here — see the proposed text the implementing
session emitted for that owner.

## Boundary with `../cache/` — complement, not overlap

This tree is the **git mirror only**. It is *complementary to and does not
overlap* [`../cache/`](../cache/README.md), which is the **site-local
pull-through package/image cache** (D41, Nexus CE buy-not-build). Division of
labour:

| Concern | Owner |
|---|---|
| Mirror of **git repositories** (history, refs, the clone source for worktrees) | **this tree** (`mirror/`) |
| Pull-through cache of **packages & container/image layers** (npm/PyPI/Go-proxy, registry blobs) | `cache/` (D41) |
| The **golden image** the VM boots (deps baked, build warm) | `golden/` (D12/D17/D49) |

The mirror serves the *source tree* a session edits; the cache serves the
*dependencies* a build resolves; the golden image is the *pre-baked workspace*.
A worktree clone hits the mirror; a `npm install` / `go mod download` inside the
VM hits the cache. **Neither implements the other's protocol** — and per D41 no
tree here implements registry semantics.

## Ops — files in this tree

| File | Role |
|---|---|
| `mirror.sh` | Operator helper: `add <url>` (one `git clone --mirror`), `refresh <repo>` / `refresh-all` (`remote update --prune`), `list`, `path <repo>`. HTTPS-remote-only; the refresh entrypoint the timer calls. |
| `lint-env-drift.sh` | Drift lint: asserts that the quadlet generator-key literals (`Image=`, `PublishPort=`, `Volume=`) in `deploy/ds-mirror-serve.container` match the canonical values in `deploy/ds-mirror.env`, that the `Volume=` container-side path matches `GIT_PROJECT_ROOT` in `deploy/git-http-backend.conf`, that the `Volume=` options field has `ro` as an exact comma-split token (fourth assertion — `rom`/`roo` are rejected), and that `deploy/git-http-backend.conf` sets `GIT_HTTP_RECEIVE_PACK=0` (fifth assertion — exact key, exact value, not commented out; the push-disabled CGI is the primary pull-only enforcement and the `:ro` mount is belt-and-suspenders on top, D83). Exits non-zero naming each mismatched key (and, for the cross-file check, naming both files and values). Run with `sh images/mirror/lint-env-drift.sh [DEPLOY_DIR]` from the repo root (or from `images/mirror/`); the deploy directory defaults to the script-relative `deploy/` but can be overridden by a positional argument or `$LINT_DEPLOY_DIR`. A sixth assertion is a standalone loopback check: the serve `PublishPort=` address must be a loopback address from the accepted set {`127.0.0.1`, `[::1]`}, regardless of `DS_MIRROR_ADDR`, so matching both files to a non-loopback address (e.g. `0.0.0.0`) cannot satisfy the env-file equality check while exposing the serve face beyond host-loopback (D83). Pass `--self-test` to run the internal regression harness (copies `deploy/` to a temp dir, verifies the clean copy passes, then injects each of the 11 recognized drifts one at a time and verifies non-zero exit per injection; injections are anchored to generator-key patterns and the harness aborts non-zero if an anchor is gone, so an upstream line reformat can never silently turn an injection into a no-op). Reads all three files; edits none. Also runs automatically (with `--self-test`) inside `smoke.sh` under the gate. |
| `smoke.sh` | Env-gated (`DS_MIRROR_SMOKE=1`) end-to-end check: run `lint-env-drift.sh` first (drift aborts the run), then `lint-env-drift.sh --self-test` (broken assertion aborts the run) → add a throwaway local upstream → mirror it → serve → clone from the mirror → assert ref parity. Refuses to run without the gate. |
| `deploy/ds-mirror.env` | Canonical reference for `DS_MIRROR_ROOT` / `DS_MIRROR_PORT` / `DS_MIRROR_ADDR` / `DS_MIRROR_IMAGE`. `mirror.sh` / `smoke.sh` source it and the systemd units load it via `EnvironmentFile=`; the quadlet loads it via `EnvironmentFile=` for the CGI runtime env, but its generator keys (`Image=` / `PublishPort=` / `Volume=`) are literals kept in lockstep with this file by hand (quadlet does not expand `EnvironmentFile` vars into those keys). |
| `deploy/ds-mirror-refresh.service` | systemd `oneshot`: runs `mirror.sh refresh-all`. No long-running process. |
| `deploy/ds-mirror-refresh.timer` | systemd timer: schedules the refresh (default every 15 min, jittered). |
| `deploy/ds-mirror-serve.container` | podman **quadlet** for the read-only `git-http-backend` HTTP face (stock git image, no code we wrote). |
| `deploy/git-http-backend.conf` | The CGI export config the quadlet mounts: fetch verbs only, push disabled (`GIT_HTTP_RECEIVE_PACK=0`). The host-loopback bind is enforced one layer up by the quadlet's `PublishPort=127.0.0.1:…` (assertion 6), not by this CGI conf. |

Concrete defaults (kept consistent across **every** file — sourced from
`ds-mirror.env` where the consumer supports `EnvironmentFile` interpolation, and
matched as hand-kept literals in the quadlet's generator keys, see above):

- mirror root: `DS_MIRROR_ROOT=/var/lib/ds-mirror`
- serve address: `DS_MIRROR_ADDR=127.0.0.1`, `DS_MIRROR_PORT=8418`. The
  loopback bind assertion requires the serve `PublishPort=` address to be a
  loopback address from the accepted set {`127.0.0.1`, `[::1]`}; nothing
  wider (e.g. `0.0.0.0`) passes.
- serve URL: `http://127.0.0.1:8418/<repo>.git`

Run `sh images/mirror/lint-env-drift.sh` after editing `ds-mirror.env`, the
quadlet, or `git-http-backend.conf` to catch any hand-kept-literal drift before
it reaches a deploy.  The lint makes six assertions:

1. `Image=` digest in `ds-mirror-serve.container` matches `DS_MIRROR_IMAGE` in `ds-mirror.env`.
2. `PublishPort=` addr and host/container port match `DS_MIRROR_ADDR` / `DS_MIRROR_PORT` in `ds-mirror.env`.
3. `Volume=` container-side path matches `GIT_PROJECT_ROOT` in `git-http-backend.conf` (divergence silently breaks serving).
4. `Volume=` options field has `ro` as an **exact comma-split token** — the options field is split on commas and `ro` must be one of the tokens, so a substring like `rom`/`roo` is rejected.  Belt-and-suspenders read-only mount on top of the push-disabled CGI (D83 boundary/egress posture).  Canonical line: `Volume=/var/lib/ds-mirror:/srv/git:ro,Z`.
5. `git-http-backend.conf` sets `GIT_HTTP_RECEIVE_PACK=0` (exact key, exact value, not commented out, not absent).  The push-disabled CGI is the **primary** pull-only enforcement (the mirror is structurally pull-only here); the `:ro` mount in assertion 4 is belt-and-suspenders on top.  Both guards must be present.
6. The serve `PublishPort=` address is a loopback address from the accepted set {`127.0.0.1`, `[::1]`} (standalone loopback check, independent of `DS_MIRROR_ADDR`) — matching both `ds-mirror.env` and the container to a non-loopback address (e.g. `0.0.0.0`) satisfies assertion 2 but exposes the serve face beyond host-loopback, so this assertion closes that gap (D83 boundary/egress posture; mirror is loopback-only).

The deploy directory defaults to the script-relative `deploy/` but can be
overridden: pass a path as the first positional argument (`sh lint-env-drift.sh
/path/to/deploy`) or export `LINT_DEPLOY_DIR` before running.  This is used
internally by `--self-test` and is also convenient for CI staging.

Pass `--self-test` to run the internal regression harness: it copies `deploy/`
to a temp dir (cleaned up on exit), confirms the clean copy exits 0, then
injects each of the **11 recognized drifts** (Image= digest, PublishPort= addr,
PublishPort= host port, Volume= host path, Volume= container path, Volume= :ro
removed, Volume= :ro→:rom token mutation, GIT_HTTP_RECEIVE_PACK=1,
GIT_HTTP_RECEIVE_PACK commented out, GIT_HTTP_RECEIVE_PACK absent,
ds-mirror.env absent) one at a
time, verifying that the lint catches each.  All 11 drift injections must be
caught for `--self-test` to exit 0 (the `PublishPort= addr` injection drives
the serve face to `0.0.0.0`, exercising the loopback assertion).  Injections are
**pattern-anchored** to generator
keys (e.g. `^Volume=`, `^GIT_HTTP_RECEIVE_PACK=`) rather than byte-exact whole
lines, and each injection asserts its anchor matched before mutating — so an
upstream line reformat aborts the self-test non-zero instead of silently turning
an injection into a no-op.  The harness is PIPESTATUS-safe: each lint
invocation's exit code is captured via `|| _rc=$?` without any piped grep that
could mask it; each caught injection prints `injection [...] caught`.

`--self-test` also guards five load-bearing tokens in this README against
one-sided drift via `scripts/lint-readme-tokens.sh` (unique-match anchoring —
zero or multiple anchor hits is itself a failure, retiring the first-match
residual risk).  After the injection sweep it recomputes all sides and fails
closed on a mismatch: (i) the **accepted loopback set** `{127.0.0.1, [::1]}`
quoted here must equal the addresses the lint's `case` statement accepts;
(ii) the **`11 recognized drifts`** count quoted here must equal the number of
injection blocks in the script; (iii–v) the three concrete defaults
`DS_MIRROR_ROOT=/var/lib/ds-mirror`, `DS_MIRROR_ADDR=127.0.0.1`, and
`DS_MIRROR_PORT=8418` quoted in the "Concrete defaults" list above must equal
the values in `deploy/ds-mirror.env`.  No side is a frozen literal — all are
derived from the live sources each run — so a future change that updates both
the README prose and the source in lockstep stays green, while editing only one
side aborts the self-test.  If any anchor is gone, the self-test aborts
non-zero rather than silently passing.

A composition note on the helper itself (wave17b origin, post-lintgate truth):
its exit-code contract (0 = every registered token matches, 1 = value drift,
2 = structural failure such as a missing README / zero-or-multiple anchor hits /
empty truth — and structural overrides drift across tokens) now has an **external
regression pin that LANDED**: `scripts/dispatch/test_lint_readme_tokens.py`
(taskdb `01KTZ6GQGRZP7KNDXR1JW7JPVX`). The wave17b attempt at that pin was
dropped at composition because it drove the helper as a standalone single-token
CLI before that CLI existed; it has since been **realigned to the sourcing API**
(`lrt_set_readme` + `lrt_register` + `lrt_check_all`, driven through a `bash -c`
shim) **and re-landed** — so the pin is NOT dropped and the contract is exercised
under the dispatch unittest gate, not only by `sh scripts/lint-readme-tokens.sh
--self-test`. The `--check README ANCHOR TRUTH_CMD EXTRACT [NAME]` mode named in
the helper header has likewise **SHIPPED** (it registers one token and calls
`lrt_check_all`, same 0/1/2 exit codes); the lintgate wave added **subprocess
`--check` regression arms** to that same test module (rc 0 match / 1 drift /
2 structural / bad-args rc 2), ratifying the CLI rather than reverting it.

A composition note on the README-token guards (wave22b origin, post-lintgate
truth): the mirror-guard unit added the three concrete-default token guards
(mirror-root, serve-addr, serve-port; items iii–v above) anchored against the
"Concrete defaults" list, bringing this README's guarded-token count to **five**
(loopback set + drift count + the three defaults). The sibling cache tree's
`images/cache/lint-image-drift.sh` `--self-test` carries an analogous set of
endpoint-URL guards (npm/PyPI/Go pull-through endpoints recomputed from
`wiring/{npmrc,pip.conf,go.env}`), and the lintgate wave further added per-row
endpoint **port-literal** guards there. Folding `images/*/lint-*.sh --self-test`
into the standing gate — so all these token guards fire under CI rather than only
under an on-demand `--self-test` — **landed in the lintgate wave**: `make
repo-lints` now runs a `check-image-drift-selftest` leg that re-runs every
glob-discovered `images/*/lint-*.sh` under `--self-test`, so a one-sided
README/source drift fails CI. The earlier-deferred `deploy/ds-mirror.env`-absent
rename/restore injection has also landed (it is the env-absent ABORT arm in this
`--self-test`, exercising the fail-closed branch when the env file is missing).

`smoke.sh` runs `lint-env-drift.sh` (drift check) and then
`lint-env-drift.sh --self-test` (assertion harness) under `DS_MIRROR_SMOKE=1`
before any throwaway repos are created, so a drifted deploy or a broken
assertion aborts the smoke run early.

The same lint is also folded into the standing gate: `make check-image-drift`
glob-discovers and runs every `images/*/lint-*.sh` in the tree — this script and
the cache drift lint enroll automatically, and a new `images/<tree>/lint-*.sh`
needs no Makefile edit to be gated (a zero-match glob is itself a fail-closed
error, D47 spirit). `make repo-lints` aggregates that with the doc-links, SPDX,
and fixture-provenance lints, and `.github/workflows/repo-lints.yml` runs
`make repo-lints` directly on every push to main and PR — so CI and the local
gate are the same command and cannot drift, and a drifted deploy fails closed
even without a smoke run. The script is owned by this image tree and only
invoked from the gate, never edited by it.

### Lint-script naming convention — `images/*/lint-*.sh`

Every drift-lint script that `make check-image-drift` should discover **must**
be named `lint-*.sh` and live **directly** in its image subdirectory (i.e. match
the glob `images/*/lint-*.sh`). This tree's script, `images/mirror/lint-env-drift.sh`,
follows that convention; `images/cache/lint-image-drift.sh` follows it too.

Rules that keep the gate sound:

- **Name it `lint-*.sh`**: any other name (e.g. `check-env.sh`, `validate.sh`)
  is silently invisible to the gate.
- **Place it directly under `images/<tree>/`**: scripts in subdirectories are
  not discovered.
- **Zero-match is a hard failure** (D47): if all lint scripts in the tree are
  deleted or renamed away from the `lint-*.sh` pattern, `make check-image-drift`
  exits non-zero immediately rather than treating a missing gate as a pass.
  This property is verified by the hermetic harness in
  `scripts/dispatch/test_image_drift_glob.py`.
- **The recipe body carries no hardcoded `lint-*.sh` literal**: the `lint-*.sh`
  pattern lives only on the overridable `IMAGE_DRIFT_GLOB ?= images/*/lint-*.sh`
  assignment; every reference inside the recipe flows through
  `$(IMAGE_DRIFT_GLOB)` or its derived `tree_glob`/`file_glob` shell vars, so an
  `IMAGE_DRIFT_GLOB=<override>` actually takes effect everywhere. The same
  harness mechanizes this invariant (`TestRecipeBodyNoHardcodedLiteral`, with a
  mutation self-test) so a future recipe edit that re-introduces a literal fails
  the gate immediately instead of waiting for a manual sweep.

Adding a new image tree with a lint script therefore requires only a correctly
named file; no Makefile edit, no `repo-lints` wiring change.

### Choice of serve face: `git-http-backend`, not `git daemon`

We serve over **smart HTTP via `git-http-backend`**, not the `git://` daemon
(`git daemon --export-all`). Justification:

- **Read-only is enforceable per-verb.** `git-http-backend` lets us export only
  the fetch path (`upload-pack`) and leave `receive-pack` (push) unexported, so
  the mirror is structurally pull-only. `git daemon` would need
  `--forbid-override=receive-pack` gymnastics and still speaks an unauthenticated
  mutable-by-config protocol.
- **It rides one well-understood transport.** HTTP over host-loopback composes
  cleanly with the per-session network model and is trivially bound to
  `127.0.0.1`; `git://` is a bespoke TCP protocol with weaker access controls.
- **It matches how VMs already clone upstream** (HTTPS remotes, D83), so the
  in-VM clone command differs only by host, not by scheme.

The git daemon remains a documented fallback if a future profile needs the
lighter protocol, but the default and the only wired path is `git-http-backend`.

## What must NOT live here

- **Daemon / service code we wrote** — no new Go module, no Rust crate, no
  long-running process. Refresh is a timer+oneshot; serve is stock
  `git-http-backend`. (Consistent with the no-new-Go-modules constraint and
  D41's buy-not-build posture for the sibling cache.)
- **Long-lived upstream credentials** — see the egress posture above; the swap
  lives in `ds-tlsproxy` (D83), the store off-host (D39).
- **Package/image-registry semantics** — that is `cache/` (D41); a mirror is
  not a registry.
- **The golden image build** — that is `golden/` (D12/D17/D49); the mirror
  feeds source into worktrees, it does not bake images.
- **guardrail-map.yaml / CODEOWNERS / oss-manifest edits** — Boundary/landing
  owned; a new unmapped `images/` subdir failing closed into full-matrix CI is
  the correct behaviour (D47).

## Neighbors

| Tree | Relation |
|---|---|
| `cache/` | Sibling host-local accelerator; **packages/images** there, **git repos** here — complement, no overlap (D41) |
| `golden/` | Pre-baked workspace image; the mirror is the *live source tree* clone source on top of that image (D12/D29) |
| `orchestrator/` | session-create chooses mirror-vs-upstream clone URL and records it (doc 15 §4.1); this tree owns the endpoint, not the choreography |
| `dataplane/` (`ds-tlsproxy`) | The egress gateway the mirror's upstream fetch rides; credential swap per D83, no creds held here |
