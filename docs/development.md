# Development notes

How the code is organized and what rules bind a change: contracts, testing tiers,
fail-closed defaults, and the build commands per tree.

The codebase is split into many trees — the orchestrator, the host agent, the Rust data
plane, the client, and more — and most of them are skeletons being filled in against frozen
contracts. This doc covers the handful of rules you will lean on from day one.

## Repo layout

| Tree | What it is |
|---|---|
| [`orchestrator/`](../orchestrator/README.md) | The Go control plane and the per-host agent: session lifecycle, placement, identity minting, policy push, Postgres state. Includes `orchestrator-lite`, the single-host all-in-one (D35). |
| [`dataplane/`](../dataplane/README.md) | The Rust data plane — one cargo workspace (D67). Services `ds-dnsgate`, `ds-tlsproxy`, `ds-flowlog` plus shared crates (`ds-nft`, `policy-core`, `ds-policy-snapshot`, `ds-admission-shm`, `ds-contracts`, `ds-telemetry`). |
| [`boundary/`](../boundary/README.md) | The Go TDD harness that is the *executable specification* of the boundary (D26). **RED by design** — see below. |
| [`vm/`](../vm/README.md) | VM runtime pieces: `ds-entrypoint` boot contract (D38), copy-on-write write-audit disks (D29), the attach forwarder, the M0 guest image. |
| [`client/`](../client/README.md) | The `serpent` CLI, the agent wrapper, capture tooling, and the TUI render layer. The approval surface lives here, never in the proxy (D18/D45/D53). |
| [`serpent-tui/`](../serpent-tui/README.md) | The terminal client binary that holds the WRITER seat over `attach.v1` (D79). |
| [`identity/`](../identity/README.md) | Workload identity, token mint, grant service, the SSO `auth-sdk`, and the KV client. Several independent Go modules. |
| [`proto/`](../proto/README.md) | **The** single contract home (D24/D58/D80). Protobuf seams plus generated Go under `proto/gen/go`. |
| [`assurance/`](../assurance/README.md) | Cross-cutting test tiers: the contract harness, guardrail conformance, e2e, benchmarks, and the conformance adapter that drives the real data plane against the `boundary/` spec. |
| [`images/`](../images/README.md) | Golden-image build config plus the host-local package/git mirror and cache config (D41 is a buy — deploy config only). |
| [`roles/`](../roles/README.md) | Session-role schema and built-in role bundles. |
| [`infra/`](../infra/README.md) | Host-side shims. |
| `scripts/` | Repo lints, release helpers, and dev tooling (see the last section). |

Structural rules that span trees:

- **`proto/gen/go` is the only legal cross-tree import.** Workspace mode makes other
  cross-imports *resolvable*, so this is a convention enforced by a CI import-boundary gate,
  not by the toolchain.
- **The open-source line runs on service boundaries, never inside a binary** (D80).
  [`oss-manifest.yaml`](../oss-manifest.yaml) is the authoritative, machine-readable path
  list, and lints read that exact file so the license map and the gate can't drift apart.
- **Unmapped paths fail closed.** [`guardrail-map.yaml`](../guardrail-map.yaml) maps code
  paths to the guardrail tests that must run for them. A changed path matching no entry runs
  the *full* matrix rather than skipping anything — forgetting to map a new tree costs CI
  time, never coverage (D47).

## Building and testing

### Go

The repo uses a Go workspace ([`go.work`](../go.work)). Because the workspace root is not
itself a module, `go build ./...` from the root does **not** work — package patterns must
resolve inside a workspace module. Build each member instead:

```sh
for d in $(go list -m -f '{{.Dir}}'); do (cd "$d" && go build ./... && go test ./...); done
```

Or work inside a single tree:

```sh
cd orchestrator && go build ./... && go test ./...
go test ./internal/session -run TestCreate     # a single test
```

Workspace members: `assurance/conformance-adapter`, `assurance/contract-harness`, `client`,
`identity/grant-service`, `orchestrator`, `proto/gen/go`, `vm`.

**Module paths are workspace-internal identifiers, not fetch URLs.** The modules here declare
paths under the `github.com/dream-serpent/dream-serpent/*` scheme while the repo itself lives at
`github.com/freeqaz/ds`. Nothing resolves those paths over the network: every cross-module
reference is satisfied through [`go.work`](../go.work) or a `replace` directive in the consuming
`go.mod`, so the modules are never `go get`-able and the declared path only has to be stable and
unique within the repo.

Several Go modules are deliberately **outside** the workspace and must be built with
`GOWORK=off`:

```sh
for d in boundary serpent-tui scripts/taskdb \
         assurance/e2e assurance/guardrail-conformance \
         infra/shims/govmomi scripts/nested-testbed/ds-identity-validate-fake \
         identity/mint identity/auth-sdk identity/digest identity/fleetreg \
         identity/idp identity/kv-client identity/fakes/digest-publisher; do
  (cd "$d" && GOWORK=off go build ./...)
done
```

`boundary/` is out of the workspace on purpose (see below). The identity submodules,
`serpent-tui`, `scripts/taskdb`, the two assurance test-tier modules, and the two shims are
standalone modules with their own dependency graphs.

### Rust data plane

One cargo workspace, pinned toolchain
([`dataplane/rust-toolchain.toml`](../dataplane/rust-toolchain.toml)), built `--locked`
against crates.io — dependencies are pinned by `Cargo.lock`, not vendored (D146 supersedes
the vendoring clause of D40/D67).

```sh
cd dataplane
cargo build --workspace --locked
cargo test  --workspace --locked
cargo clippy --workspace --locked -- -D warnings
cargo fmt --all --check
```

### Repo-wide lints

```sh
make repo-lints
```

A set of fail-closed structural guards (SPDX headers, OSS-manifest consistency, doc links,
synthetic-only test fixtures per D50, generated-artifact drift). Not wired into CI yet — see
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) for the v0 lanes, which cover the
Go and Rust builds only.

## `boundary/` fails on purpose — don't "fix" it

Tests come in four tiers:

| Level | What it checks |
|---|---|
| **(a) contract** | Each interface's suite runs *twice* — against the real implementation and against the generated fake — so a fake that lies or an implementation that drifts gets caught at the seam. |
| **(b) end-to-end** | A full session, from create → attach → tear down. |
| **(c) guardrail** | Every safety property the docs advertise becomes a test that confirms it holds. |
| **(d) load** | Throughput and contention on real hardware (a placeholder today). |

Level (c) is always framed as *confirming advertised properties*, never as attacking the
system — keep that language. It ships publicly as a versioned package anyone can run against
their own deployment (D51).

`boundary/` is an **executable specification**: every method is a stub that returns "not
implemented," and every test asserts the *real* behavior we expect. The suite is **red on
purpose** — failing is its correct, designed state. A contributor who sees `boundary/` red
has not found a bug.

Two things make that safe:

- `boundary/` lives *outside* the Go workspace, so it can never accidentally link production
  code, and its CI lane only compiles (`go vet`, `go build`, `go test -run '^$' ./...`) —
  it never runs as pass/fail.
- A separate adapter, [`assurance/conformance-adapter/`](../assurance/conformance-adapter/README.md),
  drives the real Rust data plane over the network and checks it against the spec. That
  adapter is the one place the spec meets production code.

So you make `boundary/` pass by fixing the data plane, never by editing the spec (D26).
Implementing a method inside `boundary/` itself is forbidden.

## Contracts: trees only talk through `proto/`

Trees never reach into each other's code. They share one thing: a set of versioned
interfaces, all in `proto/`. Your tree imports the generated code under `proto/gen/go` — and
nothing else from another tree.

Each interface ships with a **fake**: a stand-in you can program with canned responses, so
you build against the fake while another team builds the real thing, and the two meet at the
contract. Fakes are published with (or before) their contract, by the seam owner — never
pre-scaffolded.

An interface is **frozen** exactly once. Freezing locks it: afterwards you may *add*
optional fields, but never change or remove what's there. The freeze happens through one
checklist-gated pull request that lands the interface, ships its fake, and flips the package
from open to frozen — the checklist is [`proto/FREEZE.md`](../proto/FREEZE.md). A frozen
package can still be extended in place later as long as the change is purely additive
(`attach.v1` gained a writer-relay path and `runtime.v1` gained launch-spec fields, neither
breaking an importer).

| State | Interfaces |
|---|---|
| **Frozen** | `boundary.v1`, `identity.v1`, `orchestrator.v1`, `hypervisor.v1`, `hostagent.v1`, `attach.v1`, `runtime.v1`, `auth.v1` |
| **Frozen but narrowed** | `canvas.v1` (stub only), `roles.v1` (read path only) |
| **Open / reserved** | `planstore.v1`, `logsink.v1`, `fleetdirectory.v1` |

A `proto/` change is the special case in CI: because a contract change ripples to every
consumer, it goes through lint, a breaking-change check against a saved baseline, and a
regenerate-and-diff check that fails if the committed generated code is stale.

## Adding a new component

1. **Pick the license side first** — and make sure it lands on a service or directory
   boundary (D80).
2. **Reserve the proto seam** (and its `FREEZE.md` row) *before* writing code.
3. **Ship the fake** with the contract.
4. **Wire ownership**: a `guardrail-map.yaml` glob and a README stating what the component
   is for, who owns it, which decisions govern it, and what must *not* live there.

## Optional: `scripts/taskdb`

The repo ships a small standalone Go tool, [`scripts/taskdb`](../scripts/taskdb/README.md),
that the maintainers use to track work: a live SQLite database alongside tracked JSON files
that are the real source of truth. It is dev tooling, not part of the shipped product, and
nothing in the build depends on it.
