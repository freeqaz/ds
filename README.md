# Dream Serpent

<p align="center">
  <img src="docs/assets/logo.jpg" alt="Dream Serpent" width="600" />
</p>

A collaborative agentic coding platform with safety guardrails built in (D28) — fast
ephemeral environments, always-on and parallel agents, instant pre-built workspaces,
fleet-scale compute, with the guardrails (isolation, network policy, credential swap,
identity) that make it safe to run agents unattended with a bounded blast radius.

**Start here:** [docs/architecture.md](docs/architecture.md) — the system at altitude, the
security model, and what is built vs. designed. Then
[docs/development.md](docs/development.md) for the repo layout and build commands.

> **Status.** This is a design-docs-first repo, and most trees are skeletons built against
> frozen contracts. The attach path runs a real coding agent inside a KVM VM today, but at a
> *validation* posture — direct egress, an operator-supplied token. Production gated egress
> with the real credential swap is a separate, later phase. Treat the safety properties below
> as the design, not a live production claim.

## Architecture

**Constrain the box, not the model — and make the box the best place to work.**

The system is built around three independently-operated isolation layers that together give
the agent a bounded blast radius regardless of what it does inside the VM:

```
┌─────────────────────────────────────────────────────────────────────────┐
│  Human principal                                                         │
│    │  user-auth JWT (ES256, 15-min) ──► Biscuit sub-token (per agent)   │
│    │  D125 / D126 / D98                                                  │
│    ▼                                                                     │
│  Client (CLI / TUI)  ◄──────────────────────────────────────────────────│
│    │  attach & event stream  (dreamserpent.orchestrator.v1)              │
│    ▼                                                                     │
│  Orchestrator (control plane)                                            │
│    │  session lifecycle: create → snapshot → pause/resume → destroy      │
│    │  host scheduling · identity minting · policy push                   │
│    │  D35: two services + orchestrator-lite (single-host all-in-one)     │
│    ▼                                                                     │
│  VM Runtime (KVM / libvirt)  ─────────────────────────────────────────┐ │
│    │  per-session ephemeral VM · CoW write-audit disk · golden image   │ │
│    │  D30: KVM only (no Firecracker / multi-hypervisor layer)          │ │
│    │                                                                   │ │
│    │  Agent  ◄─────────────────── credential-swap sidecar              │ │
│    │    long-lived credentials never enter the VM (D8)                 │ │
│    │    sidecar swaps short-lived tokens for real ones outside boundary│ │
│    │                                                                   │ │
│    │  outbound traffic (default-deny)                                  │ │
│    │    ▼  NFTables L3/L4 (three-keys-agree, D44)                      │ │
│    └───────────────────────────────────────────────────────────────────┘ │
│                │                                                          │
│    ┌───────────▼─────────────────────────────────────────────────────┐   │
│    │  Boundary (Rust data plane, D15)                                │   │
│    │                                                                  │   │
│    │  ds-dnsgate  ── DNS gating proxy                                 │   │
│    │    DNS-gated allow-sets with shared expiry (D4)                  │   │
│    │    admission map owned here; REFUSED for unlisted hostnames      │   │
│    │                                                                  │   │
│    │  ds-tlsproxy ── TLS-terminating egress gateway                   │   │
│    │    per-session CA · CONNECT termination · upstream TLS           │   │
│    │    secret-scanning hook · credential swap point (D82)            │   │
│    │    QUIC: udp/443 reject+counted (doc 12 §7)                      │   │
│    └──────────────────────────────┬──────────────────────────────────┘   │
│                                   │  allowed + scanned traffic            │
│                                   ▼                                       │
│                              Internet                                     │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  Identity & Credentials (feeds all layers)                               │
│                                                                          │
│  own CA → SPIFFE/SPIRE workload identity (one frozen Validate seam)      │
│  user-auth JWT (ES256) → Biscuit sub-token per agent at fan-out          │
│  eight v1: scopes; revocation events; JWKS + SP metadata HTTP endpoints  │
│  D125 / D126 / D127 / D128 / D129                                        │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│  Shared Contracts (proto/)                                               │
│                                                                          │
│  Versioned protobuf seams between every module pair (D24 / D58 / D80)    │
│  Stage-0 freezes are one-shot and checklist-gated (proto/FREEZE.md)      │
│  proto/gen/go is the only legal cross-tree import                        │
└─────────────────────────────────────────────────────────────────────────┘
```

A Mermaid rendering of the same system, the per-plane component tables, and the end-to-end
request walk-through live in [docs/architecture.md](docs/architecture.md).

### Key security invariants

| Invariant | Decision | How enforced |
|---|---|---|
| Long-lived credentials never enter the VM | D8 | Sidecar swap outside boundary; VM only sees short-lived tokens |
| Default-deny outbound networking | D4 | NFTables L3/L4 + DNS-gated allow-sets |
| Three-keys-agree before any policy change | D44 | NFTables gate; `assurance/guardrail-conformance` suite |
| Agent identity is per-session, not per-user | D98 | Biscuit sub-token minted at session create, offline-attenuated at fan-out |
| Boundary services unreachable by the agent | D16 | `ds-dnsgate` + `ds-tlsproxy` run outside the VM on the host; the VM has no route to them |

### Milestone bands

Capability bands, not sequential gates (D14).

| Band | Capability |
|---|---|
| **M0** | Walking skeleton: one VM, terminal attach, default-deny already active |
| **M1** | Trustworthy boundary + credential swap — run agents unattended |
| **M2** | Golden images, seconds-to-start, web client |
| **M3** | Fleet & scale: multi-host scheduling, subagent fan-out into own VMs |
| **M4** | Persistent agents on sensitive data |

## Citation convention

Design decisions are cited by canonical ID — `D<number>` — from the project's decision log.
Doc sections from the internal design corpus are cited as `doc <NN> §<section>`. Both are
kept as plain-text provenance markers; the corpus itself is not part of this repository.
Every tree's README states its governing D-numbers; if you change behavior a D-number
ratifies, you are reopening that decision, not just editing code.

## Repo map

| Workstream | Code home | Notes |
|---|---|---|
| Orchestrator | [`orchestrator/`](orchestrator/), [`infra/`](infra/), [`roles/`](roles/) | Two services (D35) + `orchestrator-lite`, the single-host all-in-one; `roles/` = session-role schema + built-in bundles |
| Boundary | [`dataplane/`](dataplane/) | The Rust data plane (D15): one cargo workspace (D67). Its spec lives in `boundary/` |
| Boundary (spec) | [`boundary/`](boundary/) | Go TDD harness = executable specification (D26). RED by design; never built with production code |
| VM & runtime | [`vm/`](vm/) | `ds-entrypoint` boot contract, CoW write-audit disks, attach forwarder, M0 guest image |
| Attach & client | [`client/`](client/), [`serpent-tui/`](serpent-tui/) | CLI, agent wrapper, TUI; the approval surface lives here, never in the proxy (D18/D45/D53) |
| Identity & credentials | [`identity/`](identity/) | Workload identity, token mint, grant service, SSO `auth-sdk`, KV client (D85) |
| Image & cache builder | [`images/`](images/) | Golden images + mirror/cache deploy config (D41 is a buy) |
| Shared contracts | [`proto/`](proto/) | THE single contract home (D24/D58/D80) |
| Cross-cutting assurance | [`assurance/`](assurance/) | Contract harness, guardrail conformance, e2e, benchmarks, conformance adapter |

[`oss-manifest.yaml`](oss-manifest.yaml) is the authoritative, machine-readable list of
open-source paths; lints read that exact file so the license map and the gate can't drift
apart. The principle (D15): **everything that runs on the host is open source.** A home lab
can run the whole data plane on one box.

Some tree READMEs draw the open-source line by naming what is *not* open — a `paid/`
tree holding the hosted fleet control plane, the web client, and the identity brokerage.
That tree is not part of this repository; the references exist so the boundary stays
legible, since D80 requires the split to fall on a service boundary rather than run
through a binary. Everything shipped here is Apache-2.0.

## Deliberately absent (anti-scaffold list)

These are **not** missing — the skeleton omits them on purpose. Do not add them without
reopening the cited decision:

- **All `.proto` bodies.** Stage-0 freezes are one-shot and checklist-gated
  ([`proto/FREEZE.md`](proto/FREEZE.md)); stub messages would imply freezes that haven't
  happened. The boundary harness's buf-gate staying RED is its documented correct state.
- **All fake implementations** — fakes are published with (or before) their contract, by the
  seam owner, never pre-scaffolded.
- **POL-1 v0 content** (schema home is `dataplane/crates/ds-contracts`, doc 13 §3).
- **DNS-2b storage mechanism, snapshot transport, `ds-policyd`** — free choices per doc 13 §6.
- **Env-spec schema home** — unowned (doc 15 OQ10); no dir until an owning doc exists.
- **Registry-protocol code** (D41 is a buy — `images/cache/` is deploy config only).
- **Proxy-side approvals** (D18/D53 — the approval surface is the client's).
- **A merged `ds-proxy`** (D63 — two services).
- **Firecracker / generic multi-hypervisor layer** (D30).
- **Relay service** (D79 — direct-first attach handles).
- **QUIC terminator** (doc 12 §7 — udp/443 is reject+counted).
- **Gateway-VM / VLAN vocabulary** (D31/D66).
- **attack/redteam directories** — the vocabulary is guardrail-assurance/conformance
  (doc 06 §3c).
- **Vendor runs** — the Rust data plane pins with `Cargo.lock` and builds `--locked`; it is
  not source-vendored (D146).

## Adding a new component

Find its workstream; pick the side of the license line first (it must fall on a
service/directory boundary, D80); reserve the proto seam + `FREEZE.md` row before writing
code; publish the fake with the contract; wire a [`guardrail-map.yaml`](guardrail-map.yaml)
glob (unmapped paths already fail closed, D47) and a README stating charter, owner,
D-numbers, and what must NOT live there.

## Building

See [docs/development.md](docs/development.md) for the full per-tree matrix. In brief:

```sh
# Go workspace members
for d in $(go list -m -f '{{.Dir}}'); do (cd "$d" && go build ./... && go test ./...); done

# Rust data plane
cd dataplane && cargo build --workspace --locked && cargo test --workspace --locked
```

## License

Apache-2.0. See [LICENSE](LICENSE).
