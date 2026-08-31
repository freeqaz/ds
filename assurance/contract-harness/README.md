# assurance/contract-harness/ — fake generation + dual-run contract harness

This is the machinery behind the parallel-development story: the pipeline that generates
programmable fakes from every `proto/` contract, and the harness that runs each module's
contract suite **twice — against the real implementation and against the generated fake**
(doc 06 §2.1). If the two runs diverge, either
the fake is lying (a downstream team is coding against fiction) or the implementation has
drifted from the contract — both are caught at the seam, per-commit. This is what makes
"workstreams develop concurrently against stable seams" (D24/D14) a CI-enforced property
instead of a promise.

**Owner:** shared infrastructure; Orchestrator stewards the first seam (below). Each
seam's dual-run suite is owned by the workstream that owns the seam.

**Licensing:** OSS (Apache-2.0, in `oss-manifest.yaml`).

## First seam: orchestrator ↔ host agent

The harness's first target and proving ground is the **orchestrator ↔ host agent seam**
(doc 15 §11, doc 06 §2.1),
with **fakes published before implementations** (doc 05 OQ3). Concretely, the first
deliverables here are:

1. The fake-generation step in the codegen pipeline: generated fake server + fake client
   per contract — in-memory, behavior-specified (programmable canned responses + recorded
   calls), **not** null stubs. Generated fakes land in `proto/gen/go` (the shared module),
   not in this tree.
2. The dual-run runner: execute one conformance suite against real impl and generated
   fake, diff the outcomes, fail on divergence.
3. The orchestrator↔host-agent suite wired through it, gating per-commit.

Per doc 15 §11: any proto change runs the full (c) matrix (D47), and fixtures are
synthetic only (D50).

## Layout (landed)

| Path | What it is |
|---|---|
| [`fakegen/`](fakegen/) | The fake-generation step. Reads a service's COMPILED gRPC contract (its `grpc.ServiceDesc` + protobuf descriptor — the same artifact buf emits and `buf breaking` gates) and emits a programmable in-memory fake: per-method settable responders (canned responses) + recorded-call accessors, never null stubs. Deterministic output, so the committed fakes re-emit byte-identical (codegen-drift discipline). |
| [`cmd/fakegen/`](cmd/fakegen/) | The generator main. Emits a fake per service across the three M0 packages — `orchestrator.v1` (SessionService, PolicyService), `hypervisor.v1` (HypervisorDriverService), `hostagent.v1` (HostAgentService) — into `proto/gen/go`. `-check` is the CI drift gate (wired in `contracts.yml`). |
| [`dualrun/`](dualrun/) | The runner. Executes one conformance `Suite` against BOTH a real impl and the generated fake over an in-process bufconn, diffs the per-scenario `Observation`s, and reports the seam green only if they agree. A divergence is a lying fake or a drifted impl — both fail per-commit. |
| [`seams/hostagent/`](seams/hostagent/) | The first real seam, proven end-to-end: the orchestrator↔host-agent conformance suite, a minimal reference `HostAgentService` impl, the generated fake programmed to the same contract, and the per-commit dual-run gate (with a negative test proving the gate bites on a drifted fake). |
| [`seams/hypervisor/`](seams/hypervisor/) | The orchestrator↔host-agent `HypervisorDriverService` seam (doc 15 §11): the conformance suite over the ten HypervisorDriver verbs, an honest in-memory reference impl, and the generated fake, dual-run per-commit (with a negative test proving the gate bites on a drifted fake). |
| [`seams/orchestrator-session/`](seams/orchestrator-session/) | The `orchestrator.v1` `SessionService` seam: the conformance suite, a reference impl, and the generated fake, dual-run per-commit (with a negative test proving the gate bites on a drifted fake). |
| [`seams/orchestrator-policy/`](seams/orchestrator-policy/) | The `orchestrator.v1` `PolicyService` seam: the conformance suite, a reference impl, and the generated fake, dual-run per-commit; asserts the `content_hash` shape over a synthetic composed document (D50), with a negative test proving the gate bites on a drifted fake. |
| [`seams/identity-mint/`](seams/identity-mint/) | The `identity.v1` `IdentityMintService.MintInterceptionCA` CA-mint seam (D17/D82, doc 16 §4): the conformance suite over the per-session interception-CA mint under the two separate root hierarchies (workload-identity vs interception), an honest in-memory reference impl, and the generated fake, dual-run per-commit (with a negative test proving the gate bites on a drifted fake). |
| [`seams/identity-validate/`](seams/identity-validate/) | The `identity.v1` `IdentityValidationService.Validate` D22 sidecar seam (doc 16 §4/§9): the conformance suite over the signature + freshness + session-liveness + grant-lookup verdict, a reference impl, and the generated fake, dual-run per-commit (with a negative test proving the gate bites on a drifted fake). |
| [`seams/identity-digestfeed/`](seams/identity-digestfeed/) | The `identity.v1` `DigestFeedService.DigestPublish`/`DigestRevoke` secret-digest feed seam (D73, doc 14 §7 entry shape, doc 16 §6.6): the conformance suite over publish/revoke for both scopes, a reference impl, and the generated fake, dual-run per-commit (with a negative test proving the gate bites on a drifted fake). |
| [`seams/boundary-policystream/`](seams/boundary-policystream/) | The `boundary.v1` `PolicyStreamService.WatchPolicies`/`AckPolicy` seam (D72, doc 13): the conformance suite over the deny-wins composed-document stream keyed on `(seq, content_hash, document)`, a reference impl, and the generated fake, dual-run per-commit (with a negative test proving the gate bites on a drifted fake). |
| [`seams/canvas-board/`](seams/canvas-board/) | The `canvas.v1` `BoardService` board-arrangement / grants / projection-pin / history seam (D86/D87, doc 17 §10): the conformance suite over all thirteen unary verbs — org-scoped board CRUD, role grants riding org RBAC (D61, no parallel ACL), read-only projection pins (doc 17 §3.1), and the product-history listing (doc 17 §9, NOT the audit chain) — an honest in-memory reference impl, and the generated fake, dual-run per-commit (with a negative test proving the gate bites on a drifted fake). |

Regenerate the fakes after a re-freeze:

```sh
go run ./assurance/contract-harness/cmd/fakegen -out proto/gen/go
```

The emitted fakes are `*.gen.go` under `proto/gen/go/dreamserpent/<pkg>/v1/<pkg>fake/`
(marked generated by `.gitattributes`; never hand-edited — the `-check` drift gate
reverts edits).

## Governing decisions

- **D24** — every module boundary is a versioned contract with generated fakes and a dual-run suite (doc 06 §2)
- **D14** — stable contracts are what let workstreams deepen in parallel
- **D47** — proto changes fail closed to the full guardrail matrix
- **D50** — synthetic fixtures only in git

## What must NOT live here

- **Generated fakes** — they ship in `proto/gen/go` (same codegen pipeline, importable by everyone); this tree holds the *pipeline and runner*, not the artifacts.
- **Hand-rolled behavioral fakes** — owner-resident in `<workstream>/fakes/` (e.g. `orchestrator/fakes/`).
- **`.proto` files** — contracts live only in `proto/` (doc 06 §2.1).
- **Module-internal tests** — each module's (a) suite stays in its module; this harness *runs* those suites at the seam, it doesn't house them.
- **Non-gRPC seam testing** — the proxy wire and attach/CC seams are conformance/golden-trace problems (doc 06 §2.2) and live in `conformance-adapter/` and `client/goldentrace/` respectively.

## Neighbors

- `proto/` — contract source of truth; `proto/gen/go` — where generated fakes land; the fakes index table lives in `proto/README.md`.
- `orchestrator/fakes/` — the Stage-0 hand-rolled fakes (incl. the D49 cassette-driven WatchSession fake) the dual-run harness cross-checks.
- `conformance-adapter/` — the analogous mechanism for the two seams that speak real-world protocols instead of our RPC.
