# proto/ — THE single contract home

**Charter.** Every cross-service/cross-workstream gRPC+protobuf contract in Dream Serpent
lives in this tree and nowhere else — no `.proto` file may exist outside `proto/`
(CI-enforced). One shared source of truth lets ten parallel workstreams code against
each other's *fakes* instead of each other's source (doc 06 §2.1, doc 14 §7, doc 15 §5).
This tree is **deliberately empty of `.proto` bodies right now**: Stage-0 freezes are
one-shot and checklist-gated (doc 14 preamble), so stub messages would imply freezes
that have not happened. The buf/fake gates being RED at skeleton time is the documented
correct state.

**Owner.** Shared tree; Boundary + Orchestrator co-steward (one CODEOWNERS line).
Each package below has a single owning workstream — see its README and the
[FREEZE.md](FREEZE.md) ledger.

**License.** [OSS] Apache-2.0. *All* contracts are public, including those only paid
services implement (D24, D58, D80 — `paid/` may import only `proto/gen/go`, never OSS
service internals).

**Governing decisions.** D24 (buf lint + breaking in CI; breaking change = v2
side-by-side; any proto change runs the full D47 guardrail matrix —
doc 15 §5), D58 (contracts public),
D80 (OSS/paid line on service boundaries — doc 15 §2),
D47 (`proto/**` maps to the full guardrail matrix in `guardrail-map.yaml`).

## Naming rule

Packages are `dreamserpent.<component>.v1` — always `dreamserpent.*`, **never `ds-*`**
(`ds-` prefixes name Rust crates/services in `dataplane/`, not proto packages).
Versioning is directory-shaped: a breaking change mints a sibling `v2/` package;
reserved packages and reserved RPCs exist now precisely so additions never force a v2.

## Freeze process

A package's contract lands only via a **freeze PR**, which atomically:

1. lands the `.proto` bodies for the package;
2. updates `baselines/` (the descriptor set `buf breaking` gates against from then on);
3. flips the package's row in [FREEZE.md](FREEZE.md) from OPEN to FROZEN, citing every
   row of its gating checklist (doc 14 §2 for boundary; doc 16 §9 for the four identity
   seams; doc 15 §5 / OQ1 for the orchestrator trio) as checked or explicitly waived in
   the decision log;
4. ships the generated programmable fakes from the same codegen run — **fakes publish
   first or simultaneously, never after** (doc 05 OQ3; doc 15 TODOs).

After a freeze: additions are optional fields with reserved numbers planned ahead;
anything else is a versioned-package event requiring a doc 04 §6 decision-log entry
(doc 14 §2 change control). `buf lint` + `buf breaking` green is the merge gate.

The merge gate is [`scripts/proto-gates.sh`](../scripts/proto-gates.sh)
(lint → breaking → codegen-drift → no-stray-proto); checks that need `.proto` bodies or
baselines NO-OP and pass until the first freeze PR lands them.

## Package index

| Package | Owner workstream | Freeze stage |
|---|---|---|
| [`dreamserpent.orchestrator.v1`](dreamserpent/orchestrator/v1/) | Orchestrator | M0 |
| [`dreamserpent.hypervisor.v1`](dreamserpent/hypervisor/v1/) | Orchestrator | M0 |
| [`dreamserpent.hostagent.v1`](dreamserpent/hostagent/v1/) | Orchestrator | M0 (shape) |
| [`dreamserpent.boundary.v1`](dreamserpent/boundary/v1/) | Boundary | Stage 0 |
| [`dreamserpent.identity.v1`](dreamserpent/identity/v1/) | Identity & credentials | Stage 0 |
| [`dreamserpent.attach.v1`](dreamserpent/attach/v1/) | Attach & client | M0 |
| [`dreamserpent.runtime.v1`](dreamserpent/runtime/v1/) | VM & runtime | M0 (FROZEN 2026-06-15, D38) |
| [`dreamserpent.canvas.v1`](dreamserpent/canvas/v1/) | Collaborative canvas | stub in M0 window; v1 at M2 (D87) |
| [`dreamserpent.planstore.v1`](dreamserpent/planstore/v1/) | Orchestrator | RESERVED (doc 15 §5.6) |
| [`dreamserpent.logsink.v1`](dreamserpent/logsink/v1/) | Orchestrator | RESERVED (doc 15 §5.6) |
| [`dreamserpent.roles.v1`](dreamserpent/roles/v1/) | Orchestrator | M0 read path (FROZEN 2026-06-13; write path M2-deferred + reserved) |
| [`dreamserpent.fleetdirectory.v1`](dreamserpent/fleetdirectory/v1/) | Orchestrator | RESERVED (doc 15 §5.6 — disposition ratified D121, M2 canvas-build window) |

## Fakes index

Generated **programmable fakes** ship from the codegen pipeline into
[`gen/go/`](gen/go/) (doc 05 OQ3 — fakes first): buf emits the stubs, then the
[`assurance/contract-harness/fakegen`](../assurance/contract-harness/) step reads each
frozen service's compiled gRPC contract and emits its programmable fake (settable
responders + recorded calls) beside the stubs (`-check` drift-gated by the same
proto gate). Hand-rolled *behavioral* fakes
live in the owning workstream's tree. **Consumed how:** generated programmable fakes are
*imported* from `proto/gen/go` (the one shared module); hand-rolled behavior fakes are
**run as local processes** — runnable gRPC servers speaking the same protos, dialed
over the wire with the `proto/gen/go` stubs, never Go-imported from their home tree.
Index (grows with each freeze PR):

| Seam | Fake | Home | Consumed how | Status |
|---|---|---|---|---|
| orchestrator/hypervisor/hostagent.v1 | generated programmable fakes (SessionService/PolicyService, HypervisorDriverService, HostAgentService); D49 cassette-driven WatchSession fake | `proto/gen/go` + `orchestrator/fakes/` | import `proto/gen/go`; D49 fake runs as a local gRPC server process | FROZEN 2026-06-13; generated stubs in `proto/gen/go/dreamserpent/{orchestrator,hypervisor,hostagent}/v1/`. **Generated programmable fakes + dual-run harness LANDED 2026-06-13**: fakes in `proto/gen/go/dreamserpent/{orchestrator,hypervisor,hostagent}/v1/<pkg>fake/` from the `assurance/contract-harness/fakegen` pipeline; the orchestrator↔host-agent seam is proven real-vs-fake in `assurance/contract-harness/seams/hostagent/`. The D49 cassette-driven WatchSession behavioral fake (`orchestrator/fakes/`) lands with its harness wiring (open follow-up) |
| boundary.v1 (LOG-1, policy stream, ask-user, suspend) | generated fakes | `proto/gen/go` | import `proto/gen/go` | FROZEN 2026-06-12; generated stubs in `proto/gen/go` |
| identity.v1 D22 Validate + CA mint | generated fakes | `proto/gen/go` | import `proto/gen/go` | FROZEN 2026-06-12; generated stubs in `proto/gen/go` |
| identity.v1 digest feed (D73) | **fake publisher**, shipped *with* the Stage-0 freeze (doc 14 §7/§10) | `identity/fakes/digest-publisher/` | runs as a local process, speaks the frozen protos | LANDED 2026-06-12 (`main.go` + `publisher_test.go`); off-go.work module, gated by the `GOWORK=off` CI lane |
| attach.v1 event schema + AttachHandle | generated stubs (the `SessionEvent` union + `AttachHandle`); WatchSession serves the events | `proto/gen/go` | import `proto/gen/go` | FROZEN 2026-06-13; generated stubs in `proto/gen/go/dreamserpent/attach/v1/` |
| canvas.v1 board API | generated fake in the M0 wave (doc 17 §5) | `proto/gen/go` | import `proto/gen/go` | FROZEN 2026-06-13 (stub, co-frozen with attach.v1); generated stubs in `proto/gen/go/dreamserpent/canvas/v1/`. **Generated programmable BoardServiceFake LANDED 2026-06-13**: the `BoardServiceFake` (settable responders + recorded calls over the thirteen board-arrangement RPCs) in `proto/gen/go/dreamserpent/canvas/v1/canvasv1fake/` from the `assurance/contract-harness/fakegen` pipeline, completing M0 generated-fake coverage |
| roles.v1 catalog READ path (ListRoles/GetRole, doc 18 §6) | generated `RoleCatalogServiceFake` | `proto/gen/go` | import `proto/gen/go` | FROZEN 2026-06-13 (READ path); generated stubs in `proto/gen/go/dreamserpent/roles/v1/`, the programmable `RoleCatalogServiceFake` in `…/rolesv1fake/` from the `assurance/contract-harness/fakegen` pipeline. The catalog WRITE path (PutRole / ratification) is M2-deferred + reserved — its fake re-emits automatically when the write RPCs land (the fakegen-tracks-the-frozen-stub contract) |
| runtime.v1 entrypoint contract (EntrypointService ReportReady/ReportExit, D38) | generated `EntrypointServiceFake` | `proto/gen/go` | import `proto/gen/go` | FROZEN 2026-06-15 (D38); generated stubs in `proto/gen/go/dreamserpent/runtime/v1/`, the programmable `EntrypointServiceFake` in `…/runtimev1fake/` from the `assurance/contract-harness/fakegen` pipeline (the new `runtimev1` target). `EntrypointConfig` is a message-only boot surface (no service), so its Go types ship with the stubs |

## Non-buf seams (deliberately NOT in this tree)

Contracts whose compatibility instrument is conformance/golden-trace, not `buf breaking`
(doc 06 §2.2):

- **Proxy wire behavior** (curl/npm/git/pinned-client/DoH-blocked conformance) →
  `assurance/conformance-adapter/`.
- **Claude Code input side** of the attach wrapper → `client/fixtures/` +
  `client/goldentrace/` (D49/D50). Only the wrapper's *output* (attach.v1) is proto.
- **Yjs sync seam + awareness rooms** (canvas) → golden-trace corpus at M2
  (doc 17 §10; public per D58, but its instrument is the corpus, not buf).
- **Non-proto contract constants** — POL-1 YAML schema v0, mark constants +
  `DS_MARK_MASK`, `flush_session` signature, DNS-2b versioned API, SOA MNAME — live in
  `dataplane/crates/ds-contracts/` per doc 13 §3 / doc 14 §6 (docs 13/14 postdate and
  refine doc 09 §6's wording).

## Unowned seams (flagged, not scaffolded)

- **Env-spec schema** — no owning doc exists (doc 15
  OQ10); `RecordEnvConfig` freezes only the reference shape it stores. No package until
  an owning doc lands.

The **fleet-directory query API** (the D61 console/canvas fleet tree, flagged here as a
one-sided seam by doc 17 OQ11) is no longer
unowned: per doc 15 §5.6 the Orchestrator owns it as a
sibling reserved package, now [`dreamserpent.fleetdirectory.v1`](dreamserpent/fleetdirectory/v1/)
in the index above (RESERVED, M2 canvas-build window; disposition ratified 2026-06-12 —
D121).

## What must NOT live here

- `.proto` bodies before their freeze PR (see Freeze process).
- A `policy/v1` package — POL-1's home is `ds-contracts` (doc 13 §3); policy
  snapshot/stream messages belong to `boundary.v1`.
- Anything QEMU/libvirt-specific in `hypervisor.v1` (D30 substrate-swap seam).
- A session-input message in `canvas.v1` — structurally forbidden (doc 17 §7).
- Hand-written code: `gen/` holds codegen output (plus its go.mod/README) only.

## Codegen

`buf.gen.yaml` targets: Go → [`gen/go/`](gen/go/) (module
`github.com/dream-serpent/dream-serpent/proto/gen/go` — the ONLY Go module other trees
import across seams), Rust → `dataplane/crates/ds-contracts/src/gen/` (doc 15 §5.6,
doc 14 §6). Go↔Rust contract tests (e.g. `content_hash` canonicalization, doc 15 OQ3)
live with `orchestrator/internal/nftbridge/` and `ds-contracts`.
