# proto/gen/go — the generated-Go contract module

**Charter.** The committed output of the `proto/` Go codegen target
([../../buf.gen.yaml](../../buf.gen.yaml)): generated stubs plus **generated
programmable fakes**, per package, mirroring the `proto/dreamserpent/...` tree. This is
**the only thing Go trees import across seams** — orchestrator, vm, client, assurance,
and every `paid/` service consume contracts exclusively through this module, never
each other's internals (design Part 4 res. 4/5; D80 separability, CI-enforced by the
oss-manifest gate). Rust consumers get the parallel output in
`dataplane/crates/ds-contracts/src/gen/` (doc 14 §6, doc 15 §5.6).

**Owner:** stewarded with the `proto/` tree (Boundary + Orchestrator). **License:**
[OSS] Apache-2.0 — public contracts (D24/D58).

## Module path scheme

`github.com/dream-serpent/dream-serpent/proto/gen/go` — the repo-wide convention is
`github.com/dream-serpent/dream-serpent/<tree>` for every Go module. Generated packages
will sit at e.g.
`github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/orchestrator/v1`.

## Rules

- **Generated-only.** Files here are codegen output (marked generated in
  `.gitattributes`); the lone exception is `doc.go`, which keeps the module compiling
  while the tree is empty of generated code. Hand edits are reverted by the
  contracts-CI codegen-drift check.
- **Fakes first.** Each freeze PR ships this module's generated programmable fakes for
  the frozen package in the same PR (doc 05 OQ3); neighbors build against the fake,
  never the owner's source. The fakes index lives in [../../README.md](../../README.md).
- **Dependencies arrive with code.** `google.golang.org/protobuf` /
  `google.golang.org/grpc` enter `go.mod` with the first freeze PR's generated code —
  the skeleton builds offline with zero external deps.
- This module is listed in the root `go.work`; the `boundary/` harness is deliberately
  NOT (it is never built with production code) and satisfies its seams via
  `assurance/conformance-adapter/`.
