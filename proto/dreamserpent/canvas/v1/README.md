# dreamserpent.canvas.v1

**Charter.** The `ds-canvas` board API — the gRPC half of the canvas's owned interfaces
(docs/17 §10). D87 posture is
**contracts-now, build-at-M2**: this stub freezes in the M0 window so neighbors can name
and fake the canvas, while the service itself (`paid/canvas/`) builds nothing until the
plan store exists to project from (doc 17 §5).

**Owner workstream:** Collaborative canvas. **License:** [OSS] — the contract is public
per D58 even though the implementing service is paid (D80: paid services implement
public protos). **Freeze stage:** stub **FROZEN 2026-06-13** in
[FREEZE.md](../../../FREEZE.md) (co-frozen with `attach.v1` per the §6.1 ds-canvas-stub
rider; body in [`board.proto`](board.proto)); v1 proper at M2 build start.

## Inventory this package WILL hold (doc 17 §10)

- Board CRUD
- Role grants / sharing — riding org RBAC, **no parallel ACL system** (D61, doc 17 §8)
- Projection-pin management — pinning read-only platform projections (session tiles,
  fleet-tree nodes, plan cards) onto boards (doc 17 §3.1)
- Board history listing — a product feature, explicitly not the doc 04 §5 audit chain
  (doc 17 §9)

Class-2 control-plane actions reachable from a board (launch-from-plan-card,
driver-handoff request) are **server-arbitrated RPCs on existing control-plane
surfaces** (doc 17 §7) — they ride `orchestrator.v1`, not this package.

## Structural invariant (frozen now, D78/D61 — doc 17 §7)

**No message in this package may carry session input.** `ds-canvas` links only the
WatchSession read leg (D79) and holds no client of the writer seam; class-1
interactions (injecting into an attach stream, tailing terminals, any parallel
session-read channel) are *structurally impossible*, not policy-forbidden. The freeze
PR's checklist includes this as a structural review item, and canvas presence never
feeds the D78 attendedness signal (doc 17 §6).

## Gating

Freeze PR cites doc 17 §10 (stub scope), the §7 no-session-input structural check, and
ships the generated canvas fake in the M0 wave (doc 17 §5) so `paid/canvas/` and the
web client surface develop against fakes from the stub onward (D14).

## What must NOT live here

- **The Yjs sync seam and awareness rooms** — non-buf contracts; their compatibility
  instrument is the golden-trace corpus at M2 (doc 17 §10; doc 06 §2.2). The update
  encoding is pinned by the doc 14 §9 Yjs supply-chain row (D86), not by proto.
- A plan **write-back** seam — a frozen non-edge until/unless ratified (doc 17 §7;
  design anti-scaffold "no writer seam").
- The projection ingestion pipeline — internal implementation, declared not-a-public-
  contract per D58 (doc 17 §10).
