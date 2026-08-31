# dreamserpent.runtime.v1

**Charter.** The VM entrypoint contract — the second of the two D38 runtime seams:
host agent → guest. How a freshly cloned VM receives its entrypoint config, starts the
agent runtime, and reports the VM-local event socket that terminates at the host agent
(doc 15 §5.4). Runtime ignorance is the point (D20/D38): the orchestrator passes an
opaque `entrypoint_config_ref` in `VmSpec` and never learns runtime internals; controls
must hold when the runtime is swapped or compromised (doc 16 §12 — no mechanism may
depend on adapter cooperation).

**Owner workstream:** VM & runtime (implementation home: `vm/entrypoint/`).
**License:** [OSS] public contract. **Freeze stage:** M0 — **FROZEN 2026-06-15** (D38;
freeze PR `freeze/runtime-v1`), row in [FREEZE.md](../../../FREEZE.md).

## Inventory this package holds

- `EntrypointConfig` (`entrypoint_config.proto`) — the structured boot config the host
  agent hands the guest at boot (resolved from the D7-recorded env config; opaque to the
  orchestrator per docs/15 §5.1 `VmSpec`):
  `LaunchSpec` / `PermissionPosture` / `Budget` / `AttachWiring` / `EgressWiring` /
  `session_token_endpoint` + the opaque `bytes role_overlay_ref`. Imports and uses
  `boundary.v1.SessionRef` (never re-declared).
- `EntrypointService` (`entrypoint.proto`) — the guest-side readiness/exit handshake
  (`ReportReady` / `ReportExit`); boot-to-entrypoint is a named segment in the D81
  create→attach decomposition (doc 15 §8), so the contract exposes the boundary of that
  segment. The host agent is the server; the guest runtime wrapper is the client.
- VM-local event-socket reference — `AttachWiring` names the D38 socket that terminates
  at the host agent (doc 15 §5.4); events are forwarded onto the
  [`attach.v1`](../../attach/v1/) schema (this package never re-declares that vocabulary).

The freeze pins the message SHAPE only (OQ-C): the delivery encoding (how the host agent
transports `EntrypointConfig` into the guest, and the guest-local transport for
`EntrypointService`) stays free and may change without a v2.

## Gating

D38 contract freeze at M0 (doc 05 §8 contract set; doc 15 §10 "both runtime-seam
contracts frozen M0"), FROZEN 2026-06-15. The fold-into-`attach.v1` option (design
Part 4 res. 8) was considered and **DECLINED** (OQ-B): this row closed as a normal
FROZEN flip, not MERGED — the boot-config surface (host agent → guest) and the
event-stream surface (wrapper → consumer) are owned by different seams with different
cardinality and lifecycle, and do not share a version namespace.

## What must NOT live here

- Per-runtime adapter behavior — Claude Code specifics live ONLY in
  `client/wrapper/adapters/claude-code/` (D20/D38/D49).
- The wrapper→consumer event schema — [`attach.v1`](../../attach/v1/).
- Anything that assumes agent-framework cooperation for a guardrail (doc 16 §1
  non-goals).
