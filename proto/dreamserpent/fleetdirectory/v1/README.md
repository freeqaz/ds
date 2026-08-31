# dreamserpent.fleetdirectory.v1 — RESERVED (disposition ratified D121)

**Status: reserved, README-only — disposition ratified (D121), freeze deferred to M2.** No `.proto`
lands here until the M2 canvas-build window — its first consumer
(docs/17 §5/OQ11) — has an owning
design AND a freeze checklist exists. This directory exists now to pin the package name
and the guardrail/CODEOWNERS glob early (the `planstore.v1`/`logsink.v1` reserved-seam
pattern, design Part 4), so adding the fleet-directory query API later never forces a v2
or a tree reshuffle.

The disposition this directory executes is recorded at
docs/15 §5.6 (2026-06-11) and was
**ratified 2026-06-12 — D121**
(sessions/round4/90 §6).

**Owner workstream:** Orchestrator — it owns the never-recycled session records and
`WatchSession`, so the fleet tree is queried beside them (doc 15 §5.6).
**License:** [OSS] public contract when it lands (D58).

**Sibling, not in-package:** this is explicitly a **sibling reserved package**, **not**
in-package `orchestrator.v1` RPCs — so **nothing rides the `orchestrator.v1` M0 flip**.
It designs and freezes on its own track with the **M2 canvas-build window** (doc 17 OQ11
is the first consumer, the console is the other).

**What it will become** (docs/17 §11/§14;
docs/15 §5.6): the **D61 fleet-directory
query API** — the org→team→repo→session→subagent tree, live and RBAC'd, the shared
prerequisite of both the shared console and the canvas's session tiles (doc 17 §3
projection input). **Console presence** (who is in/watching a *session* — avatars,
spectate lists, driver identity; doc 17 §11's previously unowned carrying contract) is a
**second interface carried by or beside this same seam**, not a separate disposition or a
substitute for Yjs awareness (which syncs board documents only, never session state).

**Gating:** none defined yet — the disposition ratified (2026-06-12 — D121), but the
[FREEZE.md](../../../FREEZE.md) row stays OPEN (reserved) until the M2 canvas-build design
lands; its freeze PR will then follow the standard process and define the checklist.

**What must NOT live here:**
- The `WatchSession` event stream itself or any session-input/one-writer message — that is
  `attach.v1` / `orchestrator.v1` (D61 one-writer/N-reader; doc 15 §5).
- Canvas board storage or the Yjs sync seam — board CRUD is `canvas.v1`, board sync is the
  golden-trace corpus at M2 (doc 17 §10), neither a fleet-directory message.
- Plan records — the system of record for plans is `planstore.v1` (doc 17 §3.3); this seam
  reads the fleet tree, not plans.
- Human-RBAC / org-model schema as messages — the directory is RBAC'd at query time, but
  the org model is its own venue (doc 17 OQ7).
