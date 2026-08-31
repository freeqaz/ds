# dreamserpent.planstore.v1 — RESERVED

**Status: reserved, README-only.** No `.proto` lands here until the M2 plan store has
an owning design. This directory exists now to pin the package name and the guardrail/
CODEOWNERS glob early (D47 — design Part 4, P3's reserved-seam argument), so adding the
plan store later never forces a v2 or a tree reshuffle.

**Owner workstream:** Orchestrator (the session/plan records live in control-plane
Postgres). **License:** [OSS] public contract when it lands (D58).

**What it will become** (docs/15 §5.6):
the M2 plan store API — the system of record for plans, feeding the D61 read-only plan
boards and the canvas's plan-card projections
(docs/17 §3.3: the plan store
remains the system of record for plans; the canvas store is the system of record for
boards only).

**Gating:** none defined yet — the [FREEZE.md](../../../FREEZE.md) row stays
OPEN (reserved) until an owning design doc exists; its freeze PR will then follow the
standard process and define the checklist.

**What must NOT live here:** anything before that design — especially canvas board
storage (that is `paid/canvas/`'s Postgres store behind a replaceable interface,
D88/doc 17 §9, not a proto seam at M0).
