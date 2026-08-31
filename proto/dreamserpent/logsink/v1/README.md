# dreamserpent.logsink.v1 — RESERVED

**Status: reserved, README-only.** No `.proto` lands here at v0 — **the v0 log sink is
local files + Postgres inside the orchestrator** (D19; doc 04 OQ10;
docs/15 §5.6). This directory exists now
to pin the package name and the guardrail/CODEOWNERS glob early (D47), so a real sink
service later is an additive freeze, not a migration.

**Owner workstream:** Orchestrator (it consumes LOG-1 at the control plane).
**License:** [OSS] public contract when it lands (D58).

**What it will become** (doc 15 §5.6): a LOG-1-consuming log-sink **ingest endpoint** —
the seam through which boundary telemetry (emitted by `ds-telemetry`, schema owned by
[`boundary.v1`](../../boundary/v1/) per doc 14 §2) flows into whatever heavier storage
a tier ratifies. The orchestrator's consumption obligations are already fixed by the
LOG-1 contract: family-agnostic addresses (D75), composite mark decode (D76),
`QUIC_BLOCKED` (D70), recovery-failure refusals (D69), plane + digest-set version
(D73), fingerprint-only, index→UUID join via the session record (doc 15 §6).

**Gating:** none defined yet — the [FREEZE.md](../../../FREEZE.md) row stays
OPEN (reserved) until a sink service is ratified. Note the matching restraint on the
service side: there is deliberately **no `paid/logsink/` service directory** either
(design Part 4 res. 18).

**What must NOT live here:** the LOG-1 event schema itself (that is `boundary.v1`,
Stage 0); any storage-mechanism commitment (Postgres-vs-else is a D19 tier question).
