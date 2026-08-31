# orchestrator/fakes — Stage-0 behavioral fakes (published FIRST)

This workstream publishes **contract-first fakes before implementations** —
doc 05 OQ3, confirmed 2026-06-11: Boundary and Orchestrator fakes ship first
because the most dependency edges touch them. Every other workstream queues
behind the fakes in this directory plus the generated ones in `proto/gen/go`
(doc 15 §1, §11).

Division of labor (design Part 4, resolution 5):

- **Generated programmable fakes** ship from the proto codegen pipeline into
  `proto/gen/go` — same pipeline as the stubs, importable by everyone.
- **Hand-rolled behavioral fakes** — anything with sequencing, state, or
  recorded-traffic semantics — live HERE, owned by the seam owner, and are
  registered in the fakes index table in `proto/README.md`.

**How these are consumed.** Every hand-rolled fake in this directory — including
the D49 cassette-driven WatchSession fake — is a **runnable gRPC server**,
consumed **over the wire** as a local process (a process seam). Neighbors never
Go-import this module: they start the fake binary and dial it with the same
generated `proto/gen/go` stubs they use against the real service. The only
legal cross-tree Go import remains `proto/gen/go`.

## Deliverable list (in publication order)

1. **`dreamserpent.orchestrator.v1` fake** — SessionService/PolicyService with
   the doc 15 §3 state machine's legal
   transitions (incl. PARKED, `SUSPENDED(reason)` with the D77 taxonomy) and
   the §4.1 create-choreography precedence gates (two-key refusal D56,
   digest-ack routability gate D73).
2. **The D49 cassette-driven `WatchSession` fake** — replays scrubbed NDJSON
   cassettes (synthetic-only in git, D50; provenance discipline per
   `client/fixtures/PROVENANCE.md`) as a `stream SessionEvent` with per-event
   sequence numbers and D61 one-writer/N-reader arbitration. This is the fake
   the client TUI, console, and canvas projections all build against
   (doc 17 §10 names it for the M0 fakes wave) — it ships **first**.
3. **`dreamserpent.hypervisor.v1` fake driver** — honest capability flags
   (the ec2demo flag set is the reference honesty case), idempotent verbs on
   session_uuid, `RecoverSessions` re-adoption behavior.
4. **`dreamserpent.hostagent.v1` fake host agent** — heartbeats with
   controllable `applied_seq` (to exercise the D72 unschedulable rule and
   READY gating), observed-session injection (to exercise the §3 conflict
   rules), capacity and sample feeds.

## Rules

- Neighbors build against these fakes, **never against this module's source**.
- The dual-run (real vs fake) harness lives in `assurance/contract-harness/`;
  orchestrator ↔ host-agent is its **first real seam** (doc 15 §11, doc 06).
- Fixtures: synthetic only in git (D50). No captured production or dogfood
  traffic lands here.
- Empty of code until the Stage-0 freeze PR publishes the protos — a fake
  implies a frozen contract, and `proto/FREEZE.md` rows are all OPEN.

Governing decisions: D49, D50, D61, D72, D73, D77; doc 05 OQ3 (confirmed).
