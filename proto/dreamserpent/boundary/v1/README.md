# dreamserpent.boundary.v1

**Charter.** The boundary's Stage-0 seam set — the contracts the data plane and the
control plane must agree on before neighbor workstreams can code against fakes
(docs/09 §8 Stage 0;
docs/14 is the single gating
checklist). This is the package whose freeze is most heavily gated: the round-2 closures
(D66–D76) each added fields independently, and doc 14 §2 collects them into one table so
the **one-shot** freeze misses nothing.

**Owner workstream:** Boundary. **License:** [OSS] public contract.
**Freeze stage:** Stage 0 — row OPEN in [FREEZE.md](../../../FREEZE.md).

## Inventory this package WILL hold (doc 09 §8 Stage 0; doc 14 §2; doc 14 §2b)

- **LOG-1 event schema**: `DnsEvent` (`aaaa_only`/`aaaa_stripped` D75, POL-3 provenance
  D67, interface-anchored session attribution D69/D44, reserved `aimed_resolver` D69,
  `admission_type` echo D75), `FlowRecord` (composite ct-mark decode: raw `ct_mark` +
  `leg` enum + `mark_session_index` = index mod 2^14 — a disambiguator, never the join
  key, D76), `PolicyDecision` (`plane = KEYED|GENERIC` + digest-set version D73;
  fingerprint-only convention — a matched secret value appears in NO log/event/spool/
  error path), recovery-failure refusals as a named event class (D69), and
  family-agnostic addresses everywhere (`bytes` + `AddressFamily` enum, never
  fixed32 — D75, time-locked).
- **`SessionRef`** — the shared quartet `session_uuid, host_id, host_session_index,
  tap_name` (D66/D44; the orchestrator session record is the authority, doc 14 §4).
- **`RejectReason`** enum — distinguishes `QUIC_BLOCKED` from generic default-deny
  (D70; what makes the flip-to-inspect trigger queryable off-box).
- **Policy snapshot + stream messages** — the composed-document snapshot
  (seq, content_hash, composed policy) that `orchestrator.v1 WatchPolicies` streams;
  deny-wins, from_seq replay (D36/D72).
- **`AskUserRequest`** — **one-way** boundary → orchestrator (session, resource kind,
  name, matched rule per POL-3). Approvals return ONLY as TTL'd grants on the policy
  stream — no second response contract (POL-5); the boundary never grows an approval UI.
  Carries a **RESERVED D60 consent-class tag** (optional field, `metadata | session |
  workload`): the ask payload is what the identity-plane `AskIssued/Approved/Denied`
  events tag, so the carry-or-reserve obligation lands on this transport too
  (doc 14 §2b `AskUserRequest` row;
  counterparty reservation = the `identity.v1` D60 consent-class flag, doc 16 §9). No
  population frozen; reserving is cheap, a miss is a v2-package event.
- **Suspend signal** — boundary → orchestrator, encoding the **D77 taxonomy, not
  original D53** (genuine-threat classes only). Carries session, POL-3 provenance
  (matched rule, layer, policy version), the D77 reason class, and a **`dedup_key`**
  (doc 14 §2b suspend row;
  doc 15 §4.3). The contract freezes
  only the `dedup_key`'s **stability property** — stable per triggering event so the
  orchestrator collapses retransmits onto one `Suspend` drive under its level-triggered,
  at-least-once reconcile model (doc 15 §4.3; sessions/round4/03 reconcile table). Its
  **composition is deliberately left free to the boundary** (e.g. session + matched rule
  + triggering-flow identity): the orchestrator consumes the key as **opaque** and keys
  idempotency on stability alone, so pinning a recipe would constrain the emitter with no
  consumer benefit. This is a **pre-freeze checklist row the freeze PR cites as WAIVED**
  in the doc 04 §6 suspend-signal disposition — no proto-body or shape change is implied,
  exactly as the property is shape-neutral; a future need to pin composition is an
  additive comment-only amendment, never a v2-package event.
- **`HttpEvent`** — LOG-1 HTTP metadata event (metadata only; stamps the policy version
  per POL-3 — doc 13 §5).
  Part of the six-message Stage-0 freeze set (doc 14 §2 message-set completeness row).
  Carries a **RESERVED D60 consent-class tag** (optional field, `metadata | session |
  workload`): `HttpEvent` is the one LOG-1 message that sits at the content/non-content
  line at the TLS-terminating egress gateway (doc 08 §3 introspection-by-consent), so the
  D60 tag-or-reserve obligation lands here (doc 14 §2
  `HttpEvent` row). Reserved, not wired — no population behavior frozen; the election
  itself rides the existing policy snapshot (D60 / doc 15 §9), so no message-set or
  `.proto` body change is implied.
- **`CredentialUseEvent`** — fingerprint-only credential-use record: session, service,
  credential fingerprint — **never the credential** (D8/D73). Part of the six-message
  Stage-0 freeze set (doc 14 §2 message-set completeness row).
- **`SpoolOverflow`** — visible-loss marker `{session, dropped_count, timestamp}`: when
  the LOG-3 disk-bounded spool overflows, loss is **visible, never silent** — the marker
  ships in the surviving stream. Ratified **D116** (round-4 packet, 2026-06-12 —
  sessions/round4 packet §6):
  the harness-frozen visible-loss marker joins the Stage-0 LOG-1 wire set, authorizing the
  doc 14 §2 checklist row. Source: the `boundary/` harness flowlog fix 9 adjudication
  + the `flowlog_schema_test.go` frozen shape. Part of the six-message Stage-0 freeze set
  (doc 14 §2 `SpoolOverflow` row).

### LOG-1 messages authored in `log1.proto` (doc 14 §2)

The LOG-1 event-schema bodies now live in
[`log1.proto`](log1.proto). The doc 14 TODO (inventory-extension row) asks the
inventory to carry `HttpEvent`, `CredentialUseEvent`, and `SpoolOverflow` rows
explicitly — all
seven messages of the doc 14 §2 set (the six wire messages plus `SpoolOverflow`)
are inventoried here. The §2b seam rows above (policy snapshot+stream,
`AskUserRequest`, suspend) are owned by a sibling unit and stay untouched; they
do not live in `log1.proto`.

| Message | Role | Checklist semantics | Cite |
|---|---|---|---|
| `SessionRef` | the shared session join quartet | `session_uuid, host_id, host_session_index, tap_name`; **canonical definition lives here** (the §2b sibling unit references it); orchestrator session record is the authority; `tap_name` is the never-recycled join key | D66/D44, doc 14 §4 |
| `FlowRecord` | connection/flow record | family-agnostic addresses (`bytes` + `AddressFamily`, never fixed32); composite ct-mark decode (raw `ct_mark` + `leg` enum + `mark_session_index` = index mod 2^14, a disambiguator never the join key); `RejectReason` incl. `QUIC_BLOCKED` | D75, D76, D70 |
| `DnsEvent` | DNS query/answer record | `aaaa_only`/`aaaa_stripped`; mandatory POL-3 provenance (missing provenance fails CI); reserved optional `aimed_resolver` addr:port; `admission_type` echo `NORMAL\|SYNTHETIC\|SINKHOLE_RESERVED`; interface-anchored attribution (never raw src IP) | D75, D69/D44, POL-3 |
| `HttpEvent` | HTTP metadata event | metadata only; stamps the policy version per POL-3; **RESERVED D60 consent-class tag** (`metadata\|session\|workload`), reservation-only, no population frozen | D60, POL-3, doc 14 §2 (HttpEvent row) |
| `PolicyDecision` | recorded policy verdict | `plane = KEYED\|GENERIC` + digest-set version (a separate non-policy namespace); fingerprint-only convention (no plaintext secret in any field) | D73 |
| `CredentialUseEvent` | credential-use record | fingerprint-only — session, service, credential fingerprint, **never the credential** | D8/D73 |
| `SpoolOverflow` | visible-loss marker | `{session, dropped_count, timestamp}`; loss visible never silent; ratified **D116** (round-4 packet, 2026-06-12) authorizing the doc 14 §2 `SpoolOverflow` row | D116, doc 14 §2 (SpoolOverflow row) |

Per-commit obligation recorded, not performed: the full-v6 address round-trip
test (D75 round-trip checklist row) and Go/Rust codegen ride the one-shot freeze
PR — codegen plugins are not installed in the authoring sandbox.

## Gating

Freeze PR cites **every row of doc 14 §2** (LOG-1 checklist) and **every row of
doc 14 §2b**
(non-LOG-1 Stage-0 seams: policy snapshot+stream, `AskUserRequest` one-way, suspend
signal) as checked or waived (the `aimed_resolver` row was resolved 2026-06-11 —
reserved optional addr:port field; no §2 row remains open). Among those rows, the
**D60 consent-class reservation** (an optional `metadata | session | workload` field
RESERVED on `HttpEvent` — doc 14 §2 — and on `AskUserRequest` — doc 14 §2b) must be
cited explicitly: the freeze is one-shot, so a missed reservation on either content-bearing
seam is a v2-package event, exactly as the `identity.v1` D60 consent-class flag is freeze-
mandatory on the approval events (doc 16 §9). Reservation only — no population behavior is
frozen, and the election rides the existing policy snapshot (D60 / doc 15 §9), so no
`.proto` body change is implied. Doc 14 is the single gating checklist; the doc 09 §8 prose
cell remains narrative only. The `boundary/` Go harness's buf-gate test is RED until this
lands — its documented correct state.

The three **§2b seam bodies** (`policy_stream.proto`, `ask.proto`, `suspend.proto`) are
authored. `ask.proto` and `suspend.proto` reference `SessionRef`, which is defined ONCE in
`session_ref.proto` (doc 14 §2/§4; D66/D44) — extracted into its own file at the freeze-PR
session-ref unification so cross-package importers (the `dreamserpent.identity.v1` seams)
take a dependency on exactly that message — and imported by full path
(`dreamserpent/boundary/v1/session_ref.proto`), never redefined. `policy_stream.proto`
carries no `SessionRef` (a snapshot is host-wide, not per-session — D72; doc 13 §5) and so
imports nothing.

With the LOG-1 and §2b sets assembled side-by-side the `log1.proto` cross-file import
resolves and whole-package `buf lint` (STANDARD, module root `.`) is green — the
isolated-unresolved-import state described above has cleared.

The pre-freeze checklist row for the suspend `dedup_key` composition is settled as
**composition-free** (the stability property is frozen, the recipe is left to the
boundary and consumed opaque — see the suspend bullet above); the freeze PR cites the row
as WAIVED in the doc 04 §6 suspend-signal disposition. No proto-body change is implied.

## What must NOT live here

- **Non-proto contract constants** — POL-1 YAML schema v0, mark-space layout +
  `DS_MARK_MASK`, `flush_session` signature, the DNS-2b versioned admission-map API,
  SOA MNAME — live in `dataplane/crates/ds-contracts/` (doc 13 §3, doc 14 §5–§6).
  There is deliberately no `policy/v1` package (design Part 4 res. 9).
- Proxy wire behavior — golden/conformance instruments in
  `assurance/conformance-adapter/` (doc 06 §2.2), not buf.
- Identity-owned seams (Validate, CA mint, digest feed) —
  [`identity.v1`](../../identity/v1/) (doc 16 §9), frozen beside this package at the
  same Stage-0 moment.
