# dreamserpent.attach.v1

**Charter.** The stable side of the runtime seam: the **attach event schema** the smart
wrapper emits (D38 — wrapper → consumer events) and the **transport-ambivalent attach
handle** (D79). This proto is what stays fixed when the agent runtime is swapped or
upgraded; the Claude-Code-specific *input* side is deliberately not a proto (doc 06
§2.2 — golden-traced in `client/goldentrace/` + `client/fixtures/`, D49/D50).

**Owner workstream:** Attach & client. **License:** [OSS] public contract.
**Freeze stage:** M0 — **FROZEN 2026-06-13** in [FREEZE.md](../../../FREEZE.md)
(every doc 15 §6.1 row checked or explicitly waived; bodies in
[`attach_handle.proto`](attach_handle.proto) + [`events.proto`](events.proto)).
**Freeze-reopened / amended 2026-06-17 (D137, maintainer-authorized pre-ship, ADDITIVE):**
the browser writer-seat WRITE leg was added IN PLACE — a `WriterRelayService`
(`RequestWriterSeat`/`YieldWriterSeat`/bidi `DriveSession`) + `WriterSeatGrant`/`DriveInput`
(carrying the `DriveBlockKind` input union) in [`writer_relay.proto`](writer_relay.proto),
**reusing the v1 `InputActivity` as the read-leg projection (not redefined)**. The addition
is wire-additive (`buf breaking --against` the prior baseline passes; the
`orchestrator.v1`/`hypervisor.v1`/`canvas.v1` importers are unaffected); see the
[FREEZE.md](../../../FREEZE.md) `attach.v1` row.

## Inventory this package WILL hold

**`AttachHandle`** (docs/15 §5.4, frozen
at M0):

- `session_uuid`
- `endpoints` — repeated `EndpointCandidate`: M0 direct client→host-agent only; M2 the
  relay endpoint joins (web client); M4 the relay becomes the D61 spectate multiplexer.
  Admitting both transports from day one costs one field; deciding later costs a v2.
- `auth` — `AuthMaterial`, short-lived, session-scoped, never a long-lived cred (D39)
- `role` — `WRITER | READER` (D61 one-writer/N-reader)
- `expires_at`

**Attach event schema** (D38) — the events the wrapper emits and `WatchSession` serves
(the D18 fan-out is WatchSession-served, doc 15 §5.4): session state transitions with
the full doc 15 §3 vocabulary incl. PARKED + D77 reasons, **per-event sequence numbers
from M0**, subagent-spawn events, ask-prompt/approval events (incl. socket-hold
visibility, which is ask-event payload, not state-machine vocabulary), and the canvas
tile fields doc 17 §5 files into the checklist (plan deltas, ask pending/answered
read-only state).

**Attendedness input-activity events** — the post-interim feed for D78 (doc 15 §5.5:
M0/M1 interim is writer-attached-only until the wrapper exposes these); taxonomy free
until then (doc 16 §12). The **write-direction shapes** for this row (the writer-seat
`input_activity` event) and the canvas plan-delta half are now specified in
doc 15 §6.1 rows 6/7, and the
ask-response-as-grant flow (D45/D53 — approvals return as TTL'd policy-stream grants, never
a second proxy-side response channel) in doc 15 §6.2;
provenance labels per row (`LIVE` for the CC frames, `documented, not-live-verified` for the
attach.v1 projections), grounded on the keystone capture in
[`client/wrapper/DRIVE-FINDINGS.md`](../../../../client/wrapper/DRIVE-FINDINGS.md).

The **projection-resume wire frames** that recover the per-event seqs for a slow N-reader
(D61) — `frameResume{afterSeq}` / `frameResumeReply{span}` / `frameResumeReject{code}` and the
clean `ErrResumeWindowExceeded` reply — are specified at
doc 15 §6.1 row 9, provenance `LIVE`/code-real
(landed + test-proven in [`client/hostbridge/socket.go`](../../../../client/hostbridge/socket.go),
`socket_test.go TestSocketResume*` / `resume_test.go`).
Per the doc 15 §6.1 frame-tag-vs-proto-field-number disambiguation rider, the `frameResume`/`frameResumeReply`/`frameResumeReject` tags **8/9/10** (and the `resumeRejectCode` enum `1`/`2`) are hostbridge **socket-wire frame tags** in their OWN number space — **never `attach.v1` field numbers**: no message here may treat 8/9/10 as allocated or blocked, and the lint `scripts/check-freeze-riders.sh` fails closed on any `.proto` that cross-references them.

## Gating

The **consolidated M0 attach-event-schema freeze checklist is hosted at
doc 15 §6** and Attach & client executes
it (adjudicated, doc 17 §5): per-event sequence numbers, N-reader shape, state
vocabulary, subagent-spawn events, ask events, canvas tile fields. Missing the M0
window is a v2-package event (doc 17 §5). Cassette-driven attach fakes ship with the
freeze (D49).

## What must NOT live here

- **The CC wire/input side** — pinned-version cassettes + golden traces, never a proto
  (doc 06 §2.2; D49). New runtime = new adapter under
  `client/wrapper/adapters/`, same proto here. (The D137 `WriterRelayService.DriveSession`
  write leg is the *server-arbitrated relay contract* — the seat-gated path a keystroke/turn
  travels to reach stdin — NOT the CC stream-json input frame's wire encoding, which stays a
  cassette; `DriveInput.payload` is the opaque input body the adapter renders, not a typed CC
  frame.)
- The host-agent → guest entrypoint contract — that is the *other* D38 seam, owned by
  VM & runtime in [`runtime.v1`](../../runtime/v1/) (the two may merge at freeze time —
  design Part 4 res. 8 — but they have different owners and consumers until that call).
- Relay service design, spectate multiplexer, event persistence/replay — M2/M4, bounded
  by the reserved sequence numbers (doc 15 §10).
