// Package attach is the orchestrator-side terminator of the D18 event-stream leg
// (doc 15 §5.3/§5.4): the WatchSession streaming fan-out, the D61
// one-writer/N-reader seat arbitration, and the D79 transport-ambivalent
// attach-handle issuance. It is the in-process serving leg behind the
// orchestrator.v1 SessionService.WatchSession / Attach RPCs and the
// hypervisor.v1 HypervisorDriver.IssueAttachHandle RPC (all FROZEN at M0); this
// package never authors a proto body — it composes the frozen attach.v1 /
// orchestrator.v1 / hypervisor.v1 messages.
//
// THREE LEGS (the task scope):
//
//   - WatchSession fan-out (watch.go): a per-session SUBSCRIBER set that every
//     attached client (the one WRITER and the N READERs) joins. Every emitted
//     attach.v1.SessionEvent carries a monotonic per-session sequence number
//     stamped at this terminator FROM M0 (D79 — reserved so replay/spectate land
//     without a v2). A `from_seq` request replays from a bounded per-session
//     history ring (the slow-N-reader recovery, D61: a reader recovers events it
//     dropped without re-attaching, never stalling the shared pump). Canvas and
//     console subscribe as ORDINARY N-th readers — they are READER subscribers,
//     no special path.
//
//   - One-writer/N-reader arbitration (seat.go): D61 is enforced SERVER-SIDE at
//     this terminator. The writer seat lives in the SESSION RECORD
//     (store.Session.WriterSeat/WriterRole), and a D61 driver handoff is a RECORD
//     MUTATION WITH ATTRIBUTION (store.UpdateSession) — never a second seat. A
//     second WRITER attach is refused unless the caller hands the seat off; a
//     READER attach is always admitted (N readers). This package mutates the
//     EXISTING record fields through the EXISTING Repository seam — it adds NO
//     store schema (the writer-seat columns landed with the store/migrations
//     tree, doc 15 §5.6).
//
//   - Attach handle issuance (handle.go): Attach / IssueAttachHandle return the
//     FROZEN attach.v1.AttachHandle — endpoint candidates (M0 is the DIRECT
//     client→host-agent endpoint only, doc 15 §5.4), short-lived session-scoped
//     AuthMaterial (NEVER a long-lived cred, D39), the WRITER/READER Role the
//     seat arbitration granted, and an expiry. Issuing a WRITER handle takes the
//     seat through the same seat arbitration, so the handle and the record never
//     disagree about who holds the writer seat.
//
// The VM-LOCAL event socket (D38) terminates at the HOST AGENT, not here: the
// host agent's hostbridge (client/hostbridge) is the VM-side fan-out, and this
// orchestrator-side terminator is the control-plane fan-out the product surfaces
// subscribe to. This package is the seam between them.
//
// Governing decisions: D18 (fan-out), D61 (one-writer/N-reader), D79 (attach
// handle + per-event seqs), D39 (short-lived session-scoped auth), D38 (the
// VM-local socket terminates host-side), D78 (the writer-seat-attached signal
// this leg feeds the attendedness computation). Primary doc:
// docs/15-orchestrator-design.md §5.3, §5.4.
package attach
