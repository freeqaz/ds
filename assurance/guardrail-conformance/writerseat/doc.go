// SPDX-License-Identifier: Apache-2.0

// Package writerseat holds the executable form of the five browser-writer-seat
// guardrail-conformance claims the W5 arc adds (sessions/10 §5 / §6 W5; the
// D136/D137/D138 productized browser writer seat). It is part of the D51 public
// claims package ([../README.md]): every guardrail the docs promise becomes a test
// that tries to make the guardrail FAIL and asserts it doesn't (doc 06 §3c). The
// rows live in their OWN subpackage, distinct from the canvas/ collaborative-canvas
// rows, because the guarantees are the WRITE-LEG invariants the WriterRelayService
// adds to attach.v1 (the D137 in-place freeze amendment): seat arbitration, the
// drive choke point, the observable attributed handoff, the no-inject re-green with
// the write path present, and D78 honesty.
//
// VOCABULARY (doc 06 §3c, binding). Never attack / redteam / intrusion. These are
// **assurance tests for properties we advertise** — every row is named for the
// PROPERTY it proves and the NAMED way a regression would let it slip. A fixture
// that models a defeat path is named for the property it probes (a reader who
// reached a write surface, a rejected drive that reached stdin), never for an
// attacker. TestNoAttackVocabulary pins this for every ViolationClass + Tag.
//
// SHAPE (the canvas/orchctl sibling pattern). Each row is a small, deterministic
// Check over a typed SYNTHETIC fixture (D50) built as Go literals or loaded from
// synthetic JSON under fixtures/ — never a live orchestrator, host-agent, web
// client, session VM, KVM, or podman run. A typed ViolationClass taxonomy names
// every failure mode so each violation reports WHICH rule it tripped (the "fails
// NAMED" bar). The five rows' guardrail tags are single-sourced in Tags and pinned
// by TestTagsStable.
//
// WHAT THIS ASSERTS, AND THE D137 RE-GREEN. The W2/W3 orchestrator engine
// (orchestrator/internal/attach/writerseat.go SeatArbiter, .../controlplane/
// writerrelay.go) already EXERCISES the live seat behavior at the unit level. This
// package asserts the PUBLIC claims at the conformance level against synthetic
// fixtures that MODEL that documented contract (writer_relay.proto / events.proto /
// the SeatArbiter resolution rules) — NOT against a live orchestrator, which a
// public OSS package cannot stand up. The CRITICAL D137 amendment (sessions/10
// §3c / §5 claim 4): because attach.v1 now CARRIES the WriterRelay write leg
// in-place, the no-inject re-green asserts a ROLE_READER provably CANNOT reach the
// WriterRelayService RPCs / DriveSession stream — it does NOT assert the old, now-
// FALSE "v1 has no input message" claim. The canvas/projection claims (a canvas
// edit never reaches a session VM; canvas state cannot become an input channel)
// stay true BY CONSTRUCTION (the write path never touches the Yjs/projection layer
// or the canvas.v1 schema) and continue to live in the canvas/ package — this
// package adds the write-leg claims alongside them.
//
// ── THE FIVE ROWS (sessions/10 §5) ───────────────────────────────────────────
//
// CLAIM 1 — exactly one live writer seat per session (sessions/10 §5 claim 1; D61).
//
//	THE CLAIM: concurrent RequestWriterSeat → exactly ONE grant; the loser is
//	REFUSED (a typed RPC error), never silently dropped, never a second live seat
//	(the SeatArbiter per-session-serialized arbitration). The fixture records, per
//	concurrent request, its resolution (granted | refused | dropped). A conforming
//	contended session has EXACTLY ONE granted and the rest refused; two grants (two
//	live seats), a silent drop, or no grant under contention FAILS NAMED.
//
// CLAIM 2 — no drive without a live grant (sessions/10 §5 claim 2; D61/D137).
//
//	THE CLAIM: a DriveInput whose writer_seat_id is absent/stale/forged reaches NO
//	stdin and is REJECTED, and NO InputActivity is emitted for it (the
//	ValidateDrive choke point). The fixture records, per DriveInput, how its seat
//	id presented (live_grant | absent | stale | forged), whether it reached stdin,
//	and whether an InputActivity was emitted. A non-live presentation that reached
//	stdin OR emitted an InputActivity FAILS NAMED; a live-grant input admitted to
//	stdin that emitted NO InputActivity also FAILS NAMED (every accepted input
//	emits exactly one read-leg activity so the D78 clock advances).
//
// CLAIM 3 — every seat grant/steal/yield is attributed and observable
// (sessions/10 §5 claim 3; D8/D55/D61/D137).
//
//	THE CLAIM: a grant/steal/yield carries D8/D55 identity AND is observable on the
//	read stream at granted_seq — the W2-added WRITER_SEAT_CHANGED event every
//	N-reader sees (a steal CANNOT be silent). The fixture records, per handoff, its
//	kind, whether a read event was emitted, the seq, and the attributions. A
//	handoff that emitted no read event (silent), was observed at seq 0 (no ordering
//	point), or carried no required attribution FAILS NAMED.
//
// CLAIM 4 — a ROLE_READER provably cannot reach the WriterRelayService RPCs /
// DriveSession stream (sessions/10 §5 claim 4; the D137 re-green of the
// 01KTWJ64M0 no-inject barrier).
//
//	THE CLAIM (D137 amendment): the OLD argument "v1 has no input message" is now
//	FALSE (attach.v1 carries the write leg in-place); the re-green asserts a
//	ROLE_READER (no grant) provably CANNOT reach the WriterRelayService RPCs and
//	NO reader's input reaches stdin — the read-only surfaces stay structurally
//	read-only WITH the write leg present. The fixture records, per participant, the
//	held attach role, the WriterRelay surfaces it reached, and whether its input
//	reached stdin. A ROLE_READER that reached a write surface or stdin FAILS NAMED
//	(adding the write leg must NOT open a v1 injection path — the critical
//	regression this re-green exists to catch). This row is the re-green of canvas
//	claim 1 / doc 06 §3c "a read-only spectator provably cannot inject," run against
//	the v1 read surfaces WITH the v2 write path present.
//
// CLAIM 5 — D78 honesty: a DETACHED seat reads unattended even with N spectators
// (sessions/10 §5 claim 5; D78).
//
//	THE CLAIM: attendedness requires a human HOLDING the one writer seat AND
//	producing input within T — spectator presence NEVER feeds the signal. The
//	fixture records, per session, the seat-held-with-recent-input fact, the
//	spectator count, and the reported attendedness. A detached seat that read
//	attended, or attendedness that rose on spectator presence alone, FAILS NAMED.
//
// SYNTHETIC ONLY (D50). Every fixture is a hand-authored picture against the
// DOCUMENTED writer-relay / attach / D78 contracts (writer_relay.proto,
// events.proto, doc 15 §5.3/§5.4/§5.5, sessions/10 §5). Fixtures loaded from
// fixtures/*.json carry a `.provenance` sidecar. Nothing here stands up a real
// orchestrator, opens a DriveSession stream, arbitrates a live seat, writes a
// byte to any stdin, reads a guest surface, or touches a VM/host. The observations
// are DATA, never produced by touching any filesystem, process, network, or live
// service. There is NO live claude / qemu(VM-run) / podman / KVM invocation
// anywhere in this package, and no DS_*_LIVE token is read or set. The module is
// deliberately OFF the repo go.work `use` list and runs standalone under GOWORK=off
// (../go.mod), so the claims package stays independent of production build state.
//
// RUNNABILITY (README.md "OSS-runnable vs paid-dependent"; doc 17 §13). D51 ships
// the COMPLETE §3c table, but every row must be runnable without paid-layer scale
// machinery or be split. As modeled here ALL FIVE rows are oss-runnable: each is a
// static synthetic data-shape diff (the arbitration-outcome set, the drive-leg
// admit/reject + activity-emission shape, the handoff attribution/observability
// shape, the reader-reaches-no-write-surface shape, the attendedness-honesty shape)
// with no live-orchestrator / web-client / paid-layer dependency. The split
// mechanism (RunnabilityPaidDependent + CheckRunnable's not-applicable
// short-circuit) is present and exercised so a future row that genuinely needs the
// web-client render surface can be marked paid-dependent without a structural change.
//
// REGISTRATION (claim metadata). The five rows' guardrail tags are single-sourced
// in Tags (TagExactlyOneWriterSeat, TagNoDriveWithoutGrant,
// TagSeatChangeAttributedObservable, TagReaderCannotReachWriterRelay,
// TagAttendednessHonest) so the package's claim metadata and the repo-root
// guardrail-map.yaml writerseat row name the SAME rows; the
// scripts/check-guardrail-map-tags.sh seam lint verifies the map<->package coupling
// both ways. The map row is ALSO added here (this package owns the new glob), but a
// new unmapped subdir is fail-closed to the full matrix anyway (D47), so the rows
// self-gate; the map edit buys a CI-scope narrowing.
//
//	guardrail tag                                  row
//	writerseat-exactly-one-live-seat               (1) exactly one live writer seat (D61)
//	writerseat-no-drive-without-live-grant         (2) no drive without a live grant (D61/D137)
//	writerseat-handoff-attributed-and-observable   (3) attributed + observable handoff (D8/D55)
//	writerseat-reader-cannot-reach-writer-relay    (4) reader cannot reach WriterRelay (D137 re-green)
//	writerseat-attendedness-honest-when-detached   (5) D78 honesty when detached (D78)
//
//	runnability: oss-runnable (all five; see RUNNABILITY above)
//	anchors:     sessions/10 §5/§6 W5; writer_relay.proto; events.proto §6.1 row 7;
//	             doc 15 §5.3/§5.4/§5.5; doc 06 §3c (the (c) claims table)
//	decisions:   D136/D137/D138 (browser writer seat), D61 (one-writer/N-reader),
//	             D78 (attendedness), D8/D55 (attribution), D39 (short-lived seat),
//	             D24 (additive freeze), D26/D51 (public package), D47 (fail-closed
//	             scoping), D50 (synthetic fixtures)
//
// [../README.md]: ../README.md
package writerseat
