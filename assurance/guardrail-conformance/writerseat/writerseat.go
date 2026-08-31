// SPDX-License-Identifier: Apache-2.0

package writerseat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// ── Single-sourced guardrail tags (doc.go REGISTRATION; guardrail-map.yaml) ──
//
// The five sessions/10 §5 browser-writer-seat tags this package's rows carry, in
// doc.go REGISTRATION order. Tags is the SINGLE SOURCE for the row names: the
// repo-root guardrail-map.yaml's writerseat glob row and this slice must name the
// SAME rows, and TestTagsStable pins the slice so a silent drift fails HERE
// rather than against a differently-named map row (the canvas/orchctl multi-row
// discipline — an honest map row names a real, single-sourced tag value, never a
// placeholder string).
const (
	// TagExactlyOneWriterSeat — claim 1 (sessions/10 §5 claim 1): exactly one live
	// writer seat per session — concurrent RequestWriterSeat resolves to exactly one
	// grant; the loser is REFUSED, not silently dropped (D61 one-writer/N-reader).
	TagExactlyOneWriterSeat = "writerseat-exactly-one-live-seat"
	// TagNoDriveWithoutGrant — claim 2 (sessions/10 §5 claim 2): no drive without a
	// live grant — a DriveInput with an absent/stale/forged writer_seat_id reaches NO
	// stdin and is rejected, and NO InputActivity is emitted for it (D61/D137).
	TagNoDriveWithoutGrant = "writerseat-no-drive-without-live-grant"
	// TagSeatChangeAttributedObservable — claim 3 (sessions/10 §5 claim 3): every seat
	// grant/steal/yield is attributed (D8/D55) and observable on the read stream at
	// granted_seq — the WRITER_SEAT_CHANGED event W2 added; a steal cannot be silent.
	TagSeatChangeAttributedObservable = "writerseat-handoff-attributed-and-observable"
	// TagReaderCannotReachWriterRelay — claim 4 (sessions/10 §5 claim 4; the D137
	// re-green): a ROLE_READER (no grant) provably CANNOT reach the WriterRelayService
	// RPCs / DriveSession stream — adding the v2 write leg must NOT open a v1 injection
	// path. (Replaces the now-false "v1 has no input message" argument.)
	TagReaderCannotReachWriterRelay = "writerseat-reader-cannot-reach-writer-relay"
	// TagAttendednessHonest — claim 5 (sessions/10 §5 claim 5): D78 honesty — N
	// spectators + a DETACHED seat ⇒ attendedness reads unattended (spectator presence
	// never feeds the attendedness signal).
	TagAttendednessHonest = "writerseat-attendedness-honest-when-detached"
)

// Tags is the ordered set of single-sourced guardrail tags this package owns, for
// the guardrail-map.yaml writerseat row to name the SAME rows.
var Tags = []string{
	TagExactlyOneWriterSeat,
	TagNoDriveWithoutGrant,
	TagSeatChangeAttributedObservable,
	TagReaderCannotReachWriterRelay,
	TagAttendednessHonest,
}

// ── Runnability (README.md "OSS-runnable vs paid-dependent"; doc 17 §13) ─────
//
// D51 ships the complete table, but every row must be runnable without paid-layer
// scale machinery OR be split. As modeled here all five rows are oss-runnable:
// each is a static synthetic data-shape diff over the DOCUMENTED writer-relay
// contract (writer_relay.proto / events.proto / orchestrator SeatArbiter behavior)
// with no live orchestrator, host-agent, web-client, or paid-layer dependency. The
// split mechanism (RunnabilityPaidDependent + CheckRunnable's not-applicable
// short-circuit) is present and exercised so a future row that genuinely needs the
// web-client render surface can be marked paid-dependent without a structural change.

// Runnability marks where a row can execute.
type Runnability string

const (
	// RunnabilityOSS — executes against any OSS checkout: a static data-shape diff
	// with no live orchestrator / host-agent / web-client / paid-layer dependency.
	RunnabilityOSS Runnability = "oss-runnable"
	// RunnabilityPaidDependent — needs paid-layer / web-client machinery; on an OSS
	// run the row is reported not-applicable, never failed (doc 17 §13).
	RunnabilityPaidDependent Runnability = "paid-dependent"
)

// CheckRunnable runs check only when the row is OSS-runnable on this checkout. For
// a RunnabilityPaidDependent row on an OSS run it returns (nil, false): the row is
// NOT-APPLICABLE, never FAILED (doc 17 §13 split). The bool reports whether the
// check actually ran.
func CheckRunnable(r Runnability, check func() []Violation) ([]Violation, bool) {
	if r == RunnabilityPaidDependent {
		return nil, false
	}
	return check(), true
}

// ── Shared violation type ────────────────────────────────────────────────────

// ViolationClass names a single failure mode one of the five rows enumerates, so
// every violation reports WHICH rule it tripped (the "fails NAMED" bar). The
// constants are grouped per row below.
type ViolationClass string

// Violation is a single guardrail breach: which rule, which subject (the
// request/frame/event/reader the check ran against), and a human-readable reason
// citing the governing anchor.
type Violation struct {
	Class   ViolationClass
	Subject string
	Reason  string
}

func (v Violation) String() string {
	return fmt.Sprintf("[%s] %s: %s", v.Class, v.Subject, v.Reason)
}

// sortViolations orders a slice by (class, subject) so failure messages and
// class-set comparisons are stable across runs.
func sortViolations(vs []Violation) {
	sort.Slice(vs, func(i, j int) bool {
		if vs[i].Class != vs[j].Class {
			return vs[i].Class < vs[j].Class
		}
		return vs[i].Subject < vs[j].Subject
	})
}

// ────────────────────────────────────────────────────────────────────────────
// CLAIM 1 — exactly one live writer seat per session (sessions/10 §5 claim 1; D61).
//
// THE CLAIM: concurrent RequestWriterSeat → exactly ONE grant; the loser is
// REFUSED (a typed RPC error), never silently dropped and never a second live
// seat. The synthetic fixture models, per session, the arbitration outcomes of a
// set of concurrent seat requests against the one server-arbitrated terminator
// (SeatArbiter, writerseat.go): each outcome is GRANTED or REFUSED. A conforming
// session has EXACTLY ONE granted outcome and every other request REFUSED; two
// granted outcomes (two live seats), or a request neither granted nor refused (a
// silent drop), FAILS NAMED.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationTwoLiveSeats — more than one concurrent RequestWriterSeat resolved to a
	// live grant for the same session; the D61 one-writer invariant must yield exactly
	// one live seat.
	ViolationTwoLiveSeats ViolationClass = "two-live-writer-seats"
	// ViolationLoserSilentlyDropped — a losing RequestWriterSeat was neither granted
	// nor refused (silently dropped); the loser MUST be REFUSED with a typed error, not
	// dropped (sessions/10 §5 claim 1).
	ViolationLoserSilentlyDropped ViolationClass = "seat-loser-silently-dropped"
	// ViolationNoSeatGranted — a contended session granted NO seat at all; exactly one
	// concurrent request must win (the seat is not left unowned when drivers contend).
	ViolationNoSeatGranted ViolationClass = "no-seat-granted-under-contention"
)

// SeatRequestOutcome names how the single terminator resolved one concurrent seat
// request (the SeatArbiter.RequestSeat resolution, writerseat.go).
type SeatRequestOutcome string

const (
	// OutcomeGranted — the request won the one seat (a WriterSeatGrant was returned).
	OutcomeGranted SeatRequestOutcome = "granted"
	// OutcomeRefused — the request lost and was REFUSED with a typed error (ErrSeatHeld
	// / ErrStealAttended); not a second live seat, not a silent drop.
	OutcomeRefused SeatRequestOutcome = "refused"
	// OutcomeDropped — the request was neither granted nor refused (silently dropped);
	// this is the regression the row catches.
	OutcomeDropped SeatRequestOutcome = "dropped"
)

// SeatRequestResult is one concurrent RequestWriterSeat and how the terminator
// resolved it. For a conforming contended session exactly one is OutcomeGranted and
// the rest are OutcomeRefused.
type SeatRequestResult struct {
	// Driver labels the requesting driver for violation messages (e.g. "user:alice").
	Driver string `json:"driver"`
	// Outcome is how the single terminator resolved this request.
	Outcome SeatRequestOutcome `json:"outcome"`
}

// SeatArbitration is a synthetic fixture's full concurrent-arbitration picture for
// one session: the set of concurrent RequestWriterSeat results.
type SeatArbitration struct {
	Name     string              `json:"-"`
	Requests []SeatRequestResult `json:"requests"`
}

// CheckExactlyOneWriterSeat scans a synthetic concurrent-arbitration picture and
// returns every one-writer breach. An empty result means the picture conforms:
// exactly one concurrent request was granted, every other was refused, and none was
// silently dropped.
func CheckExactlyOneWriterSeat(a SeatArbitration) []Violation {
	var vs []Violation
	granted := 0
	for _, r := range a.Requests {
		switch r.Outcome {
		case OutcomeGranted:
			granted++
		case OutcomeRefused:
			// the conforming loser: refused with a typed error, never a second seat
		case OutcomeDropped:
			vs = append(vs, Violation{
				Class:   ViolationLoserSilentlyDropped,
				Subject: driverLabel(r.Driver),
				Reason: fmt.Sprintf("RequestWriterSeat by %s was neither granted nor refused (silently "+
					"dropped); a losing seat request MUST be REFUSED with a typed error, never silently "+
					"dropped (sessions/10 §5 claim 1; D61)", driverLabel(r.Driver)),
			})
		default:
			vs = append(vs, Violation{
				Class:   ViolationLoserSilentlyDropped,
				Subject: driverLabel(r.Driver),
				Reason: fmt.Sprintf("RequestWriterSeat by %s resolved to outcome %q outside the enumerated "+
					"{granted, refused} set — a request must resolve to a grant or a typed refusal, never an "+
					"unclassified disposition (sessions/10 §5 claim 1; D61)", driverLabel(r.Driver), r.Outcome),
			})
		}
	}
	if granted > 1 {
		vs = append(vs, Violation{
			Class:   ViolationTwoLiveSeats,
			Subject: arbLabel(a.Name),
			Reason: fmt.Sprintf("%d concurrent RequestWriterSeat resolved to a live grant for one session; "+
				"exactly ONE writer seat is live per session — a second concurrent writer is STRUCTURALLY "+
				"impossible at the single terminator, not policy-forbidden after the fact (sessions/10 §5 "+
				"claim 1; D61 one-writer/N-reader)", granted),
		})
	}
	if granted == 0 && len(a.Requests) > 0 {
		vs = append(vs, Violation{
			Class:   ViolationNoSeatGranted,
			Subject: arbLabel(a.Name),
			Reason: "a contended session granted NO seat at all; exactly one concurrent request must win " +
				"the one seat — the seat is not left unowned when drivers contend (sessions/10 §5 claim 1; D61)",
		})
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// CLAIM 2 — no drive without a live grant (sessions/10 §5 claim 2; D61/D137).
//
// THE CLAIM: a DriveInput whose writer_seat_id is absent / stale / forged / expired
// / yielded reaches NO stdin and is REJECTED, and NO InputActivity is emitted for
// it. Only a DriveInput carrying the ONE live grant is admitted (reaches stdin AND
// emits exactly one read-leg InputActivity). The synthetic fixture models, per
// DriveInput, whether its writer_seat_id matched the live grant, whether it reached
// stdin, and whether an InputActivity was emitted (the SeatArbiter.ValidateDrive
// choke point, writerseat.go). A conforming picture: a matching-seat input reaches
// stdin AND emits exactly one InputActivity; a non-matching-seat input reaches NO
// stdin AND emits NO InputActivity. A rejected drive that reached stdin, or that
// emitted an InputActivity, FAILS NAMED.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationRejectedDriveReachedStdin — a DriveInput NOT carrying the live grant
	// reached Claude Code's stdin; a stale/forged/absent seat id must reach NO stdin.
	ViolationRejectedDriveReachedStdin ViolationClass = "rejected-drive-reached-stdin"
	// ViolationRejectedDriveEmittedActivity — a DriveInput NOT carrying the live grant
	// emitted an InputActivity on the read stream; a rejected drive must emit NONE
	// (sessions/10 §5 claim 2 — "assert no InputActivity is emitted for it").
	ViolationRejectedDriveEmittedActivity ViolationClass = "rejected-drive-emitted-input-activity"
	// ViolationAdmittedDriveNoActivity — a DriveInput carrying the live grant reached
	// stdin but emitted NO InputActivity; every ACCEPTED input must emit exactly one
	// read-leg InputActivity so spectators see the driver typed (D78 clock advances).
	ViolationAdmittedDriveNoActivity ViolationClass = "admitted-drive-emitted-no-input-activity"
)

// SeatPresentation names whether a DriveInput's writer_seat_id matched the session's
// one live grant at the ValidateDrive choke point. A non-matching presentation
// (absent / stale / forged / expired / yielded) is not a live grant.
type SeatPresentation string

const (
	// PresentationLiveGrant — the DriveInput carried the session's ONE live grant; the
	// only presentation that may be admitted.
	PresentationLiveGrant SeatPresentation = "live_grant"
	// PresentationAbsent — the DriveInput carried no writer_seat_id (empty).
	PresentationAbsent SeatPresentation = "absent"
	// PresentationStale — the DriveInput carried a superseded/expired/yielded seat id
	// (minted once, no longer the live grant).
	PresentationStale SeatPresentation = "stale"
	// PresentationForged — the DriveInput carried an id this terminator never minted.
	PresentationForged SeatPresentation = "forged"
)

// DriveAttempt is one synthetic DriveInput against the drive leg: how its
// writer_seat_id presented at the ValidateDrive choke point, whether it reached
// stdin, and whether an InputActivity was emitted for it. For a conforming
// live-grant attempt: reached stdin AND one activity. For a conforming non-live
// attempt: NO stdin AND NO activity.
type DriveAttempt struct {
	// Name labels the attempt for violation messages (e.g. "forged-seat-frame").
	Name string `json:"name"`
	// Presentation is how the DriveInput's writer_seat_id presented at ValidateDrive.
	Presentation SeatPresentation `json:"presentation"`
	// ReachedStdin records whether the input reached Claude Code's stdin via the relay.
	ReachedStdin bool `json:"reached_stdin"`
	// InputActivityEmitted records whether a read-leg InputActivity was emitted for it.
	InputActivityEmitted bool `json:"input_activity_emitted"`
}

// DriveAttemptSet is a synthetic fixture's full drive-leg picture for one session.
type DriveAttemptSet struct {
	Name     string         `json:"-"`
	Attempts []DriveAttempt `json:"attempts"`
}

// CheckNoDriveWithoutGrant scans a synthetic drive-leg picture and returns every
// no-drive-without-grant breach. An empty result means the picture conforms: a
// non-live presentation reached NO stdin and emitted NO InputActivity, and a
// live-grant presentation that reached stdin emitted exactly one InputActivity.
func CheckNoDriveWithoutGrant(s DriveAttemptSet) []Violation {
	var vs []Violation
	for _, a := range s.Attempts {
		live := a.Presentation == PresentationLiveGrant
		if !live {
			if a.ReachedStdin {
				vs = append(vs, Violation{
					Class:   ViolationRejectedDriveReachedStdin,
					Subject: attemptLabel(a.Name),
					Reason: fmt.Sprintf("DriveInput %s presented an %s seat id (not the live grant) yet "+
						"reached Claude Code's stdin; a stale/forged/absent writer_seat_id must reach NO "+
						"stdin (sessions/10 §5 claim 2; D61/D137 ValidateDrive choke point)",
						attemptLabel(a.Name), a.Presentation),
				})
			}
			if a.InputActivityEmitted {
				vs = append(vs, Violation{
					Class:   ViolationRejectedDriveEmittedActivity,
					Subject: attemptLabel(a.Name),
					Reason: fmt.Sprintf("DriveInput %s presented an %s seat id (not the live grant) yet "+
						"emitted an InputActivity on the read stream; a rejected drive must emit NONE — assert "+
						"no InputActivity is emitted for it (sessions/10 §5 claim 2)",
						attemptLabel(a.Name), a.Presentation),
				})
			}
			continue
		}
		// A live-grant input that was admitted (reached stdin) MUST emit exactly one
		// InputActivity so spectators see the driver typed and the D78 clock advances.
		if a.ReachedStdin && !a.InputActivityEmitted {
			vs = append(vs, Violation{
				Class:   ViolationAdmittedDriveNoActivity,
				Subject: attemptLabel(a.Name),
				Reason: fmt.Sprintf("DriveInput %s carried the live grant and reached stdin but emitted NO "+
					"InputActivity; every ACCEPTED input emits exactly one read-leg InputActivity so "+
					"spectators see the driver typed and the D78 attendedness clock advances (writer_relay."+
					"proto; events.proto §6.1 row 7)", attemptLabel(a.Name)),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// CLAIM 3 — every seat grant/steal/yield is attributed and observable
// (sessions/10 §5 claim 3; D8/D55/D61/D137).
//
// THE CLAIM: a grant/steal/yield is a record mutation carrying the driver's D8/D55
// identity AND it is OBSERVABLE on the read stream at granted_seq — the W2-added
// WRITER_SEAT_CHANGED event every N-reader sees (a steal CANNOT be silent). The
// synthetic fixture models, per handoff, its kind (grant | steal | yield), whether
// a WRITER_SEAT_CHANGED read event was emitted, the seq it was observed at, and the
// attribution it carried. A conforming handoff: emitted an event at a real seq with
// the attribution its kind requires (a GRANT/STEAL names the new driver; a STEAL
// also names whom it was taken from; a YIELD names whom it was released from). A
// handoff that emitted NO read event (a silent handoff), was observed at seq 0 (no
// ordering point), or carried no required attribution, FAILS NAMED.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationHandoffNotObservable — a seat grant/steal/yield emitted NO
	// WRITER_SEAT_CHANGED read event; a handoff (a steal especially) cannot be silent.
	ViolationHandoffNotObservable ViolationClass = "seat-handoff-not-observable-on-read-stream"
	// ViolationHandoffNoGrantedSeq — a seat handoff's read event was observed at seq 0
	// (no ordering point); the WRITER_SEAT_CHANGED seq IS the granted_seq/released_seq
	// the write leg returns, so every reader and the new driver agree on the one
	// ordering point the seat changed hands at.
	ViolationHandoffNoGrantedSeq ViolationClass = "seat-handoff-missing-granted-seq"
	// ViolationHandoffNoAttribution — a seat grant/steal carried no D8/D55 new-driver
	// identity, or a steal/yield carried no prev-driver attribution; every handoff is
	// an attributed record mutation (D8/D55).
	ViolationHandoffNoAttribution ViolationClass = "seat-handoff-missing-attribution"
)

// HandoffKind classifies a writer-seat handoff (mirrors WriterSeatChangeKind,
// events.proto; sessions/10 §3, D138).
type HandoffKind string

const (
	// HandoffGrant — a free seat was granted to a driver (no prior live holder, or a
	// renewal by the same driver).
	HandoffGrant HandoffKind = "grant"
	// HandoffSteal — a takeover from a prior live holder (policy-gated when attended).
	HandoffSteal HandoffKind = "steal"
	// HandoffYield — the cooperative release of the seat (the seat goes free).
	HandoffYield HandoffKind = "yield"
)

// SeatHandoff is one synthetic writer-seat handoff and its read-leg projection: the
// kind, whether a WRITER_SEAT_CHANGED read event was emitted, the seq it was
// observed at, and the attributions it carried. For a conforming handoff the event
// is emitted at a non-zero seq with the attribution the kind requires.
type SeatHandoff struct {
	// Name labels the handoff for violation messages (e.g. "alice-grant").
	Name string `json:"name"`
	// Kind is the handoff kind (grant | steal | yield).
	Kind HandoffKind `json:"kind"`
	// EventEmitted records whether a WRITER_SEAT_CHANGED read event was emitted.
	EventEmitted bool `json:"event_emitted"`
	// ObservedSeq is the read-stream seq the event was observed at (the granted_seq /
	// released_seq). It MUST be non-zero for an emitted event.
	ObservedSeq uint64 `json:"observed_seq"`
	// NewDriver is the D8/D55-attributed new holder (set on grant/steal; empty on yield).
	NewDriver string `json:"new_driver"`
	// PrevDriver is whom the seat was taken/released FROM (set on steal/yield; may be
	// empty on a first grant of a never-held seat).
	PrevDriver string `json:"prev_driver"`
}

// SeatHandoffSet is a synthetic fixture's full handoff picture for one session.
type SeatHandoffSet struct {
	Name     string        `json:"-"`
	Handoffs []SeatHandoff `json:"handoffs"`
}

// CheckSeatChangeAttributedObservable scans a synthetic handoff picture and returns
// every attribution/observability breach. An empty result means the picture
// conforms: every handoff emitted a WRITER_SEAT_CHANGED event at a non-zero seq with
// the attribution its kind requires.
func CheckSeatChangeAttributedObservable(s SeatHandoffSet) []Violation {
	var vs []Violation
	for _, h := range s.Handoffs {
		if !h.EventEmitted {
			vs = append(vs, Violation{
				Class:   ViolationHandoffNotObservable,
				Subject: handoffLabel(h.Name),
				Reason: fmt.Sprintf("seat handoff %s (%s) emitted NO WRITER_SEAT_CHANGED read event; every "+
					"grant/steal/yield is observable on the read stream — a steal CANNOT be silent "+
					"(sessions/10 §5 claim 3; D61/D137 W2 read event)", handoffLabel(h.Name), h.Kind),
			})
			// No observable event ⇒ no ordering point and no attribution surfaced; the
			// not-observable class subsumes the rest for this handoff.
			continue
		}
		if h.ObservedSeq == 0 {
			vs = append(vs, Violation{
				Class:   ViolationHandoffNoGrantedSeq,
				Subject: handoffLabel(h.Name),
				Reason: fmt.Sprintf("seat handoff %s (%s) emitted a read event but at seq 0; the "+
					"WRITER_SEAT_CHANGED seq IS the granted_seq/released_seq the write leg returns — every "+
					"N-reader and the new driver must agree on the one non-zero ordering point the seat "+
					"changed hands at (sessions/10 §5 claim 3)", handoffLabel(h.Name), h.Kind),
			})
		}
		// Attribution the kind requires (D8/D55): a grant/steal names the new driver; a
		// steal/yield names whom the seat was taken/released from.
		switch h.Kind {
		case HandoffGrant:
			if h.NewDriver == "" {
				vs = append(vs, attribMiss(h, "a GRANT must name the D8/D55-attributed new driver"))
			}
		case HandoffSteal:
			if h.NewDriver == "" {
				vs = append(vs, attribMiss(h, "a STEAL must name the D8/D55-attributed new driver"))
			}
			if h.PrevDriver == "" {
				vs = append(vs, attribMiss(h, "a STEAL must name whom the seat was taken FROM (prev driver)"))
			}
		case HandoffYield:
			if h.PrevDriver == "" {
				vs = append(vs, attribMiss(h, "a YIELD must name whom the seat was released FROM (prev driver)"))
			}
		}
	}
	sortViolations(vs)
	return vs
}

// attribMiss builds the missing-attribution violation for a handoff with a
// kind-specific reason.
func attribMiss(h SeatHandoff, what string) Violation {
	return Violation{
		Class:   ViolationHandoffNoAttribution,
		Subject: handoffLabel(h.Name),
		Reason: fmt.Sprintf("seat handoff %s (%s) carried no required attribution: %s; every handoff is an "+
			"attributed record mutation (sessions/10 §5 claim 3; D8/D55)", handoffLabel(h.Name), h.Kind, what),
	}
}

// ────────────────────────────────────────────────────────────────────────────
// CLAIM 4 — a ROLE_READER (no grant) provably cannot reach the WriterRelayService
// RPCs / DriveSession stream (sessions/10 §5 claim 4; the D137 re-green of the
// 01KTWJ64M0 no-inject barrier).
//
// THE CLAIM (D137 amendment, sessions/10 §3c / §5 claim 4): the OLD argument was
// "v1 has no input message" — that is now FALSE (attach.v1 carries the WriterRelay
// write leg in-place). The re-green therefore asserts a ROLE_READER provably CANNOT
// reach the WriterRelayService RPCs (RequestWriterSeat / YieldWriterSeat /
// DriveSession): a reader holds only an attach.v1 AttachHandle{role=ROLE_READER} + a
// v1 WatchSession subscription — NO WriterRelay grant, NO DriveSession stream. The
// ONLY path to stdin is DriveSession behind a server-granted WriterSeatGrant behind
// D22/D55 auth. The synthetic fixture models, per participant, the held attach role,
// whether the participant was permitted to reach each WriterRelay surface, and
// whether the participant's input reached stdin. A conforming picture: a ROLE_READER
// reached NO WriterRelay surface and NO stdin (the read-only legs stay read-only with
// the write path present); a ROLE_READER who reached a write surface or stdin FAILS
// NAMED. Adding the write leg must NOT open a v1 injection path (the critical
// regression this re-green exists to catch).
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationReaderReachedWriterRelay — a ROLE_READER reached a WriterRelayService
	// RPC (RequestWriterSeat / YieldWriterSeat / DriveSession); a reader holds no grant
	// and no drive stream, so no WriterRelay surface is reachable by it.
	ViolationReaderReachedWriterRelay ViolationClass = "reader-reached-writer-relay-rpc"
	// ViolationReaderInputReachedStdin — a ROLE_READER's input reached Claude Code's
	// stdin; the read-only surfaces (v1 WatchSession / SSE / WS) stay structurally
	// read-only with the write leg present — a reader has no path to stdin.
	ViolationReaderInputReachedStdin ViolationClass = "reader-input-reached-stdin"
)

// AttachRole names the held attach.v1 AttachHandle role (attach_handle.proto:
// ROLE_UNSPECIFIED | ROLE_WRITER | ROLE_READER).
type AttachRole string

const (
	// RoleReader — a ROLE_READER: a read-only spectator. Holds only a v1 WatchSession
	// subscription; NO WriterRelay grant, NO DriveSession stream. May NOT inject.
	RoleReader AttachRole = "ROLE_READER"
	// RoleWriter — a ROLE_WRITER: a participant who has been GRANTED the one writer
	// seat. The only role that may reach the drive surface and stdin.
	RoleWriter AttachRole = "ROLE_WRITER"
)

// WriterRelaySurface names a WriterRelayService RPC a reader must not reach
// (writer_relay.proto). Used to label which write surface a participant touched.
type WriterRelaySurface string

const (
	// SurfaceRequestWriterSeat — the RequestWriterSeat arbitration RPC.
	SurfaceRequestWriterSeat WriterRelaySurface = "RequestWriterSeat"
	// SurfaceYieldWriterSeat — the YieldWriterSeat arbitration RPC.
	SurfaceYieldWriterSeat WriterRelaySurface = "YieldWriterSeat"
	// SurfaceDriveSession — the DriveSession drive stream — the only path to stdin.
	SurfaceDriveSession WriterRelaySurface = "DriveSession"
)

// Participant is one synthetic live-view participant against the write leg: the
// held attach role, the WriterRelay surfaces it was permitted to reach, and whether
// its input reached stdin. For a conforming ROLE_READER: NO reached surfaces and NO
// stdin.
type Participant struct {
	// Name labels the participant for violation messages (e.g. "spectator-bob").
	Name string `json:"name"`
	// Role is the held attach.v1 AttachHandle role.
	Role AttachRole `json:"role"`
	// ReachedWriterRelaySurfaces lists the WriterRelayService RPCs this participant was
	// permitted to reach. For a ROLE_READER this MUST be empty.
	ReachedWriterRelaySurfaces []WriterRelaySurface `json:"reached_writer_relay_surfaces"`
	// InputReachedStdin records whether the participant's input reached Claude Code's
	// stdin. For a ROLE_READER this MUST be false.
	InputReachedStdin bool `json:"input_reached_stdin"`
}

// ParticipantSet is a synthetic fixture's write-leg participant picture for one
// session (with the v2 write path present).
type ParticipantSet struct {
	Name         string        `json:"-"`
	Participants []Participant `json:"participants"`
}

// CheckReaderCannotReachWriterRelay scans a synthetic write-leg participant picture
// and returns every reader-escalation breach. An empty result means the picture
// conforms: no ROLE_READER reached any WriterRelayService RPC and no ROLE_READER's
// input reached stdin (the read-only surfaces stay read-only with the write leg
// present — the D137 re-green of the 01KTWJ64M0 no-inject barrier).
func CheckReaderCannotReachWriterRelay(s ParticipantSet) []Violation {
	var vs []Violation
	for _, p := range s.Participants {
		if p.Role != RoleReader {
			// A ROLE_WRITER (granted seat) may reach the drive surface and stdin — the
			// row does not over-claim; only a no-grant reader is barred.
			continue
		}
		for _, surf := range p.ReachedWriterRelaySurfaces {
			vs = append(vs, Violation{
				Class:   ViolationReaderReachedWriterRelay,
				Subject: participantLabel(p.Name),
				Reason: fmt.Sprintf("ROLE_READER %s reached WriterRelayService.%s; a reader holds only an "+
					"attach.v1 AttachHandle{role=ROLE_READER} + a v1 WatchSession subscription — NO "+
					"WriterRelay grant, NO DriveSession stream. The only path to stdin is DriveSession "+
					"behind a server-granted WriterSeatGrant behind D22/D55 auth (sessions/10 §5 claim 4; "+
					"the D137 no-inject re-green)", participantLabel(p.Name), surf),
			})
		}
		if p.InputReachedStdin {
			vs = append(vs, Violation{
				Class:   ViolationReaderInputReachedStdin,
				Subject: participantLabel(p.Name),
				Reason: fmt.Sprintf("ROLE_READER %s's input reached Claude Code's stdin; the read-only "+
					"surfaces (v1 WatchSession / SSE / WS) stay STRUCTURALLY read-only with the v2 write leg "+
					"present — adding the write path must NOT open a v1 injection path (sessions/10 §5 claim "+
					"4; the critical regression the 01KTWJ64M0 re-green catches)", participantLabel(p.Name)),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ────────────────────────────────────────────────────────────────────────────
// CLAIM 5 — D78 honesty: a DETACHED seat reads unattended even with N spectators
// (sessions/10 §5 claim 5; D78).
//
// THE CLAIM: attendedness still requires a human HOLDING the one writer seat AND
// producing input within T — spectator presence NEVER feeds the signal. The
// synthetic fixture models, per session, whether the seat is held (a live writer
// grant) with recent input, the number of read-only spectators, and the
// attendedness the signal reported. A conforming session: attended IFF the seat is
// held-with-recent-input, regardless of how many spectators are present — a DETACHED
// seat reads UNATTENDED even with N spectators. A detached seat that read attended,
// or attendedness that rose with spectator count, FAILS NAMED.
// ────────────────────────────────────────────────────────────────────────────

const (
	// ViolationDetachedSeatReadsAttended — a session with a DETACHED writer seat (no
	// live held seat with recent input) reported ATTENDED; a detached seat must read
	// unattended (D78), no matter the spectator count.
	ViolationDetachedSeatReadsAttended ViolationClass = "detached-seat-reads-attended"
	// ViolationSpectatorsFedAttendedness — a session reported ATTENDED on the strength
	// of spectator presence alone (seat NOT held-with-recent-input); spectator presence
	// NEVER feeds attendedness (D78 §3e).
	ViolationSpectatorsFedAttendedness ViolationClass = "spectator-presence-fed-attendedness"
)

// AttendednessReport is one synthetic D78 attendedness picture for a session: the
// seat-held-with-recent-input fact, the spectator count, and the attendedness the
// signal reported. For a conforming report: Attended == SeatHeldWithRecentInput,
// regardless of Spectators.
type AttendednessReport struct {
	// Name labels the session for violation messages (e.g. "n-spectators-detached").
	Name string `json:"name"`
	// SeatHeldWithRecentInput is the ONLY thing that makes a session attended: a human
	// holds the one writer seat AND produced input within T (D78).
	SeatHeldWithRecentInput bool `json:"seat_held_with_recent_input"`
	// Spectators is the number of read-only spectators present (they NEVER count).
	Spectators int `json:"spectators"`
	// Attended is the attendedness the signal reported. It MUST equal
	// SeatHeldWithRecentInput, independent of Spectators.
	Attended bool `json:"attended"`
}

// AttendednessSet is a synthetic fixture's full D78 attendedness picture.
type AttendednessSet struct {
	Name    string               `json:"-"`
	Reports []AttendednessReport `json:"reports"`
}

// CheckAttendednessHonest scans a synthetic D78 attendedness picture and returns
// every honesty breach. An empty result means the picture conforms: attendedness is
// reported IFF the seat is held-with-recent-input, never on spectator presence — a
// DETACHED seat reads unattended even with N spectators.
func CheckAttendednessHonest(s AttendednessSet) []Violation {
	var vs []Violation
	for _, r := range s.Reports {
		if r.Attended && !r.SeatHeldWithRecentInput {
			// Detached (no held seat with recent input) yet read attended. If spectators
			// are present, that is the spectator-fed-attendedness breach specifically;
			// otherwise it is a plain detached-reads-attended breach.
			if r.Spectators > 0 {
				vs = append(vs, Violation{
					Class:   ViolationSpectatorsFedAttendedness,
					Subject: reportLabel(r.Name),
					Reason: fmt.Sprintf("session %s reported ATTENDED with %d spectator(s) but NO seat held "+
						"with recent input; spectator presence NEVER feeds attendedness — attended requires a "+
						"human HOLDING the one writer seat AND producing input within T (sessions/10 §5 claim "+
						"5; D78 §3e)", reportLabel(r.Name), r.Spectators),
				})
			}
			vs = append(vs, Violation{
				Class:   ViolationDetachedSeatReadsAttended,
				Subject: reportLabel(r.Name),
				Reason: fmt.Sprintf("session %s has a DETACHED writer seat (no live held seat with recent "+
					"input) yet read ATTENDED; a detached seat reads UNATTENDED even with N spectators "+
					"(sessions/10 §5 claim 5; D78)", reportLabel(r.Name)),
			})
		}
	}
	sortViolations(vs)
	return vs
}

// ── Labels (blank-safe subject names for violation messages) ─────────────────

func arbLabel(s string) string         { return labelOr(s, "(unnamed seat arbitration)") }
func driverLabel(s string) string      { return labelOr(s, "(unnamed driver)") }
func attemptLabel(s string) string     { return labelOr(s, "(unnamed drive attempt)") }
func handoffLabel(s string) string     { return labelOr(s, "(unnamed seat handoff)") }
func participantLabel(s string) string { return labelOr(s, "(unnamed participant)") }
func reportLabel(s string) string      { return labelOr(s, "(unnamed attendedness report)") }

func labelOr(s, fallback string) string {
	if s != "" {
		return s
	}
	return fallback
}

// ── Loading fixtures (cwd-independent) ───────────────────────────────────────

// thisDir returns the directory of THIS source file (runtime.Caller-anchored), so
// fixture lookups work under `go test` from any cwd.
func thisDir() string {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(thisFile)
}

// FixturesDir is the synthetic-fixture directory, anchored off this file.
func FixturesDir() string { return filepath.Join(thisDir(), "fixtures") }

// LoadJSON reads a synthetic fixture of type T from a JSON file under fixtures/. It
// is the cwd-independent loader the JSON-backed rows use; in-code Go-literal
// fixtures need no loader.
func LoadJSON[T any](path string) (T, error) {
	var v T
	data, err := os.ReadFile(path)
	if err != nil {
		return v, fmt.Errorf("reading writerseat fixture %s: %w", path, err)
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return v, fmt.Errorf("parsing writerseat fixture %s: %w", path, err)
	}
	return v, nil
}
