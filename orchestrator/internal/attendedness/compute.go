package attendedness

// compute.go owns the D78 attendedness COMPUTATION (doc 15 §5.5). The signal is
// derived control-plane-side from the AUTHORITATIVE writer-seat state in the
// session record — the D61 source of truth ("the writer seat lives in the session
// record; a driver handoff is a record mutation with attribution", seat.go). It is
// a pure function over that state plus the server clock: no I/O, no store reads —
// the caller hands in the seat view and the clock, so the computation stays
// deterministic and unit-testable, and the transport leg (transport.go) is the one
// place a SessionLifecycleUpdate is assembled.
//
// M0/M1 INTERIM — WRITER-ATTACHED-ONLY (doc 15 §5.5, D78). The frozen full
// definition is "a human holds the one writer seat AND produced input within the
// last T minutes". The "...AND recent input" half needs the attach wrapper's
// input-activity events, which are NOT yet exposed (doc 15 §6.1 row 7: RESERVED +
// WAIVED) — so this leg implements ONLY the writer-attached half. The code is
// STRUCTURED for the refinement: Policy.RecentInputWindow carries T as a POL-1
// org-tunable VALUE (never a hardcoded constant), and Input threads the
// last-input clock through Compute so the recent-input gate drops in additively
// WHEN the events land — without that input the gate is a no-op and the result is
// writer-attached-only, exactly the interim.

import "time"

// AttachRole is the D61 seat class the attendedness computation keys on, mirrored
// here as a tiny value type so the computation depends on the seat CLASS, not on
// the store package (no import coupling: the caller maps store.RoleWriter /
// store.RoleReader / store.RoleNone onto these when it fills the SeatView). Only
// RoleWriter counts toward attendedness; readers and the empty role never do.
type AttachRole string

const (
	// RoleNone is the no-seat / writer-less state — never attended.
	RoleNone AttachRole = ""
	// RoleWriter is the one writer seat (D61). A HUMAN holding it is the only seat
	// class that counts toward attendedness (doc 15 §5.5).
	RoleWriter AttachRole = "WRITER"
	// RoleReader is one of the N readers — canvas, console, and spectators all
	// attach here. Readers NEVER count toward attendedness (doc 15 §5.5).
	RoleReader AttachRole = "READER"
)

// Policy carries the org-tunable POL-1 attendedness VALUES (doc 15 §5.5, D78).
// These are policy, never code: a deployment tunes them; nothing here is a frozen
// contract. The zero Policy is the writer-attached-only interim (RecentInputWindow
// == 0 disables the recent-input gate), which is exactly the M0/M1 behavior.
type Policy struct {
	// RecentInputWindow is T — "...AND produced input within the last T minutes"
	// (doc 15 §5.5, T ≈ 10 min). It is the POL-1 org-tunable value carried as
	// policy, NEVER a hardcoded constant. M0/M1 INTERIM: the recent-input events
	// are not yet exposed, so this is structurally present but a no-op unless the
	// caller threads a real last-input timestamp through Input (which it cannot
	// yet) — leaving the result writer-attached-only. When the attach wrapper
	// lands input-activity events, setting this (and Input.LastInputAt) turns the
	// recent-input gate on additively, with no signature change. A zero or
	// negative window disables the gate (the interim).
	RecentInputWindow time.Duration
}

// DefaultRecentInputWindow is the doc 15 §5.5 strawman for T (≈10 min). It is a
// documented STRAWMAN for the POL-1 value, NOT a frozen constant and NOT consulted
// by the interim computation — it only names the documented default so a caller
// that wires the policy need not re-derive it once input-activity events land.
const DefaultRecentInputWindow = 10 * time.Minute

// SeatView is the writer-seat half of the attendedness input: who (if anyone)
// holds the one writer seat right now, as projected from the AUTHORITATIVE session
// record (the D61 source of truth). The caller fills it from store.Session
// (WriterRole/WriterSeat) or from a live attach.SeatGrant. A detach clears the
// record's writer seat (attach.ReleaseWriter), so Role flips to RoleNone and the
// next Compute reports attended == false — the signal tracks the record honestly
// across the transition (D78); enforcing the in-flight-hold grace is the
// CONSUMER's job (TLS-1 socket-hold), never this computation's.
type SeatView struct {
	// Role is the seat class the record currently records for the writer seat
	// (D61). Only RoleWriter with a non-empty Holder counts toward attendedness;
	// RoleReader and RoleNone never do — spectators, readers, and canvas viewers
	// attach as readers and MUST NOT make a session count as attended (doc 15
	// §5.5).
	Role AttachRole

	// Holder is the writer-seat holder identity (attribution) — non-empty exactly
	// when a writer holds the seat. An empty Holder with RoleWriter is treated as
	// NOT attended (a writer role with no holder is not a human on the seat): the
	// computation refuses to claim attended on an anonymous/half-cleared seat.
	Holder string
}

// Input is the recent-input half of the attendedness definition (the "...AND
// produced input within the last T minutes" gate, doc 15 §5.5). M0/M1 INTERIM:
// the attach wrapper does not yet expose input-activity events, so the caller
// CANNOT populate HasInputSignal yet — it is left false, and Compute then runs the
// writer-attached-only interim (the recent-input gate is skipped). When the events
// land, the caller sets HasInputSignal and LastInputAt, and the gate engages
// additively with no signature change.
type Input struct {
	// HasInputSignal reports whether a real last-input timestamp is available. M0/M1
	// INTERIM: always false (the events are not exposed). False means "recent-input
	// gate not applicable" — the interim runs writer-attached-only. It is NOT
	// "no recent input" (which would wrongly force unattended); the gate only
	// applies when an actual signal exists.
	HasInputSignal bool

	// LastInputAt is the server-stamped time of the writer seat holder's most
	// recent input (the §5.5/D78 freshness clock for input). Meaningful only when
	// HasInputSignal is true. Unused in the interim.
	LastInputAt time.Time
}

// Signal is the computed D78 attendedness verdict for one session at one instant:
// the boolean the host-ward SessionLifecycleUpdate carries (Attended) plus the
// server-side freshness clock the value is stamped at (AttendedAt, §5.5/D78). It
// is what the transport leg (transport.go) folds onto the lifecycle feed.
type Signal struct {
	// Attended is the D78 verdict: true iff a human holds the one writer seat (and,
	// once input-activity events land, produced input within Policy.RecentInputWindow).
	// M0/M1 interim: writer-attached-only.
	Attended bool

	// AttendedAt is the SERVER-SIDE freshness clock for Attended (§5.5/D78) — the
	// instant the control plane computed this verdict, in unix seconds. The
	// few-seconds freshness budget the consumer measures is taken against THIS, so
	// it is stamped on EVERY compute (both attended and unattended verdicts), never
	// only when attended flips true: a stale-but-true value and a fresh-false value
	// must both be distinguishable downstream.
	AttendedAt uint64
}

// Compute derives the D78 attendedness signal from the writer-seat view and the
// (interim-empty) recent-input view, stamping the server clock `now` as the
// freshness instant (doc 15 §5.5, D78). It is pure: same inputs → same output, no
// I/O, no ambient clock.
//
// The verdict (M0/M1 interim = writer-attached-only):
//
//   - attended == true iff a HUMAN holds the one writer seat: Role == RoleWriter
//     AND Holder != "". Readers (canvas/console/spectators) and the writer-less
//     state never count (doc 15 §5.5).
//   - the recent-input gate (Policy.RecentInputWindow + Input) only TIGHTENS the
//     verdict, and only when a real input signal exists (Input.HasInputSignal).
//     In the interim no signal exists, so the gate is skipped and the result is
//     writer-attached-only. When the events land, an attended-by-seat session
//     whose last input is older than the window downgrades to unattended —
//     additively, with this same signature.
//
// AttendedAt is stamped on every call (attended or not) so the consumer's
// few-seconds freshness budget is always measured against a real server clock.
func Compute(seat SeatView, input Input, policy Policy, now time.Time) Signal {
	attended := seat.Role == RoleWriter && seat.Holder != ""

	// Recent-input gate — TIGHTENING ONLY, and only when a real signal exists.
	// In the M0/M1 interim input.HasInputSignal is always false, so this whole
	// block is skipped and the result is writer-attached-only. The refinement
	// drops in here additively when the attach wrapper exposes input-activity.
	if attended && input.HasInputSignal && policy.RecentInputWindow > 0 {
		if now.Sub(input.LastInputAt) > policy.RecentInputWindow {
			attended = false
		}
	}

	return Signal{
		Attended:   attended,
		AttendedAt: uint64(now.Unix()),
	}
}
