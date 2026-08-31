package tui

import (
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Decision is the operator's answer to an ask. The three options are the D45
// escape-hatch one-offs surfaced in the D18 client:
//
//   - DecisionAllowOnce  — allow this one operation; the grant dies with the
//     session (D45). Forwarded to the wrapper; nothing stored client-side.
//   - DecisionAllowAlways — a PROPOSAL, not a grant (D45): allow-always is an
//     org-admin acceptance request, delegable by posture. The client forwards
//     the proposal and NEVER stores or applies a standing grant. The wrapper
//     holds no approval state either; the grant, if accepted, arrives later as
//     a TTL'd entry on the policy stream (client/README.md "approval surface").
//   - DecisionDeny       — refuse the operation (D53 deny).
//
// There is no "answer everything" or "remember my choice" affordance: the only
// memory of an approval lives org-side on the policy stream, never here.
type Decision string

const (
	DecisionAllowOnce   Decision = "allow-once"
	DecisionAllowAlways Decision = "allow-always-proposal"
	DecisionDeny        Decision = "deny"
)

// IsProposal reports whether the decision is the allow-always org-admin
// proposal (D45) rather than a session-scoped one-off. The caller uses this to
// surface "submitted for org-admin acceptance" rather than "granted".
func (d Decision) IsProposal() bool { return d == DecisionAllowAlways }

// AskState is the lifecycle of one ask in the view model. An ask opens
// pending; a human decision moves it to answered; a wire AskResolved closes it
// (allow/deny/cancelled). An ask that is never answered stays AskPending and
// PARKS the session — it never times out into allow or kill (D53/D77). The
// renderer shows a parked session as awaiting a human, not as failed.
type AskState string

const (
	// AskPending: surfaced, awaiting a human decision. While any ask is
	// AskPending the session is PARKED (D53): unanswered asks pause-and-wait,
	// they do not auto-resolve.
	AskPending AskState = "pending"
	// AskAnswered: the human chose; the Decision is recorded on the Ask and
	// forwarded through the wrapper. Not the same as resolved — the wire
	// AskResolved is authoritative for the final behavior.
	AskAnswered AskState = "answered"
	// AskResolved: closed by a wire ask.resolved event (behavior
	// allow|deny|cancelled). Terminal.
	AskResolved AskState = "resolved"
)

// Ask is the view-model record of one approval request (attach.AskRequested),
// plus the local decision (if the human has answered) and the wire resolution
// (if it has closed). The client stores NO grant: Decision is the forwarded
// answer for THIS ask, not a standing rule.
type Ask struct {
	AskID    string
	NodeID   string
	ToolName string
	Source   string // "control" | "prompt-tool" | "rearm"
	Pending  bool   // re-armed from a re-attach handshake (attach.AskRequested.Pending)
	Input    []byte // verbatim tool input for display (attach JSON RawMessage)

	State AskState
	// Decision is the human's answer once State == AskAnswered. Zero value
	// ("") until answered. Never an applied grant — see Decision docs.
	Decision Decision
	// Behavior is the wire resolution behavior once State == AskResolved:
	// "allow" | "deny" | "cancelled".
	Behavior string
	// Message is the wire resolution message (e.g. a denial body), if any.
	Message string
}

// answeredByHuman marks the ask as answered with a forwarded decision. It does
// NOT resolve the ask — only a wire AskResolved does — and it stores no grant.
func (a *Ask) answeredByHuman(d Decision) {
	a.State = AskAnswered
	a.Decision = d
}

// applyResolved closes the ask from a wire ask.resolved event.
func (a *Ask) applyResolved(r *attach.AskResolved) {
	a.State = AskResolved
	a.Behavior = r.Behavior
	if r.Message != "" {
		a.Message = r.Message
	}
}
