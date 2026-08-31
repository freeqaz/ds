// Package driver is serpent-tui's WRITER-seat input leg: it forwards human
// keystrokes and ask answers to the agent's stdin THROUGH the host-agent bridge
// (D18 — input goes to the runtime's stdin via the wrapper, never to a frame
// buffer). The one writer seat is arbitrated SERVER-SIDE (D61, doc 15 §5.3); this
// leg carries input only when it holds the writer seat and never arbitrates it.
//
// WHY NOT WatchSession. The frozen orchestrator.v1 has no write RPC: WatchSession
// is the READ fan-out (serpent-tui/internal/watch). The writer seat's input path
// is the DIRECT client->host-agent endpoint the AttachHandle carries (doc 15
// §5.4), realized by client/hostbridge's framed-UDS SocketTransport: a WRITER
// handle Dial()s the direct endpoint and DriveInput/DriveGrant onto CC stdin
// through the EXISTING wrapper driver (the Driver stays the only encoder — the
// bridge carries the bytes, serpent-tui never hand-rolls a CC record).
//
// APPROVALS ARE TTL'd GRANTS, NOT A SECOND CHANNEL (D45/D53). An ask answer is a
// DriveGrant routed to the bridge's existing driver (the proven prompt-tool route
// by default). The client stores NO standing grant: allow-always is a PROPOSAL
// for org-admin acceptance (D45), forwarded once, never persisted. The wrapper
// holds no approval state either; an accepted grant arrives later as a TTL'd
// entry on the policy stream, never echoed back here as a second proxy channel.
package driver

import (
	"errors"
	"fmt"

	"github.com/dream-serpent/dream-serpent/client/hostbridge"
	"github.com/dream-serpent/dream-serpent/client/tui"
)

// GrantRoute re-exports the hostbridge grant-encoding route so callers selecting
// the ask-answer route do not import client/hostbridge directly. It is
// type-identical (an alias), so a value passed here IS a hostbridge.GrantRoute.
type GrantRoute = hostbridge.GrantRoute

// GrantRoutePromptTool / GrantRouteNativeControl re-export the two routes (the
// proven prompt-tool route is the v0 default; the native control_response route
// is the documented-not-yet-live-verified alternative). Re-exported for the same
// no-leak reason as the GrantRoute alias.
const (
	GrantRoutePromptTool    = hostbridge.GrantRoutePromptTool
	GrantRouteNativeControl = hostbridge.GrantRouteNativeControl
)

// WriterSeat is the narrow writer-seat seam the loop drives through: forward a
// line of operator input to the agent's stdin, and forward an ask answer. It is
// satisfied by a hostbridge SocketConn (the real direct-endpoint writer, via
// SeatFromSocket) and by an in-process fake (tests / offline). It is the
// serpent-tui-local twin of the client/tui Writer interface, but typed against
// the hostbridge DriveInput/DriveGrant shapes the host-agent actually consumes.
type WriterSeat interface {
	// DriveInput forwards a single line of operator input to the agent's stdin.
	DriveInput(in hostbridge.DriveInput) error
	// DriveGrant forwards an ask answer (allow/deny) via the chosen route.
	DriveGrant(grant hostbridge.DriveGrant, route hostbridge.GrantRoute) error
}

// Writer adapts a WriterSeat to the client/tui.Writer interface the interactive
// loop and the App ask-prompt flow expect, translating an operator line into a
// hostbridge.DriveInput and a tui.Decision into a hostbridge.DriveGrant. It holds
// NO approval state (D45/D53) — every answer is forwarded once and forgotten.
//
// askKeys resolves a tui ask id to the driver's join keys: the writer-seat answer
// joins on request_id (native control route) or tool_use_id (prompt-tool route),
// which are DISTINCT from the tui AskID (the eventmap collapses request_id||
// tool_use_id into AskID, so the loop must recover the route keys). The default
// is the proven prompt-tool route keyed on the AskID as the tool_use_id; a caller
// with the native control join sets Route + a RequestID resolver.
type Writer struct {
	Seat WriterSeat
	// Route selects the grant encoding: the proven prompt-tool route (default,
	// joins on ToolUseID) or the native control_response route (joins on
	// RequestID). The bridge does not decide protocol fidelity — it forwards the
	// caller's chosen route to the existing driver.
	Route hostbridge.GrantRoute
	// ResolveAsk maps a tui ask id to the (toolUseID, requestID) join pair the
	// driver needs. Nil ⇒ the ask id IS the tool_use_id (the prompt-tool default,
	// the AskID the eventmap produces when no separate request_id was on the wire).
	ResolveAsk func(askID string) (toolUseID, requestID string)
}

// Compile-time proof the adapter satisfies the OSS client/tui Writer seam.
var _ tui.Writer = (*Writer)(nil)

// SendInput forwards a line of operator input to the agent's stdin through the
// writer seat (tui.Writer). An empty line is refused locally (the driver's
// EncodeInput requires a non-empty text block; refusing here gives the operator
// a clean message rather than a wrapped encoder error).
func (w *Writer) SendInput(line string) error {
	if w.Seat == nil {
		return errors.New("serpent-tui/driver: no writer seat (reader-only or unwired)")
	}
	if line == "" {
		return errors.New("serpent-tui/driver: empty input line")
	}
	return w.Seat.DriveInput(hostbridge.DriveInput{Text: line})
}

// AnswerAsk forwards an approval decision for an open ask back through the writer
// seat as a DriveGrant (tui.Writer). It maps the tui Decision onto the driver's
// boolean allow (allow-once and allow-always both forward allow — the
// allow-always PROPOSAL is a posture decision made org-side, not a different wire
// answer for THIS ask; deny forwards allow=false). It stores NO grant (D45): the
// answer is forwarded once, the standing rule (if any) lives org-side.
func (w *Writer) AnswerAsk(askID string, d tui.Decision) error {
	if w.Seat == nil {
		return errors.New("serpent-tui/driver: no writer seat (reader-only or unwired)")
	}
	toolUseID, requestID := w.resolve(askID)
	grant := hostbridge.DriveGrant{
		RequestID: requestID,
		ToolUseID: toolUseID,
		Allow:     decisionAllows(d),
	}
	if err := w.Seat.DriveGrant(grant, w.Route); err != nil {
		return fmt.Errorf("serpent-tui/driver: answer ask %q: %w", askID, err)
	}
	return nil
}

// resolve maps a tui ask id to the driver's join keys. With no resolver the ask
// id is the tool_use_id (the prompt-tool default route the bridge uses).
func (w *Writer) resolve(askID string) (toolUseID, requestID string) {
	if w.ResolveAsk != nil {
		return w.ResolveAsk(askID)
	}
	return askID, ""
}

// decisionAllows maps a tui Decision onto the driver's boolean grant. Allow-once
// and the allow-always PROPOSAL both ALLOW this operation (the proposal's
// standing effect is an org-side acceptance, never a different answer for this
// ask, D45); Deny refuses. An empty/unknown decision is treated as a refusal
// fail-closed (the loop never forwards an unparsed decision, but the driver
// defends in depth — an ambiguous answer is never an allow).
func decisionAllows(d tui.Decision) bool {
	switch d {
	case tui.DecisionAllowOnce, tui.DecisionAllowAlways:
		return true
	default:
		return false
	}
}

// SeatFromSocket adapts a live client/hostbridge.SocketConn (a WRITER attach over
// the direct client->host-agent endpoint) into the WriterSeat seam. The SocketConn
// already refuses a READER's drive before the wire (D61); this is a thin pass-
// through so the loop drives the real host-agent in production exactly as it
// drives the in-process fake in tests. It is the production wiring; the live dial
// (DialWriterSeat) is the N7-gated step.
func SeatFromSocket(conn *hostbridge.SocketConn) WriterSeat { return socketSeat{conn} }

type socketSeat struct{ conn *hostbridge.SocketConn }

func (s socketSeat) DriveInput(in hostbridge.DriveInput) error { return s.conn.DriveInput(in) }
func (s socketSeat) DriveGrant(grant hostbridge.DriveGrant, route hostbridge.GrantRoute) error {
	return s.conn.DriveGrant(grant, route)
}
