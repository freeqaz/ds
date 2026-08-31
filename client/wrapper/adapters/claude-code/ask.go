// ask.go — owned by impl-ask: the control-protocol ask projection (P8),
// ask.requested/ask.resolved, denial fallbacks. The wrapper emits asks; it
// never stores grants or answers them (D18/D45/D53) — the only state held here
// is the in-flight correlation needed to pair a request with its resolution.
package claudecode

import (
	"sort"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// ask is one in-flight ask, keyed by tool-use id in Adapter.asks. The tool-use
// id is the single correlation key end-to-end (P8): it threads
// control_request → tool_use.id → tool_result.tool_use_id →
// result.permission_denials[].tool_use_id. askID is the control request_id
// when the ask arrived on the native channel (else the tool-use id), and is
// the key a success control_response correlates back on (the response carries
// request_id, not tool_use_id). These fields are the minimum needed to emit a
// faithful AskResolved later; no grant or approval decision is stored (D45/D53).
type ask struct {
	askID    string // control request_id when present, else nodeID
	nodeID   string // = tool_use_id, the correlation key
	toolName string
	agentID  string
	source   string // "control" | "rearm" (the channel the request arrived on)

	// answeredBehavior is the behavior a success control_response answered on
	// the wire ("allow" | "deny"), recorded on the open ask BEFORE the
	// tool_result arrives. It is the discriminator that lets
	// resolveFromToolResult tell granted-then-failed apart from a blocked deny:
	// an is_error tool_result for an answered-ALLOW ask is the granted tool
	// erroring AT RUNTIME (project allow + tool.completed{is_error}, not deny),
	// whereas an is_error tool_result with NO prior allow-grant is a true deny.
	// Empty ⇒ no control_response resolved this ask (the fallback/re-arm path),
	// in which case is_error is taken at face value as deny (the historical rule).
	answeredBehavior string
}

// handleControlRequest projects a native control_request{subtype:
// "can_use_tool"} into AskRequested (source "control", with the
// permission_suggestions[] and agent_id riders that exist only on this
// channel, P8) and opens the ask in Adapter.asks. Non-can_use_tool control
// requests carry no ask and are skipped. The ask id is the control request_id
// when present (else the tool-use id); the node id is always the tool-use id —
// the correlation key (P8).
func (a *Adapter) handleControlRequest(rec *controlRequestRecord) ([]attach.Event, error) {
	if rec.Request.Subtype != "can_use_tool" {
		// Only can_use_tool carries an ask; other control requests
		// (interrupt, cancel, …) are not approval events. Skip, do not invent.
		return nil, nil
	}
	node := rec.Request.ToolUseID
	askID := rec.RequestID
	if askID == "" {
		askID = node
	}
	a.asks[node] = &ask{
		askID:    askID,
		nodeID:   node,
		toolName: rec.Request.ToolName,
		agentID:  rec.Request.AgentID,
		source:   "control",
	}
	ev := a.emit(attach.Event{
		Type: attach.TypeAskRequested,
		AskRequested: &attach.AskRequested{
			AskID:       askID,
			NodeID:      node,
			ToolName:    rec.Request.ToolName,
			Input:       rec.Request.Input,
			Suggestions: rec.Request.PermissionSuggestions,
			AgentID:     rec.Request.AgentID,
			Source:      "control",
		},
	}, rec.UUID)
	return []attach.Event{ev}, nil
}

// handleControlResponse projects control_response records. An initialize
// response carrying pending_permission_requests[] re-arms each in-flight/parked
// ask: one AskRequested per entry (pending, source "rearm"), so a re-attaching
// client recovers the open asks (P8 — the socket-hold is the open
// control_request itself, carried as ask-event payload, doc 15 §6.1 row 5). A
// success response carrying a behavior resolves the correlated open ask at full
// fidelity (behavior × message); correlation is on request_id, which matches an
// open ask's askID (the response carries no tool_use_id).
func (a *Adapter) handleControlResponse(rec *controlResponseRecord) ([]attach.Event, error) {
	// Re-arm path: the initialize handshake's pending list. Each entry opens
	// (or re-opens) an ask keyed by tool-use id and emits AskRequested pending.
	if len(rec.Response.PendingPermissionRequests) > 0 {
		events := make([]attach.Event, 0, len(rec.Response.PendingPermissionRequests))
		for i := range rec.Response.PendingPermissionRequests {
			p := &rec.Response.PendingPermissionRequests[i]
			node := p.ToolUseID
			askID := p.RequestID
			if askID == "" {
				askID = node
			}
			a.asks[node] = &ask{
				askID:    askID,
				nodeID:   node,
				toolName: p.ToolName,
				agentID:  p.AgentID,
				source:   "rearm",
			}
			ev := a.emit(attach.Event{
				Type: attach.TypeAskRequested,
				AskRequested: &attach.AskRequested{
					AskID:       askID,
					NodeID:      node,
					ToolName:    p.ToolName,
					Input:       p.Input,
					Suggestions: p.PermissionSuggestions,
					AgentID:     p.AgentID,
					Source:      "rearm",
					Pending:     true,
				},
			}, rec.UUID)
			events = append(events, ev)
		}
		return events, nil
	}

	// Resolution path: a success response answers an open ask. Behavior is
	// "allow" | "deny"; correlate by request_id (== an open ask's askID).
	body := &rec.Response
	if body.Response.Behavior == "" {
		// No behavior and no pending list: not an ask resolution. Skip.
		return nil, nil
	}
	open := a.askByRequestID(body.RequestID)
	if open == nil {
		// A resolution with no matching open ask: never invent an ask that was
		// not on the wire (P8). Record a warning and drop.
		a.warnf("control_response %s resolves unknown request_id %q (uuid %s): no open ask", body.Subtype, body.RequestID, rec.UUID)
		return nil, nil
	}
	// Record the answered behavior on the open ask BEFORE deciding how it
	// closes: the wire reveals allow/deny here, ahead of the tool_result. On
	// an ALLOW answer the ask stays OPEN so the later tool_result can carry the
	// runtime outcome — a granted tool that then errors at runtime
	// (is_error:true) is granted-then-failed, NOT a deny (resolveFromToolResult
	// reads answeredBehavior to make that call). On a DENY answer the tool is
	// blocked and never runs, so the ask is fully resolved here and now (the
	// historical true-deny path; the matching is_error:true tool_result is the
	// denial body, owned by classify as tool.completed{denial_message}).
	open.answeredBehavior = body.Response.Behavior
	if body.Response.Behavior == "allow" {
		// Keep the ask open: closure (and the discriminated final behavior)
		// happens at the tool_result. Emit the answered-allow resolution now —
		// the grant decision is on the wire — so a client sees the answer
		// without waiting for the tool to run.
		ev := a.emit(attach.Event{
			Type: attach.TypeAskResolved,
			AskResolved: &attach.AskResolved{
				AskID:    open.askID,
				NodeID:   open.nodeID,
				Behavior: "allow",
				Message:  body.Response.Message,
			},
		}, rec.UUID)
		return []attach.Event{ev}, nil
	}
	delete(a.asks, open.nodeID)
	ev := a.emit(attach.Event{
		Type: attach.TypeAskResolved,
		AskResolved: &attach.AskResolved{
			AskID:    open.askID,
			NodeID:   open.nodeID,
			Behavior: body.Response.Behavior,
			Message:  body.Response.Message,
		},
	}, rec.UUID)
	return []attach.Event{ev}, nil
}

// resolveFromToolResult is the ask-resolution hook classify calls on every
// non-subagent tool_result. The behavior it projects turns on whether a
// control_response already answered the open ask:
//
//   - answeredBehavior == "allow": the ask was GRANTED on the control wire and
//     handleControlResponse already emitted AskResolved{allow}; this tool_result
//     is the granted tool's runtime outcome. is_error:true here is
//     granted-then-failed (the tool RAN and errored) — NOT a deny: the grant
//     stands, so no new AskResolved is projected (the answered-allow resolution
//     already fired) and classify's tool.completed{is_error:true} carries the
//     runtime error. A non-error result is a clean success; likewise no new
//     event. Either way the now-closed ask is dropped.
//   - answeredBehavior == "deny": already closed+resolved at the control_response
//     (the ask was deleted there), so this branch is never reached for it.
//   - answeredBehavior == "" (no control_response answered — the re-arm /
//     prompt-tool fallback): is_error:true is taken at face value as a deny
//     (message = the verbatim bare-string body, P8/P13), else allow. This is
//     the historical rule, unchanged, and is the ONLY path that projects deny
//     from a tool_result.
//
// No open ask ⇒ no event — never invent an ask that was never on the wire
// (headless auto-deny has NO ask; that path is ToolCompleted{denial_message}
// via classify). source is the resolving record's uuid, for Source stamping.
func (a *Adapter) resolveFromToolResult(id string, isErr bool, msg string, source string) ([]attach.Event, error) {
	open, ok := a.asks[id]
	if !ok {
		return nil, nil
	}
	delete(a.asks, id)

	// Granted-then-failed / granted-then-succeeded: a control_response already
	// answered ALLOW and emitted the resolution. The tool's runtime outcome
	// (success or is_error) does NOT re-open the grant question — the answer
	// stands. Close the ask without a second AskResolved; an is_error tool_result
	// surfaces only as classify's tool.completed{is_error:true}, distinguishing
	// granted-then-failed (allow + is_error completed, no deny) from a blocked
	// deny (behavior=deny + denial_message).
	if open.answeredBehavior == "allow" {
		return nil, nil
	}

	// Unanswered ask (no control_response on the stream): the tool_result is the
	// resolution. is_error ⇒ deny (verbatim message), else allow.
	behavior := "allow"
	resolvedMsg := ""
	if isErr {
		behavior = "deny"
		resolvedMsg = msg // verbatim bare-string body (P8/P13)
	}
	ev := a.emit(attach.Event{
		Type: attach.TypeAskResolved,
		AskResolved: &attach.AskResolved{
			AskID:    open.askID,
			NodeID:   open.nodeID,
			Behavior: behavior,
			Message:  resolvedMsg,
		},
	}, source)
	return []attach.Event{ev}, nil
}

// handleDenials consumes result.permission_denials[] at terminal (handed over
// by state.go): emit AskResolved deny for any denial whose ask is still open,
// then resolve every remaining open ask as behavior "cancelled". Denials are
// emitted before cancellations, in wire order; a denial whose ask already
// resolved (the common answered-deny path resolved it from the tool_result) is
// not re-emitted. source is the result record's uuid, for Source stamping.
func (a *Adapter) handleDenials(denials []permissionDenial, source string) ([]attach.Event, error) {
	var events []attach.Event
	for i := range denials {
		d := &denials[i]
		open, ok := a.asks[d.ToolUseID]
		if !ok {
			// Either no ask was ever on the wire for this denial (headless
			// auto-deny, P8 — classify owns that as ToolCompleted{denial_message})
			// or it already resolved from its tool_result. Either way, do not
			// synthesize an ask here.
			continue
		}
		delete(a.asks, d.ToolUseID)
		ev := a.emit(attach.Event{
			Type: attach.TypeAskResolved,
			AskResolved: &attach.AskResolved{
				AskID:    open.askID,
				NodeID:   open.nodeID,
				Behavior: "deny",
			},
		}, source)
		events = append(events, ev)
	}
	// Any ask still open at terminal was never answered on the wire: cancel it
	// (timeout/parked asks resolve as behavior "cancelled", P8). Emit in
	// tool-use-id order for determinism.
	for _, node := range a.sortedAskNodes() {
		open := a.asks[node]
		delete(a.asks, node)
		ev := a.emit(attach.Event{
			Type: attach.TypeAskResolved,
			AskResolved: &attach.AskResolved{
				AskID:    open.askID,
				NodeID:   open.nodeID,
				Behavior: "cancelled",
			},
		}, source)
		events = append(events, ev)
	}
	return events, nil
}

// askGrantedAllow reports whether an open ask for this tool-use id was answered
// ALLOW on the control wire (handleControlResponse recorded answeredBehavior and
// kept the ask open). classify consults this BEFORE resolveFromToolResult closes
// the ask, to decide whether an is_error tool_result is a permission DENIAL (no
// grant ⇒ denial_message set) or a granted tool's RUNTIME error (granted-then-
// failed ⇒ is_error completion WITHOUT a denial_message — the tool was permitted,
// it simply failed). Read-only: it never mutates the ask state.
func (a *Adapter) askGrantedAllow(id string) bool {
	open, ok := a.asks[id]
	return ok && open.answeredBehavior == "allow"
}

// askByRequestID finds the single open ask whose askID equals the control
// request_id. The asks map is keyed by tool-use id, but a success
// control_response correlates on request_id only; request_id is unique per
// ask, so the scan returns a deterministic result regardless of map order.
func (a *Adapter) askByRequestID(requestID string) *ask {
	if requestID == "" {
		return nil
	}
	for _, open := range a.asks {
		if open.askID == requestID {
			return open
		}
	}
	return nil
}

// sortedAskNodes returns the tool-use-id keys of the currently-open asks in
// ascending order, so terminal cancellation emits deterministically (map
// iteration order is unspecified).
func (a *Adapter) sortedAskNodes() []string {
	nodes := make([]string, 0, len(a.asks))
	for node := range a.asks {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	return nodes
}
