// ask_test.go — owned by impl-ask. Table-driven unit tests for the
// control-protocol ask projection (P8): control_request/control_response
// dispatch via Feed, plus the resolveFromToolResult and handleDenials hooks
// called directly (their wire-side call sites — classify and state — are owned
// by peers and exercised at the golden-test level, not here). All asserts are
// structural: event types, payload fields, and ordering. A deterministic clock
// keeps the assertions independent of wall time; no fixture cassettes are read
// (those are integration-level, IMPLEMENTATION-SPEC.md "Workflow notes").
//
// Test-local identifiers are prefixed "ask" so this file's helpers never
// collide with the package-shared scope the peer *_test.go files (classify,
// state, foundation) declare into.
package claudecode

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// askClock returns a deterministic, monotonically-incrementing clock matching
// the replay harness convention (1s per call from 2026-01-01T00:00:00Z), so
// ObservedAt is stable and ordered across a test's emitted events.
func askClock() func() time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var n int64
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

func newAskAdapter() *Adapter {
	return New(WithClock(askClock()))
}

// feedAsk runs one hand-rolled NDJSON line through Feed and fails on error.
func feedAsk(t *testing.T, a *Adapter, line string) []attach.Event {
	t.Helper()
	evs, err := a.Feed([]byte(line))
	if err != nil {
		t.Fatalf("Feed(%s) error: %v", line, err)
	}
	return evs
}

// askRequireRequested asserts ev is an ask.requested event and returns its
// payload.
func askRequireRequested(t *testing.T, ev attach.Event) *attach.AskRequested {
	t.Helper()
	if ev.Type != attach.TypeAskRequested {
		t.Fatalf("type = %q, want %q", ev.Type, attach.TypeAskRequested)
	}
	if ev.AskRequested == nil {
		t.Fatal("AskRequested payload is nil")
	}
	return ev.AskRequested
}

// askRequireResolved asserts ev is an ask.resolved event and returns its
// payload.
func askRequireResolved(t *testing.T, ev attach.Event) *attach.AskResolved {
	t.Helper()
	if ev.Type != attach.TypeAskResolved {
		t.Fatalf("type = %q, want %q", ev.Type, attach.TypeAskResolved)
	}
	if ev.AskResolved == nil {
		t.Fatal("AskResolved payload is nil")
	}
	return ev.AskResolved
}

const askSession = "00000000-0000-4000-8000-000000000001"

// --- control_request → AskRequested(source "control") -----------------------

func TestControlRequest_CanUseTool_EmitsAskRequested(t *testing.T) {
	a := newAskAdapter()
	line := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_synth_ask_1","request":{"subtype":"can_use_tool","tool_name":"Bash","display_name":"Bash","input":{"command":"echo hi > /work/scratch"},"permission_suggestions":[{"type":"addRule"}],"tool_use_id":"toolu_SYNTH_ask_1","agent_id":"agentsynth0000001","decision_reason_type":"rule","classifier_approvable":true}}`

	evs := feedAsk(t, a, line)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	req := askRequireRequested(t, evs[0])

	if req.Source != "control" {
		t.Errorf("source = %q, want control", req.Source)
	}
	if req.AskID != "req_synth_ask_1" {
		t.Errorf("ask_id = %q, want req_synth_ask_1 (control request_id)", req.AskID)
	}
	if req.NodeID != "toolu_SYNTH_ask_1" {
		t.Errorf("node_id = %q, want toolu_SYNTH_ask_1 (tool_use_id, the correlation key)", req.NodeID)
	}
	if req.ToolName != "Bash" {
		t.Errorf("tool_name = %q, want Bash", req.ToolName)
	}
	if req.AgentID != "agentsynth0000001" {
		t.Errorf("agent_id = %q, want agentsynth0000001", req.AgentID)
	}
	if req.Pending {
		t.Error("pending = true, want false on a fresh control ask")
	}
	// Suggestions are the native-channel-only rider; passthrough verbatim.
	if string(req.Suggestions) != `[{"type":"addRule"}]` {
		t.Errorf("suggestions = %s, want passthrough of the native list", req.Suggestions)
	}
	// Input is a verbatim passthrough.
	if string(req.Input) != `{"command":"echo hi > /work/scratch"}` {
		t.Errorf("input = %s, want verbatim passthrough", req.Input)
	}
	// Source stamping: the projecting record's uuid.
	if len(evs[0].Source) != 1 || evs[0].Source[0] != "00000000-0000-4000-8000-0000000000c1" {
		t.Errorf("source uuids = %v, want the control_request uuid", evs[0].Source)
	}
	// Envelope: seq from 1, session id carried.
	if evs[0].Seq != 1 {
		t.Errorf("seq = %d, want 1", evs[0].Seq)
	}
	if evs[0].SessionID != askSession {
		t.Errorf("session_id = %q, want %q", evs[0].SessionID, askSession)
	}
	// The ask is now open in the adapter, keyed by tool_use_id.
	if _, ok := a.asks["toolu_SYNTH_ask_1"]; !ok {
		t.Error("ask not opened in a.asks under the tool_use_id key")
	}
}

func TestControlRequest_NonCanUseTool_NoAsk(t *testing.T) {
	a := newAskAdapter()
	line := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c2","request_id":"req_synth_int_1","request":{"subtype":"interrupt"}}`

	evs := feedAsk(t, a, line)
	if len(evs) != 0 {
		t.Fatalf("got %d events, want 0 (non-can_use_tool carries no ask)", len(evs))
	}
	if len(a.asks) != 0 {
		t.Errorf("opened %d asks, want 0", len(a.asks))
	}
}

func TestControlRequest_MissingRequestID_FallsBackToToolUseID(t *testing.T) {
	a := newAskAdapter()
	// Prompt-tool-style ask with no request_id: ask_id falls back to tool_use_id.
	line := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c3","request":{"subtype":"can_use_tool","tool_name":"Write","input":{"path":"/work/x"},"tool_use_id":"toolu_SYNTH_ask_2"}}`

	evs := feedAsk(t, a, line)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	req := askRequireRequested(t, evs[0])
	if req.AskID != "toolu_SYNTH_ask_2" {
		t.Errorf("ask_id = %q, want fallback to tool_use_id toolu_SYNTH_ask_2", req.AskID)
	}
	if req.NodeID != "toolu_SYNTH_ask_2" {
		t.Errorf("node_id = %q, want toolu_SYNTH_ask_2", req.NodeID)
	}
	if open := a.asks["toolu_SYNTH_ask_2"]; open == nil || open.askID != "toolu_SYNTH_ask_2" {
		t.Errorf("open ask askID = %v, want fallback tool_use_id", open)
	}
}

// --- control_response success → AskResolved (full fidelity) ------------------

func TestControlResponse_SuccessAllow_ResolvesOpenAsk(t *testing.T) {
	a := newAskAdapter()
	reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_synth_ask_1","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"ls"},"tool_use_id":"toolu_SYNTH_ask_1"}}`
	feedAsk(t, a, reqLine)

	respLine := `{"type":"control_response","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c4","response":{"subtype":"success","request_id":"req_synth_ask_1","response":{"behavior":"allow","updatedInput":{"command":"ls"}}}}`
	evs := feedAsk(t, a, respLine)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	res := askRequireResolved(t, evs[0])
	if res.Behavior != "allow" {
		t.Errorf("behavior = %q, want allow", res.Behavior)
	}
	if res.AskID != "req_synth_ask_1" {
		t.Errorf("ask_id = %q, want req_synth_ask_1", res.AskID)
	}
	if res.NodeID != "toolu_SYNTH_ask_1" {
		t.Errorf("node_id = %q, want toolu_SYNTH_ask_1 (correlation key)", res.NodeID)
	}
	// An ALLOW answer emits the resolution NOW (the grant is on the wire) but
	// keeps the ask OPEN, recording answeredBehavior so the later tool_result
	// can carry the granted tool's runtime outcome (granted-then-failed vs
	// granted-then-succeeded). Closure happens at the tool_result, not here.
	open := a.asks["toolu_SYNTH_ask_1"]
	if open == nil {
		t.Fatal("ask closed after success allow; want kept open until the tool_result")
	}
	if open.answeredBehavior != "allow" {
		t.Errorf("answeredBehavior = %q, want allow (recorded on the open ask)", open.answeredBehavior)
	}
	// seq continues monotonically across request+response.
	if evs[0].Seq != 2 {
		t.Errorf("seq = %d, want 2 (after the request's seq 1)", evs[0].Seq)
	}
}

func TestControlResponse_SuccessDeny_CarriesMessageVerbatim(t *testing.T) {
	a := newAskAdapter()
	reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_synth_ask_2","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"rm -rf /"},"tool_use_id":"toolu_SYNTH_deny"}}`
	feedAsk(t, a, reqLine)

	const denyMsg = "the user denied this operation: destructive command"
	respLine := `{"type":"control_response","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c5","response":{"subtype":"success","request_id":"req_synth_ask_2","response":{"behavior":"deny","message":"` + denyMsg + `"}}}`
	evs := feedAsk(t, a, respLine)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	res := askRequireResolved(t, evs[0])
	if res.Behavior != "deny" {
		t.Errorf("behavior = %q, want deny", res.Behavior)
	}
	if res.Message != denyMsg {
		t.Errorf("message = %q, want verbatim deny message", res.Message)
	}
}

func TestControlResponse_UnknownRequestID_WarnsNoEvent(t *testing.T) {
	a := newAskAdapter()
	// No open ask: a resolution that matches nothing must not invent one (P8).
	respLine := `{"type":"control_response","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c6","response":{"subtype":"success","request_id":"req_synth_ghost","response":{"behavior":"allow"}}}`
	evs := feedAsk(t, a, respLine)
	if len(evs) != 0 {
		t.Fatalf("got %d events, want 0 (resolution with no open ask)", len(evs))
	}
	if len(a.Warnings()) == 0 {
		t.Error("expected a warning for an unknown request_id resolution")
	}
}

func TestControlResponse_NoBehaviorNoPending_Skipped(t *testing.T) {
	a := newAskAdapter()
	// A bare success response with neither a pending list nor a behavior is not
	// an ask event (e.g. an initialize ack with no parked asks).
	respLine := `{"type":"control_response","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c7","response":{"subtype":"success","request_id":"req_init"}}`
	evs := feedAsk(t, a, respLine)
	if len(evs) != 0 {
		t.Fatalf("got %d events, want 0", len(evs))
	}
	if len(a.Warnings()) != 0 {
		t.Errorf("unexpected warnings: %v", a.Warnings())
	}
}

// --- control_response initialize re-arm → AskRequested(pending, "rearm") -----

func TestControlResponse_Initialize_RearmsPendingAsks(t *testing.T) {
	a := newAskAdapter()
	respLine := `{"type":"control_response","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c8","response":{"subtype":"success","request_id":"req_init","pending_permission_requests":[{"request_id":"req_pending_1","tool_name":"Bash","input":{"command":"make"},"tool_use_id":"toolu_PENDING_1","agent_id":"agentpend0000001","permission_suggestions":[{"type":"addRule"}]},{"request_id":"req_pending_2","tool_name":"Write","input":{"path":"/work/out"},"tool_use_id":"toolu_PENDING_2"}]}}`

	evs := feedAsk(t, a, respLine)
	if len(evs) != 2 {
		t.Fatalf("got %d events, want 2 (one AskRequested per pending entry)", len(evs))
	}

	first := askRequireRequested(t, evs[0])
	if first.Source != "rearm" {
		t.Errorf("entry 0 source = %q, want rearm", first.Source)
	}
	if !first.Pending {
		t.Error("entry 0 pending = false, want true")
	}
	if first.AskID != "req_pending_1" || first.NodeID != "toolu_PENDING_1" {
		t.Errorf("entry 0 ask_id/node_id = %q/%q, want req_pending_1/toolu_PENDING_1", first.AskID, first.NodeID)
	}
	if first.ToolName != "Bash" {
		t.Errorf("entry 0 tool_name = %q, want Bash", first.ToolName)
	}
	if first.AgentID != "agentpend0000001" {
		t.Errorf("entry 0 agent_id = %q, want agentpend0000001", first.AgentID)
	}
	if string(first.Suggestions) != `[{"type":"addRule"}]` {
		t.Errorf("entry 0 suggestions = %s, want passthrough", first.Suggestions)
	}

	second := askRequireRequested(t, evs[1])
	if second.Source != "rearm" || !second.Pending {
		t.Errorf("entry 1 source/pending = %q/%v, want rearm/true", second.Source, second.Pending)
	}
	if second.AskID != "req_pending_2" || second.NodeID != "toolu_PENDING_2" {
		t.Errorf("entry 1 ask_id/node_id = %q/%q, want req_pending_2/toolu_PENDING_2", second.AskID, second.NodeID)
	}

	// Order is the wire order of the pending list.
	if evs[0].Seq >= evs[1].Seq {
		t.Errorf("seqs not increasing in list order: %d, %d", evs[0].Seq, evs[1].Seq)
	}
	// Both asks are now open and resolvable.
	if len(a.asks) != 2 {
		t.Errorf("open asks = %d, want 2", len(a.asks))
	}

	// A re-armed ask resolves like any other (here via tool_result fallback).
	res, err := a.resolveFromToolResult("toolu_PENDING_1", false, "", "00000000-0000-4000-8000-0000000000d1")
	if err != nil {
		t.Fatalf("resolveFromToolResult error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("got %d resolutions, want 1", len(res))
	}
	got := askRequireResolved(t, res[0])
	if got.AskID != "req_pending_1" || got.Behavior != "allow" {
		t.Errorf("rearmed resolve ask_id/behavior = %q/%q, want req_pending_1/allow", got.AskID, got.Behavior)
	}
}

// --- resolveFromToolResult fallback -----------------------------------------

func TestResolveFromToolResult_OpenAsk(t *testing.T) {
	tests := []struct {
		name         string
		isErr        bool
		msg          string
		wantBehavior string
		wantMsg      string
	}{
		{name: "is_error true → deny with verbatim message", isErr: true, msg: "the following parts require approval", wantBehavior: "deny", wantMsg: "the following parts require approval"},
		{name: "is_error false → allow, no message", isErr: false, msg: "", wantBehavior: "allow", wantMsg: ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newAskAdapter()
			// Open an ask via the control channel first.
			reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_fb","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"ls"},"tool_use_id":"toolu_FB"}}`
			feedAsk(t, a, reqLine)

			evs, err := a.resolveFromToolResult("toolu_FB", tc.isErr, tc.msg, "00000000-0000-4000-8000-0000000000d2")
			if err != nil {
				t.Fatalf("resolveFromToolResult error: %v", err)
			}
			if len(evs) != 1 {
				t.Fatalf("got %d events, want 1", len(evs))
			}
			res := askRequireResolved(t, evs[0])
			if res.Behavior != tc.wantBehavior {
				t.Errorf("behavior = %q, want %q", res.Behavior, tc.wantBehavior)
			}
			if res.Message != tc.wantMsg {
				t.Errorf("message = %q, want %q", res.Message, tc.wantMsg)
			}
			if res.AskID != "req_fb" || res.NodeID != "toolu_FB" {
				t.Errorf("ask_id/node_id = %q/%q, want req_fb/toolu_FB", res.AskID, res.NodeID)
			}
			// Source stamping is the resolving record's uuid.
			if len(evs[0].Source) != 1 || evs[0].Source[0] != "00000000-0000-4000-8000-0000000000d2" {
				t.Errorf("source = %v, want the resolving record uuid", evs[0].Source)
			}
			// Ask is closed.
			if _, ok := a.asks["toolu_FB"]; ok {
				t.Error("ask still open after fallback resolve")
			}
		})
	}
}

// --- granted-then-failed vs blocked deny (the gap-3 distinction) -------------

// TestGrantedThenFailed_AllowGrantThenRuntimeError proves the full wire path of
// an ASKED tool that is GRANTED (control_response behavior:allow) and then RUNS
// and ERRORS at runtime (is_error:true tool_result): it must project
// ask.resolved{allow} (the grant stands) + the granted tool's failure carried
// as tool.completed{is_error:true} by classify — NOT a second resolution and
// NOT a deny. is_error here is the granted tool erroring, not a permission
// block.
func TestGrantedThenFailed_AllowGrantThenRuntimeError(t *testing.T) {
	a := newAskAdapter()

	// 1) control_request{can_use_tool} opens the ask.
	reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_gtf","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"false"},"tool_use_id":"toolu_GTF"}}`
	reqEvs := feedAsk(t, a, reqLine)
	if len(reqEvs) != 1 {
		t.Fatalf("control_request: got %d events, want 1", len(reqEvs))
	}
	askRequireRequested(t, reqEvs[0])

	// 2) control_response answers ALLOW: emits ask.resolved{allow}, but keeps
	// the ask open with answeredBehavior recorded.
	respLine := `{"type":"control_response","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000ca","response":{"subtype":"success","request_id":"req_gtf","response":{"behavior":"allow","updatedInput":{"command":"false"}}}}`
	respEvs := feedAsk(t, a, respLine)
	if len(respEvs) != 1 {
		t.Fatalf("control_response allow: got %d events, want 1", len(respEvs))
	}
	gotAllow := askRequireResolved(t, respEvs[0])
	if gotAllow.Behavior != "allow" {
		t.Errorf("control_response resolution behavior = %q, want allow", gotAllow.Behavior)
	}
	if open := a.asks["toolu_GTF"]; open == nil || open.answeredBehavior != "allow" {
		t.Fatalf("after allow grant: ask must stay open with answeredBehavior=allow, got %+v", open)
	}

	// 3) The granted tool RUNS and ERRORS: an is_error:true tool_result. Fed as
	// a real user record so classify's handleToolResult runs end-to-end. It must
	// project tool.completed{is_error:true} for the granted tool's runtime
	// failure, and resolveFromToolResult must NOT project a deny (the grant
	// stands; the answered-allow resolution already fired). No second
	// ask.resolved is emitted.
	const runtimeErr = "command failed: exit status 1"
	resultLine := `{"type":"user","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000cb","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_GTF","is_error":true,"content":"` + runtimeErr + `"}]}}`
	resultEvs := feedAsk(t, a, resultLine)
	if len(resultEvs) != 1 {
		t.Fatalf("granted-then-failed tool_result: got %d events, want 1 (tool.completed only; no deny)", len(resultEvs))
	}
	if resultEvs[0].Type != attach.TypeToolCompleted || resultEvs[0].ToolCompleted == nil {
		t.Fatalf("event 0 type = %q, want tool.completed", resultEvs[0].Type)
	}
	tc := resultEvs[0].ToolCompleted
	if !tc.IsError {
		t.Error("granted-then-failed tool.completed IsError = false, want true (the granted tool errored)")
	}
	// The granted tool's runtime error is NOT a permission denial: denial_message
	// must be empty (a permitted-but-failed tool is not a block, gap-3).
	if tc.DenialMessage != "" {
		t.Errorf("granted-then-failed denial_message = %q, want empty (a granted tool's runtime error is not a denial)", tc.DenialMessage)
	}
	if tc.OutputExcerpt != runtimeErr {
		t.Errorf("output_excerpt = %q, want the runtime error %q", tc.OutputExcerpt, runtimeErr)
	}
	if _, ok := a.asks["toolu_GTF"]; ok {
		t.Error("ask still open after the granted tool's tool_result; want closed")
	}

	// The full projected stream for this asked tool: exactly one ask.resolved,
	// and it is ALLOW (no deny anywhere) — distinguishing granted-then-failed
	// (allow + is_error completed, no deny) from a blocked deny.
	var all []attach.Event
	all = append(all, reqEvs...)
	all = append(all, respEvs...)
	all = append(all, resultEvs...)
	var resolutions []*attach.AskResolved
	for _, ev := range all {
		if ev.Type == attach.TypeAskResolved {
			resolutions = append(resolutions, ev.AskResolved)
		}
	}
	if len(resolutions) != 1 {
		t.Fatalf("granted-then-failed projected %d ask.resolved events, want exactly 1", len(resolutions))
	}
	if resolutions[0].Behavior != "allow" {
		t.Errorf("granted-then-failed resolution behavior = %q, want allow (NOT deny)", resolutions[0].Behavior)
	}
}

// TestBlockedDeny_DenyGrantBlocksTool proves the contrasting path: an ASKED
// tool DENIED on the control wire (control_response behavior:deny) is BLOCKED —
// it resolves deny WITH the denial message at the control_response and never
// runs. This is the path that stays distinguishable from granted-then-failed:
// behavior=deny + a DenialMessage on the matching tool.completed, vs
// behavior=allow + no deny for the granted-then-failed case above.
func TestBlockedDeny_DenyGrantBlocksTool(t *testing.T) {
	a := newAskAdapter()

	reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_bd","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"rm -rf /work"},"tool_use_id":"toolu_BD"}}`
	feedAsk(t, a, reqLine)

	const denyMsg = "Permission to use Bash with command rm -rf /work has been denied."
	respLine := `{"type":"control_response","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000cc","response":{"subtype":"success","request_id":"req_bd","response":{"behavior":"deny","message":"` + denyMsg + `"}}}`
	respEvs := feedAsk(t, a, respLine)
	if len(respEvs) != 1 {
		t.Fatalf("control_response deny: got %d events, want 1", len(respEvs))
	}
	res := askRequireResolved(t, respEvs[0])
	if res.Behavior != "deny" {
		t.Errorf("behavior = %q, want deny", res.Behavior)
	}
	if res.Message != denyMsg {
		t.Errorf("message = %q, want verbatim deny message", res.Message)
	}
	// A blocked deny fully resolves AND closes the ask at the control_response —
	// the tool never runs, so there is no granted-tool tool_result to wait for.
	if _, ok := a.asks["toolu_BD"]; ok {
		t.Error("ask still open after blocked deny; want closed (the tool was blocked, never runs)")
	}

	// Sanity: the deny is unambiguously distinguishable from granted-then-failed.
	// Granted-then-failed never emits behavior=deny (see the test above); a
	// blocked deny always does and carries the denial message.
	if res.Behavior == "allow" {
		t.Error("a blocked deny must never project allow")
	}
}

func TestResolveFromToolResult_NoOpenAsk_NoEvent(t *testing.T) {
	a := newAskAdapter()
	// The headless auto-deny path: an is_error tool_result with NO ask on the
	// wire must NOT synthesize an AskResolved (P8 — that path is
	// ToolCompleted{denial_message} via classify).
	evs, err := a.resolveFromToolResult("toolu_NEVER_ASKED", true, "require approval", "00000000-0000-4000-8000-0000000000d3")
	if err != nil {
		t.Fatalf("resolveFromToolResult error: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("got %d events, want 0 (no ask was ever on the wire)", len(evs))
	}
}

// --- handleDenials at terminal ----------------------------------------------

func TestHandleDenials_CancelsUnansweredOpenAsk(t *testing.T) {
	a := newAskAdapter()
	// One open, unanswered ask at terminal with an empty permission_denials[].
	reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_open","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"sleep 99"},"tool_use_id":"toolu_OPEN"}}`
	feedAsk(t, a, reqLine)

	evs, err := a.handleDenials(nil, "00000000-0000-4000-8000-0000000000e1")
	if err != nil {
		t.Fatalf("handleDenials error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 (cancellation of the open ask)", len(evs))
	}
	res := askRequireResolved(t, evs[0])
	if res.Behavior != "cancelled" {
		t.Errorf("behavior = %q, want cancelled", res.Behavior)
	}
	if res.NodeID != "toolu_OPEN" {
		t.Errorf("node_id = %q, want toolu_OPEN", res.NodeID)
	}
	if len(a.asks) != 0 {
		t.Errorf("open asks after terminal = %d, want 0", len(a.asks))
	}
}

func TestHandleDenials_EmitsDenyForOpenDenial(t *testing.T) {
	a := newAskAdapter()
	// An ask that is still open AND appears in permission_denials[] at terminal:
	// emit deny. (The common case answers via tool_result first; this exercises
	// the path where the denial arrives only at the result record.)
	reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_d","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"x"},"tool_use_id":"toolu_DENIED"}}`
	feedAsk(t, a, reqLine)

	denials := []permissionDenial{
		{ToolName: "Bash", ToolUseID: "toolu_DENIED", ToolInput: json.RawMessage(`{"command":"x"}`)},
	}
	evs, err := a.handleDenials(denials, "00000000-0000-4000-8000-0000000000e2")
	if err != nil {
		t.Fatalf("handleDenials error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1", len(evs))
	}
	res := askRequireResolved(t, evs[0])
	if res.Behavior != "deny" {
		t.Errorf("behavior = %q, want deny", res.Behavior)
	}
	if res.NodeID != "toolu_DENIED" {
		t.Errorf("node_id = %q, want toolu_DENIED", res.NodeID)
	}
}

func TestHandleDenials_DenialAlreadyResolved_NoReEmit(t *testing.T) {
	a := newAskAdapter()
	// The canonical answered-deny path: control_request → tool_result is_error
	// resolves the ask → result carries permission_denials[] for the SAME id.
	// The denial must NOT re-emit a resolution (the ask already closed).
	reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_ad","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"x"},"tool_use_id":"toolu_AD"}}`
	feedAsk(t, a, reqLine)
	if _, err := a.resolveFromToolResult("toolu_AD", true, "denied verbatim", "00000000-0000-4000-8000-0000000000d4"); err != nil {
		t.Fatalf("resolveFromToolResult error: %v", err)
	}

	denials := []permissionDenial{{ToolName: "Bash", ToolUseID: "toolu_AD"}}
	evs, err := a.handleDenials(denials, "00000000-0000-4000-8000-0000000000e3")
	if err != nil {
		t.Fatalf("handleDenials error: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("got %d events, want 0 (denial already resolved from tool_result)", len(evs))
	}
}

func TestHandleDenials_HeadlessAutoDeny_NoAsk(t *testing.T) {
	a := newAskAdapter()
	// Headless auto-deny: permission_denials[] with NO ask ever on the wire.
	// ask.go must emit NOTHING (classify owns this as ToolCompleted{denial_message}).
	denials := []permissionDenial{{ToolName: "Bash", ToolUseID: "toolu_AUTO"}}
	evs, err := a.handleDenials(denials, "00000000-0000-4000-8000-0000000000e4")
	if err != nil {
		t.Fatalf("handleDenials error: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("got %d events, want 0 (no ask was ever on the wire)", len(evs))
	}
}

func TestHandleDenials_MixedDenyThenCancel_Ordering(t *testing.T) {
	a := newAskAdapter()
	// Two open asks: one named in permission_denials[] (deny), two not
	// (cancelled). Denials emit before cancellations; cancellations are sorted
	// by tool_use_id for determinism.
	for _, id := range []string{"toolu_AAA_cancel", "toolu_ZZZ_deny", "toolu_MMM_cancel"} {
		reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_` + id + `","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{},"tool_use_id":"` + id + `"}}`
		feedAsk(t, a, reqLine)
	}

	denials := []permissionDenial{{ToolName: "Bash", ToolUseID: "toolu_ZZZ_deny"}}
	evs, err := a.handleDenials(denials, "00000000-0000-4000-8000-0000000000e5")
	if err != nil {
		t.Fatalf("handleDenials error: %v", err)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d events, want 3 (1 deny + 2 cancel)", len(evs))
	}
	// Event 0: the deny (emitted first, in wire order of permission_denials[]).
	d0 := askRequireResolved(t, evs[0])
	if d0.Behavior != "deny" || d0.NodeID != "toolu_ZZZ_deny" {
		t.Errorf("event 0 = %q/%q, want deny/toolu_ZZZ_deny", d0.Behavior, d0.NodeID)
	}
	// Events 1,2: cancellations, sorted ascending by tool_use_id.
	c1 := askRequireResolved(t, evs[1])
	c2 := askRequireResolved(t, evs[2])
	if c1.Behavior != "cancelled" || c1.NodeID != "toolu_AAA_cancel" {
		t.Errorf("event 1 = %q/%q, want cancelled/toolu_AAA_cancel", c1.Behavior, c1.NodeID)
	}
	if c2.Behavior != "cancelled" || c2.NodeID != "toolu_MMM_cancel" {
		t.Errorf("event 2 = %q/%q, want cancelled/toolu_MMM_cancel", c2.Behavior, c2.NodeID)
	}
	// Seq is strictly increasing across all emitted resolutions.
	if !(evs[0].Seq < evs[1].Seq && evs[1].Seq < evs[2].Seq) {
		t.Errorf("seqs not strictly increasing: %d, %d, %d", evs[0].Seq, evs[1].Seq, evs[2].Seq)
	}
	if len(a.asks) != 0 {
		t.Errorf("open asks after terminal = %d, want 0", len(a.asks))
	}
}

// --- full answered-allow path through Feed ----------------------------------

func TestAskControl_RequestThenResponse_OrderingAndSeq(t *testing.T) {
	a := newAskAdapter()
	reqLine := `{"type":"control_request","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c1","request_id":"req_seq","request":{"subtype":"can_use_tool","tool_name":"Bash","input":{"command":"date"},"tool_use_id":"toolu_SEQ"}}`
	respLine := `{"type":"control_response","session_id":"` + askSession + `","uuid":"00000000-0000-4000-8000-0000000000c9","response":{"subtype":"success","request_id":"req_seq","response":{"behavior":"allow","updatedInput":{"command":"date"}}}}`

	var all []attach.Event
	all = append(all, feedAsk(t, a, reqLine)...)
	all = append(all, feedAsk(t, a, respLine)...)
	if len(all) != 2 {
		t.Fatalf("got %d events, want 2 (requested then resolved)", len(all))
	}
	askRequireRequested(t, all[0])
	askRequireResolved(t, all[1])
	if all[0].Seq != 1 || all[1].Seq != 2 {
		t.Errorf("seqs = %d,%d, want 1,2", all[0].Seq, all[1].Seq)
	}
	// ObservedAt is deterministic and ordered (replay-clock convention).
	if !all[0].ObservedAt.Before(all[1].ObservedAt) {
		t.Errorf("observed_at not ordered: %v, %v", all[0].ObservedAt, all[1].ObservedAt)
	}
}
