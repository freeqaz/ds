package eventmap

import (
	"testing"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/client/tui"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// TestEnvelopeFields proves the SessionEvent envelope (seq, session_id,
// observed_at, source, type) maps onto attach.Event field-for-field, and the
// proto unix-millis clock reconstructs deterministically (not Now()).
func TestEnvelopeFields(t *testing.T) {
	ev := &attachv1.SessionEvent{
		Seq:        7,
		SessionId:  "sess-1",
		ObservedAt: 1_700_000_000_000, // unix millis
		Type:       attachv1.EventType_EVENT_TYPE_SESSION_STATE,
		Source:     []string{"rec-a", "rec-b"},
		Payload:    &attachv1.SessionEvent_SessionState{SessionState: &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_WORKING}},
	}
	got := FromProto(ev)
	if got.Seq != 7 || got.SessionID != "sess-1" {
		t.Fatalf("envelope seq/session = %d/%q, want 7/sess-1", got.Seq, got.SessionID)
	}
	if got.Type != attach.TypeSessionState {
		t.Fatalf("type = %q, want %q", got.Type, attach.TypeSessionState)
	}
	if len(got.Source) != 2 || got.Source[0] != "rec-a" {
		t.Fatalf("source = %v, want [rec-a rec-b]", got.Source)
	}
	if got.ObservedAt.UnixMilli() != 1_700_000_000_000 {
		t.Fatalf("observed_at = %d ms, want 1700000000000 (deterministic, not Now)", got.ObservedAt.UnixMilli())
	}
	// Determinism: the same proto event maps identically every time.
	if again := FromProto(ev); again.ObservedAt != got.ObservedAt {
		t.Fatalf("observed_at not deterministic: %v vs %v", again.ObservedAt, got.ObservedAt)
	}
}

// TestStateVocabulary proves the full §3 state vocabulary maps (incl. PARKED and
// the D77-narrowed SUSPENDED reason — the read-only projection a client/tui-only
// adapter could not synthesize from the runtime stream, P9).
func TestStateVocabulary(t *testing.T) {
	cases := []struct {
		name      attachv1.SessionStateName
		reason    attachv1.SuspendReason
		freeText  string
		wantState string
		wantReas  string
	}{
		{attachv1.SessionStateName_SESSION_STATE_NAME_PARKED, 0, "task_open", "PARKED", "task_open"},
		{attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED, attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH, "", "SUSPENDED", "policy_breach"},
		{attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED, attachv1.SuspendReason_SUSPEND_REASON_USER, "manual", "SUSPENDED", "user: manual"},
		{attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED, 0, "", "DESTROYED", ""},
	}
	for _, c := range cases {
		ev := &attachv1.SessionEvent{
			Seq:     1,
			Type:    attachv1.EventType_EVENT_TYPE_SESSION_STATE,
			Payload: &attachv1.SessionEvent_SessionState{SessionState: &attachv1.SessionState{Name: c.name, Reason: c.freeText, SuspendReason: c.reason}},
		}
		got := FromProto(ev)
		if got.SessionState == nil {
			t.Fatalf("%v: nil SessionState payload", c.name)
		}
		if got.SessionState.State != c.wantState {
			t.Errorf("%v: state = %q, want %q", c.name, got.SessionState.State, c.wantState)
		}
		if got.SessionState.Reason != c.wantReas {
			t.Errorf("%v: reason = %q, want %q", c.name, got.SessionState.Reason, c.wantReas)
		}
	}
}

// TestAskCorrelationKeys proves the DISTINCT proto request_id / tool_use_id fold
// into the working model's single AskID (request_id preferred, tool_use_id
// fallback) and that `held` makes the open ask visibly pending.
func TestAskCorrelationKeys(t *testing.T) {
	// request_id present: AskID is request_id.
	withReq := FromProto(&attachv1.SessionEvent{
		Seq:     1,
		Type:    attachv1.EventType_EVENT_TYPE_ASK_REQUESTED,
		Payload: &attachv1.SessionEvent_AskRequested{AskRequested: &attachv1.AskRequested{ToolUseId: "tu-1", RequestId: "req-1", ToolName: "Bash", Held: true}},
	})
	if withReq.AskRequested == nil || withReq.AskRequested.AskID != "req-1" {
		t.Fatalf("ask with request_id: AskID = %+v, want req-1", withReq.AskRequested)
	}
	if !withReq.AskRequested.Pending {
		t.Errorf("held ask should fold to Pending=true (socket-hold visibility)")
	}
	if withReq.AskRequested.NodeID != "tu-1" {
		t.Errorf("ask node id = %q, want tu-1 (tool_use_id fallback)", withReq.AskRequested.NodeID)
	}

	// request_id absent: AskID falls back to tool_use_id.
	noReq := FromProto(&attachv1.SessionEvent{
		Seq:     2,
		Type:    attachv1.EventType_EVENT_TYPE_ASK_REQUESTED,
		Payload: &attachv1.SessionEvent_AskRequested{AskRequested: &attachv1.AskRequested{ToolUseId: "tu-2", ToolName: "Edit"}},
	})
	if noReq.AskRequested.AskID != "tu-2" {
		t.Fatalf("ask without request_id: AskID = %q, want tu-2", noReq.AskRequested.AskID)
	}
}

// TestInputActivityForwardCompat proves the §6.1 row-7 INPUT_ACTIVITY class (no
// client/wrapper/attach payload) carries its discriminator to the Model's
// forward-compat branch and renders one honest line — never a crash, never a
// fabricated shape.
func TestInputActivityForwardCompat(t *testing.T) {
	got := FromProto(&attachv1.SessionEvent{Seq: 1, Type: attachv1.EventType_EVENT_TYPE_INPUT_ACTIVITY})
	if got.Type != TypeInputActivity {
		t.Errorf("INPUT_ACTIVITY mapped to %q, want %q", got.Type, TypeInputActivity)
	}
	// Folds without panic and produces a visible line (forward-compat default).
	m := tui.NewModel()
	if err := m.Apply(got); err != nil {
		t.Fatalf("forward-compat fold of INPUT_ACTIVITY errored: %v", err)
	}
	if len(m.Lines) != 1 {
		t.Fatalf("forward-compat fold of INPUT_ACTIVITY produced %d lines, want 1", len(m.Lines))
	}
}

// TestPlanDeltaRoundTrip proves the §6.1 row-6 PLAN_DELTA class is now FIRST-CLASS
// (no longer forward-compat): the proto PlanDelta — kind, tool_use_id, and the
// full TodoItem snapshot — round-trips field-for-field onto attach.PlanDelta, and
// the Model folds it into exactly one real plan line (not "unhandled event type").
func TestPlanDeltaRoundTrip(t *testing.T) {
	ev := &attachv1.SessionEvent{
		Seq:  1,
		Type: attachv1.EventType_EVENT_TYPE_PLAN_DELTA,
		Payload: &attachv1.SessionEvent_PlanDelta{PlanDelta: &attachv1.PlanDelta{
			ToolUseId: "toolu_plan1",
			Kind:      attachv1.PlanDeltaKind_PLAN_DELTA_KIND_TODO_WRITE,
			Todos: []*attachv1.TodoItem{
				{Content: "scope the work", Status: "completed", ActiveForm: "Scoping the work", Id: "t1"},
				{Content: "wire the adapter", Status: "in_progress", ActiveForm: "Wiring the adapter", Id: "t2"},
				{Content: "land it", Status: "pending", ActiveForm: "Landing it", Id: "t3"},
			},
		}},
	}
	got := FromProto(ev)
	if got.Type != attach.TypePlanDelta {
		t.Fatalf("type = %q, want %q (working-model-owned, not the old shim)", got.Type, attach.TypePlanDelta)
	}
	if got.PlanDelta == nil {
		t.Fatalf("PlanDelta payload is nil — PLAN_DELTA fell to forward-compat instead of mapping")
	}
	pd := got.PlanDelta
	if pd.NodeID != "toolu_plan1" {
		t.Errorf("node_id = %q, want toolu_plan1 (the tool_use_id correlation key)", pd.NodeID)
	}
	if pd.Kind != attach.PlanDeltaKindTodoWrite {
		t.Errorf("kind = %q, want %q", pd.Kind, attach.PlanDeltaKindTodoWrite)
	}
	if len(pd.Todos) != 3 {
		t.Fatalf("todos = %d, want 3 (full-list snapshot)", len(pd.Todos))
	}
	if pd.Todos[1].Content != "wire the adapter" || pd.Todos[1].Status != "in_progress" ||
		pd.Todos[1].ActiveForm != "Wiring the adapter" || pd.Todos[1].ID != "t2" {
		t.Errorf("todo[1] = %+v, want the in_progress item field-for-field", pd.Todos[1])
	}
	// The Model folds it into one real plan line — a first-class delta, not the
	// forward-compat "unhandled event type" default.
	m := tui.NewModel()
	if err := m.Apply(got); err != nil {
		t.Fatalf("fold of PLAN_DELTA errored: %v", err)
	}
	if len(m.Lines) != 1 {
		t.Fatalf("PLAN_DELTA produced %d lines, want 1", len(m.Lines))
	}
	if line := m.Lines[0]; line.Kind != tui.LinePlan {
		t.Errorf("line kind = %q, want %q (a real plan line, not forward-compat)", line.Kind, tui.LinePlan)
	}
}

// TestPlanDeltaExitPlanModeRoundTrip proves the EXIT_PLAN_MODE-only fields (plan
// body + approval state) also round-trip — the proto's enum maps to the working
// model's string label off the enum (no drift).
func TestPlanDeltaExitPlanModeRoundTrip(t *testing.T) {
	ev := &attachv1.SessionEvent{
		Seq:  1,
		Type: attachv1.EventType_EVENT_TYPE_PLAN_DELTA,
		Payload: &attachv1.SessionEvent_PlanDelta{PlanDelta: &attachv1.PlanDelta{
			ToolUseId:     "toolu_plan2",
			Kind:          attachv1.PlanDeltaKind_PLAN_DELTA_KIND_EXIT_PLAN_MODE,
			Plan:          "Step 1: do X\nStep 2: do Y",
			ApprovalState: attachv1.PlanApprovalState_PLAN_APPROVAL_STATE_PROPOSED,
		}},
	}
	got := FromProto(ev)
	if got.PlanDelta == nil {
		t.Fatalf("PlanDelta payload is nil")
	}
	pd := got.PlanDelta
	if pd.Kind != attach.PlanDeltaKindExitPlanMode {
		t.Errorf("kind = %q, want %q", pd.Kind, attach.PlanDeltaKindExitPlanMode)
	}
	if pd.Plan != "Step 1: do X\nStep 2: do Y" {
		t.Errorf("plan = %q, want the verbatim plan body", pd.Plan)
	}
	if pd.ApprovalState != "proposed" {
		t.Errorf("approval_state = %q, want proposed", pd.ApprovalState)
	}
}

// TestFoldRoundTrip proves a representative event stream maps and folds through
// the OSS client/tui Model end-to-end (the mapping is what makes the reference
// fold usable for the writer-seat surface), with no fold/ordering error.
func TestFoldRoundTrip(t *testing.T) {
	stream := []*attachv1.SessionEvent{
		{Seq: 1, SessionId: "s", Type: attachv1.EventType_EVENT_TYPE_SESSION_INIT, Payload: &attachv1.SessionEvent_SessionInit{SessionInit: &attachv1.SessionInit{Model: "claude", Cwd: "/repo", Tools: []string{"Bash", "Edit"}}}},
		{Seq: 2, SessionId: "s", Type: attachv1.EventType_EVENT_TYPE_SESSION_STATE, Payload: &attachv1.SessionEvent_SessionState{SessionState: &attachv1.SessionState{Name: attachv1.SessionStateName_SESSION_STATE_NAME_WORKING}}},
		{Seq: 3, SessionId: "s", Type: attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE, Payload: &attachv1.SessionEvent_ChatMessage{ChatMessage: &attachv1.ChatMessage{MessageId: "m1", Role: "assistant", Blocks: []*attachv1.ChatBlock{{Kind: "text", Text: "hi"}}}}},
		{Seq: 4, SessionId: "s", Type: attachv1.EventType_EVENT_TYPE_TOOL_INVOKED, Payload: &attachv1.SessionEvent_ToolInvoked{ToolInvoked: &attachv1.ToolInvoked{NodeId: "n1", Name: "Bash", Kind: "native"}}},
		{Seq: 5, SessionId: "s", Type: attachv1.EventType_EVENT_TYPE_ASK_REQUESTED, Payload: &attachv1.SessionEvent_AskRequested{AskRequested: &attachv1.AskRequested{ToolUseId: "n1", RequestId: "r1", ToolName: "Bash"}}},
		{Seq: 6, SessionId: "s", Type: attachv1.EventType_EVENT_TYPE_ASK_RESOLVED, Payload: &attachv1.SessionEvent_AskResolved{AskResolved: &attachv1.AskResolved{ToolUseId: "n1", RequestId: "r1", Behavior: "allow"}}},
		{Seq: 7, SessionId: "s", Type: attachv1.EventType_EVENT_TYPE_SESSION_ACCOUNTED, Payload: &attachv1.SessionEvent_SessionAccounted{SessionAccounted: &attachv1.SessionAccounted{Outcome: "success", NumTurns: 2, TotalCostUsd: 0.01}}},
	}
	m := tui.NewModel()
	for _, pe := range stream {
		if err := m.Apply(FromProto(pe)); err != nil {
			t.Fatalf("fold seq %d: %v", pe.GetSeq(), err)
		}
	}
	if m.LastSeq() != 7 {
		t.Fatalf("LastSeq = %d, want 7", m.LastSeq())
	}
	if m.Init == nil || m.Init.Model != "claude" {
		t.Fatalf("init not folded: %+v", m.Init)
	}
	if m.Accounting == nil || m.Accounting.Outcome != "success" {
		t.Fatalf("accounting not folded: %+v", m.Accounting)
	}
	// The ask opened (seq 5) then resolved (seq 6): no pending ask remains.
	if len(m.PendingAsks()) != 0 {
		t.Fatalf("pending asks = %d, want 0 (resolved)", len(m.PendingAsks()))
	}
}
