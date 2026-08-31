// classify_test.go — owned by impl-classify: table-driven unit tests feeding
// hand-rolled NDJSON record lines through a fresh Adapter (deterministic
// clock). They assert emitted event types, payload fields, and ordering for
// the P14 classification rules, chat projection, isReplay skip (P4),
// tool_result routing (P13), and stream_event consumption (P11). No dependency
// on client/fixtures/ cassettes — that is the goldentrace integration suite.
package claudecode

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Test helpers in this file are prefixed `classify` to stay in their own
// namespace: every *_test.go in package claudecode shares one scope, and the
// peer area test files (ask_test.go, state_test.go) define their own feed/
// clock helpers. Keep these unique so the suite links regardless of peer state.

// classifyClock mirrors the replay clock: 2026-01-01T00:00:00Z + 1s per call.
func classifyClock() func() time.Time {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := 0
	return func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}
}

// classifyAdapter builds a deterministic adapter and seeds the init-derived
// allowlists so Skill/subagent allowlist checks have a registry to consult.
func classifyAdapter() *Adapter {
	a := New(WithClock(classifyClock()))
	a.sessionID = "00000000-0000-4000-8000-000000000001"
	a.skills = stringSet([]string{"verify"})
	a.agentTypes = stringSet([]string{"claude", "echoer"})
	return a
}

func classifyFeed(t *testing.T, a *Adapter, line string) []attach.Event {
	t.Helper()
	evs, err := a.Feed([]byte(line))
	if err != nil {
		t.Fatalf("Feed(%s) error: %v", line, err)
	}
	return evs
}

// --- chat projection (text/thinking ⇒ one ChatMessage merged by message_id) ---

func TestAssistantChatMessageMergesTextAndThinking(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000c1","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_1","role":"assistant","content":[{"type":"thinking","thinking":"weighing it"},{"type":"text","text":"hello"}]}}`
	evs := classifyFeed(t, a, line)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 ChatMessage", len(evs))
	}
	ev := evs[0]
	if ev.Type != attach.TypeChatMessage || ev.ChatMessage == nil {
		t.Fatalf("event = %+v, want chat.message", ev)
	}
	cm := ev.ChatMessage
	if cm.MessageID != "msg_synth_1" || cm.Role != "assistant" {
		t.Errorf("message_id/role = %q/%q", cm.MessageID, cm.Role)
	}
	if cm.ParentNodeID != "" {
		t.Errorf("parent_node_id = %q, want empty (root)", cm.ParentNodeID)
	}
	if len(cm.Blocks) != 2 || cm.Blocks[0].Kind != "thinking" || cm.Blocks[0].Text != "weighing it" ||
		cm.Blocks[1].Kind != "text" || cm.Blocks[1].Text != "hello" {
		t.Errorf("blocks = %+v, want thinking then text in order", cm.Blocks)
	}
	if len(ev.Source) != 1 || ev.Source[0] != "00000000-0000-4000-8000-0000000000c1" {
		t.Errorf("source = %v, want the assistant record uuid", ev.Source)
	}
}

func TestAssistantNestedParentNodeID(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000c2","session_id":"00000000-0000-4000-8000-000000000001","parent_tool_use_id":"toolu_SYNTHparent","message":{"id":"msg_synth_2","role":"assistant","content":[{"type":"text","text":"sub speaks"}]}}`
	evs := classifyFeed(t, a, line)
	if len(evs) != 1 || evs[0].ChatMessage == nil {
		t.Fatalf("got %+v, want one chat.message", evs)
	}
	if got := evs[0].ChatMessage.ParentNodeID; got != "toolu_SYNTHparent" {
		t.Errorf("parent_node_id = %q, want toolu_SYNTHparent", got)
	}
}

func TestAssistantEmptyTextBlocksProduceNoChat(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000c3","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_3","role":"assistant","content":[{"type":"text","text":""}]}}`
	if evs := classifyFeed(t, a, line); len(evs) != 0 {
		t.Fatalf("empty text block emitted %d events, want 0", len(evs))
	}
}

// --- tool classification by name+input (P14) ---

func TestToolClassificationByNameAndInput(t *testing.T) {
	tests := []struct {
		name     string
		toolUse  string // the tool_use block JSON
		wantKind string
		wantSrv  string
		wantTool string
		wantSkl  string
	}{
		{
			name:     "native bash",
			toolUse:  `{"type":"tool_use","id":"toolu_SYNTHbash","name":"Bash","input":{"command":"ls"},"caller":{"type":"direct"}}`,
			wantKind: "native",
		},
		{
			name:     "mcp double-underscore split, simple tool",
			toolUse:  `{"type":"tool_use","id":"toolu_SYNTHmcp","name":"mcp__echotest__echo","input":{"text":"ds-ping"},"caller":{"type":"direct"}}`,
			wantKind: "mcp",
			wantSrv:  "echotest",
			wantTool: "echo",
		},
		{
			name:     "mcp tool name with single underscore",
			toolUse:  `{"type":"tool_use","id":"toolu_SYNTHmcp2","name":"mcp__svc__complete_authentication","input":{},"caller":{"type":"direct"}}`,
			wantKind: "mcp",
			wantSrv:  "svc",
			wantTool: "complete_authentication",
		},
		{
			name:     "skill",
			toolUse:  `{"type":"tool_use","id":"toolu_SYNTHskill","name":"Skill","input":{"skill":"verify"},"caller":{"type":"direct"}}`,
			wantKind: "skill",
			wantSkl:  "verify",
		},
		{
			name:     "Task without subagent_type is native todo-list tool",
			toolUse:  `{"type":"tool_use","id":"toolu_SYNTHtodo","name":"TaskCreate","input":{"description":"do a thing"},"caller":{"type":"direct"}}`,
			wantKind: "native",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := classifyAdapter()
			line := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000d0","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_t","role":"assistant","content":[` + tc.toolUse + `]}}`
			evs := classifyFeed(t, a, line)
			if len(evs) != 1 {
				t.Fatalf("got %d events, want 1 tool.invoked", len(evs))
			}
			ev := evs[0]
			if ev.Type != attach.TypeToolInvoked || ev.ToolInvoked == nil {
				t.Fatalf("event = %+v, want tool.invoked", ev)
			}
			ti := ev.ToolInvoked
			if ti.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", ti.Kind, tc.wantKind)
			}
			if ti.Server != tc.wantSrv || ti.Tool != tc.wantTool {
				t.Errorf("server/tool = %q/%q, want %q/%q", ti.Server, ti.Tool, tc.wantSrv, tc.wantTool)
			}
			if ti.Skill != tc.wantSkl {
				t.Errorf("skill = %q, want %q", ti.Skill, tc.wantSkl)
			}
			if ti.TurnGroup != "msg_synth_t" {
				t.Errorf("turn_group = %q, want msg_synth_t", ti.TurnGroup)
			}
		})
	}
}

// A TodoWrite tool-use is a FIRST-CLASS plan delta (§6.1 row 6), NOT a generic
// ToolInvoked: classify emits one attach.TypePlanDelta carrying the full
// todo-list snapshot (the canvas plan card), decoded from input.todos[].
func TestTodoWriteEmitsPlanDelta(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000da","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_td","role":"assistant","content":[{"type":"tool_use","id":"toolu_SYNTHtodo1","name":"TodoWrite","input":{"todos":[{"content":"scope the work","status":"completed","activeForm":"Scoping the work","id":"t1"},{"content":"wire the adapter","status":"in_progress","activeForm":"Wiring the adapter","id":"t2"},{"content":"land it","status":"pending","activeForm":"Landing it"}]},"caller":{"type":"direct"}}]}}`
	evs := classifyFeed(t, a, line)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 plan.delta", len(evs))
	}
	ev := evs[0]
	if ev.Type != attach.TypePlanDelta || ev.PlanDelta == nil {
		t.Fatalf("event = %+v, want plan.delta (NOT a generic tool.invoked)", ev)
	}
	if ev.ToolInvoked != nil {
		t.Fatalf("TodoWrite leaked a tool.invoked payload: %+v", ev.ToolInvoked)
	}
	pd := ev.PlanDelta
	if pd.NodeID != "toolu_SYNTHtodo1" {
		t.Errorf("node_id = %q, want toolu_SYNTHtodo1 (the tool-use id)", pd.NodeID)
	}
	if pd.Kind != attach.PlanDeltaKindTodoWrite {
		t.Errorf("kind = %q, want %q", pd.Kind, attach.PlanDeltaKindTodoWrite)
	}
	if len(pd.Todos) != 3 {
		t.Fatalf("todos = %d, want 3 (full-list snapshot)", len(pd.Todos))
	}
	if pd.Todos[0].Content != "scope the work" || pd.Todos[0].Status != "completed" ||
		pd.Todos[0].ActiveForm != "Scoping the work" || pd.Todos[0].ID != "t1" {
		t.Errorf("todo[0] = %+v, want the completed item field-for-field", pd.Todos[0])
	}
	if pd.Todos[1].Status != "in_progress" || pd.Todos[1].Content != "wire the adapter" {
		t.Errorf("todo[1] = %+v, want the in_progress item", pd.Todos[1])
	}
	if pd.Todos[2].Status != "pending" || pd.Todos[2].ID != "" {
		t.Errorf("todo[2] = %+v, want the pending item with empty id", pd.Todos[2])
	}
	if len(ev.Source) != 1 || ev.Source[0] != "00000000-0000-4000-8000-0000000000da" {
		t.Errorf("source = %v, want the assistant record uuid", ev.Source)
	}
}

// An empty TodoWrite (todos:[]) still emits a plan delta — an honest "plan
// cleared" snapshot carrying an empty list, never a crash or a dropped event.
func TestTodoWriteEmptyListStillEmitsPlanDelta(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000db","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_td2","role":"assistant","content":[{"type":"tool_use","id":"toolu_SYNTHtodo2","name":"TodoWrite","input":{"todos":[]},"caller":{"type":"direct"}}]}}`
	evs := classifyFeed(t, a, line)
	if len(evs) != 1 || evs[0].Type != attach.TypePlanDelta || evs[0].PlanDelta == nil {
		t.Fatalf("got %+v, want one plan.delta", evs)
	}
	if len(evs[0].PlanDelta.Todos) != 0 {
		t.Errorf("todos = %d, want 0 (empty list snapshot)", len(evs[0].PlanDelta.Todos))
	}
}

// A subagent spawn (name in {Agent,Task,TaskCreate} WITH input.subagent_type)
// delegates to the tree hook and is NOT a ToolInvoked. The tree stub returns
// no events in this unit context; the assertion is that classify routed it
// there (no ToolInvoked leaked).
func TestSubagentSpawnDelegatesToTreeNotToolInvoked(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000d1","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_s","role":"assistant","content":[{"type":"tool_use","id":"toolu_SYNTHspawn","name":"Agent","input":{"description":"go","subagent_type":"echoer","prompt":"echo hi"},"caller":{"type":"direct"}}]}}`
	evs := classifyFeed(t, a, line)
	for _, ev := range evs {
		if ev.Type == attach.TypeToolInvoked {
			t.Fatalf("subagent spawn leaked a tool.invoked event: %+v", ev)
		}
	}
}

func TestSkillNotInAllowlistWarns(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000d2","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_w","role":"assistant","content":[{"type":"tool_use","id":"toolu_SYNTHskill2","name":"Skill","input":{"skill":"ghost"},"caller":{"type":"direct"}}]}}`
	evs := classifyFeed(t, a, line)
	if len(evs) != 1 || evs[0].ToolInvoked == nil || evs[0].ToolInvoked.Skill != "ghost" {
		t.Fatalf("got %+v, want one skill tool.invoked", evs)
	}
	w := a.Warnings()
	if len(w) != 1 || !strings.Contains(w[0], "ghost") {
		t.Errorf("warnings = %v, want one naming the unknown skill", w)
	}
}

// mixed turn: thinking+text+tool_use ⇒ one ChatMessage (merged) then the tool,
// in content order, both stamped with the same source uuid.
func TestMixedTurnChatThenTool(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000d3","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_m","role":"assistant","content":[{"type":"text","text":"running it"},{"type":"tool_use","id":"toolu_SYNTHmix","name":"Bash","input":{"command":"ls"},"caller":{"type":"direct"}}]}}`
	evs := classifyFeed(t, a, line)
	if len(evs) != 2 {
		t.Fatalf("got %d events, want chat.message then tool.invoked", len(evs))
	}
	if evs[0].Type != attach.TypeChatMessage || evs[1].Type != attach.TypeToolInvoked {
		t.Fatalf("order = %q,%q; want chat.message,tool.invoked", evs[0].Type, evs[1].Type)
	}
	if evs[0].Seq != 1 || evs[1].Seq != 2 {
		t.Errorf("seqs = %d,%d, want 1,2 (monotonic emission order)", evs[0].Seq, evs[1].Seq)
	}
	if input := string(evs[1].ToolInvoked.Input); !strings.Contains(input, "command") {
		t.Errorf("tool input not passed through: %q", input)
	}
}

// --- user record handling: isReplay skip (P4), tool_result routing (P13) ---

func TestUserIsReplaySkipped(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000e0","session_id":"00000000-0000-4000-8000-000000000001","isReplay":true,"timestamp":"2026-01-01T00:00:00Z","message":{"role":"user","content":[{"type":"text","text":"echoed input"}]}}`
	if evs := classifyFeed(t, a, line); len(evs) != 0 {
		t.Fatalf("isReplay record emitted %d events, want 0 (ACK marker, P4)", len(evs))
	}
	if w := a.Warnings(); len(w) != 0 {
		t.Errorf("isReplay skip warned: %v", w)
	}
}

func TestUserToolResultSuccessEmitsToolCompleted(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000e1","session_id":"00000000-0000-4000-8000-000000000001","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_SYNTHbash","is_error":false,"content":[{"type":"text","text":"file-a\nfile-b"}]}]}}`
	evs := classifyFeed(t, a, line)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 tool.completed", len(evs))
	}
	tc := evs[0].ToolCompleted
	if evs[0].Type != attach.TypeToolCompleted || tc == nil {
		t.Fatalf("event = %+v, want tool.completed", evs[0])
	}
	if tc.NodeID != "toolu_SYNTHbash" || tc.IsError {
		t.Errorf("node_id/is_error = %q/%v", tc.NodeID, tc.IsError)
	}
	if tc.OutputExcerpt != "file-a\nfile-b" {
		t.Errorf("output_excerpt = %q, want first text block", tc.OutputExcerpt)
	}
	if tc.DenialMessage != "" {
		t.Errorf("denial_message = %q, want empty on success", tc.DenialMessage)
	}
}

func TestUserToolResultErrorBareStringIsDenialMessage(t *testing.T) {
	a := classifyAdapter()
	// is_error:true content is a BARE STRING (P13) — the denial message verbatim.
	line := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000e2","session_id":"00000000-0000-4000-8000-000000000001","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_SYNTHdeny","is_error":true,"content":"Permission to use Bash with command echo has been denied."}]}}`
	evs := classifyFeed(t, a, line)
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 tool.completed", len(evs))
	}
	tc := evs[0].ToolCompleted
	if tc == nil || !tc.IsError {
		t.Fatalf("event = %+v, want is_error tool.completed", evs[0])
	}
	if tc.DenialMessage != "Permission to use Bash with command echo has been denied." {
		t.Errorf("denial_message = %q, want the bare-string body verbatim", tc.DenialMessage)
	}
	// The bare-string error body is BOTH the denial_message and the
	// output_excerpt — the body IS this completion's output (denial checklists
	// require output_excerpt = the same bare string).
	if tc.OutputExcerpt != "Permission to use Bash with command echo has been denied." {
		t.Errorf("output_excerpt = %q, want the same bare-string body as denial_message", tc.OutputExcerpt)
	}
}

func TestUserToolResultLongOutputTruncated(t *testing.T) {
	a := classifyAdapter()
	long := strings.Repeat("x", 300)
	line := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000e3","session_id":"00000000-0000-4000-8000-000000000001","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_SYNTHlong","is_error":false,"content":[{"type":"text","text":"` + long + `"}]}]}}`
	evs := classifyFeed(t, a, line)
	got := evs[0].ToolCompleted.OutputExcerpt
	if runes := []rune(got); len(runes) != 257 || runes[256] != '…' {
		t.Errorf("output_excerpt = %d runes, want 256 + … truncation", len(runes))
	}
}

// A registered subagent node's tool_result routes to the tree hook, NOT a
// bare ToolCompleted. The tree stub emits nothing in this unit context; the
// assertion is that no tool.completed leaked.
func TestSubagentToolResultRoutesToTree(t *testing.T) {
	a := classifyAdapter()
	a.registry["toolu_SYNTHspawn"] = &node{}
	line := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000e4","session_id":"00000000-0000-4000-8000-000000000001","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_SYNTHspawn","is_error":false,"content":[{"type":"text","text":"ACORN"}]}]}}`
	evs := classifyFeed(t, a, line)
	for _, ev := range evs {
		if ev.Type == attach.TypeToolCompleted {
			t.Fatalf("registered subagent result leaked a tool.completed: %+v", ev)
		}
	}
}

// The ToolSearch deferred-tool hop: a tool_result carrying subtype
// tool_reference is TOLERATED (no crash/misclassification) and emits a normal
// tool.completed so the invoked ToolSearch node is never left unpaired — the
// binding checklist (checklists/mcp-skill-native.md item 5) requires the
// completion (is_error:false, output_excerpt = the tool_reference body, P14).
func TestToolReferenceHopEmitsCompletion(t *testing.T) {
	a := classifyAdapter()
	// The cassette form: content is a [{type:"text", text:"tool_reference"}]
	// array, so the excerpt is the body "tool_reference".
	line := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000e5","session_id":"00000000-0000-4000-8000-000000000001","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_SYNTHsearch","subtype":"tool_reference","is_error":false,"content":[{"type":"text","text":"tool_reference"}],"tool_name":"mcp__echotest__echo"}]}}`
	evs := classifyFeed(t, a, line)
	if len(evs) != 1 || evs[0].Type != attach.TypeToolCompleted || evs[0].ToolCompleted == nil {
		t.Fatalf("tool_reference hop = %+v, want one tool.completed", evs)
	}
	tc := evs[0].ToolCompleted
	if tc.NodeID != "toolu_SYNTHsearch" || tc.IsError {
		t.Errorf("node_id/is_error = %q/%v, want toolu_SYNTHsearch/false", tc.NodeID, tc.IsError)
	}
	if tc.OutputExcerpt != "tool_reference" {
		t.Errorf("output_excerpt = %q, want the tool_reference body", tc.OutputExcerpt)
	}
	if tc.DenialMessage != "" {
		t.Errorf("denial_message = %q, want empty (not a denial)", tc.DenialMessage)
	}
	if w := a.Warnings(); len(w) != 0 {
		t.Errorf("tool_reference hop warned: %v", w)
	}
}

// A non-replay user record with a set parent_tool_use_id and no tool_result is
// a nested subagent prompt: corroboration only, no standalone event.
func TestNestedPromptUserRecordEmitsNothing(t *testing.T) {
	a := classifyAdapter()
	line := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000e7","session_id":"00000000-0000-4000-8000-000000000001","parent_tool_use_id":"toolu_SYNTHspawn","message":{"role":"user","content":[{"type":"text","text":"the prompt sent into the subagent"}]}}`
	if evs := classifyFeed(t, a, line); len(evs) != 0 {
		t.Fatalf("nested prompt emitted %d events, want 0 (corroboration only)", len(evs))
	}
}

// A nested prompt backfills the parent node's prompt_excerpt when the spawn
// block / task_started never carried a prompt (the missed-spawn / local_bash
// case) — corroboration, still no standalone event (spec classify.go row).
func TestNestedPromptBackfillsEmptyPromptExcerpt(t *testing.T) {
	a := classifyAdapter()
	a.registry["toolu_SYNTHspawn"] = &node{toolUseID: "toolu_SYNTHspawn"} // promptExcerpt empty
	line := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000e8","session_id":"00000000-0000-4000-8000-000000000001","parent_tool_use_id":"toolu_SYNTHspawn","message":{"role":"user","content":[{"type":"text","text":"do the inner work"}]}}`
	if evs := classifyFeed(t, a, line); len(evs) != 0 {
		t.Fatalf("nested prompt emitted %d events, want 0", len(evs))
	}
	if got := a.registry["toolu_SYNTHspawn"].promptExcerpt; got != "do the inner work" {
		t.Errorf("prompt_excerpt = %q, want backfilled from the nested prompt", got)
	}
}

// An already-corroborated prompt_excerpt (from the spawn block / task_started)
// is authoritative and never overwritten by a nested prompt (§2 keep-value).
func TestNestedPromptDoesNotOverwritePromptExcerpt(t *testing.T) {
	a := classifyAdapter()
	a.registry["toolu_SYNTHspawn"] = &node{toolUseID: "toolu_SYNTHspawn", promptExcerpt: "authoritative"}
	line := `{"type":"user","uuid":"00000000-0000-4000-8000-0000000000e9","session_id":"00000000-0000-4000-8000-000000000001","parent_tool_use_id":"toolu_SYNTHspawn","message":{"role":"user","content":[{"type":"text","text":"a different prompt text"}]}}`
	classifyFeed(t, a, line)
	if got := a.registry["toolu_SYNTHspawn"].promptExcerpt; got != "authoritative" {
		t.Errorf("prompt_excerpt = %q, want the spawn-line value kept", got)
	}
}

// --- stream_event: render channel only (P11) ---

func TestStreamEventEmitsNothing(t *testing.T) {
	a := classifyAdapter()
	lines := []string{
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-0000000000f0","session_id":"00000000-0000-4000-8000-000000000001","ttft_ms":12,"event":{"type":"message_start","message":{"id":"msg_synth_p"}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-0000000000f1","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-0000000000f2","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hel"}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-0000000000f3","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_stop","index":0}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-0000000000f4","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"message_stop"}}`,
	}
	for _, line := range lines {
		if evs := classifyFeed(t, a, line); len(evs) != 0 {
			t.Fatalf("stream_event %s emitted %d events, want 0 (render channel only, P11)", line, len(evs))
		}
	}
	if a.seq != 0 {
		t.Errorf("seq advanced to %d on stream_event-only input, want 0 (no canonical events)", a.seq)
	}
}

// P11 structural truth: a turn driven by partials yields output identical in
// content to the same turn from non-partial records alone — the partials add
// nothing canonical. Feed a stream envelope, then the authoritative
// non-partial assistant record; only the non-partial projects.
func TestPartialsThenNonPartialIdenticalToNonPartialAlone(t *testing.T) {
	withPartials := classifyAdapter()
	classifyFeed(t, withPartials, `{"type":"stream_event","uuid":"00000000-0000-4000-8000-0000000000f5","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"message_start","message":{"id":"msg_synth_q"}}}`)
	classifyFeed(t, withPartials, `{"type":"stream_event","uuid":"00000000-0000-4000-8000-0000000000f6","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"done"}}}`)
	nonPartial := `{"type":"assistant","uuid":"00000000-0000-4000-8000-0000000000f7","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_q","role":"assistant","content":[{"type":"text","text":"done"}]}}`
	withEvs := classifyFeed(t, withPartials, nonPartial)

	withoutPartials := classifyAdapter()
	withoutEvs := classifyFeed(t, withoutPartials, nonPartial)

	if !classifySameProjection(withEvs, withoutEvs) {
		t.Fatalf("partials changed the projection: with=%s without=%s", classifyMustJSON(withEvs), classifyMustJSON(withoutEvs))
	}
}

func classifySameProjection(a, b []attach.Event) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type {
			return false
		}
		if a[i].ChatMessage != nil && b[i].ChatMessage != nil {
			if a[i].ChatMessage.MessageID != b[i].ChatMessage.MessageID {
				return false
			}
			if len(a[i].ChatMessage.Blocks) != len(b[i].ChatMessage.Blocks) {
				return false
			}
		}
	}
	return true
}

func classifyMustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// --- live streaming text: WithPartials ChatDelta projection (D145, §Layer 1) ---

// classifyPartialsAdapter is classifyAdapter WithPartials: it projects the
// runtime's typing deltas as render-only attach.ChatDelta events.
func classifyPartialsAdapter() *Adapter {
	a := New(WithClock(classifyClock()), WithPartials())
	a.sessionID = "00000000-0000-4000-8000-000000000001"
	a.skills = stringSet([]string{"verify"})
	a.agentTypes = stringSet([]string{"claude", "echoer"})
	return a
}

// A2 (doc 06 §7): a message_start → content_block_delta×N → content_block_stop
// → message_stop partial sequence WithPartials emits N+1 ChatDeltas (N text
// deltas + 1 final), and the matching non-partial assistant record still emits
// exactly one ChatMessage. The deltas join the finalizing message by message_id,
// carry the block kind, and the final delta sets Final with no text.
func TestPartialsEmitNPlusOneChatDeltas(t *testing.T) {
	a := classifyPartialsAdapter()
	feed := func(line string) []attach.Event { return classifyFeed(t, a, line) }

	if evs := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000201","session_id":"00000000-0000-4000-8000-000000000001","ttft_ms":12,"event":{"type":"message_start","message":{"id":"msg_synth_lt"}}}`); len(evs) != 0 {
		t.Fatalf("message_start emitted %d events, want 0", len(evs))
	}
	if evs := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000202","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}}`); len(evs) != 0 {
		t.Fatalf("content_block_start emitted %d events, want 0", len(evs))
	}

	deltas := []string{"Hel", "lo, ", "world"}
	var got []attach.Event
	for i, d := range deltas {
		evs := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-00000000020` + string(rune('a'+i)) + `","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"` + d + `"}}}`)
		if len(evs) != 1 {
			t.Fatalf("content_block_delta %d emitted %d events, want 1 ChatDelta", i, len(evs))
		}
		got = append(got, evs[0])
	}
	stop := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000210","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_stop","index":0}}`)
	if len(stop) != 1 {
		t.Fatalf("content_block_stop emitted %d events, want 1 final ChatDelta", len(stop))
	}
	got = append(got, stop[0])
	if evs := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000211","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"message_stop"}}`); len(evs) != 0 {
		t.Fatalf("message_stop emitted %d events, want 0", len(evs))
	}

	if len(got) != len(deltas)+1 {
		t.Fatalf("got %d ChatDeltas, want N+1 = %d", len(got), len(deltas)+1)
	}
	for i, ev := range got {
		if ev.Type != attach.TypeChatDelta || ev.ChatDelta == nil {
			t.Fatalf("event %d = %+v, want chat.delta", i, ev)
		}
		cd := ev.ChatDelta
		if cd.MessageID != "msg_synth_lt" {
			t.Errorf("delta %d message_id = %q, want msg_synth_lt (joins the finalizing ChatMessage)", i, cd.MessageID)
		}
		if cd.Kind != "text" {
			t.Errorf("delta %d kind = %q, want text", i, cd.Kind)
		}
		if cd.BlockIndex != 0 {
			t.Errorf("delta %d block_index = %d, want 0", i, cd.BlockIndex)
		}
	}
	// The N text deltas carry coalesced text and are not final; the (N+1)th is
	// the content_block_stop final delta (no text, Final set).
	for i := 0; i < len(deltas); i++ {
		if got[i].ChatDelta.Text != deltas[i] || got[i].ChatDelta.Final {
			t.Errorf("delta %d = %+v, want text %q non-final", i, got[i].ChatDelta, deltas[i])
		}
	}
	final := got[len(deltas)].ChatDelta
	if !final.Final || final.Text != "" {
		t.Errorf("final delta = %+v, want Final:true with empty text", final)
	}

	// The matching non-partial assistant record still emits EXACTLY ONE
	// ChatMessage (the authoritative content, P11) — partials added nothing canonical.
	nonPartial := `{"type":"assistant","uuid":"00000000-0000-4000-8000-000000000212","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_lt","role":"assistant","content":[{"type":"text","text":"Hello, world"}]}}`
	cm := feed(nonPartial)
	if len(cm) != 1 || cm[0].Type != attach.TypeChatMessage || cm[0].ChatMessage == nil {
		t.Fatalf("non-partial record = %+v, want exactly one chat.message", cm)
	}
	if cm[0].ChatMessage.MessageID != "msg_synth_lt" {
		t.Errorf("ChatMessage message_id = %q, want msg_synth_lt", cm[0].ChatMessage.MessageID)
	}
}

// input_json_delta is tool-input assembly, NOT typing text (P11/R4): a thinking
// block streams a thinking ChatDelta, but a tool_use block's input_json_delta
// emits NO ChatDelta even WithPartials. Confirms the kind ∈ {text,thinking} gate.
func TestPartialsThinkingStreamsButToolInputDoesNot(t *testing.T) {
	a := classifyPartialsAdapter()
	feed := func(line string) []attach.Event { return classifyFeed(t, a, line) }

	feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000220","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"message_start","message":{"id":"msg_synth_mix"}}}`)
	// Block 0: thinking — streams.
	feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000221","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_start","index":0,"content_block":{"type":"thinking"}}}`)
	think := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000222","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"weighing it"}}}`)
	if len(think) != 1 || think[0].ChatDelta == nil || think[0].ChatDelta.Kind != "thinking" || think[0].ChatDelta.Text != "weighing it" {
		t.Fatalf("thinking delta = %+v, want one thinking ChatDelta carrying the thinking text", think)
	}
	// Block 1: tool_use — its input_json_delta must NOT stream as text (P11/R4).
	feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000223","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_x","name":"Bash"}}}`)
	if evs := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000224","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"command\":"}}}`); len(evs) != 0 {
		t.Fatalf("input_json_delta emitted %d events, want 0 (tool-input assembly, never typing text)", len(evs))
	}
	if evs := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000225","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_stop","index":1}}`); len(evs) != 0 {
		t.Fatalf("tool_use content_block_stop emitted %d events, want 0 (no typing for tool input)", len(evs))
	}
}

// A3 (doc 06 §7) — THE RENDER-ONLY REGRESSION GUARD: dropping every ChatDelta
// from the with-partials projection yields canonical state byte-identical to the
// without-partials projection. This is what keeps ChatDelta strictly
// non-canonical (P11): the live typing animation is the ONLY difference; the
// authoritative ChatMessage the consumer folds is unchanged.
func TestDroppingChatDeltasIsByteIdenticalToNonPartial(t *testing.T) {
	stream := []string{
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000301","session_id":"00000000-0000-4000-8000-000000000001","ttft_ms":7,"event":{"type":"message_start","message":{"id":"msg_synth_rg"}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000302","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_start","index":0,"content_block":{"type":"text"}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000303","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"par"}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000304","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"tial"}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000305","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_stop","index":0}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000306","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"message_stop"}}`,
	}
	nonPartial := `{"type":"assistant","uuid":"00000000-0000-4000-8000-000000000307","session_id":"00000000-0000-4000-8000-000000000001","message":{"id":"msg_synth_rg","role":"assistant","content":[{"type":"text","text":"partial"}]}}`

	// With-partials projection: every stream_event, then the authoritative record.
	withP := classifyPartialsAdapter()
	var withAll []attach.Event
	for _, l := range stream {
		withAll = append(withAll, classifyFeed(t, withP, l)...)
	}
	withAll = append(withAll, classifyFeed(t, withP, nonPartial)...)

	// Strip every ChatDelta — what a consumer that ignores the typing animation folds.
	var withoutDeltas []attach.Event
	sawDelta := false
	for _, ev := range withAll {
		if ev.Type == attach.TypeChatDelta {
			sawDelta = true
			continue
		}
		withoutDeltas = append(withoutDeltas, ev)
	}
	if !sawDelta {
		t.Fatal("the with-partials projection emitted no ChatDelta — the guard is vacuous")
	}

	// Without-partials projection: only the authoritative non-partial record.
	withoutP := classifyAdapter()
	canonical := classifyFeed(t, withoutP, nonPartial)

	// The canonical events (ChatDeltas dropped) must be byte-identical. Compare
	// the payloads field-for-field; the synthesized seq differs (the with-partials
	// adapter advanced seq through the deltas), so normalize seq + source before
	// the byte compare — the CONTENT is what must be identical (P11).
	if !canonicalEqual(withoutDeltas, canonical) {
		t.Fatalf("dropping ChatDeltas did not yield the canonical projection:\n with-(deltas dropped)=%s\n without=%s",
			classifyMustJSON(withoutDeltas), classifyMustJSON(canonical))
	}
}

// canonicalEqual compares two event slices for canonical (content) equality,
// ignoring the adapter-synthesized seq and source uuids (which legitimately
// differ when partials advanced the seq counter). It is the render-only guard's
// equality: the CANONICAL content a consumer folds must match.
func canonicalEqual(a, b []attach.Event) bool {
	if len(a) != len(b) {
		return false
	}
	norm := func(ev attach.Event) string {
		ev.Seq = 0
		ev.Source = nil
		ev.ObservedAt = time.Time{}
		bs, _ := json.Marshal(ev)
		return string(bs)
	}
	for i := range a {
		if norm(a[i]) != norm(b[i]) {
			return false
		}
	}
	return true
}

// THE EARLY content_block_start NIL-GUARD (handleStreamEvent, classify.go): a
// content_block_start that arrives BEFORE any message_start (a malformed / truncated
// stream — the per-message cursor a.blockKind is still nil) must NOT panic. The guard
// lazily seeds the index map so the block kind is still recorded, and a subsequent
// content_block_delta on that index streams its typing text. Every existing partials
// test feeds message_start first (which allocates a.blockKind), so this branch is
// otherwise uncovered. WithPartials ON: the seeded kind drives the delta projection.
func TestPartialsEarlyContentBlockStartNilGuard(t *testing.T) {
	a := classifyPartialsAdapter()
	feed := func(line string) []attach.Event { return classifyFeed(t, a, line) }

	// content_block_start with NO preceding message_start: a.blockKind is nil here.
	// The lazy-seed guard must record the kind without panicking and emit nothing.
	if evs := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000501","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}}`); len(evs) != 0 {
		t.Fatalf("early content_block_start emitted %d events, want 0", len(evs))
	}

	// A content_block_delta on the seeded index now streams as a text ChatDelta —
	// proof the guard actually recorded the kind into the lazily-seeded map (a nil
	// map would have left the kind unknown and dropped the delta).
	deltas := feed(`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000502","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"early"}}}`)
	if len(deltas) != 1 || deltas[0].Type != attach.TypeChatDelta || deltas[0].ChatDelta == nil {
		t.Fatalf("delta after early content_block_start = %+v, want one text ChatDelta (the guard seeded the kind)", deltas)
	}
	if deltas[0].ChatDelta.Kind != "text" || deltas[0].ChatDelta.Text != "early" {
		t.Errorf("ChatDelta = %+v, want kind text / text \"early\"", deltas[0].ChatDelta)
	}
	// MessageID is empty (no message_start carried one) — that is honest, not a crash:
	// the live tail renders without a join key until the finalizing record arrives.
	if deltas[0].ChatDelta.MessageID != "" {
		t.Errorf("MessageID = %q, want empty (no preceding message_start)", deltas[0].ChatDelta.MessageID)
	}
}

// The same early content_block_start with WithPartials OFF (the default adapter) is
// the historical drop: no panic, no emission, no cursor state, seq unchanged. Pins
// that the nil-guard's lazy-seed is partials-gated and the default build pays nothing.
func TestPartialsOffEarlyContentBlockStartDrops(t *testing.T) {
	a := classifyAdapter() // default: no WithPartials
	if evs := classifyFeed(t, a, `{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000503","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_start","index":0,"content_block":{"type":"text"}}}`); len(evs) != 0 {
		t.Fatalf("partials-off early content_block_start emitted %d events, want 0", len(evs))
	}
	if a.seq != 0 {
		t.Errorf("partials-off early content_block_start advanced seq to %d, want 0 (byte-identical default)", a.seq)
	}
}

// The default build (WithPartials OFF) is byte-identical: a stream_event-only
// input emits nothing and never advances seq, exactly the historical drop. This
// pins the byte-identical-default invariant alongside the existing
// TestStreamEventEmitsNothing (which uses the default adapter).
func TestPartialsOffStreamEventStillDrops(t *testing.T) {
	a := classifyAdapter() // default: no WithPartials
	lines := []string{
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000401","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"message_start","message":{"id":"msg_synth_off"}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000402","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_start","index":0,"content_block":{"type":"text"}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000403","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}}`,
		`{"type":"stream_event","uuid":"00000000-0000-4000-8000-000000000404","session_id":"00000000-0000-4000-8000-000000000001","event":{"type":"content_block_stop","index":0}}`,
	}
	for _, l := range lines {
		if evs := classifyFeed(t, a, l); len(evs) != 0 {
			t.Fatalf("partials-off stream_event %s emitted %d events, want 0", l, len(evs))
		}
	}
	if a.seq != 0 {
		t.Errorf("partials-off seq advanced to %d, want 0 (byte-identical default)", a.seq)
	}
}
