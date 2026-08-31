// tree_test.go — owned by impl-tree. Table-driven unit tests feeding
// hand-rolled NDJSON record lines through a fresh Adapter on the deterministic
// clock. Asserts the subagent registry join, the three-key correlation, parent
// attribution, and the spawned/progress/completed/accounted projections. Does
// NOT depend on client/fixtures/ cassettes (those are the golden suite's job).
package claudecode

import (
	"testing"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// feedAll feeds every line through a fresh adapter and returns the flattened
// projection. Lines that error fail the test (these are well-formed records).
func feedAll(t *testing.T, a *Adapter, lines ...string) []attach.Event {
	t.Helper()
	var out []attach.Event
	for _, line := range lines {
		evs, err := a.Feed([]byte(line))
		if err != nil {
			t.Fatalf("Feed(%s) error: %v", line, err)
		}
		out = append(out, evs...)
	}
	return out
}

// onlyOfType filters the projection to events of one type.
func onlyOfType(evs []attach.Event, ty attach.Type) []attach.Event {
	var out []attach.Event
	for _, ev := range evs {
		if ev.Type == ty {
			out = append(out, ev)
		}
	}
	return out
}

// Wire-line builders — synthetic ids per D50.
const (
	tu1 = "toolu_SYNTH0000000000000000001"
	tu2 = "toolu_SYNTH0000000000000000002"
	tu3 = "toolu_SYNTH0000000000000000003"
	tu4 = "toolu_SYNTH0000000000000000004"

	task1 = "a1a1a1a1a1a1a1a1"
	task2 = "b2b2b2b2b2b2b2b2"
	task3 = "c3c3c3c3c3c3c3c3"
	task4 = "d4d4d4d4d4d4d4d4"
)

func spawnLine(uuid, msgID, toolUseID, parent, subagentType, desc, prompt string) string {
	parentField := "null"
	if parent != "" {
		parentField = `"` + parent + `"`
	}
	return `{"type":"assistant","uuid":"` + uuid + `","session_id":"sess","parent_tool_use_id":` + parentField +
		`,"message":{"id":"` + msgID + `","role":"assistant","content":[` +
		`{"type":"tool_use","id":"` + toolUseID + `","name":"Agent","input":{"description":"` + desc +
		`","subagent_type":"` + subagentType + `","prompt":"` + prompt + `"},"caller":{"type":"direct"}}]}}`
}

func taskStartedLine(uuid, toolUseID, taskID, subagentType, desc, prompt string) string {
	return `{"type":"system","subtype":"task_started","uuid":"` + uuid + `","session_id":"sess","parent_tool_use_id":null` +
		`,"task_id":"` + taskID + `","tool_use_id":"` + toolUseID + `","task_type":"local_agent","description":"` + desc +
		`","prompt":"` + prompt + `","subagent_type":"` + subagentType + `"}`
}

func taskProgressLine(uuid, toolUseID, taskID, lastTool, usage string) string {
	return `{"type":"system","subtype":"task_progress","uuid":"` + uuid + `","session_id":"sess"` +
		`,"task_id":"` + taskID + `","tool_use_id":"` + toolUseID + `","last_tool_name":"` + lastTool +
		`","usage":` + usage + `}`
}

func taskNotificationLine(uuid, toolUseID, taskID, status, summary string) string {
	return `{"type":"system","subtype":"task_notification","uuid":"` + uuid + `","session_id":"sess"` +
		`,"task_id":"` + taskID + `","tool_use_id":"` + toolUseID + `","status":"` + status +
		`","summary":"` + summary + `","output_file":"","usage":{"subagent_tokens":null}}`
}

// resultLine builds a user record carrying a subagent tool_result with the
// two-text-block content (output + <usage> trailer).
func resultLine(uuid, toolUseID, returnedTo, output, agentID string, tokens, tools, durMS int) string {
	parentField := "null"
	if returnedTo != "" {
		parentField = `"` + returnedTo + `"`
	}
	trailer := `agentId: ` + agentID + ` (use SendMessage with to: '` + agentID + `' to continue this agent)\n<usage>subagent_tokens: ` +
		itoa(tokens) + `\ntool_uses: ` + itoa(tools) + `\nduration_ms: ` + itoa(durMS) + `</usage>`
	return `{"type":"user","uuid":"` + uuid + `","session_id":"sess","parent_tool_use_id":` + parentField +
		`,"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"` + toolUseID +
		`","is_error":false,"content":[{"type":"text","text":"` + output + `"},{"type":"text","text":"` + trailer + `"}]}]}}`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

// TestSpawnJoinEitherOrder asserts SubagentSpawned fires exactly once, on the
// join of the spawn block and task_started, regardless of arrival order.
func TestSpawnJoinEitherOrder(t *testing.T) {
	t.Run("spawn first", func(t *testing.T) {
		a := New(WithClock(testClock()))
		evs := feedAll(t, a,
			spawnLine("u1", "msg1", tu1, "", "echoer", "scan", "do it"),
			taskStartedLine("u2", tu1, task1, "echoer", "scan", "do it"),
		)
		spawned := onlyOfType(evs, attach.TypeSubagentSpawned)
		if len(spawned) != 1 {
			t.Fatalf("got %d subagent.spawned, want exactly 1 (join-once)", len(spawned))
		}
	})
	t.Run("task_started first", func(t *testing.T) {
		a := New(WithClock(testClock()))
		evs := feedAll(t, a,
			taskStartedLine("u2", tu1, task1, "echoer", "scan", "do it"),
			spawnLine("u1", "msg1", tu1, "", "echoer", "scan", "do it"),
		)
		spawned := onlyOfType(evs, attach.TypeSubagentSpawned)
		if len(spawned) != 1 {
			t.Fatalf("got %d subagent.spawned, want exactly 1 (join-once, reverse order)", len(spawned))
		}
		s := spawned[0].SubagentSpawned
		if s.NodeID != tu1 || s.TaskID != task1 || s.SubagentType != "echoer" {
			t.Errorf("spawned payload mismapped: %+v", s)
		}
		if s.Description != "scan" || s.PromptExcerpt != "do it" || s.TaskType != "local_agent" {
			t.Errorf("spawned descriptive fields mismapped: %+v", s)
		}
		if s.TurnGroup != "msg1" {
			t.Errorf("turn_group = %q, want msg1 (spawn line message.id)", s.TurnGroup)
		}
	})
}

// TestSpawnNoEmitOnHalfJoin asserts a node with only one half does not emit.
func TestSpawnNoEmitOnHalfJoin(t *testing.T) {
	a := New(WithClock(testClock()))
	evs := feedAll(t, a, spawnLine("u1", "msg1", tu1, "", "echoer", "scan", "do it"))
	if got := onlyOfType(evs, attach.TypeSubagentSpawned); len(got) != 0 {
		t.Fatalf("spawn block alone emitted %d spawned events, want 0 (awaiting task_started)", len(got))
	}
}

// TestRootParentExactConfidence asserts a depth-1 (root-child) spawn is
// "exact" with an empty parent_node_id.
func TestRootParentExactConfidence(t *testing.T) {
	a := New(WithClock(testClock()))
	evs := feedAll(t, a,
		spawnLine("u1", "msg1", tu1, "", "echoer", "scan", "do it"),
		taskStartedLine("u2", tu1, task1, "echoer", "scan", "do it"),
	)
	s := onlyOfType(evs, attach.TypeSubagentSpawned)[0].SubagentSpawned
	if s.ParentNodeID != "" {
		t.Errorf("parent_node_id = %q, want empty (root child)", s.ParentNodeID)
	}
	if s.ParentConfidence != "exact" {
		t.Errorf("parent_confidence = %q, want exact (depth 1)", s.ParentConfidence)
	}
}

// TestNestedExactAtDepth2 asserts a grandchild (depth 2) keeps "exact"
// confidence, attributed from its spawn-line parent (P2/§2 rule 3).
func TestNestedExactAtDepth2(t *testing.T) {
	a := New(WithClock(testClock()))
	// outer (root) → inner (parent=outer). inner spawn line is tagged
	// parent_tool_use_id = outer's id (P2 flatten-to-1).
	evs := feedAll(t, a,
		spawnLine("u1", "msg1", tu1, "", "outer", "outer", "p"),
		taskStartedLine("u2", tu1, task1, "outer", "outer", "p"),
		spawnLine("u3", "msg2", tu2, tu1, "inner", "inner", "q"),
		taskStartedLine("u4", tu2, task2, "inner", "inner", "q"),
	)
	spawned := onlyOfType(evs, attach.TypeSubagentSpawned)
	if len(spawned) != 2 {
		t.Fatalf("got %d spawned, want 2", len(spawned))
	}
	inner := spawned[1].SubagentSpawned
	if inner.NodeID != tu2 {
		t.Fatalf("second spawned node = %q, want inner %q", inner.NodeID, tu2)
	}
	if inner.ParentNodeID != tu1 {
		t.Errorf("inner parent_node_id = %q, want outer %q (spawn-line parent)", inner.ParentNodeID, tu1)
	}
	if inner.ParentConfidence != "exact" {
		t.Errorf("inner parent_confidence = %q, want exact (depth 2)", inner.ParentConfidence)
	}
}

// TestInferredAtDepth3 asserts depth-3 attribution downgrades to "inferred"
// (OBSERVABILITY-DESIGN §2 rule 4 — depth ≥3 untested).
func TestInferredAtDepth3(t *testing.T) {
	a := New(WithClock(testClock()))
	evs := feedAll(t, a,
		spawnLine("u1", "msg1", tu1, "", "l1", "l1", "p"),
		taskStartedLine("u2", tu1, task1, "l1", "l1", "p"),
		spawnLine("u3", "msg2", tu2, tu1, "l2", "l2", "q"),
		taskStartedLine("u4", tu2, task2, "l2", "l2", "q"),
		spawnLine("u5", "msg3", tu3, tu2, "l3", "l3", "r"),
		taskStartedLine("u6", tu3, task3, "l3", "l3", "r"),
	)
	spawned := onlyOfType(evs, attach.TypeSubagentSpawned)
	if len(spawned) != 3 {
		t.Fatalf("got %d spawned, want 3", len(spawned))
	}
	deepest := spawned[2].SubagentSpawned
	if deepest.NodeID != tu3 {
		t.Fatalf("third spawned node = %q, want %q", deepest.NodeID, tu3)
	}
	if deepest.ParentConfidence != "inferred" {
		t.Errorf("depth-3 parent_confidence = %q, want inferred", deepest.ParentConfidence)
	}
	if deepest.ParentNodeID != tu2 {
		t.Errorf("depth-3 parent_node_id = %q, want %q (spawn-line value kept)", deepest.ParentNodeID, tu2)
	}
}

// TestDepthConfidenceFloorTo4 pins the parent_confidence floor across a 4-deep
// spawn chain (root→l1→l2→l3→l4), built entirely through the adapter's own
// ingest path (spawnLine + taskStartedLine, each spawn line tagged with its
// launching parent's tool_use id per P2 flatten-to-1). It locks all four edges
// at once:
//
//   - depth 1 → "exact"    (root child)
//   - depth 2 → "exact"    (the floor must NOT creep down to depth 2)
//   - depth 3 → "inferred" (the §2-rule-4 downgrade)
//   - depth 4 → "inferred" (the floor proof: an implementation tagging ONLY
//     depth == 3, which TestInferredAtDepth3 alone would pass, fails here)
//
// This is the depth-4 guard the cassette suite lacks (the deepest fixture is
// depth 3): it catches both a literal `== 3` confidence rule and any floor
// creep below depth 3, without a new cassette/golden battery (a separate
// optional follow-up). It pokes no private registry state — every node is born
// from the join of its two wire halves, exactly the real path.
func TestDepthConfidenceFloorTo4(t *testing.T) {
	a := New(WithClock(testClock()))
	evs := feedAll(t, a,
		spawnLine("u1", "msg1", tu1, "", "l1", "l1", "p"),
		taskStartedLine("u2", tu1, task1, "l1", "l1", "p"),
		spawnLine("u3", "msg2", tu2, tu1, "l2", "l2", "q"),
		taskStartedLine("u4", tu2, task2, "l2", "l2", "q"),
		spawnLine("u5", "msg3", tu3, tu2, "l3", "l3", "r"),
		taskStartedLine("u6", tu3, task3, "l3", "l3", "r"),
		spawnLine("u7", "msg4", tu4, tu3, "l4", "l4", "s"),
		taskStartedLine("u8", tu4, task4, "l4", "l4", "s"),
	)
	spawned := onlyOfType(evs, attach.TypeSubagentSpawned)
	if len(spawned) != 4 {
		t.Fatalf("got %d spawned, want 4 (one per chain level)", len(spawned))
	}

	// Each spawn is emitted on its join, so spawned[] is in chain order:
	// l1 (depth 1) … l4 (depth 4).
	cases := []struct {
		idx        int
		node       string
		parent     string
		confidence string
		depthLabel string
	}{
		{0, tu1, "", "exact", "depth 1 (root child)"},
		{1, tu2, tu1, "exact", "depth 2 (floor must not creep down)"},
		{2, tu3, tu2, "inferred", "depth 3"},
		{3, tu4, tu3, "inferred", "depth 4 (new floor proof — fails a ==3 rule)"},
	}
	for _, c := range cases {
		s := spawned[c.idx].SubagentSpawned
		if s.NodeID != c.node {
			t.Fatalf("%s: spawned[%d] node = %q, want %q", c.depthLabel, c.idx, s.NodeID, c.node)
		}
		if s.ParentNodeID != c.parent {
			t.Errorf("%s: parent_node_id = %q, want %q (spawn-line value kept)", c.depthLabel, s.ParentNodeID, c.parent)
		}
		if s.ParentConfidence != c.confidence {
			t.Errorf("%s: parent_confidence = %q, want %q", c.depthLabel, s.ParentConfidence, c.confidence)
		}
	}
}

// TestProgress1to1 asserts SubagentProgress is 1:1 from task_progress with the
// uncharacterized flag and verbatim usage passthrough.
func TestProgress1to1(t *testing.T) {
	a := New(WithClock(testClock()))
	usage := `{"foo":1,"bar":"baz"}`
	evs := feedAll(t, a,
		spawnLine("u1", "msg1", tu1, "", "echoer", "scan", "do it"),
		taskStartedLine("u2", tu1, task1, "echoer", "scan", "do it"),
		taskProgressLine("u3", tu1, task1, "Bash", usage),
	)
	prog := onlyOfType(evs, attach.TypeSubagentProgress)
	if len(prog) != 1 {
		t.Fatalf("got %d progress, want 1", len(prog))
	}
	p := prog[0].SubagentProgress
	if p.NodeID != tu1 || p.TaskID != task1 || p.LastToolName != "Bash" {
		t.Errorf("progress fields mismapped: %+v", p)
	}
	if !p.Uncharacterized {
		t.Error("progress.uncharacterized = false, want true (usage contents unverified)")
	}
	if string(p.UsageRaw) != usage {
		t.Errorf("progress.usage_raw = %s, want verbatim %s", p.UsageRaw, usage)
	}
}

// TestCompleted1to1ClosesTask asserts SubagentCompleted is 1:1 from
// task_notification and that it closes the open task.
func TestCompleted1to1ClosesTask(t *testing.T) {
	a := New(WithClock(testClock()))
	feedAll(t, a,
		spawnLine("u1", "msg1", tu1, "", "echoer", "scan", "do it"),
		taskStartedLine("u2", tu1, task1, "echoer", "scan", "do it"),
	)
	if _, open := a.openTasks[task1]; !open {
		t.Fatal("task1 not opened after task_started")
	}
	evs := feedAll(t, a, taskNotificationLine("u3", tu1, task1, "completed", "all done"))
	comp := onlyOfType(evs, attach.TypeSubagentCompleted)
	if len(comp) != 1 {
		t.Fatalf("got %d completed, want 1", len(comp))
	}
	c := comp[0].SubagentCompleted
	if c.NodeID != tu1 || c.TaskID != task1 || c.Status != "completed" || c.Summary != "all done" {
		t.Errorf("completed fields mismapped: %+v", c)
	}
	if _, open := a.openTasks[task1]; open {
		t.Error("task1 still open after task_notification — must close for the state latch")
	}
}

// TestAccountedParsesTrailer asserts SubagentAccounted parses the <usage>
// trailer, sets the continuation, and sources returned_to from the result
// line's parent_tool_use_id.
func TestAccountedParsesTrailer(t *testing.T) {
	a := New(WithClock(testClock()))
	// register the node first so handleSubagentResult finds it.
	a.registry[tu1] = &node{toolUseID: tu1, spawnSeen: true, taskStartedSeen: true, taskID: task1}

	block := &contentBlock{
		Type:      "tool_result",
		ToolUseID: tu1,
		IsError:   false,
		Content:   []byte(`[{"type":"text","text":"ACORN"},{"type":"text","text":"agentId: ` + task1 + ` (use SendMessage with to: '` + task1 + `' to continue this agent)\n<usage>subagent_tokens: 964\ntool_uses: 2\nduration_ms: 1134</usage>"}]`),
	}
	rec := &userRecord{UUID: "u9", ParentToolUseID: ""}
	evs, err := a.handleSubagentResult(block, rec)
	if err != nil {
		t.Fatalf("handleSubagentResult error: %v", err)
	}
	if len(evs) != 1 || evs[0].Type != attach.TypeSubagentAccounted {
		t.Fatalf("got %v, want one subagent.accounted", evs)
	}
	acct := evs[0].SubagentAccounted
	if acct.NodeID != tu1 {
		t.Errorf("node_id = %q, want %q", acct.NodeID, tu1)
	}
	if acct.AgentID != task1 {
		t.Errorf("agent_id = %q, want %q (trailer agentId line)", acct.AgentID, task1)
	}
	if acct.SubagentTokens != 964 || acct.ToolUses != 2 || acct.DurationMS != 1134 {
		t.Errorf("accounting numbers mismapped: tokens=%d tools=%d dur=%d", acct.SubagentTokens, acct.ToolUses, acct.DurationMS)
	}
	if acct.OutputExcerpt != "ACORN" {
		t.Errorf("output_excerpt = %q, want first text block ACORN", acct.OutputExcerpt)
	}
	if acct.ReturnedTo != "" {
		t.Errorf("returned_to = %q, want empty (root return)", acct.ReturnedTo)
	}
	if acct.Continuation == nil || acct.Continuation.AgentID != task1 || acct.Continuation.Hint != "SendMessage" {
		t.Errorf("continuation = %+v, want {agent_id:%s, hint:SendMessage}", acct.Continuation, task1)
	}
	if len(a.Warnings()) != 0 {
		t.Errorf("clean accounting warned: %v", a.Warnings())
	}
}

// TestAccountedIntegrityWarnOnAgentIDMismatch asserts the agentId != task_id
// integrity check produces a warning (not an error).
func TestAccountedIntegrityWarnOnAgentIDMismatch(t *testing.T) {
	a := New(WithClock(testClock()))
	a.registry[tu1] = &node{toolUseID: tu1, spawnSeen: true, taskStartedSeen: true, taskID: task1}

	block := &contentBlock{
		Type:      "tool_result",
		ToolUseID: tu1,
		Content:   []byte(`[{"type":"text","text":"OUT"},{"type":"text","text":"agentId: ` + task2 + `\n<usage>subagent_tokens: 1\ntool_uses: 0\nduration_ms: 5</usage>"}]`),
	}
	evs, err := a.handleSubagentResult(block, &userRecord{UUID: "u9"})
	if err != nil {
		t.Fatalf("handleSubagentResult error: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("want one accounted event, got %d", len(evs))
	}
	w := a.Warnings()
	if len(w) != 1 {
		t.Fatalf("want exactly 1 integrity warning, got %v", w)
	}
	if !contains(w[0], "integrity") || !contains(w[0], task1) || !contains(w[0], task2) {
		t.Errorf("integrity warning text unexpected: %q", w[0])
	}
}

// TestAccountedParentCorroborationWarn asserts a return-target disagreement
// warns but keeps the spawn-line parent value (§2 rule 2).
func TestAccountedParentCorroborationWarn(t *testing.T) {
	a := New(WithClock(testClock()))
	a.registry[tu1] = &node{toolUseID: tu1, spawnSeen: true, taskStartedSeen: true, taskID: task1, parentNode: tu2}

	block := &contentBlock{
		Type:      "tool_result",
		ToolUseID: tu1,
		Content:   []byte(`[{"type":"text","text":"OUT"},{"type":"text","text":"agentId: ` + task1 + `\n<usage>subagent_tokens: 1\ntool_uses: 0\nduration_ms: 5</usage>"}]`),
	}
	// result returns to root (parent="") but spawn-line says parent=tu2.
	_, err := a.handleSubagentResult(block, &userRecord{UUID: "u9", ParentToolUseID: ""})
	if err != nil {
		t.Fatalf("handleSubagentResult error: %v", err)
	}
	w := a.Warnings()
	if len(w) != 1 || !contains(w[0], "corroboration") {
		t.Fatalf("want one parent-corroboration warning, got %v", w)
	}
}

// TestAccountedUnregisteredNodeWarns asserts a tool_result for a node never
// spawned/started warns but still emits accounting (id-keyed, position-blind).
func TestAccountedUnregisteredNodeWarns(t *testing.T) {
	a := New(WithClock(testClock()))
	block := &contentBlock{
		Type:      "tool_result",
		ToolUseID: tu1,
		Content:   []byte(`[{"type":"text","text":"OUT"},{"type":"text","text":"agentId: ` + task1 + `\n<usage>subagent_tokens: 1\ntool_uses: 0\nduration_ms: 5</usage>"}]`),
	}
	evs, _ := a.handleSubagentResult(block, &userRecord{UUID: "u9"})
	if len(evs) != 1 {
		t.Fatalf("want one accounted event for unregistered node, got %d", len(evs))
	}
	if w := a.Warnings(); len(w) != 1 || !contains(w[0], "unregistered") {
		t.Errorf("want one unregistered-node warning, got %v", w)
	}
}

// TestAccountedIsErrorBareString asserts an is_error result (bare-string body,
// no trailer) still emits accounting with is_error set and zero accounting.
func TestAccountedIsErrorBareString(t *testing.T) {
	a := New(WithClock(testClock()))
	a.registry[tu1] = &node{toolUseID: tu1, spawnSeen: true, taskStartedSeen: true, taskID: task1}
	block := &contentBlock{
		Type:      "tool_result",
		ToolUseID: tu1,
		IsError:   true,
		Content:   []byte(`"the subagent failed before producing a trailer"`),
	}
	evs, _ := a.handleSubagentResult(block, &userRecord{UUID: "u9"})
	if len(evs) != 1 {
		t.Fatalf("want one accounted event, got %d", len(evs))
	}
	acct := evs[0].SubagentAccounted
	if !acct.IsError {
		t.Error("is_error not propagated to accounting")
	}
	if acct.SubagentTokens != 0 || acct.Continuation != nil {
		t.Errorf("bare-string error must carry no trailer accounting: %+v", acct)
	}
	if acct.OutputExcerpt != "the subagent failed before producing a trailer" {
		t.Errorf("output_excerpt = %q, want the bare string", acct.OutputExcerpt)
	}
}

// TestFanoutCorrelateByIDNotPosition asserts that three parallel spawns in one
// turn (one message.id) correlate progress/completed/accounted by id even when
// completions arrive in REVERSE spawn order (P1/P10).
func TestFanoutCorrelateByIDNotPosition(t *testing.T) {
	a := New(WithClock(testClock()))
	// 3 spawns sharing one message.id (P1: one logical turn, N stream lines).
	feedAll(t, a,
		spawnLine("s1", "fan", tu1, "", "echoer", "d1", "p1"),
		spawnLine("s2", "fan", tu2, "", "echoer", "d2", "p2"),
		spawnLine("s3", "fan", tu3, "", "echoer", "d3", "p3"),
		taskStartedLine("t1", tu1, task1, "echoer", "d1", "p1"),
		taskStartedLine("t2", tu2, task2, "echoer", "d2", "p2"),
		taskStartedLine("t3", tu3, task3, "echoer", "d3", "p3"),
	)
	// completions arrive in REVERSE order: 3, 2, 1.
	evs := feedAll(t, a,
		taskNotificationLine("n3", tu3, task3, "completed", "s3 done"),
		resultLine("r3", tu3, "", "OUT3", task3, 30, 3, 300),
		taskNotificationLine("n1", tu1, task1, "completed", "s1 done"),
		resultLine("r1", tu1, "", "OUT1", task1, 10, 1, 100),
		taskNotificationLine("n2", tu2, task2, "completed", "s2 done"),
		resultLine("r2", tu2, "", "OUT2", task2, 20, 2, 200),
	)

	// completed correlate by id, never by spawn position.
	wantSummary := map[string]string{tu3: "s3 done", tu1: "s1 done", tu2: "s2 done"}
	for _, ev := range onlyOfType(evs, attach.TypeSubagentCompleted) {
		c := ev.SubagentCompleted
		if wantSummary[c.NodeID] != c.Summary {
			t.Errorf("completed node %q summary = %q, want %q", c.NodeID, c.Summary, wantSummary[c.NodeID])
		}
	}
	// accounted correlate by id: tokens must match each node's own result.
	wantTokens := map[string]int64{tu1: 10, tu2: 20, tu3: 30}
	for _, ev := range onlyOfType(evs, attach.TypeSubagentAccounted) {
		acct := ev.SubagentAccounted
		if acct.SubagentTokens != wantTokens[acct.NodeID] {
			t.Errorf("accounted node %q tokens = %d, want %d (correlate by id, not position)", acct.NodeID, acct.SubagentTokens, wantTokens[acct.NodeID])
		}
	}
	if len(a.Warnings()) != 0 {
		t.Errorf("clean fan-out warned: %v", a.Warnings())
	}
}

// TestUnknownSubagentTypeWarns asserts a subagent_type not in the init
// allowlist warns (not errors) once init has been seen.
func TestUnknownSubagentTypeWarns(t *testing.T) {
	a := New(WithClock(testClock()))
	feedAll(t, a, initLine) // seeds agentTypes {claude, echoer}
	evs := feedAll(t, a,
		spawnLine("u1", "msg1", tu1, "", "ghost", "scan", "do it"),
		taskStartedLine("u2", tu1, task1, "ghost", "scan", "do it"),
	)
	if got := onlyOfType(evs, attach.TypeSubagentSpawned); len(got) != 1 {
		t.Fatalf("unknown subagent_type must still spawn, got %d", len(got))
	}
	w := a.Warnings()
	if len(w) != 1 || !contains(w[0], "allowlist") || !contains(w[0], "ghost") {
		t.Errorf("want one allowlist warning naming ghost, got %v", w)
	}
}

// TestProgressEmitsForTaskFirstNode asserts a task_progress for a node
// registered task-first still emits (id-keyed liveness).
func TestProgressEmitsForTaskFirstNode(t *testing.T) {
	a := New(WithClock(testClock()))
	evs := feedAll(t, a,
		taskStartedLine("u1", tu1, task1, "echoer", "scan", "p"),
		taskProgressLine("u2", tu1, task1, "Read", `{}`),
	)
	if got := onlyOfType(evs, attach.TypeSubagentProgress); len(got) != 1 {
		t.Fatalf("got %d progress, want 1", len(got))
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
