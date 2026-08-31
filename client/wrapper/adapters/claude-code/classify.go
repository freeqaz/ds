// classify.go — owned by impl-classify: P14 name+input tool classification,
// chat/tool events, partial/stream_event handling, isReplay ACK skip.
//
// Classification is by NAME + INPUT only (P14): the tool_use block key set is
// identical across mcp/agent/skill/native ({type,id,name,input,caller},
// caller=={type:"direct"}), so block keys and caller.type carry no signal.
// stream_event records are a render channel only (P11): consumed, never a
// source of canonical events — the non-partial assistant/user records are
// authoritative.
package claudecode

import (
	"encoding/json"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Subagent-spawn tool names (P14/PROTOCOL-NOTES): the model sees the Task tool
// as Agent; weaker models misfire Task→TaskCreate. The discriminator beyond
// the name is input.subagent_type — a bare Task/TaskCreate without it is the
// todo-list tool, not a spawn.
var spawnToolNames = map[string]struct{}{
	"Agent":      {},
	"Task":       {},
	"TaskCreate": {},
}

// IsSpawnToolUse is the SINGLE, exported spawn-discriminator: a tool_use block
// is a subagent spawn iff its name is in spawnToolNames AND its
// input.subagent_type is non-empty (P14 — a bare Task/TaskCreate without a
// subagent_type is the todo-list tool, not a spawn). This is the EXACT predicate
// handleToolUse routes registerSpawn on; it is exported so the completeness
// machinery that classifies a cassette as "spawn-path" does not re-implement the
// discriminator verbatim and risk drifting from the routing rule. The read side
// (goldentrace replay/spawn_scenarios.go lineHasSpawnBlock) calls it across the
// legal goldentrace→adapter import edge; the write-side completeness check
// (spawn_scenarios_test.go lineHasSpawnBlockCC, in-package) calls it directly.
// Per-package mirroring is still required ONLY for the fixture TABLE (that cycle
// is uncrossable, see spawn_scenarios.go); the CLASSIFIER itself is single-sourced
// here.
func IsSpawnToolUse(name string, input json.RawMessage) bool {
	if strings.HasPrefix(name, "mcp__") {
		// mcp__ names never carry a bare spawn name (no "__" in the spawn names),
		// but guard explicitly so the predicate matches handleToolUse's order.
		return false
	}
	if _, ok := spawnToolNames[name]; !ok {
		return false
	}
	return subagentType(input) != ""
}

// handleAssistant projects one assistant stream line. text/thinking blocks ⇒
// one ChatMessage (consumers merge by message_id, P11). tool_use blocks are
// classified by NAME in order (P14): ^mcp__ (split on "__", ≥3 parts) ⇒ mcp;
// name ∈ {Agent,Task,TaskCreate} with input.subagent_type ⇒ subagent (delegate
// to registerSpawn); name == "Skill" ⇒ skill; else native ⇒ ToolInvoked.
// Subagent spawns are SubagentSpawned, never ToolInvoked.
func (a *Adapter) handleAssistant(rec *assistantRecord) ([]attach.Event, error) {
	var events []attach.Event

	chatBlocks, blocks := a.collectChatBlocks(rec.Message.Content)
	if len(chatBlocks) > 0 {
		events = append(events, a.emit(attach.Event{
			Type: attach.TypeChatMessage,
			ChatMessage: &attach.ChatMessage{
				MessageID:    rec.Message.ID,
				Role:         messageRole(rec.Message.Role),
				ParentNodeID: rec.ParentToolUseID,
				Blocks:       chatBlocks,
			},
		}, rec.UUID))
	}

	for _, block := range blocks {
		evs, err := a.handleToolUse(block, rec)
		if err != nil {
			return events, err
		}
		events = append(events, evs...)
	}
	return events, nil
}

// collectChatBlocks splits a message's content into the text/thinking blocks
// (merged into one ChatMessage) and the tool_use blocks (classified one by
// one). Only text/thinking blocks with content become chat blocks.
func (a *Adapter) collectChatBlocks(content []contentBlock) ([]attach.ChatBlock, []*contentBlock) {
	var chat []attach.ChatBlock
	var tools []*contentBlock
	for i := range content {
		block := &content[i]
		switch block.Type {
		case "text":
			if block.Text != "" {
				chat = append(chat, attach.ChatBlock{Kind: "text", Text: block.Text})
			}
		case "thinking":
			if block.Thinking != "" {
				chat = append(chat, attach.ChatBlock{Kind: "thinking", Text: block.Thinking})
			}
		case "tool_use":
			tools = append(tools, block)
		}
	}
	return chat, tools
}

// handleToolUse classifies one tool_use block (P14) and projects it. A
// subagent spawn delegates to the tree hook (registerSpawn → SubagentSpawned),
// never ToolInvoked; everything else is a ToolInvoked with its kind decomposed.
func (a *Adapter) handleToolUse(block *contentBlock, rec *assistantRecord) ([]attach.Event, error) {
	name := block.Name

	// Subagent spawn: name in {Agent,Task,TaskCreate} AND input.subagent_type
	// present. A bare Task without subagent_type is the todo-list tool — fall
	// through to native classification. mcp__ names never reach this branch
	// (no "__" in the spawn names), so the order of these two checks is
	// independent, but P14 fixes mcp first. The discriminator is single-sourced
	// in IsSpawnToolUse, which the completeness checks (read + write side) also
	// consume — so the routing rule and the spawn-path classifier cannot drift.
	if IsSpawnToolUse(name, block.Input) {
		return a.registerSpawn(block, rec)
	}

	// Plan delta: a TodoWrite tool-use is the full-list todo-plan snapshot
	// (§6.1 row 6 plan half, PROTOCOL-NOTES "Plan-delta / TodoWrite"), NOT a
	// generic ToolInvoked. It carries input.todos[] (a bare Task/TaskCreate
	// without subagent_type already fell through the spawn check above; the
	// TodoWrite name is the unambiguous discriminator for the canvas plan card).
	// Emit a first-class PlanDelta carrying the todo-list snapshot so the
	// writer-seat surface renders the plan/todo card instead of an opaque tool.
	if name == "TodoWrite" {
		return []attach.Event{a.emit(attach.Event{
			Type: attach.TypePlanDelta,
			PlanDelta: &attach.PlanDelta{
				NodeID: block.ID,
				Kind:   attach.PlanDeltaKindTodoWrite,
				Todos:  todoItems(block.Input),
			},
		}, rec.UUID)}, nil
	}

	inv := &attach.ToolInvoked{
		NodeID:       block.ID,
		Name:         name,
		ParentNodeID: rec.ParentToolUseID,
		TurnGroup:    rec.Message.ID,
		Input:        nonEmptyRaw(block.Input),
	}
	switch {
	case strings.HasPrefix(name, "mcp__"):
		// Split on "__" (double underscore), NOT single (tool names contain
		// single underscores, e.g. complete_authentication). server = part 1,
		// tool = join of the rest (P14).
		inv.Kind = "mcp"
		inv.Server, inv.Tool = decomposeMCP(name)
	case name == "Skill":
		inv.Kind = "skill"
		inv.Skill = skillName(block.Input)
		if inv.Skill != "" {
			if _, ok := a.skills[inv.Skill]; !ok {
				a.warnf("skill %q not in init.skills[] allowlist (uuid %s)", inv.Skill, rec.UUID)
			}
		}
	default:
		inv.Kind = "native"
	}
	return []attach.Event{a.emit(attach.Event{Type: attach.TypeToolInvoked, ToolInvoked: inv}, rec.UUID)}, nil
}

// handleUser projects one user stream line. isReplay:true ⇒ ACK marker, skip
// entirely (P4). tool_result blocks route to handleSubagentResult when the id
// is a registered subagent node, else emit ToolCompleted (is_error content is
// a BARE STRING; tool_reference hops are tolerated, never emitted) and call
// resolveFromToolResult for any open ask. Nested-prompt text records
// (parent_tool_use_id set, no tool_result) feed the tree's prompt_excerpt
// corroboration — no standalone event.
func (a *Adapter) handleUser(rec *userRecord) ([]attach.Event, error) {
	if rec.IsReplay {
		// Echoed/acked input, not a node in the spawn tree (P4): skip.
		return nil, nil
	}

	var events []attach.Event
	sawToolResult := false
	for i := range rec.Message.Content {
		block := &rec.Message.Content[i]
		if block.Type != "tool_result" {
			continue
		}
		sawToolResult = true

		// The ToolSearch deferred-tool hop (a tool_result whose content
		// carries subtype tool_reference {tool_name}) is NOT suppressed: it
		// takes the normal non-subagent completion path. "Tolerate a ToolSearch
		// hop" (P14) means don't crash or misclassify it, not drop it — the
		// binding checklist (checklists/mcp-skill-native.md item 5) requires the
		// invoked ToolSearch node to pair with a tool.completed (is_error:false,
		// output_excerpt = the tool_reference body), so the node is never left
		// invoked-without-completed.
		evs, err := a.handleToolResult(block, rec)
		if err != nil {
			return events, err
		}
		events = append(events, evs...)
	}

	// A non-replay user record with no tool_result and a set parent_tool_use_id
	// is a nested subagent prompt (the parent model's prompt into the subagent,
	// P1 parent→child PROMPT linkage): consumed for the tree's prompt_excerpt
	// corroboration, no standalone event (spec classify.go row). The spawn block
	// and task_started normally carry the prompt, so this only backfills the
	// missed-spawn / local_bash case where neither did — keep-spawn-line-on-
	// disagreement, never overwrite an already-corroborated prompt.
	if !sawToolResult && rec.ParentToolUseID != "" {
		a.corroborateNestedPrompt(rec.ParentToolUseID, nestedPromptText(rec.Message.Content))
	}
	return events, nil
}

// corroborateNestedPrompt feeds a nested-prompt user record's text into the
// parent node's prompt_excerpt when that field is still empty (the spawn block
// / task_started prompt is authoritative and never overwritten). No standalone
// event is emitted; this is corroboration only (spec classify.go row; §2 keep-
// the-authoritative-value-on-disagreement).
func (a *Adapter) corroborateNestedPrompt(parentNodeID, text string) {
	if text == "" {
		return
	}
	n, ok := a.registry[parentNodeID]
	if !ok {
		return
	}
	if n.promptExcerpt == "" {
		n.promptExcerpt = excerpt(text)
	}
}

// nestedPromptText returns the first text block of a nested-prompt user record
// (the prompt the parent sent into the subagent), or "" if none.
func nestedPromptText(content []contentBlock) string {
	for i := range content {
		if content[i].Type == "text" && content[i].Text != "" {
			return content[i].Text
		}
	}
	return ""
}

// handleToolResult routes one tool_result block. A registered subagent node ⇒
// the tree's SubagentAccounted projection. Otherwise ⇒ ToolCompleted plus an
// ask-resolution fallback (resolveFromToolResult): is_error:true tool_result
// content is a BARE STRING (P13), carried as the denial/error message verbatim.
func (a *Adapter) handleToolResult(block *contentBlock, rec *userRecord) ([]attach.Event, error) {
	if _, ok := a.registry[block.ToolUseID]; ok {
		return a.handleSubagentResult(block, rec)
	}

	// is_error content is a bare string (P13); success content is a block
	// array — extract the first text block. Either way the body becomes the
	// output_excerpt: the bare-string error body IS this completion's output
	// (the binding denial checklists — checklists/denial-headless.md item 4,
	// checklists/ask-control.md item 10 — require output_excerpt = the same
	// bare string the denial_message carries).
	var output string
	if block.IsError {
		output = bareStringContent(block.Content)
	} else {
		output = firstTextBlock(block.Content)
	}

	completed := &attach.ToolCompleted{
		NodeID:        block.ToolUseID,
		IsError:       block.IsError,
		OutputExcerpt: excerpt(output),
	}
	// A permission denial is an is_error:true tool_result whose bare-string
	// body is the denial message (P13/P8). Surface it as denial_message so a
	// headless auto-deny (which has NO ask, P8) is still visible.
	//
	// EXCEPTION — granted-then-failed: if the open ask for this node was
	// answered ALLOW on the control wire (askGrantedAllow), an is_error here is
	// the granted tool erroring AT RUNTIME, not a permission block. The grant
	// stands, so this is a plain tool failure (IsError set, output_excerpt
	// carries the runtime error) and must NOT be tagged as a denial — tagging it
	// would render a permitted-but-failed tool as denied, conflating the two
	// states the ask layer now keeps distinct (gap-3). Only a true block (no
	// allow-grant) sets denial_message.
	if block.IsError && !a.askGrantedAllow(block.ToolUseID) {
		completed.DenialMessage = output
	}
	events := []attach.Event{a.emit(attach.Event{Type: attach.TypeToolCompleted, ToolCompleted: completed}, rec.UUID)}

	// Ask-resolution fallback: resolve any open ask correlated by tool_use_id
	// (no open ask ⇒ no event; never invents an ask). On is_error the bare-string
	// body (now in output) is the deny message, propagated verbatim (P8/P13).
	// ask.go owns the policy.
	resolved, err := a.resolveFromToolResult(block.ToolUseID, block.IsError, output, rec.UUID)
	if err != nil {
		return events, err
	}
	events = append(events, resolved...)
	return events, nil
}

// WithPartials opts the adapter into projecting the runtime's typing deltas as
// render-only attach.ChatDelta events (doc serpent-cli-mvp/06 Layer 1, D145,
// P11). It is default-OFF, mirroring WithClock's opt-in shape: without it
// handleStreamEvent stays the historical no-op drop, so the DEFAULT build is
// byte-identical and a consumer that never asks for live text pays nothing.
//
// The deltas it emits are strictly NON-CANONICAL: dropping every ChatDelta
// leaves the canonical projection (sourced from the authoritative non-partial
// ChatMessage, P11) byte-identical — that is the render-only regression guard.
// Arming --include-partial-messages on the runtime launch is a SEPARATE
// host-agent leg (the EntrypointConfig.LaunchSpec); this Option only governs
// whether the adapter renders the partials it already receives.
//
// The per-message partial cursor (a.partials/a.curMsgID/a.curParent/a.blockKind)
// lives directly on the Adapter struct (adapter.go), GC'd with the adapter like
// the rest of its per-stream state. classify.go owns the projection that reads
// and writes those fields; setting the latch here mirrors WithClock.
func WithPartials() Option {
	return func(a *Adapter) { a.partials = true }
}

// handleStreamEvent consumes a partial-message record. Default (WithPartials
// off): render channel ONLY (P11) — no emission, the non-partial assistant/user
// records stay authoritative, exactly the historical drop.
//
// With WithPartials it projects the typing deltas as render-only attach.ChatDelta
// events: one coalesced ChatDelta per content_block_delta for kind ∈
// {text,thinking}, plus a final ChatDelta on content_block_stop. input_json_delta
// is dropped from the typing view (it is tool-input assembly, JSON-parsed only at
// content_block_stop — never streamed as text, P11/R4). These deltas are
// strictly non-canonical: a consumer that drops them folds the identical
// canonical state from the ChatMessage that finalizes the same message_id.
func (a *Adapter) handleStreamEvent(rec *streamEventRecord) ([]attach.Event, error) {
	if !a.partials {
		// Deliberately no emission (P11): partials are a duplicate for live
		// rendering. Tolerated and dropped (the historical default). The default
		// path touches no cursor state and allocates no map, so the byte-identical
		// default build pays nothing.
		return nil, nil
	}

	switch rec.Event.Type {
	case "message_start":
		// New message: reset the per-message index space (P10) and capture the
		// message id + parent threading the deltas join on.
		a.curMsgID = streamMessageID(rec.Event.Message)
		a.curParent = rec.ParentToolUseID
		a.blockKind = make(map[int]string)
		return nil, nil
	case "content_block_start":
		if a.blockKind == nil {
			// A content_block_start before any message_start (malformed stream):
			// lazily seed the index map so the kind is still recorded.
			a.blockKind = make(map[int]string)
		}
		a.blockKind[rec.Event.Index] = contentBlockKind(rec.Event.ContentBlock)
		return nil, nil
	case "content_block_delta":
		kind := a.blockKind[rec.Event.Index]
		if kind != "text" && kind != "thinking" {
			// input_json_delta and friends are tool-input assembly, never typing
			// text (P11/R4): dropped from the live view.
			return nil, nil
		}
		text := streamDeltaText(rec.Event.Delta, kind)
		if text == "" {
			// An empty priming/coalesced delta carries no typing text — skip it so
			// the live tail never flickers an empty block.
			return nil, nil
		}
		return []attach.Event{a.emit(attach.Event{
			Type: attach.TypeChatDelta,
			ChatDelta: &attach.ChatDelta{
				MessageID:    a.curMsgID,
				ParentNodeID: a.curParent,
				BlockIndex:   int32(rec.Event.Index),
				Kind:         kind,
				Text:         text,
			},
		}, rec.UUID)}, nil
	case "content_block_stop":
		kind := a.blockKind[rec.Event.Index]
		if kind != "text" && kind != "thinking" {
			return nil, nil
		}
		return []attach.Event{a.emit(attach.Event{
			Type: attach.TypeChatDelta,
			ChatDelta: &attach.ChatDelta{
				MessageID:    a.curMsgID,
				ParentNodeID: a.curParent,
				BlockIndex:   int32(rec.Event.Index),
				Kind:         kind,
				Final:        true,
			},
		}, rec.UUID)}, nil
	}
	return nil, nil
}

// streamMessageID reads message.id out of a stream_event message_start payload
// (the raw Anthropic message object) without binding the rest of its shape. It
// is the join key the deltas carry to the finalizing ChatMessage (P11).
func streamMessageID(raw json.RawMessage) string {
	return rawStringField(raw, "id")
}

// contentBlockKind reads content_block.type out of a content_block_start payload
// — "text" | "thinking" | "tool_use" | … — so a content_block_delta knows whether
// it is typing text or assembling tool-input JSON (only the former two are
// rendered as typing, P11/R4). An absent/malformed block yields "".
func contentBlockKind(raw json.RawMessage) string {
	return rawStringField(raw, "type")
}

// streamDeltaText returns the typing text a content_block_delta carries for the
// given block kind: text_delta.text for a text block, thinking_delta.thinking for
// a thinking block. The streamDelta struct already decoded both fields
// (records.go); selecting by kind keeps an input_json_delta's partial_json out of
// the typing view (it is never text, P11/R4).
func streamDeltaText(d streamDelta, kind string) string {
	switch kind {
	case "thinking":
		return d.Thinking
	default: // "text"
		return d.Text
	}
}

// --- helpers (classification & content polymorphism) ---

// messageRole defaults an empty assistant role to "assistant" — assistant
// records carry role on the API message, but the chat event must always name a
// role.
func messageRole(role string) string {
	if role == "" {
		return "assistant"
	}
	return role
}

// decomposeMCP splits an mcp__<server>__<tool> name on the DOUBLE underscore
// (P14): server = the first segment after the mcp__ prefix, tool = the join of
// the rest (tool names contain single underscores, e.g.
// mcp__svc__complete_authentication ⇒ server "svc", tool
// "complete_authentication"). A malformed name (<3 parts) yields empty fields.
func decomposeMCP(name string) (server, tool string) {
	parts := strings.Split(name, "__")
	// parts[0] == "mcp"; need at least mcp, server, tool ⇒ ≥3 parts.
	if len(parts) < 3 {
		return "", ""
	}
	return parts[1], strings.Join(parts[2:], "__")
}

// subagentType reads input.subagent_type (the spawn discriminator, P14)
// without binding the rest of the spawn input shape.
func subagentType(input json.RawMessage) string {
	return rawStringField(input, "subagent_type")
}

// skillName reads input.skill (the Skill tool discriminator, P14).
func skillName(input json.RawMessage) string {
	return rawStringField(input, "skill")
}

// todoItems decodes a TodoWrite tool-use input.todos[] into the working-model
// snapshot (the §6.1 row-6 plan card). The CC wire shape is
// input:{todos:[{content, status, activeForm, id}]} — content+status are
// always present; activeForm (the present-tense in-progress label) and id are
// best-effort. Absent/malformed input yields nil (the plan delta still emits,
// carrying an empty list — an honest "plan cleared" snapshot, never a crash).
func todoItems(input json.RawMessage) []attach.TodoItem {
	if len(input) == 0 {
		return nil
	}
	var obj struct {
		Todos []struct {
			Content    string `json:"content"`
			Status     string `json:"status"`
			ActiveForm string `json:"activeForm"`
			ID         string `json:"id"`
		} `json:"todos"`
	}
	if err := json.Unmarshal(input, &obj); err != nil {
		return nil
	}
	if len(obj.Todos) == 0 {
		return nil
	}
	out := make([]attach.TodoItem, 0, len(obj.Todos))
	for _, t := range obj.Todos {
		out = append(out, attach.TodoItem{
			Content:    t.Content,
			Status:     t.Status,
			ActiveForm: t.ActiveForm,
			ID:         t.ID,
		})
	}
	return out
}

// rawStringField pulls a single string field out of a raw JSON object without
// committing to its full shape; absent/non-string ⇒ "".
func rawStringField(raw json.RawMessage, field string) string {
	if len(raw) == 0 {
		return ""
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	v, ok := obj[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		return ""
	}
	return s
}

// nonEmptyRaw returns the raw input only when it carries content, so an absent
// input stays omitempty rather than serializing as a bare "null".
func nonEmptyRaw(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

// bareStringContent reads an is_error:true tool_result content, which is a
// BARE STRING (P13). It tolerates the alternate array-of-text shape so a
// future array-bodied error still yields a message.
func bareStringContent(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	// Defensive: an error body that arrived as a text-block array.
	return firstTextBlock(raw)
}

// firstTextBlock reads the first text block of a success tool_result content
// array (P13). It tolerates a bare-string content too (returned verbatim).
func firstTextBlock(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "\"") {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return ""
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) != nil {
		return ""
	}
	for _, b := range blocks {
		if b.Type == "text" && b.Text != "" {
			return b.Text
		}
	}
	return ""
}
