// tree.go — owned by impl-tree: the subagent registry, the three-key join
// (tool_use_id, task_id/agentId, message.id), and the spawned/progress/
// completed/accounted projection (OBSERVABILITY-DESIGN §1/§2, PHASE2 P1/P2,
// PHASE3 P10). Correlation is by id only, never by stream position (P1/P10):
// spawn-side records interleave in spawn order, completions arrive in
// completion order. parent_tool_use_id flattens to depth 1 (P2), so the spawn
// line itself is the only reliable parentage write.
package claudecode

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// node is one subagent-registry entry, keyed by tool-use id in
// Adapter.registry. The spawn block and system/task_started halves may arrive
// in either order; spawnedEmitted guards the once-per-node SubagentSpawned
// (provisional on the first half, finalized on the join). Parent attribution
// is set from the spawn line's parent_tool_use_id (P2); depth ≥3 downgrades
// confidence to "inferred" (OBSERVABILITY-DESIGN §2).
type node struct {
	toolUseID string // primary key — links spawn block ↔ task_* ↔ tool_result

	// spawn-block half (assistant Agent tool_use)
	spawnSeen        bool
	subagentType     string
	description      string
	promptExcerpt    string
	turnGroup        string // spawn line message.id — groups fan-out siblings (P1)
	parentNode       string // spawn-line parent_tool_use_id; "" ⇒ child of root
	parentConfidence string

	// task_started half (system/task_started)
	taskStartedSeen bool
	taskID          string
	taskType        string

	spawnedEmitted bool // SubagentSpawned emitted once, on the join
}

// depthOf walks the spawn-line parent chain from n to root and returns the
// node's depth (root children are depth 1). The chain follows parentNode
// (a tool_use id) through the registry; an unknown ancestor terminates the
// walk (the missed-spawn case keeps the partial depth).
func (a *Adapter) depthOf(n *node) int {
	depth := 1
	parent := n.parentNode
	seen := map[string]struct{}{n.toolUseID: {}}
	for parent != "" {
		if _, loop := seen[parent]; loop {
			break // defensive: never trust the wire to be acyclic
		}
		seen[parent] = struct{}{}
		depth++
		pn, ok := a.registry[parent]
		if !ok {
			break
		}
		parent = pn.parentNode
	}
	return depth
}

// emitSpawned finalizes a node and emits SubagentSpawned exactly once, on the
// join of the spawn block and task_started (either arrival order). The depth
// rule downgrades confidence to "inferred" at depth ≥3 (OBSERVABILITY-DESIGN
// §2): the spawn line is tagged with the true parent's launching id at depth
// ≤2 (P2-verified) but is untested deeper. source is the uuid of the record
// that completed the join.
//
// Floor property (a one-directional threshold, not an equality on depth==3):
// confidence is "exact" for every depth ≤2 and "inferred" for every depth ≥3,
// with no upper bound — depth 4, 5, … stay "inferred". The threshold must not
// creep down to tag depth 2 as inferred, and a literal depth==3 check would be
// wrong (it would let depth-4 edges report "exact"). TestDepthConfidenceFloorTo4
// pins both failure modes at depths 2 and 4.
func (a *Adapter) emitSpawned(n *node, source string) []attach.Event {
	if n.spawnedEmitted || !n.spawnSeen || !n.taskStartedSeen {
		return nil
	}
	n.spawnedEmitted = true

	confidence := "exact"
	if a.depthOf(n) >= 3 {
		confidence = "inferred"
	}
	n.parentConfidence = confidence

	ev := a.emit(attach.Event{
		Type: attach.TypeSubagentSpawned,
		SubagentSpawned: &attach.SubagentSpawned{
			NodeID:           n.toolUseID,
			TaskID:           n.taskID,
			SubagentType:     n.subagentType,
			Description:      n.description,
			PromptExcerpt:    n.promptExcerpt,
			TaskType:         n.taskType,
			ParentNodeID:     n.parentNode,
			ParentConfidence: confidence,
			TurnGroup:        n.turnGroup,
		},
	}, source)
	return []attach.Event{ev}
}

// registerSpawn joins an Agent/Task spawn tool_use block (routed here by
// classify after name+input classification, P14) into the registry. Parentage
// comes from the spawn line's parent_tool_use_id — the one reliably-written
// edge (P2/§2). An unknown subagent_type against the init allowlist is a
// warning, not an error. SubagentSpawned fires here only when the task_started
// half already arrived.
func (a *Adapter) registerSpawn(block *contentBlock, rec *assistantRecord) ([]attach.Event, error) {
	id := block.ID
	if id == "" {
		a.warnf("subagent spawn block with empty tool_use id (uuid %s): skipped", rec.UUID)
		return nil, nil
	}

	var in struct {
		Description  string `json:"description"`
		SubagentType string `json:"subagent_type"`
		Prompt       string `json:"prompt"`
	}
	if len(block.Input) > 0 {
		_ = json.Unmarshal(block.Input, &in)
	}

	if in.SubagentType != "" {
		if _, ok := a.agentTypes[in.SubagentType]; !ok && a.initSeen {
			a.warnf("subagent_type %q not in init.agents[] allowlist (node %s)", in.SubagentType, id)
		}
	}

	n := a.registry[id]
	if n == nil {
		n = &node{toolUseID: id}
		a.registry[id] = n
	}
	n.spawnSeen = true
	n.subagentType = in.SubagentType
	n.description = in.Description
	if in.Prompt != "" {
		n.promptExcerpt = excerpt(in.Prompt)
	}
	n.turnGroup = rec.Message.ID
	// parent_tool_use_id of the assistant line carrying the spawn block —
	// null ⇒ child of root (P2/§2). Never sourced from task_started (always
	// null there).
	n.parentNode = rec.ParentToolUseID

	return a.emitSpawned(n, rec.UUID), nil
}

// handleTaskStarted joins system/task_started into the registry (provisional
// on first arrival, finalized on join with the spawn block — either order),
// opens the task in Adapter.openTasks (the state area reads it for WORKING),
// and emits SubagentSpawned on the join. task_* records always carry a null
// parent_tool_use_id, so parentage is never taken from here (P1/§2).
func (a *Adapter) handleTaskStarted(rec *taskStartedRecord) ([]attach.Event, error) {
	id := rec.ToolUseID
	if id == "" {
		a.warnf("task_started with empty tool_use_id (task %s, uuid %s): skipped", rec.TaskID, rec.UUID)
		return nil, nil
	}

	n := a.registry[id]
	if n == nil {
		n = &node{toolUseID: id}
		a.registry[id] = n
	}
	n.taskStartedSeen = true
	n.taskID = rec.TaskID
	n.taskType = rec.TaskType
	// task_started carries its own description/subagent_type/prompt for the
	// local_agent variant; use them to corroborate / backfill a half-missed
	// spawn block (P9: local_bash omits these keys).
	if n.subagentType == "" {
		n.subagentType = rec.SubagentType
	}
	if n.description == "" {
		n.description = rec.Description
	}
	if n.promptExcerpt == "" && rec.Prompt != "" {
		n.promptExcerpt = excerpt(rec.Prompt)
	}

	// Open the task for the state latch; closed on task_notification.
	if rec.TaskID != "" {
		a.openTasks[rec.TaskID] = struct{}{}
	}

	// An open task is itself a WORKING signal (P9): when no status=="requesting"
	// ping has latched the loop, the opening task_started drives ATTACHED→WORKING
	// (reason "task_open"). The transition is emitted before SubagentSpawned so
	// the latch flips at the moment the first task opens (state.go owns the latch;
	// this is the documented tree→state seam — openTasks is the shared input).
	var events []attach.Event
	events = append(events, a.setWorking(true, "task_open", rec.UUID)...)
	events = append(events, a.emitSpawned(n, rec.UUID)...)
	return events, nil
}

// handleTaskProgress emits SubagentProgress 1:1 (OBSERVABILITY-DESIGN §1):
// last_tool_name is the only liveness peek into a subagent's inner work, and
// usage is a verbatim passthrough flagged uncharacterized — never rendered as
// token burn (§4). Correlate by id; a progress for an unknown node still
// emits (the node may have been registered task-first).
func (a *Adapter) handleTaskProgress(rec *taskProgressRecord) ([]attach.Event, error) {
	id := rec.ToolUseID
	if id == "" {
		a.warnf("task_progress with empty tool_use_id (task %s, uuid %s): skipped", rec.TaskID, rec.UUID)
		return nil, nil
	}

	ev := a.emit(attach.Event{
		Type: attach.TypeSubagentProgress,
		SubagentProgress: &attach.SubagentProgress{
			NodeID:          id,
			TaskID:          rec.TaskID,
			LastToolName:    rec.LastToolName,
			UsageRaw:        rec.Usage,
			Uncharacterized: true,
		},
	}, rec.UUID)
	return []attach.Event{ev}, nil
}

// handleTaskNotification emits SubagentCompleted 1:1 (OBSERVABILITY-DESIGN §1)
// and closes the task in Adapter.openTasks. Notifications arrive in completion
// order — correlate by id, NEVER position (P1/P10). status/summary/output_file
// pass through verbatim (vocabulary unenumerated, P9). Tokens are NOT sourced
// here: task_notification.usage.subagent_tokens is observed null (P1) — they
// arrive separately on SubagentAccounted from the result trailer.
func (a *Adapter) handleTaskNotification(rec *taskNotificationRecord) ([]attach.Event, error) {
	id := rec.ToolUseID
	if id == "" {
		a.warnf("task_notification with empty tool_use_id (task %s, uuid %s): skipped", rec.TaskID, rec.UUID)
		return nil, nil
	}

	if rec.TaskID != "" {
		delete(a.openTasks, rec.TaskID)
	}

	ev := a.emit(attach.Event{
		Type: attach.TypeSubagentCompleted,
		SubagentCompleted: &attach.SubagentCompleted{
			NodeID:     id,
			TaskID:     rec.TaskID,
			Status:     rec.Status,
			Summary:    rec.Summary,
			OutputFile: rec.OutputFile,
		},
	}, rec.UUID)
	return []attach.Event{ev}, nil
}

// handleSubagentResult projects a registered node's tool_result (routed here
// by classify) into SubagentAccounted (OBSERVABILITY-DESIGN §1) — the
// authoritative per-subagent accounting, arriving in completion order possibly
// long after completed. It parses the result content's <usage> trailer
// (agentId: line; subagent_tokens/tool_uses/duration_ms), asserts agentId ==
// task_id as an integrity check (warning on mismatch), and corroborates parent
// via the return target (the result line's parent_tool_use_id = the level it
// returns to), keeping the spawn-line value on disagreement (§2 rule 2).
func (a *Adapter) handleSubagentResult(block *contentBlock, rec *userRecord) ([]attach.Event, error) {
	id := block.ToolUseID
	n := a.registry[id]

	outputExcerpt, trailer := parseResultContent(block.Content)
	acct := &attach.SubagentAccounted{
		NodeID:         id,
		AgentID:        trailer.agentID,
		SubagentTokens: trailer.subagentTokens,
		ToolUses:       trailer.toolUses,
		DurationMS:     trailer.durationMS,
		OutputExcerpt:  excerpt(outputExcerpt),
		IsError:        block.IsError,
	}

	// returned_to is the result line's top-level parent_tool_use_id (the level
	// it returns to; null = root) — parent corroboration, never the primary
	// join (§2 / OBSERVABILITY-DESIGN §1).
	acct.ReturnedTo = rec.ParentToolUseID

	if trailer.agentID != "" {
		acct.Continuation = &attach.Continuation{AgentID: trailer.agentID, Hint: "SendMessage"}
	}

	if n != nil {
		// Integrity check: agentId in the trailer must equal the node's
		// task_id (same hex, P1/§1).
		if trailer.agentID != "" && n.taskID != "" && trailer.agentID != n.taskID {
			a.warnf("subagent accounting integrity: node %s agentId %q != task_id %q", id, trailer.agentID, n.taskID)
		}
		// Return-target corroboration: disagreement with the spawn-line parent
		// is flagged; the spawn-line value is authoritative and kept (§2 rule
		// 2). Both empty (root) agree silently.
		if n.spawnSeen && acct.ReturnedTo != n.parentNode {
			a.warnf("subagent parent corroboration: node %s spawn-line parent %q != return target %q (keeping spawn-line value)", id, n.parentNode, acct.ReturnedTo)
		}
	} else {
		a.warnf("subagent accounting for unregistered node %s (uuid %s): no spawn/task_started seen", id, rec.UUID)
	}

	ev := a.emit(attach.Event{
		Type:              attach.TypeSubagentAccounted,
		SubagentAccounted: acct,
	}, rec.UUID)
	return []attach.Event{ev}, nil
}

// resultTrailer holds the parsed <usage> metadata block of a subagent's
// tool_result (PROTOCOL-NOTES "subagent sub-protocol" §3).
type resultTrailer struct {
	agentID        string
	subagentTokens int64
	toolUses       int64
	durationMS     int64
}

// parseResultContent splits a subagent tool_result's content into its output
// excerpt (the first text block) and its accounting trailer (the second text
// block: an `agentId:` line and a `<usage>…</usage>` block of `key: value`
// lines). content is the raw JSON of contentBlock.Content — a [{type,text}]
// array on success (a BARE STRING on is_error, P13, which carries no trailer).
// Parsing is tolerant: any block missing/malformed yields zero values, never
// an error (forward-compat: trailer drift is a cassette diff, not a crash).
func parseResultContent(content json.RawMessage) (output string, tr resultTrailer) {
	if len(content) == 0 {
		return "", tr
	}

	// is_error results carry a bare string body (P13): the whole content is
	// the message, with no structured trailer.
	var bare string
	if err := json.Unmarshal(content, &bare); err == nil {
		return bare, tr
	}

	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(content, &blocks); err != nil {
		return "", tr
	}

	texts := make([]string, 0, len(blocks))
	for _, b := range blocks {
		if b.Type == "text" {
			texts = append(texts, b.Text)
		}
	}
	if len(texts) > 0 {
		output = texts[0]
	}
	// The trailer is the LAST text block (the `agentId:` + `<usage>` block);
	// any earlier block is subagent output. Scan all blocks for the trailer
	// markers rather than assuming exactly two.
	for _, t := range texts {
		if strings.Contains(t, "agentId:") || strings.Contains(t, "<usage>") {
			tr = parseTrailer(t)
			break
		}
	}
	return output, tr
}

// parseTrailer extracts agentId and the <usage> accounting fields from the
// trailer text block. Format (PROTOCOL-NOTES §3):
//
//	agentId: <hex> (use SendMessage with to: '<hex>' to continue this agent)
//	<usage>subagent_tokens: N
//	tool_uses: N
//	duration_ms: N</usage>
func parseTrailer(s string) resultTrailer {
	var tr resultTrailer
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "<usage>"))
		line = strings.TrimSuffix(line, "</usage>")
		switch {
		case strings.HasPrefix(line, "agentId:"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "agentId:"))
			// the agentId is the first token; the rest is the SendMessage hint.
			tr.agentID = firstToken(rest)
		case strings.HasPrefix(line, "subagent_tokens:"):
			tr.subagentTokens = parseInt(strings.TrimPrefix(line, "subagent_tokens:"))
		case strings.HasPrefix(line, "tool_uses:"):
			tr.toolUses = parseInt(strings.TrimPrefix(line, "tool_uses:"))
		case strings.HasPrefix(line, "duration_ms:"):
			tr.durationMS = parseInt(strings.TrimPrefix(line, "duration_ms:"))
		}
	}
	return tr
}

func firstToken(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t("); i >= 0 {
		return s[:i]
	}
	return s
}

func parseInt(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
