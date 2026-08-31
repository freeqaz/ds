// Package eventmap maps a FROZEN proto attach.v1.SessionEvent onto the OSS
// client/wrapper/attach.Event working model so the existing client/tui Model can
// fold it (D18 structured deltas).
//
// WHY THIS LIVES HERE, NOT IN client/. client/ is stdlib-only by charter and its
// attach.Event is a hand-written working model that imports NO proto (the
// attach.v1 proto freezes elsewhere; client/wrapper/attach/attach.go is the OSS
// seam). serpent-tui is the Option-C module that may take both — so the
// proto->Event translation is done HERE, narrowly, never by migrating client/'s
// types onto the frozen proto (the N6 scope fence). The webclient read leg
// (paid/webclient/attach) folds proto SessionEvents into its OWN proto-only
// model precisely because it may not reach client/tui; serpent-tui CAN reach
// client/tui, so it maps proto->attach.Event and reuses the reference fold.
//
// FIDELITY. The mapping is field-for-field against the two shapes
// (proto/dreamserpent/attach/v1/events.proto <-> client/wrapper/attach/attach.go).
// Three proto event classes have NO place in the client/wrapper/attach.Event
// working model (it predates the §6.1 additions): PLAN_DELTA (§6.1 row 6),
// INPUT_ACTIVITY (§6.1 row 7), and the typed SUSPENDED reason. They are mapped
// LOSSLESS-ENOUGH for the writer-seat TUI: a SessionState carries its name (incl.
// PARKED/SUSPENDED) into attach.SessionState.State, and the two row-6/row-7
// classes are surfaced through the model's forward-compat path (an unhandled
// Type renders a single honest status line, never a crash, never a fabricated
// shape — Model.Apply's default branch). This keeps client/ untouched while the
// human still sees every event the orchestrator fans out.
package eventmap

import (
	"time"

	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Extra attach.Type value for the one §6.1 event class the client/wrapper/attach
// working model still has no payload for: INPUT_ACTIVITY (row 7). It carries the
// proto type through to Model.Apply's forward-compat branch (renders one honest
// status line) rather than being silently dropped — a new event class on the
// wire is visible, never invented into an existing shape. This is LOCAL to
// serpent-tui (client/ stays as-is, the scope fence).
//
// PLAN_DELTA (row 6) is NO LONGER here: the working model now owns
// attach.TypePlanDelta + attach.PlanDelta, so the PLAN_DELTA arm populates a
// real payload (planDelta below) instead of dropping to forward-compat.
const (
	TypeInputActivity attach.Type = "input.activity"
)

// FromProto maps one frozen attach.v1.SessionEvent onto the client/wrapper/attach
// Event the client/tui Model folds. The envelope fields (seq, session_id,
// observed_at, source) map directly; the payload is dispatched off the proto
// oneof and projected onto the matching attach.* payload pointer. Exactly one
// payload pointer is set, matching attach.Event's "exactly one non-nil" contract
// (the model asserts it on fold).
//
// observed_at: the proto carries unix MILLIS (events.proto SessionEvent.seq/
// observed_at comment "unix millis"); attach.Event.ObservedAt is a time.Time
// (deterministic in replay), so it is reconstructed as UnixMilli — never a
// wall-clock Now(), so a replay/golden of the SAME event stream is identical.
func FromProto(ev *attachv1.SessionEvent) attach.Event {
	out := attach.Event{
		Seq:        ev.GetSeq(),
		SessionID:  ev.GetSessionId(),
		ObservedAt: observedAt(ev.GetObservedAt()),
		Type:       eventType(ev.GetType()),
		Source:     cloneStrings(ev.GetSource()),
	}

	switch ev.GetType() {
	case attachv1.EventType_EVENT_TYPE_SESSION_INIT:
		out.SessionInit = sessionInit(ev.GetSessionInit())
	case attachv1.EventType_EVENT_TYPE_SESSION_STATE:
		out.SessionState = sessionState(ev.GetSessionState())
	case attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE:
		out.ChatMessage = chatMessage(ev.GetChatMessage())
	case attachv1.EventType_EVENT_TYPE_CHAT_DELTA:
		out.ChatDelta = chatDelta(ev.GetChatDelta())
	case attachv1.EventType_EVENT_TYPE_TOOL_INVOKED:
		out.ToolInvoked = toolInvoked(ev.GetToolInvoked())
	case attachv1.EventType_EVENT_TYPE_TOOL_COMPLETED:
		out.ToolCompleted = toolCompleted(ev.GetToolCompleted())
	case attachv1.EventType_EVENT_TYPE_SUBAGENT_SPAWNED:
		out.SubagentSpawned = subagentSpawned(ev.GetSubagentSpawned())
	case attachv1.EventType_EVENT_TYPE_SUBAGENT_PROGRESS:
		out.SubagentProgress = subagentProgress(ev.GetSubagentProgress())
	case attachv1.EventType_EVENT_TYPE_SUBAGENT_COMPLETED:
		out.SubagentCompleted = subagentCompleted(ev.GetSubagentCompleted())
	case attachv1.EventType_EVENT_TYPE_SUBAGENT_ACCOUNTED:
		out.SubagentAccounted = subagentAccounted(ev.GetSubagentAccounted())
	case attachv1.EventType_EVENT_TYPE_ASK_REQUESTED:
		out.AskRequested = askRequested(ev.GetAskRequested())
	case attachv1.EventType_EVENT_TYPE_ASK_RESOLVED:
		out.AskResolved = askResolved(ev.GetAskResolved())
	case attachv1.EventType_EVENT_TYPE_PLAN_DELTA:
		out.PlanDelta = planDelta(ev.GetPlanDelta())
	case attachv1.EventType_EVENT_TYPE_QUOTA_UPDATED:
		out.QuotaUpdated = quotaUpdated(ev.GetQuotaUpdated())
	case attachv1.EventType_EVENT_TYPE_SESSION_ACCOUNTED:
		out.SessionAccounted = sessionAccounted(ev.GetSessionAccounted())
	default:
		// INPUT_ACTIVITY / UNSPECIFIED: no client/wrapper/attach payload exists.
		// eventType() carried the discriminator through; the Model's forward-
		// compat default branch renders one honest status line. PLAN_DELTA is no
		// longer here — it has a real payload now (the case above).
	}
	return out
}

// observedAt reconstructs the deterministic adapter clock from proto unix millis.
// 0 (unset) maps to the zero Time so a replay is stable.
func observedAt(millis uint64) time.Time {
	if millis == 0 {
		return time.Time{}
	}
	return time.UnixMilli(int64(millis)).UTC()
}

// eventType maps the proto EventType discriminator onto the attach.Type the
// Model switches on. PLAN_DELTA (§6.1 row 6) maps to the working-model-owned
// attach.TypePlanDelta (a real payload, the planDelta mapping below); the row-7
// INPUT_ACTIVITY class maps to the serpent-tui-local Type constant so it reaches
// Model.Apply's forward-compat branch (rendered, not dropped); UNSPECIFIED maps
// to an empty Type (the default branch too).
func eventType(t attachv1.EventType) attach.Type {
	switch t {
	case attachv1.EventType_EVENT_TYPE_SESSION_INIT:
		return attach.TypeSessionInit
	case attachv1.EventType_EVENT_TYPE_SESSION_STATE:
		return attach.TypeSessionState
	case attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE:
		return attach.TypeChatMessage
	case attachv1.EventType_EVENT_TYPE_CHAT_DELTA:
		return attach.TypeChatDelta
	case attachv1.EventType_EVENT_TYPE_TOOL_INVOKED:
		return attach.TypeToolInvoked
	case attachv1.EventType_EVENT_TYPE_TOOL_COMPLETED:
		return attach.TypeToolCompleted
	case attachv1.EventType_EVENT_TYPE_SUBAGENT_SPAWNED:
		return attach.TypeSubagentSpawned
	case attachv1.EventType_EVENT_TYPE_SUBAGENT_PROGRESS:
		return attach.TypeSubagentProgress
	case attachv1.EventType_EVENT_TYPE_SUBAGENT_COMPLETED:
		return attach.TypeSubagentCompleted
	case attachv1.EventType_EVENT_TYPE_SUBAGENT_ACCOUNTED:
		return attach.TypeSubagentAccounted
	case attachv1.EventType_EVENT_TYPE_ASK_REQUESTED:
		return attach.TypeAskRequested
	case attachv1.EventType_EVENT_TYPE_ASK_RESOLVED:
		return attach.TypeAskResolved
	case attachv1.EventType_EVENT_TYPE_QUOTA_UPDATED:
		return attach.TypeQuotaUpdated
	case attachv1.EventType_EVENT_TYPE_SESSION_ACCOUNTED:
		return attach.TypeSessionAccounted
	case attachv1.EventType_EVENT_TYPE_PLAN_DELTA:
		return attach.TypePlanDelta
	case attachv1.EventType_EVENT_TYPE_INPUT_ACTIVITY:
		return TypeInputActivity
	default:
		return ""
	}
}

func sessionInit(p *attachv1.SessionInit) *attach.SessionInit {
	if p == nil {
		return nil
	}
	return &attach.SessionInit{
		RuntimeVersion: p.GetRuntimeVersion(),
		Model:          p.GetModel(),
		CWD:            p.GetCwd(),
		PermissionMode: p.GetPermissionMode(),
		APIKeySource:   p.GetApiKeySource(),
		Tools:          cloneStrings(p.GetTools()),
		AgentTypes:     cloneStrings(p.GetAgentTypes()),
		Skills:         cloneStrings(p.GetSkills()),
		SlashCommands:  cloneStrings(p.GetSlashCommands()),
		MCPServers:     cloneBytes(p.GetMcpServers()),
		OutputStyle:    p.GetOutputStyle(),
	}
}

// sessionState projects the full §3 vocabulary (incl. PARKED + the D77-narrowed
// SUSPENDED reason) onto attach.SessionState. The working model's State is a
// free string, so the proto's enum name (SessionStateName) maps to the short §3
// render name and the typed SuspendReason is folded into the Reason refinement
// label when present (so SUSPENDED(policy_breach) is visible — the read-only
// projection, never authority, D77). This is how the writer-seat human sees a
// PARKED/SUSPENDED state the client/wrapper/attach adapter alone could not
// synthesize (it only sources ATTACHED/WORKING from the runtime, P9).
func sessionState(p *attachv1.SessionState) *attach.SessionState {
	if p == nil {
		return nil
	}
	out := &attach.SessionState{
		State:  stateName(p.GetName()),
		Reason: p.GetReason(),
	}
	if p.GetName() == attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED {
		if r := suspendReason(p.GetSuspendReason()); r != "" {
			if out.Reason == "" {
				out.Reason = r
			} else {
				out.Reason = r + ": " + out.Reason
			}
		}
	}
	return out
}

func chatMessage(p *attachv1.ChatMessage) *attach.ChatMessage {
	if p == nil {
		return nil
	}
	blocks := make([]attach.ChatBlock, 0, len(p.GetBlocks()))
	for _, b := range p.GetBlocks() {
		blocks = append(blocks, attach.ChatBlock{Kind: b.GetKind(), Text: b.GetText()})
	}
	return &attach.ChatMessage{
		MessageID:    p.GetMessageId(),
		Role:         p.GetRole(),
		ParentNodeID: p.GetParentNodeId(),
		Blocks:       blocks,
	}
}

// chatDelta maps the frozen attach.v1.ChatDelta onto the working-model
// attach.ChatDelta (D145, §Layer 1): the live typing-delta the writer-seat
// surface renders as a tail region below the committed transcript, REPLACED by
// the committed ChatMessage on finalization. It is render-only (P11) — the
// non-partial ChatMessage stays authoritative, so a reader that never folds these
// loses only the typing animation.
func chatDelta(p *attachv1.ChatDelta) *attach.ChatDelta {
	if p == nil {
		return nil
	}
	return &attach.ChatDelta{
		MessageID:    p.GetMessageId(),
		ParentNodeID: p.GetParentNodeId(),
		BlockIndex:   p.GetBlockIndex(),
		Kind:         p.GetKind(),
		Text:         p.GetText(),
		Final:        p.GetFinal(),
	}
}

func toolInvoked(p *attachv1.ToolInvoked) *attach.ToolInvoked {
	if p == nil {
		return nil
	}
	return &attach.ToolInvoked{
		NodeID:       p.GetNodeId(),
		Name:         p.GetName(),
		Kind:         p.GetKind(),
		Server:       p.GetServer(),
		Tool:         p.GetTool(),
		Skill:        p.GetSkill(),
		ParentNodeID: p.GetParentNodeId(),
		TurnGroup:    p.GetTurnGroup(),
		Input:        cloneBytes(p.GetInput()),
	}
}

func toolCompleted(p *attachv1.ToolCompleted) *attach.ToolCompleted {
	if p == nil {
		return nil
	}
	return &attach.ToolCompleted{
		NodeID:        p.GetNodeId(),
		IsError:       p.GetIsError(),
		OutputExcerpt: p.GetOutputExcerpt(),
		DenialMessage: p.GetDenialMessage(),
	}
}

func subagentSpawned(p *attachv1.SubagentSpawned) *attach.SubagentSpawned {
	if p == nil {
		return nil
	}
	return &attach.SubagentSpawned{
		NodeID:           p.GetNodeId(),
		TaskID:           p.GetTaskId(),
		SubagentType:     p.GetSubagentType(),
		Description:      p.GetDescription(),
		PromptExcerpt:    p.GetPromptExcerpt(),
		TaskType:         p.GetTaskType(),
		ParentNodeID:     p.GetParentNodeId(),
		ParentConfidence: p.GetParentConfidence(),
		TurnGroup:        p.GetTurnGroup(),
	}
}

func subagentProgress(p *attachv1.SubagentProgress) *attach.SubagentProgress {
	if p == nil {
		return nil
	}
	return &attach.SubagentProgress{
		NodeID:          p.GetNodeId(),
		TaskID:          p.GetTaskId(),
		LastToolName:    p.GetLastToolName(),
		ElapsedMS:       p.GetElapsedMs(),
		UsageRaw:        cloneBytes(p.GetUsageRaw()),
		Uncharacterized: p.GetUncharacterized(),
	}
}

func subagentCompleted(p *attachv1.SubagentCompleted) *attach.SubagentCompleted {
	if p == nil {
		return nil
	}
	return &attach.SubagentCompleted{
		NodeID:     p.GetNodeId(),
		TaskID:     p.GetTaskId(),
		Status:     p.GetStatus(),
		Summary:    p.GetSummary(),
		OutputFile: p.GetOutputFile(),
	}
}

func subagentAccounted(p *attachv1.SubagentAccounted) *attach.SubagentAccounted {
	if p == nil {
		return nil
	}
	out := &attach.SubagentAccounted{
		NodeID:         p.GetNodeId(),
		AgentID:        p.GetAgentId(),
		SubagentTokens: p.GetSubagentTokens(),
		ToolUses:       p.GetToolUses(),
		DurationMS:     p.GetDurationMs(),
		OutputExcerpt:  p.GetOutputExcerpt(),
		IsError:        p.GetIsError(),
		ReturnedTo:     p.GetReturnedTo(),
	}
	if c := p.GetContinuation(); c != nil {
		out.Continuation = &attach.Continuation{AgentID: c.GetAgentId(), Hint: c.GetHint()}
	}
	return out
}

// askRequested maps the proto ask onto the working model. The proto carries
// tool_use_id (the attach.v1 correlation key) AND request_id (the control-channel
// answer key) as DISTINCT fields; the working model's single AskID is "the
// control request id if present, else the tool-use id" (attach.go) — so the
// mapping prefers request_id and falls back to tool_use_id, preserving the
// end-to-end join the writer-seat answer path needs (the driver's DriveGrant
// joins on request_id for the native route, tool_use_id for the prompt-tool
// route — both are recovered downstream from NodeID/AskID by the loop). `held`
// (the socket-hold-as-ask-payload, never §3 state) folds into Pending so the
// open ask is visibly held; Source carries the proto source verbatim.
func askRequested(p *attachv1.AskRequested) *attach.AskRequested {
	if p == nil {
		return nil
	}
	askID := p.GetRequestId()
	if askID == "" {
		askID = p.GetToolUseId()
	}
	return &attach.AskRequested{
		AskID:       askID,
		NodeID:      askNodeID(p),
		ToolName:    p.GetToolName(),
		Input:       cloneBytes(p.GetInput()),
		Suggestions: cloneBytes(p.GetSuggestions()),
		AgentID:     p.GetAgentId(),
		Source:      p.GetSource(),
		Pending:     p.GetPending() || p.GetHeld(),
	}
}

// askNodeID resolves the ask's node id — the proto carries node_id (alias of
// tool_use_id at the event node level); fall back to tool_use_id so the tree
// threading in the Model always has the correlation key.
func askNodeID(p *attachv1.AskRequested) string {
	if n := p.GetNodeId(); n != "" {
		return n
	}
	return p.GetToolUseId()
}

func askResolved(p *attachv1.AskResolved) *attach.AskResolved {
	if p == nil {
		return nil
	}
	askID := p.GetRequestId()
	if askID == "" {
		askID = p.GetToolUseId()
	}
	nodeID := p.GetNodeId()
	if nodeID == "" {
		nodeID = p.GetToolUseId()
	}
	return &attach.AskResolved{
		AskID:          askID,
		NodeID:         nodeID,
		Behavior:       p.GetBehavior(),
		Classification: p.GetClassification(),
		Message:        p.GetMessage(),
	}
}

// planDelta maps the frozen attach.v1.PlanDelta onto the working-model
// attach.PlanDelta (§6.1 row 6): the tool_use_id correlation key, the typed kind
// (TodoWrite / ExitPlanMode / Task* — derived off the enum so no string literal
// drifts), the full todo-list snapshot, and the EXIT_PLAN_MODE-only plan body +
// approval state. This is the first-class projection that lets the writer-seat
// surface render the plan/todo card instead of an opaque forward-compat line.
func planDelta(p *attachv1.PlanDelta) *attach.PlanDelta {
	if p == nil {
		return nil
	}
	out := &attach.PlanDelta{
		NodeID:        p.GetToolUseId(),
		Kind:          planDeltaKind(p.GetKind()),
		Plan:          p.GetPlan(),
		ApprovalState: planApprovalState(p.GetApprovalState()),
	}
	if todos := p.GetTodos(); len(todos) > 0 {
		out.Todos = make([]attach.TodoItem, 0, len(todos))
		for _, t := range todos {
			out.Todos = append(out.Todos, attach.TodoItem{
				Content:    t.GetContent(),
				Status:     t.GetStatus(),
				ActiveForm: t.GetActiveForm(),
				ID:         t.GetId(),
			})
		}
	}
	return out
}

// planDeltaKind maps the frozen PlanDeltaKind enum onto the working-model kind
// string (the attach.PlanDeltaKind* constants). UNSPECIFIED renders as "" so an
// unset kind is honest-empty rather than a fabricated label.
func planDeltaKind(k attachv1.PlanDeltaKind) string {
	switch k {
	case attachv1.PlanDeltaKind_PLAN_DELTA_KIND_TODO_WRITE:
		return attach.PlanDeltaKindTodoWrite
	case attachv1.PlanDeltaKind_PLAN_DELTA_KIND_EXIT_PLAN_MODE:
		return attach.PlanDeltaKindExitPlanMode
	case attachv1.PlanDeltaKind_PLAN_DELTA_KIND_TASK_OP:
		return attach.PlanDeltaKindTaskOp
	default:
		return ""
	}
}

// planApprovalState maps the EXIT_PLAN_MODE-only approval-state enum onto its §6
// label (read-only projection). UNSPECIFIED returns "" so it does not pollute a
// TodoWrite delta (which never carries an approval state).
func planApprovalState(s attachv1.PlanApprovalState) string {
	switch s {
	case attachv1.PlanApprovalState_PLAN_APPROVAL_STATE_PROPOSED:
		return "proposed"
	case attachv1.PlanApprovalState_PLAN_APPROVAL_STATE_APPROVED:
		return "approved"
	case attachv1.PlanApprovalState_PLAN_APPROVAL_STATE_REJECTED:
		return "rejected"
	default:
		return ""
	}
}

func quotaUpdated(p *attachv1.QuotaUpdated) *attach.QuotaUpdated {
	if p == nil {
		return nil
	}
	return &attach.QuotaUpdated{
		RateLimitType:         p.GetRateLimitType(),
		Status:                p.GetStatus(),
		ResetsAt:              cloneBytes(p.GetResetsAt()),
		IsUsingOverage:        p.GetIsUsingOverage(),
		OverageStatus:         p.GetOverageStatus(),
		OverageDisabledReason: p.GetOverageDisabledReason(),
		Semantics:             p.GetSemantics(),
	}
}

func sessionAccounted(p *attachv1.SessionAccounted) *attach.SessionAccounted {
	if p == nil {
		return nil
	}
	return &attach.SessionAccounted{
		Outcome:        p.GetOutcome(),
		IsError:        p.GetIsError(),
		NumTurns:       int(p.GetNumTurns()),
		DurationMS:     p.GetDurationMs(),
		TotalCostUSD:   p.GetTotalCostUsd(),
		TerminalReason: p.GetTerminalReason(),
		Errors:         cloneStrings(p.GetErrors()),
		Usage:          cloneBytes(p.GetUsage()),
		ModelUsage:     cloneBytes(p.GetModelUsage()),
		DenialCount:    int(p.GetDenialCount()),
	}
}

// stateName maps the frozen §3 SessionStateName enum onto the short render name
// the client/tui surface shows (the lower-case stateName form, doc 17 §3.1). It
// is derived off the enum (no string literals to drift): the §3 vocabulary is
// the single source. UNSPECIFIED renders as "UNSPECIFIED" so an unset state is
// visible rather than blank.
func stateName(n attachv1.SessionStateName) string {
	switch n {
	case attachv1.SessionStateName_SESSION_STATE_NAME_PENDING:
		return "PENDING"
	case attachv1.SessionStateName_SESSION_STATE_NAME_CREATING:
		return "CREATING"
	case attachv1.SessionStateName_SESSION_STATE_NAME_READY:
		return "READY"
	case attachv1.SessionStateName_SESSION_STATE_NAME_ATTACHED:
		return "ATTACHED"
	case attachv1.SessionStateName_SESSION_STATE_NAME_WORKING:
		return "WORKING"
	case attachv1.SessionStateName_SESSION_STATE_NAME_SNAPSHOTTING:
		return "SNAPSHOTTING"
	case attachv1.SessionStateName_SESSION_STATE_NAME_MIGRATING:
		return "MIGRATING"
	case attachv1.SessionStateName_SESSION_STATE_NAME_PARKED:
		return "PARKED"
	case attachv1.SessionStateName_SESSION_STATE_NAME_SUSPENDED:
		return "SUSPENDED"
	case attachv1.SessionStateName_SESSION_STATE_NAME_RESUMING:
		return "RESUMING"
	case attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYING:
		return "DESTROYING"
	case attachv1.SessionStateName_SESSION_STATE_NAME_DESTROYED:
		return "DESTROYED"
	default:
		return "UNSPECIFIED"
	}
}

// suspendReason maps the D77-narrowed SUSPENDED reason enum onto its §3 label
// (read-only projection, never authority). UNSPECIFIED returns empty so it does
// not pollute the refinement label.
func suspendReason(r attachv1.SuspendReason) string {
	switch r {
	case attachv1.SuspendReason_SUSPEND_REASON_USER:
		return "user"
	case attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH:
		return "policy_breach"
	case attachv1.SuspendReason_SUSPEND_REASON_REBALANCE:
		return "rebalance"
	default:
		return ""
	}
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
