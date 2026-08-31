// Package attach is the runtime-ignorant Go shape of the
// dreamserpent.attach.v1 events the smart wrapper emits (D18/D38).
//
// The proto freezes at M0 in proto/dreamserpent/attach/v1/ (README-reserved);
// until that freeze this package is the working model and must not contain a
// proto body. Field tables follow client/goldentrace/OBSERVABILITY-DESIGN.md
// §1 with the PHASE3-FINDINGS corrections (P8 ask, P9 state, P10 ordering,
// P13 terminals).
//
// Nothing here may name a specific runtime (D38): runtime-specific vocabulary
// stays inside client/wrapper/adapters/. The wrapper holds no approval state
// (D18/D45/D53): it emits ask events; it never stores grants or answers asks.
package attach

import (
	"encoding/json"
	"time"
)

// Type discriminates the event payload. Exactly one payload pointer on Event
// is non-nil, and it corresponds to this value.
type Type string

const (
	TypeSessionInit       Type = "session.init"
	TypeSessionState      Type = "session.state"
	TypeChatMessage       Type = "chat.message"
	TypeChatDelta         Type = "chat.delta"
	TypeToolInvoked       Type = "tool.invoked"
	TypeToolCompleted     Type = "tool.completed"
	TypeSubagentSpawned   Type = "subagent.spawned"
	TypeSubagentProgress  Type = "subagent.progress"
	TypeSubagentCompleted Type = "subagent.completed"
	TypeSubagentAccounted Type = "subagent.accounted"
	TypeAskRequested      Type = "ask.requested"
	TypeAskResolved       Type = "ask.resolved"
	TypePlanDelta         Type = "plan.delta"
	TypeQuotaUpdated      Type = "quota.updated"
	TypeSessionAccounted  Type = "session.accounted"
)

// PlanDelta delta kinds, mirroring attach.v1.PlanDeltaKind (§6.1 row 6): the
// three runtime tool-use blocks a plan delta classifies — ExitPlanMode (the
// plan-mode approval framing), TodoWrite (the full-list todo replacement), and
// the Task* structured-todo family (NEVER a subagent spawn — that needs
// input.subagent_type, handled in classify.go). These are the working-model
// vocabulary; the adapter sources only TodoWrite today (PROTOCOL-NOTES §"Plan-
// delta / TodoWrite"), the others are reserved here so the shape is complete
// for the eventmap proto round-trip.
const (
	PlanDeltaKindTodoWrite    = "todo_write"
	PlanDeltaKindExitPlanMode = "exit_plan_mode"
	PlanDeltaKindTaskOp       = "task_op"
)

// The only two SessionState.State values with a wire source (P9). The
// orchestrator owns the rest of the doc 15 §3 vocabulary; an adapter must
// never synthesize orchestrator-owned states from the runtime stream.
const (
	StateAttached = "ATTACHED"
	StateWorking  = "WORKING"
)

// QuotaSemanticsProvisional is the constant QuotaUpdated.Semantics value:
// quota field semantics under load are unfixed (P18 open).
const QuotaSemanticsProvisional = "provisional"

// Event is the envelope. Seq is adapter-synthesized from stdout arrival order —
// the wire has no monotonic token (PHASE3 P10: verified a safe topological sort
// for the local single-process case). Exactly one payload pointer is non-nil.
type Event struct {
	Seq        uint64    `json:"seq"`
	SessionID  string    `json:"session_id"`
	ObservedAt time.Time `json:"observed_at"` // adapter clock; deterministic in replay
	Type       Type      `json:"type"`
	Source     []string  `json:"source,omitempty"` // runtime record uuids this was projected from

	SessionInit       *SessionInit       `json:"session_init,omitempty"`
	SessionState      *SessionState      `json:"session_state,omitempty"`
	ChatMessage       *ChatMessage       `json:"chat_message,omitempty"`
	ChatDelta         *ChatDelta         `json:"chat_delta,omitempty"`
	ToolInvoked       *ToolInvoked       `json:"tool_invoked,omitempty"`
	ToolCompleted     *ToolCompleted     `json:"tool_completed,omitempty"`
	SubagentSpawned   *SubagentSpawned   `json:"subagent_spawned,omitempty"`
	SubagentProgress  *SubagentProgress  `json:"subagent_progress,omitempty"`
	SubagentCompleted *SubagentCompleted `json:"subagent_completed,omitempty"`
	SubagentAccounted *SubagentAccounted `json:"subagent_accounted,omitempty"`
	AskRequested      *AskRequested      `json:"ask_requested,omitempty"`
	AskResolved       *AskResolved       `json:"ask_resolved,omitempty"`
	PlanDelta         *PlanDelta         `json:"plan_delta,omitempty"`
	QuotaUpdated      *QuotaUpdated      `json:"quota_updated,omitempty"`
	SessionAccounted  *SessionAccounted  `json:"session_accounted,omitempty"`
}

// SessionInit is the attach-time snapshot of the runtime's session config
// (OBSERVABILITY-DESIGN §1; doc 15 §6.1).
type SessionInit struct {
	RuntimeVersion string          `json:"runtime_version,omitempty"`
	Model          string          `json:"model,omitempty"`
	CWD            string          `json:"cwd,omitempty"`
	PermissionMode string          `json:"permission_mode,omitempty"`
	APIKeySource   string          `json:"api_key_source,omitempty"`
	Tools          []string        `json:"tools,omitempty"`
	AgentTypes     []string        `json:"agent_types,omitempty"`
	Skills         []string        `json:"skills,omitempty"`
	SlashCommands  []string        `json:"slash_commands,omitempty"`
	MCPServers     json.RawMessage `json:"mcp_servers,omitempty"`
	OutputStyle    string          `json:"output_style,omitempty"`
}

// SessionState is emitted on transitions only. State is "ATTACHED" or
// "WORKING" — the ONLY two states with a wire source (P9); the adapter must
// never synthesize orchestrator-owned states.
type SessionState struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"` // e.g. "requesting", "task_open", "turn_complete"
}

// ChatBlock is one content block of a chat message. Kind is "text" or
// "thinking".
type ChatBlock struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// ChatMessage is one event per non-partial assistant stream line carrying
// text/thinking blocks; consumers merge by MessageID (P11: the non-partial
// record is authoritative and arrives once per content block).
type ChatMessage struct {
	MessageID    string      `json:"message_id"`
	Role         string      `json:"role"`
	ParentNodeID string      `json:"parent_node_id,omitempty"` // empty ⇒ root
	Blocks       []ChatBlock `json:"blocks"`
}

// ChatDelta is a LIVE, PRE-FINAL refinement of a chat message still being
// streamed (the runtime's typing deltas, D145/P11). It is RENDER-ONLY: the
// authoritative content is the non-partial ChatMessage that arrives at turn end
// (merge by MessageID). A consumer that ignores ChatDelta loses nothing but the
// typing animation — dropping every ChatDelta leaves the canonical projection
// byte-identical (the regression guard). The adapter emits it only WithPartials
// (default-off), and only for Kind ∈ {text, thinking}: input_json_delta is
// tool-input assembly, never streamed as text (P11). Final is set on the
// content_block_stop that closes the block. Runtime-IGNORANT (D38): a generic
// typing delta — the runtime stream_event shapes stay inside
// client/wrapper/adapters/.
type ChatDelta struct {
	MessageID    string `json:"message_id"`               // joins this delta to the finalizing ChatMessage
	ParentNodeID string `json:"parent_node_id,omitempty"` // empty ⇒ root (mirrors ChatMessage)
	BlockIndex   int32  `json:"block_index"`              // the content block this delta extends (per-message index)
	Kind         string `json:"kind"`                     // "text" | "thinking"
	Text         string `json:"text,omitempty"`           // the coalesced delta text for this content_block_delta
	Final        bool   `json:"final,omitempty"`          // true on content_block_stop: this block is complete
}

// ToolInvoked is a tool-use start. NOT emitted for subagent spawns (those are
// SubagentSpawned). Kind is "native", "mcp", or "skill" (P14 classification);
// Server/Tool carry the mcp decomposition, Skill the skill name.
type ToolInvoked struct {
	NodeID       string          `json:"node_id"` // the tool-use id
	Name         string          `json:"name"`
	Kind         string          `json:"kind"`
	Server       string          `json:"server,omitempty"`
	Tool         string          `json:"tool,omitempty"`
	Skill        string          `json:"skill,omitempty"`
	ParentNodeID string          `json:"parent_node_id,omitempty"`
	TurnGroup    string          `json:"turn_group,omitempty"` // groups blocks of one logical turn
	Input        json.RawMessage `json:"input,omitempty"`
}

// ToolCompleted is the matching completion. DenialMessage is set when this
// completion is a permission denial — the is_error bare-string body (P13/P8).
type ToolCompleted struct {
	NodeID        string `json:"node_id"`
	IsError       bool   `json:"is_error,omitempty"`
	OutputExcerpt string `json:"output_excerpt,omitempty"` // first text block, ≤256 runes
	DenialMessage string `json:"denial_message,omitempty"`
}

// SubagentSpawned is a node entering the spawn tree (OBSERVABILITY-DESIGN §1).
// ParentConfidence is "exact" at depth ≤2, "inferred" at depth ≥3 (§2).
type SubagentSpawned struct {
	NodeID           string `json:"node_id"`
	TaskID           string `json:"task_id,omitempty"`
	SubagentType     string `json:"subagent_type,omitempty"`
	Description      string `json:"description,omitempty"`
	PromptExcerpt    string `json:"prompt_excerpt,omitempty"`
	TaskType         string `json:"task_type,omitempty"`
	ParentNodeID     string `json:"parent_node_id,omitempty"` // empty ⇒ root
	ParentConfidence string `json:"parent_confidence,omitempty"`
	TurnGroup        string `json:"turn_group,omitempty"`
}

// SubagentProgress is coarse liveness (OBSERVABILITY-DESIGN §1). UsageRaw is
// a verbatim passthrough flagged Uncharacterized — no capture establishes its
// contents; never render it as token burn. ElapsedMS is adapter-clock, not
// wire truth.
type SubagentProgress struct {
	NodeID          string          `json:"node_id"`
	TaskID          string          `json:"task_id,omitempty"`
	LastToolName    string          `json:"last_tool_name,omitempty"`
	ElapsedMS       int64           `json:"elapsed_ms,omitempty"`
	UsageRaw        json.RawMessage `json:"usage_raw,omitempty"`
	Uncharacterized bool            `json:"uncharacterized,omitempty"`
}

// SubagentCompleted is the lifecycle terminal (OBSERVABILITY-DESIGN §1).
// Tokens are NOT sourced here — accounting arrives separately on
// SubagentAccounted, possibly much later and in completion order.
type SubagentCompleted struct {
	NodeID     string `json:"node_id"`
	TaskID     string `json:"task_id,omitempty"`
	Status     string `json:"status,omitempty"`
	Summary    string `json:"summary,omitempty"`
	OutputFile string `json:"output_file,omitempty"`
}

// Continuation is the display-only resumption hint a completed subagent
// advertises; it is gated in headless runs and must not be presented as
// actionable (OBSERVABILITY-DESIGN §1).
type Continuation struct {
	AgentID string `json:"agent_id"`
	Hint    string `json:"hint"`
}

// SubagentAccounted is the authoritative per-subagent accounting
// (OBSERVABILITY-DESIGN §1): the usage trailer of the node's result.
// ReturnedTo is the node the result returned to (empty ⇒ root) — parent
// corroboration, never the primary join.
type SubagentAccounted struct {
	NodeID         string        `json:"node_id"`
	AgentID        string        `json:"agent_id,omitempty"`
	SubagentTokens int64         `json:"subagent_tokens,omitempty"`
	ToolUses       int64         `json:"tool_uses,omitempty"`
	DurationMS     int64         `json:"duration_ms,omitempty"`
	OutputExcerpt  string        `json:"output_excerpt,omitempty"`
	IsError        bool          `json:"is_error,omitempty"`
	ReturnedTo     string        `json:"returned_to,omitempty"`
	Continuation   *Continuation `json:"continuation,omitempty"`
}

// AskRequested is an approval request surfaced from the control protocol
// (P8). NodeID is the tool-use id — the correlation key end-to-end. Source is
// "control", "prompt-tool", or "rearm"; Pending is true when re-armed from
// the pending-requests list of a re-attach handshake. The wrapper never
// answers asks itself (D18/D45/D53).
type AskRequested struct {
	AskID       string          `json:"ask_id"` // control request id if present, else the tool-use id
	NodeID      string          `json:"node_id"`
	ToolName    string          `json:"tool_name,omitempty"`
	Input       json.RawMessage `json:"input,omitempty"`
	Suggestions json.RawMessage `json:"suggestions,omitempty"` // native channel only
	AgentID     string          `json:"agent_id,omitempty"`
	Source      string          `json:"source"`
	Pending     bool            `json:"pending,omitempty"`
}

// AskResolved closes an ask. Behavior is "allow", "deny", or "cancelled";
// Classification is user_temporary | user_permanent | user_reject when known
// (P8 option set).
type AskResolved struct {
	AskID          string `json:"ask_id"`
	NodeID         string `json:"node_id"`
	Behavior       string `json:"behavior"`
	Classification string `json:"classification,omitempty"`
	Message        string `json:"message,omitempty"`
}

// TodoItem is one TodoWrite list entry — the working-model mirror of
// attach.v1.TodoItem. The full list is replaced each TodoWrite call; the canvas
// plan/todo card diffs it against the previous list. Status is "pending" |
// "in_progress" | "completed"; ActiveForm is the present-tense label CC renders
// while the item is in progress; ID is stable across calls when CC supplies it.
type TodoItem struct {
	Content    string `json:"content"`
	Status     string `json:"status"`
	ActiveForm string `json:"active_form,omitempty"`
	ID         string `json:"id,omitempty"`
}

// PlanDelta is the §6.1 row-6 plan-half event class — a first-class event
// (NOT a generic ToolInvoked): a TodoWrite/Task*/ExitPlanMode tool-use block
// carries a plan snapshot the writer-seat surface renders as the plan/todo
// card. The adapter emits it for TodoWrite today (the full todo-list snapshot
// in Todos); Kind is one of the PlanDeltaKind* constants. NodeID is the
// tool-use id (the correlation key, mirroring the proto's tool_use_id). Plan
// and ApprovalState are EXIT_PLAN_MODE-only and stay empty for TodoWrite.
type PlanDelta struct {
	NodeID        string     `json:"node_id"` // the tool-use id (proto tool_use_id)
	Kind          string     `json:"kind"`
	Todos         []TodoItem `json:"todos,omitempty"`          // TODO_WRITE / TASK_OP — full-list replacement
	Plan          string     `json:"plan,omitempty"`           // EXIT_PLAN_MODE only — the plan body
	ApprovalState string     `json:"approval_state,omitempty"` // EXIT_PLAN_MODE only — joins the §6.2 ask
}

// QuotaUpdated is a passthrough of the wire rate-limit fields. Semantics is
// always QuotaSemanticsProvisional (P18 open: behavior under load unfixed).
type QuotaUpdated struct {
	RateLimitType         string          `json:"rate_limit_type,omitempty"`
	Status                string          `json:"status,omitempty"`
	ResetsAt              json.RawMessage `json:"resets_at,omitempty"`
	IsUsingOverage        bool            `json:"is_using_overage,omitempty"`
	OverageStatus         string          `json:"overage_status,omitempty"`
	OverageDisabledReason string          `json:"overage_disabled_reason,omitempty"`
	Semantics             string          `json:"semantics"`
}

// SessionAccounted is the terminal accounting event. Outcome is the closed
// set {success, error_during_execution, error_max_turns, error_max_budget_usd,
// error_max_structured_output_retries} (P13). TerminalReason is optional —
// absent on the budget terminal. NEVER derived from a stop reason (P9:
// nondeterministic).
type SessionAccounted struct {
	Outcome        string          `json:"outcome"`
	IsError        bool            `json:"is_error,omitempty"`
	NumTurns       int             `json:"num_turns,omitempty"`
	DurationMS     int64           `json:"duration_ms,omitempty"`
	TotalCostUSD   float64         `json:"total_cost_usd,omitempty"`
	TerminalReason string          `json:"terminal_reason,omitempty"`
	Errors         []string        `json:"errors,omitempty"`
	Usage          json.RawMessage `json:"usage,omitempty"`
	ModelUsage     json.RawMessage `json:"model_usage,omitempty"`
	DenialCount    int             `json:"denial_count,omitempty"`
}
