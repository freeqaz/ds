// records.go — the Claude Code stdout wire shapes this adapter decodes
// (foundation-owned, D49). Key sets follow client/goldentrace/PROTOCOL-NOTES.md
// (the canonical wire map) with the PHASE3-FINDINGS.md corrections; captured
// against CC 2.1.173, the version pinned by the golden image. These structs
// never leave this package (D38): everything outside adapters/claude-code/
// speaks attach.v1 only.
package claudecode

import "encoding/json"

// fixtureHeader matches the D50 provenance header that every committed
// cassette carries as its first line (client/fixtures/PROVENANCE.md). It is
// not a CC record; Feed skips it.
type fixtureHeader struct {
	DSFixture *struct {
		Provenance string `json:"provenance"`
		Seam       string `json:"seam"`
		Created    string `json:"created"`
		Tool       string `json:"tool"`
	} `json:"ds_fixture"`
}

// envelope is the field set every CC stdout record carries (PROTOCOL-NOTES
// "Message envelope"). parent_tool_use_id is null/absent on the root session;
// JSON null decodes to "". It is prompt-side attribution only — null on
// results and all task_* records, and it flattens nesting to depth 1 (P2):
// correlation is by id triple, never by this field alone.
type envelope struct {
	Type            string `json:"type"`
	Subtype         string `json:"subtype"`
	UUID            string `json:"uuid"`
	SessionID       string `json:"session_id"`
	ParentToolUseID string `json:"parent_tool_use_id"`
}

// initRecord is system/init — the attach-time session-config snapshot.
// tools[] and agents[] are DISJOINT registries (P14): callable tool names vs
// subagent types.
type initRecord struct {
	Type                    string          `json:"type"`
	Subtype                 string          `json:"subtype"`
	UUID                    string          `json:"uuid"`
	SessionID               string          `json:"session_id"`
	CWD                     string          `json:"cwd"`
	ClaudeCodeVersion       string          `json:"claude_code_version"`
	Model                   string          `json:"model"`
	PermissionMode          string          `json:"permissionMode"`
	APIKeySource            string          `json:"apiKeySource"`
	OutputStyle             string          `json:"output_style"`
	FastModeState           string          `json:"fast_mode_state"`
	Tools                   []string        `json:"tools"`
	Agents                  []string        `json:"agents"`
	SlashCommands           []string        `json:"slash_commands"`
	Skills                  []string        `json:"skills"`
	Plugins                 json.RawMessage `json:"plugins"`
	MCPServers              json.RawMessage `json:"mcp_servers"`
	MemoryPaths             json.RawMessage `json:"memory_paths"`
	AnalyticsDisabled       bool            `json:"analytics_disabled"`
	ProductFeedbackDisabled bool            `json:"product_feedback_disabled"`
}

// statusRecord is system/status — a fixed 5-key record (P9). In print mode
// .status carries only "requesting" (one ping per model API round-trip); it
// is a request-in-flight signal, not a state enum.
type statusRecord struct {
	Type      string `json:"type"`
	Subtype   string `json:"subtype"`
	UUID      string `json:"uuid"`
	SessionID string `json:"session_id"`
	Status    string `json:"status"`
}

// thinkingTokensRecord is system/thinking_tokens — a high-frequency live
// token estimate, deliberately outside the event model (PROTOCOL-NOTES
// message-type table).
type thinkingTokensRecord struct {
	Type                 string `json:"type"`
	Subtype              string `json:"subtype"`
	UUID                 string `json:"uuid"`
	SessionID            string `json:"session_id"`
	EstimatedTokens      int64  `json:"estimated_tokens"`
	EstimatedTokensDelta int64  `json:"estimated_tokens_delta"`
}

// taskStartedRecord is system/task_started. Keys diverge by task_type (P9):
// local_agent adds prompt+subagent_type; local_bash omits them.
// parent_tool_use_id is always null on task_* records — correlate via
// tool_use_id + task_id.
type taskStartedRecord struct {
	Type         string `json:"type"`
	Subtype      string `json:"subtype"`
	UUID         string `json:"uuid"`
	SessionID    string `json:"session_id"`
	TaskID       string `json:"task_id"`
	ToolUseID    string `json:"tool_use_id"`
	TaskType     string `json:"task_type"` // {local_agent, local_bash} (P9)
	Description  string `json:"description"`
	Prompt       string `json:"prompt"`
	SubagentType string `json:"subagent_type"`
}

// taskProgressRecord is system/task_progress — in-flight liveness. It carries
// no .status field (P9); usage contents are uncharacterized — pass through
// verbatim, never render as token burn.
type taskProgressRecord struct {
	Type         string          `json:"type"`
	Subtype      string          `json:"subtype"`
	UUID         string          `json:"uuid"`
	SessionID    string          `json:"session_id"`
	TaskID       string          `json:"task_id"`
	ToolUseID    string          `json:"tool_use_id"`
	Description  string          `json:"description"`
	SubagentType string          `json:"subagent_type"`
	LastToolName string          `json:"last_tool_name"`
	Usage        json.RawMessage `json:"usage"`
}

// taskNotificationRecord is system/task_notification — lifecycle terminal.
// .status observed "completed" only; failure/abort variants unobserved (P9) —
// pass through verbatim. usage.subagent_tokens was observed null here: tokens
// are sourced from the result trailer, never from this record.
type taskNotificationRecord struct {
	Type       string          `json:"type"`
	Subtype    string          `json:"subtype"`
	UUID       string          `json:"uuid"`
	SessionID  string          `json:"session_id"`
	TaskID     string          `json:"task_id"`
	ToolUseID  string          `json:"tool_use_id"`
	Status     string          `json:"status"`
	Summary    string          `json:"summary"`
	OutputFile string          `json:"output_file"`
	Usage      json.RawMessage `json:"usage"`
}

// message is the verbatim Anthropic API message object carried by assistant
// records (and, reduced to {role, content}, by user records). The non-partial
// assistant record arrives once PER CONTENT BLOCK sharing one id (P11) —
// merge by id, never assume one stream line = one logical message.
type message struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	Role         string          `json:"role"`
	Model        string          `json:"model"`
	Content      []contentBlock  `json:"content"`
	StopReason   string          `json:"stop_reason"`
	StopSequence json.RawMessage `json:"stop_sequence"`
	Usage        json.RawMessage `json:"usage"`
}

// contentBlock is one message content block. The top-level key set is
// IDENTICAL across mcp/agent/skill/native tool_use blocks ({type, id, name,
// input, caller}, caller always {type:"direct"}) — classification is by
// name+input only, never by keys or caller (P14). tool_result Content is a
// block array on success and a BARE STRING when IsError (P13); a ToolSearch
// hop's tool_result carries the tool_reference subtype {tool_name} (P14).
type contentBlock struct {
	Type string `json:"type"`

	// text
	Text string `json:"text,omitempty"`

	// thinking
	Thinking  string `json:"thinking,omitempty"`
	Signature string `json:"signature,omitempty"`

	// tool_use
	ID     string          `json:"id,omitempty"`
	Name   string          `json:"name,omitempty"`
	Input  json.RawMessage `json:"input,omitempty"`
	Caller json.RawMessage `json:"caller,omitempty"`

	// tool_result
	ToolUseID string          `json:"tool_use_id,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
	Content   json.RawMessage `json:"content,omitempty"`

	// tool_reference (the ToolSearch deferred-tool hop, P14)
	Subtype  string `json:"subtype,omitempty"`
	ToolName string `json:"tool_name,omitempty"`
}

// assistantRecord is one assistant stream line — a model turn.
type assistantRecord struct {
	Type            string  `json:"type"`
	UUID            string  `json:"uuid"`
	SessionID       string  `json:"session_id"`
	ParentToolUseID string  `json:"parent_tool_use_id"`
	RequestID       string  `json:"request_id"`
	Message         message `json:"message"`
}

// userRecord is a tool result OR a nested subagent prompt. IsReplay:true is
// the unambiguous discriminator for an echoed/acked input — an ACK marker,
// never a tree node; skip entirely (P4). ToolUseResult is a bare "Error: …"
// string on failure vs a structured object on success (P13).
type userRecord struct {
	Type            string          `json:"type"`
	UUID            string          `json:"uuid"`
	SessionID       string          `json:"session_id"`
	ParentToolUseID string          `json:"parent_tool_use_id"`
	IsReplay        bool            `json:"isReplay"`
	Timestamp       string          `json:"timestamp"`
	ToolUseResult   json.RawMessage `json:"tool_use_result"`
	Message         message         `json:"message"`
}

// permissionDenial is one result.permission_denials[] entry (P5/P8).
type permissionDenial struct {
	ToolName  string          `json:"tool_name"`
	ToolUseID string          `json:"tool_use_id"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// resultRecord is the terminal record. Subtype is the closed set {success,
// error_during_execution, error_max_turns, error_max_budget_usd,
// error_max_structured_output_retries} (P13). terminal_reason is dropped on
// the budget terminal; api_error_status is present only on success; never
// branch on stop_reason (P9: nondeterministic between tool_use/end_turn).
type resultRecord struct {
	Type              string             `json:"type"`
	Subtype           string             `json:"subtype"`
	UUID              string             `json:"uuid"`
	SessionID         string             `json:"session_id"`
	IsError           bool               `json:"is_error"`
	NumTurns          int                `json:"num_turns"`
	StopReason        string             `json:"stop_reason"`
	TerminalReason    string             `json:"terminal_reason"`
	Result            string             `json:"result"`
	Errors            []string           `json:"errors"`
	TotalCostUSD      float64            `json:"total_cost_usd"`
	DurationMS        int64              `json:"duration_ms"`
	DurationAPIMS     int64              `json:"duration_api_ms"`
	TTFTMS            int64              `json:"ttft_ms"`
	TTFTStreamMS      int64              `json:"ttft_stream_ms"`
	TimeToRequestMS   int64              `json:"time_to_request_ms"`
	APIErrorStatus    json.RawMessage    `json:"api_error_status"`
	PermissionDenials []permissionDenial `json:"permission_denials"`
	Usage             json.RawMessage    `json:"usage"`
	ModelUsage        json.RawMessage    `json:"modelUsage"`
}

// streamEventRecord is one --include-partial-messages record. Render channel
// ONLY (P11): the non-partial records are authoritative; non-stream records
// can straddle mid-envelope; anchor on content_block_stop/message_stop, never
// on tool_result position. ttft_ms appears only on message_start.
type streamEventRecord struct {
	Type            string          `json:"type"`
	UUID            string          `json:"uuid"`
	SessionID       string          `json:"session_id"`
	ParentToolUseID string          `json:"parent_tool_use_id"`
	TTFTMS          int64           `json:"ttft_ms"`
	Event           streamEventBody `json:"event"`
}

// streamEventBody is the raw Anthropic streaming event: message_start →
// (content_block_start → content_block_delta* → content_block_stop)* →
// message_delta → message_stop. Index is per-message and resets at each
// message_start (P10) — it can never order records across messages.
type streamEventBody struct {
	Type         string          `json:"type"`
	Index        int             `json:"index"`
	ContentBlock json.RawMessage `json:"content_block"`
	Delta        streamDelta     `json:"delta"`
	Message      json.RawMessage `json:"message"`
	Usage        json.RawMessage `json:"usage"`
}

// streamDelta is a content_block_delta or message_delta payload. For
// input_json_delta, concatenate PartialJSON per index and JSON-parse only at
// content_block_stop — the first delta is an empty priming string and
// intermediate concatenations are invalid JSON by design (P11).
type streamDelta struct {
	Type         string          `json:"type"`
	Text         string          `json:"text"`
	Thinking     string          `json:"thinking"`
	PartialJSON  string          `json:"partial_json"`
	Signature    string          `json:"signature"`
	StopReason   string          `json:"stop_reason"`
	StopSequence json.RawMessage `json:"stop_sequence"`
}

// rateLimitRecord is rate_limit_event. Semantics under load are unfixed
// (P18) — the projection marks them provisional.
type rateLimitRecord struct {
	Type          string        `json:"type"`
	UUID          string        `json:"uuid"`
	SessionID     string        `json:"session_id"`
	RateLimitInfo rateLimitInfo `json:"rate_limit_info"`
}

type rateLimitInfo struct {
	RateLimitType         string          `json:"rateLimitType"`
	Status                string          `json:"status"`
	ResetsAt              json.RawMessage `json:"resetsAt"`
	IsUsingOverage        bool            `json:"isUsingOverage"`
	OverageStatus         string          `json:"overageStatus"`
	OverageDisabledReason string          `json:"overageDisabledReason"`
}

// controlRequestRecord is the native control-channel ask (P8):
// control_request{request_id, request:{subtype:"can_use_tool", …}}. The
// richer fields (display_name, permission_suggestions[], agent_id,
// decision_reason*, classifier_approvable) exist ONLY on this channel — the
// prompt-tool route cannot source them.
//
// LIVE-VERIFIED 2026-06-12 (keystone 01KTXBG14J; re-pin pass): the live
// can_use_tool request carried tool_name/display_name/input/description/
// permission_suggestions[]/decision_reason_type/tool_use_id, but agent_id,
// classifier_approvable, blocked_path, and decision_reason were ABSENT on a
// benign-Bash ask — they are DECISION-CONDITIONAL, not always-present (the
// binary populates them only when the decision has them, e.g. a path-blocked or
// agent-scoped ask). A decoder must treat them as optional (the omitempty-free
// fields here zero-value cleanly). Live permission_suggestions[] shape is
// {type:"addRules", rules:[{toolName, ruleContent}], behavior, destination} and
// live decision_reason_type was "subcommandResults" (DRIVE-FINDINGS.md §1).
type controlRequestRecord struct {
	Type      string             `json:"type"`
	UUID      string             `json:"uuid"`
	SessionID string             `json:"session_id"`
	RequestID string             `json:"request_id"`
	Request   controlRequestBody `json:"request"`
}

type controlRequestBody struct {
	Subtype               string          `json:"subtype"`
	ToolName              string          `json:"tool_name"`
	DisplayName           string          `json:"display_name"`
	Input                 json.RawMessage `json:"input"`
	Description           string          `json:"description"`
	PermissionSuggestions json.RawMessage `json:"permission_suggestions"`
	BlockedPath           string          `json:"blocked_path"`
	DecisionReason        json.RawMessage `json:"decision_reason"`
	DecisionReasonType    string          `json:"decision_reason_type"`
	ClassifierApprovable  bool            `json:"classifier_approvable"`
	ToolUseID             string          `json:"tool_use_id"`
	AgentID               string          `json:"agent_id"`
}

// controlResponseRecord is the ask answer (P8):
// control_response{response:{subtype:"success", request_id,
// response:{behavior, …}}}. The initialize-handshake response carries
// pending_permission_requests[] (and pending_user_dialog_requests[]) so a
// re-attaching client re-arms in-flight/parked asks.
//
// LIVE-VERIFIED 2026-06-12 (keystone 01KTXBG14J; re-pin pass): pending_*
// requests were ABSENT on every live initialize response — they are CONDITIONAL
// riders present only on re-attach to a session with parked asks, not always-
// present fields. STILL-UNMODELLED (documented gap, not yet added here, no
// behavior change in the re-pin pass): the live initialize response ALSO carries
// a capability/registry block {commands[], agents[], models[], output_style,
// available_output_styles[], account{tokenSource,apiProvider}, pid} that this
// struct does not model. An adapter that needs the command/agent/model registry
// from the handshake must add it (it overlaps but is NOT identical to
// system/init's name arrays — init lists names, this lists objects with
// descriptions). DRIVE-FINDINGS.md §1a.
type controlResponseRecord struct {
	Type      string              `json:"type"`
	UUID      string              `json:"uuid"`
	SessionID string              `json:"session_id"`
	Response  controlResponseBody `json:"response"`
}

type controlResponseBody struct {
	Subtype   string          `json:"subtype"`
	RequestID string          `json:"request_id"`
	Response  controlDecision `json:"response"`

	// initialize-handshake riders (P8 re-arm; doc 15 §6.1 row 5: the
	// socket-hold is the open control_request itself, carried as ask-event
	// payload, never state vocabulary).
	PendingPermissionRequests []pendingPermissionRequest `json:"pending_permission_requests"`
	PendingUserDialogRequests json.RawMessage            `json:"pending_user_dialog_requests"`
}

// controlDecision is the answered ask: allow returns updatedInput (+ optional
// updatedPermissions); deny returns a message (which propagates verbatim into
// the is_error tool_result and result.permission_denials[], P8); timeout
// resolves as behavior "cancelled".
type controlDecision struct {
	Behavior           string          `json:"behavior"`
	UpdatedInput       json.RawMessage `json:"updatedInput"`
	UpdatedPermissions json.RawMessage `json:"updatedPermissions"`
	Message            string          `json:"message"`
}

// pendingPermissionRequest is one re-armed ask from the initialize response.
type pendingPermissionRequest struct {
	RequestID             string          `json:"request_id"`
	ToolName              string          `json:"tool_name"`
	Input                 json.RawMessage `json:"input"`
	ToolUseID             string          `json:"tool_use_id"`
	AgentID               string          `json:"agent_id"`
	PermissionSuggestions json.RawMessage `json:"permission_suggestions"`
}
