// SPDX-License-Identifier: Apache-2.0

package main

// contentsource_live.go supplies the production adapter main.go's liveDeps wires onto the
// READ-STREAM content seam (controlplane.ContentSource, declared narrow in
// internal/controlplane/contentrelay.go because the orchestrator may not import the host-agent
// runtime module directly — the only legal cross-tree import is proto/gen/go, enforced by the
// import-boundary gate). It is the READ-LEG twin of the W3 write leg (drivesink_live.go):
// constructed ONLY under DS_ORCH_LIVE=1 (a non-live run never resolves liveDeps, D50),
// fail-CLOSED when its backing is absent (a nil source leaves the content relay unconstructed —
// the WatchSession fan-out then carries only the control edges, exactly today's degrade, doc 15
// §5.3), and exercised OFFLINE by unit tests over a synthetic host-agent endpoint (D50: no live
// VM/host-agent/CC in CI).
//
// WHAT THIS CLOSES. The content relay (contentrelay.go) landed the full per-session pump +
// isContentEvent read-only boundary + Fanout publish, but main.go left Deps.ContentSource nil,
// so a live run's fan-out carried the D3 state edges (attachrelay.go), the WRITER_SEAT_CHANGED
// handoff (the SeatArbiter), and the InputActivity write projection (writerrelay.go) — but NO
// CC CONTENT. A non-writer reader saw seat/state edges and no chat/tool output. This is the
// missing INBOUND host-agent client for the read leg: it attaches to the host-agent's per-
// session bridge as a D61 READER over the framed-UDS RELAY carrier, decodes the bridge's
// frameEvent stream, and surfaces each decoded CC content event on the ContentSource channel the
// relay pumps into the SAME Fanout every N-reader subscribes to (the symmetric twin of the
// write leg: drivesink_live.go carries an admitted frame host-ward to CC stdin; this carries
// CC's projected content control-plane-ward to the fan-out).
//
// WHY A HAND-ROLLED WIRE, NOT AN IMPORT OF client/hostbridge. The host-agent bridge's framed-UDS
// carrier + its projected attach.Event working model live in the client/ tree (a SEPARATE Go
// module). The orchestrator may not import them (the import-boundary gate forbids any cross-tree
// Go import but proto/gen/go), so — exactly as the write leg does — this leg speaks the bridge's
// DOCUMENTED framed-UDS wire directly with a stdlib-only codec (the SAME no-shared-crate, no-FFI
// discipline, D40/D67). The shared wire — the frame TLV codec (writeBridgeFrame/readBridgeFrame),
// the attach-handshake handle shape (wireAttachHandle), the reject mapping (rejectError), the
// frame number space (incl. the READER role + the resume ring frames) — is single-sourced in
// wire.go (the write leg speaks the SAME file). This leg additionally reuses the write leg's
// per-session endpoint resolver (driveEndpointResolver / overlayDriveEndpointResolver — the SAME
// overlay attach-token store + attach socket dir the write leg dials). It ADDS only the read-side
// frameEvent DECODE, the resume-ring replay on re-open (D61 slow-reader recovery), and the
// attach.Event-JSON → attach.v1.SessionEvent projection. The decode shapes it mirrors are:
//
//	frameEvent (server→client, client/hostbridge/socket.go frameEvent = 4): one attach.Event
//	JSON — the host-agent bridge's projected content event (client/wrapper/attach.Event, the OSS
//	working model). frameEnd (= 7) marks the session terminal (the stream close).
//
// The attach.Event JSON shape is mirrored LOCALLY here as wireContentEvent (the SAME json tags
// client/wrapper/attach/attach.go declares, so the bytes the bridge marshals decode here), and
// projected onto the frozen attach.v1.SessionEvent — the REVERSE of serpent-tui's
// internal/eventmap.FromProto (which maps proto → attach.Event for the writer-seat TUI). A
// host-agent bridge that changes this wire is a coordinated change on BOTH sides; the offline
// test pins this consumer half against a synthetic server that mirrors it.
//
// READ-ONLY BY CONSTRUCTION (D136 spectators). This leg only READS: it presents a READER attach
// handle (never the WRITER seat) and pushes decoded events onto the relay's channel — it drives
// NO input. The content relay additionally enforces the read-only content boundary at the seam
// (isContentEvent drops any control edge a source yields), so even a decoded SESSION_STATE /
// WRITER_SEAT_CHANGED / INPUT_ACTIVITY never re-enters the fan-out through the content leg (they
// keep their own authoritative producers). This adapter therefore projects EVERY decoded event
// faithfully (including the envelope Type) and lets the relay's filter be the single choke point.
//
// NEVER-LOG-THE-CONTENT (D73). Nothing here logs a decoded event's body or the attach token; the
// bytes cross the wire opaquely and every error names only the session + the structural fault.
// The live e2e (a real host-agent bridge relaying a real CC session's content) is operator-gated
// — the unit tests validate this consumer against a synthetic endpoint; the remaining live-
// validation steps are recorded as a taskdb note.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/controlplane"
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// The shared framed-UDS wire this leg speaks — the frame codec, the attach handle, the reject
// mapping, the frame number space (incl. bridgeRoleReader + the resume-ring frames
// bridgeFrameResume/ResumeReply/ResumeReject and bridgeResumeRejectCode) — is defined in wire.go
// (single source, mirrored by the WRITE leg too). This file uses those symbols and adds the
// read-side decode + resume replay below.

// --- the mirrored attach.Event JSON wire shape (the consumer half of the bridge frameEvent) ---
//
// wireContentEvent is the local Go shape of the host-agent bridge's projected attach.Event JSON
// (client/wrapper/attach/attach.go), declared here with the SAME json tags so the bytes the
// bridge marshals decode into it. It is NOT the frozen proto (the bridge speaks its OSS working
// model over the wire, not attach.v1); toSessionEvent projects it onto the frozen
// attach.v1.SessionEvent the fan-out carries. Exactly one payload pointer is non-nil, matching
// the Type discriminator (the "exactly one non-nil" contract attach.Event holds).
type wireContentEvent struct {
	Seq        uint64    `json:"seq"`
	SessionID  string    `json:"session_id"`
	ObservedAt time.Time `json:"observed_at"` // adapter clock (RFC3339 on the wire); projected to unix millis
	Type       string    `json:"type"`
	Source     []string  `json:"source,omitempty"`

	SessionInit       *wireSessionInit       `json:"session_init,omitempty"`
	SessionState      *wireSessionState      `json:"session_state,omitempty"`
	ChatMessage       *wireChatMessage       `json:"chat_message,omitempty"`
	ChatDelta         *wireChatDelta         `json:"chat_delta,omitempty"`
	ToolInvoked       *wireToolInvoked       `json:"tool_invoked,omitempty"`
	ToolCompleted     *wireToolCompleted     `json:"tool_completed,omitempty"`
	SubagentSpawned   *wireSubagentSpawned   `json:"subagent_spawned,omitempty"`
	SubagentProgress  *wireSubagentProgress  `json:"subagent_progress,omitempty"`
	SubagentCompleted *wireSubagentCompleted `json:"subagent_completed,omitempty"`
	SubagentAccounted *wireSubagentAccounted `json:"subagent_accounted,omitempty"`
	AskRequested      *wireAskRequested      `json:"ask_requested,omitempty"`
	AskResolved       *wireAskResolved       `json:"ask_resolved,omitempty"`
	PlanDelta         *wirePlanDelta         `json:"plan_delta,omitempty"`
	QuotaUpdated      *wireQuotaUpdated      `json:"quota_updated,omitempty"`
	SessionAccounted  *wireSessionAccounted  `json:"session_accounted,omitempty"`
}

// The mirrored attach.v1 content payloads (the SAME json tags as client/wrapper/attach). Only
// the fields the fan-out carries are named; each maps field-for-field onto the frozen proto in
// toSessionEvent. SessionState is mirrored so a decoded state event carries its name through the
// envelope, but the relay's isContentEvent filter DROPS it (it is a control edge, not content),
// so this leg never re-originates a state edge.

type wireSessionInit struct {
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

type wireSessionState struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

type wireChatBlock struct {
	Kind string `json:"kind"`
	Text string `json:"text"`
}

type wireChatMessage struct {
	MessageID    string          `json:"message_id"`
	Role         string          `json:"role"`
	ParentNodeID string          `json:"parent_node_id,omitempty"`
	Blocks       []wireChatBlock `json:"blocks"`
}

type wireChatDelta struct {
	MessageID    string `json:"message_id"`
	ParentNodeID string `json:"parent_node_id,omitempty"`
	BlockIndex   int32  `json:"block_index"`
	Kind         string `json:"kind"`
	Text         string `json:"text,omitempty"`
	Final        bool   `json:"final,omitempty"`
}

type wireToolInvoked struct {
	NodeID       string          `json:"node_id"`
	Name         string          `json:"name"`
	Kind         string          `json:"kind"`
	Server       string          `json:"server,omitempty"`
	Tool         string          `json:"tool,omitempty"`
	Skill        string          `json:"skill,omitempty"`
	ParentNodeID string          `json:"parent_node_id,omitempty"`
	TurnGroup    string          `json:"turn_group,omitempty"`
	Input        json.RawMessage `json:"input,omitempty"`
}

type wireToolCompleted struct {
	NodeID        string `json:"node_id"`
	IsError       bool   `json:"is_error,omitempty"`
	OutputExcerpt string `json:"output_excerpt,omitempty"`
	DenialMessage string `json:"denial_message,omitempty"`
}

type wireSubagentSpawned struct {
	NodeID           string `json:"node_id"`
	TaskID           string `json:"task_id,omitempty"`
	SubagentType     string `json:"subagent_type,omitempty"`
	Description      string `json:"description,omitempty"`
	PromptExcerpt    string `json:"prompt_excerpt,omitempty"`
	TaskType         string `json:"task_type,omitempty"`
	ParentNodeID     string `json:"parent_node_id,omitempty"`
	ParentConfidence string `json:"parent_confidence,omitempty"`
	TurnGroup        string `json:"turn_group,omitempty"`
}

type wireSubagentProgress struct {
	NodeID          string          `json:"node_id"`
	TaskID          string          `json:"task_id,omitempty"`
	LastToolName    string          `json:"last_tool_name,omitempty"`
	ElapsedMS       int64           `json:"elapsed_ms,omitempty"`
	UsageRaw        json.RawMessage `json:"usage_raw,omitempty"`
	Uncharacterized bool            `json:"uncharacterized,omitempty"`
}

type wireSubagentCompleted struct {
	NodeID     string `json:"node_id"`
	TaskID     string `json:"task_id,omitempty"`
	Status     string `json:"status,omitempty"`
	Summary    string `json:"summary,omitempty"`
	OutputFile string `json:"output_file,omitempty"`
}

type wireContinuation struct {
	AgentID string `json:"agent_id"`
	Hint    string `json:"hint"`
}

type wireSubagentAccounted struct {
	NodeID         string            `json:"node_id"`
	AgentID        string            `json:"agent_id,omitempty"`
	SubagentTokens int64             `json:"subagent_tokens,omitempty"`
	ToolUses       int64             `json:"tool_uses,omitempty"`
	DurationMS     int64             `json:"duration_ms,omitempty"`
	OutputExcerpt  string            `json:"output_excerpt,omitempty"`
	IsError        bool              `json:"is_error,omitempty"`
	ReturnedTo     string            `json:"returned_to,omitempty"`
	Continuation   *wireContinuation `json:"continuation,omitempty"`
}

type wireAskRequested struct {
	AskID       string          `json:"ask_id"`
	NodeID      string          `json:"node_id"`
	ToolName    string          `json:"tool_name,omitempty"`
	Input       json.RawMessage `json:"input,omitempty"`
	Suggestions json.RawMessage `json:"suggestions,omitempty"`
	AgentID     string          `json:"agent_id,omitempty"`
	Source      string          `json:"source"`
	Pending     bool            `json:"pending,omitempty"`
}

type wireAskResolved struct {
	AskID          string `json:"ask_id"`
	NodeID         string `json:"node_id"`
	Behavior       string `json:"behavior"`
	Classification string `json:"classification,omitempty"`
	Message        string `json:"message,omitempty"`
}

type wireTodoItem struct {
	Content    string `json:"content"`
	Status     string `json:"status"`
	ActiveForm string `json:"active_form,omitempty"`
	ID         string `json:"id,omitempty"`
}

type wirePlanDelta struct {
	NodeID        string         `json:"node_id"`
	Kind          string         `json:"kind"`
	Todos         []wireTodoItem `json:"todos,omitempty"`
	Plan          string         `json:"plan,omitempty"`
	ApprovalState string         `json:"approval_state,omitempty"`
}

type wireQuotaUpdated struct {
	RateLimitType         string          `json:"rate_limit_type,omitempty"`
	Status                string          `json:"status,omitempty"`
	ResetsAt              json.RawMessage `json:"resets_at,omitempty"`
	IsUsingOverage        bool            `json:"is_using_overage,omitempty"`
	OverageStatus         string          `json:"overage_status,omitempty"`
	OverageDisabledReason string          `json:"overage_disabled_reason,omitempty"`
	Semantics             string          `json:"semantics"`
}

type wireSessionAccounted struct {
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

// --- the live ContentSource ---

// hostAgentContentSource is the production controlplane.ContentSource: it opens a READ-ONLY
// stream of a session's projected CC content by attaching to the host-agent's per-session bridge
// as a D61 READER over the framed-UDS RELAY carrier, decoding each frameEvent's attach.Event JSON
// into a frozen attach.v1.SessionEvent, and yielding them on a channel the content relay pumps
// into the Fanout. Unlike the write leg it caches NO per-session CONNECTION: the relay drives one
// OpenContent per open and re-opens after a transient close (contentrelay.go run()), so each
// OpenContent is a fresh reader attach (a reader attach never contends the writer seat).
//
// IT DOES keep a tiny per-session RESUME CURSOR — the highest host-side seq it has delivered — so
// a re-open REPLAYS the bridge's bounded history ring (frameResume/frameResumeReply) from that
// cursor instead of rejoining at the live head (D61 slow-reader recovery). Without it a transient
// host-side drop leaves a spectator with a permanent content GAP (the events published between the
// drop and the re-open never reach the fan-out); with it the gap is replayed exactly once before
// the live stream resumes. It is the read-ward mirror of hostAgentDriveSink, reusing that leg's
// endpoint resolver + the shared frame codec (wire.go).
type hostAgentContentSource struct {
	resolve driveEndpointResolver
	// dial connects the host-local relay UDS. Injectable so a test can exercise dial faults; the
	// production default is a UDS net.Dialer bounded by defaultRelayDialTimeout (the SAME dialer
	// shape the write leg installs).
	dial func(ctx context.Context, address string) (net.Conn, error)
	// handshakeTimeout bounds the reader attach handshake; 0 ⇒ defaultRelayHandshakeTimeout.
	handshakeTimeout time.Duration

	// mu guards the resume cursor + the drop counters. OpenContent/pump run one-at-a-time per
	// session (the relay drives a single pump goroutine per session), but a test may read the
	// counters concurrently, so every access is under the lock.
	mu sync.Mutex
	// lastSeq is the highest host-side seq (attach.Event.Seq) delivered on the seam per session.
	// A re-open resumes from it; 0 ⇒ never delivered ⇒ no resume (rejoin at head is correct — a
	// first attach has no gap to recover).
	lastSeq map[string]uint64
	// droppedEnvelopeOnly counts content events dropped at decode because their type was set but
	// the payload pointer was absent (a hollow envelope a misbehaving source cannot turn into a
	// fan-out event). droppedMalformed counts non-JSON frameEvent bodies skipped. Both are
	// observability for the fail-closed decode (surfaced via the accessors below).
	droppedEnvelopeOnly uint64
	droppedMalformed    uint64
}

// newHostAgentContentSource builds the live source over the endpoint resolver. A nil resolver is
// a wiring bug rejected at construction (fail-closed: a source that cannot resolve where to dial
// could never open a stream). The production dialer is installed here; a test overrides it after
// construction.
func newHostAgentContentSource(resolve driveEndpointResolver) (*hostAgentContentSource, error) {
	if resolve == nil {
		return nil, fmt.Errorf("content source: nil endpoint resolver (no way to resolve the relay endpoint)")
	}
	return &hostAgentContentSource{
		resolve: resolve,
		dial: func(ctx context.Context, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: defaultRelayDialTimeout}
			return d.DialContext(ctx, "unix", address)
		},
		lastSeq: make(map[string]uint64),
	}, nil
}

// resumeAfter returns the seq a re-open should resume the history ring from (the highest seq
// delivered so far for the session). 0 ⇒ no prior delivery ⇒ no resume (a first attach).
func (s *hostAgentContentSource) resumeAfter(sessionUUID string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq[sessionUUID]
}

// recordSeq advances the session's resume cursor to seq if it is higher (monotone high-water
// mark). A zero seq (an unsequenced event) never moves the cursor.
func (s *hostAgentContentSource) recordSeq(sessionUUID string, seq uint64) {
	if seq == 0 {
		return
	}
	s.mu.Lock()
	if seq > s.lastSeq[sessionUUID] {
		s.lastSeq[sessionUUID] = seq
	}
	s.mu.Unlock()
}

// countEnvelopeOnly / countMalformed advance the fail-closed decode drop counters.
func (s *hostAgentContentSource) countEnvelopeOnly() {
	s.mu.Lock()
	s.droppedEnvelopeOnly++
	s.mu.Unlock()
}

func (s *hostAgentContentSource) countMalformed() {
	s.mu.Lock()
	s.droppedMalformed++
	s.mu.Unlock()
}

// DroppedEnvelopeOnly / DroppedMalformed report the fail-closed decode drop counts (observability
// for the test + a future metrics hook): events the content leg refused to forward because their
// body was a hollow envelope (type set, payload absent) or non-JSON.
func (s *hostAgentContentSource) DroppedEnvelopeOnly() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.droppedEnvelopeOnly
}

func (s *hostAgentContentSource) DroppedMalformed() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.droppedMalformed
}

// OpenContent opens a read-only subscription to CC's projected content for sessionUUID (the
// controlplane.ContentSource contract). It resolves the session's relay endpoint + attach token,
// dials + performs the READER attach handshake, and — on accept — launches a pump goroutine that
// decodes the bridge's frameEvent stream onto the returned channel, CLOSING it on frameEnd, a
// clean EOF, a transport fault, or ctx cancel (so the relay re-opens while its pump context is
// live, or stops on shutdown). A resolve miss (no provisioned relay / no persisted attach token),
// a dial fault, or a reject is returned as a non-nil err with NO stream opened — the relay logs
// it and retries with a bounded backoff (a not-yet-ready bridge during CREATING is expected).
func (s *hostAgentContentSource) OpenContent(ctx context.Context, sessionUUID string) (<-chan *attachv1.SessionEvent, error) {
	if sessionUUID == "" {
		return nil, fmt.Errorf("content source: OpenContent with empty session uuid")
	}
	ep, ok, err := s.resolve.ResolveRelayEndpoint(ctx, sessionUUID)
	if err != nil {
		return nil, err
	}
	if !ok {
		// Fail-closed: no servable relay endpoint / no session-scoped attach token — the session
		// was never attach-provisioned, so there is no content to read (yet). The relay retries.
		return nil, fmt.Errorf("content source: no relay endpoint for session %q (no persisted attach token — fail-closed)", sessionUUID)
	}

	raw, bw, br, err := s.dialAttach(ctx, sessionUUID, ep)
	if err != nil {
		return nil, err
	}

	out := make(chan *attachv1.SessionEvent)
	go s.pump(ctx, sessionUUID, raw, bw, br, out)
	return out, nil
}

// dialAttach dials the relay UDS and performs the READER attach handshake: it presents a READER
// AttachHandle (the resolved address + the session-scoped token) and awaits frameAccept /
// frameReject. On accept it clears the handshake deadline (the pump reads with no deadline) and
// returns the live conn + its buffered writer (for the resume request) + reader. A reject maps
// back to a readable cause (the SAME rejectError the write leg uses); a dial/handshake fault is
// surfaced. It REUSES the shared wireAttachHandle + frame codec (wire.go) verbatim — only the
// presented role differs (READER, not WRITER).
func (s *hostAgentContentSource) dialAttach(ctx context.Context, sessionUUID string, ep driveRelayEndpoint) (net.Conn, *bufio.Writer, *bufio.Reader, error) {
	raw, err := s.dial(ctx, ep.address)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("content source: dial relay %q for session %q: %w", ep.address, sessionUUID, err)
	}

	handle := wireAttachHandle{
		SessionUUID: sessionUUID,
		Endpoints:   []wireEndpointCandidate{{Transport: bridgeTransportUnix, Address: ep.address}},
		Auth:        wireAuthMaterial{Token: string(ep.token)},
		Role:        bridgeRoleReader,
		ExpiresAt:   ep.expiresAt,
	}
	hjson, err := json.Marshal(handle)
	if err != nil {
		_ = raw.Close()
		return nil, nil, nil, fmt.Errorf("content source: marshal attach handle for session %q: %w", sessionUUID, err)
	}

	hsTimeout := s.handshakeTimeout
	if hsTimeout <= 0 {
		hsTimeout = defaultRelayHandshakeTimeout
	}
	_ = raw.SetDeadline(time.Now().Add(hsTimeout))

	bw := bufio.NewWriter(raw)
	br := bufio.NewReader(raw)
	if err := writeBridgeFrame(bw, bridgeFrameAttach, hjson); err != nil {
		_ = raw.Close()
		return nil, nil, nil, fmt.Errorf("content source: send attach for session %q: %w", sessionUUID, err)
	}
	ft, replyPayload, err := readBridgeFrame(br)
	if err != nil {
		_ = raw.Close()
		return nil, nil, nil, fmt.Errorf("content source: read attach reply for session %q: %w", sessionUUID, err)
	}
	switch ft {
	case bridgeFrameAccept:
		_ = raw.SetDeadline(time.Time{}) // clear: the pump reads with no deadline
		return raw, bw, br, nil
	case bridgeFrameReject:
		_ = raw.Close()
		return nil, nil, nil, rejectError(sessionUUID, replyPayload)
	default:
		_ = raw.Close()
		return nil, nil, nil, fmt.Errorf("content source: unexpected attach reply frame %d for session %q", ft, sessionUUID)
	}
}

// pump reads the server's frame stream, decodes each frameEvent into an attach.v1.SessionEvent,
// and pushes it onto out until the stream ends (frameEnd / clean EOF / transport fault) or ctx is
// cancelled — CLOSING out on every exit path (the relay's drain treats a closed channel as a
// stream close and re-opens while its pump context is live). A ctx-cancel watcher closes the raw
// conn to unblock a blocked read (the pump reads with no deadline).
//
// On a RE-OPEN (a prior delivery advanced the session's resume cursor) it first sends
// frameResume{afterSeq} and REPLAYS the recovered span before the live stream, so a spectator sees
// no content gap after a transient host-side drop (D61). Resume answers (frameResumeReply /
// frameResumeReject) are demultiplexed inline. ORDERING MATTERS here: on the real bridge the
// per-conn outbox drainer and answerResume are independent writers (serialized per-frame only), so
// a live frameEvent with a seq ABOVE the whole span can hit the wire BEFORE the resume reply. If
// the pump delivered it eagerly, the high-water cursor would advance past the span and the replay
// would be dropped wholesale — the exact gap the resume exists to close. So while a resume answer
// is PENDING, live frameEvents are HELD in a bounded buffer; the reply's span is replayed first,
// then the held events flush through the same cursor gate, so ordering is restored and the
// span/live overlap is delivered exactly once. The hold is bounded (events + bytes): a server that
// never answers the resume flushes the hold and degrades to live-head delivery (today's behavior),
// never an unbounded alloc. A frameEvent whose payload fails to decode is SKIPPED (a single
// malformed / envelope-only event never tears an otherwise-live stream), so one bad event does not
// blind a reader to the session.
func (s *hostAgentContentSource) pump(ctx context.Context, sessionUUID string, raw net.Conn, bw *bufio.Writer, br *bufio.Reader, out chan<- *attachv1.SessionEvent) {
	defer close(out)
	defer func() { _ = raw.Close() }()

	// Wake a blocked read when the pump context is cancelled (stop on DESTROYED / shutdown):
	// closing the conn faults the in-flight readBridgeFrame, so the loop exits promptly.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = raw.Close()
		case <-stop:
		}
	}()

	// Re-open resume: replay the ring from the last delivered seq. A first attach (cursor 0) has
	// no gap to recover and sends nothing (rejoin at head is correct). The send is BEST-EFFORT: a
	// resume-send fault (e.g. a server already closing a short stream) must not abandon frames
	// already buffered + readable, so we fall through to the read loop regardless — it surfaces any
	// real transport fault. Only a SUCCESSFUL send arms the pending-answer hold below (a server
	// that never saw the request will never answer it).
	awaitingResume := false
	if afterSeq := s.resumeAfter(sessionUUID); afterSeq > 0 {
		awaitingResume = s.sendResume(raw, bw, afterSeq) == nil
	}
	// held buffers live frameEvent payloads that arrive while the resume answer is pending (the
	// outbox drainer racing ahead of answerResume on the real bridge); they flush — through the
	// same cursor gate — after the span replays, restoring order without loss or duplication.
	var held [][]byte
	heldBytes := 0
	flushHeld := func() bool {
		awaitingResume = false
		for _, blob := range held {
			ev, res := classifyContentEvent(blob)
			if !s.forward(ctx, sessionUUID, ev, res, out) {
				return false
			}
		}
		held, heldBytes = nil, 0
		return true
	}

	for {
		ft, payload, err := readBridgeFrame(br)
		if err != nil {
			return // EOF / transport fault / ctx-close ⇒ terminal; the relay re-opens.
		}
		switch ft {
		case bridgeFrameEnd:
			// The host-side stream ended (CC exited / bridge dropped). A short stream can end
			// before the resume answer lands — deliver anything held rather than dropping it.
			if awaitingResume {
				_ = flushHeld()
			}
			return
		case bridgeFrameEvent:
			if awaitingResume {
				// Hold live events until the resume answer so the span replays FIRST (see the
				// pump doc). The hold is bounded: past the cap, assume the server will not
				// answer and degrade to live-head delivery (the pre-resume behavior).
				held = append(held, payload)
				heldBytes += len(payload)
				if len(held) > maxResumeHoldEvents || heldBytes > maxResumeHoldBytes {
					if !flushHeld() {
						return
					}
				}
				continue
			}
			ev, res := classifyContentEvent(payload)
			if !s.forward(ctx, sessionUUID, ev, res, out) {
				return // ctx cancelled while delivering.
			}
		case bridgeFrameResumeReply:
			// The recovered span (the gap between the drop and this re-open): replay it in seq
			// order before the live head. Each event is decoded + projected + envelope-filtered
			// like a live frameEvent, and dropped if at/below the cursor (exactly-once). Held
			// live events then flush through the same cursor gate (span/live overlap deduped).
			span := decodeResumeSpan(payload)
			for _, blob := range span {
				ev, res := classifyContentEvent(blob)
				if !s.forward(ctx, sessionUUID, ev, res, out) {
					return
				}
			}
			if !flushHeld() {
				return
			}
		case bridgeFrameResumeReject:
			// The ring aged the requested span out (window exceeded), or a server fault answering
			// the resume: the gap is unrecoverable — rejoin at the live head (flushing anything
			// held, in arrival order). Best-effort recovery is additive; a reject never tears the
			// live stream.
			if !flushHeld() {
				return
			}
		default:
			// Any other server frame is discarded: this leg reads content + resume answers only.
		}
	}
}

// maxResumeHoldEvents / maxResumeHoldBytes bound the live-event hold while a resume answer is
// pending (see pump). The real bridge answers a resume inline within one round-trip, so the hold
// is normally a handful of events; the caps only bite when a server takes the resume request and
// never answers — the pump then flushes and degrades to live-head delivery rather than buffering
// without bound.
const (
	maxResumeHoldEvents = 1024
	maxResumeHoldBytes  = 8 << 20
)

// forward delivers one classified event onto out, honoring the fail-closed decode result and the
// per-session resume cursor. It returns false ONLY when ctx was cancelled mid-send (the pump then
// exits). A malformed / envelope-only event is counted + skipped (never forwarded); a live/resumed
// content event at or below the resume cursor is a duplicate already delivered and is dropped
// (exactly-once), otherwise it is delivered and advances the cursor.
func (s *hostAgentContentSource) forward(ctx context.Context, sessionUUID string, ev *attachv1.SessionEvent, res contentDecodeResult, out chan<- *attachv1.SessionEvent) bool {
	switch res {
	case contentDecodeMalformed:
		s.countMalformed()
		return true
	case contentDecodeEnvelopeOnly:
		s.countEnvelopeOnly()
		return true
	}
	// Exactly-once against the resume cursor: a sequenced event we already delivered (seq ≤ the
	// high-water mark) is a resume/live overlap duplicate and is dropped. An unsequenced event
	// (seq 0) is always delivered (the cursor cannot dedup it).
	if seq := ev.GetSeq(); seq != 0 {
		if seq <= s.resumeAfter(sessionUUID) {
			return true
		}
		s.recordSeq(sessionUUID, seq)
	}
	select {
	case out <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

// sendResume writes one frameResume request (8-byte BE afterSeq) under a bounded write deadline so
// a wedged server cannot stall the re-open, then clears the deadline for the pump's deadline-free
// reads. A write fault surfaces so the pump returns and the relay re-dials.
func (s *hostAgentContentSource) sendResume(raw net.Conn, bw *bufio.Writer, afterSeq uint64) error {
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], afterSeq)
	_ = raw.SetWriteDeadline(time.Now().Add(relayWriteTimeout))
	err := writeBridgeFrame(bw, bridgeFrameResume, seq[:])
	_ = raw.SetWriteDeadline(time.Time{})
	return err
}

// decodeResumeSpan unpacks a frameResumeReply payload into the recovered attach.Event JSON blobs:
// a 4-byte BE count, then for each event a 4-byte BE length and the event JSON. It mirrors
// client/hostbridge's decodeSpan, returning the raw JSON blobs (each is classified by the pump the
// SAME way a live frameEvent is). A malformed / truncated / oversized span is rejected fail-closed
// (an empty span, never a panic or an over-allocation) so a bad reply cannot wedge the read leg.
func decodeResumeSpan(payload []byte) [][]byte {
	if len(payload) < 4 {
		return nil
	}
	count := binary.BigEndian.Uint32(payload[:4])
	off := 4
	capHint := count
	if capHint > 1024 {
		capHint = 1024 // bound the pre-alloc; a huge count is validated per-event below.
	}
	out := make([][]byte, 0, capHint)
	for i := uint32(0); i < count; i++ {
		if off+4 > len(payload) {
			return out // truncated: return what parsed cleanly.
		}
		l := binary.BigEndian.Uint32(payload[off : off+4])
		off += 4
		if l > bridgeMaxFrameBytes || off+int(l) > len(payload) {
			return out // an oversized/overrunning length: stop fail-closed.
		}
		blob := make([]byte, l)
		copy(blob, payload[off:off+int(l)])
		out = append(out, blob)
		off += int(l)
	}
	return out
}

var _ controlplane.ContentSource = (*hostAgentContentSource)(nil)

// --- the attach.Event JSON → attach.v1.SessionEvent projection (the reverse of eventmap) ---

// contentDecodeResult is the fail-closed outcome of decoding one frameEvent / resumed-span event.
type contentDecodeResult int

const (
	// contentDecodeOK: a well-formed event with its payload — forward it.
	contentDecodeOK contentDecodeResult = iota
	// contentDecodeMalformed: a non-JSON body — skip + count (never a fatal that tears the stream).
	contentDecodeMalformed
	// contentDecodeEnvelopeOnly: a genuine CONTENT type whose payload pointer was absent — a
	// hollow envelope. Dropped at decode so a misbehaving content source is STRICTLY INERT: it
	// can never push a typed-but-empty content event onto the fan-out. Control-edge types
	// (SESSION_STATE) legitimately carry no payload from this leg and are NOT envelope-only
	// (the relay's isContentEvent filter drops them); UNSPECIFIED is left to that filter too.
	contentDecodeEnvelopeOnly
)

// classifyContentEvent unmarshals one attach.Event JSON payload, projects it onto the frozen
// attach.v1.SessionEvent the fan-out carries, and classifies it. It projects EVERY well-formed
// event (including the envelope Type + control-edge types) so the relay's isContentEvent filter
// stays the single choke point for control edges — but it FAILS CLOSED on a content type that
// arrived without its payload (envelope-only), so the content leg forwards no hollow content event.
func classifyContentEvent(payload []byte) (*attachv1.SessionEvent, contentDecodeResult) {
	var w wireContentEvent
	if err := json.Unmarshal(payload, &w); err != nil {
		return nil, contentDecodeMalformed
	}
	ev := toSessionEvent(&w)
	if isEnvelopeOnlyContent(ev) {
		return ev, contentDecodeEnvelopeOnly
	}
	return ev, contentDecodeOK
}

// decodeContentEvent is the boolean façade over classifyContentEvent (kept for the direct decode
// call sites + tests). ok=false covers BOTH a malformed body and an envelope-only content event —
// either way the pump does not forward it.
func decodeContentEvent(payload []byte) (*attachv1.SessionEvent, bool) {
	ev, res := classifyContentEvent(payload)
	return ev, res == contentDecodeOK
}

// isEnvelopeOnlyContent reports whether ev names a genuine CC CONTENT type but carries no payload
// (the oneof is unset) — a hollow envelope a misbehaving source could use to push a typed-but-empty
// frame onto the read stream. Such an event is dropped at decode (fail-closed). A control-edge type
// (SESSION_STATE) or an unknown/UNSPECIFIED type is NOT envelope-only here — those legitimately
// carry no payload from this leg and are dropped by the relay's isContentEvent filter, the single
// choke point for control edges (this leg never re-originates one).
func isEnvelopeOnlyContent(ev *attachv1.SessionEvent) bool {
	if ev == nil {
		return false
	}
	return isRelayContentType(ev.GetType()) && ev.Payload == nil
}

// isRelayContentType mirrors controlplane.isContentEvent's read-only allowlist (kept in sync
// deliberately — the two packages cannot share an unexported helper across the D40/D67 boundary).
// It is used ONLY to decide whether an absent payload makes an event envelope-only; the relay's
// own isContentEvent remains the authoritative fan-out filter.
func isRelayContentType(t attachv1.EventType) bool {
	switch t {
	case attachv1.EventType_EVENT_TYPE_SESSION_INIT,
		attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE,
		attachv1.EventType_EVENT_TYPE_CHAT_DELTA,
		attachv1.EventType_EVENT_TYPE_TOOL_INVOKED,
		attachv1.EventType_EVENT_TYPE_TOOL_COMPLETED,
		attachv1.EventType_EVENT_TYPE_SUBAGENT_SPAWNED,
		attachv1.EventType_EVENT_TYPE_SUBAGENT_PROGRESS,
		attachv1.EventType_EVENT_TYPE_SUBAGENT_COMPLETED,
		attachv1.EventType_EVENT_TYPE_SUBAGENT_ACCOUNTED,
		attachv1.EventType_EVENT_TYPE_ASK_REQUESTED,
		attachv1.EventType_EVENT_TYPE_ASK_RESOLVED,
		attachv1.EventType_EVENT_TYPE_QUOTA_UPDATED,
		attachv1.EventType_EVENT_TYPE_SESSION_ACCOUNTED,
		attachv1.EventType_EVENT_TYPE_PLAN_DELTA:
		return true
	default:
		return false
	}
}

// toSessionEvent projects the mirrored attach.Event onto the frozen proto. The envelope maps
// directly (observed_at is reconstructed from the wire RFC3339 time to the proto's unix millis —
// the reverse of eventmap.observedAt); the payload is dispatched off the Type discriminator onto
// the matching proto oneof. The Fanout re-stamps seq + session_id (the seq authority, watch.go),
// so a source-supplied seq/session_id is carried for fidelity but not authoritative.
func toSessionEvent(w *wireContentEvent) *attachv1.SessionEvent {
	ev := &attachv1.SessionEvent{
		Seq:        w.Seq,
		SessionId:  w.SessionID,
		ObservedAt: observedAtMillis(w.ObservedAt),
		Type:       toEventType(w.Type),
		Source:     cloneStrings(w.Source),
	}

	switch w.Type {
	case "session.init":
		if p := w.SessionInit; p != nil {
			ev.Payload = &attachv1.SessionEvent_SessionInit{SessionInit: &attachv1.SessionInit{
				RuntimeVersion: p.RuntimeVersion,
				Model:          p.Model,
				Cwd:            p.CWD,
				PermissionMode: p.PermissionMode,
				ApiKeySource:   p.APIKeySource,
				Tools:          cloneStrings(p.Tools),
				AgentTypes:     cloneStrings(p.AgentTypes),
				Skills:         cloneStrings(p.Skills),
				SlashCommands:  cloneStrings(p.SlashCommands),
				McpServers:     cloneBytes(p.MCPServers),
				OutputStyle:    p.OutputStyle,
			}}
		}
	case "session.state":
		// A control edge: mirrored for envelope fidelity, but the relay's isContentEvent filter
		// DROPS it (SESSION_STATE has its own authoritative producer, attachrelay.go). No proto
		// SessionState is projected here — this leg never carries a state edge onto the fan-out.
	case "chat.message":
		if p := w.ChatMessage; p != nil {
			blocks := make([]*attachv1.ChatBlock, 0, len(p.Blocks))
			for _, b := range p.Blocks {
				blocks = append(blocks, &attachv1.ChatBlock{Kind: b.Kind, Text: b.Text})
			}
			ev.Payload = &attachv1.SessionEvent_ChatMessage{ChatMessage: &attachv1.ChatMessage{
				MessageId:    p.MessageID,
				Role:         p.Role,
				ParentNodeId: p.ParentNodeID,
				Blocks:       blocks,
			}}
		}
	case "chat.delta":
		if p := w.ChatDelta; p != nil {
			ev.Payload = &attachv1.SessionEvent_ChatDelta{ChatDelta: &attachv1.ChatDelta{
				MessageId:    p.MessageID,
				ParentNodeId: p.ParentNodeID,
				BlockIndex:   p.BlockIndex,
				Kind:         p.Kind,
				Text:         p.Text,
				Final:        p.Final,
			}}
		}
	case "tool.invoked":
		if p := w.ToolInvoked; p != nil {
			ev.Payload = &attachv1.SessionEvent_ToolInvoked{ToolInvoked: &attachv1.ToolInvoked{
				NodeId:       p.NodeID,
				Name:         p.Name,
				Kind:         p.Kind,
				Server:       p.Server,
				Tool:         p.Tool,
				Skill:        p.Skill,
				ParentNodeId: p.ParentNodeID,
				TurnGroup:    p.TurnGroup,
				Input:        cloneBytes(p.Input),
			}}
		}
	case "tool.completed":
		if p := w.ToolCompleted; p != nil {
			ev.Payload = &attachv1.SessionEvent_ToolCompleted{ToolCompleted: &attachv1.ToolCompleted{
				NodeId:        p.NodeID,
				IsError:       p.IsError,
				OutputExcerpt: p.OutputExcerpt,
				DenialMessage: p.DenialMessage,
			}}
		}
	case "subagent.spawned":
		if p := w.SubagentSpawned; p != nil {
			ev.Payload = &attachv1.SessionEvent_SubagentSpawned{SubagentSpawned: &attachv1.SubagentSpawned{
				NodeId:           p.NodeID,
				TaskId:           p.TaskID,
				SubagentType:     p.SubagentType,
				Description:      p.Description,
				PromptExcerpt:    p.PromptExcerpt,
				TaskType:         p.TaskType,
				ParentNodeId:     p.ParentNodeID,
				ParentConfidence: p.ParentConfidence,
				TurnGroup:        p.TurnGroup,
			}}
		}
	case "subagent.progress":
		if p := w.SubagentProgress; p != nil {
			ev.Payload = &attachv1.SessionEvent_SubagentProgress{SubagentProgress: &attachv1.SubagentProgress{
				NodeId:          p.NodeID,
				TaskId:          p.TaskID,
				LastToolName:    p.LastToolName,
				ElapsedMs:       p.ElapsedMS,
				UsageRaw:        cloneBytes(p.UsageRaw),
				Uncharacterized: p.Uncharacterized,
			}}
		}
	case "subagent.completed":
		if p := w.SubagentCompleted; p != nil {
			ev.Payload = &attachv1.SessionEvent_SubagentCompleted{SubagentCompleted: &attachv1.SubagentCompleted{
				NodeId:     p.NodeID,
				TaskId:     p.TaskID,
				Status:     p.Status,
				Summary:    p.Summary,
				OutputFile: p.OutputFile,
			}}
		}
	case "subagent.accounted":
		if p := w.SubagentAccounted; p != nil {
			acc := &attachv1.SubagentAccounted{
				NodeId:         p.NodeID,
				AgentId:        p.AgentID,
				SubagentTokens: p.SubagentTokens,
				ToolUses:       p.ToolUses,
				DurationMs:     p.DurationMS,
				OutputExcerpt:  p.OutputExcerpt,
				IsError:        p.IsError,
				ReturnedTo:     p.ReturnedTo,
			}
			if c := p.Continuation; c != nil {
				acc.Continuation = &attachv1.Continuation{AgentId: c.AgentID, Hint: c.Hint}
			}
			ev.Payload = &attachv1.SessionEvent_SubagentAccounted{SubagentAccounted: acc}
		}
	case "ask.requested":
		if p := w.AskRequested; p != nil {
			// The working model collapses the proto's distinct tool_use_id / request_id into one
			// AskID ("the control request id if present, else the tool-use id") and carries the
			// tool-use id as NodeID. Reversing: NodeID IS the tool-use id (the correlation key),
			// so tool_use_id = node_id; request_id = ask_id (preserving the control-answer key
			// end-to-end); node_id = node_id.
			ev.Payload = &attachv1.SessionEvent_AskRequested{AskRequested: &attachv1.AskRequested{
				ToolUseId:   p.NodeID,
				RequestId:   p.AskID,
				NodeId:      p.NodeID,
				ToolName:    p.ToolName,
				Input:       cloneBytes(p.Input),
				Suggestions: cloneBytes(p.Suggestions),
				AgentId:     p.AgentID,
				Source:      p.Source,
				Pending:     p.Pending,
			}}
		}
	case "ask.resolved":
		if p := w.AskResolved; p != nil {
			ev.Payload = &attachv1.SessionEvent_AskResolved{AskResolved: &attachv1.AskResolved{
				ToolUseId:      p.NodeID,
				RequestId:      p.AskID,
				NodeId:         p.NodeID,
				Behavior:       p.Behavior,
				Classification: p.Classification,
				Message:        p.Message,
			}}
		}
	case "plan.delta":
		if p := w.PlanDelta; p != nil {
			pd := &attachv1.PlanDelta{
				ToolUseId:     p.NodeID,
				Kind:          toPlanDeltaKind(p.Kind),
				Plan:          p.Plan,
				ApprovalState: toPlanApprovalState(p.ApprovalState),
			}
			if len(p.Todos) > 0 {
				pd.Todos = make([]*attachv1.TodoItem, 0, len(p.Todos))
				for _, t := range p.Todos {
					pd.Todos = append(pd.Todos, &attachv1.TodoItem{
						Content:    t.Content,
						Status:     t.Status,
						ActiveForm: t.ActiveForm,
						Id:         t.ID,
					})
				}
			}
			ev.Payload = &attachv1.SessionEvent_PlanDelta{PlanDelta: pd}
		}
	case "quota.updated":
		if p := w.QuotaUpdated; p != nil {
			ev.Payload = &attachv1.SessionEvent_QuotaUpdated{QuotaUpdated: &attachv1.QuotaUpdated{
				RateLimitType:         p.RateLimitType,
				Status:                p.Status,
				ResetsAt:              cloneBytes(p.ResetsAt),
				IsUsingOverage:        p.IsUsingOverage,
				OverageStatus:         p.OverageStatus,
				OverageDisabledReason: p.OverageDisabledReason,
				Semantics:             p.Semantics,
			}}
		}
	case "session.accounted":
		if p := w.SessionAccounted; p != nil {
			ev.Payload = &attachv1.SessionEvent_SessionAccounted{SessionAccounted: &attachv1.SessionAccounted{
				Outcome:        p.Outcome,
				IsError:        p.IsError,
				NumTurns:       int64(p.NumTurns),
				DurationMs:     p.DurationMS,
				TotalCostUsd:   p.TotalCostUSD,
				TerminalReason: p.TerminalReason,
				Errors:         cloneStrings(p.Errors),
				Usage:          cloneBytes(p.Usage),
				ModelUsage:     cloneBytes(p.ModelUsage),
				DenialCount:    int64(p.DenialCount),
			}}
		}
	default:
		// An unknown/UNSPECIFIED type carries its envelope only; toEventType maps it to
		// UNSPECIFIED and the relay's isContentEvent filter drops it (fail-closed on the unknown).
	}
	return ev
}

// observedAtMillis reconstructs the proto's unix-millis clock from the wire RFC3339 time (the
// reverse of eventmap.observedAt). A zero time maps to 0 (unset) so a replay is stable.
func observedAtMillis(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	ms := t.UnixMilli()
	if ms < 0 {
		return 0
	}
	return uint64(ms)
}

// toEventType maps the attach.Event Type discriminator string (client/wrapper/attach.Type)
// onto the frozen proto EventType — the reverse of eventmap.eventType. An unknown string maps to
// UNSPECIFIED (the relay's isContentEvent filter then drops it: fail-closed on the unknown).
func toEventType(t string) attachv1.EventType {
	switch t {
	case "session.init":
		return attachv1.EventType_EVENT_TYPE_SESSION_INIT
	case "session.state":
		return attachv1.EventType_EVENT_TYPE_SESSION_STATE
	case "chat.message":
		return attachv1.EventType_EVENT_TYPE_CHAT_MESSAGE
	case "chat.delta":
		return attachv1.EventType_EVENT_TYPE_CHAT_DELTA
	case "tool.invoked":
		return attachv1.EventType_EVENT_TYPE_TOOL_INVOKED
	case "tool.completed":
		return attachv1.EventType_EVENT_TYPE_TOOL_COMPLETED
	case "subagent.spawned":
		return attachv1.EventType_EVENT_TYPE_SUBAGENT_SPAWNED
	case "subagent.progress":
		return attachv1.EventType_EVENT_TYPE_SUBAGENT_PROGRESS
	case "subagent.completed":
		return attachv1.EventType_EVENT_TYPE_SUBAGENT_COMPLETED
	case "subagent.accounted":
		return attachv1.EventType_EVENT_TYPE_SUBAGENT_ACCOUNTED
	case "ask.requested":
		return attachv1.EventType_EVENT_TYPE_ASK_REQUESTED
	case "ask.resolved":
		return attachv1.EventType_EVENT_TYPE_ASK_RESOLVED
	case "plan.delta":
		return attachv1.EventType_EVENT_TYPE_PLAN_DELTA
	case "quota.updated":
		return attachv1.EventType_EVENT_TYPE_QUOTA_UPDATED
	case "session.accounted":
		return attachv1.EventType_EVENT_TYPE_SESSION_ACCOUNTED
	default:
		return attachv1.EventType_EVENT_TYPE_UNSPECIFIED
	}
}

// toPlanDeltaKind maps the working-model plan-delta kind string onto the frozen enum (the reverse
// of eventmap.planDeltaKind). An unknown/empty kind maps to UNSPECIFIED.
func toPlanDeltaKind(k string) attachv1.PlanDeltaKind {
	switch k {
	case "todo_write":
		return attachv1.PlanDeltaKind_PLAN_DELTA_KIND_TODO_WRITE
	case "exit_plan_mode":
		return attachv1.PlanDeltaKind_PLAN_DELTA_KIND_EXIT_PLAN_MODE
	case "task_op":
		return attachv1.PlanDeltaKind_PLAN_DELTA_KIND_TASK_OP
	default:
		return attachv1.PlanDeltaKind_PLAN_DELTA_KIND_UNSPECIFIED
	}
}

// toPlanApprovalState maps the EXIT_PLAN_MODE-only approval-state string onto the frozen enum (the
// reverse of eventmap.planApprovalState). An unknown/empty state maps to UNSPECIFIED.
func toPlanApprovalState(s string) attachv1.PlanApprovalState {
	switch s {
	case "proposed":
		return attachv1.PlanApprovalState_PLAN_APPROVAL_STATE_PROPOSED
	case "approved":
		return attachv1.PlanApprovalState_PLAN_APPROVAL_STATE_APPROVED
	case "rejected":
		return attachv1.PlanApprovalState_PLAN_APPROVAL_STATE_REJECTED
	default:
		return attachv1.PlanApprovalState_PLAN_APPROVAL_STATE_UNSPECIFIED
	}
}

// cloneStrings / cloneBytes defensively copy the decoded slices so a projected proto never
// aliases the transient wire buffer (mirroring eventmap's helpers). Named distinctly from the
// write leg's helpers (this file owns them; the write leg has none).
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

// resolveContentSource resolves the read-stream content seam (Deps.ContentSource) from the
// environment gates — the offline-testable slice of liveDeps' wiring (the read twin of
// resolveWriterDriveSink). getenv is injected (os.Getenv in main, a map lookup in tests). It
// gates on DS_ORCH_OVERLAY_DIR (the host-agent's per-session attach-token store home the reader
// attach authenticates against — the SAME gate the write leg uses): UNSET ⇒ a NIL source, so
// NewControlPlane leaves the content relay unconstructed and the fan-out carries only the control
// edges (a clean documented degrade, doc 15 §5.3). SET ⇒ the live source over the overlay token
// store + the attach socket dir (DS_ORCH_ATTACH_SOCKET_DIR, or the shared default). A
// construction fault (an unreadable token store) is a loud error (a live run that MEANT to wire
// the content leg must not degrade silently). No closer is returned: the source caches no state
// (each OpenContent's pump is owned by the relay's serve-lifetime context, cancelled at shutdown).
func resolveContentSource(getenv func(string) string) (controlplane.ContentSource, error) {
	overlayDir := getenv("DS_ORCH_OVERLAY_DIR")
	if overlayDir == "" {
		// A typed-nil pointer must never leave here inside the interface (it would defeat
		// NewControlPlane's `d.ContentSource != nil` guard), so the gate-off arm returns the
		// untyped nil interface value directly.
		return nil, nil
	}
	resolver, err := newOverlayDriveEndpointResolver(overlayDir, getenv("DS_ORCH_ATTACH_SOCKET_DIR"))
	if err != nil {
		return nil, err
	}
	source, err := newHostAgentContentSource(resolver)
	if err != nil {
		return nil, err
	}
	return source, nil
}
