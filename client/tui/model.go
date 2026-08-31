package tui

import (
	"fmt"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Model is the structured view state the renderer draws from. It is built by
// folding attach.v1 events in Seq order (D18 structured deltas, never frames).
// It is deterministic: the same event slice always yields the same Model, so
// the renderer is golden-testable.
//
// The model holds NO approval state as policy: an Ask records the human's
// answer for THIS ask and the wire resolution, never a standing grant (D45).
type Model struct {
	SessionID string
	Init      *attach.SessionInit

	// State / Reason track the last session.state transition. While any ask is
	// pending the session is PARKED — see Parked().
	State  string
	Reason string

	// Lines is the structured transcript in arrival order — the renderable
	// log. Each Line is a typed, pre-formatted delta, never a terminal frame.
	Lines []Line

	// Asks is every ask seen, in arrival order; AskByID indexes them. The
	// pending subset is what the approval surface prompts on.
	Asks    []*Ask
	askByID map[string]*Ask

	// nodes is the subagent/tool tree keyed by node id, for parent threading
	// and live status; treeOrder preserves first-seen order for stable render.
	nodes     map[string]*treeNode
	treeOrder []string

	// tools joins each ToolInvoked to its ToolCompleted by NodeID for the
	// Layer-5 collapsible tool panels (doc serpent-cli-mvp/06 §Layer 5).
	// toolOrder preserves first-invoked order so the rich render is
	// deterministic. This is render metadata ONLY: it never feeds Lines, so the
	// RenderPlain golden surface stays byte-stable (the enrichment lives only in
	// the interactive RenderRich path).
	tools     map[string]*toolPair
	toolOrder []string

	// live is the Layer-1 live-tail buffer: the in-flight typing text for a chat
	// message still being streamed (attach.TypeChatDelta, D145/P11), keyed by
	// (message_id, block_index). It is render-only and NEVER appended to Lines:
	// the committed ChatMessage is authoritative and CLEARS its message's live
	// blocks when it arrives (the delta is replaced by the canonical LineChat).
	// So dropping every ChatDelta leaves the transcript (and the RenderPlain
	// golden) byte-identical — only the interactive Render() draws the tail.
	// liveOrder preserves first-seen (message_id, block_index) order so the tail
	// renders deterministically.
	live      map[liveKey]*liveBlock
	liveOrder []liveKey

	// Accounting is the terminal session.accounted payload, if seen.
	Accounting *attach.SessionAccounted
	// Quota is the latest quota.updated passthrough, if seen.
	Quota *attach.QuotaUpdated

	// lastSeq is the highest Seq folded — the resume token (doc 15 §6.1 row 1).
	lastSeq uint64
}

// LineKind discriminates a structured transcript line for the renderer.
type LineKind string

const (
	LineSessionInit  LineKind = "session"
	LineState        LineKind = "state"
	LineThinking     LineKind = "thinking"
	LineChat         LineKind = "chat"
	LineTool         LineKind = "tool"
	LineToolResult   LineKind = "tool-result"
	LineSubagent     LineKind = "subagent"
	LineSubProgress  LineKind = "subagent-progress"
	LineSubComplete  LineKind = "subagent-complete"
	LineSubAccounted LineKind = "subagent-accounted"
	LineAsk          LineKind = "ask"
	LineAskResolved  LineKind = "ask-resolved"
	LinePlan         LineKind = "plan"
	LineQuota        LineKind = "quota"
	LineAccounted    LineKind = "accounted"
)

// Line is one structured transcript entry. Depth indents the subagent tree.
// Text is the pre-rendered, single-purpose payload — the renderer adds glyphs
// and indentation, it never re-parses wire fields.
type Line struct {
	Seq   uint64
	Kind  LineKind
	Depth int
	Text  string
}

// treeNode is a node in the subagent/tool spawn tree, threaded by parent for
// depth computation (the D18 per-call hierarchy, doc 15 §6.1 row 4).
type treeNode struct {
	id       string
	parentID string
	label    string
	depth    int
}

// toolPair joins one ToolInvoked to its matching ToolCompleted by NodeID for
// the Layer-5 collapsible tool panel. It retains the raw wire payloads (already
// on the frozen attach.v1 wire) so the rich renderer can reconstruct a Layer-2
// diff from Invoked.Input and show Completed.OutputExcerpt as the body. Seq is
// the invoked event's seq, fixing the panel's transcript position; TurnGroup is
// copied from the invoke for stable grouping (doc 06 §Layer 5). Completed is nil
// until the matching completion folds (a still-running tool).
type toolPair struct {
	NodeID    string
	TurnGroup string
	Depth     int
	Seq       uint64
	Invoked   *attach.ToolInvoked
	Completed *attach.ToolCompleted
}

// liveKey identifies one in-flight chat content block — (message_id,
// block_index) — for the Layer-1 live-tail buffer. The block_index space is
// per-message (P10), so the message id is part of the key.
type liveKey struct {
	messageID  string
	blockIndex int32
}

// liveBlock is the accumulated render-only typing text for one in-flight content
// block. Kind is "text" or "thinking"; Text grows as content_block_delta events
// fold in; Done is set on the final delta (content_block_stop). ParentNodeID
// threads the tail under its subagent (mirroring ChatMessage). It is REPLACED by
// the committed LineChat when the authoritative ChatMessage for messageID
// arrives — so it is never canonical (P11).
type liveBlock struct {
	key          liveKey
	kind         string
	parentNodeID string
	text         string
	done         bool
}

// NewModel returns an empty model ready to Apply events.
func NewModel() *Model {
	return &Model{
		askByID: make(map[string]*Ask),
		nodes:   make(map[string]*treeNode),
		tools:   make(map[string]*toolPair),
		live:    make(map[liveKey]*liveBlock),
	}
}

// LastSeq is the highest event Seq folded — pass it back as fromSeq to resume a
// re-attach exactly where rendering left off (doc 15 §6.1 row 1).
func (m *Model) LastSeq() uint64 { return m.lastSeq }

// PendingAsks returns the open (AskPending) asks in arrival order — what the
// approval surface prompts on.
func (m *Model) PendingAsks() []*Ask {
	var out []*Ask
	for _, a := range m.Asks {
		if a.State == AskPending {
			out = append(out, a)
		}
	}
	return out
}

// Parked reports whether the session is PARKED on an unanswered ask (D53/D77):
// any pending ask parks the session — it waits for a human, never timing out
// into allow or kill. The renderer surfaces this as the session status.
func (m *Model) Parked() bool { return len(m.PendingAsks()) > 0 }

// AnswerAsk records the human's decision on a pending ask locally and returns
// it so the caller can forward it through the wrapper Writer. It stores NO
// grant (D45): the ask moves to AskAnswered, nothing more. Returns an error if
// the ask is unknown or already closed.
func (m *Model) AnswerAsk(askID string, d Decision) (*Ask, error) {
	a, ok := m.askByID[askID]
	if !ok {
		return nil, fmt.Errorf("tui: no such ask %q", askID)
	}
	if a.State != AskPending {
		return nil, fmt.Errorf("tui: ask %q is %s, not pending", askID, a.State)
	}
	a.answeredByHuman(d)
	return a, nil
}

// Apply folds one event into the model in Seq order. It asserts strict Seq
// monotonicity (the wrapper is the ordering authority, P10): an out-of-order or
// duplicate Seq is a contract violation surfaced as an error, never silently
// reordered. Exactly one payload pointer is expected per the envelope contract.
func (m *Model) Apply(ev attach.Event) error {
	if ev.Seq <= m.lastSeq && m.lastSeq != 0 {
		return fmt.Errorf("tui: event seq %d not after %d (ordering authority is the wrapper, P10)", ev.Seq, m.lastSeq)
	}
	m.lastSeq = ev.Seq
	if ev.SessionID != "" {
		m.SessionID = ev.SessionID
	}

	switch ev.Type {
	case attach.TypeSessionInit:
		m.Init = ev.SessionInit
		m.append(ev.Seq, LineSessionInit, 0, formatInit(ev.SessionInit))
	case attach.TypeSessionState:
		m.State = ev.SessionState.State
		m.Reason = ev.SessionState.Reason
		m.append(ev.Seq, LineState, 0, formatState(ev.SessionState))
	case attach.TypeChatMessage:
		m.applyChat(ev)
	case attach.TypeChatDelta:
		m.applyChatDelta(ev)
	case attach.TypeToolInvoked:
		m.applyToolInvoked(ev)
	case attach.TypeToolCompleted:
		m.applyToolCompleted(ev)
	case attach.TypeSubagentSpawned:
		m.applySubagentSpawned(ev)
	case attach.TypeSubagentProgress:
		d := m.depthOf(ev.SubagentProgress.NodeID)
		m.append(ev.Seq, LineSubProgress, d, formatSubProgress(ev.SubagentProgress))
	case attach.TypeSubagentCompleted:
		d := m.depthOf(ev.SubagentCompleted.NodeID)
		m.append(ev.Seq, LineSubComplete, d, formatSubCompleted(ev.SubagentCompleted))
	case attach.TypeSubagentAccounted:
		d := m.depthOf(ev.SubagentAccounted.NodeID)
		m.append(ev.Seq, LineSubAccounted, d, formatSubAccounted(ev.SubagentAccounted))
	case attach.TypeAskRequested:
		m.applyAskRequested(ev)
	case attach.TypeAskResolved:
		m.applyAskResolved(ev)
	case attach.TypePlanDelta:
		// Plan delta (§6.1 row 6): the TodoWrite/Task*/ExitPlanMode plan-card
		// snapshot, threaded under its tool-use node so the plan card sits where
		// the call happened. One line per delta (the full-list snapshot summary).
		m.append(ev.Seq, LinePlan, m.depthOf(ev.PlanDelta.NodeID), formatPlanDelta(ev.PlanDelta))
	case attach.TypeQuotaUpdated:
		m.Quota = ev.QuotaUpdated
		m.append(ev.Seq, LineQuota, 0, formatQuota(ev.QuotaUpdated))
	case attach.TypeSessionAccounted:
		m.Accounting = ev.SessionAccounted
		m.append(ev.Seq, LineAccounted, 0, formatAccounted(ev.SessionAccounted))
	default:
		// Unknown type: forward-compat. Surface it without inventing a shape —
		// a new event class on the wire is a freeze-checklist input, not a
		// crash and not a silently-dropped delta.
		m.append(ev.Seq, LineState, 0, fmt.Sprintf("unhandled event type %q (seq %d)", ev.Type, ev.Seq))
	}
	return nil
}

func (m *Model) applyChat(ev attach.Event) {
	d := m.depthOf(ev.ChatMessage.ParentNodeID)
	for _, b := range ev.ChatMessage.Blocks {
		switch b.Kind {
		case "thinking":
			m.append(ev.Seq, LineThinking, d, formatThinking(ev.ChatMessage, b))
		default:
			m.append(ev.Seq, LineChat, d, formatChat(ev.ChatMessage, b))
		}
	}
	// The authoritative ChatMessage has committed this message's content into
	// Lines (above): drop any live-tail blocks for the same message_id so the
	// typing animation is REPLACED by the committed transcript (P11). Because the
	// committed render is sourced entirely from Lines, a stream that never carried
	// the deltas yields the identical transcript — the render-only invariant.
	m.clearLiveMessage(ev.ChatMessage.MessageID)
}

// applyChatDelta folds one render-only typing delta (D145/P11) into the live-tail
// buffer for its (message_id, block_index). It NEVER appends to Lines: the live
// text is a tail region the interactive Render() draws below the committed
// transcript and the committed ChatMessage later replaces. A coalesced delta
// grows the block's text; a Final delta (content_block_stop) marks it complete
// but keeps it visible until the ChatMessage commits.
func (m *Model) applyChatDelta(ev attach.Event) {
	cd := ev.ChatDelta
	if cd == nil {
		return
	}
	key := liveKey{messageID: cd.MessageID, blockIndex: cd.BlockIndex}
	lb, ok := m.live[key]
	if !ok {
		lb = &liveBlock{key: key, kind: cd.Kind, parentNodeID: cd.ParentNodeID}
		m.live[key] = lb
		m.liveOrder = append(m.liveOrder, key)
	}
	if cd.Kind != "" {
		lb.kind = cd.Kind
	}
	if cd.ParentNodeID != "" {
		lb.parentNodeID = cd.ParentNodeID
	}
	lb.text += cd.Text
	if cd.Final {
		lb.done = true
	}
}

// clearLiveMessage drops every live-tail block belonging to message_id — called
// when that message's authoritative ChatMessage commits, so the typing tail is
// replaced by the committed LineChat (P11). A message with no live blocks is a
// no-op (the partials-off path).
func (m *Model) clearLiveMessage(messageID string) {
	if len(m.live) == 0 {
		return
	}
	kept := m.liveOrder[:0]
	for _, k := range m.liveOrder {
		if k.messageID == messageID {
			delete(m.live, k)
			continue
		}
		kept = append(kept, k)
	}
	m.liveOrder = kept
}

// LiveTail returns the in-flight typing blocks (Layer-1 live tail) in first-seen
// order — the render-only region the interactive Render() draws below the
// committed transcript. It is empty unless the adapter was constructed
// WithPartials (and never feeds RenderPlain), so the golden surface is unaffected.
func (m *Model) LiveTail() []*liveBlock {
	out := make([]*liveBlock, 0, len(m.liveOrder))
	for _, k := range m.liveOrder {
		if lb, ok := m.live[k]; ok {
			out = append(out, lb)
		}
	}
	return out
}

func (m *Model) applyToolInvoked(ev attach.Event) {
	t := ev.ToolInvoked
	parent := t.ParentNodeID
	m.addNode(t.NodeID, parent, t.Name)
	m.recordToolInvoked(ev.Seq, t)
	m.append(ev.Seq, LineTool, m.depthOf(t.NodeID), formatTool(t))
}

func (m *Model) applyToolCompleted(ev attach.Event) {
	t := ev.ToolCompleted
	m.recordToolCompleted(t)
	m.append(ev.Seq, LineToolResult, m.depthOf(t.NodeID), formatToolCompleted(t))
}

// recordToolInvoked retains a tool-use's raw payload for the Layer-5 panel
// join. It defensively copies the opaque Input bytes (the wire owns them) so a
// later mutation of the event slice cannot disturb the rendered diff. A repeat
// NodeID keeps the first invocation (idempotent, mirroring addNode).
func (m *Model) recordToolInvoked(seq uint64, t *attach.ToolInvoked) {
	if t == nil || t.NodeID == "" {
		return
	}
	if _, ok := m.tools[t.NodeID]; ok {
		return
	}
	cp := *t
	cp.Input = append([]byte(nil), t.Input...)
	m.tools[t.NodeID] = &toolPair{
		NodeID:    t.NodeID,
		TurnGroup: t.TurnGroup,
		Depth:     m.depthOf(t.NodeID),
		Seq:       seq,
		Invoked:   &cp,
	}
	m.toolOrder = append(m.toolOrder, t.NodeID)
}

// recordToolCompleted joins a completion to its invocation by NodeID. A
// completion with no surfaced invocation is ignored for the panel (the plain
// transcript still shows it via Lines) — the panel groups only matched pairs.
func (m *Model) recordToolCompleted(t *attach.ToolCompleted) {
	if t == nil || t.NodeID == "" {
		return
	}
	if p, ok := m.tools[t.NodeID]; ok {
		cp := *t
		p.Completed = &cp
	}
}

// ToolPanels returns the joined ToolInvoked/ToolCompleted pairs in stable
// first-invoked order for the Layer-5 collapsible renderer. The order is
// deterministic (toolOrder is append-only on first invoke), so the rich render
// is golden-stable.
func (m *Model) ToolPanels() []*toolPair {
	out := make([]*toolPair, 0, len(m.toolOrder))
	for _, id := range m.toolOrder {
		if p, ok := m.tools[id]; ok {
			out = append(out, p)
		}
	}
	return out
}

func (m *Model) applySubagentSpawned(ev attach.Event) {
	s := ev.SubagentSpawned
	label := s.SubagentType
	if label == "" {
		label = "subagent"
	}
	m.addNode(s.NodeID, s.ParentNodeID, label)
	m.append(ev.Seq, LineSubagent, m.depthOf(s.NodeID), formatSubagent(s))
}

func (m *Model) applyAskRequested(ev attach.Event) {
	r := ev.AskRequested
	a := &Ask{
		AskID:    r.AskID,
		NodeID:   r.NodeID,
		ToolName: r.ToolName,
		Source:   r.Source,
		Pending:  r.Pending,
		Input:    append([]byte(nil), r.Input...),
		State:    AskPending,
	}
	// A re-arm of an already-known ask updates in place rather than duplicating
	// the prompt (the socket-hold re-arm path, ask.go).
	if existing, ok := m.askByID[a.AskID]; ok {
		existing.Pending = a.Pending
		existing.State = AskPending
		m.append(ev.Seq, LineAsk, m.depthOf(r.NodeID), formatAsk(existing))
		return
	}
	m.askByID[a.AskID] = a
	m.Asks = append(m.Asks, a)
	m.append(ev.Seq, LineAsk, m.depthOf(r.NodeID), formatAsk(a))
}

func (m *Model) applyAskResolved(ev attach.Event) {
	r := ev.AskResolved
	a, ok := m.askByID[r.AskID]
	if !ok {
		// A resolution with no known ask: do not invent an ask that was never
		// surfaced. Record the resolution line so the divergence is visible.
		m.append(ev.Seq, LineAskResolved, m.depthOf(r.NodeID), formatAskResolvedOrphan(r))
		return
	}
	a.applyResolved(r)
	m.append(ev.Seq, LineAskResolved, m.depthOf(r.NodeID), formatAskResolved(a))
}

// addNode records a tree node and computes its depth from its parent. An
// orphan (parent not yet/never seen) is depth 0 — the renderer never blocks on
// a missing parent; parent confidence is the adapter's concern (attach.go).
func (m *Model) addNode(id, parentID, label string) {
	if id == "" {
		return
	}
	if _, ok := m.nodes[id]; ok {
		return
	}
	depth := 0
	if parentID != "" {
		if p, ok := m.nodes[parentID]; ok {
			depth = p.depth + 1
		}
	}
	m.nodes[id] = &treeNode{id: id, parentID: parentID, label: label, depth: depth}
	m.treeOrder = append(m.treeOrder, id)
}

// depthOf returns the render depth for a node id (0 for root or unknown).
func (m *Model) depthOf(id string) int {
	if id == "" {
		return 0
	}
	if n, ok := m.nodes[id]; ok {
		return n.depth
	}
	return 0
}

func (m *Model) append(seq uint64, kind LineKind, depth int, text string) {
	m.Lines = append(m.Lines, Line{Seq: seq, Kind: kind, Depth: depth, Text: text})
}
