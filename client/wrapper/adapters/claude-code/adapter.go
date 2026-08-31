// Package claudecode is THE runtime-specific code (D20/D38): it parses the
// Claude Code stream-json session protocol (pinned by golden traces, D49) and
// projects it into dreamserpent.attach.v1 events (client/wrapper/attach).
// CC-isms must never leak out of this directory — everything upstream of the
// adapter is runtime-ignorant.
//
// Foundation file: envelope decode, the dispatch switch, monotonic seq
// assignment (stdout arrival order is the verified-safe basis, P10), Source
// stamping, and the shared emit helper live here. Per-record projection logic
// lives in the area files (classify.go, tree.go, state.go, ask.go), called as
// hooks from the dispatch below.
package claudecode

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// maxLineBytes bounds one stdout NDJSON line in ProcessStream (10MB).
const maxLineBytes = 10 << 20

// Option configures an Adapter at construction.
type Option func(*Adapter)

// WithClock overrides the adapter clock — replay determinism: goldens must be
// byte-stable across runs (client/goldentrace/replay).
func WithClock(fn func() time.Time) Option {
	return func(a *Adapter) { a.clock = fn }
}

// Adapter projects one CC session's stdout stream into attach.v1 events. It
// is single-stream stateful and not safe for concurrent use. It holds NO
// approval state (D18/D45/D53): asks are emitted, never stored as grants or
// answered here.
type Adapter struct {
	clock    func() time.Time
	seq      uint64
	warnings []string

	// sessionID is the last session id seen on a record envelope; control
	// records may omit it, so the latest value is stamped on every event.
	sessionID string

	// Shared cross-area state. Foundation defines the fields; the area files
	// own their contents (the node/ask types live with their owners).
	registry   map[string]*node    // subagent registry keyed by tool-use id (tree.go)
	openTasks  map[string]struct{} // task_started seen, no task_notification yet (tree.go writes, state.go reads)
	asks       map[string]*ask     // open asks keyed by tool-use id (ask.go)
	working    bool                // ATTACHED⇄WORKING latch; SessionState emits on transitions only (state.go)
	initSeen   bool                // system/init consumed
	agentTypes map[string]struct{} // init.agents[] — subagent-type allowlist (unknown type ⇒ warning, not error)
	skills     map[string]struct{} // init.skills[] — skill allowlist

	// WithPartials render-only typing-delta cursor (classify.go owns the
	// projection; the fields live here, GC'd with the adapter, like the
	// per-adapter state above). All zero-valued by default: partials=false is
	// the historical drop, so a build that never passes WithPartials touches
	// none of this and stays byte-identical. blockKind is lazily (re)allocated
	// on each message_start — New() need not pre-seed it, so the default
	// (partials-off) path never allocates a map.
	partials  bool           // opted in via WithPartials (else handleStreamEvent drops, as historically)
	curMsgID  string         // message.id of the partial message currently streaming
	curParent string         // parent_tool_use_id of the streaming message (subagent threading)
	blockKind map[int]string // content-block index → block kind, reset each message_start
}

// New constructs an Adapter. The default clock is time.Now; replay passes
// WithClock for determinism.
func New(opts ...Option) *Adapter {
	a := &Adapter{
		clock:      time.Now,
		registry:   make(map[string]*node),
		openTasks:  make(map[string]struct{}),
		asks:       make(map[string]*ask),
		agentTypes: make(map[string]struct{}),
		skills:     make(map[string]struct{}),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Warnings returns the accumulated skip/integrity warnings, in order.
func (a *Adapter) Warnings() []string {
	return append([]string(nil), a.warnings...)
}

// Feed consumes one stdout NDJSON line (one CC record) and returns the attach
// events it projects, in emission order. Unknown record types are skipped with
// a recorded warning, never an error (forward-compat: drift is a cassette
// diff, not a crash). A leading {"ds_fixture":…} header line is skipped.
func (a *Adapter) Feed(line []byte) ([]attach.Event, error) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, nil
	}

	// D50 provenance header, not a CC record.
	var hdr fixtureHeader
	if err := json.Unmarshal(trimmed, &hdr); err == nil && hdr.DSFixture != nil {
		return nil, nil
	}

	var env envelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return nil, fmt.Errorf("claudecode: undecodable stream line: %w", err)
	}
	if env.SessionID != "" {
		a.sessionID = env.SessionID
	}

	switch env.Type {
	case "system":
		switch env.Subtype {
		case "init":
			rec, ok := decodeRecord[initRecord](a, trimmed, &env)
			if !ok {
				return nil, nil
			}
			return a.handleInit(rec)
		case "status":
			rec, ok := decodeRecord[statusRecord](a, trimmed, &env)
			if !ok {
				return nil, nil
			}
			return a.handleStatus(rec)
		case "thinking_tokens":
			// Live token estimate, render-frequency; deliberately outside
			// the event model (PROTOCOL-NOTES message-type table).
			_, _ = decodeRecord[thinkingTokensRecord](a, trimmed, &env)
			return nil, nil
		case "task_started":
			rec, ok := decodeRecord[taskStartedRecord](a, trimmed, &env)
			if !ok {
				return nil, nil
			}
			return a.handleTaskStarted(rec)
		case "task_progress":
			rec, ok := decodeRecord[taskProgressRecord](a, trimmed, &env)
			if !ok {
				return nil, nil
			}
			return a.handleTaskProgress(rec)
		case "task_notification":
			rec, ok := decodeRecord[taskNotificationRecord](a, trimmed, &env)
			if !ok {
				return nil, nil
			}
			return a.handleTaskNotification(rec)
		default:
			a.warnf("unknown system subtype %q (uuid %s): record skipped", env.Subtype, env.UUID)
			return nil, nil
		}
	case "assistant":
		rec, ok := decodeRecord[assistantRecord](a, trimmed, &env)
		if !ok {
			return nil, nil
		}
		return a.handleAssistant(rec)
	case "user":
		rec, ok := decodeRecord[userRecord](a, trimmed, &env)
		if !ok {
			return nil, nil
		}
		return a.handleUser(rec)
	case "result":
		rec, ok := decodeRecord[resultRecord](a, trimmed, &env)
		if !ok {
			return nil, nil
		}
		return a.handleResult(rec)
	case "stream_event":
		rec, ok := decodeRecord[streamEventRecord](a, trimmed, &env)
		if !ok {
			return nil, nil
		}
		return a.handleStreamEvent(rec)
	case "rate_limit_event":
		rec, ok := decodeRecord[rateLimitRecord](a, trimmed, &env)
		if !ok {
			return nil, nil
		}
		return a.handleRateLimit(rec)
	case "control_request":
		rec, ok := decodeRecord[controlRequestRecord](a, trimmed, &env)
		if !ok {
			return nil, nil
		}
		return a.handleControlRequest(rec)
	case "control_response":
		rec, ok := decodeRecord[controlResponseRecord](a, trimmed, &env)
		if !ok {
			return nil, nil
		}
		return a.handleControlResponse(rec)
	default:
		a.warnf("unknown record type %q (uuid %s): record skipped", env.Type, env.UUID)
		return nil, nil
	}
}

// ProcessStream feeds every line of r through Feed and returns the
// concatenated projection. Lines are bounded at maxLineBytes.
func (a *Adapter) ProcessStream(r io.Reader) ([]attach.Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	var events []attach.Event
	for sc.Scan() {
		evs, err := a.Feed(sc.Bytes())
		if err != nil {
			return events, err
		}
		events = append(events, evs...)
	}
	if err := sc.Err(); err != nil {
		return events, err
	}
	return events, nil
}

// handleInit consumes system/init (foundation-owned: no area hook covers it):
// it seeds the allowlist registries (P14: tools[] and agents[] are disjoint)
// and emits the session.init snapshot.
func (a *Adapter) handleInit(rec *initRecord) ([]attach.Event, error) {
	a.initSeen = true
	a.agentTypes = stringSet(rec.Agents)
	a.skills = stringSet(rec.Skills)
	ev := a.emit(attach.Event{
		Type: attach.TypeSessionInit,
		SessionInit: &attach.SessionInit{
			RuntimeVersion: rec.ClaudeCodeVersion,
			Model:          rec.Model,
			CWD:            rec.CWD,
			PermissionMode: rec.PermissionMode,
			APIKeySource:   rec.APIKeySource,
			Tools:          rec.Tools,
			AgentTypes:     rec.Agents,
			Skills:         rec.Skills,
			SlashCommands:  rec.SlashCommands,
			MCPServers:     rec.MCPServers,
			OutputStyle:    rec.OutputStyle,
		},
	}, rec.UUID)
	return []attach.Event{ev}, nil
}

// emit stamps the shared attach envelope onto ev and returns it: the next
// monotonic seq (from 1, assigned in emission order — P10), the adapter
// clock, the current session id, and Source = the uuid(s) of the CC record(s)
// the event was projected from. Every hook must route its events through
// here.
func (a *Adapter) emit(ev attach.Event, source ...string) attach.Event {
	a.seq++
	ev.Seq = a.seq
	ev.SessionID = a.sessionID
	ev.ObservedAt = a.clock()
	if len(source) > 0 {
		ev.Source = source
	}
	return ev
}

// warnf records a non-fatal projection warning (unknown record, integrity
// mismatch, allowlist miss). Warnings never abort the stream.
func (a *Adapter) warnf(format string, args ...any) {
	a.warnings = append(a.warnings, fmt.Sprintf(format, args...))
}

// decodeRecord re-unmarshals a full line into the typed record for a known
// record type. Failure is a recorded warning, not an error: drift in a known
// record is a cassette diff, not a crash.
func decodeRecord[T any](a *Adapter, line []byte, env *envelope) (*T, bool) {
	rec := new(T)
	if err := json.Unmarshal(line, rec); err != nil {
		a.warnf("undecodable %s/%s record (uuid %s): skipped: %v", env.Type, env.Subtype, env.UUID, err)
		return nil, false
	}
	return rec, true
}

// excerpt truncates s to at most 256 runes, appending "…" when truncated —
// the shared rule for every *_excerpt field.
func excerpt(s string) string {
	const max = 256
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "…"
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}
