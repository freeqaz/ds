// SPDX-License-Identifier: Apache-2.0
//
// Package cassette is the record/replay determinism substrate for the
// Anthropic /v1/messages SSE plane — the in-process, stdlib-only Go port of
// the external cia tool's cassette layer (../../../../goldentrace/CAPTURE-TOOL-DESIGN.md
// §2, the "KEEP" core). It lets a real Claude Code process become a
// deterministic function of its inputs: RECORD freezes the model's SSE replies
// to a JSON cassette once; REPLAY serves them back offline, so the replay tier
// is hermetic and zero-egress (D50) — no API reached, no credentials needed.
//
// A cassette is a single JSON file holding an ordered list of interactions.
// Each interaction pairs a *tolerant* request match key with the raw,
// post-gzip-decode SSE response body + replay-relevant headers Anthropic
// returned. The on-disk format is byte-compatible with cia's version:1
// cassette so a capture taken by either tool replays through the other.
//
// PORT FIDELITY. The match key derivation reproduces cia's
// normalize_request/match_key exactly (cross-tool replay would diverge on the
// slightest difference). The decisive subtlety is JSON canonicalization:
// Python's json.dumps escapes non-ASCII to \uXXXX (ensure_ascii) and does NOT
// HTML-escape <>&, whereas Go's encoding/json HTML-escapes <>& and emits raw
// UTF-8 — a naive json.Marshal diverges. This package therefore uses a small
// canonical encoder (canonicalJSON) that matches CPython's json byte-for-byte;
// a shared-vector test pins keys taken from real cia.
package cassette

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// CassetteVersion is the on-disk schema version; a mismatch is rejected on
// load. Kept at 1 for byte-compatibility with cia (cia.cassette.CASSETTE_VERSION).
const CassetteVersion = 1

// MessagesPath is the Anthropic inference endpoint the cassette layer keys on.
const MessagesPath = "/v1/messages"

// replayHeaderAllow is the set of response headers worth persisting for replay
// fidelity. Everything else (Set-Cookie, request-id, anthropic-ratelimit-*,
// date, cf-*, …) is volatile or identifying and is dropped — replay is about
// the SSE body shape, not the transport envelope. content-type is the one
// header CC's client keys on to pick the streaming path, so it is always kept.
var replayHeaderAllow = map[string]struct{}{
	"content-type": {},
}

// volatileRequestHeaders never participate in matching (volatile / identifying).
// They are also what scrub strips so no Bearer token can survive (D50, §2.2 of
// HARDENING-NOTES.md). The set mirrors cia.cassette._VOLATILE_REQUEST_HEADERS
// plus the auth-method tells HARDENING-NOTES §2.2 names.
//
// SINGLE SOURCE OF TRUTH. This one set governs all three request-header scrub
// walls, so it must stay complete against HARDENING-NOTES §2.2 (the governing
// scrub contract) or a real auth/correlatable header silently survives:
//   - the replay --passthrough incremental-record scrub,
//   - the `scrub` subcommand, via the exported VolatileRequestHeader, and
//   - the tolerant matcher's request-header drop (these headers never key a match).
//
// Its §2.2-mandated membership — Authorization, x-api-key, anthropic-beta,
// X-Claude-Code-Session-Id, x-client-request-id — is pinned by volatile_test.go
// against §2.2; removing any of those header-level tells fails that test closed,
// naming the missing header. The §2.2 BODY-level tells (agentId/task_id,
// cwd/memory_paths, total_cost_usd) are deliberately NOT here: they are body
// re-authoring concerns (raw → re-authored synthetic), not transport-header
// strips. Cia's transport-noise entries below (request-id, user-agent, date,
// cookie, …) are extra-but-benign — §2.2 pins a floor, not exact equality.
var volatileRequestHeaders = map[string]struct{}{
	"authorization":                          {},
	"x-api-key":                              {},
	"anthropic-ratelimit-requests-remaining": {},
	"request-id":                             {},
	"x-request-id":                           {},
	"user-agent":                             {},
	"date":                                   {},
	"cookie":                                 {},
	"anthropic-beta":                         {},
	"x-claude-code-session-id":               {},
	"x-client-request-id":                    {},
}

// VolatileRequestHeader reports whether a header name (case-insensitive) is in
// the volatile/auth set that matching ignores and scrub strips.
func VolatileRequestHeader(name string) bool {
	_, ok := volatileRequestHeaders[strings.ToLower(name)]
	return ok
}

// Interaction is one recorded request -> SSE-response pair. The on-disk JSON
// shape ({key, normalized, status_code, headers, body}) is byte-compatible
// with cia's Interaction.to_dict().
type Interaction struct {
	Key        string            `json:"key"`
	Normalized Normalized        `json:"normalized"`
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	// Body is the raw, post-gzip-decode SSE response as text (the line-oriented
	// event:/data: stream the client consumes). Stored as text because it is
	// UTF-8; bytes are reconstructed on replay via ResponseBytes.
	Body string `json:"body"`

	// plays counts how many times this interaction has been served during the
	// current replay session. Runtime-only; never persisted (matches cia's
	// Interaction.plays field=compare=False).
	plays int
}

// ResponseBytes reconstructs the response body bytes for replay.
func (i *Interaction) ResponseBytes() []byte { return []byte(i.Body) }

// Normalized is the tolerant request fingerprint the match key is derived from
// (kept on disk for debugging / inspection). It mirrors the dict that cia's
// normalize_request returns.
type Normalized struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Model    any    `json:"model"`
	System   string `json:"system"`
	Sequence []Turn `json:"sequence"`
}

// Turn is one (role, flattened-content) pair of the conversation sequence.
type Turn struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Cassette is an ordered, on-disk collection of recorded interactions.
type Cassette struct {
	Version      int            `json:"version"`
	Interactions []*Interaction `json:"interactions"`
}

// New returns an empty cassette stamped at the current version.
func New() *Cassette { return &Cassette{Version: CassetteVersion} }

// Add appends an interaction (record path).
func (c *Cassette) Add(it *Interaction) { c.Interactions = append(c.Interactions, it) }

// Len reports the number of recorded interactions.
func (c *Cassette) Len() int { return len(c.Interactions) }

// Record normalizes a request and appends a new interaction for it, mirroring
// cia.cassette.Cassette.record (filtered headers, derived key).
func (c *Cassette) Record(method, path string, requestBody map[string]any,
	statusCode int, headers map[string]string, body string) *Interaction {
	norm := NormalizeRequest(method, path, requestBody)
	it := &Interaction{
		Key:        MatchKey(norm),
		Normalized: norm,
		StatusCode: statusCode,
		Headers:    FilterReplayHeaders(headers),
		Body:       body,
	}
	c.Add(it)
	return it
}

// FilterReplayHeaders keeps only the headers that matter for replay fidelity
// (content-type), lowercased, dropping volatile/identifying transport headers.
// Mirrors cia.cassette.filter_replay_headers, including the content-type
// default.
func FilterReplayHeaders(headers map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range headers {
		if _, ok := replayHeaderAllow[strings.ToLower(k)]; ok {
			out[strings.ToLower(k)] = v
		}
	}
	if _, ok := out["content-type"]; !ok {
		out["content-type"] = "text/event-stream"
	}
	return out
}

// NormalizeRequest reduces a /v1/messages request to its tolerant semantic
// identity. Keyed on method, path (query stripped), model, system-prompt text,
// and the conversation sequence (ordered (role, flattened-content) pairs).
// Deliberately ignored: every volatile id, headers, request metadata, sampling
// params (temperature/top_p/top_k/max_tokens), and stream — and the growing
// history is folded into the sequence so turn N matches regardless of how the
// client re-sent prior turns. Faithful port of cia.cassette.normalize_request.
func NormalizeRequest(method, path string, body map[string]any) Normalized {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}

	var systemText string
	switch s := body["system"].(type) {
	case []any:
		systemText = contentText(s)
	case string:
		systemText = s
	default:
		systemText = ""
	}

	seq := []Turn{}
	if msgs, ok := body["messages"].([]any); ok {
		for _, m := range msgs {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			role, _ := msg["role"].(string)
			seq = append(seq, Turn{
				Role:    role,
				Content: contentText(msg["content"]),
			})
		}
	}

	return Normalized{
		Method:   strings.ToUpper(method),
		Path:     path,
		Model:    body["model"],
		System:   systemText,
		Sequence: seq,
	}
}

// contentText flattens a message content field (str or list of blocks) into
// the text that semantically identifies the turn — fingerprinting only the
// *shape* of each turn (role + kind + text of each block), never block ids,
// cache_control markers, or tool_use_id. Faithful port of cia._content_text.
func contentText(content any) string {
	switch c := content.(type) {
	case string:
		return c
	case []any:
		parts := make([]string, 0, len(c))
		for _, b := range c {
			block, ok := b.(map[string]any)
			if !ok {
				parts = append(parts, pyStr(b))
				continue
			}
			btype, _ := block["type"].(string)
			switch btype {
			case "text":
				parts = append(parts, "text:"+asText(block["text"]))
			case "tool_result":
				// tool_use_id is volatile; key on result payload shape only.
				parts = append(parts, "tool_result:"+contentText(block["content"]))
			case "tool_use":
				// id is volatile; tool name + input identify the call.
				parts = append(parts, "tool_use:"+asText(block["name"])+":"+
					pyJSONDefault(block["input"]))
			case "image":
				// Don't fold megabytes of base64 into the key; hash the source.
				var data any
				if src, ok := block["source"].(map[string]any); ok {
					data = src["data"]
				}
				parts = append(parts, "image:"+sha256Prefix(asText(data)))
			default:
				parts = append(parts, btype+":"+pyJSONDefault(block))
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

// asText renders a value that cia treats as "(block.get(x) or ”)": a JSON
// string passes through, anything missing/None becomes "".
func asText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// MatchKey is the stable, content-addressed key for a normalized request. A
// short human-readable prefix (model + turn count + last user turn) aids
// debugging; the full normalized form is sha256-hashed so any semantic
// difference yields a different key.
//
// Byte-for-byte parity with cia.cassette.match_key:
//
//	canonical = json.dumps(normalized, sort_keys=True, separators=(",",":"))
//	digest    = sha256(canonical).hexdigest()
//	key       = f"{model}|turns={n}|{last_user[:40]}|{digest[:16]}"
func MatchKey(n Normalized) string {
	canonical := canonicalJSON(normalizedToMap(n), false)
	digest := sha256Hex(canonical)

	count := len(n.Sequence)
	lastUser := ""
	for i := len(n.Sequence) - 1; i >= 0; i-- {
		if n.Sequence[i].Role == "user" {
			lastUser = truncate40(strings.ReplaceAll(strings.TrimSpace(n.Sequence[i].Content), "\n", " "))
			break
		}
	}
	model := "?"
	if m, ok := n.Model.(string); ok && m != "" {
		model = m
	} else if n.Model != nil {
		// cia: `normalized.get("model") or "?"` — a non-string truthy model is
		// rare for real CC; mirror the "or" fallthrough for empty/None only.
		if s := pyStr(n.Model); s != "" && s != "None" {
			model = s
		}
	}
	return fmt.Sprintf("%s|turns=%d|%s|%s", model, count, lastUser, digest[:16])
}

// truncate40 returns the first 40 runes of s (cia slices Python str by code
// points, so we slice runes, not bytes).
func truncate40(s string) string {
	r := []rune(s)
	if len(r) <= 40 {
		return s
	}
	return string(r[:40])
}

// normalizedToMap renders Normalized as the plain map cia builds, so the
// canonical encoder sees exactly the dict json.dumps(sort_keys=True) would.
func normalizedToMap(n Normalized) map[string]any {
	seq := make([]any, 0, len(n.Sequence))
	for _, t := range n.Sequence {
		seq = append(seq, map[string]any{"role": t.Role, "content": t.Content})
	}
	return map[string]any{
		"method":   n.Method,
		"path":     n.Path,
		"model":    n.Model,
		"system":   n.System,
		"sequence": seq,
	}
}

// FindMatch returns the next unplayed interaction matching this request, or
// nil. VCR "once" ordering: scan in recorded order, return the first key match
// not yet served this session; then fall back to any key match regardless of
// play count (idempotent replay of a single recording the client repeats),
// distinguished from nil (no key match at all — the real "unknown request").
// Faithful port of cia.cassette.Cassette.find_match.
func (c *Cassette) FindMatch(method, path string, body map[string]any) *Interaction {
	want := MatchKey(NormalizeRequest(method, path, body))
	for _, it := range c.Interactions {
		if it.Key == want && it.plays == 0 {
			it.plays++
			return it
		}
	}
	for _, it := range c.Interactions {
		if it.Key == want {
			it.plays++
			return it
		}
	}
	return nil
}

// ResetPlays clears the per-session play counters (matches cia.reset_plays).
func (c *Cassette) ResetPlays() {
	for _, it := range c.Interactions {
		it.plays = 0
	}
}

// Save writes the cassette to disk in cia's version:1 JSON shape: a top-level
// {version, interactions:[…]} object, 2-space indented, non-ASCII preserved
// (ensure_ascii=False on disk — the human-diffable form), trailing newline.
func (c *Cassette) Save(path string) error {
	if path == "" {
		return fmt.Errorf("cassette: Save: no path given")
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	out, err := marshalCassette(c)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

// marshalCassette renders a cassette the way cia's Cassette.save does:
// json.dumps(doc, indent=2, ensure_ascii=False) + "\n". Go's encoding/json
// with SetIndent + SetEscapeHTML(false) matches the on-disk bytes for the
// fields cia emits, so we build the ordered doc explicitly.
func marshalCassette(c *Cassette) ([]byte, error) {
	type onDiskInteraction struct {
		Key        string            `json:"key"`
		Normalized Normalized        `json:"normalized"`
		StatusCode int               `json:"status_code"`
		Headers    map[string]string `json:"headers"`
		Body       string            `json:"body"`
	}
	type onDisk struct {
		Version      int                 `json:"version"`
		Interactions []onDiskInteraction `json:"interactions"`
	}
	doc := onDisk{Version: c.Version}
	if doc.Version == 0 {
		doc.Version = CassetteVersion
	}
	doc.Interactions = make([]onDiskInteraction, 0, len(c.Interactions))
	for _, it := range c.Interactions {
		doc.Interactions = append(doc.Interactions, onDiskInteraction{
			Key:        it.Key,
			Normalized: it.Normalized,
			StatusCode: it.StatusCode,
			Headers:    it.Headers,
			Body:       it.Body,
		})
	}
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	// encoder.Encode already appends a trailing newline (matching cia's +"\n").
	return []byte(sb.String()), nil
}

// Load reads a cassette from disk, validating the version and rebuilding the
// interaction list (faithful port of cia.cassette.Cassette.load).
func Load(path string) (*Cassette, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parse(raw, path)
}

// parse decodes cassette bytes (split out so tests can decode in-memory).
func parse(raw []byte, label string) (*Cassette, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("%s: not a cassette: %w", label, err)
	}
	if _, ok := probe["interactions"]; !ok {
		return nil, fmt.Errorf("%s: not a cassette (missing 'interactions')", label)
	}
	version := 0
	if v, ok := probe["version"]; ok {
		_ = json.Unmarshal(v, &version)
	}
	if version != CassetteVersion {
		return nil, fmt.Errorf("%s: cassette version %d != supported %d",
			label, version, CassetteVersion)
	}
	var c Cassette
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	c.Version = version
	return &c, nil
}

// ---------------------------------------------------------------------- //
// CPython-compatible canonical JSON                                       //
// ---------------------------------------------------------------------- //
//
// Go's encoding/json cannot reproduce CPython's json.dumps byte-for-byte: it
// HTML-escapes <>&, emits raw UTF-8, and offers no ensure_ascii. Cross-tool
// match-key parity requires the exact Python bytes, so we hand-roll the small
// subset of JSON the normalized form (and block sub-encodings) use: strings,
// numbers, bools, null, sorted-key objects, arrays.

// canonicalJSON renders v the way Python json.dumps does. compact=false uses
// separators (",",":") — the form match_key hashes. compact=true uses Python's
// DEFAULT separators (", ", ": ") — the form _content_text uses inside a
// tool_use input / unknown block.
func canonicalJSON(v any, defaultSeps bool) string {
	var sb strings.Builder
	encodeCanonical(&sb, v, defaultSeps)
	return sb.String()
}

func encodeCanonical(sb *strings.Builder, v any, defaultSeps bool) {
	itemSep, kvSep := ",", ":"
	if defaultSeps {
		itemSep, kvSep = ", ", ": "
	}
	switch t := v.(type) {
	case nil:
		sb.WriteString("null")
	case bool:
		if t {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case string:
		writePyString(sb, t)
	case float64:
		sb.WriteString(formatPyNumber(t))
	case int:
		sb.WriteString(strconv.Itoa(t))
	case int64:
		sb.WriteString(strconv.FormatInt(t, 10))
	case json.Number:
		sb.WriteString(string(t))
	case []any:
		sb.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				sb.WriteString(itemSep)
			}
			encodeCanonical(sb, e, defaultSeps)
		}
		sb.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				sb.WriteString(itemSep)
			}
			writePyString(sb, k)
			sb.WriteString(kvSep)
			encodeCanonical(sb, t[k], defaultSeps)
		}
		sb.WriteByte('}')
	default:
		// default=str fallback (cia passes default=str to the inner dumps):
		// render unknown types as their Python str(), JSON-quoted.
		writePyString(sb, pyStr(v))
	}
}

// formatPyNumber renders a float the way Python's json.dumps does for the
// integers/whole-floats that appear in CC bodies (it emits "2" for 2.0 only
// when the value came from a Python int; a JSON-decoded 2 arrives here as
// float64). Go's json decodes all numbers to float64, so we render whole
// values without a decimal point to match Python int formatting, which is what
// CC sends for fields like max_tokens.
func formatPyNumber(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// pyJSONDefault renders v exactly as cia's inner
// json.dumps(x, sort_keys=True, default=str) does — DEFAULT separators
// (", ", ": "), ensure_ascii, no HTML escaping — for tool_use input and
// unknown-block encodings.
func pyJSONDefault(v any) string { return canonicalJSON(v, true) }

// writePyString writes s as a JSON string literal byte-for-byte like CPython's
// json encoder with ensure_ascii=True: ASCII control + the standard short
// escapes, every non-ASCII rune as \uXXXX (surrogate pairs above U+FFFF), and
// — crucially — NO HTML escaping of <>& (Go's default escapes these; cia does
// not).
func writePyString(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '\b':
			sb.WriteString(`\b`)
		case '\f':
			sb.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				fmt.Fprintf(sb, `\u%04x`, r)
			case r < 0x7f:
				sb.WriteRune(r)
			case r <= 0xffff:
				fmt.Fprintf(sb, `\u%04x`, r)
			default:
				// Astral plane: emit a UTF-16 surrogate pair, as CPython does.
				r -= 0x10000
				hi := 0xd800 + (r >> 10)
				lo := 0xdc00 + (r & 0x3ff)
				fmt.Fprintf(sb, `\u%04x\u%04x`, hi, lo)
			}
		}
	}
	sb.WriteByte('"')
}

// pyStr renders a value roughly as Python's str() would for the simple types
// that reach the default=str fallback (cia's blocks are dicts/strings; this is
// only hit for malformed input). It is intentionally conservative.
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case bool:
		if t {
			return "True"
		}
		return "False"
	case string:
		return t
	case float64:
		return formatPyNumber(t)
	default:
		return fmt.Sprintf("%v", v)
	}
}
