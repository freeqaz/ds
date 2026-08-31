// Package fidelity closes the "are our hand-authored synthetic cassettes
// actually faithful to real CC?" question (DRIVE-PROTOCOL.md §"Determinism via
// record-replay"; taskdb 01KTXBGTK6).
//
// THE LOOP. For each scenario:
//
//	live-capture raw CC stream  ──┐
//	                              ├─▶ adapter PROJECTION ─▶ id-relative CANON ─┐
//	re-authored synthetic cassette┘                                            ├─ EQUAL?
//	                                                                            ┘
//
// The adapter's projection of the re-authored SYNTHETIC cassette must equal its
// projection of the LIVE stream — but NOT byte-for-byte: CC mints fresh random
// session_id/uuid/tool_use_id/task_id per run, instant replay collapses timing,
// and token/cost numbers vary run to run (DRIVE-FINDINGS §5). So equality is
// ID-RELATIVE and STRUCTURAL: this file canonicalizes a projection by replacing
// every volatile id with a correlation-PRESERVING placeholder (the SAME id seen
// twice maps to the SAME placeholder, so the correlation structure — which the
// adapter's whole job is to get right — is what's compared) and by erasing the
// non-reproducible timing/cost/token magnitudes. Two canon forms that differ is
// a real divergence: a STALE cassette or genuine CC DRIFT. CIA's API-plane
// capture is what distinguishes which (DRIVE-PROTOCOL.md); this package proves
// the divergence EXISTS and is reviewable.
//
// Pure stdlib; no live claude/cia/podman. The always-on tests run the canon +
// equality against committed synthetic fixtures (D50, zero egress). The
// DS_E2E_LIVE-gated test (fidelity_live_test.go) runs canon-equality vs a LIVE
// projection.
package fidelity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// Canon is the id-relative, timing-erased canonical form of one projection: the
// structural fingerprint two projections are compared on. It is a slice of
// per-event canonical JSON objects (one line each, stable key order via
// encoding/json) — human-diffable, so a divergence is a reviewable diff.
type Canon struct {
	// Events is the canonicalized per-event JSON, in emission order. Volatile
	// ids are placeholdered (correlation-preserving), timing/cost erased.
	Events []json.RawMessage
}

// Canonicalize reduces a projection to its id-relative structural form. The
// transform is deterministic and stable: the same []attach.Event always yields
// byte-identical Canon, and two projections that are structurally equivalent
// (same event types in the same order, same correlation graph, same non-volatile
// payloads) yield equal Canon regardless of the concrete random ids/timings CC
// minted.
//
// What is normalized (the volatile set, from DRIVE-FINDINGS §5 + the attach.v1
// field tables):
//
//   - session_id, source[] (record uuids), message_id, node_id, parent_node_id,
//     ask_id, task_id, agent_id, turn_group, returned_to, continuation.agent_id:
//     each distinct value is rewritten to a placeholder "<kind#N>" minted in
//     first-seen order PER KIND, so correlation is preserved across events while
//     the concrete random id is erased. A node referenced as a parent of another
//     keeps the same placeholder — the spawn/ask correlation graph is what's
//     compared.
//   - observed_at (adapter clock), duration_ms, total_cost_usd, elapsed_ms:
//     zeroed — not reproducible under instant replay (DRIVE-PROTOCOL.md: "Timing-
//     derived metrics are not reproducible under replay; do not assert").
//   - usage / model_usage / usage_raw / suggestions / resets_at: token and
//     rate magnitudes vary run-to-run and carry model-internal counters; reduced
//     to a presence marker ("<present>") so the STRUCTURAL fact "accounting was
//     emitted" is compared, not the volatile numbers.
//
// What is KEPT (the structural set the fidelity check actually asserts): event
// type and order, role, kind, tool/skill/server names, behavior, outcome,
// is_error, status, source-of-ask, parent_confidence, the input/text payloads,
// and the full correlation graph in placeholdered form.
func Canonicalize(evs []attach.Event) Canon {
	c := newCanonicalizer()
	out := make([]json.RawMessage, 0, len(evs))
	for _, ev := range evs {
		out = append(out, c.event(ev))
	}
	return Canon{Events: out}
}

// canonicalizer holds the per-kind id placeholder maps for one Canonicalize
// pass so a given concrete id maps to one stable placeholder throughout.
type canonicalizer struct {
	maps map[string]map[string]string // kind -> (concrete id -> placeholder)
	next map[string]int               // kind -> next placeholder ordinal
}

func newCanonicalizer() *canonicalizer {
	return &canonicalizer{
		maps: map[string]map[string]string{},
		next: map[string]int{},
	}
}

// ph mints (or returns) the correlation-preserving placeholder for a concrete
// id within an id "kind" (node, session, ask, task, agent, msg, turn, src). The
// empty string stays empty (an absent id is structurally absent, not a node).
func (c *canonicalizer) ph(kind, id string) string {
	if id == "" {
		return ""
	}
	m := c.maps[kind]
	if m == nil {
		m = map[string]string{}
		c.maps[kind] = m
	}
	if p, ok := m[id]; ok {
		return p
	}
	c.next[kind]++
	p := fmt.Sprintf("<%s#%d>", kind, c.next[kind])
	m[id] = p
	return p
}

// event canonicalizes one attach.Event to a stable JSON object. It works on a
// decoded generic map so it never has to track every field by hand — it walks
// the known id/timing/usage fields and rewrites them, then re-encodes with
// sorted keys.
func (c *canonicalizer) event(ev attach.Event) json.RawMessage {
	raw, err := json.Marshal(ev)
	if err != nil {
		// A projection that won't re-marshal is itself a divergence signal; encode
		// the error so the diff shows it rather than panicking.
		return json.RawMessage(fmt.Sprintf("{%q:%q}", "canon_error", err.Error()))
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return json.RawMessage(fmt.Sprintf("{%q:%q}", "canon_error", err.Error()))
	}
	c.walk(m, "")
	return canonJSON(m)
}

// walk rewrites volatile fields in place. path is the dotted ancestry so a key
// like "node_id" is treated the same wherever it appears. Arrays of record
// uuids (source) are placeholdered element-wise.
func (c *canonicalizer) walk(v any, key string) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = c.rewriteField(k, val)
		}
		return t
	default:
		return v
	}
}

// rewriteField applies the volatile-field policy for one key/value.
func (c *canonicalizer) rewriteField(key string, val any) any {
	switch key {
	// --- correlation ids: placeholder, kind-keyed (correlation-preserving) ----
	case "session_id":
		return c.ph("session", asString(val))
	case "message_id":
		return c.ph("msg", asString(val))
	case "node_id", "parent_node_id", "returned_to":
		return c.ph("node", asString(val))
	case "ask_id":
		return c.ph("ask", asString(val))
	case "task_id":
		return c.ph("task", asString(val))
	case "agent_id":
		return c.ph("agent", asString(val))
	case "turn_group":
		return c.ph("turn", asString(val))
	case "source":
		if arr, ok := val.([]any); ok {
			out := make([]any, len(arr))
			for i, e := range arr {
				out[i] = c.ph("src", asString(e))
			}
			return out
		}
		return val

	// --- timing / cost: not reproducible under replay — erase to a constant ----
	case "observed_at", "duration_ms", "elapsed_ms", "total_cost_usd":
		return nil

	// --- volatile magnitudes / model-internal counters: presence-only ----------
	case "usage", "model_usage", "usage_raw", "suggestions", "resets_at":
		if val == nil {
			return nil
		}
		return "<present>"

	default:
		// Recurse into nested objects (e.g. continuation{agent_id,hint}).
		if m, ok := val.(map[string]any); ok {
			for k, vv := range m {
				m[k] = c.rewriteField(k, vv)
			}
			return m
		}
		return val
	}
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// canonJSON marshals a map with stable (sorted) key order so two canon events
// are byte-comparable. encoding/json already sorts map keys, but we route
// through a custom path to guarantee it independent of stdlib internals and to
// drop the null-valued (erased) fields so a diff is tight.
func canonJSON(m map[string]any) json.RawMessage {
	pruned := pruneNulls(m)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(pruned); err != nil {
		return json.RawMessage(fmt.Sprintf("{%q:%q}", "canon_error", err.Error()))
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n"))
}

// pruneNulls drops keys whose canonicalized value is nil (the erased timing
// fields) so they do not clutter the diff, recursively.
func pruneNulls(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if t[k] == nil {
				continue
			}
			out[k] = pruneNulls(t[k])
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = pruneNulls(e)
		}
		return out
	default:
		return v
	}
}
