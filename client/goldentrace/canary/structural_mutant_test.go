// structural_mutant_test.go — the STRUCTURAL DRIFT MATRIX: a set of mutant
// CLASSES, each modelling one shape of CC-latest protocol drift, run against
// EVERY committed cassette (client/fixtures/*.cc-wire.ndjson) where the class's
// record-class actually occurs. It is the offline teeth that prove the canary's
// id-relative canon BITES on the structural changes that matter — record
// reordering, a dropped lifecycle/rate-limit/terminal frame, a flipped outcome,
// a dropped subagent-spawn or permission-ask record — across the whole fixture
// corpus, not just the baseline-chat shape (doc 06 §2.2: "the test fixtures must
// include the subagent-spawn path, not just chat deltas").
//
// THE LOOP (per cassette, per class):
//
//	committed cassette (READ-ONLY)  ──┐
//	   │  in-memory line transform     ├─▶ adapter PROJECTION ─▶ id-relative CANON ─┐
//	   │  (content-addressed, never    │       (fidelity.ProjectStream /             ├─ SIGNAL?
//	   │   written back — D50)         │        fidelity.Canonicalize)               ┘
//	   └─ mutated stream  ─────────────┘
//
// Each class declares a SIGNAL it must produce against the faithful canon:
//
//   - kind "length": the mutant's canon has a different EVENT COUNT (a dropped or
//     added record the projector collapses to a missing/extra event).
//   - kind "value":  the mutant's canon has the SAME event count but a divergent
//     line (a reordered/flipped frame the projector still emits, just differently).
//   - kind "equal":  the mutant's RAW BYTES changed but the canon compares EQUAL —
//     the canon-erasure-pinning class. It mutates ONLY fields the id-relative canon
//     intentionally erases (session_id/uuid rewritten consistently, timing/cost
//     bumped), so a faithful canon MUST absorb the change. This makes the canon's
//     erasure LOAD-BEARING: a canon regression that stops erasing volatile ids
//     turns this class red.
//
// APPLICABILITY + NON-VACUITY (the teeth). The per-class anchor predicate is the
// applicability discriminator: anchor absent in THIS cassette ⇒ the class does
// not apply there (an ACCOUNTED skip), anchor present ⇒ the class MUST mutate and
// MUST produce its signal. Two teeth keep the generalization from buying vacuity:
//
//	(a) every class must bite on AT LEAST ONE cassette — a class applicable
//	    nowhere is a HARD FAILURE (a stale anchor, a vacuous class).
//	(b) the six baseline structural classes must ALL still bite on baseline-chat
//	    specifically — the original floor this matrix grew out of, never relaxed.
//
// And, separately, the matrix must exercise >1 cassette INCLUDING at least one
// spawn-path cassette and one ask/tool_use cassette, so the named blind spots get
// real structural-drift rows.
//
// HERMETIC + D50. Pure stdlib + the in-tree adapter. Every mutation is an
// in-memory line transform over a cassette read READ-ONLY — NOTHING is ever
// written under client/fixtures/ or testdata/. No subprocess, no live
// claude/cia/podman, DS_E2E_LIVE never set. The transforms are CONTENT-ADDRESSED
// (they locate frames by record type/content, not by absolute line index), so a
// class applies wherever its record class occurs and no-ops detectably elsewhere.
package canary

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/goldentrace/fidelity"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// structuralSignal is the canon-level outcome a mutant class asserts against the
// faithful projection.
type structuralSignal int

const (
	// signalLength: the mutant canon must have a DIFFERENT event count (a record
	// dropped/added that the projector reflects as a missing/extra event).
	signalLength structuralSignal = iota
	// signalValue: the mutant canon must have the SAME event count but a divergent
	// line (a reordered/flipped frame).
	signalValue
	// signalEqual: the mutant's RAW BYTES must differ but the canon must compare
	// EQUAL — the canon-erasure-pinning class. Only volatile, canon-erased fields
	// are touched, so a faithful canon absorbs the change.
	signalEqual
)

func (s structuralSignal) String() string {
	switch s {
	case signalLength:
		return "length"
	case signalValue:
		return "value"
	case signalEqual:
		return "equal"
	default:
		return "unknown"
	}
}

// structuralMutant is one drift CLASS: a content-addressed, in-memory transform
// over a cassette's raw NDJSON lines, plus the canon SIGNAL it must produce
// wherever its record class occurs.
type structuralMutant struct {
	// name is the class id used in failure messages (with the cassette).
	name string
	// why names the structural property the class proves the canon pins.
	why string
	// signal is the canon-level outcome this class must produce against the
	// faithful projection on every cassette where it applies.
	signal structuralSignal
	// applies reports whether this class's record class occurs in the cassette's
	// lines — the applicability discriminator. False ⇒ ACCOUNTED skip here.
	applies func(lines []string) bool
	// mutate returns the content-addressed mutation of the lines. It is only
	// called when applies==true; it must change the stream (a no-op is a hard
	// failure surfaced by the non-vacuity guard).
	mutate func(lines []string) []string
}

// ── cassette line helpers (in-memory, read-only source) ─────────────────────

// cassetteLines reads a committed cassette into its non-empty NDJSON lines. The
// source file is NEVER written back (D50).
func cassetteLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read cassette %s: %v", path, err)
	}
	var out []string
	for _, ln := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}

// recordType decodes a raw NDJSON line to its (type, subtype). The ds_fixture
// header line (no "type") returns ("", "").
func recordType(line string) (typ, subtype string) {
	var o map[string]any
	if json.Unmarshal([]byte(line), &o) != nil {
		return "", ""
	}
	typ, _ = o["type"].(string)
	subtype, _ = o["subtype"].(string)
	return typ, subtype
}

// firstIndex returns the first line index whose record matches pred, or -1.
func firstIndex(lines []string, pred func(typ, subtype string) bool) int {
	for i, ln := range lines {
		if t, s := recordType(ln); pred(t, s) {
			return i
		}
	}
	return -1
}

// lastIndex returns the last line index whose record matches pred, or -1.
func lastIndex(lines []string, pred func(typ, subtype string) bool) int {
	for i := len(lines) - 1; i >= 0; i-- {
		if t, s := recordType(lines[i]); pred(t, s) {
			return i
		}
	}
	return -1
}

// firstAdjacentSameType returns i where lines[i] and lines[i+1] are both records
// of the given type, or -1. The content-addressed anchor for the reorder class.
func firstAdjacentSameType(lines []string, typ string) int {
	for i := 0; i+1 < len(lines); i++ {
		t0, _ := recordType(lines[i])
		t1, _ := recordType(lines[i+1])
		if t0 == typ && t1 == typ {
			return i
		}
	}
	return -1
}

// dropIndex returns a copy of lines with index i removed.
func dropIndex(lines []string, i int) []string {
	out := make([]string, 0, len(lines)-1)
	out = append(out, lines[:i]...)
	return append(out, lines[i+1:]...)
}

// swapIndex returns a copy of lines with lines[i] and lines[i+1] swapped.
func swapIndex(lines []string, i int) []string {
	out := append([]string(nil), lines...)
	out[i], out[i+1] = out[i+1], out[i]
	return out
}

// flipResultOutcome returns a copy of lines with the result record at i flipped
// from a success outcome to an error one (is_error→true, subtype→an error). The
// outcome is a STRUCTURAL field the canon keeps, so this is a "value" signal.
func flipResultOutcome(lines []string, i int) []string {
	var o map[string]any
	if json.Unmarshal([]byte(lines[i]), &o) != nil {
		return lines // leave unchanged; the no-op guard will catch it
	}
	o["is_error"] = true
	o["subtype"] = "error_during_execution"
	if _, ok := o["terminal_reason"]; ok {
		o["terminal_reason"] = "error"
	}
	b, err := json.Marshal(o)
	if err != nil {
		return lines
	}
	out := append([]string(nil), lines...)
	out[i] = string(b)
	return out
}

// ── predicates the classes content-address on ──────────────────────────────

func isType(typ string) func(t, s string) bool {
	return func(t, _ string) bool { return t == typ }
}
func isSystemSub(sub string) func(t, s string) bool {
	return func(t, s string) bool { return t == "system" && s == sub }
}

// uuidShape matches a v4-uuid-shaped value — exactly the volatile session_id /
// record-uuid fields the cassettes carry (task_id/request_id/message_id/
// parent_tool_use_id are NOT uuid-shaped, so this never touches a canon-KEPT id).
var uuidShape = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// timingKeys are the per-record fields the canon erases to a constant (timing /
// cost / replay-volatile magnitudes). The canon-erasure class bumps these.
var timingKeys = map[string]bool{
	"duration_ms": true, "duration_api_ms": true, "elapsed_ms": true,
	"ttft_ms": true, "ttft_stream_ms": true, "time_to_request_ms": true,
	"observed_at": true, "total_cost_usd": true,
	"resetsAt": true, "resets_at": true,
}

// rewriteErasedFields rewrites ONLY the fields the id-relative canon intentionally
// erases: every v4-uuid-shaped value (session_id + record uuids) is remapped
// CONSISTENTLY (the same old value → the same new value everywhere, preserving the
// correlation graph), and every timing/cost field is bumped. Message text, tool
// names, roles, outcomes — the structural set the canon KEEPS — are left byte-for-
// byte intact. A faithful canon must therefore absorb this entirely (signalEqual).
func rewriteErasedFields(lines []string) []string {
	remap := map[string]string{}
	var nextUUID int
	mintUUID := func(old string) string {
		if v, ok := remap[old]; ok {
			return v
		}
		nextUUID++
		// A distinct, valid-shaped v4 uuid keyed on the ordinal — collision-free
		// (the 8-hex tail uniquely encodes nextUUID), so two distinct old ids never
		// alias and correlation is preserved 1:1.
		v := fmt.Sprintf("ffffffff-aaaa-4bbb-8ccc-%012x", nextUUID)
		remap[old] = v
		return v
	}
	out := make([]string, len(lines))
	for i, ln := range lines {
		// Remap every uuid-shaped value consistently across the whole stream.
		nl := uuidShape.ReplaceAllStringFunc(ln, mintUUID)
		// Bump the canon-erased timing/cost magnitudes via a json round-trip.
		var o map[string]any
		if json.Unmarshal([]byte(nl), &o) == nil {
			bumpTimingFields(o)
			if b, err := json.Marshal(o); err == nil {
				nl = string(b)
			}
		}
		out[i] = nl
	}
	return out
}

// bumpTimingFields rewrites every canon-erased timing/cost field to a different
// value, recursively (some live in nested objects like rate_limit_info/usage).
func bumpTimingFields(o map[string]any) {
	for k, v := range o {
		if timingKeys[k] {
			switch v.(type) {
			case float64, int, json.Number:
				o[k] = 4242424242
			default:
				o[k] = 4242424242
			}
			continue
		}
		switch t := v.(type) {
		case map[string]any:
			bumpTimingFields(t)
		case []any:
			for _, e := range t {
				if m, ok := e.(map[string]any); ok {
					bumpTimingFields(m)
				}
			}
		}
	}
}

// ── the matrix: the structural drift CLASSES ────────────────────────────────

// structuralMutants is the full matrix of drift classes. The first six are the
// baseline structural classes (each must bite on baseline-chat); the next two
// target the named blind spots (subagent-spawn lifecycle, permission-ask /
// control records) and bite only where those record classes occur; the last is
// the canon-erasure-pinning class. ALL classes are content-addressed.
func structuralMutants() []structuralMutant {
	return []structuralMutant{
		// 1. Reorder two adjacent assistant frames — emission ORDER is structural;
		//    the canon must diverge on the swapped pair (same count, "value").
		{
			name:   "reorder-assistant-frames",
			why:    "two adjacent assistant frames emitted out of order",
			signal: signalValue,
			applies: func(lines []string) bool {
				return firstAdjacentSameType(lines, "assistant") >= 0
			},
			mutate: func(lines []string) []string {
				return swapIndex(lines, firstAdjacentSameType(lines, "assistant"))
			},
		},
		// 2. Drop the rate_limit_event frame — a dropped accounting record is a
		//    missing canon event ("length").
		{
			name:   "drop-rate-limit-frame",
			why:    "the rate_limit_event accounting frame dropped",
			signal: signalLength,
			applies: func(lines []string) bool {
				return firstIndex(lines, isType("rate_limit_event")) >= 0
			},
			mutate: func(lines []string) []string {
				return dropIndex(lines, firstIndex(lines, isType("rate_limit_event")))
			},
		},
		// 3. Drop the terminal result frame (missing-terminal) — a truncated stream
		//    that never reaches its terminal is a missing canon event ("length").
		{
			name:   "missing-terminal",
			why:    "the terminal result frame dropped (truncated stream)",
			signal: signalLength,
			applies: func(lines []string) bool {
				return lastIndex(lines, isType("result")) >= 0
			},
			mutate: func(lines []string) []string {
				return dropIndex(lines, lastIndex(lines, isType("result")))
			},
		},
		// 4. Drop the system/init frame — a stream missing its init record is a
		//    missing canon event ("length").
		{
			name:   "drop-init-frame",
			why:    "the system/init frame dropped",
			signal: signalLength,
			applies: func(lines []string) bool {
				return firstIndex(lines, isSystemSub("init")) >= 0
			},
			mutate: func(lines []string) []string {
				return dropIndex(lines, firstIndex(lines, isSystemSub("init")))
			},
		},
		// 5. Drop a system/status frame — a missing status record is a missing
		//    canon event ("length").
		{
			name:   "drop-status-frame",
			why:    "a system/status frame dropped",
			signal: signalLength,
			applies: func(lines []string) bool {
				return firstIndex(lines, isSystemSub("status")) >= 0
			},
			mutate: func(lines []string) []string {
				return dropIndex(lines, firstIndex(lines, isSystemSub("status")))
			},
		},
		// 6. Flip the terminal result outcome success→error — the outcome is a
		//    structural field the canon keeps, so the canon diverges on that line
		//    at the same event count ("value").
		{
			name:   "flip-result-outcome",
			why:    "the terminal result outcome flipped success→error",
			signal: signalValue,
			applies: func(lines []string) bool {
				return lastIndex(lines, isType("result")) >= 0
			},
			mutate: func(lines []string) []string {
				return flipResultOutcome(lines, lastIndex(lines, isType("result")))
			},
		},
		// 7. (BLIND SPOT: subagent-spawn) Drop a system/task_started lifecycle frame.
		//    Applies only where the spawn path occurs (nested-spawn, depth3-nested-
		//    spawn, parallel-fanout, …); a dropped lifecycle record is a missing
		//    canon event ("length"). This is the structural-drift row the spawn path
		//    had ZERO of (doc 06 §2.2).
		{
			name:   "drop-spawn-lifecycle",
			why:    "a subagent-spawn task_started lifecycle frame dropped",
			signal: signalLength,
			applies: func(lines []string) bool {
				return firstIndex(lines, isSystemSub("task_started")) >= 0
			},
			mutate: func(lines []string) []string {
				return dropIndex(lines, firstIndex(lines, isSystemSub("task_started")))
			},
		},
		// 8. (BLIND SPOT: permission-ask / tool_use) Drop a control_request record.
		//    Applies only where the ask/control path occurs (ask-control, drive-
		//    native-allow/deny, drive-fid-native-ask, …); a dropped ask record is a
		//    missing canon event ("length"). This is the structural-drift row the
		//    ask/tool_use path had ZERO of.
		{
			name:   "drop-ask-control-request",
			why:    "a permission-ask control_request frame dropped",
			signal: signalLength,
			applies: func(lines []string) bool {
				return firstIndex(lines, isType("control_request")) >= 0
			},
			mutate: func(lines []string) []string {
				return dropIndex(lines, firstIndex(lines, isType("control_request")))
			},
		},
		// 9. (CANON-ERASURE PINNING) Mutate ONLY fields the id-relative canon erases —
		//    rewrite every uuid/session-id consistently (preserving correlation) and
		//    bump timing/cost. Bytes change; the faithful canon compares EQUAL. A
		//    canon regression that stops erasing a volatile id turns this RED.
		//    Applies to every cassette (all carry uuid-shaped ids + a result/timing
		//    record).
		{
			name:   "canon-erased-fields",
			why:    "only canon-erased volatile fields (uuid/session-id/timing) mutated",
			signal: signalEqual,
			applies: func(lines []string) bool {
				for _, ln := range lines {
					if uuidShape.MatchString(ln) {
						return true
					}
				}
				return false
			},
			mutate: rewriteErasedFields,
		},
	}
}

// baselineFloorClasses are the SIX baseline structural classes that must all
// still bite on baseline-chat specifically (tooth (b) — the original floor this
// matrix grew out of, never relaxed).
var baselineFloorClasses = []string{
	"reorder-assistant-frames",
	"drop-rate-limit-frame",
	"missing-terminal",
	"drop-init-frame",
	"drop-status-frame",
	"flip-result-outcome",
}

// spawnPathCassettes / askToolUseCassettes name the blind-spot cassettes the
// matrix must acquire a structural-drift row on (the doc 06 §2.2 corpus). At
// least one of each must be exercised with a real catch.
var (
	spawnPathCassettes  = map[string]bool{"nested-spawn": true, "depth3-nested-spawn": true, "parallel-fanout": true, "subagent-spawn": true}
	askToolUseCassettes = map[string]bool{"ask-control": true, "drive-native-allow": true, "drive-native-deny": true, "drive-fid-native-ask": true, "drive-fid-native-ask-live-equiv": true, "drive-multiturn": true, "drive-fid-multiturn": true}
)

// fixtureCassettes globs the committed cassettes (the SAME glob the goldens use),
// READ-ONLY. It returns the absolute-ish paths sorted, and their base names.
func fixtureCassettes(t *testing.T) []string {
	t.Helper()
	glob := pkgLayout().FixturesGlob
	matches, err := filepath.Glob(glob)
	if err != nil {
		t.Fatalf("glob cassettes %s: %v", glob, err)
	}
	if len(matches) == 0 {
		t.Fatalf("no cassettes matched %s — the structural matrix has nothing to run "+
			"(the fixtures corpus is the offline teeth)", glob)
	}
	sort.Strings(matches)
	return matches
}

// projectCanon projects an in-memory NDJSON stream to its id-relative canon. The
// bool reports whether the projection succeeded (a parse refusal on a mutated
// shape is itself a valid catch for a structural class).
func projectCanon(lines []string) (fidelity.Canon, []attach.Event, bool) {
	stream := []byte(strings.Join(lines, "\n") + "\n")
	evs, err := fidelity.ProjectStream(bytes.NewReader(stream))
	if err != nil {
		return fidelity.Canon{}, nil, false
	}
	return fidelity.Canonicalize(evs), evs, true
}

// TestStructuralMutantMatrixIsCaughtAsDrift runs the full structural drift matrix
// over EVERY committed cassette and asserts, for each (cassette, class) where the
// class applies, that the mutant produces its declared canon SIGNAL — a missing/
// extra event (length), a divergent line at equal count (value), or bytes-changed-
// canon-equal (the canon-erasure class). It enforces the non-vacuity teeth:
//
//   - per (cassette, class): a mutation that no-ops (bytes unchanged) is a HARD
//     FAILURE, and a length/value class whose mutant canon still compares EQUAL is
//     a HARD FAILURE (the detector went blind);
//   - tooth (a): every class must bite on at least one cassette;
//   - tooth (b): the six baseline classes must all bite on baseline-chat;
//   - the matrix must exercise >1 cassette including ≥1 spawn-path cassette and ≥1
//     ask/tool_use cassette (the doc 06 §2.2 blind spots get real drift rows).
//
// Every mutation is an in-memory transform over a READ-ONLY cassette (D50);
// nothing is written under fixtures/ or testdata/, no subprocess, no live
// claude/cia/podman.
func TestStructuralMutantMatrixIsCaughtAsDrift(t *testing.T) {
	cassettes := fixtureCassettes(t)
	classes := structuralMutants()

	// Accounting: which cassettes each class bit on, which cassettes were
	// exercised at all, and the per-baseline-chat hit set (tooth (b)).
	//
	//   - classBitOn[class] = cassettes where the class produced its DECLARED signal
	//     (a real catch). Tooth (a)/(b) read this.
	//   - inert[class]      = cassettes where the anchor was present and the bytes
	//     changed, but this cassette's projection treats the record as structurally
	//     inert (canon absorbed it / it diverged in another shape). Accounted, for
	//     visibility — never counted as a catch.
	classBitOn := map[string][]string{}
	inert := map[string][]string{}
	exercised := map[string]bool{}
	var spawnHit, askHit []string

	for _, cassettePath := range cassettes {
		name := base(cassettePath)
		lines := cassetteLines(t, cassettePath)

		// The faithful canon — the structural fingerprint every mutant is judged
		// against. A cassette that won't project is a corpus problem, not a drift.
		faithful, _, ok := projectCanon(lines)
		if !ok {
			t.Fatalf("committed cassette %s failed to project faithfully — the corpus is broken, "+
				"not the mutant", name)
		}

		for _, m := range classes {
			if !m.applies(lines) {
				// ACCOUNTED skip: the class's record-class does not occur here. Not a
				// failure — the applicability discriminator. (Logged, not asserted.)
				t.Logf("SKIP    %-26s %-22s (record class absent — not applicable here)", name, m.name)
				continue
			}

			mutLines := m.mutate(lines)
			rawChanged := strings.Join(mutLines, "\n") != strings.Join(lines, "\n")
			if !rawChanged {
				// NON-VACUITY: the class claimed applicability but its content-addressed
				// transform produced identical bytes — a stale anchor / dead transform.
				t.Errorf("%s / %s: the mutation was a NO-OP (raw bytes unchanged) though the class "+
					"claims to apply — the content-addressed anchor has gone stale; a vacuous "+
					"mutant is a hard failure", name, m.name)
				continue
			}

			mutCanon, _, projOK := projectCanon(mutLines)

			switch m.signal {
			case signalEqual:
				// CANON-ERASURE: bytes changed (asserted above) and the canon MUST be
				// EQUAL. Bytes-unchanged would already have failed the no-op guard, so
				// reaching here with rawChanged==true is the EXPECTED leg; the canon
				// staying equal is what proves the erasure is load-bearing.
				if !projOK {
					t.Errorf("%s / %s: the volatile-only mutant FAILED to project — rewriting only "+
						"canon-erased fields must not break projection", name, m.name)
					continue
				}
				diff := canonDiff(faithful, mutCanon)
				if !diff.Equal {
					t.Errorf("%s / %s: a mutation of ONLY canon-erased fields (uuid/session-id/timing) "+
						"changed the CANON — the id-relative canon stopped erasing a volatile field, so "+
						"its equality verdict is no longer trustworthy.\n%s", name, m.name, diff.Report)
					continue
				}
				classBitOn[m.name] = append(classBitOn[m.name], name)
				exercised[name] = true
				t.Logf("EQUAL   %-26s %-22s bytes changed, canon EQUAL (erasure load-bearing)", name, m.name)

			default:
				// LENGTH / VALUE: a structural drift the canon MUST flag wherever the
				// mutated record is structurally LOAD-BEARING in that cassette's
				// projection. A projection refusal on the mutated shape is a valid catch
				// (the adapter rejecting the drift is a loud signal).
				if !projOK {
					classBitOn[m.name] = append(classBitOn[m.name], name)
					exercised[name] = true
					recordBlindSpot(name, m, &spawnHit, &askHit)
					t.Logf("CAUGHT  %-26s %-22s projection refused the mutant (a valid catch)", name, m.name)
					continue
				}
				diff := canonDiff(faithful, mutCanon)
				if diff.Equal {
					// INERT-RECORD SKIP (accounted, not a failure): the raw anchor is
					// present, the content-addressed transform DID change the bytes (the
					// no-op guard above passed), but this cassette's projection treats the
					// mutated record as structurally inert — the adapter folds/merges it so
					// the canon is unaffected (e.g. a parallel-fanout assistant pair with no
					// ordering correlation, or a control_request the adapter does not project
					// as a standalone event in a deny shape). That is NOT detector blindness
					// — the record simply carries no structural signal here. It is
					// distinguished from a bytes-unchanged no-op (a HARD FAILURE, caught
					// above) and the class still has to BITE elsewhere (tooth (a)). The
					// canon-erasure class proves the complementary direction (bytes changed,
					// canon equal is the EXPECTED outcome), so "canon absorbed it" is never a
					// silent pass without a class that mandates a catch somewhere.
					inert[m.name] = append(inert[m.name], name)
					t.Logf("INERT   %-26s %-22s anchor present but canon-inert here (accounted skip)", name, m.name)
					continue
				}
				if strings.TrimSpace(diff.Report) == "" {
					t.Errorf("%s / %s: the structural drift was flagged but produced an EMPTY report — "+
						"a catch must be reviewable", name, m.name)
					continue
				}
				// Signal-kind pinning: where it BITES, a "length" class must move the
				// event COUNT and a "value" class must diverge at the SAME count. A
				// length-class anchor that diverges only in VALUE (or vice-versa) here is
				// the inert/wrong-signal case for THIS cassette — accounted as inert (the
				// record perturbs the canon, just not in this class's declared shape on
				// this cassette), never a silent miscount. The class still has to bite in
				// its declared shape SOMEWHERE (tooth (a) on classBitOn).
				sameCount := len(faithful.Events) == len(mutCanon.Events)
				signalMatch := (m.signal == signalLength && !sameCount) || (m.signal == signalValue && sameCount)
				if !signalMatch {
					inert[m.name] = append(inert[m.name], name)
					t.Logf("INERT   %-26s %-22s diverges but not in %s shape here (count %d→%d; accounted skip)",
						name, m.name, m.signal, len(faithful.Events), len(mutCanon.Events))
					continue
				}
				classBitOn[m.name] = append(classBitOn[m.name], name)
				exercised[name] = true
				recordBlindSpot(name, m, &spawnHit, &askHit)
				t.Logf("CAUGHT  %-26s %-22s %-6s drift flagged (%s)", name, m.name, m.signal, m.why)
			}
		}
	}

	// ── TOOTH (a): every class must bite on at least one cassette.
	for _, m := range classes {
		if len(classBitOn[m.name]) == 0 {
			t.Errorf("mutant class %q bit on ZERO cassettes — a class applicable nowhere is a "+
				"vacuous class (its anchor is stale across the whole corpus); HARD FAILURE", m.name)
		}
	}

	// ── TOOTH (b): the six baseline classes must all bite on baseline-chat.
	for _, cls := range baselineFloorClasses {
		if !contains(classBitOn[cls], "baseline-chat") {
			t.Errorf("baseline floor class %q did NOT bite on baseline-chat — the original "+
				"baseline-chat structural floor was weakened; HARD FAILURE", cls)
		}
	}

	// ── TOOTH (blind-spot classes): the two classes that target the doc 06 §2.2
	// blind spots must each bite on a cassette of their named kind — not merely
	// "somewhere". This pins the spawn / ask-tool_use coverage to the right corpus.
	if !anyIn(classBitOn["drop-spawn-lifecycle"], spawnPathCassettes) {
		t.Errorf("the spawn-lifecycle class bit on no SPAWN-PATH cassette — its structural-drift "+
			"coverage of the subagent-spawn path is vacuous. bit on: %v", classBitOn["drop-spawn-lifecycle"])
	}
	if !anyIn(classBitOn["drop-ask-control-request"], askToolUseCassettes) {
		t.Errorf("the ask-control class bit on no ASK/TOOL_USE cassette — its structural-drift "+
			"coverage of the permission-ask path is vacuous. bit on: %v", classBitOn["drop-ask-control-request"])
	}

	// ── BLIND-SPOT COVERAGE: the matrix must exercise >1 cassette, including ≥1
	// spawn-path cassette and ≥1 ask/tool_use cassette, each with a REAL catch.
	if len(exercised) < 2 {
		t.Errorf("the structural matrix exercised %d cassette(s) — it must exercise >1 so the "+
			"corpus, not just baseline-chat, is under structural-drift coverage", len(exercised))
	}
	if len(spawnHit) == 0 {
		t.Errorf("NO spawn-path cassette acquired a structural-drift row — doc 06 §2.2 names the "+
			"subagent-spawn path explicitly; the spawn blind spot is still uncovered. exercised: %v",
			sortedKeys(exercised))
	}
	if len(askHit) == 0 {
		t.Errorf("NO ask/tool_use cassette acquired a structural-drift row — the permission-ask / "+
			"control-record blind spot is still uncovered. exercised: %v", sortedKeys(exercised))
	}

	// A compact matrix summary so the operator sees WHICH cassettes were exercised
	// (>1, incl. spawn + ask) and which (anchor-present) rows were canon-inert.
	t.Logf("structural matrix: %d cassettes exercised; spawn-path rows on %v; ask/tool_use rows on %v",
		len(exercised), spawnHit, askHit)
	for _, m := range classes {
		if len(inert[m.name]) > 0 {
			t.Logf("  class %-26s caught on %d cassette(s); canon-inert (anchor present) on %v",
				m.name, len(classBitOn[m.name]), inert[m.name])
		}
	}
}

// anyIn reports whether any element of xs is a key in the set.
func anyIn(xs []string, set map[string]bool) bool {
	for _, x := range xs {
		if set[x] {
			return true
		}
	}
	return false
}

// TestStructuralNoOpMutantRejectedByStaleAnchor proves the non-vacuity guard
// itself has teeth: a class whose content-addressed anchor cannot find its record
// must be an ACCOUNTED skip (applies==false), never a silent pass that mutates
// nothing — and a transform that DOES find its anchor must actually change the
// bytes. It synthesises a no-op condition two ways and asserts the matrix's own
// guard would catch a stale/dead transform, so a future edit that lets a class
// "apply" while mutating nothing fails LOUDLY rather than going vacuous.
func TestStructuralNoOpMutantRejectedByStaleAnchor(t *testing.T) {
	// A minimal cassette with NO assistant pair, NO rate_limit, NO control_request,
	// NO task_started — only a header + an init + a result. The spawn/ask/reorder/
	// rate-limit classes must report applies==false here (accounted skip), and the
	// classes that DO apply (init, result-drop, flip, canon-erasure) must produce a
	// real byte change.
	lines := []string{
		`{"ds_fixture":{"provenance":"synthetic","seam":"attach.cc-wire"}}`,
		`{"type":"system","subtype":"init","session_id":"00000000-0000-4000-8000-000000000010","uuid":"00000000-0000-4000-8000-0000000000b0","cwd":"/work","claude_code_version":"2.1.173","model":"claude-sonnet-4-6"}`,
		`{"type":"assistant","session_id":"00000000-0000-4000-8000-000000000010","uuid":"00000000-0000-4000-8000-0000000000b2","parent_tool_use_id":null,"request_id":"req_x","message":{"id":"msg_x","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}}`,
		`{"type":"result","subtype":"success","session_id":"00000000-0000-4000-8000-000000000010","uuid":"00000000-0000-4000-8000-0000000000b5","is_error":false,"num_turns":1,"stop_reason":"end_turn","terminal_reason":"completed","result":"hi","total_cost_usd":0.01,"duration_ms":100}`,
	}

	classByName := map[string]structuralMutant{}
	for _, m := range structuralMutants() {
		classByName[m.name] = m
	}

	// The classes whose record class is ABSENT here must NOT apply — that is the
	// stale-anchor → accounted-skip discipline (not a silent vacuous mutate).
	for _, absent := range []string{
		"reorder-assistant-frames", // only one assistant, no adjacent pair
		"drop-rate-limit-frame",    // no rate_limit_event
		"drop-status-frame",        // no system/status
		"drop-spawn-lifecycle",     // no task_started
		"drop-ask-control-request", // no control_request
	} {
		if classByName[absent].applies(lines) {
			t.Errorf("class %q reported APPLIES on a cassette lacking its record class — a stale "+
				"anchor would then mutate nothing and pass vacuously; it must be an accounted skip",
				absent)
		}
	}

	// The classes whose record class IS present must apply AND change the bytes —
	// a transform that found its anchor but no-opped is the hard failure the matrix
	// guards against.
	for _, present := range []string{"drop-init-frame", "missing-terminal", "flip-result-outcome", "canon-erased-fields"} {
		m := classByName[present]
		if !m.applies(lines) {
			t.Fatalf("class %q should apply to a cassette carrying its record class", present)
		}
		mut := m.mutate(lines)
		if strings.Join(mut, "\n") == strings.Join(lines, "\n") {
			t.Errorf("class %q applied but produced IDENTICAL bytes — a no-op transform is the "+
				"vacuity the matrix's guard must reject", present)
		}
	}

	// And the guard's signal contract: the canon-erasure class, on this cassette,
	// must change bytes yet keep the canon EQUAL — bytes-unchanged would be a hard
	// failure, bytes-changed-canon-equal is its expected outcome.
	ce := classByName["canon-erased-fields"]
	faithful, _, ok := projectCanon(lines)
	if !ok {
		t.Fatal("the minimal synthetic cassette failed to project")
	}
	mut := ce.mutate(lines)
	if strings.Join(mut, "\n") == strings.Join(lines, "\n") {
		t.Fatal("canon-erased-fields produced no byte change on the minimal cassette — bytes-unchanged " +
			"is a hard failure, the class must perturb a volatile field")
	}
	mutCanon, _, mok := projectCanon(mut)
	if !mok {
		t.Fatal("canon-erased-fields broke projection — rewriting only erased fields must not")
	}
	if d := canonDiff(faithful, mutCanon); !d.Equal {
		t.Fatalf("canon-erased-fields changed the CANON on the minimal cassette — the canon stopped "+
			"erasing a volatile field:\n%s", d.Report)
	}
}

// recordBlindSpot tags a real catch against the spawn-path / ask-tool_use
// blind-spot cassette sets so the matrix can assert each got a structural-drift
// row. Only the targeted classes count toward a blind-spot row (a canon-erasure
// "equal" row is not a structural-drift catch).
func recordBlindSpot(cassette string, m structuralMutant, spawnHit, askHit *[]string) {
	if m.name == "drop-spawn-lifecycle" && spawnPathCassettes[cassette] {
		if !contains(*spawnHit, cassette) {
			*spawnHit = append(*spawnHit, cassette)
		}
	}
	if m.name == "drop-ask-control-request" && askToolUseCassettes[cassette] {
		if !contains(*askHit, cassette) {
			*askHit = append(*askHit, cassette)
		}
	}
}

// canonDiff compares two id-relative canons line for line, reusing the same
// equality engine the fidelity loop uses so a divergence renders the SAME
// reviewable diff an operator reads. It bridges canary's Canon to fidelity's
// projection-equality by comparing the canonical event slices directly.
func canonDiff(a, b fidelity.Canon) fidelity.Diff {
	if len(a.Events) != len(b.Events) {
		return fidelity.Diff{
			Equal: false,
			Report: fmt.Sprintf("canon length diverges: faithful has %d events, mutant has %d\n%s",
				len(a.Events), len(b.Events), renderCanonSideBySide(a, b)),
		}
	}
	for i := range a.Events {
		if !bytes.Equal(a.Events[i], b.Events[i]) {
			return fidelity.Diff{
				Equal: false,
				Report: fmt.Sprintf("canon diverges at event %d (id-relative form):\n"+
					"  faithful: %s\n  mutant:   %s", i, string(a.Events[i]), string(b.Events[i])),
			}
		}
	}
	return fidelity.Diff{Equal: true}
}

// renderCanonSideBySide dumps both canons for the length-mismatch case so a
// missing/extra event is locatable in the failure message.
func renderCanonSideBySide(a, b fidelity.Canon) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  --- faithful (%d) ---\n", len(a.Events))
	for i, e := range a.Events {
		fmt.Fprintf(&sb, "    [%d] %s\n", i, clip(string(e)))
	}
	fmt.Fprintf(&sb, "  --- mutant (%d) ---\n", len(b.Events))
	for i, e := range b.Events {
		fmt.Fprintf(&sb, "    [%d] %s\n", i, clip(string(e)))
	}
	return sb.String()
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
