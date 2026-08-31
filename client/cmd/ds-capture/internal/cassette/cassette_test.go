// SPDX-License-Identifier: Apache-2.0

package cassette

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------- //
// CIA-PARITY shared-vector test                                           //
// ---------------------------------------------------------------------- //
//
// The golden keys in testdata/parity-vectors.json are the keys the Go matcher
// (NormalizeRequest + MatchKey) computes; TestMatchKeyCIAParity pins them
// offline so any regression in the Go port fails loudly with no live cia. The
// env-gated DS_CIA_PARITY=1 manual run (TestMatchKeyCIAParityDrift) re-derives
// the same keys against a REAL local cia checkout — a passing offline pin PLUS
// a passing manual run together prove byte-for-byte cross-tool match-key
// parity, so a cassette recorded by either tool replays through the other. The
// pin was last reconciled against a local cia checkout on 2026-06-12; the
// widened image / multi-image / mixed-tool_result+text vectors carry Go-computed
// keys and MUST be re-pinned by the manual DS_CIA_PARITY run against a real cia
// before they are trusted as cross-tool goldens (D49 spirit: queued review,
// never auto-regen — see TestMatchKeyCIAParityDrift below).
//
// The vectors deliberately exercise the three encoder hazards that make a naive
// json.Marshal diverge from CPython's json.dumps: non-ASCII (ensure_ascii
// \uXXXX), the <>& characters (Go HTML-escapes, Python does not), and a
// multi-turn growing-history body with tool_use/tool_result blocks. They are
// widened to cover CAPTURE-TOOL-DESIGN.md §7's most-likely-subtle-bug surface at
// zero live-run cost: varied image media_type (which is NOT part of the key —
// only source.data is hashed), multi-image content blocks, and mixed
// tool_result+text content (including a tool_result whose content is itself a
// block list of text + image).
//
// The vectors (name, request body, expected key) are SINGLE-SOURCED from the
// synthetic JSON fixture testdata/parity-vectors.json (+ its .provenance
// sidecar) so the offline pin below and the env-gated regen/drift leg
// (TestMatchKeyCIAParityDrift) can never disagree about what is being checked.
//
// DRIFT (future-proofing). The offline test pins keys the Go matcher must
// reproduce; it cannot, by itself, detect FUTURE drift in cia's own key
// derivation (CAPTURE-TOOL-DESIGN.md §6 Q3 / §7 — the most likely subtle bug
// before the 01KTXKJYYW migration trusts ds-capture replay against
// cia-recorded cassettes). TestMatchKeyCIAParityDrift is the cross-tool sensor:
// it is OFF by default (t.Skip ONLY when the DS_CIA_PARITY gate is unset), and
// CI + the offline suite NEVER run it. To re-derive the goldens against a local
// cia checkout (a deferred MANUAL step):
//
//	DS_CIA_PARITY=1 DS_CIA_DIR=/path/to/cia \
//	  go test ./client/cmd/ds-capture/internal/cassette/ -run TestMatchKeyCIAParityDrift -v
//
// It exec's python3 importing cia.cassette and computing
// match_key(normalize_request("POST","/v1/messages", body)) per vector — a
// PURE-FUNCTION library call: no network, no proxy, NEVER `cia run` / live
// claude. On divergence it FAILS loudly, naming the first divergent vector and
// printing the freshly computed cia keys so a human re-pins testdata/
// parity-vectors.json DELIBERATELY (drift is a queued review per D49 spirit,
// never auto-regen).
//
// OPT-IN MUST NOT SILENTLY DEGRADE. Setting DS_CIA_PARITY=1 is an explicit
// operator signal "run the cross-tool check". If the gate is on but the cia
// checkout is unusable (DS_CIA_DIR unset, missing, or not a cia checkout), the
// drift leg t.FATALs — it never t.Skips, because a skip would read as "all
// good" to the operator who asked for the check. t.Skip is correct ONLY when
// the gate itself (DS_CIA_PARITY) is unset.

// parityVector is one (name, request body, expected cia key) tuple. method and
// path are shared (POST /v1/messages) — see parityVectors.
type parityVector struct {
	Name string         `json:"name"`
	Body map[string]any `json:"body"`
	Key  string         `json:"key"`
}

// parityVectorFile is the on-disk shape of testdata/parity-vectors.json.
type parityVectorFile struct {
	Method  string         `json:"method"`
	Path    string         `json:"path"`
	Vectors []parityVector `json:"vectors"`
}

// parityVectorsPath is the single source of truth, relative to this package.
const parityVectorsPath = "testdata/parity-vectors.json"

// loadParityVectors reads the synthetic fixture both the offline pin and the
// drift leg key off of. JSON numbers decode to float64, exactly as a live CC
// body would after the proxy's json decode — and NormalizeRequest ignores the
// sampling params (temperature/max_tokens/stream) anyway, so the round-trip is
// faithful.
func loadParityVectors(t *testing.T) parityVectorFile {
	t.Helper()
	raw, err := os.ReadFile(parityVectorsPath)
	if err != nil {
		t.Fatalf("read parity vectors %s: %v", parityVectorsPath, err)
	}
	var pf parityVectorFile
	if err := json.Unmarshal(raw, &pf); err != nil {
		t.Fatalf("parse parity vectors %s: %v", parityVectorsPath, err)
	}
	if pf.Method == "" || pf.Path == "" {
		t.Fatalf("parity vectors %s: missing method/path", parityVectorsPath)
	}
	if len(pf.Vectors) == 0 {
		t.Fatalf("parity vectors %s: no vectors", parityVectorsPath)
	}
	return pf
}

func TestMatchKeyCIAParity(t *testing.T) {
	pf := loadParityVectors(t)
	for _, v := range pf.Vectors {
		got := MatchKey(NormalizeRequest(pf.Method, pf.Path, v.Body))
		if got != v.Key {
			t.Errorf("%s: match key diverged from cia\n got=%q\nwant=%q", v.Name, got, v.Key)
		}
	}
}

// ciaParityDriftScript is the pure-function cia driver run under python3. It
// imports cia.cassette and recomputes match_key(normalize_request(...)) for
// every vector in the same testdata fixture the Go pin uses, emitting
// "name<TAB>key" lines on stdout. NO network, NO proxy, NO `cia run` — it only
// calls two pure library functions. DS_CIA_DIR is prepended to sys.path so the
// local cia checkout is importable without installing it.
const ciaParityDriftScript = `
import json, os, sys
sys.path.insert(0, os.environ["DS_CIA_DIR"])
from cia.cassette import normalize_request, match_key  # pure functions; no I/O
with open(os.environ["DS_CIA_VECTORS"], "r", encoding="utf-8") as fh:
    doc = json.load(fh)
method, path = doc["method"], doc["path"]
for v in doc["vectors"]:
    key = match_key(normalize_request(method, path, v["body"]))
    sys.stdout.write(v["name"] + "\t" + key + "\n")
`

// TestMatchKeyCIAParityDrift is the env-gated cross-tool drift sensor. The
// DS_CIA_PARITY gate is the operator's explicit opt-in:
//
//   - DS_CIA_PARITY unset → t.Skip (the check is off; CI and the default
//     offline suite take this branch and never exec cia). This is the ONLY
//     correct skip.
//   - DS_CIA_PARITY=1 but the cia checkout is unusable (DS_CIA_DIR unset,
//     missing, or not a cia checkout) → t.FATAL. The opt-in is an explicit
//     signal "run this check"; degrading to a skip would read as "all good" to
//     the operator who asked for it, silently hiding the very drift the leg
//     exists to catch. Fail loudly, naming exactly what is broken.
//   - DS_CIA_PARITY=1 with a real cia checkout → exec python3 to recompute every
//     vector's key with the REAL cia library (a pure
//     match_key(normalize_request(...)) call — no network, no proxy, never
//     `cia run` / live claude) and fail on the FIRST vector whose freshly
//     computed cia key differs from the pinned golden, printing both so a human
//     re-pins testdata/parity-vectors.json deliberately (D49 spirit: queued
//     review, never auto-regen).
//
// Manual invocation:
//
//	DS_CIA_PARITY=1 DS_CIA_DIR=/path/to/cia \
//	  go test ./client/cmd/ds-capture/internal/cassette/ -run TestMatchKeyCIAParityDrift -v
func TestMatchKeyCIAParityDrift(t *testing.T) {
	if os.Getenv("DS_CIA_PARITY") != "1" {
		t.Skip("cross-tool cia drift check is off; set DS_CIA_PARITY=1 and DS_CIA_DIR=<cia checkout> to run it (deferred manual step — never in CI)")
	}
	// From here on DS_CIA_PARITY=1: the operator explicitly asked to run the
	// check, so a broken cia checkout is a LOUD FAILURE, never a silent skip.
	ciaDir := os.Getenv("DS_CIA_DIR")
	if ciaDir == "" {
		t.Fatal("DS_CIA_PARITY=1 (explicit opt-in) but DS_CIA_DIR is unset; set DS_CIA_DIR=<cia checkout> so cia.cassette is importable. The opt-in must not silently degrade to a skip — that would read as 'parity confirmed' when nothing was checked")
	}
	if _, err := os.Stat(filepath.Join(ciaDir, "cia", "cassette.py")); err != nil {
		t.Fatalf("DS_CIA_PARITY=1 (explicit opt-in) but DS_CIA_DIR=%q does not look like a cia checkout (no cia/cassette.py): %v. The opt-in must not silently degrade to a skip — fix DS_CIA_DIR or unset DS_CIA_PARITY", ciaDir, err)
	}

	pf := loadParityVectors(t)

	// Pure-function cia call: python3 -c <script>, fed the same testdata fixture.
	// Absolute path so cwd cannot change which vectors are checked.
	vectorsAbs, err := filepath.Abs(parityVectorsPath)
	if err != nil {
		t.Fatalf("resolve vectors path: %v", err)
	}
	cmd := exec.Command("python3", "-c", ciaParityDriftScript)
	cmd.Env = append(os.Environ(), "DS_CIA_DIR="+ciaDir, "DS_CIA_VECTORS="+vectorsAbs)
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("exec python3 cia.cassette driver failed: %v\nstderr:\n%s", err, stderr)
	}

	// Parse "name<TAB>key" lines and compare against the pinned goldens. Fail on
	// the FIRST divergence, printing the fresh cia key so a human re-pins.
	got := make(map[string]string, len(pf.Vectors))
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		name, key, ok := strings.Cut(line, "\t")
		if !ok {
			t.Fatalf("cia driver emitted a malformed line (no tab): %q", line)
		}
		got[name] = key
	}

	for _, v := range pf.Vectors {
		fresh, ok := got[v.Name]
		if !ok {
			t.Fatalf("cia driver did not emit a key for vector %q (got %d of %d)", v.Name, len(got), len(pf.Vectors))
		}
		if fresh != v.Key {
			t.Fatalf("CIA KEY-DERIVATION DRIFT — vector %q diverged from the pinned golden.\n"+
				"  pinned golden : %s\n"+
				"  fresh from cia: %s\n"+
				"cia's match_key has changed. This is a QUEUED REVIEW (D49 spirit), NOT an auto-regen: "+
				"verify the change is intended, then deliberately re-pin %s. Fresh keys for all vectors:\n%s",
				v.Name, v.Key, fresh, parityVectorsPath, formatFreshKeys(pf.Vectors, got))
		}
	}
}

// formatFreshKeys renders the full name->fresh-key table (in vector order) so a
// re-pin has every value at hand, not just the first divergent one.
func formatFreshKeys(vectors []parityVector, got map[string]string) string {
	var b strings.Builder
	for _, v := range vectors {
		b.WriteString("  ")
		b.WriteString(v.Name)
		b.WriteString(": ")
		b.WriteString(got[v.Name])
		b.WriteString("\n")
	}
	return b.String()
}

// TestCIAParityDriftOptInFailsLoudlyOnBrokenEnv proves the opt-in-must-not-
// silently-degrade contract: with DS_CIA_PARITY=1 (explicit operator opt-in)
// but a DS_CIA_DIR that points at an EMPTY directory (no cia/cassette.py),
// TestMatchKeyCIAParityDrift must FAIL (t.Fatal), not Skip — a skip would read
// as "parity confirmed" when nothing was checked.
//
// It proves this WITHOUT any real cia execution: the drift leg t.Fatals at the
// os.Stat("cia/cassette.py") guard, which fires BEFORE the python3/cia exec
// path is ever reached, so no python3, no cia.cassette, and certainly no
// `cia run` / live claude is invoked. The subprocess is just this test binary
// re-run with the gate set against an empty temp dir.
//
// The re-exec (os.Args[0] with -test.run pinned to the drift test) is the
// standard Go pattern for asserting a t.Fatal path: run the failing test in a
// child process and assert the child exits non-zero, instead of fataling this
// (passing) test. A guard env var (DS_CIA_PARITY_SELFTEST_CHILD) is NOT needed
// because -test.run already isolates the child to exactly the drift test.
func TestCIAParityDriftOptInFailsLoudlyOnBrokenEnv(t *testing.T) {
	// An empty temp dir: it exists, but has no cia/cassette.py, so it is a
	// broken/"moved or stale" cia checkout from the drift leg's point of view.
	emptyDir := t.TempDir()

	// Re-run ONLY TestMatchKeyCIAParityDrift in a child process, with the opt-in
	// gate ON and DS_CIA_DIR aimed at the empty dir. -test.run is anchored so no
	// other test in the package runs in the child.
	cmd := exec.Command(os.Args[0], "-test.run", "^TestMatchKeyCIAParityDrift$", "-test.v")
	cmd.Env = append(os.Environ(),
		"DS_CIA_PARITY=1",
		"DS_CIA_DIR="+emptyDir,
	)
	out, err := cmd.CombinedOutput()
	combined := string(out)

	// The child MUST fail (non-zero exit). A nil err means it passed or skipped
	// — exactly the silent-degradation regression this test exists to forbid.
	if err == nil {
		t.Fatalf("DS_CIA_PARITY=1 with an empty/broken DS_CIA_DIR did NOT fail the drift test "+
			"(it passed or skipped — the opt-in silently degraded). child output:\n%s", combined)
	}
	if _, ok := err.(*exec.ExitError); !ok {
		// A non-ExitError (e.g. the binary could not be launched) is an
		// environment problem, not the behavior under test.
		t.Fatalf("could not run the drift test in a child process: %v\noutput:\n%s", err, combined)
	}

	// It must FAIL, not SKIP: assert the child reported a failure and did not
	// take the skip branch.
	if !strings.Contains(combined, "--- FAIL") && !strings.Contains(combined, "FAIL\t") {
		t.Errorf("child exited non-zero but output does not show a test FAILURE; "+
			"the opt-in path must t.Fatal, not skip. output:\n%s", combined)
	}
	if strings.Contains(combined, "--- SKIP") {
		t.Errorf("drift test SKIPPED under DS_CIA_PARITY=1 with a broken DS_CIA_DIR — "+
			"the explicit opt-in must never degrade to a skip. output:\n%s", combined)
	}
	// And the loud message must name the opt-in so an operator understands why.
	if !strings.Contains(combined, "DS_CIA_PARITY=1") {
		t.Errorf("drift-failure message should name the DS_CIA_PARITY=1 opt-in. output:\n%s", combined)
	}
	// Prove no real cia ran: the empty-dir guard fatals BEFORE the python3 exec,
	// so the cia driver's failure string can never appear.
	if strings.Contains(combined, "exec python3 cia.cassette driver failed") {
		t.Errorf("the empty-DS_CIA_DIR case must fatal at the checkout guard, BEFORE any "+
			"python3/cia execution; the python3 driver was reached. output:\n%s", combined)
	}
}

// TestMatcherToleranceGrowingHistory proves the tolerant matcher: a body whose
// volatile ids, sampling params, stream flag, and request metadata all differ
// yields the SAME key, as long as the semantic turn sequence is identical.
func TestMatcherToleranceGrowingHistory(t *testing.T) {
	base := map[string]any{
		"model":  "claude-synthetic-test-1",
		"system": "You are a test fixture.",
		"messages": []any{
			map[string]any{"role": "user", "content": "list files"},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "text", "text": "I'll list them."},
				map[string]any{"type": "tool_use", "id": "toolu_VOLATILE_AAA", "name": "ls", "input": map[string]any{"path": "/x"}},
			}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "toolu_VOLATILE_AAA", "content": "a.txt\nb.txt"},
			}},
			map[string]any{"role": "user", "content": "thanks"},
		},
	}
	// Same conversation, but every volatile/ignored field is perturbed.
	perturbed := map[string]any{
		"model":       "claude-synthetic-test-1",
		"system":      "You are a test fixture.",
		"stream":      true,
		"temperature": 0.2,
		"top_p":       0.9,
		"top_k":       float64(40),
		"metadata":    map[string]any{"user_id": "synthetic-user-zzz"},
		"messages": []any{
			map[string]any{"role": "user", "content": "list files"},
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "text", "text": "I'll list them."},
				map[string]any{"type": "tool_use", "id": "toolu_VOLATILE_DIFFERENT", "name": "ls", "input": map[string]any{"path": "/x"}},
			}},
			map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": "toolu_VOLATILE_DIFFERENT", "content": "a.txt\nb.txt"},
			}},
			map[string]any{"role": "user", "content": "thanks"},
		},
	}
	kBase := MatchKey(NormalizeRequest("POST", "/v1/messages", base))
	kPert := MatchKey(NormalizeRequest("POST", "/v1/messages", perturbed))
	if kBase != kPert {
		t.Fatalf("tolerant matcher broke: volatile/sampling perturbation changed the key\n base=%q\npert=%q", kBase, kPert)
	}
}

// TestMatcherDistinguishesSemantics proves the matcher is non-vacuous: a real
// semantic change (different last turn, different model, different system)
// yields a DIFFERENT key.
func TestMatcherDistinguishesSemantics(t *testing.T) {
	mk := func(model, sys, last string) string {
		return MatchKey(NormalizeRequest("POST", "/v1/messages", map[string]any{
			"model":    model,
			"system":   sys,
			"messages": []any{map[string]any{"role": "user", "content": last}},
		}))
	}
	a := mk("claude-synthetic-test-1", "sys", "hello")
	for _, b := range []string{
		mk("claude-synthetic-test-2", "sys", "hello"),   // model differs
		mk("claude-synthetic-test-1", "sys2", "hello"),  // system differs
		mk("claude-synthetic-test-1", "sys", "goodbye"), // turn differs
	} {
		if a == b {
			t.Errorf("matcher vacuous: semantic difference produced same key %q", a)
		}
	}
}

// TestQueryStringStripped confirms the path query string is dropped (cia
// path.split("?",1)[0]) so it cannot perturb the key.
func TestQueryStringStripped(t *testing.T) {
	body := map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "x"}}}
	a := MatchKey(NormalizeRequest("POST", "/v1/messages", body))
	b := MatchKey(NormalizeRequest("POST", "/v1/messages?beta=true", body))
	if a != b {
		t.Errorf("query string leaked into key:\n a=%q\n b=%q", a, b)
	}
}

// TestFindMatchOnceSemantics proves VCR "once" ordering: two recordings of
// different turns are each served once, in order; a recording the client
// repeats falls through to serving that single recording again (idempotent),
// while a truly unknown request returns nil.
func TestFindMatchOnceSemantics(t *testing.T) {
	c := New()
	turn := func(content string) map[string]any {
		return map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": content}}}
	}
	c.Record("POST", "/v1/messages", turn("one"), 200, nil, "event: a\ndata: 1\n\n")
	c.Record("POST", "/v1/messages", turn("two"), 200, nil, "event: b\ndata: 2\n\n")

	// First match for "one" returns the first recording.
	got := c.FindMatch("POST", "/v1/messages", turn("one"))
	if got == nil || got.Body != "event: a\ndata: 1\n\n" {
		t.Fatalf("first 'one' match wrong: %#v", got)
	}
	// "two" returns its own recording (in order).
	got = c.FindMatch("POST", "/v1/messages", turn("two"))
	if got == nil || got.Body != "event: b\ndata: 2\n\n" {
		t.Fatalf("'two' match wrong: %#v", got)
	}
	// "one" repeats: only one recording exists, so the idempotent fallback
	// serves it again (not a miss).
	got = c.FindMatch("POST", "/v1/messages", turn("one"))
	if got == nil || got.Body != "event: a\ndata: 1\n\n" {
		t.Fatalf("repeated 'one' should fall back to its single recording: %#v", got)
	}
	// A truly unknown request returns nil.
	if got = c.FindMatch("POST", "/v1/messages", turn("unknown")); got != nil {
		t.Fatalf("unknown request should miss, got %#v", got)
	}
}

// TestFindMatchOnceConsumesDistinctRecordings proves two recordings of the
// SAME turn are each consumed once, in order, before the idempotent fallback.
func TestFindMatchOnceConsumesDistinctRecordings(t *testing.T) {
	c := New()
	turn := map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "dup"}}}
	c.Record("POST", "/v1/messages", turn, 200, nil, "first")
	c.Record("POST", "/v1/messages", turn, 200, nil, "second")

	if got := c.FindMatch("POST", "/v1/messages", turn); got == nil || got.Body != "first" {
		t.Fatalf("play 1 should be 'first', got %#v", got)
	}
	if got := c.FindMatch("POST", "/v1/messages", turn); got == nil || got.Body != "second" {
		t.Fatalf("play 2 should be 'second', got %#v", got)
	}
	// Both consumed: fallback re-serves a recording rather than missing.
	if got := c.FindMatch("POST", "/v1/messages", turn); got == nil {
		t.Fatalf("play 3 should idempotently re-serve, got nil")
	}
	c.ResetPlays()
	if got := c.FindMatch("POST", "/v1/messages", turn); got == nil || got.Body != "first" {
		t.Fatalf("after ResetPlays play 1 should be 'first', got %#v", got)
	}
}

// TestSaveLoadRoundTrip proves a cassette saves and loads losslessly, and that
// the on-disk JSON carries cia's version:1 shape.
func TestSaveLoadRoundTrip(t *testing.T) {
	c := New()
	c.Record("POST", "/v1/messages",
		map[string]any{"model": "claude-synthetic-test-1", "system": "Ünïcode ☃ <tag>",
			"messages": []any{map[string]any{"role": "user", "content": "say hi"}}},
		200, map[string]string{"content-type": "text/event-stream", "request-id": "DROP-ME"},
		"event: message_start\ndata: {\"type\":\"message_start\"}\n\n")

	dir := t.TempDir()
	path := dir + "/round.json"
	if err := c.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Version != CassetteVersion {
		t.Errorf("version: got %d want %d", loaded.Version, CassetteVersion)
	}
	if loaded.Len() != 1 {
		t.Fatalf("interactions: got %d want 1", loaded.Len())
	}
	got := loaded.Interactions[0]
	if got.Key != c.Interactions[0].Key {
		t.Errorf("key not preserved:\n got=%q\nwant=%q", got.Key, c.Interactions[0].Key)
	}
	if got.Body != c.Interactions[0].Body {
		t.Errorf("body not preserved")
	}
	// request-id must have been dropped; content-type kept.
	if _, ok := got.Headers["request-id"]; ok {
		t.Errorf("volatile request-id header survived into the cassette")
	}
	if got.Headers["content-type"] != "text/event-stream" {
		t.Errorf("content-type not preserved: %q", got.Headers["content-type"])
	}
}

// TestOnDiskShapeCIACompatible asserts the persisted JSON is the cia version:1
// document shape: a top-level {version, interactions:[{key,normalized,
// status_code,headers,body}]}, with no HTML-escaping of <>& and raw non-ASCII
// (ensure_ascii=False on disk — the human-diffable form cia.save writes).
func TestOnDiskShapeCIACompatible(t *testing.T) {
	c := New()
	c.Record("POST", "/v1/messages",
		map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "a < b & <tag> ☃"}}},
		200, nil, "event: x\ndata: 1 < 2\n\n")
	raw, err := marshalCassette(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(raw)
	// version:1 present.
	if !strings.Contains(s, `"version": 1`) {
		t.Errorf("missing version:1 in on-disk doc:\n%s", s)
	}
	// The required keys are present.
	for _, want := range []string{`"interactions"`, `"key"`, `"normalized"`, `"status_code"`, `"headers"`, `"body"`} {
		if !strings.Contains(s, want) {
			t.Errorf("on-disk doc missing field %s", want)
		}
	}
	// On disk, <>& are NOT HTML-escaped: Go's default encoder would emit the
	// six-char \uXXXX escape for each of < (<), > (>), & (&) —
	// those escape sequences must be ABSENT, since cia writes the raw chars
	// (ensure_ascii=False, no HTML escaping). Build the needles from a
	// backslash so the source itself is unambiguous.
	bs := string([]byte{0x5c}) // a single backslash
	for _, code := range []string{"u003c", "u003e", "u0026"} {
		needle := bs + code
		if strings.Contains(s, needle) {
			t.Errorf("on-disk doc HTML-escaped a char as %s (should be raw):\n%s", needle, s)
		}
	}
	// The raw characters should be present in the body verbatim.
	if !strings.Contains(s, "1 < 2") {
		t.Errorf("on-disk body should carry raw '<':\n%s", s)
	}
	if !strings.Contains(s, "☃") {
		t.Errorf("on-disk doc should carry raw non-ASCII (ensure_ascii=False)")
	}
	// And it must still parse as a cassette.
	if _, err := parse(raw, "memory"); err != nil {
		t.Errorf("re-parse of on-disk doc failed: %v", err)
	}
}

// TestLoadRejectsBadVersion proves a version mismatch is rejected (cia parity).
func TestLoadRejectsBadVersion(t *testing.T) {
	bad := []byte(`{"version": 99, "interactions": []}`)
	if _, err := parse(bad, "bad"); err == nil {
		t.Errorf("expected version-mismatch rejection, got nil")
	}
	missing := []byte(`{"version": 1}`)
	if _, err := parse(missing, "missing"); err == nil {
		t.Errorf("expected missing-interactions rejection, got nil")
	}
}

// TestFilterReplayHeaders proves only content-type survives and it defaults.
func TestFilterReplayHeaders(t *testing.T) {
	out := FilterReplayHeaders(map[string]string{
		"Content-Type":  "text/event-stream; charset=utf-8",
		"Authorization": "<stripped>",
		"Request-Id":    "<stripped>",
		"Date":          "<stripped>",
	})
	if len(out) != 1 {
		t.Fatalf("expected only content-type, got %v", out)
	}
	if out["content-type"] != "text/event-stream; charset=utf-8" {
		t.Errorf("content-type wrong: %q", out["content-type"])
	}
	// Default when absent.
	d := FilterReplayHeaders(map[string]string{"x-foo": "bar"})
	if d["content-type"] != "text/event-stream" {
		t.Errorf("content-type default missing: %v", d)
	}
}

// TestNormalizedJSONFieldOrder confirms the Normalized struct marshals with
// json field names cia expects (snake_case via tags where they differ).
func TestNormalizedJSONFieldOrder(t *testing.T) {
	n := NormalizeRequest("post", "/v1/messages?x=1",
		map[string]any{"model": "m", "messages": []any{map[string]any{"role": "user", "content": "hi"}}})
	if n.Method != "POST" {
		t.Errorf("method not upper-cased: %q", n.Method)
	}
	if n.Path != "/v1/messages" {
		t.Errorf("path query not stripped: %q", n.Path)
	}
	b, _ := json.Marshal(n)
	for _, want := range []string{`"method"`, `"path"`, `"model"`, `"system"`, `"sequence"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("normalized JSON missing %s: %s", want, b)
		}
	}
}

// TestParseSSE proves the event:/data: framing parser, including multi-line
// data joining and comment/blank handling — with NO metrics surface.
func TestParseSSE(t *testing.T) {
	body := ": comment line\n" +
		"event: message_start\n" +
		"data: {\"type\":\"message_start\"}\n" +
		"\n" +
		"event: content_block_delta\n" +
		"data: line one\n" +
		"data: line two\n" +
		"\n"
	evs := ParseSSE(body)
	if len(evs) != 2 {
		t.Fatalf("expected 2 events, got %d: %#v", len(evs), evs)
	}
	if evs[0].Event != "message_start" || evs[0].Data != `{"type":"message_start"}` {
		t.Errorf("event 0 wrong: %#v", evs[0])
	}
	if evs[1].Event != "content_block_delta" || evs[1].Data != "line one\nline two" {
		t.Errorf("event 1 multi-line data wrong: %#v", evs[1])
	}
	types := EventTypes(body)
	if len(types) != 2 || types[0] != "message_start" || types[1] != "content_block_delta" {
		t.Errorf("EventTypes wrong: %v", types)
	}
}

// TestVolatileRequestHeader covers the auth/volatile set scrub strips.
func TestVolatileRequestHeader(t *testing.T) {
	for _, h := range []string{"Authorization", "x-api-key", "anthropic-beta", "X-Claude-Code-Session-Id", "cookie"} {
		if !VolatileRequestHeader(h) {
			t.Errorf("%q should be volatile/auth", h)
		}
	}
	if VolatileRequestHeader("content-type") {
		t.Errorf("content-type must not be volatile")
	}
}
