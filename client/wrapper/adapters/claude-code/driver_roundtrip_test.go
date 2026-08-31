// driver_roundtrip_test.go — the WRITE-side MIRROR of the read-side spawn
// assertions (goldentrace/replay/spawn_test.go). Where the read side replays the
// spawn/ask cassettes and asserts the spawn-tree *projection* shape, this file
// asserts the inverse: the driver's emitted wire BYTES for the spawn-adjacent
// drive flows are PINNED (golden-style), and those same bytes, fed back through
// the adapter's decode path, are projection-stable.
//
// Why a separate file from driver_test.go: driver_test.go decodes emitted bytes
// back through records.go and asserts STRUCTURALLY (field-by-field). It proves
// the shape is *decodable* and the correlation ids thread through, but it does
// NOT pin the literal wire bytes — so a re-marshaling that reorders keys, adds a
// spurious field, or changes whitespace could still pass every structural check
// while diverging from the captured P4/P8 wire shape the read side decodes. The
// read side has explicit golden byte pins (validateEvents byte-compares the
// projection; spawn_test.go names the spawn shape); the write side had decode-
// back round-trips but no golden byte-shape pins. This file adds them, mirroring
// the read side's spawn assertions onto the write path.
//
// Assertion discipline (DRIVE-PROTOCOL.md "Rules the replay tier MUST honor"):
//   - The pinned bytes are ID-RELATIVE, not literal-CC-minted. The Driver mints
//     NO uuid/session_id/task_id — CC stamps those — so nothing in a pinned line
//     is a CC-minted-at-runtime id. The ONLY ids that appear are the within-run
//     correlation ids the CALLER supplies (the ask's request_id / tool_use_id),
//     which DRIVE-PROTOCOL.md explicitly says to correlate on ("the within-run id
//     triple"). Those are deterministic inputs to the encoder, so pinning the
//     full output line is legitimate and reproducible.
//   - No wall-clock / timing anywhere: the Driver emits none and asserts none.
//   - The drive scenarios are FIXTURE-DERIVED — the same spawn-adjacent flows the
//     read side asserts: the nested-spawn / parallel-fanout subagent-driving
//     prompts (the P4 inputs that drive each subagent turn) and the ask-control
//     allow/deny grants (the P8 control_response the read side decodes off
//     creq_synthetic_0301/0302). Driving the SAME scenarios from the write side
//     is what makes this the mirror.
//
// Determinism note: encoding/json marshals struct fields in declaration order,
// so each EncodeInput/EncodeGrant/EncodeGrantPromptTool output is a deterministic
// function of its input — the golden lines below are byte-stable across runs.
// TestDriveGolden_DeterministicAcrossRuns proves it by re-encoding and comparing.
package claudecode

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// --- Fixture-derived ask correlation (the write-side derivation anchor) -------
//
// The write-side grant goldens used to HAND-PIN creq_synthetic_0301/0302 and the
// echoed input as free literals; this block derives those same correlation ids —
// and the allow path's echoed-input — from the committed ask-control cassette by
// the adapter's OWN ProcessStream, so the write side's join keys come from the
// fixture bytes, not a second hand-maintained copy. DRIVE-PROTOCOL.md fixes the
// discipline: the request_id / tool_use_id are the within-run correlation ids the
// caller supplies, deterministic inputs to the encoder — derived here, then the
// golden wire lines are CROSS-CHECKED against the derived values (the byte-pins
// stay, but they are proven to carry the fixture's ids, not arbitrary constants).

// askControlFixture is the cassette the write-side ask flows derive from — the
// derivation ANCHOR (project constraint: zero byte changes to it). Relative to
// this package dir (client/wrapper/adapters/claude-code).
const askControlFixture = "../../../fixtures/ask-control.cc-wire.ndjson"

// derivedAsk is one ask projected out of the ask-control cassette: the request_id
// the control_response joins on, the tool_use id it correlated, and the input the
// request carried (the allow path echoes this verbatim).
type derivedAsk struct {
	requestID string          // AskRequested.AskID — the control request_id (creq_synthetic_03xx)
	toolUseID string          // AskRequested.NodeID — the tool_use id the ask correlated
	input     json.RawMessage // AskRequested.Input — the request's tool input (echoed on allow)
}

// deriveAskControlAsks runs the adapter's ProcessStream over the committed
// ask-control cassette and returns the projected asks keyed by the tool command
// the request carries (input.command) — a STABLE semantic handle that is NOT the
// synthetic correlation id. This is the SAME decode path the read side exercises
// (handleControlRequest → AskRequested), so the write-side request_id /
// tool_use_id / echoed-input are all DERIVED from the fixture the read side
// decodes, with no creq_synthetic_03xx literal as the selector: the grant table
// names an ask by its command (mkdir/rm), and the correlation id flows out of the
// cassette bytes.
func deriveAskControlAsks(t *testing.T) map[string]derivedAsk {
	t.Helper()
	f, err := os.Open(askControlFixture)
	if err != nil {
		t.Fatalf("open ask-control cassette: %v", err)
	}
	defer f.Close()

	a := New(WithClock(testClock()))
	evs, err := a.ProcessStream(f)
	if err != nil {
		t.Fatalf("ProcessStream(ask-control): %v", err)
	}

	asks := map[string]derivedAsk{}
	for _, ev := range evs {
		if ev.Type != attach.TypeAskRequested || ev.AskRequested == nil {
			continue
		}
		r := ev.AskRequested
		// The native ask carries request_id as AskID and the tool_use id as
		// NodeID (ask.go handleControlRequest); skip a rearm/non-native ask (none
		// in this fixture, but be exact about the channel).
		if r.Source != "control" {
			continue
		}
		cmd := askCommand(r.Input)
		if cmd == "" {
			t.Fatalf("derived ask %q carries no input.command to key on (input=%s)", r.AskID, r.Input)
		}
		if _, dup := asks[cmd]; dup {
			t.Fatalf("ask-control cassette has two asks with command %q — the derivation keys on a UNIQUE command", cmd)
		}
		asks[cmd] = derivedAsk{
			requestID: r.AskID,
			toolUseID: r.NodeID,
			input:     append(json.RawMessage(nil), r.Input...),
		}
	}
	if len(asks) == 0 {
		t.Fatal("ask-control cassette projected no native asks — the derivation anchor is broken")
	}
	return asks
}

// askCommand reads input.command from a derived ask's tool input — the stable
// semantic key deriveAskControlAsks maps each ask under (so the grant table can
// reference an ask without naming its synthetic request_id).
func askCommand(input json.RawMessage) string {
	var obj struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(input, &obj); err != nil {
		return ""
	}
	return obj.Command
}

// askByCommand returns the derived ask for the tool command, failing the test by
// name if the cassette carried none (so a fixture edit that drops/renames the ask
// is caught here rather than silently leaving a golden unverified).
func askByCommand(t *testing.T, asks map[string]derivedAsk, command string) derivedAsk {
	t.Helper()
	a, ok := asks[command]
	if !ok {
		cmds := make([]string, 0, len(asks))
		for k := range asks {
			cmds = append(cmds, k)
		}
		t.Fatalf("ask-control cassette carries no ask with command %q (derived: %v)", command, cmds)
	}
	return a
}

// drvSameProjection reports whether two decoded projections are equal. The
// records.go decode structs embed json.RawMessage ([]byte), so they are not
// `==`-comparable; re-marshal both and byte-compare — the decoded projection is
// "stable" iff it serializes identically. (The ENCODER output is already byte-
// pinned by the golden tests; this asserts the DECODED view is reproducible too.)
func drvSameProjection[T any](t *testing.T, a, b T) bool {
	t.Helper()
	ab, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("re-marshal projection a: %v", err)
	}
	bb, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("re-marshal projection b: %v", err)
	}
	return bytes.Equal(ab, bb)
}

// --- The fixture-derived drive scenarios (mirror of the read-side spawn set) --
//
// These mirror the spawn-adjacent flows goldentrace/replay/spawn_test.go asserts:
//   - nested-spawn   (client/fixtures/nested-spawn.cc-wire.ndjson): the outer/inner
//     subagent-driving prompts.
//   - parallel-fanout (…/parallel-fanout.cc-wire.ndjson): the per-sibling prompts.
//   - ask-control    (…/ask-control.cc-wire.ndjson): the allow (creq_synthetic_0301,
//     mkdir, updatedInput echoed) and deny (creq_synthetic_0302, rm -rf, message)
//     control_response the read side decodes via handleControlResponse.
//
// Each row is the DRIVE input the thin client / policy stream would emit to
// reproduce that scenario from the write side, plus the exact wire line the
// Driver must emit. The wire lines were captured from the encoder itself and are
// the golden — a change to them is a deliberate wire-shape change to review, not
// an incidental test edit.

// driveInputGoldens pins EncodeInput across the spawn-driving prompts the read
// side's spawn cassettes carry. The text is the (deterministic) prompt that
// drives each subagent turn; the golden is the full P4 single-block envelope.
var driveInputGoldens = []struct {
	scenario string // which read-side cassette this drive prompt belongs to
	name     string
	text     string
	wantLine string
}{
	{
		scenario: "nested-spawn",
		name:     "outer-prompt",
		text:     "spawn the inner subagent then report",
		wantLine: `{"type":"user","message":{"role":"user","content":[{"type":"text","text":"spawn the inner subagent then report"}]}}`,
	},
	{
		scenario: "nested-spawn",
		name:     "inner-prompt",
		text:     "do the inner work",
		wantLine: `{"type":"user","message":{"role":"user","content":[{"type":"text","text":"do the inner work"}]}}`,
	},
	{
		scenario: "parallel-fanout",
		name:     "alpha-prompt",
		text:     "scan alpha",
		wantLine: `{"type":"user","message":{"role":"user","content":[{"type":"text","text":"scan alpha"}]}}`,
	},
	// subagent-spawn (the read side's missed-lifecycle / accounting-only cassette):
	// the write-side mirror still drives the turn that launches that subagent, so
	// the legacy smoke scenario is covered on BOTH sides (its read-side row pins 0
	// projected spawns; the write-side row pins the byte-shape of the launching
	// prompt). Added to keep the per-package spawn coverage in lockstep — the
	// completeness check (spawn_scenarios_test.go) would otherwise flag
	// subagent-spawn as write-side-uncovered.
	{
		scenario: "subagent-spawn",
		name:     "launch-prompt",
		text:     "run the legacy smoke subagent",
		wantLine: `{"type":"user","message":{"role":"user","content":[{"type":"text","text":"run the legacy smoke subagent"}]}}`,
	},
	// depth3-nested-spawn (root → outer → middle → grand): the deepest spawn
	// cassette the read side asserts (the depth-3 "inferred" confidence branch).
	// Mirrored here so the depth-3 scenario drives from the write side too —
	// ACCEPTANCE requires depth3-nested-spawn covered on BOTH sides.
	{
		scenario: "depth3-nested-spawn",
		name:     "grand-prompt",
		text:     "drive the depth-3 grandchild chain",
		wantLine: `{"type":"user","message":{"role":"user","content":[{"type":"text","text":"drive the depth-3 grandchild chain"}]}}`,
	},
	{
		scenario: "ask-control",
		name:     "driving-turn",
		text:     "delete the scratch dir",
		wantLine: `{"type":"user","message":{"role":"user","content":[{"type":"text","text":"delete the scratch dir"}]}}`,
	},
}

// driveGrantGolden pins EncodeGrant (native P8 control_response) AND
// EncodeGrantPromptTool (the proven-live body) across the ask-control allow/deny
// flows the read side decodes. The request_id / tool_use_id are NOT hand-pinned
// literals here: each row names its ask by the tool COMMAND (a stable semantic
// handle), and grant(t, asks) BUILDS the DriveGrant by looking the ask up in the
// fixture-derived map — so the correlation ids the encoder consumes come from the
// committed ask-control bytes (the read side's askByRequestID join key), the
// DRIVE-PROTOCOL.md "id-relative, never literal" discipline. The wantNativeLine /
// wantPromptToolLine byte-pins are KEPT literal (they are the wire shape under
// review) and cross-checked against the derived ids by
// TestDriveGrantGoldens_IDsDerivedFromFixture.
type driveGrantGolden struct {
	scenario string
	name     string
	command  string // selects the fixture ask (input.command); NOT the synthetic id
	allow    bool
	// echoesInput true ⇒ the allow grant echoes the ask's OWN input verbatim
	// (UpdatedInput = the fixture-derived input). false ⇒ no rewrite (allow omits
	// updatedInput) on an allow, or a deny.
	echoesInput bool
	message     string // deny reason (deny rows only)

	wantNativeLine     string // EncodeGrant golden (literal byte-pin, cross-checked)
	wantPromptToolLine string // EncodeGrantPromptTool golden (literal byte-pin, cross-checked)
}

// grant builds the DriveGrant the encoder is fed, deriving RequestID / ToolUseID
// (and, on an echoing allow, the echoed UpdatedInput) from the fixture ask the
// row's command selects. Nothing in the returned grant is a hand-pinned synthetic
// id: every correlation value flows out of ask-control.cc-wire.ndjson.
func (g driveGrantGolden) grant(t *testing.T, asks map[string]derivedAsk) DriveGrant {
	t.Helper()
	ask := askByCommand(t, asks, g.command)
	dg := DriveGrant{
		RequestID: ask.requestID,
		ToolUseID: ask.toolUseID,
		Allow:     g.allow,
		Message:   g.message,
	}
	if g.allow && g.echoesInput {
		// The allow path echoes the request's own input verbatim — derived from
		// the cassette, not retyped.
		dg.UpdatedInput = append(json.RawMessage(nil), ask.input...)
	}
	return dg
}

var driveGrantGoldens = []driveGrantGolden{
	{
		scenario:           "ask-control",
		name:               "allow-mkdir-echoes-input",
		command:            "mkdir -p /work/scratch",
		allow:              true,
		echoesInput:        true,
		wantNativeLine:     `{"type":"control_response","response":{"subtype":"success","request_id":"creq_synthetic_0301","response":{"behavior":"allow","updatedInput":{"command":"mkdir -p /work/scratch","description":"create scratch dir"}}}}`,
		wantPromptToolLine: `{"behavior":"allow","updatedInput":{"command":"mkdir -p /work/scratch","description":"create scratch dir"}}`,
	},
	{
		scenario:           "ask-control",
		name:               "deny-rm-carries-message",
		command:            "rm -rf /work/scratch",
		allow:              false,
		message:            "Permission to use Bash with command rm -rf /work/scratch has been denied.",
		wantNativeLine:     `{"type":"control_response","response":{"subtype":"success","request_id":"creq_synthetic_0302","response":{"behavior":"deny","message":"Permission to use Bash with command rm -rf /work/scratch has been denied."}}}`,
		wantPromptToolLine: `{"behavior":"deny","message":"Permission to use Bash with command rm -rf /work/scratch has been denied."}`,
	},
	{
		scenario:           "ask-control",
		name:               "allow-no-rewrite-omits-updatedInput",
		command:            "mkdir -p /work/scratch",
		allow:              true,
		echoesInput:        false,
		wantNativeLine:     `{"type":"control_response","response":{"subtype":"success","request_id":"creq_synthetic_0301","response":{"behavior":"allow"}}}`,
		wantPromptToolLine: `{"behavior":"allow"}`,
	},
}

// TestDriveGolden_SpawnTableDrivesEveryMirroredFixture consumes the write-side
// shared spawn table (spawnScenarioFixtures, the mirror of the canonical
// fixture-derived list — see spawn_scenarios_test.go) and asserts every mirrored
// SPAWN fixture has at least one driveInputGoldens row driving its turn, AND that
// each such row's pinned wire line still byte-matches the Driver's EncodeInput.
// This is the roundtrip file's explicit consumption of the shared table: the
// spawn-driving scenarios are enumerated FROM the mirror, not from a hand-rolled
// list local to this test, so dropping a mirrored fixture's drive golden fails
// here (and the completeness check in spawn_scenarios_test.go flags it too).
// ask-control is a drive scenario but not a spawn fixture, so it is not in the
// mirror and not required here; its byte pins live in the grant goldens.
func TestDriveGolden_SpawnTableDrivesEveryMirroredFixture(t *testing.T) {
	d := NewDriver()
	byScenario := map[string][]string{} // spawn fixture → its pinned drive lines
	for _, g := range driveInputGoldens {
		byScenario[g.scenario] = append(byScenario[g.scenario], g.wantLine)
	}
	for _, fixture := range spawnScenarioFixtures {
		t.Run(fixture, func(t *testing.T) {
			lines, ok := byScenario[fixture]
			if !ok || len(lines) == 0 {
				t.Fatalf("mirrored spawn fixture %q has no driveInputGoldens row driving its turn — the write side does not pin the bytes that drive this spawn cassette", fixture)
			}
			// Re-assert each driving golden still byte-matches the encoder, so the
			// shared-table consumption carries a live byte pin, not just presence.
			for _, g := range driveInputGoldens {
				if g.scenario != fixture {
					continue
				}
				line, err := d.EncodeInput(DriveInput{Text: g.text})
				if err != nil {
					t.Fatalf("EncodeInput(%s/%s): %v", g.scenario, g.name, err)
				}
				if string(line) != g.wantLine {
					t.Errorf("%s/%s: EncodeInput wire line mismatch (shared-table drive pin)\n got: %s\nwant: %s", g.scenario, g.name, line, g.wantLine)
				}
			}
		})
	}
}

// --- Golden byte-shape pins: EncodeInput (P4 spawn-driving prompts) -----------

// TestDriveGolden_EncodeInput_SpawnPrompts pins the exact P4 wire line the Driver
// emits for each spawn-driving prompt. This is the write-side mirror of the read
// side's spawn-cassette assertions: where spawn_test.go pins the spawn-tree
// projection, this pins the input bytes that would DRIVE those spawns.
func TestDriveGolden_EncodeInput_SpawnPrompts(t *testing.T) {
	d := NewDriver()
	for _, tc := range driveInputGoldens {
		t.Run(tc.scenario+"/"+tc.name, func(t *testing.T) {
			line, err := d.EncodeInput(DriveInput{Text: tc.text})
			if err != nil {
				t.Fatalf("EncodeInput: %v", err)
			}
			if string(line) != tc.wantLine {
				t.Errorf("EncodeInput wire line mismatch (golden byte-shape pin)\n got: %s\nwant: %s", line, tc.wantLine)
			}
		})
	}
}

// --- Golden byte-shape pins: EncodeGrant + EncodeGrantPromptTool (P8 asks) -----

// TestDriveGolden_EncodeGrant_AskControlFlows pins the exact control_response and
// prompt-tool-body wire lines for the ask-control allow/deny grants the read side
// decodes (the mkdir allow / rm deny asks). The grant fed to the encoder has its
// correlation ids DERIVED from the ask-control cassette (tc.grant builds it off
// the fixture), so a green byte-pin here is a byte-pin of the encoder output for
// the FIXTURE's ids, not for retyped constants. It is the write-side mirror of
// the read side's TestControlResponse_* assertions.
func TestDriveGolden_EncodeGrant_AskControlFlows(t *testing.T) {
	d := NewDriver()
	asks := deriveAskControlAsks(t)
	for _, tc := range driveGrantGoldens {
		t.Run(tc.scenario+"/"+tc.name, func(t *testing.T) {
			grant := tc.grant(t, asks)
			native, err := d.EncodeGrant(grant)
			if err != nil {
				t.Fatalf("EncodeGrant: %v", err)
			}
			if string(native) != tc.wantNativeLine {
				t.Errorf("EncodeGrant wire line mismatch (golden byte-shape pin)\n got: %s\nwant: %s", native, tc.wantNativeLine)
			}

			pt, err := d.EncodeGrantPromptTool(grant)
			if err != nil {
				t.Fatalf("EncodeGrantPromptTool: %v", err)
			}
			if string(pt) != tc.wantPromptToolLine {
				t.Errorf("EncodeGrantPromptTool wire line mismatch (golden byte-shape pin)\n got: %s\nwant: %s", pt, tc.wantPromptToolLine)
			}
		})
	}
}

// TestDriveGrantGoldens_IDsDerivedFromFixture is the cross-check that KEEPS the
// golden byte-pins honest: it derives the ask correlation ids from the committed
// ask-control cassette and asserts each grant golden's pinned wantNativeLine
// carries exactly that fixture-derived request_id (and that the deny case's
// derived tool_use_id is NEVER in the native line — P8 joins on request_id only).
// On the echoing allow it asserts the derived ask input equals the input echoed
// in the golden line, so the "echoed-input" claim is proven against the fixture
// bytes rather than a retyped literal. This is what makes the kept literal
// wantNativeLine an id-CROSS-CHECKED byte-pin, not a free constant.
func TestDriveGrantGoldens_IDsDerivedFromFixture(t *testing.T) {
	asks := deriveAskControlAsks(t)
	for _, tc := range driveGrantGoldens {
		t.Run(tc.scenario+"/"+tc.name, func(t *testing.T) {
			ask := askByCommand(t, asks, tc.command)

			// The pinned native line must carry the fixture-derived request_id.
			if !bytes.Contains([]byte(tc.wantNativeLine), []byte(`"request_id":"`+ask.requestID+`"`)) {
				t.Errorf("wantNativeLine does not carry the fixture-derived request_id %q (the golden id is not the cassette's)\nline: %s", ask.requestID, tc.wantNativeLine)
			}
			// And it must never carry the tool_use_id: P8 joins on request_id only,
			// so the derived tool_use_id must be absent from the control_response.
			if ask.toolUseID != "" && bytes.Contains([]byte(tc.wantNativeLine), []byte(ask.toolUseID)) {
				t.Errorf("wantNativeLine leaks the derived tool_use_id %q; P8 control_response joins on request_id only\nline: %s", ask.toolUseID, tc.wantNativeLine)
			}

			// The built grant's ids are the derived ids (no hand-pinned identity).
			built := tc.grant(t, asks)
			if built.RequestID != ask.requestID {
				t.Errorf("built grant request_id = %q, want fixture-derived %q", built.RequestID, ask.requestID)
			}
			if built.ToolUseID != ask.toolUseID {
				t.Errorf("built grant tool_use_id = %q, want fixture-derived %q", built.ToolUseID, ask.toolUseID)
			}

			// On the echoing allow, the echoed UpdatedInput is the fixture's own
			// input (semantically equal — the golden line carries it verbatim).
			if tc.allow && tc.echoesInput {
				if !jsonEqual(t, string(built.UpdatedInput), string(ask.input)) {
					t.Errorf("echoed UpdatedInput = %q, want fixture-derived input %q", built.UpdatedInput, ask.input)
				}
				if !bytes.Contains([]byte(tc.wantNativeLine), []byte(`"updatedInput":`)) {
					t.Errorf("echoing-allow golden omits updatedInput\nline: %s", tc.wantNativeLine)
				}
			}
		})
	}
}

// --- Decode-back projection stability (the round-trip half) -------------------
//
// The complement to the byte pins: the driver-emitted bytes, fed back through
// records.go's OWN decode structs (the exact structs the read adapter uses),
// recover the same correlation ids and shape the write side put in — and do so
// IDENTICALLY across two independent encode→decode passes. This proves the
// write→read round trip is projection-stable, not merely decodable once.

// TestDriveRoundTrip_InputProjectionStable encodes each spawn-driving prompt,
// decodes it through userRecord (the read side's inbound shape), and asserts the
// projection (type/role/single-text-block/text) is exactly what the read side
// would parse — and is stable across two passes.
func TestDriveRoundTrip_InputProjectionStable(t *testing.T) {
	d := NewDriver()
	for _, tc := range driveInputGoldens {
		t.Run(tc.scenario+"/"+tc.name, func(t *testing.T) {
			project := func() userRecord {
				line, err := d.EncodeInput(DriveInput{Text: tc.text})
				if err != nil {
					t.Fatalf("EncodeInput: %v", err)
				}
				return drvDecode[userRecord](t, line)
			}
			a, b := project(), project()

			// Structural projection the read side parses (P4 single-block).
			if a.Type != "user" {
				t.Errorf("decoded type = %q, want user", a.Type)
			}
			if a.Message.Role != "user" {
				t.Errorf("decoded message.role = %q, want user", a.Message.Role)
			}
			if len(a.Message.Content) != 1 {
				t.Fatalf("decoded content has %d blocks, want exactly 1 (P4)", len(a.Message.Content))
			}
			if a.Message.Content[0].Type != "text" {
				t.Errorf("decoded content[0].type = %q, want text", a.Message.Content[0].Type)
			}
			if a.Message.Content[0].Text != tc.text {
				t.Errorf("decoded content[0].text = %q, want %q (verbatim round-trip)", a.Message.Content[0].Text, tc.text)
			}
			// Projection stability: a second independent pass projects identically.
			if !drvSameProjection(t, a, b) {
				t.Errorf("input projection not stable across passes:\n  a: %+v\n  b: %+v", a, b)
			}
		})
	}
}

// TestDriveRoundTrip_GrantProjectionStable encodes each ask-control grant through
// the NATIVE control_response, decodes it through controlResponseRecord (the read
// side's control-channel struct), and asserts the read side recovers the same
// request_id join key and behavior decision — id-relative, never on tool_use_id
// (P8: the success response correlates on request_id only). Stable across passes.
func TestDriveRoundTrip_GrantProjectionStable(t *testing.T) {
	d := NewDriver()
	asks := deriveAskControlAsks(t)
	for _, tc := range driveGrantGoldens {
		t.Run(tc.scenario+"/"+tc.name, func(t *testing.T) {
			grant := tc.grant(t, asks)
			project := func() controlResponseRecord {
				line, err := d.EncodeGrant(grant)
				if err != nil {
					t.Fatalf("EncodeGrant: %v", err)
				}
				return drvDecode[controlResponseRecord](t, line)
			}
			a, b := project(), project()

			if a.Type != "control_response" {
				t.Errorf("decoded type = %q, want control_response", a.Type)
			}
			if a.Response.Subtype != "success" {
				t.Errorf("decoded response.subtype = %q, want success", a.Response.Subtype)
			}
			// id-relative: the read side joins on request_id (== the ask's,
			// fixture-derived), and the within-run id threads through unchanged.
			if a.Response.RequestID != grant.RequestID {
				t.Errorf("decoded request_id = %q, want %q (the read side's askByRequestID join key)", a.Response.RequestID, grant.RequestID)
			}
			wantBehavior := "deny"
			if grant.Allow {
				wantBehavior = "allow"
			}
			if a.Response.Response.Behavior != wantBehavior {
				t.Errorf("decoded behavior = %q, want %q", a.Response.Response.Behavior, wantBehavior)
			}

			// The native control_response must NOT correlate on tool_use_id even
			// though the grant carried one (P8) — assert it never appears in the
			// emitted line, mirroring the read side's request_id-only join.
			line, _ := d.EncodeGrant(grant)
			if grant.ToolUseID != "" && bytes.Contains(line, []byte(grant.ToolUseID)) {
				t.Errorf("control_response leaked tool_use_id %q; P8 joins on request_id only\nline: %s", grant.ToolUseID, line)
			}

			if !drvSameProjection(t, a, b) {
				t.Errorf("grant projection not stable across passes:\n  a: %+v\n  b: %+v", a, b)
			}
		})
	}
}

// TestDriveRoundTrip_PromptToolProjectionStable encodes each ask-control grant
// through the PROVEN-live prompt-tool body, decodes it through controlDecision
// (the bare decision the read side reads, no request_id envelope — the JSON-RPC
// call id correlates out of band, P8), and asserts the behavior + behavior-
// conditional field round-trip and are stable.
func TestDriveRoundTrip_PromptToolProjectionStable(t *testing.T) {
	d := NewDriver()
	asks := deriveAskControlAsks(t)
	for _, tc := range driveGrantGoldens {
		t.Run(tc.scenario+"/"+tc.name, func(t *testing.T) {
			grant := tc.grant(t, asks)
			project := func() controlDecision {
				line, err := d.EncodeGrantPromptTool(grant)
				if err != nil {
					t.Fatalf("EncodeGrantPromptTool: %v", err)
				}
				return drvDecode[controlDecision](t, line)
			}
			a, b := project(), project()

			wantBehavior := "deny"
			if grant.Allow {
				wantBehavior = "allow"
			}
			if a.Behavior != wantBehavior {
				t.Errorf("decoded behavior = %q, want %q", a.Behavior, wantBehavior)
			}
			if grant.Allow {
				// allow: updatedInput round-trips (or is absent when not rewritten);
				// message must be empty.
				if a.Message != "" {
					t.Errorf("allow body carries message %q; P8 allow returns updatedInput, not message", a.Message)
				}
				gotInput := string(a.UpdatedInput)
				wantInput := string(grant.UpdatedInput)
				if wantInput == "" {
					if !drvJSONAbsent(gotInput) {
						t.Errorf("updatedInput = %q, want absent/null (no rewrite)", gotInput)
					}
				} else if !jsonEqual(t, gotInput, wantInput) {
					t.Errorf("updatedInput = %q, want %q", gotInput, wantInput)
				}
			} else {
				// deny: message round-trips verbatim; updatedInput must be absent.
				if a.Message != grant.Message {
					t.Errorf("deny message = %q, want %q (verbatim)", a.Message, grant.Message)
				}
				if !drvJSONAbsent(string(a.UpdatedInput)) {
					t.Errorf("deny body carries updatedInput %q; P8 deny returns message, not updatedInput", a.UpdatedInput)
				}
			}

			// The prompt-tool body carries NO request_id envelope (out-of-band
			// correlation, P8) — mirror the read side: assert it is absent.
			line, _ := d.EncodeGrantPromptTool(grant)
			if fields := drvRawFields(t, line); func() bool { _, ok := fields["request_id"]; return ok }() {
				t.Errorf("prompt-tool body carries request_id; it must correlate out of band (P8)\nline: %s", line)
			}

			if !drvSameProjection(t, a, b) {
				t.Errorf("prompt-tool projection not stable across passes:\n  a: %+v\n  b: %+v", a, b)
			}
		})
	}
}

// --- The full drive loop, golden-pinned (input → ask-answer grant) ------------

// TestDriveGolden_SpawnDrivingLoop pins the BYTES of a complete v0 drive loop
// derived from the ask-control cassette: the client drives an input (P4), CC asks
// (read side, not exercised here), the human grants on the policy stream, and the
// Driver turns the grant into a control_response correlated on the SAME request_id
// the ask carried. Both wire lines are pinned, and the correlation is asserted id-
// relative — the write-side mirror of TestDriveSequence_InputThenGrantCorrelatesOnRequestID
// upgraded with golden byte pins.
func TestDriveGolden_SpawnDrivingLoop(t *testing.T) {
	d := NewDriver()
	asks := deriveAskControlAsks(t)

	const wantInput = `{"type":"user","message":{"role":"user","content":[{"type":"text","text":"delete the scratch dir"}]}}`
	inputLine, err := d.EncodeInput(DriveInput{Text: "delete the scratch dir"})
	if err != nil {
		t.Fatalf("EncodeInput: %v", err)
	}
	if string(inputLine) != wantInput {
		t.Errorf("drive-loop input wire line mismatch\n got: %s\nwant: %s", inputLine, wantInput)
	}

	// The ask is the rm/deny ask (request_id creq_synthetic_0302) — derived from
	// the cassette, not retyped. The human allows a REWRITTEN input instead (a
	// genuine override, so the rewrite is a literal, not the fixture's echoed
	// input); the control_response must pin on that derived request_id so the read
	// side's askByRequestID correlates.
	rmAsk := askByCommand(t, asks, "rm -rf /work/scratch")
	const wantGrant = `{"type":"control_response","response":{"subtype":"success","request_id":"creq_synthetic_0302","response":{"behavior":"allow","updatedInput":{"command":"rm -rf /work/scratch"}}}}`
	grantLine, err := d.EncodeGrant(DriveGrant{
		RequestID:    rmAsk.requestID,
		ToolUseID:    rmAsk.toolUseID,
		Allow:        true,
		UpdatedInput: json.RawMessage(`{"command":"rm -rf /work/scratch"}`),
	})
	if err != nil {
		t.Fatalf("EncodeGrant: %v", err)
	}
	if string(grantLine) != wantGrant {
		t.Errorf("drive-loop grant wire line mismatch\n got: %s\nwant: %s", grantLine, wantGrant)
	}
	// The kept golden byte-pin must carry the fixture-derived request_id (the
	// literal in wantGrant is cross-checked against the cassette, not free).
	if !bytes.Contains([]byte(wantGrant), []byte(`"request_id":"`+rmAsk.requestID+`"`)) {
		t.Errorf("drive-loop wantGrant does not carry the fixture-derived request_id %q", rmAsk.requestID)
	}

	// id-relative cross-check: decode the grant back and confirm the join key is
	// the fixture-derived request_id.
	resp := drvDecode[controlResponseRecord](t, grantLine)
	if resp.Response.RequestID != rmAsk.requestID {
		t.Errorf("control_response.request_id = %q, want %q (fixture-derived ask join key)", resp.Response.RequestID, rmAsk.requestID)
	}
}

// --- Determinism across runs (the golden-stability proof) ---------------------

// TestDriveGolden_DeterministicAcrossRuns proves the byte pins above are not
// flaky: every encoder output is byte-identical when re-encoded from the same
// input (encoding/json marshals struct fields in declaration order, so output is
// a pure function of input). This is the write-side analogue of the read side's
// pinned-clock determinism — the precondition that makes golden byte pins valid.
func TestDriveGolden_DeterministicAcrossRuns(t *testing.T) {
	d := NewDriver()

	for _, tc := range driveInputGoldens {
		first, err := d.EncodeInput(DriveInput{Text: tc.text})
		if err != nil {
			t.Fatalf("EncodeInput(%s): %v", tc.name, err)
		}
		second, err := NewDriver().EncodeInput(DriveInput{Text: tc.text})
		if err != nil {
			t.Fatalf("EncodeInput(%s) second: %v", tc.name, err)
		}
		if !bytes.Equal(first, second) {
			t.Errorf("EncodeInput(%s) not deterministic across runs:\n  first:  %s\n  second: %s", tc.name, first, second)
		}
	}

	asks := deriveAskControlAsks(t)
	for _, tc := range driveGrantGoldens {
		grant := tc.grant(t, asks)
		nf, err := d.EncodeGrant(grant)
		if err != nil {
			t.Fatalf("EncodeGrant(%s): %v", tc.name, err)
		}
		ns, err := NewDriver().EncodeGrant(grant)
		if err != nil {
			t.Fatalf("EncodeGrant(%s) second: %v", tc.name, err)
		}
		if !bytes.Equal(nf, ns) {
			t.Errorf("EncodeGrant(%s) not deterministic:\n  first:  %s\n  second: %s", tc.name, nf, ns)
		}

		pf, err := d.EncodeGrantPromptTool(grant)
		if err != nil {
			t.Fatalf("EncodeGrantPromptTool(%s): %v", tc.name, err)
		}
		ps, err := NewDriver().EncodeGrantPromptTool(grant)
		if err != nil {
			t.Fatalf("EncodeGrantPromptTool(%s) second: %v", tc.name, err)
		}
		if !bytes.Equal(pf, ps) {
			t.Errorf("EncodeGrantPromptTool(%s) not deterministic:\n  first:  %s\n  second: %s", tc.name, pf, ps)
		}
	}
}
