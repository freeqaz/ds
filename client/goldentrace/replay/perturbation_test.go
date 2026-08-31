package replay

// perturbation_test.go — the self-test that proves the golden suite has TEETH
// (docs/06 §5, OQ4/D49). It is the CC-protocol-drift early-warning system in
// executable form: §2.2's promise is "when Anthropic changes the format, a
// golden-trace test breaks before customers do." A green golden suite alone
// cannot tell "the format is stable" from "the harness stopped looking" — so
// this file PROVES the suite actually breaks on a format change.
//
// TestGoldens (golden_test.go) proves the projection is byte-stable for the
// committed cassettes; it cannot prove that a *wrong* projection would be
// caught — a vacuously-passing golden (an adapter that drops a field both ways)
// is the failure mode goldens famously hide. This test closes that gap: it
// perturbs a cassette IN MEMORY (never on disk — no fixture or golden write,
// HARDENING-NOTES §2.3 / D50, no D50 provenance header needed), replays both
// the pristine and the mutant through the SAME claude-code adapter, and asserts
// the mutation provably bites — the projection DIVERGES, OR the adapter raises a
// warning it did not raise on the pristine bytes (the documented
// parse-error-as-drift / warning-as-drift branches, adapter.go Feed: "drift is
// a cassette diff, not a crash"). A silently-tolerated mutation is an adapter
// BLIND SPOT and fails the test loudly (the finding is reported up, never
// patched in the adapter from this owned file).
//
// Every row also passes the STALE-ANCHOR GUARD: the in-memory mutation must
// actually change the cassette bytes. A mutation whose anchor string no longer
// occurs (a cassette was re-authored out from under it) is a no-op that would
// make this whole test vacuous — so a no-op mutation is itself a hard failure,
// not a skipped row. This is the same discipline TestGoldens leans on, one
// level meta.
//
// The mutation is confined to memory: nothing is written under
// client/fixtures/ or testdata/, no golden is touched, so the test is inert in
// normal runs — it passes precisely because the harness still notices drift. If
// a future adapter change made the suite tolerate a mutation silently, THIS test
// goes red — the canary for "the early-warning system itself regressed."
//
// Drift-class coverage (the union of two prior realizations of this self-test,
// unified here as a strict superset). Two axes:
//   - the most-VISIBLE classes — chat-delta and spawn-discriminator drift — that
//     establish the harness bites at all;
//   - the highest-VALUE blind spots — the control channel and the per-subagent
//     accounting trailer (DRIVE-PROTOCOL.md "three gaps", gaps 2 & 3): the
//     control_request{can_use_tool}/control_response surface and the
//     agentId/returned_to result trailer are binary-extracted-only, never proven
//     live, so a silent adapter regression there is the costliest one to miss.
//
// All synthetic, fixture-fed, zero-egress: no live claude, no container, no
// proxy (project constraint 5; the live tier rides DS_E2E_LIVE in
// goldentrace/e2e/, never here).

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	claudecode "github.com/dream-serpent/dream-serpent/client/wrapper/adapters/claude-code"
	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// driftBranch names the detector that caught a perturbation: the three branches
// of TestPerturbationDriftIsCaught, in the order they are tried. branchAny means
// the row does not pin a specific branch — any of A/B/C catching it passes (the
// historical behavior every pre-existing row keeps). branchC is the warning-as-
// drift detector; a row that pins it asserts the FIRST two branches did NOT fire
// (no parse error, projection byte-identical) and the warning branch DID — so a
// future change that silences adapter Warnings while leaving the projection
// byte-identical fails this row loudly, which a branchAny row could not catch
// (it would silently resolve on Branch B before the warning branch is reached).
type driftBranch int

const (
	branchAny driftBranch = iota // no pin — any detector passes (default; all legacy rows)
	branchA                      // parse-error-as-drift
	branchB                      // golden / projection divergence
	branchC                      // warning-as-drift
)

// String renders the branch for the per-row accounting log line and failure
// messages: which detector named the drift (or which one was REQUIRED).
func (b driftBranch) String() string {
	switch b {
	case branchA:
		return "A (parse-error-as-drift)"
	case branchB:
		return "B (projection divergence)"
	case branchC:
		return "C (warning-as-drift)"
	default:
		return "any"
	}
}

// perturbation is one deliberate, reviewable in-memory mutation of a committed
// cassette — a stand-in for an upstream CC protocol change. cassette is the base
// name under client/fixtures/ (no suffix, suffix shared from golden_test.go).
// anchor is the exact substring the mutation rewrites; replacement is what it
// becomes (a plain bytes.ReplaceAll, so every drift class is a transparent,
// reviewable diff — no opaque mutation closures). drift is the one-line
// description of the projection drift the mutation simulates: it documents WHY
// the row bites, and what CC format change it would catch, for the reader of a
// failure.
//
// wantBranch, when set to a non-branchAny value, PINS the detector the row must
// resolve on: the loop asserts the earlier branches did NOT fire and the named
// branch DID. The zero value (branchAny) is the historical behavior — first
// branch to catch wins — so every pre-existing row stays a strict superset,
// unchanged. Only the warning-only rows pin branchC.
//
// wantWarningContains is the SURFACE PIN for a branchC row: a list of substrings
// that must ALL appear in at least one NEW (mutant-only) warning. It is honored
// ONLY on the branchC path of assertBranch (a branchAny / unset row skips it
// exactly as today). Asserting merely that SOME new warning fired (the original
// branchC guarantee) cannot tell "the warning named the mutated surface" from
// "an unrelated warning happened to fire" — so a refactor that moved the
// corroboration/correlation check elsewhere could let a row pass on the wrong
// warning, silently weakening the Branch-C guarantee. This field re-pins each
// Branch-C row to the EXACT surface it mutated (the request_id the unknown-ask
// warning names; the parent id the corroboration warning names), read verbatim
// off the adapter's warnf strings at impl time. The zero value (nil) is a no-op
// skip, so every pre-existing row stays unchanged.
type perturbation struct {
	name                string
	cassette            string
	anchor              string
	replacement         string
	drift               string
	wantBranch          driftBranch
	wantWarningContains []string
}

// perturbations enumerates every drift class. The "visible" group establishes
// the self-test bites at all (chat-delta and spawn-discriminator drift); the
// "control channel" and "accounting trailer" groups extend coverage to
// DRIVE-PROTOCOL.md's unproven-live surfaces — the requested high-value blind
// spots.
var perturbations = []perturbation{
	// --- visible classes: chat-delta and spawn-discriminator drift ---
	// (establish the suite catches the format changes a customer would see first)

	{
		// CC renaming the assistant text content-block type is the most visible
		// drift class: the adapter keys chat projection on "type":"text", so a
		// rename here makes the chat deltas disappear from the projection.
		name:        "assistant-content-type-renamed",
		cassette:    "baseline-chat",
		anchor:      `{"type":"text"`,
		replacement: `{"type":"prose"`,
		drift:       "upstream rename of the assistant text content-block type → chat.message projection drops; ChatMessage block vanishes vs pristine",
	},
	{
		// A within-block corruption of the assistant text itself: the chat
		// delta still projects, but its rendered text drifts. Catches a subtler
		// class than the type rename — the field is read but its CONTENT is
		// mis-carried (e.g. a re-encoding/escaping change upstream).
		name:        "chat-text-corruption",
		cassette:    "baseline-chat",
		anchor:      "Hello",
		replacement: "H3LL0",
		drift:       "assistant chat.message text mutated → ChatMessage.Blocks[].Text diverges from the pristine projection",
	},
	{
		// CC renaming the system/task_started discriminator is exactly the drift
		// class doc 06 §5 worries about: the spawn-join keys on this subtype, so
		// the spawn lifecycle silently stops projecting (subagent.spawned vanishes,
		// only the accounting trailer survives — the OBSERVABILITY §2 missed-
		// lifecycle branch). nested-spawn carries the task_started half, so the
		// rename provably bites.
		name:        "task_started-subtype-renamed",
		cassette:    "nested-spawn",
		anchor:      `"subtype":"task_started"`,
		replacement: `"subtype":"task_begun"`,
		drift:       "upstream rename of the system/task_started discriminator → spawn-join drops, subagent.spawned disappears from the projection",
	},
	{
		// The spawn↔result join correlates on tool_use_id. Rewriting the id on
		// the spawn/result line breaks that join: the SubagentAccounted node_id
		// drifts and the unmatched-trailer warning fires. subagent-spawn is the
		// accounting-only cassette (no task_started half), so this isolates the
		// id-correlation surface.
		name:        "tool-result-id-corruption",
		cassette:    "subagent-spawn",
		anchor:      "toolu_SYNTHETIC000000000001",
		replacement: "toolu_SYNTHETIC0000000000XX",
		drift:       "spawn/result tool_use_id rewritten → the spawn↔result join breaks; SubagentAccounted node_id + warning diverge",
	},

	// --- control channel: control_request{can_use_tool} / control_response ---
	// (DRIVE-PROTOCOL.md gap 2, P8 — binary-extracted, never proven live)

	{
		// The control_request's subtype is the discriminator handleControlRequest
		// switches on (ask.go): anything but "can_use_tool" opens NO ask. Mutate
		// it on the FIRST request only (anchored by request_id so exactly one line
		// bites): the ask.requested projection for that ask vanishes, and the
		// matching control_response then resolves an unknown request_id → adapter
		// warning + ask.resolved drift. Catches a CC rename of the native ask
		// discriminator — the load-bearing unknown the keystone exists to pin.
		name:        "control-discriminator-mutation",
		cassette:    "ask-control",
		anchor:      `creq_synthetic_0301","request":{"subtype":"can_use_tool"`,
		replacement: `creq_synthetic_0301","request":{"subtype":"can_use_tool_RENAMED"`,
		drift:       "control_request discriminator renamed → ask.requested for the first ask vanishes and its control_response resolves an unknown request_id (warning)",
	},
	{
		// A success control_response correlates back on request_id only
		// (handleControlResponse → askByRequestID): the response carries no
		// tool_use_id. Corrupt the RESPONSE's request_id (leave the request's
		// intact, so the ask still opens) and the resolution can no longer find
		// its open ask: a warning fires and the explicit control-channel
		// ask.resolved is lost (a later tool_result fallback resolves it from a
		// different source, so seq/source order also drifts). Catches a CC change
		// to the request_id correlation contract on the control channel.
		name:        "control-correlation-corruption",
		cassette:    "ask-control",
		anchor:      `"response":{"subtype":"success","request_id":"creq_synthetic_0301"`,
		replacement: `"response":{"subtype":"success","request_id":"creq_synthetic_ORPHAN"`,
		drift:       "control_response correlation id corrupted → resolution misses its open ask (warning); ask lifecycle drifts to the tool_result fallback",
	},

	// --- accounting trailer: agentId / returned_to ---
	// (DRIVE-PROTOCOL.md gap 3 / OBSERVABILITY-DESIGN §1, the per-subagent result
	// trailer — the authoritative accounting source)

	{
		// The inner subagent's result trailer carries `agentId: <hex>`, parsed by
		// parseTrailer into SubagentAccounted.AgentID (+ Continuation.AgentID) and
		// integrity-checked against the node's task_id (tree.go: agentId ==
		// task_id). nested-spawn HAS the task_started half (subagent-spawn does
		// not), so mutating the trailer hex both diverges the projection AND trips
		// the integrity warning — the accounting source is provably read. Catches a
		// CC change to the result-trailer agentId field or its meaning.
		name:        "accounting-trailer-agentid-mutation",
		cassette:    "nested-spawn",
		anchor:      "agentId: e5e5e5e5e5e5e5e5",
		replacement: "agentId: f6f6f6f6f6f6f6f6",
		drift:       "result-trailer agentId rewritten → SubagentAccounted.agent_id/continuation diverge and the agentId==task_id integrity warning fires",
	},
	{
		// returned_to is the result line's TOP-LEVEL parent_tool_use_id (the level
		// the subagent returns to), copied to SubagentAccounted.ReturnedTo and
		// corroborated against the spawn-line parent (tree.go §2 rule 2). Repoint
		// the inner result's return target away from its true outer parent:
		// ReturnedTo diverges and the parent-corroboration warning fires. Catches a
		// CC change to where a subagent result reports its return parent.
		name:        "accounting-returned-to-mutation",
		cassette:    "nested-spawn",
		anchor:      `"uuid":"00000000-0000-4000-8000-0000000000d7","parent_tool_use_id":"toolu_SYNTHETICNESTEDOUTER1"`,
		replacement: `"uuid":"00000000-0000-4000-8000-0000000000d7","parent_tool_use_id":"toolu_SYNTHETICWRONGPARENT"`,
		drift:       "result-line parent_tool_use_id repointed → SubagentAccounted.returned_to diverges and the parent-corroboration warning fires",
	},

	// --- warning-only: Branch C (warning-as-drift) as the FIRST and SOLE detector ---
	// (the realizations of Branch C — every other row above resolves on Branch B
	// (projection divergence) BEFORE the warning branch is reached, so without
	// these rows a regression that silenced adapter Warnings while leaving the
	// projection byte-identical would NOT turn the self-test red. Two surfaces are
	// pinned: the control-channel handshake (control-response-warning-only) and the
	// per-subagent accounting trailer (accounting-corroboration-warning-only) — the
	// two unproven-live blind spots a warning-only regression would otherwise hide.)

	{
		// The drive-native-allow cassette opens with a control_request{subtype:
		// "initialize"} (request_id …a01) — a handshake request that, by P8, opens
		// NO ask (handleControlRequest skips every non-can_use_tool subtype). Its
		// success control_response (the same …a01 id) carries the init payload but
		// NO `behavior`, so handleControlResponse takes the "not an ask resolution"
		// path and emits nothing.
		//
		// This row injects a `behavior` into that initialize response — simulating
		// a CC change where the handshake response grows an ask-resolution
		// discriminator. The adapter now reads it as a resolution, scans for the
		// open ask keyed by request_id …a01, finds none (the initialize request
		// opened no ask, P8 — "never invent an ask that was not on the wire"), and
		// raises the unknown-request_id WARNING. Crucially it then returns NO event
		// (ask.go handleControlResponse: warn + return nil) — so the projection
		// NDJSON is BYTE-IDENTICAL to pristine. Branch A cannot fire (the bytes
		// still parse) and Branch B cannot fire (no projection change), so Branch C
		// is the FIRST and SOLE detector. wantBranch pins exactly that: a future
		// change that drops the warning here goes red even though the projection is
		// unchanged — the regression a projection-divergence row structurally
		// cannot catch.
		name:        "control-response-warning-only",
		cassette:    "drive-native-allow",
		anchor:      `"request_id":"creq-00000000-0000-4000-8000-000000000a01","response":{"commands":`,
		replacement: `"request_id":"creq-00000000-0000-4000-8000-000000000a01","response":{"behavior":"allow","commands":`,
		drift:       "initialize control_response grows a `behavior` discriminator → adapter reads it as an ask resolution against a request_id that opened no ask; the unknown-request_id warning fires while the projection stays byte-identical (no event emitted)",
		wantBranch:  branchC,
		// Surface pin: the new warning must name the MUTATED surface — the
		// unknown request_id of the initialize handshake. The adapter emits
		// `control_response success resolves unknown request_id "creq-…a01"
		// (uuid …): no open ask` (ask.go handleControlResponse). Pin both the
		// unknown-ask warning fragment and the literal request_id so a refactor
		// that warned about the wrong surface (or on an unrelated handle) fails
		// this row instead of passing on a coincidental warning.
		wantWarningContains: []string{
			"unknown request_id",
			"creq-00000000-0000-4000-8000-000000000a01",
		},
	},
	{
		// The SECOND warning-only Branch-C row, on the ACCOUNTING-TRAILER
		// integrity surface (DRIVE-PROTOCOL.md gap 3 — the per-subagent result
		// trailer). It pins the parent-corroboration integrity warning
		// (tree.go handleSubagentResult §2 rule 2: the result line's return
		// target is checked against the spawn-line parent, the spawn-line value
		// kept on disagreement) as a WARNING-ONLY trip — distinct from the
		// nested-spawn accounting-returned-to-mutation row, which fires the SAME
		// warning but resolves on Branch B because the mutated return target
		// projects into SubagentAccounted.returned_to.
		//
		// The trick is the cassette choice: subagent-spawn is the accounting-ONLY
		// cassette — its single node has a spawn block (spawnSeen) but NO
		// system/task_started half, so emitSpawned's join never completes and
		// SubagentSpawned is NEVER emitted. The node's parent therefore reaches
		// NO projected field (SubagentSpawned.parent_node_id is the only sink for
		// n.parentNode, and that event does not exist for this node). Yet the
		// corroboration check still runs — it gates on n.spawnSeen (true here),
		// not on the spawn having been emitted.
		//
		// This row repoints the SPAWN line's parent_tool_use_id from null to a
		// phantom id (anchored by the spawn block's uuid …a2 so exactly one line
		// bites). Now n.parentNode = the phantom while the result line's return
		// target stays null (acct.ReturnedTo == ""), so the corroboration warning
		// fires (n.spawnSeen && ReturnedTo != parentNode). Crucially the
		// projection is BYTE-IDENTICAL: SubagentSpawned was never emitted (no sink
		// for the mutated parent), and SubagentAccounted.returned_to stays omitted
		// because acct.ReturnedTo is still the unchanged "" — so Branch A cannot
		// fire (the bytes parse), Branch B cannot fire (no projection change), and
		// Branch C is the FIRST and SOLE detector. wantBranch pins exactly that: a
		// future change that silences the accounting parent-corroboration warning
		// while leaving the projection unchanged goes red here, the regression a
		// projection-divergence row structurally cannot catch on the accounting
		// trailer.
		name:        "accounting-corroboration-warning-only",
		cassette:    "subagent-spawn",
		anchor:      `"uuid":"00000000-0000-4000-8000-0000000000a2","parent_tool_use_id":null`,
		replacement: `"uuid":"00000000-0000-4000-8000-0000000000a2","parent_tool_use_id":"toolu_SYNTHETICPHANTOMPARENT"`,
		drift:       "spawn-line parent_tool_use_id repointed on an accounting-only (task_started-less) node → the result's return-target corroboration disagrees with the spawn-line parent and the parent-corroboration integrity warning fires, while the projection stays byte-identical (SubagentSpawned never emitted, returned_to still omitted)",
		wantBranch:  branchC,
		// Surface pin: the new warning must name the MUTATED surface — the
		// parent-corroboration integrity check on the repointed spawn-line
		// parent. The adapter emits `subagent parent corroboration: node …
		// spawn-line parent "toolu_SYNTHETICPHANTOMPARENT" != return target ""
		// (keeping spawn-line value)` (tree.go handleSubagentResult §2 rule 2).
		// Pin both the corroboration warning fragment and the phantom parent id
		// so the row fails if a future change fired the unknown-request_id or
		// agentId-integrity warning (the wrong surface) in its place.
		wantWarningContains: []string{
			"subagent parent corroboration",
			"toolu_SYNTHETICPHANTOMPARENT",
		},
	},
}

// TestPerturbationDriftIsCaught is the meta-self-test: for each drift class it
// replays the pristine cassette and its in-memory mutant through the same
// adapter and asserts the mutation BITES — via a parse error the pristine did
// not raise (Branch A, parse-error-as-drift), OR a divergence in the projection
// NDJSON (Branch B, golden-divergence), OR a warning the adapter raised on the
// mutant but not the pristine (Branch C, warning-as-drift). A row that changes
// cassette bytes yet leaves the projection AND the warning set identical is an
// adapter BLIND SPOT: this test fails it (it does NOT silently tolerate it), and
// the finding is reported up, never patched in the adapter from this owned file.
// Nothing is written under client/fixtures/ or testdata/.
//
// Every row also logs PER-ROW BRANCH ACCOUNTING — which of A/B/C named the drift
// — and a row whose wantBranch is pinned (non-branchAny) additionally ASSERTS it
// resolved on exactly that branch, with the earlier branches proven NOT to fire.
// The branchC row is the one that pins: it asserts no parse error (not A), the
// projection BYTE-IDENTICAL (not B, asserted not incidental), and a NEW warning
// (C) — so a regression that silences adapter Warnings without a projection
// change goes red here, the failure a branchAny row resolves past on Branch B.
func TestPerturbationDriftIsCaught(t *testing.T) {
	for _, p := range perturbations {
		p := p
		t.Run(p.name, func(t *testing.T) {
			cassettePath := filepath.Join("..", "..", "fixtures", p.cassette+cassetteSuffix)
			pristine, err := os.ReadFile(cassettePath)
			if err != nil {
				t.Fatalf("read cassette %s: %v", cassettePath, err)
			}

			// Stale-anchor guard: the mutation MUST change the bytes. A vanished
			// anchor would make the row a vacuous no-op — fail loudly so a
			// re-authored cassette can never silently defang the self-test.
			if bytes.Count(pristine, []byte(p.anchor)) == 0 {
				t.Fatalf("stale anchor: %q not found in %s — the cassette was re-authored out from under this row; "+
					"re-pin the anchor (this self-test must never be a no-op, so it can no longer simulate %q)",
					p.anchor, p.cassette, p.drift)
			}
			mutant := bytes.ReplaceAll(pristine, []byte(p.anchor), []byte(p.replacement))
			if bytes.Equal(mutant, pristine) {
				t.Fatalf("anchor guard: mutation %q→%q left the cassette bytes of %s unchanged — perturbation cannot bite",
					p.anchor, p.replacement, p.cassette)
			}

			base, baseWarns, err := replayBytes(pristine)
			if err != nil {
				t.Fatalf("replay pristine %s: %v", p.cassette, err)
			}
			mut, mutWarns, mutErr := replayBytes(mutant)
			baseND := mustNDJSON(t, base)
			mutND := mustNDJSON(t, mut)

			// Resolve the catching branch in the documented try order (A → B → C),
			// WITHOUT early-returning, so the per-row accounting and the wantBranch
			// pin below see the full picture. caught stays branchAny iff no branch
			// fired (the BLIND SPOT below).
			caught := branchAny
			var detail string
			switch {
			case mutErr != nil:
				// Branch A — parse-error-as-drift: a parse error on the mutant the
				// pristine did not raise is itself drift caught (the documented
				// parse-error-as-drift path, adapter.go Feed).
				caught = branchA
				detail = mutErr.Error()
			default:
				if line, diff := firstDiffLine(baseND, mutND); diff {
					// Branch B — golden divergence: the projection NDJSON differs
					// from the pristine projection, with a readable first-diff line
					// for the operator reviewing a real red canary.
					caught = branchB
					detail = "first diff at " + line
				} else if w := newWarnings(baseWarns, mutWarns); len(w) > 0 {
					// Branch C — warning-as-drift: the projection is byte-identical,
					// but the adapter raised a warning it did not raise on the
					// pristine bytes (integrity/correlation misses surface as
					// Warnings, not projection changes).
					caught = branchC
					detail = strings.Join(w, "\n  ")
				}
			}

			if caught == branchAny {
				// BLIND SPOT — silently tolerated: the mutation changed cassette
				// bytes but the projection AND the warning set are identical. The
				// adapter is not reading this surface. Fail loudly; the finding is
				// reported up, never patched in the adapter from this owned test file.
				t.Errorf("BLIND SPOT: mutation %q bit the cassette bytes of %s but the projection and warnings are IDENTICAL — "+
					"the drift early-warning system has gone blind to this class of CC format change.\n"+
					"  simulated drift (expected to be caught): %s\n"+
					"Either the adapter now silently tolerates this mutation, or the perturbation anchor no longer bites the read path.",
					p.name, p.cassette, p.drift)
				return
			}

			// Per-row branch accounting: NAME the detector that caught this row, for
			// the operator reading a green or red run. Every row logs this.
			t.Logf("drift caught on Branch %s: %s\n  %s\n  simulated drift: %s", caught, p.name, detail, p.drift)

			// wantBranch pin: a row that names its branch asserts it resolved on
			// EXACTLY that branch — the earlier branches are proven not to fire, so
			// the row keeps testing the surface it was written for and fails loud if
			// a future change makes it resolve earlier (or not at all). branchAny
			// rows skip this — they keep the historical first-branch-wins behavior.
			if p.wantBranch != branchAny {
				assertBranch(t, p, caught, baseND, mutND, mutErr, newWarnings(baseWarns, mutWarns))
			}
		})
	}
}

// assertBranch enforces a row's wantBranch pin. For the branchC (warning-only)
// row it asserts, in order: Branch A did NOT fire (the mutant parsed cleanly),
// Branch B did NOT fire (the projection is BYTE-IDENTICAL — asserted, never left
// incidental), and Branch C DID fire (a new warning) — i.e. caught == branchC.
// The earlier-branch checks are restated against the raw signals (not just the
// resolved `caught`) so the failure message pinpoints WHICH guarantee slipped.
//
// SURFACE PIN (branchC only): when the row sets wantWarningContains, it is not
// enough that SOME new warning fired — at least one NEW (mutant-only) warning
// must contain EVERY pinned substring, so the row is bound to the surface it
// mutated. newWarns is the mutant-only warning set (newWarnings(base, mut),
// already computed at the call site so the same slice the loop logged is the one
// checked); the failure prints it in full so a reviewer of a red row sees the
// actual warnings that fired instead of the expected surface. A branchAny /
// unset row never reaches this arm, so the pin is a strict extension.
func assertBranch(t *testing.T, p perturbation, caught driftBranch, baseND, mutND []byte, mutErr error, newWarns []string) {
	t.Helper()
	switch p.wantBranch {
	case branchC:
		if mutErr != nil {
			t.Fatalf("%s pins Branch C (warning-only) but Branch A fired: the mutant raised a parse error %v — "+
				"the row no longer isolates the warning surface", p.name, mutErr)
		}
		if !bytes.Equal(baseND, mutND) {
			line, _ := firstDiffLine(baseND, mutND)
			t.Fatalf("%s pins Branch C (warning-only) but the projection DIVERGED (Branch B) at %s — "+
				"the mutation must leave the projection BYTE-IDENTICAL so Branch C is the SOLE detector; "+
				"a divergence means a projection-divergence row already covers this and the warning branch is no longer primary",
				p.name, line)
		}
		if caught != branchC {
			t.Fatalf("%s pins Branch C (warning-only) but no new adapter warning fired — "+
				"the projection is byte-identical AND no warning rose, so the drift went UNDETECTED; "+
				"this is the exact regression (warnings silenced without a projection change) the row exists to catch",
				p.name)
		}
		// Surface pin: a NEW warning fired (caught == branchC above), but it must
		// also NAME the mutated surface. Require at least one mutant-only warning
		// that contains EVERY pinned substring — so a refactor that moved the
		// corroboration/correlation check elsewhere (and now warns on an unrelated
		// surface) fails here even though SOME warning still rose. The zero value
		// (nil) skips this, so only the rows that opt in are pinned.
		if len(p.wantWarningContains) > 0 {
			if !anyWarningContainsAll(newWarns, p.wantWarningContains) {
				t.Fatalf("%s pins Branch C to the mutated surface but NO new warning names it: "+
					"no mutant-only warning contains all of %q — the warning fired on the WRONG surface "+
					"(a refactor may have moved the corroboration/correlation check, so the row now passes on an "+
					"unrelated warning, silently weakening the Branch-C guarantee).\n  new (mutant-only) warnings:\n  %s",
					p.name, p.wantWarningContains, formatWarnings(newWarns))
			}
		}
	default:
		if caught != p.wantBranch {
			t.Fatalf("%s pins Branch %s but resolved on Branch %s", p.name, p.wantBranch, caught)
		}
	}
}

// anyWarningContainsAll reports whether at least one warning contains EVERY
// substring in want. The all-in-ONE-warning requirement (not spread across the
// set) is deliberate: it binds the pin to a single warning about the mutated
// surface, so two unrelated warnings that each carry one fragment cannot
// spuriously satisfy the pin.
func anyWarningContainsAll(warnings, want []string) bool {
	for _, w := range warnings {
		all := true
		for _, sub := range want {
			if !strings.Contains(w, sub) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// formatWarnings renders the mutant-only warning set for a readable surface-pin
// failure: one warning per line, or an explicit marker when empty (which cannot
// happen once caught == branchC, but keeps the message unambiguous).
func formatWarnings(warnings []string) string {
	if len(warnings) == 0 {
		return "(none)"
	}
	return strings.Join(warnings, "\n  ")
}

// replayBytes drives a cassette buffer through a fresh deterministic adapter
// (the same clock pinning Replay uses — 2026-01-01T00:00:00Z, +1s per call — so
// the projection NDJSON matches the committed goldens byte-for-byte) and returns
// the projection, the adapter's accumulated warnings, and any fatal stream
// error. A fresh adapter+clock per call keeps the pristine/mutant runs
// independent. We do NOT call Replay directly: it discards Warnings, which this
// self-test needs for the warning-as-drift branch. We do NOT touch replay.go —
// the public claude-code adapter API (New/WithClock/ProcessStream/Warnings) is
// all this needs.
func replayBytes(b []byte) ([]attach.Event, []string, error) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	n := 0
	a := claudecode.New(claudecode.WithClock(func() time.Time {
		t := base.Add(time.Duration(n) * time.Second)
		n++
		return t
	}))
	evs, err := a.ProcessStream(bytes.NewReader(b))
	return evs, a.Warnings(), err
}

// mustNDJSON serializes a projection to the golden NDJSON form (the byte-compare
// basis TestGoldens uses), failing the test on an encode error.
func mustNDJSON(t *testing.T, evs []attach.Event) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteNDJSON(&buf, evs); err != nil {
		t.Fatalf("encode events: %v", err)
	}
	return buf.Bytes()
}

// firstDiffLine reports the first line index (1-based) at which two NDJSON blobs
// differ, with a short before/after marker so a reviewer of a red drift canary
// sees a pinpoint, not a wall of NDJSON. It returns (summary, true) on any
// divergence — including a length mismatch — and ("", false) when identical.
func firstDiffLine(a, b []byte) (string, bool) {
	la := strings.Split(strings.TrimRight(string(a), "\n"), "\n")
	lb := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	max := len(la)
	if len(lb) > max {
		max = len(lb)
	}
	for i := 0; i < max; i++ {
		var x, y string
		if i < len(la) {
			x = la[i]
		}
		if i < len(lb) {
			y = lb[i]
		}
		if x != y {
			return diffSummary(i+1, x, y), true
		}
	}
	return "", false
}

// diffSummary renders a one-line, length-bounded before/after for a single
// diverging projection line.
func diffSummary(lineNo int, pristine, mutant string) string {
	return "line " + strconv.Itoa(lineNo) + ":\n    pristine: " + clip(pristine) + "\n    mutant:   " + clip(mutant)
}

// newWarnings returns the warnings present in the mutant run but not the
// pristine run (count-aware: a warning the mutant raised an extra time still
// surfaces). Order follows the mutant run.
func newWarnings(base, mut []string) []string {
	remaining := make(map[string]int, len(base))
	for _, w := range base {
		remaining[w]++
	}
	var added []string
	for _, w := range mut {
		if remaining[w] > 0 {
			remaining[w]--
			continue
		}
		added = append(added, w)
	}
	return added
}

// clip truncates a long projection line for a readable one-line diff summary;
// an absent line (one side shorter) renders as a clear marker, not an empty
// string.
func clip(s string) string {
	const max = 160
	if s == "" {
		return "(line absent)"
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// --- always-on pristine-absence half of the Branch-C surface pin ---------------
//
// TestPerturbationDriftIsCaught (above) already proves a Branch-C row's pinned
// warning surface is PRESENT in the mutant-only warning set: assertBranch fires
// the mutant, and the surface-pin arm requires a NEW (mutant-only) warning that
// names the mutated surface. That is the "present-in-the-mutant" half.
//
// But "the pin appears in the mutant warnings" is only HALF the non-vacuity proof
// the pin needs to be standing CI. If the SAME pinned substring set ALSO matched a
// warning the adapter raised on the PRISTINE bytes, the row would be vacuous: the
// warning is not evidence the MUTATION bit — the pristine run already carried it,
// so a future change that emitted that warning unconditionally (mutant or not)
// would keep the row green while silently severing the warning from the drift it
// is supposed to witness. newWarnings() already subtracts the pristine set, so the
// LOOP cannot be fooled — but the PIN itself (the hand-authored substring list)
// could be authored against a substring the pristine warnings happen to contain,
// and nothing in the loop catches THAT.
//
// This test is the pristine-absence half, made always-on for every pinned row: for
// every branchC perturbation it replays the PRISTINE cassette (the same
// replayBytes the loop uses) and asserts NO pristine warning contains the row's
// full pinned substring set — i.e. anyWarningContainsAll(pristineWarnings, pins) is
// FALSE. Combined with the mutant-presence half already enforced in the loop, the
// pair pins each Branch-C row to a surface that is present in the mutant AND absent
// in the pristine — the full non-vacuity guarantee, standing in CI, no hand audit.
//
// COVERAGE IS COMPULSORY, not opt-in: the test enumerates the perturbations slice,
// and EVERY branchC row must declare its pinned set here (branchCWarningPins). A
// branchC row with no registered pins fails LOUD — so a future Branch-C row added
// to the perturbations table automatically inherits the pristine-absence check
// (it must register its pins or this test names it), exactly the "all current and
// future pinned rows get it free" property the surface pin needs to stay honest.
//
// SELF-CONTAINED: it reuses replayBytes (pristine warnings) and reads the pins
// from a row-name-keyed map declared here, so it pins the same surfaces the loop's
// mutant-presence arm pins without depending on any field of the perturbation
// struct — the two halves describe the SAME surface from the two ends (pristine /
// mutant) and a divergence between them is itself a reviewable signal.

// branchCWarningPins is the row-name → pinned-substring-set map for every
// warning-only (branchC) perturbation. These are the EXACT surfaces the
// mutant-presence arm of TestPerturbationDriftIsCaught requires a NEW warning to
// name — restated here as the pristine-ABSENCE obligation: none of these sets may
// match a warning the PRISTINE bytes raise, or the pin is vacuous. A branchC row
// absent from this map fails TestBranchCWarningPinsAbsentFromPristine by name, so
// the coverage cannot silently lapse for a future row.
var branchCWarningPins = map[string][]string{
	// control-response-warning-only: the initialize control_response grows a
	// `behavior`, read as an ask resolution against request_id …a01 that opened
	// no ask → ask.go warnf "control_response success resolves unknown request_id
	// "creq-…a01" (uuid …): no open ask". The pristine initialize response has no
	// `behavior`, so the resolution path is never taken and this warning is absent.
	"control-response-warning-only": {
		"unknown request_id",
		"creq-00000000-0000-4000-8000-000000000a01",
	},
	// accounting-corroboration-warning-only: the spawn-line parent is repointed to
	// a phantom while the result return target stays null → tree.go warnf "subagent
	// parent corroboration: node … spawn-line parent "toolu_SYNTHETICPHANTOMPARENT"
	// != return target "" (keeping spawn-line value)". The pristine spawn line has
	// parent_tool_use_id null, so spawn-line parent == return target and the
	// corroboration check agrees — no warning on the pristine bytes.
	"accounting-corroboration-warning-only": {
		"subagent parent corroboration",
		"toolu_SYNTHETICPHANTOMPARENT",
	},
}

// TestBranchCWarningPinsAbsentFromPristine is the always-on pristine-absence half
// of the Branch-C surface pin. For every branchC row it replays the PRISTINE
// cassette and asserts the row's pinned substring set is NOT carried by any
// pristine warning (warningHasAllPins == false for every pristine warning) — so
// the warning the mutant-presence arm keys on is genuinely MUTATION-induced, not a
// pristine warning the pin coincidentally matches. Every branchC row must register
// its pins in branchCWarningPins; a row that does not fails here by name, so future
// pinned rows inherit the check without per-row wiring.
func TestBranchCWarningPinsAbsentFromPristine(t *testing.T) {
	sawBranchC := false
	for _, p := range perturbations {
		if p.wantBranch != branchC {
			continue
		}
		sawBranchC = true
		p := p
		t.Run(p.name, func(t *testing.T) {
			pins, ok := branchCWarningPins[p.name]
			if !ok {
				t.Fatalf("%s pins Branch C but has no entry in branchCWarningPins — every warning-only row "+
					"MUST register its pinned surface here so the pristine-absence half stays always-on; add the "+
					"same substring set the mutant-presence arm (assertBranch wantWarningContains) requires",
					p.name)
			}
			if len(pins) == 0 {
				t.Fatalf("%s has an EMPTY pinned set in branchCWarningPins — an empty pin is vacuously absent "+
					"(and vacuously present), so it proves nothing; pin the surface the warning names", p.name)
			}

			cassettePath := filepath.Join("..", "..", "fixtures", p.cassette+cassetteSuffix)
			pristine, err := os.ReadFile(cassettePath)
			if err != nil {
				t.Fatalf("read cassette %s: %v", cassettePath, err)
			}

			// Stale-anchor parity with the loop: the row must still be able to bite
			// the cassette, or the pin describes a surface the cassette no longer
			// carries. Guard it here too so a re-authored cassette cannot leave this
			// half asserting against bytes the mutation can no longer touch.
			if bytes.Count(pristine, []byte(p.anchor)) == 0 {
				t.Fatalf("stale anchor: %q not found in %s — the cassette was re-authored out from under this "+
					"branchC row; the pristine-absence pin can no longer be trusted (re-pin the anchor)",
					p.anchor, p.cassette)
			}

			_, pristineWarns, err := replayBytes(pristine)
			if err != nil {
				t.Fatalf("replay pristine %s: %v", p.cassette, err)
			}

			// The load-bearing assertion: NO pristine warning may carry the full
			// pinned set. If one does, the pin is matching a warning the pristine run
			// already raised, so the mutant-presence arm proves nothing about THIS
			// mutation — the surface pin is vacuous and must be re-authored against a
			// surface the mutation actually introduces.
			for _, w := range pristineWarns {
				if warningHasAllPins(w, pins) {
					t.Fatalf("%s: a PRISTINE warning already names the pinned Branch-C surface %q — the surface "+
						"pin is VACUOUS: the mutant-presence arm keys on a warning the pristine bytes ALSO raise, so "+
						"it is not evidence the mutation bit. Re-author the pin to a surface the mutation INTRODUCES.\n"+
						"  matching pristine warning: %s",
						p.name, pins, w)
				}
			}
		})
	}
	if !sawBranchC {
		t.Fatal("no branchC perturbation rows found — the pristine-absence half has nothing to guard; " +
			"if the warning-only rows were removed the surface pin lost its teeth")
	}
}

// warningHasAllPins reports whether a single warning string contains EVERY pinned
// substring. The all-in-ONE-warning requirement mirrors the mutant-presence arm's
// anyWarningContainsAll semantics, so the two halves describe the SAME single
// warning: a pristine warning that carried every fragment (in one string) would be
// the exact warning the pin keys on, hence vacuous. It is named distinctly from the
// loop's anyWarningContainsAll to avoid a redeclaration where this half and the
// mutant-presence arm coexist in one file.
func warningHasAllPins(warning string, pins []string) bool {
	for _, sub := range pins {
		if !strings.Contains(warning, sub) {
			return false
		}
	}
	return true
}
