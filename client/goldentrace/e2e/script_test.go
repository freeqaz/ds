// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/client/wrapper/attach"
)

// script_test.go — OFFLINE coverage for the scripted headless drive (the
// always-on, ungated half that runs in the wave gate) PLUS the DS_E2E_LIVE-gated
// VM-side-effect test. The offline tests prove the JSONL parser and the
// DriveScriptScenario multi-turn stepping against the fake-CC driveFakeSocketBridge
// — every line the live leg runs except the model's scripted choice to call the
// tool. The gated test (TestScriptedDriveVMSideEffectReal) skips cleanly without
// the gate.

// --- (1) JSONL parser unit tests --------------------------------------------

func TestParseScript(t *testing.T) {
	const src = `
# a self-documenting scripted drive
{"prompt":"write the token to the proof file","allow":true,"assert":{"file":"ds-headless-proof.txt","contains":"DS-PROOF-TOKEN-123"}}

{"prompt":"a second turn, deny its tool","allow":false,"deny_message":"nope"}
`
	turns, err := ParseScript(strings.NewReader(src))
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}
	if len(turns) != 2 {
		t.Fatalf("parsed %d turns, want 2 (blank + comment lines skipped)", len(turns))
	}
	if turns[0].Prompt == "" || !turns[0].Allow {
		t.Errorf("turn 1 = %+v, want prompt set + allow true", turns[0])
	}
	if turns[0].Assert == nil || turns[0].Assert.Contains != "DS-PROOF-TOKEN-123" {
		t.Errorf("turn 1 assert = %+v, want contains token", turns[0].Assert)
	}
	if turns[1].Allow {
		t.Errorf("turn 2 allow = true, want false (deny turn)")
	}
	if turns[1].DenyMessage != "nope" {
		t.Errorf("turn 2 deny_message = %q, want %q", turns[1].DenyMessage, "nope")
	}
}

func TestParseScriptRejects(t *testing.T) {
	cases := map[string]string{
		"empty script":         "\n# only a comment\n",
		"empty prompt":         `{"prompt":"","allow":true}`,
		"unknown field":        `{"prompt":"x","allowed":true}`,
		"assert missing field": `{"prompt":"x","assert":{"file":"p.txt"}}`,
		"malformed json":       `{"prompt":"x",`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseScript(strings.NewReader(src)); err == nil {
				t.Errorf("ParseScript(%q) = nil error, want a parse error", src)
			}
		})
	}
}

// TestParseScriptFixture parses the committed proof.jsonl fixture the smoke
// harness drives, so a malformed fixture is caught in the wave gate (offline),
// not only when an operator arms the live leg.
func TestParseScriptFixture(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "proof.jsonl"))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	turns, err := ParseScript(f)
	if err != nil {
		t.Fatalf("ParseScript(proof.jsonl): %v", err)
	}
	if len(turns) != 1 {
		t.Fatalf("proof.jsonl has %d turns, want exactly 1 (the deterministic single-turn proof)", len(turns))
	}
	if turns[0].Assert == nil {
		t.Fatal("proof.jsonl turn carries no assert: the side-effect proof needs file+contains")
	}
	if !turns[0].Allow {
		t.Error("proof.jsonl turn must allow its tool so the proof file is actually written")
	}
}

// --- (3) DriveScriptScenario stepping against the fake-CC bridge (offline) ---

// TestDriveScriptScenarioFakeCC drives the SCRIPTED scenario over the exact
// host-agent + framed-UDS + thin-client wiring the live path uses, with CC
// replaced by a scripted single-turn fake-CC helper process. It proves the
// JSONL-driven stepping closes the ask grant round-trip and reaches the turn's
// result, offline, in the wave gate — no podman/claude/cia touched.
func TestDriveScriptScenarioFakeCC(t *testing.T) {
	cfg := LiveDriveConfig{
		Image:         "ds/cc-sandbox:2.1.173", // named, never run (fake path)
		Model:         "sonnet",
		BudgetUSD:     "1.0",
		PodmanNetwork: "none",
		ccCommand:     scriptFakeCCCommand("allow"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	turns := []Turn{{
		Prompt: "write the token DS-PROOF-TOKEN-123 to /work/ds-headless-proof.txt with the Bash tool",
		Allow:  true,
		Assert: &TurnAssert{File: "ds-headless-proof.txt", Contains: "DS-PROOF-TOKEN-123"},
	}}
	res, err := driveFakeSocketBridge(ctx, cfg, "fake-script-session", DriveScriptScenario(turns, 10*time.Second))
	if err != nil {
		t.Fatalf("driveFakeSocketBridge (script): %v", err)
	}
	if !res.AskAnswered {
		t.Fatal("the scripted drive never answered an ask (the grant round-trip did not run)")
	}
	// The same structural/id-relative assertions the live leg runs: well-formed
	// stream, a chat turn, and the ask request→resolve round-trip closed allow.
	validateEventsLive(t, res.Events)
	if !liveProjectionContains(res.Events, attach.TypeChatMessage) {
		t.Error("no chat.message in the scripted projection")
	}
	assertAskRoundTripLive(t, res.Events, true /*allow*/)
}

// TestDriveScriptScenarioFakeCCDeny is the deny twin: the script denies the turn's
// tool, and the resolution carries behavior "deny".
func TestDriveScriptScenarioFakeCCDeny(t *testing.T) {
	cfg := LiveDriveConfig{
		Image:         "ds/cc-sandbox:2.1.173",
		Model:         "sonnet",
		BudgetUSD:     "1.0",
		PodmanNetwork: "none",
		ccCommand:     scriptFakeCCCommand("deny"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	turns := []Turn{{
		Prompt:      "write a token to the proof file with the Bash tool",
		Allow:       false,
		DenyMessage: "Denied by the scripted headless drive (turn.allow=false).",
	}}
	res, err := driveFakeSocketBridge(ctx, cfg, "fake-script-session-deny", DriveScriptScenario(turns, 10*time.Second))
	if err != nil {
		t.Fatalf("driveFakeSocketBridge (script deny): %v", err)
	}
	validateEventsLive(t, res.Events)
	assertAskRoundTripLive(t, res.Events, false /*deny*/)
}

// TestDriveScriptScenarioMultiTurn proves the multi-turn stepping: two turns, each
// with its own ask, advance independently — turn 2's prompt is driven only after
// turn 1 reaches its result, and BOTH asks are answered.
func TestDriveScriptScenarioMultiTurn(t *testing.T) {
	cfg := LiveDriveConfig{
		Image:         "ds/cc-sandbox:2.1.173",
		Model:         "sonnet",
		BudgetUSD:     "1.0",
		PodmanNetwork: "none",
		ccCommand:     scriptFakeCCCommand("multi"),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	turns := []Turn{
		{Prompt: "turn one: run the Bash tool", Allow: true},
		{Prompt: "turn two: run the Bash tool again", Allow: true},
	}
	res, err := driveFakeSocketBridge(ctx, cfg, "fake-script-multi", DriveScriptScenario(turns, 12*time.Second))
	if err != nil {
		t.Fatalf("driveFakeSocketBridge (multi): %v", err)
	}
	validateEventsLive(t, res.Events)
	// Two results means both turns reached their session.accounted (the stepping
	// advanced per-turn, not collapsed onto a single result).
	results := 0
	resolvedAskIDs := map[string]bool{}
	for _, ev := range res.Events {
		switch ev.Type {
		case attach.TypeSessionAccounted:
			results++
		case attach.TypeAskResolved:
			if ev.AskResolved != nil {
				resolvedAskIDs[ev.AskResolved.AskID] = true
			}
		}
	}
	if results < 2 {
		t.Errorf("multi-turn drive produced %d session.accounted, want >= 2 (each turn its own result)", results)
	}
	// DISTINCT resolved ask ids: turn 2 must answer ITS OWN ask, not re-grant
	// turn 1's already-resolved ask (the whole event history stays visible in the
	// snapshot, so a position-based join would re-answer the first/stale ask and
	// stall the live turn). Two distinct ids prove the id-keyed stepping.
	if len(resolvedAskIDs) < 2 {
		t.Errorf("multi-turn drive resolved %d DISTINCT ask id(s), want >= 2 (each turn must answer its own ask, not re-grant a stale one): %v", len(resolvedAskIDs), resolvedAskIDs)
	}
}

// --- (3b) the BROAD-COVERAGE fixture, offline (coverage.jsonl twin) ----------

// TestParseCoverageFixture parses the committed coverage.jsonl fixture in the wave
// gate (offline), so a malformed broad-coverage fixture is caught here, not only
// when an operator arms the KVM live leg. It pins the fixture's load-bearing shape:
// it drives MULTIPLE turns, exercises BOTH grant branches (at least one allow and
// at least one deny), and every assert carries both file and contains.
func TestParseCoverageFixture(t *testing.T) {
	turns := loadCoverageTurns(t)
	if len(turns) < 10 {
		t.Fatalf("coverage.jsonl has %d turns, want >= 10 (Bash, Write, Read+Edit, TodoWrite, Glob, Grep, Grep-deny, Read-error, Task, MultiEdit)", len(turns))
	}
	sawAllow, sawDeny, sawDenyMsg := false, false, false
	for i, turn := range turns {
		if turn.Allow {
			sawAllow = true
		} else {
			sawDeny = true
			if strings.TrimSpace(turn.DenyMessage) != "" {
				sawDenyMsg = true
			}
		}
		if turn.Assert != nil && (turn.Assert.File == "" || turn.Assert.Contains == "") {
			t.Errorf("coverage turn %d assert = %+v, want both file and contains", i+1, turn.Assert)
		}
	}
	if !sawAllow {
		t.Error("coverage.jsonl has no allow turn (the allow grant branch is not exercised)")
	}
	if !sawDeny {
		t.Error("coverage.jsonl has no deny turn (the deny grant branch is not exercised)")
	}
	if !sawDenyMsg {
		t.Error("coverage.jsonl deny turn has no deny_message (the verbatim deny-reason propagation is not exercised)")
	}
}

// TestDriveCoverageScenarioFakeCC drives the SAME coverage.jsonl turns the gated
// KVM test drives, but against a scripted multi-feature fake-CC over the exact
// host-agent + framed-UDS + thin-client wiring the live path uses. It proves the
// broad-coverage assertion helpers (assertToolCoverageLive / assertDenyRoundTripLive
// / assertSpawnCorrelationLive / assertTurnAccountingLive) are green in the wave
// gate — every line the live KVM leg runs except the model's scripted choice to
// call each tool. No podman/claude/KVM is touched.
func TestDriveCoverageScenarioFakeCC(t *testing.T) {
	cfg := LiveDriveConfig{
		Image:         "ds/cc-sandbox:2.1.173", // named, never run (fake path)
		Model:         "sonnet",
		BudgetUSD:     "1.0",
		PodmanNetwork: "none",
		ccCommand:     coverageFakeCCCommand(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	turns := loadCoverageTurns(t)
	res, err := driveFakeSocketBridge(ctx, cfg, "fake-coverage-session", DriveScriptScenario(turns, 12*time.Second))
	if err != nil {
		t.Fatalf("driveFakeSocketBridge (coverage): %v", err)
	}

	// The SAME conformance helpers the gated KVM test runs, over the fake projection.
	validateEventsLive(t, res.Events)
	if !liveProjectionContains(res.Events, attach.TypeChatMessage) {
		t.Error("no chat.message in the coverage projection")
	}
	// Breadth: the named native tools each fired and completed clean (allow branch) —
	// the full surface Bash + Read + Write + Edit + MultiEdit + Glob + Grep, not just
	// Bash. The offline fake drives ALL of them deterministically, so the offline twin
	// hard-asserts the model-reliable set AND the live-soft set (MultiEdit/Glob/Grep)
	// here — the live test relaxes the soft set to best-effort (see their rationale).
	assertToolPairsLive(t, res.Events, coverageAllowTools)
	assertToolPairsLive(t, res.Events, coverageOfflineHardTools)
	assertToolPairsLive(t, res.Events, coverageSoftTools)
	// TYPED plan delta: the TodoWrite turn projected a first-class attach.PlanDelta
	// (Kind=todo_write) carrying its >=2-item Todos snapshot.
	if !liveProjectionContains(res.Events, attach.TypePlanDelta) {
		t.Error("no plan.delta in the coverage projection (the TodoWrite turn did not project a TYPED PlanDelta)")
	}
	assertPlanDeltaLive(t, res.Events, 2)
	// The allow ask round-trip closed (assertAskRoundTripLive takes the FIRST ask;
	// turn 1 is allow, so it asserts allow), and the deny round-trip closed too.
	assertAskRoundTripLive(t, res.Events, true /*allow*/)
	assertDenyRoundTripLive(t, res.Events)
	// The IsError-not-deny branch: a granted tool that FAILED at runtime, distinct
	// from the denied tool (different node, no DenialMessage).
	assertErrorNotDenyLive(t, res.Events)
	// The subagent spawn correlates to its terminals, AND a tool the subagent ran
	// correlates UNDER the spawn (the nested-under-subagent shape).
	assertSpawnCorrelationLive(t, res.Events)
	if !liveProjectionContains(res.Events, attach.TypeSubagentSpawned) {
		t.Error("no subagent.spawned in the coverage projection (the Task turn did not spawn)")
	}
	assertNestedUnderSubagentLive(t, res.Events)
	// One running result per driven turn.
	assertTurnAccountingLive(t, res.Events, len(turns))
}

// coverageAllowTools is the set of native tools the coverage fixture's ALLOW turns
// drive cleanly that REQUIRE a named tool.invoked/completed pair. These are the
// tools the real model reliably routes through by name (the write/edit/read
// mutating + read tools); assertToolPairsLive requires each. The DENY turn runs a
// SEPARATE Grep that is blocked (asserted by assertDenyRoundTripLive, NOT here) and
// the ReadErr turn runs a SEPARATE failing Read (asserted by assertErrorNotDenyLive).
// Shared by the offline twin (where the fake drives each deterministically) and the
// gated KVM test.
var coverageAllowTools = []string{"Bash", "Write", "Read", "Edit"}

// coverageOfflineHardTools are tools the OFFLINE fake-CC twin additionally drives by
// name and hard-asserts, but the LIVE model routes around even under a forced
// single-tool prompt — so live they are best-effort (logged, with the in-VM proof
// file as the load-bearing evidence), NOT hard-asserted. MultiEdit (gap-2) is here:
// confirmed LIVE on the KVM tier, the model created the seed file but DID NOT issue
// the MultiEdit call (it judged a 2-line file not worth a multi-hunk edit and left
// the seed, or applied the change another way), so no MultiEdit tool.invoked fired
// and the multi-hunk tokens never landed. CLASSIFICATION: OFFLINE-HARD +
// LIVE-BEST-EFFORT — the offline twin proves the MultiEdit invoked→completed pair +
// the two-hunk input deterministically; live we log whether the name fired and the
// multi-hunk effect when it lands, rather than flaking on a model choice we can't pin.
var coverageOfflineHardTools = []string{"MultiEdit"}

// coverageSoftTools are tools the fixture ASKS for by name but the real model
// MODEL-DISCRETIONARILY routes around even under a forced single-tool prompt
// ("Your FIRST action must be a call to the Glob tool (not Bash, not LS)…"): a
// "search /work" instruction has a natural Bash/ls/grep substitute the model
// prefers, and the named Glob/Grep tool.invoked then never fires. This was
// confirmed LIVE on the KVM tier (epic 01KVCHFEFF round-0 + gap-1 01KVCMY36T:
// the model satisfied both search turns with Bash and wrote the proof directly).
// CLASSIFICATION (gap-1): these stay OFFLINE-HARD + LIVE-EFFECT-ONLY — the OFFLINE
// fake drives them by name (assertToolPairsLive via coverageAllowTools' twin in
// TestDriveCoverageScenarioFakeCC requires the named pair deterministically), and
// the LIVE leg logs the named-projection breadth as best-effort while the
// load-bearing live proof for those turns is the in-VM side effect (the per-turn
// cov-glob/cov-grep proof file), NOT which tool the non-deterministic model picked.
// Forcing them HARD live would make the drive flaky on a model choice we cannot
// pin, so we DOCUMENT them as model-discretionary rather than hard-assert them.
var coverageSoftTools = []string{"Glob", "Grep"}

// loadCoverageTurns parses the committed coverage.jsonl broad-coverage drive script.
func loadCoverageTurns(t *testing.T) []Turn {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "coverage.jsonl"))
	if err != nil {
		t.Fatalf("open coverage.jsonl fixture: %v", err)
	}
	defer f.Close()
	turns, err := ParseScript(f)
	if err != nil {
		t.Fatalf("parse coverage.jsonl: %v", err)
	}
	return turns
}

// --- (2) the DS_E2E_LIVE-gated VM-side-effect scripted drive -----------------

// TestScriptedDriveVMSideEffectReal drives a deterministic single-turn script from
// the committed proof.jsonl fixture against a REAL Claude Code process in a
// rootless podman container, then asserts BOTH halves of the headless-drive proof:
//
//   - the PROJECTED attach.v1 result events (the ask request→resolve round-trip
//     closed allow, the same id-relative conformance the fake leg proves), AND
//   - the VM-SIDE EFFECT: the proof file CC was instructed to write actually
//     exists in the container workdir (the host side of the /work bind mount) and
//     contains the deterministic token — proving CC EXECUTED the instruction, not
//     merely streamed text about it.
//
// It SKIPS without DS_E2E_LIVE=1 (every CI / go test run) and launches NOTHING
// then. Permission posture: the tool-use ask is answered on the PROVEN attach.v1
// grant auto-answer path (DriveScriptScenario → GrantAsk → the wrapper's native
// control_response), NEVER --dangerously-skip-permissions on the host.
func TestScriptedDriveVMSideEffectReal(t *testing.T) {
	if os.Getenv(LiveGateEnv) != "1" {
		t.Skip("DS_E2E_LIVE != 1: the scripted VM-side-effect drive is the deferred manual live step (scripts/ds-headless-drive-smoke.sh). Skipping; the fake-CC twins prove the stepping + parser offline.")
	}

	turns := loadFixtureTurns(t)

	// A host workdir under ~/tmp (the scratch convention) bind-mounted read-write
	// at the container /work, so the proof file CC writes is observable here. It is
	// NON-sensitive scratch — assertNoForbiddenMount still rejects a host /tmp,
	// host HOME, or ~/.claude target by construction.
	workdir, err := os.MkdirTemp(scratchRoot(), "ds-headless-proof-")
	if err != nil {
		t.Fatalf("proof workdir: %v", err)
	}
	// Rootless-podman userns: the host workdir is owned by the host user (== container
	// root), but CC runs NON-root in the container, so a default-0700 /work bind is
	// unwritable (EACCES) and CC retries past the one-ask-per-turn grant budget. Make
	// it world-writable so the container's mapped user can write the proof file; the
	// host (owner) still reads it back, and assertNoForbiddenMount already fences the
	// path to non-sensitive scratch.
	if err := os.Chmod(workdir, 0o777); err != nil {
		t.Fatalf("proof workdir chmod: %v", err)
	}
	defer os.RemoveAll(workdir)

	cfg := LiveDriveConfigDefaults()
	cfg.WorkdirHost = workdir
	applyLiveRoutingEnv(t, &cfg) // the documented DS_LIVE_* routing knobs (shared with the conformance test)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, err := DriveLiveSocketBridge(ctx, cfg, fmt.Sprintf("live-script-%d", time.Now().Unix()),
		DriveScriptScenario(turns, 2*time.Minute))
	if err != nil {
		t.Fatalf("DriveLiveSocketBridge (scripted): %v", err)
	}
	t.Logf("scripted drive projected %d attach.v1 events; raw capture (raw-class, uncommitted): %s", len(res.Events), res.RawCapturePath)

	// Half 1 — the projected attach.v1 round-trip (allow), id-relative.
	validateEventsLive(t, res.Events)
	assertAskRoundTripLive(t, res.Events, true /*allow*/)
	if !res.AskAnswered {
		t.Error("the scripted drive never answered an ask on the live run")
	}

	// Half 2 — the VM-side effect: every turn that carried an assert wrote its proof
	// file with its token, on the host side of the /work mount.
	for i, turn := range turns {
		if turn.Assert == nil {
			continue
		}
		proof := filepath.Join(workdir, turn.Assert.File)
		got, rerr := os.ReadFile(proof)
		if rerr != nil {
			t.Fatalf("turn %d VM-side effect: proof file %s not found on the host /work mount: %v (CC did not execute the write instruction)", i+1, proof, rerr)
		}
		if !strings.Contains(string(got), turn.Assert.Contains) {
			t.Errorf("turn %d VM-side effect: proof file %s = %q, want it to contain token %q", i+1, proof, string(got), turn.Assert.Contains)
		} else {
			t.Logf("turn %d VM-side effect proven: %s contains %q", i+1, proof, turn.Assert.Contains)
		}
	}
}

// --- (2b) the DS_KVM_LIVE-gated KVM-VM writer-seat VM-side-effect drive --------

// TestScriptedDriveKVMVMSideEffectReal is the KVM-tier RETARGET of
// TestScriptedDriveVMSideEffectReal: it drives the SAME committed proof.jsonl
// fixture, with the SAME DriveScriptScenario stepping and the SAME assertion
// helpers (validateEventsLive / assertAskRoundTripLive + the VM-side-effect proof
// readback), but against a REAL Claude Code running INSIDE a per-session KVM VM
// instead of a rootless podman container. It is a TRANSPORT-TARGET SWAP, not a
// scenario change: the thin client dials the writer-seat the live ds-hostbridge
// serving child advertises (resolved at runtime from DS_KVM_LIVE_*) over the SAME
// hostbridge.SocketTransport the podman tier dials its local UDS with.
//
// It SKIPS CLEAN (exit 0) without DS_KVM_LIVE=1 — every CI / sandbox / go test run
// — and dials NOTHING then. When armed, the operator must have a live VM serving
// the session (the M1 create→boot path), with the writer-seat endpoint + session
// UUID + short-lived token exported in DS_KVM_LIVE_* (see kvmAttachFromEnv /
// LIVE-VALIDATION.md tier D). Permission posture is identical to the podman tier:
// the tool-use ask is answered on the proven attach.v1 grant path
// (DriveScriptScenario → GrantAsk → the wrapper's native control_response inside
// the VM), NEVER --dangerously-skip-permissions.
//
// The VM-side-effect half reads the proof file back from the host side of the
// guest-mounted /work (the operator points DS_KVM_LIVE_WORK at it — the host
// directory the M1 image bind/9p-mounts at the guest /work CC wrote to). Unset ⇒
// the projected-events half still runs (the round-trip proof), and the side-effect
// readback is reported as a manual operator check rather than failing the run, so
// the test does not assume a particular host↔guest share mechanism.
func TestScriptedDriveKVMVMSideEffectReal(t *testing.T) {
	if os.Getenv(KVMLiveGateEnv) != "1" {
		t.Skip("DS_KVM_LIVE != 1: the per-session KVM-VM writer-seat drive is the M1 deferred manual live step (LIVE-VALIDATION.md tier D). Skipping; the fake-CC twins prove the stepping + parser offline, and the podman tier proves the live CC round-trip.")
	}

	turns := loadFixtureTurns(t)

	kvm, err := kvmAttachFromEnv()
	if err != nil {
		t.Fatalf("KVM-tier env: %v", err)
	}
	cfg := LiveDriveConfig{KVMAttach: kvm}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	res, err := DriveKVMScripted(ctx, cfg, DriveScriptScenario(turns, 2*time.Minute))
	if err != nil {
		t.Fatalf("DriveKVMScripted (scripted): %v", err)
	}
	t.Logf("KVM-tier scripted drive projected %d attach.v1 events over the per-session writer-seat", len(res.Events))

	// Half 1 — the projected attach.v1 round-trip (allow), id-relative — the EXACT
	// podman-tier conformance helpers, unchanged.
	validateEventsLive(t, res.Events)
	assertAskRoundTripLive(t, res.Events, true /*allow*/)
	if !res.AskAnswered {
		t.Error("the scripted drive never answered an ask on the live KVM run")
	}

	// Half 2 — the VM-SIDE effect: the proof file CC was instructed to write exists
	// on the host side of the guest /work share and carries the token. Resolved
	// from DS_KVM_LIVE_WORK (the host dir mounted at the guest /work); unset ⇒ the
	// readback is an operator manual step, not a failure (the host↔guest share
	// mechanism is not assumed by this harness).
	workdir := strings.TrimSpace(os.Getenv("DS_KVM_LIVE_WORK"))
	if workdir == "" {
		t.Logf("DS_KVM_LIVE_WORK unset: the VM-side-effect proof readback is a manual operator check (inspect the guest /work for the proof file carrying the token). The projected round-trip above is proven.")
		return
	}
	for i, turn := range turns {
		if turn.Assert == nil {
			continue
		}
		proof := filepath.Join(workdir, turn.Assert.File)
		got, rerr := os.ReadFile(proof)
		if rerr != nil {
			t.Fatalf("turn %d VM-side effect: proof file %s not found on the host side of the guest /work share: %v (CC did not execute the write instruction in the VM)", i+1, proof, rerr)
		}
		if !strings.Contains(string(got), turn.Assert.Contains) {
			t.Errorf("turn %d VM-side effect: proof file %s = %q, want it to contain token %q", i+1, proof, string(got), turn.Assert.Contains)
		} else {
			t.Logf("turn %d VM-side effect proven on the KVM guest: %s contains %q", i+1, proof, turn.Assert.Contains)
		}
	}
}

// --- (2c) the DS_KVM_LIVE-gated BROAD-COVERAGE KVM-VM writer-seat drive --------

// TestScriptedDriveKVMCoverageReal is the BROAD-COVERAGE KVM-tier drive: it loads
// the committed coverage.jsonl fixture (Bash, Write, Read+Edit, TodoWrite, Glob/Grep,
// a deny, a doomed Read, a nested Task subagent, and MultiEdit — allow and deny
// branches) and drives it against a REAL Claude Code running INSIDE a per-session
// KVM VM over the writer-seat, then asserts the corresponding attach.v1 projection
// PER FEATURE plus the real in-VM side effects. It is the breadth counterpart of
// TestScriptedDriveKVMVMSideEffectReal (which pins a single deterministic write):
// same DriveScriptScenario stepping, same writer-seat transport, richer fixture +
// per-feature assertions.
//
// ASSERTION TIERS (gap-1): HARD live — Bash/Read/Write/Edit/MultiEdit named pairs,
// the allow + deny ask round-trips, subagent.spawned, one session.accounted per
// turn, and every per-turn in-VM proof file (incl. the MultiEdit multi-hunk effect).
// MODEL-DISCRETIONARY (offline-hard, live-effect-only/opportunistic) — the Glob/Grep
// tool NAMES, the typed TodoWrite PlanDelta, the doomed-Read IsError-not-deny, and
// the nested-under-subagent threading: even under forced single-tool prompts the
// real model routes around the named tool (Bash for searches), records a tiny plan
// without TodoWrite, declines a read it judges doomed, or CC flattens the subagent
// depth. Each is hard-asserted by the OFFLINE fake-CC twin and proven in-VM by its
// side-effect file; live they are logged-not-failed so the drive never flakes on a
// model choice we cannot pin. See coverageSoftTools and the per-feature comments.
//
// It SKIPS CLEAN (exit 0) without DS_KVM_LIVE=1 — every CI / sandbox / go test run
// — and dials NOTHING then; the offline fake-CC twin (TestDriveCoverageScenarioFakeCC)
// proves the same helpers green in the wave gate. When armed, the operator must
// have a live VM serving the session (M1 create→boot path) with DS_KVM_LIVE_*
// exported (kvmAttachFromEnv); DS_KVM_LIVE_WORK points at the host side of the
// guest /work share for the side-effect readback (unset ⇒ readback is a manual
// operator check, the projected per-feature events still proven). Permission
// posture matches every tier: each ask is answered on the attach.v1 grant path
// (DriveScriptScenario → GrantAsk → the wrapper's native control_response inside
// the VM), NEVER --dangerously-skip-permissions.
func TestScriptedDriveKVMCoverageReal(t *testing.T) {
	if os.Getenv(KVMLiveGateEnv) != "1" {
		t.Skip("DS_KVM_LIVE != 1: the broad-coverage per-session KVM-VM drive is the M1 deferred manual live step (LIVE-VALIDATION.md tier D). Skipping; TestDriveCoverageScenarioFakeCC proves the per-feature assertions offline, and TestScriptedDriveKVMVMSideEffectReal proves the live writer-seat round-trip.")
	}

	turns := loadCoverageTurns(t)

	kvm, err := kvmAttachFromEnv()
	if err != nil {
		t.Fatalf("KVM-tier env: %v", err)
	}
	cfg := LiveDriveConfig{KVMAttach: kvm}

	// 9 broad-coverage turns, each a real billed model turn; the overall budget is
	// generous (per-turn ceiling 3m) so a slow turn never times out the whole drive.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	defer cancel()

	res, err := DriveKVMScripted(ctx, cfg, DriveScriptScenario(turns, 3*time.Minute))
	if err != nil {
		t.Fatalf("DriveKVMScripted (coverage): %v", err)
	}
	t.Logf("KVM-tier coverage drive projected %d attach.v1 events over the per-session writer-seat", len(res.Events))
	for _, ev := range res.Events {
		t.Logf("  seq=%d type=%s", ev.Seq, ev.Type)
	}

	// Half 1 — the PER-FEATURE attach.v1 projection, id-relative, the same helpers
	// the offline twin runs:
	validateEventsLive(t, res.Events)
	if !liveProjectionContains(res.Events, attach.TypeChatMessage) {
		t.Error("no chat.message in the coverage projection (the conversation did not drive)")
	}
	// tool breadth (HARD): Bash/Read/Write/Edit each fired and completed clean (allow)
	// — the distinct native tool names the real model reliably routes by name when the
	// per-turn prompt forces a specific mutating/reading tool (a write/read/edit
	// instruction has no natural shortcut the way a "search /work" instruction does, so
	// the model honors the named tool).
	assertToolPairsLive(t, res.Events, coverageAllowTools)
	// BEST-EFFORT live (offline-hard): Glob/Grep (the search shortcut) and MultiEdit
	// (gap-2 — the live model created the seed file but declined the multi-hunk edit on
	// a tiny file). Logged-not-failed; the offline twin hard-asserts all of these, and
	// the in-VM proof file is the live evidence for the write turns.
	logToolPairsLive(t, res.Events, coverageSoftTools)
	logToolPairsLive(t, res.Events, coverageOfflineHardTools)
	// TYPED plan delta — MODEL-DISCRETIONARY (gap-1): the TodoWrite turn projects a
	// first-class attach.PlanDelta (Kind=todo_write, >=2-item Todos) WHEN the model
	// routes the plan through the TodoWrite tool. Even under a forced single-tool
	// prompt ("Use the TodoWrite tool — and no other tool for the plan…Do NOT use
	// TaskCreate, Task, or Bash to record the plan"), the real model frequently
	// considers a 2-item plan too small to warrant a TodoWrite and records it some
	// other way (confirmed LIVE on the KVM tier — no plan.delta projected on that
	// run). CLASSIFICATION: OFFLINE-HARD + LIVE-EFFECT-ONLY — the OFFLINE twin asserts
	// the typed PlanDelta deterministically (the fake always emits a TodoWrite
	// tool-use → assertPlanDeltaLive), and the in-VM cov-plan.txt proves the plan
	// turn executed; live we assert the typed shape WHEN it projects and log-not-fail
	// when the model routed around it, rather than flaking on a model choice we
	// cannot pin.
	if liveProjectionContains(res.Events, attach.TypePlanDelta) {
		assertPlanDeltaLive(t, res.Events, 2)
		t.Logf("TYPED PlanDelta projected LIVE: the TodoWrite turn surfaced a first-class plan.delta with its Todos snapshot")
	} else {
		t.Logf("no plan.delta in the LIVE projection: the model recorded the 2-item plan without TodoWrite this run — model-discretionary/offline-hard/live-effect-only (the offline twin asserts the typed PlanDelta deterministically, and cov-plan.txt proves the plan turn executed in-VM)")
	}
	// the allow ask round-trip (turn 1 is allow ⇒ the FIRST ask is allow) and the
	// deny round-trip (the Grep-deny turn) both closed — HARD.
	assertAskRoundTripLive(t, res.Events, true /*allow*/)
	assertDenyRoundTripLive(t, res.Events)
	// the IsError-not-deny branch — MODEL-DISCRETIONARY (gap-1, the doomed Read): the
	// failing read-only Read carries an un-asked tool.completed IsError=true (no
	// correlated ask.resolved), distinct from the grant-path deny. This is the LEAST
	// pinnable feature: even told "read exactly the file path …it is expected to fail
	// …just report the error", the real model usually DECLINES to attempt a read it
	// can reason will fail and answers in chat that the file is missing — emitting NO
	// errored tool.completed at all (confirmed LIVE on the KVM tier). We cannot force
	// the model to make a call it judges pointless. CLASSIFICATION: OFFLINE-HARD +
	// LIVE-OPPORTUNISTIC — the OFFLINE twin asserts the un-asked errored completion
	// deterministically (the fake always emits it → assertErrorNotDenyLive in
	// TestDriveCoverageScenarioFakeCC); live we assert it WHEN it surfaces and log the
	// model's decline otherwise. (The deeper projection limit — the adapter cannot
	// tell a granted-then-failed ASKED tool from a deny, only an UN-ASKED failure is
	// provably-not-a-deny — is gap-3 01KVCNDT7G; this turn exercises the un-asked arm.)
	if liveProjectionHasErrorNotDeny(res.Events) {
		assertErrorNotDenyLive(t, res.Events)
		t.Logf("IsError-not-deny projected LIVE: an un-asked tool.completed carries IsError=true with no ask.resolved, distinct from the grant-path deny")
	} else {
		t.Logf("IsError-not-deny not projected LIVE this run: the model declined the doomed read and answered in chat that the file is missing — model-discretionary/offline-hard (the offline twin asserts the un-asked errored completion deterministically)")
	}
	// the nested-Task turn's subagent spawn correlates to its terminals — HARD.
	assertSpawnCorrelationLive(t, res.Events)
	if !liveProjectionContains(res.Events, attach.TypeSubagentSpawned) {
		t.Error("no subagent.spawned in the coverage projection (the Task turn did not spawn a subagent)")
	}
	// nested-under-subagent — TRANSPORT-DISCRETIONARY (gap-1): a tool the subagent ran
	// correlates UNDER the spawn by parent node_id. Unlike the model-choice softs
	// above, this depends on whether CC's stream-json threads the in-subagent tool's
	// parent_tool_use_id back to the spawn node (CC's depth-flattening, P2) — not on a
	// prompt we can strengthen. It HAS projected LIVE on the KVM tier (a tool.invoked
	// correlated under the spawn), but is not guaranteed per-run. CLASSIFICATION:
	// OFFLINE-HARD + LIVE-OPPORTUNISTIC — the OFFLINE twin asserts it deterministically
	// (assertNestedUnderSubagentLive); live we log whether it threaded, and cov-task.txt
	// proves the subagent ran its in-VM Bash write regardless. (The spawn ITSELF is
	// hard-asserted above — subagent.spawned must project.)
	if liveProjectionHasNestedUnderSubagent(res.Events) {
		t.Logf("nested-under-subagent projected LIVE: a tool.invoked correlates UNDER the spawned subagent by parent node_id")
	} else {
		t.Logf("nested-under-subagent not projected LIVE this run: the in-subagent tool did not thread its parent back to the spawn node (best-effort; the offline twin asserts it, and cov-task.txt proves the subagent ran its in-VM write)")
	}
	// one running result per driven turn.
	assertTurnAccountingLive(t, res.Events, len(turns))
	if !res.AskAnswered {
		t.Error("the coverage drive never answered an ask on the live KVM run")
	}

	// Half 2 — the real in-VM SIDE EFFECTS: every turn that carried an assert wrote
	// its proof file with its token, on the host side of the guest /work share.
	// Resolved from DS_KVM_LIVE_WORK; unset ⇒ a manual operator check (the
	// host↔guest share mechanism is not assumed by this harness).
	workdir := strings.TrimSpace(os.Getenv("DS_KVM_LIVE_WORK"))
	if workdir == "" {
		t.Logf("DS_KVM_LIVE_WORK unset: the VM-side-effect proof readback is a manual operator check (inspect the guest /work for the per-turn proof files carrying their COV-*-9X4T tokens). The projected per-feature round-trips above are proven.")
		return
	}
	for i, turn := range turns {
		if turn.Assert == nil {
			continue
		}
		proof := filepath.Join(workdir, turn.Assert.File)
		got, rerr := os.ReadFile(proof)
		if rerr != nil {
			t.Fatalf("turn %d VM-side effect: proof file %s not found on the host side of the guest /work share: %v (CC did not execute the instruction in the VM)", i+1, proof, rerr)
		}
		if !strings.Contains(string(got), turn.Assert.Contains) {
			t.Errorf("turn %d VM-side effect: proof file %s = %q, want it to contain token %q", i+1, proof, string(got), turn.Assert.Contains)
		} else {
			t.Logf("turn %d VM-side effect proven on the KVM guest: %s contains %q", i+1, proof, turn.Assert.Contains)
		}
	}

	// gap-2 MULTI-HUNK proof (BEST-EFFORT live): when the model issues the MultiEdit
	// call, cov-medit.txt carries BOTH replaced tokens (the two hunks of the single
	// call). LIVE the model frequently declines a multi-hunk edit on a 2-line file and
	// leaves the seed (ALPHA-SEED/BETA-SEED) — confirmed on the KVM tier — so this is
	// logged, not failed: the offline twin hard-asserts the MultiEdit invoked→completed
	// pair + two-hunk input deterministically. (The seed Write itself ran in-VM, so the
	// file exists either way.)
	meditProof := filepath.Join(workdir, "cov-medit.txt")
	if got, rerr := os.ReadFile(meditProof); rerr != nil {
		t.Logf("MultiEdit VM-side effect: proof file %s not found (the model did not even write the seed this run): %v — best-effort live; the offline twin proves the pair deterministically", meditProof, rerr)
	} else {
		bothLanded := strings.Contains(string(got), "COV-MEDIT-A-9X4T") && strings.Contains(string(got), "COV-MEDIT-B-9X4T")
		if bothLanded {
			t.Logf("MultiEdit multi-hunk effect proven on the KVM guest: %s carries both COV-MEDIT-A/B-9X4T (two hunks in one call)", meditProof)
		} else {
			t.Logf("MultiEdit multi-hunk effect not applied LIVE this run: %s = %q (the model created the seed but declined the multi-hunk edit on a tiny file) — model-discretionary/offline-hard (the offline twin asserts the MultiEdit pair + two-hunk input deterministically)", meditProof, string(got))
		}
	}
}

// TestDriveKVMScriptedGateUnset proves the KVM tier dials NOTHING when DS_KVM_LIVE
// is unset: DriveKVMScripted returns ErrKVMLiveGateUnset and touches no socket. It
// is the always-on guard that the gated tier is gated (the offline twin of the
// podman tier's TestDriveLiveSocketBridgeGated), so a regression that drops the
// gate is caught in the wave gate, not only when an operator forgets to arm it.
func TestDriveKVMScriptedGateUnset(t *testing.T) {
	t.Setenv(KVMLiveGateEnv, "") // ensure unset/non-"1".
	// A populated endpoint must STILL not dial when the gate is unset — the gate is
	// the launch authority, not the endpoint presence.
	cfg := LiveDriveConfig{KVMAttach: KVMAttachConfig{
		Endpoint:    "/run/ds/attach/never-dialed.sock",
		SessionUUID: "00000000-0000-4000-8000-00000000kvm0",
		Token:       "never-used",
	}}
	_, err := DriveKVMScripted(context.Background(), cfg, DriveScriptScenario([]Turn{{Prompt: "x", Allow: true}}, time.Second))
	if !errors.Is(err, ErrKVMLiveGateUnset) {
		t.Fatalf("DriveKVMScripted with %s unset = %v, want ErrKVMLiveGateUnset (the KVM tier must dial nothing unarmed)", KVMLiveGateEnv, err)
	}
}

// loadFixtureTurns parses the committed proof.jsonl drive script (the deterministic
// single-turn proof the smoke harness drives).
func loadFixtureTurns(t *testing.T) []Turn {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "proof.jsonl"))
	if err != nil {
		t.Fatalf("open proof.jsonl fixture: %v", err)
	}
	defer f.Close()
	turns, err := ParseScript(f)
	if err != nil {
		t.Fatalf("parse proof.jsonl: %v", err)
	}
	return turns
}

// applyLiveRoutingEnv applies the documented additive DS_LIVE_* routing knobs to a
// live config (the ds-capture egress-gateway port/CA/network overrides), mirroring
// TestLiveDriveSocketBridgeReal so the scripted live leg routes through the same
// first-party gateway. Unset ⇒ the proven LiveDriveConfigDefaults stand.
func applyLiveRoutingEnv(t *testing.T, cfg *LiveDriveConfig) {
	t.Helper()
	if sc := os.Getenv("DS_LIVE_SCRATCH"); sc != "" {
		cfg.ScratchDir = sc
	}
	if pp := os.Getenv("DS_LIVE_PROXY_PORT"); pp != "" {
		port, err := strconv.Atoi(pp)
		if err != nil {
			t.Fatalf("DS_LIVE_PROXY_PORT=%q is not an integer: %v", pp, err)
		}
		cfg.ProxyPort = port
		cfg.PodmanNetwork = fmt.Sprintf("pasta:-T,%d", port)
	}
	if ca := os.Getenv("DS_LIVE_CA"); ca != "" {
		cfg.CAHost = ca
	}
	if net := os.Getenv("DS_LIVE_NET"); net != "" {
		cfg.PodmanNetwork = net
	}
}

// --- the scripted fake-CC helper process -------------------------------------

// scriptFakeCCCommand re-execs THIS test binary as the scripted single-turn fake-CC
// helper (the standard Go helper-process pattern), so the fake CC is a REAL separate
// process with REAL stdio pipes — the exact pipe shape the live podman process
// presents, only the bytes scripted. mode is "allow" | "deny" | "multi".
func scriptFakeCCCommand(mode string) func(ctx context.Context) *exec.Cmd {
	return func(ctx context.Context) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestScriptFakeCCHelperProcess")
		cmd.Env = append(os.Environ(), "GO_SCRIPT_FAKE_CC=1", "GO_SCRIPT_FAKE_CC_MODE="+mode)
		return cmd
	}
}

// TestScriptFakeCCHelperProcess is the scripted fake-CC helper process: when
// GO_SCRIPT_FAKE_CC=1 it is NOT a test but a scripted stream-json CC stand-in for
// the SCRIPTED drive. Per driven user input it emits an assistant chat + a Bash
// tool_use + a native can_use_tool control_request it HOLDS until the host's
// control_response, then (on the answer) the tool_result + the turn's result. It
// stays alive across turns (multi mode drives two), mirroring the sustained
// stream-json host the live CC presents. Synthetic by construction (no real ids,
// text, or creds — D50).
func TestScriptFakeCCHelperProcess(t *testing.T) {
	if os.Getenv("GO_SCRIPT_FAKE_CC") != "1" {
		return // ordinary test invocation: not the helper.
	}
	runScriptFakeCC(os.Getenv("GO_SCRIPT_FAKE_CC_MODE"))
	os.Exit(0)
}

// runScriptFakeCC scripts a sustained stream-json CC that, per user input, drives
// one Bash ask held until the host answers, then emits the tool_result + result.
// "multi" drives the same shape for each of two turns; "allow"/"deny" drive a
// single turn (the host's grant decision determines the tool_result is_error).
func runScriptFakeCC(mode string) {
	const session = "00000000-0000-4000-8000-0000005c2191"
	out := bufio.NewWriter(os.Stdout)
	emit := func(v map[string]any) {
		b, _ := json.Marshal(v)
		out.Write(b)
		out.WriteByte('\n')
		out.Flush()
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	turn := 0
	uuidN := 0
	nextUUID := func() string { uuidN++; return fmt.Sprintf("00000000-0000-4000-8000-0000000c5c%02d", uuidN) }
	reqID := func(n int) string { return fmt.Sprintf("creq-script-fake-%016d", n) }
	toolID := func(n int) string { return fmt.Sprintf("toolu_SCRIPTFAKE%010d", n) }

	maxTurns := 1
	if mode == "multi" {
		maxTurns = 2
	}

	emitInit := func() {
		emit(map[string]any{
			"type": "system", "subtype": "init", "session_id": session, "uuid": nextUUID(),
			"cwd": "/work", "claude_code_version": "2.1.173", "model": "claude-sonnet-4-6",
			"permissionMode": "default", "apiKeySource": "none",
			"tools":  []string{"Bash"},
			"agents": []string{"claude"},
		})
	}

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		switch msg["type"] {
		case "control_response":
			// The host answered the held ask for the current turn. Emit the matching
			// tool_result and the turn's final assistant + result, then either step to
			// the next turn (multi) or exit.
			resp, _ := msg["response"].(map[string]any)
			inner, _ := resp["response"].(map[string]any)
			behavior, _ := inner["behavior"].(string)
			isErr := behavior != "allow"
			content := "(Bash completed)"
			if isErr {
				content = "Denied by the scripted headless drive (turn.allow=false)."
			}
			emit(map[string]any{
				"type": "user", "session_id": session, "uuid": nextUUID(),
				"message": map[string]any{"role": "user", "content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": toolID(turn),
						"is_error": isErr, "content": content},
				}},
			})
			emit(map[string]any{
				"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
				"message": map[string]any{"id": fmt.Sprintf("msg_script_%d", turn), "type": "message", "role": "assistant",
					"model": "claude-sonnet-4-6", "stop_reason": "end_turn",
					"content": []any{map[string]any{"type": "text", "text": "Done."}}},
			})
			emit(map[string]any{
				"type": "result", "subtype": "success", "session_id": session, "uuid": nextUUID(),
				"is_error": false, "num_turns": turn, "result": "Done.", "total_cost_usd": 0,
			})
			out.Flush()
			if turn >= maxTurns {
				os.Exit(0)
			}

		case "user":
			turn++
			emitInit()
			// Assistant chat + a Bash tool_use, then a NATIVE can_use_tool
			// control_request the host must answer (HELD — no tool_result until the
			// control_response arrives, DRIVE-FINDINGS §1a socket-hold).
			emit(map[string]any{
				"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
				"message": map[string]any{"id": fmt.Sprintf("msg_script_pre_%d", turn), "type": "message", "role": "assistant",
					"model": "claude-sonnet-4-6", "stop_reason": "tool_use",
					"content": []any{
						map[string]any{"type": "text", "text": "On it — writing the proof file with the Bash tool."},
						map[string]any{"type": "tool_use", "id": toolID(turn),
							"name": "Bash", "input": map[string]any{"command": "echo token > /work/ds-headless-proof.txt"}},
					}},
			})
			emit(map[string]any{
				"type": "control_request", "request_id": reqID(turn),
				"request": map[string]any{"subtype": "can_use_tool", "tool_name": "Bash",
					"display_name": "Bash",
					"input":        map[string]any{"command": "echo token > /work/ds-headless-proof.txt"},
					"tool_use_id":  toolID(turn),
				},
			})
			// HOLD: the tool_result waits for the host's control_response (above).
			_ = mode
		}
	}
	out.Flush()
}

// --- the broad-coverage fake-CC helper process -------------------------------

// coverageFakeCCCommand re-execs THIS test binary as the broad-coverage fake-CC
// helper (the standard Go helper-process pattern), so the fake CC is a REAL
// separate process with REAL stdio pipes — the exact pipe shape the live KVM
// process presents, only the bytes scripted across the 5 coverage turns.
func coverageFakeCCCommand() func(ctx context.Context) *exec.Cmd {
	return func(ctx context.Context) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestCoverageFakeCCHelperProcess")
		cmd.Env = append(os.Environ(), "GO_COVERAGE_FAKE_CC=1")
		return cmd
	}
}

// TestCoverageFakeCCHelperProcess is the broad-coverage fake-CC helper: when
// GO_COVERAGE_FAKE_CC=1 it is NOT a test but a scripted stream-json CC stand-in
// that, per driven user input, plays the coverage.jsonl turn's tool — a held
// can_use_tool ask (Bash/Write/Read+Edit/Grep, and a Task spawn on the last turn)
// — so the host's per-turn grant (allow on 1/2/3/5, deny on 4) drives the
// tool_result is_error and the projection carries ToolInvoked/ToolCompleted,
// AskRequested/AskResolved, and SubagentSpawned. Synthetic by construction (no
// real ids, text, or creds — D50).
func TestCoverageFakeCCHelperProcess(t *testing.T) {
	if os.Getenv("GO_COVERAGE_FAKE_CC") != "1" {
		return // ordinary test invocation: not the helper.
	}
	runCoverageFakeCC()
	os.Exit(0)
}

// coverageTurnTool is the SCRIPTED-FEATURE name the coverage fake plays on each
// turn, in fixture order — the breadth surface the live KVM drive covers. It is a
// fake-only label (the asked tool, the non-asking pre-tools, and the result shape
// per turn are derived from it below), NOT a 1:1 wire tool name:
//
//	Bash      — asking Bash (allow) → clean write.
//	Write     — asking Write (allow).
//	Edit      — non-asking Read round-trip + asking Edit (allow); two completions.
//	TodoWrite — a non-asking TodoWrite tool_use (→ TYPED attach.PlanDelta, not an
//	            ask) + asking Bash for the token write (allow).
//	Glob      — non-asking Glob round-trip + asking Bash (allow); Glob name fires.
//	Grep      — non-asking Grep round-trip + asking Bash (allow); Grep name fires.
//	GrepDeny  — asking Grep (DENY) → the deny branch (ask.resolved deny +
//	            tool.completed IsError=true with a DenialMessage).
//	ReadErr   — a NON-asking Read of a nonexistent path whose tool_result is
//	            is_error=true — a tool that auto-allowed (NO ask) then FAILED, so it
//	            projects a tool.completed IsError=true with NO correlated
//	            ask.resolved. This is the IsError-not-deny branch: the adapter
//	            derives an asked tool's ask.resolved behavior from the tool_result
//	            is_error (resolveFromToolResult), so a GRANTED-then-failed ASKED tool
//	            is projection-indistinguishable from a deny — only an UN-ASKED
//	            (read-only) failure is provably not a deny.
//	Task      — Task spawn + task_started (→ subagent.spawned), a NESTED Bash whose
//	            assistant line parent_tool_use_id == the spawn node (asked, allow),
//	            then task_notification (→ subagent.completed) so the lifecycle and
//	            the nested-under-subagent tool correlate by node_id.
//	MultiEdit — non-asking Write (the seed file) + asking MultiEdit (allow) whose
//	            input carries a TWO-hunk edits[] (two old_string→new_string pairs in
//	            ONE call); MultiEdit is a distinct native tool NAME from Edit and its
//	            invoked→completed pair fires on the one multi-hunk call.
var coverageTurnTool = []string{"Bash", "Write", "Edit", "TodoWrite", "Glob", "Grep", "GrepDeny", "ReadErr", "Task", "MultiEdit"}

// runCoverageFakeCC scripts a sustained stream-json CC across the 9 coverage turns.
// Per driven user input it emits the turn's pre-tools (non-asking Read/Glob/Grep/
// TodoWrite round-trips, or the Task spawn lifecycle) then the turn's ASKING tool
// + a held can_use_tool control_request; on the host's control_response it emits
// the asked tool's tool_result (is_error per the grant behavior, with the BashErr
// turn forcing is_error=true on an ALLOW grant) + the turn's result, stepping or
// exiting. The Task turn additionally emits a task_notification on resolve.
func runCoverageFakeCC() {
	const session = "00000000-0000-4000-8000-00000c0e2a6e"
	out := bufio.NewWriter(os.Stdout)
	emit := func(v map[string]any) {
		b, _ := json.Marshal(v)
		out.Write(b)
		out.WriteByte('\n')
		out.Flush()
	}
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	turn := 0
	uuidN := 0
	nextUUID := func() string { uuidN++; return fmt.Sprintf("00000000-0000-4000-8000-00000c0fae%02d", uuidN) }
	reqID := func(n int) string { return fmt.Sprintf("creq-cov-fake-%018d", n) }
	toolID := func(n int) string { return fmt.Sprintf("toolu_COVFAKE%013d", n) }
	maxTurns := len(coverageTurnTool)

	emitInit := func() {
		emit(map[string]any{
			"type": "system", "subtype": "init", "session_id": session, "uuid": nextUUID(),
			"cwd": "/work", "claude_code_version": "2.1.173", "model": "claude-sonnet-4-6",
			"permissionMode": "default", "apiKeySource": "none",
			"tools":  []string{"Bash", "Write", "Read", "Edit", "Grep", "Glob", "Task", "TodoWrite"},
			"agents": []string{"claude", "general-purpose"},
		})
	}

	// spawnToolID names the Task spawn's tool_use id distinctly from the asked tool;
	// it is also the parent_tool_use_id of the nested Bash, so the in-subagent tool
	// correlates UNDER the spawned node (the nested-under-subagent shape).
	spawnToolID := func(n int) string { return fmt.Sprintf("toolu_COVSPAWN%012d", n) }
	taskID := func(n int) string { return fmt.Sprintf("cov9ktask%07d", n) }

	// emitNonAskingTool emits a complete (assistant tool_use + clean tool_result)
	// round-trip for a read-only tool that auto-allows (no can_use_tool ask), so the
	// projection carries that tool's tool.invoked/tool.completed pair before the
	// turn's asking tool.
	emitNonAskingTool := func(idTag, name string, input map[string]any, resultContent string) {
		id := fmt.Sprintf("toolu_COV%s%010d", idTag, turn)
		emit(map[string]any{
			"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
			"message": map[string]any{"id": fmt.Sprintf("msg_cov_%s_%d", idTag, turn), "type": "message", "role": "assistant",
				"model": "claude-sonnet-4-6", "stop_reason": "tool_use",
				"content": []any{
					map[string]any{"type": "text", "text": fmt.Sprintf("Using the %s tool.", name)},
					map[string]any{"type": "tool_use", "id": id, "name": name, "input": input},
				}},
		})
		emit(map[string]any{
			"type": "user", "session_id": session, "uuid": nextUUID(),
			"message": map[string]any{"role": "user", "content": []any{
				map[string]any{"type": "tool_result", "tool_use_id": id,
					"is_error": false, "content": resultContent},
			}},
		})
	}

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		switch msg["type"] {
		case "control_response":
			// The host answered THIS turn's held ask. Emit the matching tool_result +
			// the turn's final assistant + result, then step or exit.
			resp, _ := msg["response"].(map[string]any)
			inner, _ := resp["response"].(map[string]any)
			behavior, _ := inner["behavior"].(string)
			tool := coverageTurnTool[turn-1]

			// is_error / content by branch:
			//   deny grant        ⇒ is_error true, DENIAL framing (DenialMessage).
			//   otherwise (allow) ⇒ is_error false, clean completion.
			// (The IsError-not-deny branch is the ReadErr turn, a no-ask read-only
			// failure handled inline in the user case — it never reaches here.)
			isErr := behavior != "allow"
			content := fmt.Sprintf("(%s completed)", tool)
			if isErr {
				content = "Denied by the coverage drive (deny branch) — the tool was blocked."
			}
			emit(map[string]any{
				"type": "user", "session_id": session, "uuid": nextUUID(),
				"message": map[string]any{"role": "user", "content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": toolID(turn),
						"is_error": isErr, "content": content},
				}},
			})
			// Task turn: after the in-subagent Bash resolves, the dispatched subagent
			// reports its task_notification (→ subagent.completed/accounted) so the
			// spawn lifecycle correlates by node_id.
			if tool == "Task" {
				emit(map[string]any{
					"type": "system", "subtype": "task_notification", "session_id": session, "uuid": nextUUID(),
					"task_id": taskID(turn), "tool_use_id": spawnToolID(turn),
					"subagent_type": "general-purpose",
					"usage":         map[string]any{"total_tokens": 21, "tool_uses": 1, "duration_ms": 80},
					"summary":       "wrote the task proof file",
				})
			}
			emit(map[string]any{
				"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
				"message": map[string]any{"id": fmt.Sprintf("msg_cov_%d", turn), "type": "message", "role": "assistant",
					"model": "claude-sonnet-4-6", "stop_reason": "end_turn",
					"content": []any{map[string]any{"type": "text", "text": "Done."}}},
			})
			emit(map[string]any{
				"type": "result", "subtype": "success", "session_id": session, "uuid": nextUUID(),
				"is_error": false, "num_turns": turn, "result": "Done.", "total_cost_usd": 0,
			})
			out.Flush()
			if turn >= maxTurns {
				os.Exit(0)
			}

		case "user":
			turn++
			emitInit()
			tool := coverageTurnTool[turn-1]

			// ReadErr is a SELF-CONTAINED no-ask turn: a read-only Read that fails. It
			// raises NO can_use_tool ask (auto-allow), so it emits its is_error
			// tool_result + the turn's result inline here and never holds — there is
			// no control_response to wait for. (Driving it through the asking path
			// would make the adapter resolve it as a deny, indistinguishable from the
			// real deny turn; the un-asked failure is the only projection-distinct
			// IsError-not-deny shape.)
			if tool == "ReadErr" {
				errReadID := fmt.Sprintf("toolu_COVRDERR%012d", turn)
				emit(map[string]any{
					"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
					"message": map[string]any{"id": fmt.Sprintf("msg_cov_rderr_%d", turn), "type": "message", "role": "assistant",
						"model": "claude-sonnet-4-6", "stop_reason": "tool_use",
						"content": []any{
							map[string]any{"type": "text", "text": "Reading the missing file (expected to fail)."},
							map[string]any{"type": "tool_use", "id": errReadID, "name": "Read",
								"input": map[string]any{"file_path": "/work/this-path-does-not-exist-COV-ERR-9X4T.txt"}},
						}},
				})
				emit(map[string]any{
					"type": "user", "session_id": session, "uuid": nextUUID(),
					"message": map[string]any{"role": "user", "content": []any{
						map[string]any{"type": "tool_result", "tool_use_id": errReadID,
							"is_error": true, "content": "Error: file not found: /work/this-path-does-not-exist-COV-ERR-9X4T.txt"},
					}},
				})
				emit(map[string]any{
					"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
					"message": map[string]any{"id": fmt.Sprintf("msg_cov_%d", turn), "type": "message", "role": "assistant",
						"model": "claude-sonnet-4-6", "stop_reason": "end_turn",
						"content": []any{map[string]any{"type": "text", "text": "The file does not exist; the read failed."}}},
				})
				emit(map[string]any{
					"type": "result", "subtype": "success", "session_id": session, "uuid": nextUUID(),
					"is_error": false, "num_turns": turn, "result": "Read failed (expected).", "total_cost_usd": 0,
				})
				out.Flush()
				continue // no held ask; the next user line steps the turn forward
			}

			// nestedParent is "" except on the Task turn, where the asking Bash is the
			// IN-SUBAGENT write — its assistant line carries parent_tool_use_id == the
			// spawn node, so the resulting tool.invoked correlates UNDER the subagent.
			nestedParent := any(nil)

			switch tool {
			case "Edit":
				// Non-asking Read before the asking Edit (two completions on the turn).
				emitNonAskingTool("READ", "Read",
					map[string]any{"file_path": "/work/cov-write.txt"}, "COV-WRITE-9X4T")
			case "TodoWrite":
				// A TodoWrite tool_use is NOT a can_use_tool ask — classify.go projects
				// it to a TYPED attach.PlanDelta (Kind=todo_write, Todos[]). Emit it as a
				// non-asking tool_use + a clean tool_result; the asking tool below is the
				// Bash token write.
				todoID := fmt.Sprintf("toolu_COVTODO%013d", turn)
				emit(map[string]any{
					"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
					"message": map[string]any{"id": fmt.Sprintf("msg_cov_todo_%d", turn), "type": "message", "role": "assistant",
						"model": "claude-sonnet-4-6", "stop_reason": "tool_use",
						"content": []any{
							map[string]any{"type": "text", "text": "Recording the 2-item plan with the TodoWrite tool."},
							map[string]any{"type": "tool_use", "id": todoID, "name": "TodoWrite",
								"input": map[string]any{"todos": []any{
									map[string]any{"content": "write the plan proof file", "status": "in_progress", "activeForm": "writing the plan proof file"},
									map[string]any{"content": "stop", "status": "pending", "activeForm": "stopping"},
								}}},
						}},
				})
				emit(map[string]any{
					"type": "user", "session_id": session, "uuid": nextUUID(),
					"message": map[string]any{"role": "user", "content": []any{
						map[string]any{"type": "tool_result", "tool_use_id": todoID,
							"is_error": false, "content": "Todos updated"},
					}},
				})
			case "Glob":
				emitNonAskingTool("GLOB", "Glob",
					map[string]any{"pattern": "*.txt", "path": "/work"}, "/work/cov-write.txt")
			case "Grep":
				emitNonAskingTool("GREP", "Grep",
					map[string]any{"pattern": "COV-WRITE-9X4T", "path": "/work"}, "/work/cov-write.txt")
			case "MultiEdit":
				// Non-asking Write seeds the file with the two replaceable markers; the
				// asking MultiEdit below rewrites BOTH in one multi-hunk call.
				emitNonAskingTool("MEDITSEED", "Write",
					map[string]any{"file_path": "/work/cov-medit.txt", "content": "ALPHA-SEED\nBETA-SEED\n"}, "File created")
			case "Task":
				// The Task spawn tool_use + its task_started (→ subagent.spawned) BEFORE
				// the in-subagent asking tool, so the spawn node exists to parent under.
				emit(map[string]any{
					"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nil,
					"message": map[string]any{"id": fmt.Sprintf("msg_cov_spawn_%d", turn), "type": "message", "role": "assistant",
						"model": "claude-sonnet-4-6", "stop_reason": "tool_use",
						"content": []any{
							map[string]any{"type": "text", "text": "Dispatching a subagent to write the task proof."},
							map[string]any{"type": "tool_use", "id": spawnToolID(turn),
								"name": "Task", "input": map[string]any{"description": "write task proof",
									"subagent_type": "general-purpose", "prompt": "write /work/cov-task.txt"}},
						}},
				})
				emit(map[string]any{
					"type": "system", "subtype": "task_started", "session_id": session, "uuid": nextUUID(),
					"task_id": taskID(turn), "tool_use_id": spawnToolID(turn),
					"task_type": "local_agent", "subagent_type": "general-purpose",
					"description": "write task proof", "prompt": "write /work/cov-task.txt",
				})
				// The asking tool runs INSIDE the subagent: its assistant line is parented
				// by the spawn node, so its tool.invoked correlates under the subagent.
				nestedParent = spawnToolID(turn)
			}

			// The turn's ASKING tool: an assistant tool_use + a held can_use_tool
			// control_request the host must answer (HELD — no tool_result until the
			// control_response arrives, DRIVE-FINDINGS §1a socket-hold). On the
			// pre-tool turns (TodoWrite/Glob/Grep) the asking tool is the Bash token
			// write; the deny/error/task turns each carry their own asking shape.
			askedTool := "Bash"
			askedInput := map[string]any{"reason": "coverage " + tool}
			switch tool {
			case "Bash":
				askedInput = map[string]any{"command": "printf '%s' 'COV-BASH-9X4T' > /work/cov-bash.txt"}
			case "Write":
				askedTool = "Write"
				askedInput = map[string]any{"file_path": "/work/cov-write.txt", "content": "COV-WRITE-9X4T"}
			case "Edit":
				askedTool = "Edit"
				askedInput = map[string]any{"file_path": "/work/cov-write.txt", "old_string": "COV-WRITE-9X4T", "new_string": "COV-WRITE-9X4T\nCOV-EDIT-9X4T"}
			case "TodoWrite":
				askedInput = map[string]any{"command": "printf '%s' 'COV-PLAN-9X4T' > /work/cov-plan.txt"}
			case "Glob":
				askedInput = map[string]any{"command": "printf '%s' 'COV-GLOB-9X4T' > /work/cov-glob.txt"}
			case "Grep":
				askedInput = map[string]any{"command": "printf '%s' 'COV-GREP-9X4T' > /work/cov-grep.txt"}
			case "GrepDeny":
				askedTool = "Grep"
				askedInput = map[string]any{"pattern": "COV-WRITE-9X4T", "path": "/work"}
			case "BashErr":
				askedInput = map[string]any{"command": "cat /work/this-path-does-not-exist-COV-ERR-9X4T.txt"}
			case "Task":
				askedInput = map[string]any{"command": "printf '%s' 'COV-TASK-9X4T' > /work/cov-task.txt"}
			case "MultiEdit":
				// One MultiEdit call carrying a TWO-hunk edits[] — two old_string→new_string
				// pairs applied atomically (the multi-hunk shape the live prompt forces).
				askedTool = "MultiEdit"
				askedInput = map[string]any{"file_path": "/work/cov-medit.txt", "edits": []any{
					map[string]any{"old_string": "ALPHA-SEED", "new_string": "COV-MEDIT-A-9X4T"},
					map[string]any{"old_string": "BETA-SEED", "new_string": "COV-MEDIT-B-9X4T"},
				}}
			}
			emit(map[string]any{
				"type": "assistant", "session_id": session, "uuid": nextUUID(), "parent_tool_use_id": nestedParent,
				"message": map[string]any{"id": fmt.Sprintf("msg_cov_pre_%d", turn), "type": "message", "role": "assistant",
					"model": "claude-sonnet-4-6", "stop_reason": "tool_use",
					"content": []any{
						map[string]any{"type": "text", "text": fmt.Sprintf("On it — using the %s tool.", askedTool)},
						map[string]any{"type": "tool_use", "id": toolID(turn),
							"name": askedTool, "input": askedInput},
					}},
			})
			emit(map[string]any{
				"type": "control_request", "request_id": reqID(turn),
				"request": map[string]any{"subtype": "can_use_tool", "tool_name": askedTool,
					"display_name": askedTool,
					"input":        askedInput,
					"tool_use_id":  toolID(turn),
				},
			})
			// HOLD: the tool_result waits for the host's control_response (above).
		}
	}
	out.Flush()
}

// referenced so a refactor that drops a usage still compiles cleanly.
var (
	_ = errors.New
	_ = attach.TypeAskResolved
)
