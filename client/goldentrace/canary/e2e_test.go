// e2e_test.go — the OFFLINE end-to-end stitch of the capture→scrub→gate→diff
// loop, never launching claude/cia/podman.
//
// The landed canary proves each STAGE in isolation: the scrub pass in
// capture.sh (capture.sh --scrub), EnforceProvenanceGate in provenance.go,
// DriftAgainstLatest in live.go, and Regenerate/reviewableDiff in regen.go. What
// had no always-on coverage is the STITCH BETWEEN them: that a synthetic
// CC-latest raw capture, run through the REAL capture.sh scrub subprocess, then
// the REAL provenance gate, then the REAL live drift check, closes the loop end
// to end. This file is that hermetic offline e2e.
//
// The loop under test (taskdb 01KTY1BNGHD4CJ3CE0RVZ1XH82):
//
//	synthetic CC-latest raw capture  (t.TempDir(), planted raw-class markers
//	   │                              + a token-SHAPED non-secret Bearer value
//	   │                              + a DELIBERATE protocol drift in the mutant)
//	   ├─ capture.sh --scrub ─────▶  candidate (auth→"Bearer ds_fixture",
//	   │   (os/exec, the ONLY        session_id/uuid/cwd/total_cost_usd→synthetic,
//	   │    subprocess this test     ds_fixture synthetic header prepended)
//	   │    ever launches)
//	   ├─ EnforceProvenanceGate ──▶  the SCRUBBED candidate PASSES; the UNSCRUBBED
//	   │                              raw FAILS (the gate blocks an unscrubbed
//	   │                              artifact — the negative leg)
//	   └─ DriftAgainstLatest ─────▶  armed in-process via t.Setenv(LiveGateEnv=1)
//	       (live.go, gated)          + t.Setenv(DS_CANARY_RAW_BASELINE,candidate):
//	                                 NO-DRIFT for the faithful scrubbed capture,
//	                                 drifts>0 with a reviewable diff for the mutant.
//
// HERMETIC + FLEET-SAFE. The armed env is t.Setenv (test-process-scoped only);
// DriftAgainstLatest reads files and launches nothing (asserted: the only
// subprocess the whole loop spawns is the capture.sh scrub). Every write lands
// in t.TempDir() — no committed canon golden and no capture.sh is touched. If
// there is no POSIX shell to run capture.sh, the loop skips with a reason
// (capture.sh is invoked, never re-implemented).
package canary

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// captureScript is capture.sh's path relative to this package's test cwd
// (goldentrace/canary). The test INVOKES it; it never edits or re-implements the
// scrub (DO-NOT-EDIT-capture.sh discipline, taskdb 01KTY1BNGHD4CJ3CE0RVZ1XH82).
const captureScript = "../capture.sh"

// committedBaselineCassette is the committed synthetic cassette this test's
// synthetic raw capture is DERIVED from, relative to the package test cwd. It is
// read-only here — the raw is authored into t.TempDir(), never written back.
const committedBaselineCassette = "../../fixtures/baseline-chat.cc-wire.ndjson"

// rawMarkerSessionID is a real-LOOKING session UUID planted in the raw capture
// (a CC-minted v4 shape, NOT one of the cassette's all-zero synthetic ids). The
// scrub rewrites session_id by key, so this must not survive into the candidate.
const rawMarkerSessionID = "7c9e6679-7425-40de-944b-e07fc1f90ae7"

// rawMarkerCWD is a real-LOOKING absolute cwd planted in the raw init record.
// The scrub rewrites cwd→"/work"; the marker must not survive.
const rawMarkerCWD = "/home/realuser/projects/secret-thing"

// rawBearerToken is a token-SHAPED value that is NOT a real secret: a fixed
// synthetic string assembled to be >= the gate's 40-char Bearer threshold so the
// UNSCRUBBED raw trips EnforceProvenanceGate's Bearer value scan, while carrying
// no usable credential. The scrub collapses the whole header value to the short
// "Bearer ds_fixture" (16 chars, below the threshold), so the candidate passes.
// Assembled from harmless pieces so this SOURCE file never carries a literal a
// secret scanner would flag (the provenance_test.go tokenBody discipline).
func rawBearerToken() string {
	// "ds_fake_capture_NOTASECRET_" + 40 'A's ⇒ 67 token chars (>= 40).
	return "ds_fake_capture_" + "NOTASECRET_" + strings.Repeat("A", 40)
}

// synthRawCapture authors a synthetic "CC-latest raw capture" into dir, mirroring
// the committed baseline-chat event sequence (init, status, assistant-thinking,
// assistant-text, rate_limit, result) but with RAW-CLASS markers planted in
// EXACTLY the fields capture.sh scrub_pass rewrites: a token-shaped Bearer value
// in an authorization header, a real-looking session_id on every record, distinct
// real-looking uuids, a real cwd, and a non-zero total_cost_usd. With drift=true
// it also plants a DELIBERATE protocol drift (a hand-written divergence vs the
// pinned shape, D50): the assistant text block carries a different payload, so the
// mutant's id-relative canon diverges from the faithful one on a nameable line.
//
// It returns the raw file path. No git tree is touched — dir is the caller's
// t.TempDir().
func synthRawCapture(t *testing.T, dir string, drift bool) string {
	t.Helper()
	bearer := "Bearer " + rawBearerToken()
	sid := rawMarkerSessionID

	assistantText := "Hello! How can I help you today?"
	if drift {
		// The planted protocol drift: a hand-written payload divergence vs the
		// pinned shape. It survives the scrub (scrub touches only auth/correlatable
		// keys, never message text), so the mutant's canon differs from the
		// faithful golden at the assistant chat.message event.
		assistantText = "Hello! I am a DRIFTED CC-latest response — protocol shape changed."
	}

	// Each line is one CC stream-json record. The init record carries the planted
	// authorization header (the raw-class secret-shaped marker) + the real cwd; the
	// result carries a non-zero total_cost_usd. Every record carries the real sid
	// and a distinct real-looking uuid — all fields the scrub rewrites by key.
	lines := []string{
		`{"type":"system","subtype":"init","session_id":"` + sid + `","uuid":"a1b2c3d4-0000-4000-8000-000000000001","cwd":"` + rawMarkerCWD + `","claude_code_version":"2.1.173","model":"claude-sonnet-4-6","permissionMode":"bypassPermissions","apiKeySource":"none","output_style":"default","fast_mode_state":"off","tools":["Task","Bash"],"agents":["claude","Explore","general-purpose","Plan","statusline-setup"],"slash_commands":[],"skills":[],"plugins":[],"mcp_servers":[],"memory_paths":{"auto":"/home/realuser/.memory/"},"analytics_disabled":false,"product_feedback_disabled":false,"headers":{"authorization":"` + bearer + `"}}`,
		`{"type":"system","subtype":"status","status":"requesting","uuid":"a1b2c3d4-0000-4000-8000-000000000002","session_id":"` + sid + `"}`,
		`{"type":"assistant","session_id":"` + sid + `","uuid":"a1b2c3d4-0000-4000-8000-000000000003","parent_tool_use_id":null,"request_id":"req_real_capture_0001","message":{"id":"msg_real_capture_0001","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"thinking","thinking":"The user just said hello. I will answer briefly.","signature":"REALSIG"}],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":900,"output_tokens":18}}}`,
		`{"type":"assistant","session_id":"` + sid + `","uuid":"a1b2c3d4-0000-4000-8000-000000000004","parent_tool_use_id":null,"request_id":"req_real_capture_0001","message":{"id":"msg_real_capture_0001","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[{"type":"text","text":"` + assistantText + `"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":900,"output_tokens":29}}}`,
		`{"type":"rate_limit_event","session_id":"` + sid + `","uuid":"a1b2c3d4-0000-4000-8000-000000000005","rate_limit_info":{"rateLimitType":"five_hour","status":"allowed","resetsAt":1893456000,"isUsingOverage":false,"overageStatus":"not_in_overage","overageDisabledReason":""}}`,
		`{"type":"result","subtype":"success","session_id":"` + sid + `","uuid":"a1b2c3d4-0000-4000-8000-000000000006","is_error":false,"num_turns":1,"stop_reason":"end_turn","terminal_reason":"completed","result":"` + assistantText + `","total_cost_usd":0.0123,"duration_ms":2100,"duration_api_ms":1850,"ttft_ms":420,"ttft_stream_ms":410,"time_to_request_ms":12,"api_error_status":null,"permission_denials":[],"usage":{"input_tokens":900,"output_tokens":47,"cache_creation_input_tokens":0,"cache_read_input_tokens":0},"modelUsage":{"claude-sonnet-4-6":{"inputTokens":900,"outputTokens":47,"cacheReadInputTokens":0,"cacheCreationInputTokens":0,"costUSD":0,"contextWindow":200000}}}`,
	}

	name := "cc-latest-raw.ndjson"
	if drift {
		name = "cc-latest-raw-drift.ndjson"
	}
	raw := filepath.Join(dir, name)
	if err := os.WriteFile(raw, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write synthetic raw capture: %v", err)
	}
	return raw
}

// posixShell finds a POSIX shell to run capture.sh, or "" if none. capture.sh is
// a bash script (set -euo pipefail), so bash is preferred; sh is the documented
// fallback. The whole offline loop skips-with-reason when none is present — it
// invokes the real scrub, never a Go re-implementation of it.
func posixShell(t *testing.T) string {
	t.Helper()
	for _, sh := range []string{"bash", "sh"} {
		if p, err := exec.LookPath(sh); err == nil {
			return p
		}
	}
	return ""
}

// runScrub invokes `capture.sh --scrub <raw> <candidate>` via os/exec — the REAL
// D50 scrub pass, offline shell+jq with the sed fallback the script already
// carries. It returns the candidate's bytes. The candidate is written under dir
// (t.TempDir()), never a git tree; the script itself refuses a candidate under
// fixtures/. This is the ONLY subprocess the offline loop launches — no claude,
// no cia, no podman.
func runScrub(t *testing.T, shell, dir, raw string) (candidatePath string, content []byte) {
	t.Helper()
	candidatePath = filepath.Join(dir, "candidate.cc-wire.ndjson")
	cmd := exec.Command(shell, captureScript, "--scrub", raw, candidatePath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("capture.sh --scrub failed: %v\n%s", err, out)
	}
	content, rerr := os.ReadFile(candidatePath)
	if rerr != nil {
		t.Fatalf("read scrubbed candidate %s: %v", candidatePath, rerr)
	}
	return candidatePath, content
}

// TestOfflineCaptureScrubGateDriftLoop is the offline end-to-end stitch:
// synthetic CC-latest raw → capture.sh --scrub → EnforceProvenanceGate (scrubbed
// PASSES, raw FAILS) → DriftAgainstLatest (no-drift faithful, drift mutant). It
// launches ONLY the capture.sh scrub subprocess; nothing else (no
// claude/cia/podman). Every write is under t.TempDir(); no committed golden or
// capture.sh is modified.
func TestOfflineCaptureScrubGateDriftLoop(t *testing.T) {
	shell := posixShell(t)
	if shell == "" {
		t.Skip("no POSIX shell (bash/sh) on PATH — the offline loop invokes capture.sh --scrub " +
			"and cannot run without one; this is the documented skip-with-reason, not a failure")
	}
	// Sanity: the script we are about to invoke exists where we expect it (so a
	// missing/renamed capture.sh is a clear failure, not a confusing exec error).
	if _, err := os.Stat(captureScript); err != nil {
		t.Fatalf("capture.sh not found at %s (invoked, never edited): %v", captureScript, err)
	}

	dir := t.TempDir()

	// ── STAGE 1: synthesize a CC-latest raw capture with planted raw-class markers.
	raw := synthRawCapture(t, dir, false /* faithful, no protocol drift */)
	rawContent, err := os.ReadFile(raw)
	if err != nil {
		t.Fatalf("read raw capture: %v", err)
	}

	// ── STAGE 2: the UNSCRUBBED raw FAILS the provenance gate (the negative leg —
	// the gate blocks an unscrubbed artifact). It must fail on the token-shaped
	// Bearer value AND on the missing synthetic header (the raw has neither a
	// ds_fixture header nor a scrubbed auth value).
	rawVerdict := EnforceProvenanceGate(filepath.Join(dir, "raw-as-candidate.cc-wire.ndjson"), rawContent)
	if rawVerdict.OK {
		t.Fatal("the UNSCRUBBED raw capture PASSED the provenance gate — the gate must block an " +
			"unscrubbed artifact (it carries a token-shaped Bearer value and no synthetic header)")
	}
	if !violationContains(rawVerdict, "secret leak") {
		t.Errorf("the gate did not flag the planted token-shaped Bearer value on the raw capture; "+
			"violations: %v", rawVerdict.Violations)
	}
	if !violationContains(rawVerdict, "header") {
		t.Errorf("the gate did not flag the missing synthetic header on the raw capture; "+
			"violations: %v", rawVerdict.Violations)
	}

	// ── STAGE 2b: run the REAL capture.sh --scrub pass (the only subprocess).
	candidatePath, candidate := runScrub(t, shell, dir, raw)

	// The scrub must have neutralized the planted markers: the raw-class session id,
	// cwd, and token-shaped Bearer value must NOT survive into the candidate (a
	// belt-and-suspenders re-assert of the scrub contract before the gate).
	if strings.Contains(string(candidate), rawMarkerSessionID) {
		t.Errorf("scrub left the raw-class session id in the candidate — scrub_pass did not rewrite session_id")
	}
	if strings.Contains(string(candidate), rawMarkerCWD) {
		t.Errorf("scrub left the raw-class cwd in the candidate — scrub_pass did not rewrite cwd")
	}
	if strings.Contains(string(candidate), rawBearerToken()) {
		t.Errorf("scrub left the token-shaped Bearer value in the candidate — scrub_pass did not rewrite authorization")
	}

	// ── STAGE 3: the SCRUBBED candidate PASSES the provenance gate. Gate the
	// candidate at its REAL path (not an empty path) so all three D50 checks run —
	// the synthetic header, the no-token-value scan, AND the raw-tree check. The
	// candidate lives under t.TempDir() (not a recognized raw-tree marker), so a
	// clean pass proves the content AND the path clear the wall, the full gate
	// rather than a content-only subset.
	candVerdict := EnforceProvenanceGate(candidatePath, candidate)
	if !candVerdict.OK {
		t.Fatalf("the SCRUBBED candidate was BLOCKED by the provenance gate — the scrub→gate "+
			"stitch is broken; violations: %v", candVerdict.Violations)
	}

	// ── STAGE 4 + 5: arm the live leg IN-PROCESS (t.Setenv, test-scoped only) and
	// run DriftAgainstLatest. The golden dir is a t.TempDir() seeded with the canon
	// of the FAITHFUL scrubbed candidate — that is the committed-canon-golden role,
	// authored the same way the operator's committed golden was, without touching
	// any file under the real testdata/. DriftAgainstLatest reads files and
	// launches nothing.
	t.Setenv(LiveGateEnv, "1")
	if !LiveGateArmed() {
		t.Fatal("t.Setenv(DS_E2E_LIVE=1) did not arm the live gate in-process")
	}

	goldenDir := t.TempDir()
	faithfulCanon, err := CassetteCanon(candidatePath)
	if err != nil {
		t.Fatalf("canonize the faithful scrubbed candidate: %v", err)
	}
	// The golden the live drift check diffs against: the canon of the faithful
	// scrubbed capture, written under a TempDir golden dir (NEVER the committed
	// testdata/). baseline-chat is the golden base the baseline live scenario maps to.
	if err := os.WriteFile(filepath.Join(goldenDir, "baseline-chat"+canonGoldenSuffix), faithfulCanon, 0o644); err != nil {
		t.Fatalf("seed temp golden: %v", err)
	}
	layout := Layout{
		FixturesGlob: pkgLayout().FixturesGlob, // unused by DriftAgainstLatest; kept consistent
		GoldenDir:    goldenDir,
	}

	// ── STAGE 4: the FAITHFUL scrubbed capture canonizes equal to the (TempDir)
	// committed canon golden ⇒ NO drift on the armed live leg.
	t.Setenv("DS_CANARY_RAW_BASELINE", candidatePath)
	results, drifts, err := DriftAgainstLatest(layout)
	if err != nil {
		t.Fatalf("DriftAgainstLatest (faithful) errored: %v", err)
	}
	if drifts != 0 {
		t.Fatalf("the FAITHFUL scrubbed capture reported %d drift against its canon golden — "+
			"the capture→scrub→canon stitch is not faithful:\n%s", drifts, renderResults(results))
	}
	if !baselineStatusIs(results, "ok") {
		t.Errorf("baseline live scenario status was not ok for the faithful capture:\n%s",
			renderResults(results))
	}

	// ── STAGE 5: a MUTATED candidate (the planted protocol drift) ⇒ drifts>0 with
	// a REVIEWABLE diff naming the divergent line. The same TempDir golden (the
	// faithful canon) is the baseline; the mutant diverges on the assistant
	// chat.message event.
	mutantRaw := synthRawCapture(t, dir, true /* plant the protocol drift */)
	mutantPath, _ := runScrub(t, shell, t.TempDir(), mutantRaw)
	t.Setenv("DS_CANARY_RAW_BASELINE", mutantPath)
	mResults, mDrifts, err := DriftAgainstLatest(layout)
	if err != nil {
		t.Fatalf("DriftAgainstLatest (mutant) errored: %v", err)
	}
	if mDrifts == 0 {
		t.Fatalf("the MUTATED (protocol-drift) capture reported NO drift — the live drift check is "+
			"vacuous; it must catch the planted divergence:\n%s", renderResults(mResults))
	}
	report := baselineReport(mResults)
	if report == "" {
		t.Fatal("the mutant drift produced no per-scenario report — a catch must be reviewable")
	}
	// The reviewable diff must name the divergence (the regen.reviewableDiff shape)
	// and point at the drifted assistant payload so an operator sees a pinpoint.
	for _, marker := range []string{"DIVERGES", "first diff"} {
		if !strings.Contains(report, marker) {
			t.Errorf("the mutant drift report is not reviewable — missing %q:\n%s", marker, report)
		}
	}
	if !strings.Contains(report, "DRIFTED") {
		t.Errorf("the reviewable diff did not name the divergent (drifted) line:\n%s", report)
	}
}

// TestLiveDriftLaunchesNoSubprocess concretely asserts the loop's hermetic
// claim: the live drift leg (DriftAgainstLatest) reads files and launches
// NOTHING — no claude, no cia, no podman. It arms the gate in-process (t.Setenv,
// test-scoped) over a TempDir golden, then runs DriftAgainstLatest with PATH
// EMPTIED: if the live leg tried to exec any binary it would fail loudly on the
// stripped PATH, so a clean no-drift verdict is proof it spawned no subprocess.
// (The scrub subprocess — the ONE the loop is allowed — is intentionally NOT in
// this path; it ran earlier in the full loop. This test isolates the live leg.)
func TestLiveDriftLaunchesNoSubprocess(t *testing.T) {
	dir := t.TempDir()
	// Author a faithful synthetic capture directly as a scrubbed-shaped candidate:
	// the live leg only needs a projectable cassette with a synthetic header, which
	// CassetteCanon/ProjectFile read with no subprocess. We reuse the scrub-output
	// shape by writing the synthetic header + faithful body (no shell needed here —
	// this test deliberately removes PATH, so it must not depend on a subprocess).
	candidate := filepath.Join(dir, "faithful.cc-wire.ndjson")
	body := syntheticHeader + "\n" +
		`{"type":"system","subtype":"init","session_id":"f24b8a07-0000-0000-0000-000000000001","uuid":"00000000-0000-4000-8000-0000000000b0","cwd":"/work","claude_code_version":"2.1.173","model":"claude-sonnet-4-6","permissionMode":"bypassPermissions","apiKeySource":"none","output_style":"default","fast_mode_state":"off","tools":["Task","Bash"],"agents":["claude","Explore","general-purpose","Plan","statusline-setup"],"slash_commands":[],"skills":[],"plugins":[],"mcp_servers":[],"memory_paths":{"auto":"/work/.memory/"},"analytics_disabled":false,"product_feedback_disabled":false}` + "\n"
	if err := os.WriteFile(candidate, []byte(body), 0o644); err != nil {
		t.Fatalf("write faithful candidate: %v", err)
	}
	goldenDir := t.TempDir()
	canon, err := CassetteCanon(candidate)
	if err != nil {
		t.Fatalf("canonize candidate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goldenDir, "baseline-chat"+canonGoldenSuffix), canon, 0o644); err != nil {
		t.Fatalf("seed golden: %v", err)
	}

	t.Setenv(LiveGateEnv, "1")
	t.Setenv("DS_CANARY_RAW_BASELINE", candidate)
	// Empty PATH: any os/exec.Command(...).Run inside the live leg would now fail
	// with exec.ErrNotFound. A clean run proves the leg launches no subprocess.
	t.Setenv("PATH", "")

	results, drifts, err := DriftAgainstLatest(Layout{GoldenDir: goldenDir})
	if err != nil {
		t.Fatalf("DriftAgainstLatest errored with PATH emptied — the live leg must read files and "+
			"launch nothing, but it failed: %v", err)
	}
	if drifts != 0 {
		t.Fatalf("the faithful candidate drifted against its own canon (%d) — the no-subprocess "+
			"live leg is not faithful:\n%s", drifts, renderResults(results))
	}
}

// violationContains reports whether any gate violation mentions substr.
func violationContains(r ProvenanceResult, substr string) bool {
	for _, v := range r.Violations {
		if strings.Contains(v, substr) {
			return true
		}
	}
	return false
}

// baselineStatusIs reports whether the baseline live scenario's result has the
// given status (the other scenarios are skipped — their raw env is unset).
func baselineStatusIs(results []RegenResult, status string) bool {
	for _, r := range results {
		if r.Cassette == "baseline" {
			return r.Status == status
		}
	}
	return false
}

// baselineReport returns the baseline scenario's reviewable diff report.
func baselineReport(results []RegenResult) string {
	for _, r := range results {
		if r.Cassette == "baseline" {
			return r.Report
		}
	}
	return ""
}

// renderResults is a compact dump of the live drift results for failure messages.
func renderResults(results []RegenResult) string {
	var sb strings.Builder
	for _, r := range results {
		sb.WriteString(r.Cassette)
		sb.WriteString(": ")
		sb.WriteString(r.Status)
		if r.Report != "" {
			sb.WriteString("\n")
			sb.WriteString(r.Report)
		}
		sb.WriteString("\n")
	}
	return sb.String()
}
