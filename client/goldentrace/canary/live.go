// live.go — the LIVE CC-latest leg of the canary, DS_E2E_LIVE-gated and
// DOCUMENTED as the deferred operator/scheduled step. Nothing here launches in
// the fleet: the only live gate is DS_E2E_LIVE, which this package never sets,
// and with it unset DriftAgainstLatest returns ErrLiveGateUnset without touching
// claude/ds-capture/podman.
//
// FIRST-PARTY ONLY (CAPTURE-TOOL-DESIGN.md §3/§5 step 3). The canary live lane is
// built first-party and is NEVER wired to the external `../cia`: the operator
// captures CC-latest through the first-party `ds-capture record` egress gateway
// (the free :18099, never the protected :18080 monitor) and the cc_sandbox.sh
// planner; this package only ever CONSUMES the resulting raw stdout the operator
// points DS_CANARY_RAW_* at. There is no cia binary anywhere on this path.
//
// WHAT THE LIVE LEG IS (the nightly canary's reason to exist, D49). The golden
// IMAGE pins the production CC version (CC 2.1.173, e2e/README.md G5); the
// canary is the ONE tier that intentionally faces CC-LATEST. The operator
// captures a CC-latest stdout stream — through `ds-capture record` and the
// cc_sandbox.sh/pasta recipe — projects it through the SAME adapter,
// canonicalizes, and diffs against the committed canon goldens this package
// regenerates offline. A divergence is unreviewed drift → a SCHEDULED REVIEW
// TASK, not a production incident.
//
// THE DEFERRED OPERATOR STEP (the runbook, all gated; the operator runs it, the
// fleet never does):
//
//  1. Build/refresh the pinned-LATEST sandbox image and capture CC-latest stdout
//     for each canary scenario, recording the API plane in parallel with the
//     first-party tool:
//
//     DS_E2E_LIVE=1 ds-capture record --port 18099 \
//     --cassette <jobdir>/canary-baseline.api.json
//     # drive CC-latest (canary-baseline scenario) through the cc_sandbox.sh
//     # plan, egress via the capture tool's :18099 egress gateway (a FREE port +
//     # private socket — coexisting with the protected :18080 monitor, never
//     # binding it; HARDENING-NOTES §2). Tee CC stdout to <jobdir>. The raw
//     # stdout + API cassette are RAW-CLASS: they stay under <jobdir>, NEVER
//     # committed (D50).
//
//  2. Point the canary at the raw capture(s) and run the live drift check:
//
//     DS_E2E_LIVE=1 \
//     DS_CANARY_RAW_BASELINE=<jobdir>/canary-baseline.ndjson \
//     go run ./goldentrace/canary/cmd/canary live
//
//     It projects each raw live capture → canon and diffs it against the
//     committed canon golden. A divergence is a STALE cassette or genuine CC
//     DRIFT; the ds-capture API-plane cassette tells which (DRIVE-PROTOCOL.md).
//
//  3. The pre-flight ALWAYS runs first (canary.go RunOffline → RunPreflight), so
//     even an armed live run aborts with OutcomeMachineryBlind if a detector is
//     neutered — a blind detector never reaches the live verdict.
package canary

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LiveGateEnv is the single documented live gate (DS_E2E_LIVE=1), shared with
// the e2e harness and cc_sandbox.sh. Unset ⇒ nothing live launches.
const LiveGateEnv = "DS_E2E_LIVE"

// ErrLiveGateUnset is returned by DriftAgainstLatest when DS_E2E_LIVE != "1".
// It is the canary's half of the single-gate story: the live capture is opt-in
// and the deferred operator step; a caller without the gate gets a clear signal,
// never a silent no-op and never an accidental launch. Tests assert on this
// without ever capturing.
var ErrLiveGateUnset = errors.New("canary: DS_E2E_LIVE != 1; the live CC-latest leg is gated " +
	"(set DS_E2E_LIVE=1 to arm; this is the deferred operator/scheduled step — see live.go runbook)")

// LiveScenario names one canary scenario whose CC-latest capture is diffed
// against the committed canon golden. RawEnv is the env var the operator points
// at the raw live capture their armed run produced (raw-class, under the job
// dir, never committed); Golden is the committed canon-golden base name.
type LiveScenario struct {
	Name   string
	RawEnv string // e.g. DS_CANARY_RAW_BASELINE
	Golden string // base name under testdata/ (== the cassette base name)
}

// liveScenarios maps the canary's scenarios to their raw-capture env + golden.
// They mirror the capture.sh scripted scenario set (canary-* scenarios) and the
// committed cassettes the always-on lane regenerates.
var liveScenarios = []LiveScenario{
	{Name: "baseline", RawEnv: "DS_CANARY_RAW_BASELINE", Golden: "baseline-chat"},
	{Name: "ask-control", RawEnv: "DS_CANARY_RAW_ASK_CONTROL", Golden: "ask-control"},
	{Name: "subagent", RawEnv: "DS_CANARY_RAW_SUBAGENT", Golden: "nested-spawn"},
}

// LiveGateArmed reports whether the single documented live gate is set. Unset is
// the default and every CI / fleet run — nothing live is ever launched.
func LiveGateArmed() bool { return os.Getenv(LiveGateEnv) == "1" }

// DriftAgainstLatest is the live tier entry point. GATED: with DS_E2E_LIVE unset
// it returns ErrLiveGateUnset and captures NOTHING — no claude, no ds-capture, no
// podman. Armed, it projects each operator-provided raw CC-latest capture → canon
// and diffs it against the committed canon golden, returning the per-scenario
// drift results. It NEVER captures itself: the capture is the deferred
// ds-capture/cc_sandbox/pasta operator step (the runbook above); this only
// consumes the raw stdout the operator points DS_CANARY_RAW_* at.
//
// l locates the committed canon goldens. A scenario whose raw env is unset is
// skipped (reported), so an operator can arm one scenario at a time.
func DriftAgainstLatest(l Layout) (results []RegenResult, drifts int, err error) {
	if !LiveGateArmed() {
		return nil, 0, ErrLiveGateUnset
	}

	// Belt-and-suspenders: refuse a raw path that points inside the protected
	// monitor's home (~/.cia). The first-party ds-capture records to a PRIVATE
	// job dir on the free :18099 — never the shared monitor — but we re-assert it
	// here so an operator mis-pointing us never reads from the protected monitor.
	home := os.Getenv("HOME")
	for _, s := range liveScenarios {
		raw := os.Getenv(s.RawEnv)
		if raw == "" {
			results = append(results, RegenResult{
				Cassette: s.Name,
				Golden:   l.goldenPath(s.Golden + cassetteSuffix),
				Status:   "skipped",
				Report:   fmt.Sprintf("%s unset — arm this scenario by pointing it at the raw CC-latest capture (raw-class, under the job dir)", s.RawEnv),
			})
			continue
		}
		if home != "" && strings.HasPrefix(filepath.Clean(raw), filepath.Join(home, ".cia")) {
			return results, drifts, fmt.Errorf("canary: %s points inside ~/.cia (the protected "+
				"monitor home) — point it at a PRIVATE job-dir raw capture, never the shared monitor", s.RawEnv)
		}

		got, perr := CassetteCanon(raw)
		if perr != nil {
			results = append(results, RegenResult{Cassette: s.Name, Golden: s.Golden, Status: "error", Report: perr.Error()})
			drifts++
			continue
		}
		goldenPath := l.goldenPath(s.Golden + cassetteSuffix)
		want, rerr := os.ReadFile(goldenPath)
		if rerr != nil {
			results = append(results, RegenResult{Cassette: s.Name, Golden: goldenPath, Status: "error", Report: rerr.Error()})
			drifts++
			continue
		}
		r := RegenResult{Cassette: s.Name, Golden: goldenPath}
		if string(want) == string(got) {
			r.Status = "ok"
		} else {
			r.Status = "drift"
			r.Report = reviewableDiff(goldenPath, want, []byte(got))
			drifts++
		}
		results = append(results, r)
	}
	return results, drifts, nil
}
