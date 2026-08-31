// canary.go — the lane orchestrator: PRE-FLIGHT first, then the real drift
// check, with the live CC-latest leg gated and never run in the fleet.
//
// THE ORDER IS LOAD-BEARING (taskdb 01KTXRJ2RQ). The canary FIRST proves the
// detectors catch planted drift (RunPreflight: the in-process probe + the owned
// perturbation self-tests) and ONLY THEN runs the real drift check
// (Regenerate). A canary whose detector is broken fails LOUDLY with
// OutcomeMachineryBlind — a DISTINCT outcome from OutcomeDriftDetected — never
// passes vacuously. A neutered detector fails the lane.
//
// THE TWO HALVES:
//   - ALWAYS-ON (RunOffline): pre-flight + offline regen against the committed
//     cassettes. Hermetic, fleet-safe, no gate. This is what CI and the nightly
//     workflow's always-on lane run.
//   - LIVE (live.go, DS_E2E_LIVE-gated): the deferred operator step that
//     captures CC-LATEST and diffs its projection against the committed canon
//     goldens. NEVER run by this package's tests or the fleet; the only live
//     gate is DS_E2E_LIVE, which this code never sets.
package canary

import (
	"context"
	"fmt"
	"io"
)

// LaneResult is the canary lane's outcome.
type LaneResult struct {
	Outcome Outcome
	// Drifts is the number of cassettes whose regenerated canon diverged from
	// the committed golden (0 on a faithful run).
	Drifts int
	// Err carries the failure detail (a machineryBlindError on a blind
	// pre-flight, a regen error otherwise). Nil on OutcomeFaithful.
	Err error
}

// RunOffline is the always-on lane: pre-flight, then the offline regen/drift
// check against the committed cassettes. It NEVER touches claude/ds-capture/podman and
// needs no gate. repoRoot is the client module root (for the subprocess
// self-tests); pass "" to skip the subprocess layer and rely on the in-process
// probe alone (the package's own tests do this to avoid recursing into a
// `go test` of themselves).
//
// The contract the acceptance criteria pin:
//   - a NEUTERED detector ⇒ OutcomeMachineryBlind (the lane fails before it
//     would ever report "no drift"), distinct from a real drift;
//   - detectors bite + a regen diff ⇒ OutcomeDriftDetected (a reviewable diff,
//     queued review per D49);
//   - detectors bite + clean regen ⇒ OutcomeFaithful.
func RunOffline(ctx context.Context, l Layout, repoRoot string, w io.Writer) LaneResult {
	reportf := func(s string) { fmt.Fprintln(w, s) }

	// 1. PRE-FLIGHT — prove the detectors bite BEFORE trusting any verdict.
	fmt.Fprintln(w, "=== canary pre-flight: detection-machinery self-check ===")
	if err := RunPreflight(ctx, l, repoRoot, reportf); err != nil {
		fmt.Fprintf(w, "\nCANARY ABORTED — %s\n", OutcomeMachineryBlind)
		fmt.Fprintln(w, err.Error())
		fmt.Fprintln(w, "\nThe canary's drift verdict is NOT trustworthy until the detection "+
			"machinery is fixed. This is a DISTINCT failure from a CC drift — fix the "+
			"detector, do not review a drift diff.")
		return LaneResult{Outcome: OutcomeMachineryBlind, Err: err}
	}

	// 2. REAL DRIFT CHECK — offline regen against committed cassettes.
	fmt.Fprintln(w, "\n=== canary drift check: regen vs committed canon goldens (offline) ===")
	results, drifts, err := Regenerate(l, false /* compare, never rewrite */)
	if err != nil {
		fmt.Fprintf(w, "canary regen error: %v\n", err)
		return LaneResult{Outcome: OutcomeDriftDetected, Drifts: drifts, Err: err}
	}
	WriteReport(w, results, drifts)
	if drifts > 0 {
		fmt.Fprintf(w, "\nCANARY: %s — %d cassette(s) diverged. On the always-on lane this is a "+
			"STALE cassette to re-author; on the live CC-latest tier it is queued CC drift to "+
			"review (D49, not a production incident).\n", OutcomeDriftDetected, drifts)
		return LaneResult{Outcome: OutcomeDriftDetected, Drifts: drifts}
	}
	fmt.Fprintf(w, "\nCANARY: %s — detectors bite AND every cassette projects to its committed "+
		"canon golden.\n", OutcomeFaithful)
	return LaneResult{Outcome: OutcomeFaithful}
}
