// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"time"
)

// cmd_bench.go is the doc-27 Lever-0 wavebench READ surface — the slice that
// retroactively ties Lever 3 (the serialized landing queue) back to Lever 0
// (the CONFLICT-LOSS metric). doc 27 §6 defines
//
//	CONFLICT-LOSS = (defer + merge-block + land_retry) / dispatched
//
// and L132 records the invariant that `wave-event --phase land` telemetry should
// score land_retry -> 0 on a healthy serial queue. GO3 computes ONLY the
// land_retry term here; defer (Lever 1, scope-overlap deferrals) and merge-block
// (Lever 2, merge-train blocks) are out of this slice's scope and are cited in
// the formula comment but not summed. This metric feeds the doc-27 §3-Deferred
// "real-gates/landing > 1.3" build-gate for the merge-train batcher.
//
// GROUNDED DERIVATION. The landq runner (cmd_landq.go) already emits phase='land'
// wave_events at every queue transition via emitLandEvent, each carrying
// Note="landq #<id> <branch>" (the land_queue BIGSERIAL row id is the stable
// per-branch/per-content key — a requeue REUSES the same id, so all of a branch's
// retries share one key). Over the selected window we read that stream and tally:
//
//   - dispatched = count of land events that reached status='landing'. Both
//     claimed/landing (a fresh claim attempt) and push-retry/landing (an in-claim
//     re-push because origin moved) are 'a land attempt was made', so both count.
//   - landed = count of DISTINCT branch-keys (parsed from Note's '#<id>') that
//     reached status='landed'.
//   - land_retry = EXTRA attempts beyond the first success per branch =
//     dispatched - landed (clamped >= 0 against partial --since windows). A clean
//     serial queue lands each branch in exactly one claimed/landing with no
//     push-retry and no requeue, so dispatched == landed => land_retry == 0.
//   - land_retry_rate = land_retry / dispatched (the CONFLICT-LOSS land_retry term
//     as a rate). conflict/failed transition counts are surfaced as diagnostic
//     breakdown.
//
// POSTURE. bench score is a READ over real shared state. It matches the FAIL-OPEN
// shape of its sibling readers of the SAME tables (`wave-event list`, `landq
// list`): a disabled or unreachable lock server yields {reachable:false, note:...}
// and exit 0, never a hard error — so it is safe to run from a dashboard or a 0444
// wave-sandbox snapshot. main.go's writeVerb classifies bench as a read (it only
// ever touches the remote wave_events table, never the local SQLite DB).

// benchPayload is the bench score result, shared by the JSON and human renderers.
type benchPayload struct {
	Dispatched     int     `json:"dispatched"`
	LandedBranches int     `json:"landed_branches"`
	LandRetry      int     `json:"land_retry"`
	LandRetryRate  float64 `json:"land_retry_rate"`
	Conflicts      int     `json:"conflicts"`
	Failures       int     `json:"failures"`
	Wave           string  `json:"wave,omitempty"`
	SinceSecs      int64   `json:"since_secs,omitempty"`
	Reachable      bool    `json:"reachable"`
	Note           string  `json:"note,omitempty"`
}

func cmdBench(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("taskdb bench <score>")
	}
	switch args[0] {
	case "score":
		return benchScore(db, args[1:])
	default:
		return fmt.Errorf("taskdb bench: unknown subcommand %q (want: score)", args[0])
	}
}

// benchScore reads the phase='land' wave_events stream and reports the doc-27 §6
// land_retry term (extra land attempts beyond the first success per branch), as a
// count + rate, optionally narrowed to one wave and/or a trailing time window.
// FAIL-OPEN like `wave-event list` / `landq list`: a disabled/unreachable server
// yields an empty payload + note and exits 0 (never blocks a dashboard or a
// snapshot); only a genuine bad flag is a real usage error.
func benchScore(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("bench score", flag.ContinueOnError)
	wave := fs.String("wave", "", "narrow to one wave label (default: all waves)")
	since := fs.Duration("since", 0, "trailing window (e.g. 168h); 0 = the full stream (exact)")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	out := benchPayload{Wave: *wave}
	if *since > 0 {
		out.SinceSecs = int64(since.Seconds())
	}

	cfg, _ := loadLockConfig()
	if cfg == nil || !cfg.Enabled {
		out.Note = "benchmark disabled (lock server off)"
		return benchEmit(out, *asJSON)
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		out.Note = "shared server unreachable — benchmark unavailable: " + compactErr(err)
		return benchEmit(out, *asJSON)
	}
	defer ls.close()

	out.Reachable = true
	st, err := ls.landRetryStats(*wave, *since)
	if err != nil {
		// An un-migrated DB / query error degrades like the other fail-open readers:
		// a note, no metric, exit 0.
		out.Reachable = false
		out.Note = "land stats query failed: " + compactErr(err)
		return benchEmit(out, *asJSON)
	}
	out.Dispatched = st.Dispatched
	out.LandedBranches = st.LandedBranches
	out.LandRetry = st.LandRetry
	out.Conflicts = st.Conflicts
	out.Failures = st.Failures
	if st.Dispatched > 0 {
		out.LandRetryRate = float64(st.LandRetry) / float64(st.Dispatched)
	}
	return benchEmit(out, *asJSON)
}

// benchEmit renders a benchPayload as JSON or one human line. Every fail-open
// return path shares this formatter.
func benchEmit(out benchPayload, asJSON bool) error {
	if asJSON {
		return printJSON(out)
	}
	waveLabel := "all"
	if out.Wave != "" {
		waveLabel = out.Wave
	}
	windowLabel := "all"
	if out.SinceSecs > 0 {
		windowLabel = time.Duration(out.SinceSecs * int64(time.Second)).String()
	}
	if !out.Reachable {
		fmt.Printf("land-phase bench (wave=%s, window=%s): %s\n", waveLabel, windowLabel, out.Note)
		return nil
	}
	fmt.Printf("land-phase bench (wave=%s, window=%s): dispatched=%d landed=%d land_retry=%d (rate=%.3f) conflicts=%d failures=%d\n",
		waveLabel, windowLabel, out.Dispatched, out.LandedBranches, out.LandRetry, out.LandRetryRate, out.Conflicts, out.Failures)
	return nil
}
