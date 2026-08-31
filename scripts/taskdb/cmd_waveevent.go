// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"strconv"
)

// cmd_waveevent.go is the telemetry-write seam for the task-wave engine. The
// Workflow runtime has no shell/fs/network of its own, so the engine cannot emit
// telemetry itself — it instruments the prompts of the agents it ALREADY spawns
// (scope/impl/review/gate/plan/merge/finalize/land) to fire ONE fast
// `taskdb wave-event ...` call at each meaningful transition. This subcommand is
// that call.
//
// Two properties shape it, mirroring the lock server it lives beside:
//
//   - REMOTE-ONLY, never the local DB. A wave event is an insert into the SHARED
//     Postgres `taskdb` DB (wave_events + lock_heartbeats), NOT a write to the
//     local SQLite store. That is deliberate: a SANDBOX fleet agent (whose
//     taskdb.sqlite is a read-only 444 snapshot) may safely emit telemetry — it
//     touches no local task content or DAG; git tasks/*.json stays the sole
//     authority for those. So wave-event is classified READ for the read-only
//     snapshot gate (it never opens the local DB for writing).
//
//   - FAIL-OPEN, always. If the shared server is disabled, the tunnel is down,
//     the schema isn't applied, or the insert errors, wave-event prints one quiet
//     banner and EXITS 0. Telemetry must never block, slow, or fail a wave.
//     TASKDB_LOCK_DISABLE=1 (the lock server's own kill switch) silences it, and
//     so does the sibling TASKDB_TRACK_DISABLE=1 (telemetry-only opt-out that
//     keeps locking on).

func cmdWaveEvent(db *sql.DB, args []string) error {
	// `wave-event list` is the READ surface (the dashboard shells out to it):
	// it returns recent telemetry rows + per-wave/unit progress as JSON. It is a
	// pure remote read — fail-open, never touches the local DB. Everything else is
	// the WRITE path (recording one transition).
	if len(args) > 0 && (args[0] == "list" || args[0] == "ls") {
		return cmdWaveEventList(db, args[1:])
	}

	// `wave-event runs` is the HISTORICAL read surface (the dashboard's "past
	// runs" view shells out to it): one summary row per (wave, run_id) over the
	// WHOLE event stream — not just the recent tail `list` returns — so old runs
	// that scrolled out of the cap are still browsable. Also a pure remote read,
	// fail-open, never touches the local DB.
	if len(args) > 0 && args[0] == "runs" {
		return cmdWaveEventRuns(db, args[1:])
	}

	fs := flag.NewFlagSet("wave-event", flag.ContinueOnError)
	wave := fs.String("wave", "", "wave label")
	runID := fs.String("run", "", "per-dispatch run id")
	unit := fs.String("unit", "", "unit key (slug)")
	task := fs.String("task", "", "task id (ULID); prefix resolved when known locally")
	phase := fs.String("phase", "", "pipeline phase (scope|implement|review|gate|plan|wave2|merge|finalize|land)")
	agent := fs.String("agent", "", "agent label")
	event := fs.String("event", "", "start|end|status-change|heartbeat")
	status := fs.String("status", "", "task status at this transition (open|in-progress|done|blocked)")
	session := fs.String("session", "", "holding session id (defaults to a heartbeat for the lock holder)")
	tokens := fs.String("tokens", "", "output tokens spent so far this turn (budget.spent proxy)")
	note := fs.String("note", "", "free-text detail")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Telemetry kill switches. TASKDB_TRACK_DISABLE silences telemetry while
	// leaving locking on; TASKDB_LOCK_DISABLE (the lock server's own switch)
	// silences both. Either one → quiet no-op, exit 0.
	if truthyEnv("TASKDB_TRACK_DISABLE") || truthyEnv("TASKDB_LOCK_DISABLE") {
		return nil
	}

	tok := int64(-1)
	if *tokens != "" {
		if n, err := strconv.ParseInt(*tokens, 10, 64); err == nil {
			tok = n
		}
	}

	// Resolve a task PREFIX to the full ULID when this checkout knows it — but a
	// sandbox snapshot or an unknown id is fine: store whatever we were given,
	// since the row joins to tasks by id in the dashboard and a partial id simply
	// won't join (harmless, self-heals on the next full-id event). Never fatal.
	taskID := *task
	if taskID != "" && db != nil && !dbReadOnly {
		if full, err := resolveTaskID(db, taskID); err == nil {
			taskID = full
		}
	}

	e := WaveEvent{
		Wave:       *wave,
		RunID:      *runID,
		UnitKey:    *unit,
		TaskID:     taskID,
		Phase:      *phase,
		AgentLabel: *agent,
		Event:      *event,
		Status:     *status,
		Session:    *session,
		Host:       devHost(),
		Tokens:     tok,
		Note:       *note,
	}

	// FAIL-OPEN remote write, mirroring lockServerOrLocal: disabled or unreachable
	// → one quiet banner (warnDegraded is once-per-process), exit 0.
	cfg, cfgErr := loadLockConfig()
	if cfgErr != nil {
		warnDegraded("taskdb wave-event: %v — telemetry skipped", cfgErr)
		return nil
	}
	if cfg == nil || !cfg.Enabled {
		return nil // lock server disabled: telemetry is off too, silently
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		warnDegraded("taskdb wave-event: shared server unreachable (%s) — telemetry skipped (wave proceeds; open the tunnel to restore live progress)", compactErr(err))
		return nil
	}
	defer ls.close()
	if err := ls.recordEvent(e); err != nil {
		warnDegraded("taskdb wave-event: insert failed (%s) — telemetry skipped", compactErr(err))
		return nil
	}
	return nil
}

// cmdWaveEventList is the read surface the dashboard shells out to. It returns
// the recent telemetry tail (optionally narrowed to one wave/run) plus a
// per-(wave,unit) progress rollup, as JSON. FAIL-OPEN like the writer: a down
// tunnel / disabled server yields an empty payload with a note, never an error
// exit, so the dashboard degrades gracefully (exactly like loadLocks).
func cmdWaveEventList(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("wave-event list", flag.ContinueOnError)
	wave := fs.String("wave", "", "narrow to one wave label")
	runID := fs.String("run", "", "narrow to one run id")
	limit := fs.Int("limit", 200, "max events to return (newest first)")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	type payload struct {
		Events    []WaveEvent      `json:"events"`
		Progress  []WaveUnitRollup `json:"progress"`
		Reachable bool             `json:"reachable"`
		Note      string           `json:"note,omitempty"`
	}
	out := payload{Events: []WaveEvent{}, Progress: []WaveUnitRollup{}}

	cfg, _ := loadLockConfig()
	if cfg == nil || !cfg.Enabled {
		out.Note = "telemetry disabled (lock server off)"
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		out.Note = "shared server unreachable — telemetry unavailable: " + compactErr(err)
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	defer ls.close()

	out.Reachable = true
	if evs, err := ls.listEvents(*wave, *runID, *limit); err == nil {
		out.Events = evs
	}
	if rl, err := ls.unitRollup(*wave, *runID); err == nil {
		out.Progress = rl
	}

	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("wave telemetry: %d recent event(s), %d unit(s) in progress rollup\n", len(out.Events), len(out.Progress))
	for _, p := range out.Progress {
		fmt.Printf("  [%s/%s] task=%s phase=%s status=%s events=%d last=%s\n",
			p.Wave, p.UnitKey, shortID(p.TaskID), p.LastPhase, p.LastStatus, p.EventCount, p.LastEvent)
	}
	return nil
}

// cmdWaveEventRuns is the HISTORICAL read surface: it returns one summary row per
// (wave, run_id) over the ENTIRE wave_events stream — every workflow run that ever
// recorded telemetry, newest activity first — so the dashboard can browse past
// runs, not just the live tail. FAIL-OPEN exactly like cmdWaveEventList: a
// disabled/unreachable server yields an empty payload with a note and exit 0.
func cmdWaveEventRuns(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("wave-event runs", flag.ContinueOnError)
	wave := fs.String("wave", "", "narrow to one wave label")
	limit := fs.Int("limit", 500, "max runs to return (most recent activity first)")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	type payload struct {
		Runs      []WaveRun `json:"runs"`
		Reachable bool      `json:"reachable"`
		Note      string    `json:"note,omitempty"`
	}
	out := payload{Runs: []WaveRun{}}

	cfg, _ := loadLockConfig()
	if cfg == nil || !cfg.Enabled {
		out.Note = "telemetry disabled (lock server off)"
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		out.Note = "shared server unreachable — telemetry unavailable: " + compactErr(err)
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	defer ls.close()

	out.Reachable = true
	if runs, err := ls.listRuns(*wave, *limit); err == nil {
		out.Runs = runs
	} else {
		out.Note = "run history query failed: " + compactErr(err)
	}

	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("wave history: %d run(s)\n", len(out.Runs))
	for _, r := range out.Runs {
		outcome := "incomplete"
		if r.Landed {
			outcome = "landed"
		} else if r.Terminal {
			outcome = "finalized"
		}
		fmt.Printf("  [%s] run=%s units=%d events=%d %s last=%s\n",
			r.Wave, r.RunID, r.UnitCount, r.EventCount, outcome, r.LastTs)
	}
	return nil
}
