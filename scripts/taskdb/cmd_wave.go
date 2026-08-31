// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// cmd_wave.go is the composable, agent-scriptable orchestration SDK: the
// `taskdb wave` verb group. It is a THIN, ADDITIVE wrapper over the same remote
// telemetry seam `wave-event` already uses (recordEvent/recordEvents, listEvents,
// unitRollup on the shared Postgres) — never the local DB. Like its neighbours it
// is REMOTE-ONLY and FAIL-OPEN: a disabled/unreachable lock server is a quiet
// degrade (JSON reports reachable:false), never a blocked agent.
//
//   wave report   record ONE transition (== wave-event write) or a --batch of them
//   wave status   pre-rolled LIVE per-unit status (rollup + activity-aware staleness)
//   wave tail     recent events newest-first, optionally --follow
//
// The legacy `wave-event` / `wave-event list` verbs are UNCHANGED and route
// through the SAME handlers (cmdWaveEvent / cmdWaveEventList), so task-wave.js's
// existing `taskdb wave-event ...` calls keep working byte-for-byte.

func cmdWave(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb wave <report|status|tail>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "report":
		return cmdWaveReport(db, rest)
	case "status":
		return cmdWaveStatus(db, rest)
	case "tail":
		return cmdWaveTail(db, rest)
	default:
		return fmt.Errorf("unknown wave subcommand: %s (want report|status|tail)", sub)
	}
}

// cmdWaveReport records ONE wave/unit transition (the same flags and behavior as
// the `wave-event` write) OR, with --batch, a whole JSON array of events in ONE
// transaction. FAIL-OPEN throughout: a disabled/unreachable server reports
// recorded=false (single) / recorded=0 (batch) with reachable=false and exits 0.
func cmdWaveReport(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("wave report", flag.ContinueOnError)
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
	batch := fs.String("batch", "", "read a JSON array of event objects from a file or - (stdin) and record ALL in one transaction")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*batch) != "" {
		return waveReportBatch(*batch, *asJSON)
	}

	// Telemetry kill switches mirror wave-event: TASKDB_TRACK_DISABLE silences
	// telemetry only, TASKDB_LOCK_DISABLE silences both. Either → quiet no-op.
	if truthyEnv("TASKDB_TRACK_DISABLE") || truthyEnv("TASKDB_LOCK_DISABLE") {
		if *asJSON {
			return printJSON(map[string]any{"recorded": false, "reachable": false, "task": *task})
		}
		return nil
	}

	tok := int64(-1)
	if *tokens != "" {
		if n, err := strconv.ParseInt(*tokens, 10, 64); err == nil {
			tok = n
		}
	}

	// Resolve a task PREFIX to the full ULID when this checkout knows it (exactly
	// like cmdWaveEvent); a sandbox snapshot or unknown id is fine — store as given.
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

	recorded, reachable := recordOneEvent(e)
	if *asJSON {
		return printJSON(map[string]any{"recorded": recorded, "reachable": reachable, "task": taskID})
	}
	return nil
}

// recordOneEvent runs the fail-open remote write for one event, returning
// (recorded, reachable). It mirrors cmdWaveEvent's banner discipline (warnDegraded
// is once-per-process) and NEVER errors — telemetry must not block a wave.
func recordOneEvent(e WaveEvent) (recorded, reachable bool) {
	cfg, cfgErr := loadLockConfig()
	if cfgErr != nil {
		warnDegraded("taskdb wave report: %v — telemetry skipped", cfgErr)
		return false, false
	}
	if cfg == nil || !cfg.Enabled {
		return false, false // lock server disabled: telemetry off, silently
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		warnDegraded("taskdb wave report: shared server unreachable (%s) — telemetry skipped (wave proceeds; open the tunnel to restore live progress)", compactErr(err))
		return false, false
	}
	defer ls.close()
	if err := ls.recordEvent(e); err != nil {
		warnDegraded("taskdb wave report: insert failed (%s) — telemetry skipped", compactErr(err))
		return false, true
	}
	return true, true
}

// waveReportBatch reads a JSON array of WaveEvent objects from path (or "-" for
// stdin) and records them ALL in ONE transaction (recordEvents). FAIL-OPEN like
// the single path: a disabled/unreachable server reports recorded=0,
// reachable=false and exits 0. A malformed batch is a REAL usage error (the caller
// handed us bad input), not the degraded path.
func waveReportBatch(path string, asJSON bool) error {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(path)
	}
	if err != nil {
		return fmt.Errorf("reading batch from %s: %w", path, err)
	}
	var events []WaveEvent
	if err := json.Unmarshal(raw, &events); err != nil {
		return fmt.Errorf("parsing batch JSON (expected an array of event objects): %w", err)
	}
	// Stamp host on any row that omitted it, mirroring the single-event path.
	for i := range events {
		if events[i].Host == "" {
			events[i].Host = devHost()
		}
	}

	report := func(recorded int, reachable bool) error {
		if asJSON {
			return printJSON(map[string]any{"recorded": recorded, "reachable": reachable})
		}
		fmt.Printf("wave report: recorded %d event(s) (reachable=%v)\n", recorded, reachable)
		return nil
	}

	if truthyEnv("TASKDB_TRACK_DISABLE") || truthyEnv("TASKDB_LOCK_DISABLE") {
		return report(0, false)
	}
	cfg, cfgErr := loadLockConfig()
	if cfgErr != nil {
		warnDegraded("taskdb wave report --batch: %v — telemetry skipped", cfgErr)
		return report(0, false)
	}
	if cfg == nil || !cfg.Enabled {
		return report(0, false)
	}
	ls, oerr := openLockServer(cfg)
	if oerr != nil {
		warnDegraded("taskdb wave report --batch: shared server unreachable (%s) — telemetry skipped", compactErr(oerr))
		return report(0, false)
	}
	defer ls.close()
	if rerr := ls.recordEvents(events); rerr != nil {
		warnDegraded("taskdb wave report --batch: insert failed (%s) — telemetry skipped", compactErr(rerr))
		return report(0, true)
	}
	return report(len(events), true)
}

// WaveUnitStatus is one row of `wave status`: a unit's rolled-up progress plus the
// activity-aware staleness verdict (lockStale, the shared rule). active_secs is the
// freshest-activity age in seconds (heartbeat age when the task has a heartbeat,
// else the unit's event age) — the "how long since this moved" headline.
type WaveUnitStatus struct {
	Unit       string `json:"unit"`
	Task       string `json:"task"`
	Phase      string `json:"phase"`
	Status     string `json:"status"`
	Event      string `json:"event"`
	Events     int    `json:"events"`
	UpdatedAt  string `json:"updated_at"`
	Stale      bool   `json:"stale"`
	ActiveSecs int64  `json:"active_secs"`
}

// cmdWaveStatus is the headline LIVE-status primitive: unitRollup(wave,run) joined
// with activity-aware staleness, in ONE call. It reuses the SAME lockStale rule
// printRemoteLocks uses (the shared helper in cmd_lifecycle.go). Optional --unit
// filter. FAIL-OPEN: disabled/unreachable reports reachable:false with a note.
func cmdWaveStatus(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("wave status", flag.ContinueOnError)
	wave := fs.String("wave", "", "narrow to one wave label")
	runID := fs.String("run", "", "narrow to one run id")
	unit := fs.String("unit", "", "narrow to one unit key")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	type payload struct {
		Units     []WaveUnitStatus `json:"units"`
		Reachable bool             `json:"reachable"`
		Note      string           `json:"note,omitempty"`
	}
	out := payload{Units: []WaveUnitStatus{}}

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
		out.Note = "shared server unreachable — wave status unavailable: " + compactErr(err)
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	defer ls.close()
	out.Reachable = true

	rollup, rerr := ls.unitRollup(*wave, *runID)
	if rerr != nil {
		out.Note = "rollup query failed: " + compactErr(rerr)
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	activity, _ := ls.unitActivityAges(*wave, *runID)

	for _, r := range rollup {
		if *unit != "" && r.UnitKey != *unit {
			continue
		}
		ua := activity[r.UnitKey]
		stale := lockStale(ua.EventAge, ua.HBAge, ua.HasHeartbeat)
		// active_secs: the freshest activity age — heartbeat age when present (it is
		// the truest "is this unit alive" signal), else the unit's event age.
		active := int64(ua.EventAge / time.Second)
		if ua.HasHeartbeat && ua.HBAge < ua.EventAge {
			active = int64(ua.HBAge / time.Second)
		}
		out.Units = append(out.Units, WaveUnitStatus{
			Unit:       r.UnitKey,
			Task:       r.TaskID,
			Phase:      r.LastPhase,
			Status:     r.LastStatus,
			Event:      r.LastEvent,
			Events:     r.EventCount,
			UpdatedAt:  r.UpdatedAt,
			Stale:      stale,
			ActiveSecs: active,
		})
	}

	if *asJSON {
		return printJSON(out)
	}
	if len(out.Units) == 0 {
		fmt.Println("wave status: no units (nothing recorded for this wave/run yet)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "UNIT\tPHASE\tSTATUS\tEVENT\t#EV\tACTIVE\tTASK")
	for _, u := range out.Units {
		flag := ""
		if u.Stale {
			flag = " ⚠STALE"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s ago%s\t%s\n",
			u.Unit, u.Phase, u.Status, u.Event, u.Events,
			(time.Duration(u.ActiveSecs) * time.Second).Round(time.Second), flag, shortID(u.Task))
	}
	return w.Flush()
}

// cmdWaveTail prints recent wave events newest-first via listEvents. Without
// --follow it prints once and exits; with --follow it polls ~2s and prints new
// events by id cursor (advancing past the highest ts/id seen). FAIL-OPEN: a
// disabled/unreachable server prints a note and exits 0.
func cmdWaveTail(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("wave tail", flag.ContinueOnError)
	wave := fs.String("wave", "", "narrow to one wave label")
	runID := fs.String("run", "", "narrow to one run id")
	limit := fs.Int("limit", 40, "max events to print (newest first)")
	follow := fs.Bool("follow", false, "poll for new events (~2s) and stream them until interrupted")
	asJSON := fs.Bool("json", false, "output JSON (a single snapshot; ignores --follow)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, _ := loadLockConfig()
	if cfg == nil || !cfg.Enabled {
		note := "telemetry disabled (lock server off)"
		if *asJSON {
			return printJSON(map[string]any{"events": []WaveEvent{}, "reachable": false, "note": note})
		}
		fmt.Println(note)
		return nil
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		note := "shared server unreachable — wave tail unavailable: " + compactErr(err)
		if *asJSON {
			return printJSON(map[string]any{"events": []WaveEvent{}, "reachable": false, "note": note})
		}
		fmt.Println(note)
		return nil
	}
	defer ls.close()

	evs, lerr := ls.listEvents(*wave, *runID, *limit)
	if lerr != nil {
		note := "events query failed: " + compactErr(lerr)
		if *asJSON {
			return printJSON(map[string]any{"events": []WaveEvent{}, "reachable": true, "note": note})
		}
		fmt.Println(note)
		return nil
	}

	if *asJSON {
		// A single snapshot — JSON callers poll themselves; --follow is a TTY stream.
		return printJSON(map[string]any{"events": evs, "reachable": true})
	}

	// listEvents returns newest-first; print oldest-first so a tail reads top→bottom.
	printWaveEventsChrono(evs)
	if !*follow {
		return nil
	}

	// Follow: poll, advancing a cursor past the freshest (ts,id) seen so we only
	// print NEW rows. listEvents has no since-cursor, so we de-dup by a small
	// recency key (ts|wave|unit|event|phase) — cheap and good enough for a TTY tail.
	seen := map[string]bool{}
	for _, e := range evs {
		seen[tailKey(e)] = true
	}
	for {
		time.Sleep(2 * time.Second)
		fresh, ferr := ls.listEvents(*wave, *runID, *limit)
		if ferr != nil {
			continue // fail-open: a transient blip never kills the tail
		}
		var nw []WaveEvent
		for _, e := range fresh {
			k := tailKey(e)
			if !seen[k] {
				seen[k] = true
				nw = append(nw, e)
			}
		}
		printWaveEventsChrono(nw)
	}
}

// tailKey is the de-dup key for --follow: events lack a stable client-visible id
// in the WaveEvent wire shape, so we key on the recency-distinguishing fields.
func tailKey(e WaveEvent) string {
	return strings.Join([]string{e.Ts, e.Wave, e.RunID, e.UnitKey, e.Phase, e.Event, e.Status, e.Note}, "|")
}

// printWaveEventsChrono prints events oldest-first (the input is newest-first).
func printWaveEventsChrono(evs []WaveEvent) {
	for i := len(evs) - 1; i >= 0; i-- {
		e := evs[i]
		fmt.Printf("%s [%s/%s] %s phase=%s event=%s status=%s",
			e.Ts, e.Wave, e.UnitKey, shortID(e.TaskID), e.Phase, e.Event, e.Status)
		if e.Note != "" {
			fmt.Printf(" — %s", e.Note)
		}
		fmt.Println()
	}
}
