// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// cmd_landq.go is the producer surface for the serialized landing queue (doc 27
// Lever 3): a wave (or a dev) ENQUEUEs a gate-green branch, and a single elected
// runner fast-forward-lands the queue onto main one branch at a time so two
// landings never race the same main. This file holds the PRODUCER + read verbs
// (enqueue / list / status), the SERIAL runner (run), and the operator controls
// (reap / cancel / requeue). The producer/read verbs are FAIL-OPEN; the runner
// and operator verbs are LOUD (mustLockServer) — an operator cancelling against a
// down tunnel wants a real error, not a silent no-op.
//
// It shares the two properties of its lock-server / wave-event neighbours:
//
//   - REMOTE-ONLY, never the local DB. A queue row is an insert into the SHARED
//     Postgres `taskdb` DB (land_queue), NOT a write to the local SQLite store.
//     The git branch refs are the sole authority for the work; land_queue is
//     disposable coordination state. So landq is classified READ for the
//     read-only-snapshot gate (writeVerb): a 444 wave-sandbox snapshot may emit
//     it because it touches no local task content or DAG.
//
//   - FAIL-OPEN, always. If the shared server is disabled, the tunnel is down,
//     the schema isn't applied, or the insert errors, the producer prints one
//     quiet banner and EXITS 0 (enqueue reporting {enqueued:false}). Queueing a
//     landing must never block, slow, or fail a wave — the fallback is exactly
//     today's behaviour (land 'main' directly). A genuine caller mistake (an
//     empty --branch) is a real usage error, NOT the degraded path.

// landqAutoReapEveryIdle rate-limits the leader idle-loop orphaned-lock auto-reap
// (docs/23 OQ4): the sweep runs about once per this many idle poll ticks rather
// than on every ~2s beat, so a mostly-idle leader still cleans stale wave locks
// promptly (~a minute at the default 2s --sleep) without hammering the shared DB.
const landqAutoReapEveryIdle = 30

// Leader-liveness knobs. Together these close the "a crashed leader strands the
// queue forever" gap: the sentinel is the ONE lock reap() deliberately refuses to
// age out, so before this it could only be cleared by a clean SIGTERM or an
// operator running `lockserver unlock --force`. A reboot on 2026-08-18 left it
// held for 11h41m with a 2-minute election timer reporting success the whole time.
const (
	// landqLeaderHeartbeatEvery is how often the leader refreshes the sentinel's
	// locked_at WHILE a land is in flight. Without this the heartbeat fires once at
	// the top of landOnePass and then goes silent for the whole merge+gate (up to
	// --gate-timeout, 20m by default), which would force any takeover threshold to
	// be at least that large. A cheap session-scoped UPDATE every 30s makes
	// locked_at a true seconds-granularity liveness signal at all times.
	landqLeaderHeartbeatEvery = 30 * time.Second

	// landqDefaultTakeoverAfter is the default silence window before a candidate
	// reclaims the sentinel. Deliberately conservative: it is clamped up to
	// landqTakeoverFloorFactor x --gate-timeout anyway (45m > 2x20m only barely, so
	// the clamp usually does not bite at defaults), and being slow to take over
	// costs one extra idle window while being too eager risks a double writer.
	landqDefaultTakeoverAfter = 45 * time.Minute

	// landqTakeoverFloorFactor keeps the takeover threshold safely above the gate
	// timeout. This matters most during a ROLLOUT: an already-running leader on an
	// older binary has no mid-gate heartbeat, so its locked_at legitimately ages
	// for the length of a gate. 2x that window is the margin.
	landqTakeoverFloorFactor = 2

	// landqTakeoverMinFloor is the absolute floor, for operators who set a very
	// small --gate-timeout. 10m is still ~20 missed 30s heartbeats.
	landqTakeoverMinFloor = 10 * time.Minute

	// landqSentinelSuspectAge is when a still-held sentinel starts looking wrong
	// enough to warn about if takeover is DISABLED. Matches the 30m staleness
	// cutoff `taskdb status` already uses to print its ⚠ STALE flag.
	landqSentinelSuspectAge = 30 * time.Minute
)

// resolveLandLeaderTakeover clamps a requested takeover threshold up to the safe
// floor for the configured gate timeout, returning the effective value and
// whether it had to be raised. requested<=0 means DISABLED and is passed through
// untouched — an operator turning the feature off must not have it clamped back
// on. Pure, so the clamp boundaries are table-tested rather than reasoned about.
func resolveLandLeaderTakeover(requested, gateTimeout time.Duration) (effective time.Duration, clamped bool) {
	if requested <= 0 {
		return 0, false
	}
	floor := time.Duration(landqTakeoverFloorFactor) * gateTimeout
	if floor < landqTakeoverMinFloor {
		floor = landqTakeoverMinFloor
	}
	if requested < floor {
		return floor, true
	}
	return requested, false
}

// startLeaderHeartbeat keeps the sentinel's locked_at fresh for the duration of a
// (potentially very slow) land pass, and returns a stop func the caller defers.
//
// It uses refreshLock rather than heartbeatLandLeader deliberately: the latter
// also records a wave_event for the observability trail, which is right once per
// pass but would write a row every 30s here and bloat the event log. refreshLock
// is the bare session-scoped locked_at bump, and being session-scoped it can
// never resurrect a sentinel that a new leader has since taken over.
func startLeaderHeartbeat(ls *lockServer, session string, every time.Duration) (stop func()) {
	if every <= 0 {
		return func() {}
	}
	done := make(chan struct{})
	var once sync.Once
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				_, _ = ls.refreshLock(landLeaderSentinel, session)
			}
		}
	}()
	return func() { once.Do(func() { close(done) }) }
}

func cmdLandq(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb landq <enqueue|list|status|run|reap|cancel|requeue>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "enqueue", "add":
		return cmdLandqEnqueue(db, rest)
	case "list", "ls":
		return cmdLandqList(db, rest)
	case "status":
		return cmdLandqStatus(db, rest)
	case "run":
		return cmdLandqRun(db, rest)
	case "reap":
		return cmdLandqReap(db, rest)
	case "cancel":
		return cmdLandqCancel(db, rest)
	case "requeue":
		return cmdLandqRequeue(db, rest)
	case "leader":
		return cmdLandqLeader(db, rest)
	default:
		return fmt.Errorf("unknown landq subcommand: %s", sub)
	}
}

// cmdLandqLeader reports the current holder of the landLeaderSentinel — the answer
// to "is the landing runner up, and who leads?". A FAIL-OPEN read like
// list/status: a disabled/unreachable server reports reachable:false rather than
// erroring, so a monitoring script never wedges on a down tunnel.
//
//	--json: {leader:<session>|null, host, held_secs, reachable}
//	human:  `leader: <session> on <host> (held <dur>)` or
//	        `no leader elected (runner down?)`
func cmdLandqLeader(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("landq leader", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	type payload struct {
		Leader    *string `json:"leader"`
		Host      string  `json:"host,omitempty"`
		HeldSecs  int64   `json:"held_secs"`
		Reachable bool    `json:"reachable"`
		Note      string  `json:"note,omitempty"`
	}
	out := payload{}

	cfg, _ := loadLockConfig()
	if cfg == nil || !cfg.Enabled {
		out.Note = "landing queue disabled (lock server off)"
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		out.Note = "shared server unreachable — leader unknown: " + compactErr(err)
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	defer ls.close()
	out.Reachable = true

	h, herr := ls.holder(landLeaderSentinel)
	if herr != nil {
		out.Note = "leader query failed: " + compactErr(herr)
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	if h == nil {
		// No sentinel held → no elected runner.
		if *asJSON {
			return printJSON(out) // Leader nil, HeldSecs 0, Reachable true
		}
		fmt.Println("no leader elected (runner down?)")
		return nil
	}
	out.Leader = &h.LockedBy
	out.Host = h.Host
	held := time.Since(h.LockedAt)
	if held < 0 {
		held = 0
	}
	out.HeldSecs = int64(held / time.Second)
	if *asJSON {
		return printJSON(out)
	}
	fmt.Printf("leader: %s on %s (held %s)\n", h.LockedBy, h.Host, held.Round(time.Second))
	return nil
}

// cmdLandqEnqueue is the producer: insert (or no-op onto) a 'queued' row for a
// gate-green branch. FAIL-OPEN exactly like cmdWaveEvent: a disabled server is a
// SILENT exit-0 no-op (queueing is off, fall back to direct landing); an
// unreachable server or an insert error prints ONE warnDegraded banner and exits
// 0 with {enqueued:false}. Only a missing --branch (a caller mistake) returns a
// real usage error.
func cmdLandqEnqueue(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("landq enqueue", flag.ContinueOnError)
	branch := fs.String("branch", "", "the gate-green ref to land (required)")
	base := fs.String("base", "", "main sha the branch was gated over")
	tasks := fs.String("tasks", "", "space-joined owned task ULIDs")
	gate := fs.String("gate", "", "gate command run in the merged worktree before FF-push (default: the runner's static --gate)")
	wave := fs.String("wave", "", "wave label")
	runID := fs.String("run", "", "per-dispatch run id")
	priority := fs.Int("priority", 0, "landing priority (higher lands first)")
	session := fs.String("session", "", "requesting session id")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *branch == "" {
		// Caller mistake, not the degraded path: surface it as a real error.
		return fmt.Errorf("landq enqueue: --branch is required")
	}

	// degraded emits the {enqueued:false} no-op result both the disabled and the
	// unreachable/error paths share, then returns nil (exit 0).
	degraded := func() error {
		if *asJSON {
			return printJSON(map[string]any{"branch": *branch, "enqueued": false})
		}
		return nil
	}

	cfg, cfgErr := loadLockConfig()
	if cfgErr != nil {
		warnDegraded("taskdb landq enqueue: %v — landing not queued (land directly)", cfgErr)
		return degraded()
	}
	if cfg == nil || !cfg.Enabled {
		// Lock server disabled: queueing is off too, silently (mirrors wave-event).
		return degraded()
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		warnDegraded("taskdb landq enqueue: shared server unreachable (%s) — landing not queued (land directly; open the tunnel to restore the serial queue)", compactErr(err))
		return degraded()
	}
	defer ls.close()

	e := LandEntry{
		Branch:      *branch,
		BaseSHA:     *base,
		TaskIDs:     *tasks,
		Gate:        *gate,
		Wave:        *wave,
		RunID:       *runID,
		Priority:    *priority,
		RequestedBy: *session,
		Host:        devHost(),
	}
	id, enqueued, err := ls.enqueueLand(e)
	if err != nil {
		warnDegraded("taskdb landq enqueue: insert failed (%s) — landing not queued (land directly)", compactErr(err))
		return degraded()
	}
	if *asJSON {
		return printJSON(map[string]any{"id": id, "branch": *branch, "enqueued": enqueued})
	}
	if enqueued {
		fmt.Printf("queued #%d %s\n", id, *branch)
	} else {
		fmt.Printf("already queued #%d %s (no-op)\n", id, *branch)
	}
	return nil
}

// cmdLandqList is the read surface: the land_queue rows, newest first, optionally
// narrowed to one status. FAIL-OPEN like cmdWaveEventList: a disabled/unreachable
// server yields an empty payload with a note, never an error exit, so a dashboard
// shelling out to --json degrades gracefully.
func cmdLandqList(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("landq list", flag.ContinueOnError)
	status := fs.String("status", "", "narrow to one status (queued|landing|landed|conflict|failed|cancelled)")
	limit := fs.Int("limit", 100, "max rows to return (newest first; 0 = no limit)")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	type payload struct {
		Queue     []LandEntry `json:"queue"`
		Reachable bool        `json:"reachable"`
		Note      string      `json:"note,omitempty"`
	}
	out := payload{Queue: []LandEntry{}}

	cfg, _ := loadLockConfig()
	if cfg == nil || !cfg.Enabled {
		out.Note = "landing queue disabled (lock server off)"
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		out.Note = "shared server unreachable — landing queue unavailable: " + compactErr(err)
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	defer ls.close()

	out.Reachable = true
	if rows, err := ls.listLand(*status, *limit); err == nil {
		out.Queue = rows
	} else {
		out.Note = "query failed: " + compactErr(err)
	}

	if *asJSON {
		return printJSON(out)
	}
	if len(out.Queue) == 0 {
		fmt.Println("landing queue: empty")
		return nil
	}
	fmt.Printf("landing queue: %d row(s)\n", len(out.Queue))
	for _, r := range out.Queue {
		fmt.Printf("  #%d [%s] %s prio=%d tasks=%q gate=%q by=%s @%s\n",
			r.ID, r.Status, r.Branch, r.Priority, r.TaskIDs, r.Gate, r.RequestedBy, r.EnqueuedAt)
	}
	return nil
}

// cmdLandqStatus is a terse depth-by-status summary of the queue — the same
// fail-open read as list, rolled up by status. Folded into `taskdb status` too.
func cmdLandqStatus(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("landq status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	type payload struct {
		Depth     map[string]int `json:"depth"`
		Total     int            `json:"total"`
		Reachable bool           `json:"reachable"`
		Note      string         `json:"note,omitempty"`
	}
	out := payload{Depth: map[string]int{}}

	cfg, _ := loadLockConfig()
	if cfg == nil || !cfg.Enabled {
		out.Note = "landing queue disabled (lock server off)"
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		out.Note = "shared server unreachable — landing queue unavailable: " + compactErr(err)
		if *asJSON {
			return printJSON(out)
		}
		fmt.Println(out.Note)
		return nil
	}
	defer ls.close()

	out.Reachable = true
	if rows, err := ls.listLand("", 0); err == nil {
		for _, r := range rows {
			out.Depth[r.Status]++
			out.Total++
		}
	} else {
		out.Note = "query failed: " + compactErr(err)
	}

	if *asJSON {
		return printJSON(out)
	}
	if out.Total == 0 {
		fmt.Println("landing queue: empty")
		return nil
	}
	fmt.Printf("landing queue: %d row(s)", out.Total)
	for _, s := range []string{"queued", "landing", "landed", "conflict", "failed", "cancelled"} {
		if n := out.Depth[s]; n > 0 {
			fmt.Printf("  %s %d", s, n)
		}
	}
	fmt.Println()
	return nil
}

// cmdLandqRun is THE serial landing runner (doc 27 Lever 3): a single elected
// writer that drains the land_queue, fast-forward-landing one branch at a time
// onto <main>. Unlike enqueue/list/status it is NOT fail-open — a silent runner
// that can't reach the server would strand the queue, so it errors LOUDLY via
// mustLockServer() exactly like the lockserver verbs. Single-writer is enforced
// by the __land_leader__ sentinel in task_locks: only the runner that wins the
// sentinel acquire() proceeds; a second concurrent runner prints who holds it and
// exits 0 quietly. Under that one writer the FF-push CANNOT be peer-rejected
// (origin only moves through this runner), so the §1 rewind race is structurally
// impossible — the rewind-proof invariants of ⑨ LAND (origin under ours, never
// rebase the merge, never --force, push the explicit SHA) are preserved verbatim.
func cmdLandqRun(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("landq run", flag.ContinueOnError)
	once := fs.Bool("once", false, "land a single entry (or exit if the queue is empty) then return — for cron/CI")
	dryRun := fs.Bool("dry-run", false, "do everything EXCEPT the real push: log \"would push <sha>\" and leave the row queued")
	gate := fs.String("gate", "", "shell command run ONCE in the merged worktree; non-zero = the branch fails to land")
	gateTimeout := fs.Duration("gate-timeout", 20*time.Minute, "kill the per-row gate (and its process group) after this and requeue the row (0 = no deadline)")
	maxAttempts := fs.Int("max-attempts", 5, "park a row 'failed' after this many transient-gate requeues (claim attempts) so a gate that can never RUN cannot starve the serial queue forever; 0 = unbounded")
	mainBranch := fs.String("main", "main", "the branch to land onto (origin/<main>)")
	age := fs.Duration("age", 30*time.Minute, "reap 'landing' rows whose started_at is older than this back to 'queued'")
	batch := fs.Int("batch", 1, "DORMANT merge-train depth: land up to N queued branches under ONE gate per pass with split-bisection on red (doc 27 §3 Deferred). DEFAULT 1 = today's byte-identical serial path. >1 is a deliberate, BENCH-GATED operator choice — enable only when wavebench shows real-gates/landing > 1.3 (the train trades a wider blast radius on red for fewer gate runs)")
	takeoverAfter := fs.Duration("takeover-after", landqDefaultTakeoverAfter, "take over the __land_leader__ sentinel when its heartbeat has been silent this long (a crashed/rebooted leader can never release it, and reap() excludes it by design). Clamped up to a floor of 2x --gate-timeout so a LIVE leader mid-gate is never stolen; 0 disables takeover and restores the hand-recovery-only behavior")
	session := fs.String("session", "", "runner/leader session id (defaults to a host-derived id)")
	sleep := fs.Duration("sleep", 2*time.Second, "daemon idle poll interval when the queue is empty (ignored with --once)")
	noCanonicalSync := fs.Bool("no-canonical-sync", false, "do NOT fast-forward this canonical checkout's <main> ref to origin/<main> after each land (default: keep the checkout in sync; ref+tracked-tree only, never thaws the live DB)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	sess := strings.TrimSpace(*session)
	if sess == "" {
		sess = "landq-runner-" + devHost()
	}
	host := devHost()

	// LOUD on an unreachable/disabled server — a silent runner strands the queue.
	ls, err := mustLockServer()
	if err != nil {
		return err
	}
	defer ls.close()

	// Nudge migrate on an un-migrated DB so the runner isn't claiming blind.
	if present, perr := ls.landSchemaPresent(); perr == nil && !present {
		if merr := ls.migrate(); merr != nil {
			return fmt.Errorf("land_queue schema absent and migrate failed: %w", merr)
		}
	}

	// Elect the single writer. A loser exits 0 quietly (single-writer guarantee)
	// UNLESS the incumbent is provably dead, in which case it takes the sentinel
	// over — see the takeover block below.
	won, holder, err := ls.acquireLandLeader(sess, host)
	if err != nil {
		return fmt.Errorf("electing land leader: %w", err)
	}
	if !won {
		// A hard kill (SIGKILL / crash / power loss / reboot) skips the deferred
		// releaseLandLeader, and reap() deliberately excludes the sentinel from the
		// blanket age-DELETE, so nothing else will EVER reclaim it. Before standing
		// down, check whether the incumbent's heartbeat has gone silent long enough
		// that it cannot be running, and if so steal the sentinel atomically.
		takeover, clamped := resolveLandLeaderTakeover(*takeoverAfter, *gateTimeout)
		if clamped {
			fmt.Printf("landq run: --takeover-after raised to %s (floor is 2x --gate-timeout %s, so a live leader mid-gate is never stolen)\n",
				takeover, *gateTimeout)
		}
		if landLeaderTakeoverEligible(holder, time.Now(), takeover) {
			stole, terr := ls.takeoverLandLeader(sess, host, holder.LockedBy, takeover)
			if terr != nil {
				return fmt.Errorf("taking over a stale %s from %s: %w", landLeaderSentinel, holder.LockedBy, terr)
			}
			if stole {
				fmt.Printf("landq run: took over %s from %s on %s — its heartbeat was silent for %s (> %s), so it cannot be running\n",
					landLeaderSentinel, holder.LockedBy, holder.Host,
					time.Since(holder.LockedAt).Round(time.Second), takeover)
				won = true
			}
			// stole=false: the incumbent heartbeated between our read and the CAS, or
			// a peer candidate won the same race. Either way someone live holds it.
		}
	}
	if !won {
		who := "another session"
		if holder != nil {
			age := time.Since(holder.LockedAt).Round(time.Second)
			who = fmt.Sprintf("%s on %s (held %s)", holder.LockedBy, holder.Host, age)
			// Make an un-reclaimable sentinel LOUD. Silence here is what turned a
			// reboot into a half-day landing outage: the message read exactly the
			// same at 2 minutes as at 11 hours, so the 2-minute election timer
			// looked healthy while nothing was landing.
			if takeover, _ := resolveLandLeaderTakeover(*takeoverAfter, *gateTimeout); takeover <= 0 && age > landqSentinelSuspectAge {
				fmt.Printf("landq run: ⚠ %s has been held %s with takeover DISABLED — if that runner is gone the queue is stranded.\n"+
					"  check:    pgrep -af '[l]andq run'\n"+
					"  recover:  taskdb lockserver unlock %s --force\n",
					landLeaderSentinel, age, landLeaderSentinel)
			}
		}
		fmt.Printf("another runner holds %s — %s; this runner exits.\n", landLeaderSentinel, who)
		return nil
	}
	defer func() { _, _ = ls.releaseLandLeader(sess) }()

	repo, err := repoRoot()
	if err != nil {
		return fmt.Errorf("locating repo root: %w", err)
	}

	// Leaked-worktree sweep (#15): a PRIOR runner that crashed mid-land (SIGKILL /
	// power loss) leaves its `ds-landq-merge-*` throwaway worktree behind. Now that
	// we are the sole elected leader, reclaim that disk before draining the queue —
	// `git worktree prune` clears dead admin entries, then any orphan merge dir
	// under DS_WT_ROOT/$HOME/tmp that is NOT a currently-registered worktree is
	// removed. Best-effort: a sweep error never blocks landing.
	if n, serr := sweepStaleMergeWorktrees(repo); serr != nil {
		fmt.Printf("landq run: stale merge-worktree sweep error (non-fatal): %v\n", serr)
	} else if n > 0 {
		fmt.Printf("landq run: swept %d stale merge worktree(s) from a crashed prior runner\n", n)
	}

	// Graceful leadership handoff: on SIGTERM/SIGINT (systemctl stop/restart, Ctrl-C)
	// stop BETWEEN passes — never mid-land — so the deferred releaseLandLeader fires
	// and the next runner wins the sentinel IMMEDIATELY. This is still the fast path
	// and the only one that costs zero downtime.
	//
	// A hard kill (SIGKILL / crash / power loss / reboot) cannot run the deferred
	// release, and reap() excludes the sentinel from its blanket age-DELETE, so the
	// orphaned sentinel is now cleared by the --takeover-after reclaim above (a
	// candidate steals it once the heartbeat has been silent past the threshold).
	// `taskdb lockserver unlock __land_leader__ --force` remains the INSTANT manual
	// recovery, and the only recovery when takeover is disabled (--takeover-after=0)
	// — see LANDQ-RUNBOOK.md. systemd must allow an in-flight land to finish: set
	// TimeoutStopSec above the slowest land.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	stop := func(s os.Signal) {
		fmt.Printf("landq run: received %s — releasing %s, exiting cleanly\n", s, landLeaderSentinel)
	}

	// Orphaned-lock auto-reap cadence (docs/23 OQ4, re-scoped 2026-07-02): the
	// supervised always-on leader is the natural home for a background sweep of
	// stale wave locks, so a crashed unit's hold ages out without any operator
	// running a reap verb. Rate-limited to once per landqAutoReapEveryIdle idle
	// ticks (not every ~2s idle beat) so the poll loop stays cheap; the reap is
	// still fail-open and a no-op when TASKDB_LOCK_AUTOREAP_AGE disables it.
	idleReapTick := 0

	for {
		// Check for a stop signal BETWEEN passes so we never abandon a land mid-push.
		select {
		case s := <-sigCh:
			stop(s)
			return nil
		default:
		}
		// Re-validate ownership of the election sentinel BEFORE moving main. If a
		// force-unlock or a reap (despite the exclusion) freed it and a second
		// runner re-won it, we must STOP rather than race a second writer onto main.
		// A transient read error is non-fatal (don't strand the queue on a blip).
		if h, herr := ls.holder(landLeaderSentinel); herr == nil {
			if h == nil || h.LockedBy != sess {
				who := "nobody"
				if h != nil {
					who = h.LockedBy
				}
				fmt.Printf("landq run: lost %s (now held by %s) — exiting to avoid a double writer\n",
					landLeaderSentinel, who)
				return nil
			}
		}
		// --batch dispatch. N<=1 is the DEFAULT serial path: it calls the UNCHANGED
		// landOnePass byte-for-byte, so the live behavior (and every existing T3
		// runner test) is unaffected. The merge-train (landTrainPass) is reached ONLY
		// when an operator deliberately passes --batch>1 — see the flag help and
		// doc 27 §3 (bench-gated on real-gates/landing > 1.3).
		// Hold the sentinel fresh for the WHOLE pass, not just its first instant.
		// The merge+gate can run for --gate-timeout (20m by default) without
		// otherwise touching locked_at, which would leave a live leader looking
		// indistinguishable from a crashed one to any staleness check.
		stopHB := startLeaderHeartbeat(ls, sess, landqLeaderHeartbeatEvery)
		var landed bool
		if *batch > 1 {
			landed, err = landTrainPass(ls, repo, sess, *mainBranch, *gate, *age, *gateTimeout, *maxAttempts, *batch, *dryRun, !*noCanonicalSync)
		} else {
			landed, err = landOnePass(ls, repo, sess, *mainBranch, *gate, *age, *gateTimeout, *maxAttempts, *dryRun, !*noCanonicalSync)
		}
		stopHB()
		if err != nil {
			return err
		}
		if *once {
			return nil
		}
		if !landed {
			// Queue drained: idle a beat, but keep the sentinel fresh so a slow
			// idle daemon isn't reaped out from under itself. Wake EARLY on a stop
			// signal so a restart is prompt, not delayed by a full --sleep window.
			_ = ls.heartbeatLandLeader(sess)
			// Background orphaned-lock sweep, guarded by the age knob and rate-limited
			// so it runs about once per landqAutoReapEveryIdle idle ticks rather than
			// every beat. reap() is activity-aware + sentinel-excluding, so a live
			// heartbeating holder and __land_leader__ (this very leader) are never
			// evicted; fail-open, a reap error never disturbs the loop.
			if a := autoReapAge(); a > 0 {
				idleReapTick++
				if idleReapTick >= landqAutoReapEveryIdle {
					idleReapTick = 0
					if freed, rerr := ls.reap(a); rerr == nil {
						for _, id := range freed {
							fmt.Printf("landq run: auto-reaped stale orphaned lock %s (age > %s)\n", id, a)
						}
					}
				}
			}
			select {
			case s := <-sigCh:
				stop(s)
				return nil
			case <-time.After(*sleep):
			}
		}
	}
}

// --- operator controls (the LOUD consumer verbs) ---
//
// reap / cancel / requeue are operator-facing queue surgery, so — like the
// lockserver reap/unlock verbs and unlike the fail-open enqueue/list/status —
// they go through mustLockServer(): on a disabled/unreachable server they ERROR
// LOUDLY rather than silently no-op, because an operator who types `landq cancel`
// against a down tunnel must NOT be told it worked when nothing happened.

// cmdLandqReap returns orphaned 'landing' rows (a dead runner that never finished)
// back to 'queued' so the next runner re-attempts them, wrapping reapStaleLanding
// (T3). Mirrors `lockserver reap`'s shape: LOUD via mustLockServer, an --age
// window (default 30m, matching `landq run`'s --age), --dry-run (report without
// mutating), and --json. --dry-run lists the current 'landing' rows whose
// started_at has aged past the cutoff WITHOUT touching any row; the real path
// calls reapStaleLanding and reports the requeued ids.
func cmdLandqReap(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("landq reap", flag.ContinueOnError)
	age := fs.Duration("age", 30*time.Minute, "requeue 'landing' rows whose started_at is older than this")
	dryRun := fs.Bool("dry-run", false, "report what WOULD be reaped without mutating any row")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ls, err := mustLockServer()
	if err != nil {
		return err
	}
	defer ls.close()

	var reaped []int64
	if *dryRun {
		// Compute the would-reap set WITHOUT mutating via listStaleLanding, which
		// runs the SAME server-side staleness predicate as reapStaleLanding
		// (started_at < now() - make_interval) but as a SELECT. The whole comparison
		// happens in Postgres, so the dry-run preview can never disagree with the real
		// reap — and we never round-trip a to_char timestamp through a Go layout
		// (Postgres `to_char(..., 'OF')` renders a whole-hour UTC offset as "+00",
		// which no single Go reference layout parses; the previous string-parse path
		// silently excluded EVERY row on the UTC production server, a false negative).
		reaped, err = ls.listStaleLanding(*age)
		if err != nil {
			return fmt.Errorf("listing stale landing rows for dry-run: %w", err)
		}
	} else {
		reaped, err = ls.reapStaleLanding(*age)
		if err != nil {
			return fmt.Errorf("reaping stale landing rows: %w", err)
		}
	}

	if *asJSON {
		if reaped == nil {
			reaped = []int64{}
		}
		return printJSON(reaped)
	}
	if len(reaped) == 0 {
		fmt.Println("nothing to reap")
		return nil
	}
	verb := "reaped"
	if *dryRun {
		verb = "would reap"
	}
	for _, id := range reaped {
		fmt.Printf("%s #%d back to queued\n", verb, id)
	}
	return nil
}

// cmdLandqCancel is the operator stop: drive a 'queued'|'landing' entry to
// 'cancelled'. The id is the numeric BIGSERIAL land_queue id (NOT a ULID task
// prefix), so it is parsed with strconv.ParseInt — a non-numeric id is a clean
// error, never a silent zero-match. LOUD via mustLockServer. cancelLand's status
// guard means a row not in a cancellable state (or a missing id) returns false,
// surfaced here as a real error so the operator knows nothing changed.
func cmdLandqCancel(db *sql.DB, args []string) error {
	id, _, err := peelID(args, "taskdb landq cancel <id>")
	if err != nil {
		return err
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("landq cancel: <id> must be a numeric queue id, got %q", id)
	}
	ls, err := mustLockServer()
	if err != nil {
		return err
	}
	defer ls.close()
	ok, err := ls.cancelLand(n)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("landq #%d not found or not in a cancellable state (queued|landing)", n)
	}
	fmt.Printf("cancelled #%d\n", n)
	return nil
}

// cmdLandqRequeue is the operator re-drive: drive a 'failed'|'conflict'|
// 'cancelled' entry back to 'queued' (clearing runner/started_at/finished_at/
// detail) so the runner repicks it. Same numeric-id parse + LOUD mustLockServer
// shape as cancel. requeueLand's status guard makes a row not in a requeueable
// state (or a missing id) return false, surfaced here as a real error.
func cmdLandqRequeue(db *sql.DB, args []string) error {
	id, _, err := peelID(args, "taskdb landq requeue <id>")
	if err != nil {
		return err
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("landq requeue: <id> must be a numeric queue id, got %q", id)
	}
	ls, err := mustLockServer()
	if err != nil {
		return err
	}
	defer ls.close()
	ok, err := ls.requeueLand(n)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("landq #%d not found or not in a requeueable state (failed|conflict|cancelled)", n)
	}
	fmt.Printf("requeued #%d -> queued\n", n)
	return nil
}

// landOnePass runs ONE iteration of the runner loop: heartbeat the sentinel, reap
// stale 'landing' rows, fetch main, claim the next queued row, merge it under
// origin/<main> in a throwaway worktree, gate it, and (green) FF-push it to main.
// Returns landed=true when it claimed and processed a row (regardless of the
// land's outcome — conflict/failed/landed all count as "did work"), landed=false
// when the queue was empty. Every row transition emits best-effort telemetry and
// always cleans up its throwaway worktree.
// transientCapHit reports whether a TRANSIENT gate failure on a row that has now
// been claimed `attempts` times should be parked terminally ('failed') instead of
// requeued. claimNextLand bumps attempts on every claim, so this bounds how many
// times a gate that can never RUN (missing toolchain, perpetual timeout) requeues
// at the head of the serial queue before we stop starving the branches behind it.
// maxAttempts <= 0 means unbounded (never cap). A real RED gate parks immediately
// regardless and never reaches this path.
func transientCapHit(attempts, maxAttempts int) bool {
	return maxAttempts > 0 && attempts >= maxAttempts
}

func landOnePass(ls *lockServer, repo, session, mainBranch, gate string, age, gateTimeout time.Duration, maxAttempts int, dryRun, syncCanonical bool) (landed bool, err error) {
	// Keep the leader sentinel fresh BEFORE the (potentially slow) merge+gate so a
	// long land doesn't let the sentinel age out and a second writer win.
	// heartbeatLandLeader bumps the sentinel's task_locks.locked_at (the column
	// reap() compares) AND reap() now excludes the sentinel outright, so the
	// election can no longer be reaped from under a live leader.
	_ = ls.heartbeatLandLeader(session)

	// Recover a dead peer's orphaned in-flight rows before claiming.
	if requeued, rerr := ls.reapStaleLanding(age); rerr == nil {
		for _, id := range requeued {
			fmt.Printf("reaped stale landing row #%d back to queued\n", id)
		}
	}

	// Refresh main so the merge is against the latest origin tip.
	if out, ferr := runGit(repo, "fetch", "origin", mainBranch); ferr != nil {
		return false, fmt.Errorf("git fetch origin %s: %v\n%s", mainBranch, ferr, out)
	}

	entry, err := ls.claimNextLand(session)
	if err != nil {
		return false, fmt.Errorf("claiming next land row: %w", err)
	}
	if entry == nil {
		return false, nil // queue drained
	}
	emitLandEvent(ls, entry, session, "claimed", "landing")

	// A clean throwaway worktree DETACHED at origin/<main> so HEAD == origin/<main>
	// is the FIRST parent of the merge (origin under ours, the rewind-proof shape).
	wt, werr := makeThrowawayWorktree(repo, mainBranch)
	if werr != nil {
		// Couldn't even stage the land: requeue by leaving it via the reaper. Mark
		// failed with the reason so an operator sees it; the reaper would also
		// recover it, but a hard tooling error is worth surfacing as failed.
		_ = ls.setLandStatus(entry.ID, "failed", withDetail("worktree setup: "+compactErr(werr)), landFinished())
		emitLandEvent(ls, entry, session, "status-change", "failed")
		return true, nil
	}
	defer removeThrowawayWorktree(repo, wt)

	// The entry branch lives on ORIGIN (the producer pushed it before enqueuing),
	// not necessarily as a local ref in this fresh throwaway worktree — fetch it to
	// FETCH_HEAD and resolve its tip sha. A fetch failure here means the branch is
	// gone from origin (deleted/never-pushed): a real failure, not a conflict.
	branchSHA, ferr := fetchEntryBranch(wt, entry.Branch)
	if ferr != nil {
		_ = ls.setLandStatus(entry.ID, "failed", withDetail("fetch branch: "+compactErr(ferr)), landFinished())
		emitLandEvent(ls, entry, session, "status-change", "failed")
		fmt.Printf("#%d %s: branch not fetchable from origin: %v\n", entry.ID, entry.Branch, ferr)
		return true, nil
	}

	// Idempotent already-landed short-circuit (#16): if the branch tip is ALREADY
	// an ancestor of origin/<main>, a prior land (or a runner that FF-pushed then
	// died before flipping the row, which the reaper requeued) already merged it —
	// mark landed and skip the redundant re-merge/re-push. branchSHA is resolved
	// from the THROWAWAY WORKTREE's OWN FETCH_HEAD (just above), NEVER the shared
	// canonical-repo FETCH_HEAD: concurrent parallel-session fetches into the main
	// repo clobber that single file, which once made this check read a DIFFERENT
	// branch's already-on-main sha and falsely short-circuit (#4560). origin/<main>
	// is a shared remote ref (refreshed by the fetch above), valid in the worktree.
	if isAncestor(wt, branchSHA, "origin/"+mainBranch) {
		_ = ls.setLandStatus(entry.ID, "landed", withMergeCommit(branchSHA), landFinished())
		emitLandEvent(ls, entry, session, "status-change", "landed")
		fmt.Printf("#%d %s: already landed (idempotent)\n", entry.ID, entry.Branch)
		return true, nil
	}

	// Merge the entry branch INTO origin/<main> (origin is parent #1). --no-ff so
	// the merge commit always exists and carries the branch as a clear second
	// parent. We merge the explicit fetched sha. We never rebase and never --force.
	//
	// mergeEntryBranch absorbs the seed conflict class: between this branch's BASE
	// and current main a parallel session PRUNED some tasks/*.json the branch
	// still carries, so git reports a TREE-level modify/delete BEFORE the union
	// merge driver can reach them. tasks/*.json are disposable, re-freezable
	// coordination state, so a tasks/-only conflict is auto-resolved in place
	// (honoring main's prune) and the land continues; a conflict touching ANY
	// non-tasks/ path still BLOCKS (re-dispatch).
	outcome, ok, mergeOut, merr := mergeEntryBranch(wt, entry, branchSHA)
	if !ok {
		// Couldn't even enumerate the conflict: preserve the original
		// abort+mark-conflict behavior.
		conflicted := conflictedFiles(wt)
		detail := "merge conflict"
		if conflicted != "" {
			detail += ": " + conflicted
		}
		_ = runGitIgnore(wt, "merge", "--abort")
		_ = ls.setLandStatus(entry.ID, "conflict", withDetail(detail), landFinished())
		emitLandEvent(ls, entry, session, "status-change", "conflict")
		fmt.Printf("#%d %s: conflict (%s) [%v]\n%s\n", entry.ID, entry.Branch, conflicted, merr, mergeOut)
		return true, nil
	}
	if outcome.blocked {
		_ = ls.setLandStatus(entry.ID, "conflict", withDetail(outcome.blockDetail), landFinished())
		emitLandEvent(ls, entry, session, "status-change", "conflict")
		fmt.Printf("#%d %s: conflict (%s)\n%s\n", entry.ID, entry.Branch, outcome.blockDetail, mergeOut)
		return true, nil
	}
	if len(outcome.autoResolved) > 0 {
		fmt.Printf("#%d %s: auto-resolved %d tasks/-only modify/delete conflict(s) (honored main's prune): %s\n",
			entry.ID, entry.Branch, len(outcome.autoResolved), strings.Join(outcome.autoResolved, ", "))
	}

	// Run the gate ONCE in the merged worktree. PER-ROW PRECEDENCE: the row's own
	// gate (carried from the enqueuer, e.g. the wave's real compose-build) overrides
	// the runner's static --gate for THIS branch; an empty row-gate falls back to
	// the static --gate (today's behavior). Default (both empty) is a no-op pass.
	effGate := gate
	if entry.Gate != "" {
		effGate = entry.Gate
	}
	if effGate != "" {
		gr := runGate(wt, effGate, gateTimeout)
		if !gr.ok {
			tail := gateTail(gr.out)
			if gr.transient {
				// Timeout / missing toolchain / signal death: NOT a red gate.
				// Requeue the row so a transient stall self-recovers instead of
				// permanently burning the branch.
				reason := fmt.Sprintf("gate transient (exit %d): %s", gr.exitCode, tail)
				if gr.timedOut {
					reason = fmt.Sprintf("gate timed out after %s: %s", gateTimeout, tail)
				}
				if gr.exhausted != "" {
					// Name the resource, and say plainly that the branch is not
					// implicated — this detail is what an operator reads first.
					reason = fmt.Sprintf("gate hit RESOURCE EXHAUSTION (%s) on the leader box, not a code failure — "+
						"check free space/quota on TMPDIR (%s) and DS_WT_ROOT: %s",
						gr.exhausted, gateScratchDir(), tail)
				}
				// Per-row cap: claimNextLand bumps attempts on EVERY claim, so
				// entry.Attempts is how many times this row has been (re)attempted.
				// Without a cap a gate that can never RUN on the leader box (e.g. a
				// toolchain missing from PATH, a permanently-timing-out build) would
				// requeue forever AT THE HEAD of the serial queue and starve every
				// branch behind it. After maxAttempts, park it terminally so an
				// operator sees it — a real RED gate already parks immediately below.
				if transientCapHit(entry.Attempts, maxAttempts) {
					detail := fmt.Sprintf("gate transient on %d attempt(s), giving up (max-attempts=%d): %s",
						entry.Attempts, maxAttempts, reason)
					_ = ls.setLandStatus(entry.ID, "failed", withDetail(detail), landFinished())
					emitLandEvent(ls, entry, session, "status-change", "failed")
					fmt.Printf("#%d %s: gate TRANSIENT cap hit — FAILED (%s)\n", entry.ID, entry.Branch, detail)
					return true, nil
				}
				_ = ls.setLandStatus(entry.ID, "queued",
					withDetail(reason), landRunner(""), landStartedNull())
				emitLandEvent(ls, entry, session, "status-change", "queued")
				fmt.Printf("#%d %s: gate TRANSIENT — requeued (attempt %d/%d) (%s)\n",
					entry.ID, entry.Branch, entry.Attempts, maxAttempts, reason)
				return true, nil
			}
			// A clean non-zero exit: a real RED gate. Park the row terminally with
			// the most diagnostic fact (the exit code) in the detail.
			detail := fmt.Sprintf("gate red (exit %d): %s", gr.exitCode, tail)
			_ = ls.setLandStatus(entry.ID, "failed", withDetail(detail), landFinished())
			emitLandEvent(ls, entry, session, "status-change", "failed")
			fmt.Printf("#%d %s: gate FAILED\n%s\n", entry.ID, entry.Branch, detail)
			return true, nil
		}
	}

	// Green. Resolve the merge HEAD sha we intend to land.
	sha, serr := gitHead(wt)
	if serr != nil {
		return false, fmt.Errorf("resolving merge HEAD: %w", serr)
	}

	if dryRun {
		// Exercise the whole green path WITHOUT moving main: leave the row queued
		// so a real runner still lands it, and note the dry-run.
		_ = ls.setLandStatus(entry.ID, "queued",
			withDetail(fmt.Sprintf("dry-run: would push %s to %s", sha, mainBranch)))
		emitLandEvent(ls, entry, session, "dry-run", "queued")
		fmt.Printf("#%d %s: would push %s to %s (dry-run; row left queued)\n",
			entry.ID, entry.Branch, sha, mainBranch)
		return true, nil
	}

	// Real land: FF-only push of the explicit merge SHA. Under the single-writer
	// sentinel this cannot be peer-rejected; the up-to-5 retry only handles the
	// tiny race where origin moved between our fetch and push (re-merge on top).
	if perr := pushLand(ls, repo, wt, entry, mainBranch, session); perr != nil {
		_ = ls.setLandStatus(entry.ID, "failed", withDetail("push: "+compactErr(perr)), landFinished())
		emitLandEvent(ls, entry, session, "status-change", "failed")
		fmt.Printf("#%d %s: push failed: %v\n", entry.ID, entry.Branch, perr)
		return true, nil
	}
	sha, _ = gitHead(wt) // re-read: a retry may have re-created the merge commit
	_ = ls.setLandStatus(entry.ID, "landed", withMergeCommit(sha), landFinished())
	emitLandEvent(ls, entry, session, "status-change", "landed")
	// Landing is the GLOBAL-visibility chokepoint (docs/23 Proposal A; doc 27
	// Lever 3): the work is now on origin/main but other clones have not yet
	// pulled it, so tombstone EACH landed task_id here too — this protects clones
	// that never saw the release-path tombstone (e.g. a wave whose units finished
	// on a different machine). Best-effort, never fatal, mirroring emitLandEvent's
	// posture. ON CONFLICT(task_id) DO UPDATE makes this idempotent with the
	// release-path upsert, so the double-write is free. ONLY on the REAL-push
	// branch — the dry-run/conflict/failed/idempotent-short-circuit branches do
	// NOT tombstone (a branch we did not actually push must not gate claims).
	// F9 defense-in-depth: tombstone ONLY ids that are terminal in the tree we just
	// landed — a non-terminal id leaked into --tasks (stale tree / hand enqueue) is
	// skipped+warned, never falsely marked done cross-machine.
	tombstoneLandedTasks(ls, wt, sha, entry.TaskIDs, session, entry.ID, entry.Branch)
	fmt.Printf("#%d %s: LANDED %s onto %s\n", entry.ID, entry.Branch, sha, mainBranch)
	// Keep THIS box's canonical checkout current with the tip we just pushed, so it
	// stops drifting behind the queue it serves (best-effort; never fails the land).
	if syncCanonical {
		syncCanonicalToOrigin(repo, mainBranch)
	}
	return true, nil
}

// --- merge-train batcher (DORMANT; doc 27 §3 Deferred) -----------------------
//
// EVERYTHING below in this section is unreachable on the default serial path.
// `landq run` only calls landTrainPass when an operator passes --batch>1; with
// the default --batch 1 the runner takes the byte-identical landOnePass path and
// none of this code executes. The capability is built but DORMANT, and its
// activation is BENCH-GATED: build/run the train only once wavebench (doc 27
// Lever 0) shows real-gates/landing > 1.3 — i.e. the serial queue is actually
// gate-bound. A train trades a WIDER blast radius on a red gate (a whole batch
// re-gates / requeues) for FEWER gate runs, so it only pays off when gates, not
// landings, are the bottleneck. GO4 takes NO compile-time dependency on the
// bench scorer (GO3); the >1.3 trigger is an operator decision, documented here
// and in the --batch flag help and usage().

// trainMember pairs a claimed land row with the per-row merge facts the train
// needs (its fetched tip sha, and whether it short-circuited as already-landed).
type trainMember struct {
	entry     *LandEntry
	branchSHA string // resolved tip of the entry branch in the throwaway worktree
	alreadyIn bool   // already an ancestor of origin/<main> (idempotent skip)
}

// bisectGreenPrefix is the PURE, git/Postgres-FREE core of split-bisection. Given
// `items` (a train of land members in pick order) and a `gate` predicate that
// reports whether the PREFIX items[:k] is green, it binary-searches the LARGEST k
// in [0,len] such that gate(items[:k]) is green, returning that k. items[k] (when
// k<len) is therefore the FIRST red member — the culprit. The empty prefix
// gate(items[:0]) is assumed green (nothing assembled = origin/<main> unchanged),
// which holds for the real predicate (an empty train trivially passes its gate).
//
// MONOTONICITY ASSUMPTION: the predicate is treated as monotone in the prefix —
// once a prefix is red, every LONGER prefix is red. This is the standard
// merge-train bisection model (a member that breaks the build keeps it broken as
// more are stacked on top). Under it the binary search is correct and runs in
// O(log n) gate evaluations instead of the O(n) of a linear scan. The unit test
// pins this with a synthetic "green iff no member == BAD" predicate (monotone)
// across green-all / red-first / red-middle / red-last / single-red / empty.
func bisectGreenPrefix[T any](items []T, gate func(prefix []T) bool) int {
	// Invariant: gate(items[:lo]) is green; gate(items[:hi]) is unknown/red.
	// Start lo=0 (empty prefix green by assumption), hi=len(items).
	lo, hi := 0, len(items)
	// Fast path: the whole train is green — no red member.
	if gate(items[:hi]) {
		return hi
	}
	// Binary-search the boundary: the largest green prefix length.
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		if gate(items[:mid]) {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo
}

// landTrainPass is the N>1 sibling of landOnePass: it claims up to batchN queued
// rows and lands them as a MERGE TRAIN under a SINGLE gate run, with
// split-bisection on a red gate. It preserves landOnePass's rewind-proof
// invariants verbatim: the throwaway worktree is detached at origin/<main> so
// origin is parent #1 of every merge; the push is FF-only of the explicit SHA via
// pushLand; the merge is never rebased and never --force'd; the worktree is always
// cleaned up. It is DORMANT — reached only via `landq run --batch N>1`.
//
// PER-ROW GATE CONSTRAINT: a train runs ONE gate over the assembled batch, so it
// uses the runner's static --gate (NOT any member's per-row entry.Gate — a single
// worktree cannot honor N different gates). If any claimed member carries its own
// per-row gate, that member is NOT safe to fold into a shared-gate train, so the
// train REQUEUES it untouched (it lands later via a --batch 1 pass or its own
// runner). This keeps the per-row-gate contract (landOnePass's precedence) intact:
// a row that needs its own gate never rides a train that would run a different one.
func landTrainPass(ls *lockServer, repo, session, mainBranch, gate string, age, gateTimeout time.Duration, maxAttempts, batchN int, dryRun, syncCanonical bool) (landed bool, err error) {
	// Same preamble as landOnePass: heartbeat the sentinel, recover a dead peer's
	// orphaned in-flight rows, refresh main.
	_ = ls.heartbeatLandLeader(session)
	if requeued, rerr := ls.reapStaleLanding(age); rerr == nil {
		for _, id := range requeued {
			fmt.Printf("reaped stale landing row #%d back to queued\n", id)
		}
	}
	if out, ferr := runGit(repo, "fetch", "origin", mainBranch); ferr != nil {
		return false, fmt.Errorf("git fetch origin %s: %v\n%s", mainBranch, ferr, out)
	}

	entries, err := ls.claimNextLandBatch(session, batchN)
	if err != nil {
		return false, fmt.Errorf("claiming land batch: %w", err)
	}
	if len(entries) == 0 {
		return false, nil // queue drained
	}

	// Per-row-gate members can't ride a shared-gate train: requeue them cleanly so
	// a later pass (a --batch 1 serial runner, or its own runner) honors their gate.
	// Keep only the shared-gate members for the train.
	var train []*LandEntry
	for _, e := range entries {
		if e.Gate != "" {
			_ = ls.setLandStatus(e.ID, "queued",
				withDetail("requeued: per-row gate cannot ride a --batch>1 shared-gate train"),
				landRunner(""), landStartedNull())
			emitLandEvent(ls, e, session, "status-change", "queued")
			fmt.Printf("#%d %s: per-row gate — requeued out of the train (lands serially)\n", e.ID, e.Branch)
			continue
		}
		train = append(train, e)
	}
	if len(train) == 0 {
		// We DID claim+process rows (all requeued), so this pass did work.
		return true, nil
	}
	for _, e := range train {
		emitLandEvent(ls, e, session, "claimed", "landing")
	}

	// ONE throwaway worktree detached at origin/<main> — origin is parent #1 of the
	// whole train, the rewind-proof shape. Reused for the train assembly AND for
	// each bisection candidate (reset --hard between assemblies).
	wt, werr := makeThrowawayWorktree(repo, mainBranch)
	if werr != nil {
		// Couldn't even stage: requeue the whole train so the next pass repicks it.
		for _, e := range train {
			_ = ls.setLandStatus(e.ID, "queued",
				withDetail("train worktree setup: "+compactErr(werr)), landRunner(""), landStartedNull())
			emitLandEvent(ls, e, session, "status-change", "queued")
		}
		return true, nil
	}
	defer removeThrowawayWorktree(repo, wt)

	// Resolve each member's tip sha and short-circuit already-landed members.
	members := make([]trainMember, 0, len(train))
	for _, e := range train {
		branchSHA, ferr := fetchEntryBranch(wt, e.Branch)
		if ferr != nil {
			// Branch gone from origin: a real failure for THIS member. Mark it failed
			// and drop it from the train; the rest still proceed.
			_ = ls.setLandStatus(e.ID, "failed", withDetail("fetch branch: "+compactErr(ferr)), landFinished())
			emitLandEvent(ls, e, session, "status-change", "failed")
			fmt.Printf("#%d %s: branch not fetchable from origin: %v\n", e.ID, e.Branch, ferr)
			continue
		}
		alreadyIn := isAncestor(wt, branchSHA, "origin/"+mainBranch)
		if alreadyIn {
			_ = ls.setLandStatus(e.ID, "landed", withMergeCommit(branchSHA), landFinished())
			emitLandEvent(ls, e, session, "status-change", "landed")
			fmt.Printf("#%d %s: already landed (idempotent)\n", e.ID, e.Branch)
			continue
		}
		members = append(members, trainMember{entry: e, branchSHA: branchSHA})
	}
	if len(members) == 0 {
		return true, nil // all members were already-landed / unfetchable
	}

	// assembleTrain resets the worktree to a fresh origin/<main> and stack-merges the
	// given members IN ORDER. It returns the merged HEAD sha and ok=false if ANY
	// member fails to merge cleanly (a real code conflict OR a union-driver-refused
	// tasks/ conflict) — a member that won't even merge is, for bisection purposes,
	// treated EXACTLY like a red one (the gate predicate folds "won't merge" into
	// "not green"). On a clean assembly the merge is COMPLETE on the worktree HEAD.
	assembleTrain := func(ms []trainMember) (head string, blockIdx int, ok bool) {
		if o, rerr := runGit(wt, "reset", "--hard", "origin/"+mainBranch); rerr != nil {
			fmt.Printf("train: reset to origin/%s failed: %v\n%s\n", mainBranch, rerr, o)
			return "", -1, false
		}
		for i, m := range ms {
			outcome, mok, mergeOut, merr := mergeEntryBranch(wt, m.entry, m.branchSHA)
			if !mok {
				_ = runGitIgnore(wt, "merge", "--abort")
				fmt.Printf("train: #%d %s unenumerable merge conflict [%v]\n%s\n", m.entry.ID, m.entry.Branch, merr, mergeOut)
				return "", i, false
			}
			if outcome.blocked {
				fmt.Printf("train: #%d %s blocked on merge (%s)\n", m.entry.ID, m.entry.Branch, outcome.blockDetail)
				return "", i, false
			}
			if len(outcome.autoResolved) > 0 {
				fmt.Printf("train: #%d %s auto-resolved %d tasks/-only conflict(s)\n", m.entry.ID, m.entry.Branch, len(outcome.autoResolved))
			}
		}
		h, herr := gitHead(wt)
		if herr != nil {
			return "", -1, false
		}
		return h, -1, true
	}

	// gatePrefix is the bisection predicate: assemble members[:k] on the fresh
	// worktree and run the runner's static --gate ONCE over it. Green iff the
	// assembly merged cleanly AND the gate passed (a non-mergeable prefix folds into
	// "not green"). An empty prefix is trivially green (origin/<main> unchanged). A
	// TRANSIENT gate outcome (timeout / missing toolchain / signal) is conservatively
	// treated as NOT green so the train never lands over an unverified prefix — the
	// requeued tail re-runs next pass.
	gatePrefix := func(prefix []trainMember) bool {
		if len(prefix) == 0 {
			return true
		}
		_, _, ok := assembleTrain(prefix)
		if !ok {
			return false
		}
		if gate == "" {
			return true // no gate configured: a clean assembly is "green"
		}
		gr := runGate(wt, gate, gateTimeout)
		return gr.ok
	}

	// Try the WHOLE train first (the common, all-green case is a single gate run).
	if gatePrefix(members) {
		head, _, ok := assembleTrain(members) // re-assemble the verified train for the push
		if !ok {
			// Should not happen (we just gated this exact set green), but be safe.
			for _, m := range members {
				_ = ls.setLandStatus(m.entry.ID, "queued",
					withDetail("train re-assemble after green gate failed; requeued"),
					landRunner(""), landStartedNull())
				emitLandEvent(ls, m.entry, session, "status-change", "queued")
			}
			return true, nil
		}
		return finishTrainGreen(ls, repo, wt, members, head, mainBranch, session, dryRun, syncCanonical), nil
	}

	// RED train: bisect to the maximal green prefix; members[prefixLen] is the first
	// red. Land the green prefix, fail the first red, requeue the rest.
	prefixLen := bisectGreenPrefix(members, gatePrefix)
	greenPrefix := members[:prefixLen]
	var firstRed *trainMember
	var tail []trainMember
	if prefixLen < len(members) {
		firstRed = &members[prefixLen]
		tail = members[prefixLen+1:]
	}

	// Land the maximal green prefix (if any). gatePrefix already left the worktree
	// assembled at greenPrefix when prefixLen>0 and it was the last predicate call,
	// but bisection's last call is not guaranteed to be the prefix — re-assemble to
	// be certain before pushing.
	if prefixLen > 0 {
		head, _, ok := assembleTrain(greenPrefix)
		if !ok {
			for _, m := range greenPrefix {
				_ = ls.setLandStatus(m.entry.ID, "queued",
					withDetail("green-prefix re-assemble failed; requeued"),
					landRunner(""), landStartedNull())
				emitLandEvent(ls, m.entry, session, "status-change", "queued")
			}
		} else {
			_ = finishTrainGreen(ls, repo, wt, greenPrefix, head, mainBranch, session, dryRun, syncCanonical)
		}
	}

	// Fail the first red member with a diagnostic detail.
	if firstRed != nil {
		detail := "split-bisection: first red member of a --batch train"
		if gate != "" {
			// Re-assemble just the prefix+this member and capture the gate tail for
			// the operator; best-effort (its failure doesn't change the verdict).
			if _, _, ok := assembleTrain(members[:prefixLen+1]); ok {
				gr := runGate(wt, gate, gateTimeout)
				if !gr.ok {
					detail = fmt.Sprintf("split-bisection red (gate exit %d): %s", gr.exitCode, gateTail(gr.out))
				}
			} else {
				detail = "split-bisection: first member that fails to MERGE onto the green prefix"
			}
		}
		_ = ls.setLandStatus(firstRed.entry.ID, "failed", withDetail(detail), landFinished())
		emitLandEvent(ls, firstRed.entry, session, "status-change", "failed")
		fmt.Printf("#%d %s: TRAIN RED — failed (%s)\n", firstRed.entry.ID, firstRed.entry.Branch, detail)
	}

	// Requeue every member AFTER the first red so the next pass repicks them in
	// order (runner cleared, started_at NULLed — the same clean reset the transient
	// requeue uses; attempts was already bumped by the batch claim so the max-attempts
	// cap still bounds re-picks).
	for _, m := range tail {
		_ = ls.setLandStatus(m.entry.ID, "queued",
			withDetail("requeued behind a split-bisection red member"),
			landRunner(""), landStartedNull())
		emitLandEvent(ls, m.entry, session, "status-change", "queued")
		fmt.Printf("#%d %s: requeued (behind train red)\n", m.entry.ID, m.entry.Branch)
	}
	return true, nil
}

// finishTrainGreen FF-pushes a gate-green assembled train HEAD once and marks every
// member 'landed' (+ tombstone + event), or — on --dry-run — requeues the members
// without pushing. The worktree is already assembled at `head` (origin/<main> is
// parent #1 of the chain). Returns true (this pass did work) in all cases. The
// push reuses pushLand verbatim so the FF-only / single-writer / re-merge-on-retry
// invariants are identical to the serial path; on a push error every member is
// marked failed (the train did not land).
func finishTrainGreen(ls *lockServer, repo, wt string, members []trainMember, head, mainBranch, session string, dryRun, syncCanonical bool) bool {
	if dryRun {
		for _, m := range members {
			_ = ls.setLandStatus(m.entry.ID, "queued",
				withDetail(fmt.Sprintf("dry-run: would land in a train head %s to %s", head, mainBranch)))
			emitLandEvent(ls, m.entry, session, "dry-run", "queued")
			fmt.Printf("#%d %s: would land (train head %s, dry-run; row left queued)\n", m.entry.ID, m.entry.Branch, head)
		}
		return true
	}

	// Push the assembled train HEAD once. pushLand retries by re-fetching+re-merging
	// the LAST member's branch on a non-FF reject; for a train we instead re-push the
	// whole assembled head with a small retry on origin movement (the single-writer
	// sentinel makes a peer move nearly impossible). Reuse pushTrainHead.
	if perr := pushTrainHead(ls, repo, wt, members, mainBranch, session); perr != nil {
		for _, m := range members {
			_ = ls.setLandStatus(m.entry.ID, "failed", withDetail("train push: "+compactErr(perr)), landFinished())
			emitLandEvent(ls, m.entry, session, "status-change", "failed")
		}
		fmt.Printf("train: push failed: %v\n", perr)
		return true
	}
	sha, _ := gitHead(wt) // re-read: a retry may have re-created the merge chain
	for _, m := range members {
		_ = ls.setLandStatus(m.entry.ID, "landed", withMergeCommit(sha), landFinished())
		emitLandEvent(ls, m.entry, session, "status-change", "landed")
		// F9: same terminal-in-landed-tree gate as the serial path. The whole train
		// shares one assembled HEAD (sha), so every member's task files are present
		// in it — gate each id against that landed tree, skip+warn non-terminals.
		tombstoneLandedTasks(ls, wt, sha, m.entry.TaskIDs, session, m.entry.ID, m.entry.Branch)
		fmt.Printf("#%d %s: LANDED (train head %s) onto %s\n", m.entry.ID, m.entry.Branch, sha, mainBranch)
	}
	// Same canonical-checkout catch-up as the serial path (best-effort, never fatal).
	if syncCanonical {
		syncCanonicalToOrigin(repo, mainBranch)
	}
	return true
}

// pushTrainHead FF-only-pushes the assembled train HEAD to origin/<main>, retrying
// up to 5 times if origin moved between assembly and push by re-assembling the
// WHOLE train on the fresh tip (reset --hard origin/<main> + re-merge each member
// in order). NEVER --force, NEVER any ref other than a fast-forward to <main>,
// ALWAYS the explicit HEAD sha — identical posture to pushLand, generalized to N
// members. Under the single-writer sentinel a non-FF reject is nearly impossible;
// the retry only covers the tiny race where origin moved between our fetch and push.
func pushTrainHead(ls *lockServer, repo, wt string, members []trainMember, mainBranch, session string) error {
	const maxAttempts = 5
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		sha, err := gitHead(wt)
		if err != nil {
			return err
		}
		out, perr := runGit(wt, "push", "origin", sha+":refs/heads/"+mainBranch)
		if perr == nil {
			return nil // FF push of the whole train succeeded
		}
		lastErr = fmt.Errorf("git push (train) attempt %d: %v\n%s", attempt, perr, out)
		if attempt == maxAttempts {
			break
		}
		// origin moved: re-fetch and RE-ASSEMBLE the whole train on the new tip.
		if o, ferr := runGit(repo, "fetch", "origin", mainBranch); ferr != nil {
			lastErr = fmt.Errorf("re-fetch on train retry %d: %v\n%s", attempt, ferr, o)
			continue
		}
		if o, rerr := runGit(wt, "reset", "--hard", "origin/"+mainBranch); rerr != nil {
			lastErr = fmt.Errorf("reset to origin/%s on train retry %d: %v\n%s", mainBranch, attempt, rerr, o)
			continue
		}
		for _, m := range members {
			branchSHA, berr := fetchEntryBranch(wt, m.entry.Branch)
			if berr != nil {
				return fmt.Errorf("re-fetch train member %s on retry %d: %w", m.entry.Branch, attempt, berr)
			}
			outcome, ok, o, merr := mergeEntryBranch(wt, m.entry, branchSHA)
			if !ok || outcome.blocked {
				detail := outcome.blockDetail
				if detail == "" && merr != nil {
					detail = merr.Error()
				}
				// A member that merged clean a moment ago now genuinely conflicts with
				// the new tip — surface as a push error so the caller marks the train
				// failed (it did not land).
				return fmt.Errorf("re-merge train member %s on retry %d conflicted: %s\n%s", m.entry.Branch, attempt, detail, o)
			}
		}
		emitLandEvent(ls, members[0].entry, session, "push-retry", "landing")
	}
	return lastErr
}

// pushLand FF-only-pushes the worktree's merge HEAD to origin/<main>, retrying up
// to 5 times if origin moved in the race between fetch and push (re-fetching and
// re-merging the entry branch under the new tip each time). NEVER --force, NEVER
// any ref other than a fast-forward to <main>, ALWAYS the explicit HEAD sha.
func pushLand(ls *lockServer, repo, wt string, entry *LandEntry, mainBranch, session string) error {
	const maxAttempts = 5
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		sha, err := gitHead(wt)
		if err != nil {
			return err
		}
		out, perr := runGit(wt, "push", "origin", sha+":refs/heads/"+mainBranch)
		if perr == nil {
			return nil // FF push succeeded
		}
		lastErr = fmt.Errorf("git push attempt %d: %v\n%s", attempt, perr, out)
		if attempt == maxAttempts {
			break
		}
		// origin moved (non-FF reject): re-fetch and re-merge the entry branch on
		// top of the new tip, then retry the push. Reset the worktree to the fresh
		// origin/<main> and merge the branch in again (origin still parent #1).
		if o, ferr := runGit(repo, "fetch", "origin", mainBranch); ferr != nil {
			lastErr = fmt.Errorf("re-fetch on retry %d: %v\n%s", attempt, ferr, o)
			continue
		}
		if o, rerr := runGit(wt, "reset", "--hard", "origin/"+mainBranch); rerr != nil {
			lastErr = fmt.Errorf("reset to origin/%s on retry %d: %v\n%s", mainBranch, attempt, rerr, o)
			continue
		}
		branchSHA, berr := fetchEntryBranch(wt, entry.Branch)
		if berr != nil {
			return fmt.Errorf("re-fetch entry branch on retry %d: %w", attempt, berr)
		}
		// Re-merge under the fresh tip via the SAME tasks/-prune auto-resolve as the
		// initial land: the new tip may have pruned more tasks/*.json the branch
		// carries, which would otherwise surface as a spurious re-merge conflict.
		outcome, ok, o, merr := mergeEntryBranch(wt, entry, branchSHA)
		if !ok || outcome.blocked {
			// A branch that merged clean a moment ago now genuinely conflicts with
			// the new tip — surface as a push error so the caller marks it failed.
			detail := outcome.blockDetail
			if detail == "" && merr != nil {
				detail = merr.Error()
			}
			return fmt.Errorf("re-merge on retry %d conflicted: %s\n%s", attempt, detail, o)
		}
		if len(outcome.autoResolved) > 0 {
			fmt.Printf("#%d %s: re-merge auto-resolved %d tasks/-only conflict(s): %s\n",
				entry.ID, entry.Branch, len(outcome.autoResolved), strings.Join(outcome.autoResolved, ", "))
		}
		emitLandEvent(ls, entry, session, "push-retry", "landing")
	}
	return lastErr
}

// mergeWorktreePrefix is the os.MkdirTemp prefix for every throwaway land-merge
// worktree. The leaked-worktree sweep (sweepStaleMergeWorktrees) matches on it.
const mergeWorktreePrefix = "ds-landq-merge-"

// mergeWorktreeRoot is the parent dir for throwaway land-merge worktrees:
// DS_WT_ROOT when set, else $HOME/tmp (btrfs/CoW; never /tmp tmpfs). Shared by
// makeThrowawayWorktree (where it CREATEs) and sweepStaleMergeWorktrees (where it
// SCANs) so the two never disagree on where the dirs live.
func mergeWorktreeRoot() (string, error) {
	root := strings.TrimSpace(os.Getenv("DS_WT_ROOT"))
	if root == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", herr
		}
		root = filepath.Join(home, "tmp")
	}
	return root, nil
}

// sweepStaleMergeWorktrees reclaims throwaway land-merge worktrees leaked by a
// PRIOR runner that crashed mid-land (#15). The new elected leader calls it once,
// before draining the queue. It (1) runs `git worktree prune` to clear git's
// admin entries for gone worktrees, then (2) removes any directory under
// mergeWorktreeRoot() whose name starts with mergeWorktreePrefix that is NOT a
// currently-registered worktree of this repo. Returns the count removed.
//
// A currently-registered merge worktree (one this live process — or a concurrent
// one, though the single-leader sentinel makes that nearly impossible — is
// actively using) is identified via `git worktree list --porcelain` and is NEVER
// removed; only true orphans are swept. Best-effort: a missing root dir is "no
// orphans", not an error.
func sweepStaleMergeWorktrees(repo string) (int, error) {
	// Drop git's admin records for worktrees whose dirs are already gone.
	_ = runGitIgnore(repo, "worktree", "prune")

	root, err := mergeWorktreeRoot()
	if err != nil {
		return 0, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // no root yet → nothing to sweep
		}
		return 0, err
	}

	registered, rerr := registeredWorktreePaths(repo)
	if rerr != nil {
		// If we cannot enumerate the live worktrees, do NOT risk removing one we
		// are actively using — bail out rather than guess.
		return 0, rerr
	}

	removed := 0
	var firstErr error
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), mergeWorktreePrefix) {
			continue
		}
		path := filepath.Join(root, e.Name())
		if registered[filepath.Clean(path)] {
			continue // a live worktree — leave it alone
		}
		// Orphan: prefer `git worktree remove` (cleans any lingering admin record),
		// fall back to a raw RemoveAll so a dir git no longer tracks is still freed.
		if _, gerr := runGit(repo, "worktree", "remove", "--force", path); gerr != nil {
			if rmErr := os.RemoveAll(path); rmErr != nil {
				if firstErr == nil {
					firstErr = rmErr
				}
				continue
			}
		}
		removed++
	}
	return removed, firstErr
}

// registeredWorktreePaths returns the set of absolute, cleaned worktree paths git
// currently tracks for repo (from `git worktree list --porcelain`). Used by the
// leaked-worktree sweep to avoid removing a live worktree.
func registeredWorktreePaths(repo string) (map[string]bool, error) {
	out, err := runGit(repo, "worktree", "list", "--porcelain")
	if err != nil {
		return nil, fmt.Errorf("git worktree list: %v\n%s", err, out)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if p, ok := strings.CutPrefix(line, "worktree "); ok {
			set[filepath.Clean(strings.TrimSpace(p))] = true
		}
	}
	return set, nil
}

// makeThrowawayWorktree creates a clean DETACHED worktree at origin/<main> under
// ~/tmp (btrfs/CoW; never /tmp tmpfs). DS_WT_ROOT overrides the parent dir. The
// detach is what puts origin/<main> at HEAD so a subsequent `git merge <branch>`
// makes origin/<main> the FIRST parent. Caller must removeThrowawayWorktree it.
func makeThrowawayWorktree(repo, mainBranch string) (string, error) {
	root, rerr := mergeWorktreeRoot()
	if rerr != nil {
		return "", rerr
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", err
	}
	wt, err := os.MkdirTemp(root, mergeWorktreePrefix)
	if err != nil {
		return "", err
	}
	// os.MkdirTemp made the dir; `git worktree add` wants to create it, so remove
	// the empty placeholder first.
	if err := os.Remove(wt); err != nil {
		return "", err
	}
	if out, err := runGit(repo, "worktree", "add", "--detach", wt, "origin/"+mainBranch); err != nil {
		return "", fmt.Errorf("git worktree add: %v\n%s", err, out)
	}
	return wt, nil
}

// removeThrowawayWorktree force-removes the throwaway worktree (best-effort: a
// leftover is reapable by `git worktree prune`, so cleanup failure is logged, not
// fatal).
func removeThrowawayWorktree(repo, wt string) {
	if _, err := runGit(repo, "worktree", "remove", "--force", wt); err != nil {
		// Fall back to a raw rmdir + prune so we don't leak the dir.
		_ = os.RemoveAll(wt)
		_ = runGitIgnore(repo, "worktree", "prune")
	}
}

// emitLandEvent records a best-effort land-phase wave-event for a queue
// transition so wavebench (doc 27 Lever 0) can later score land_retry. NEVER
// fatal — telemetry must not break a land.
func emitLandEvent(ls *lockServer, entry *LandEntry, session, event, status string) {
	_ = ls.recordEvent(WaveEvent{
		Wave:    entry.Wave,
		RunID:   entry.RunID,
		TaskID:  entry.TaskIDs,
		Phase:   "land",
		Event:   event,
		Status:  status,
		Session: session,
		Host:    devHost(),
		Note:    fmt.Sprintf("landq #%d %s", entry.ID, entry.Branch),
	})
}

// --- small git/shell helpers (runner-local) ---

// runGit runs a git subcommand in dir and returns its combined output.
func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runGitIgnore runs a git subcommand, discarding its output (cleanup paths).
func runGitIgnore(dir string, args ...string) error {
	_, err := runGit(dir, args...)
	return err
}

// fetchEntryBranch fetches the entry branch from origin into the worktree's
// FETCH_HEAD and returns its resolved tip sha, ready to merge. The producer
// pushed the branch to origin before enqueuing, so it is fetched by name (it is
// not necessarily a local ref in this fresh detached worktree). An error here
// means the branch is absent from origin (deleted / never pushed) — a real
// failure the caller surfaces as 'failed', distinct from a merge conflict.
func fetchEntryBranch(wt, branch string) (string, error) {
	if out, err := runGit(wt, "fetch", "origin", branch); err != nil {
		return "", fmt.Errorf("git fetch origin %s: %v\n%s", branch, err, strings.TrimSpace(out))
	}
	out, rerr := runGit(wt, "rev-parse", "FETCH_HEAD")
	if rerr != nil {
		return "", fmt.Errorf("git rev-parse FETCH_HEAD: %v\n%s", rerr, strings.TrimSpace(out))
	}
	return strings.TrimSpace(out), nil
}

// gitHead resolves the current HEAD sha of a worktree.
func gitHead(wt string) (string, error) {
	out, err := runGit(wt, "rev-parse", "HEAD")
	if err != nil {
		return "", fmt.Errorf("git rev-parse HEAD: %v\n%s", err, out)
	}
	return strings.TrimSpace(out), nil
}

// isAncestor reports whether commit-ish anc is an ancestor of (or equal to)
// commit-ish desc in dir, via `git merge-base --is-ancestor` (exit 0 = yes,
// exit 1 = no). Any other error (a bad ref, git missing) reads as false — the
// caller treats false as "not already landed" and proceeds normally, so an
// ambiguous result never wrongly skips a real land.
func isAncestor(dir, anc, desc string) bool {
	_, err := runGit(dir, "merge-base", "--is-ancestor", anc, desc)
	return err == nil
}

// landedTaskTerminal is the defense-in-depth guard for the leader's done-tombstone
// (F9). The leader is remote-only and cannot read this box's SQLite, but it CAN
// read the EXACT branch content it just landed: `git show <sha>:tasks/task-<id>.json`
// in the throwaway worktree it merged. It reports terminal=true ONLY when that
// landed file exists AND its status is terminal (done/dropped).
//
// FAIL-SAFE DIRECTION. Any ambiguity — the file is absent from the landed tree,
// unreadable, or unparseable — returns terminal=false (do NOT tombstone). The safe
// error is to UNDER-tombstone (a clone re-discovers the task and re-claims it),
// never to FALSELY tombstone an open id (which would gate claims for up to
// TOMBSTONE_TTL even though the deliverable is absent from main — the 2026-06-21
// false-tombstone-of-deferred-followups incident). `reason` is a short
// human-readable cause for the skip/log line; it is "" when terminal is true.
func landedTaskTerminal(wt, sha, taskID string) (terminal bool, reason string) {
	out, err := runGit(wt, "show", sha+":tasks/task-"+taskID+".json")
	if err != nil {
		// Most commonly: pathspec did not match (the task file is absent from the
		// landed tree). Treat every read failure as non-terminal — never tombstone.
		return false, "not present in landed tree (git show: " + compactErr(err) + ")"
	}
	var probe struct {
		Status string `json:"status"`
	}
	if jerr := json.Unmarshal([]byte(out), &probe); jerr != nil {
		return false, "landed task file unparseable: " + compactErr(jerr)
	}
	if probe.Status == "" {
		return false, "landed task file has no status"
	}
	if !isTerminalStatus(probe.Status) {
		return false, "landed status is " + probe.Status + " (not terminal)"
	}
	return true, ""
}

// tombstoneLandedTasks tombstones EACH terminal task id from a just-landed entry,
// gating on landedTaskTerminal so a non-terminal id leaked into --tasks (a stale
// tree, or a hand `landq enqueue --tasks ...`) is SKIPPED with a clear warning
// rather than falsely marked done cross-machine (F9). Best-effort, never fatal —
// it mirrors the upsertTombstone posture (a tombstone write failure does not fail
// a land that already pushed). `entryID`/`branch` are only for the log lines.
func tombstoneLandedTasks(ls *lockServer, wt, sha, taskIDs, session string, entryID int64, branch string) {
	for _, taskID := range strings.Fields(taskIDs) {
		if ok, reason := landedTaskTerminal(wt, sha, taskID); !ok {
			fmt.Printf("#%d %s: SKIP tombstone for task %s — %s (open ids in --tasks must not be tombstoned)\n",
				entryID, branch, taskID, reason)
			continue
		}
		_ = ls.upsertTombstone(taskID, "done", session, devHost())
	}
}

// --- canonical-checkout auto-sync (post-land) --------------------------------
//
// The leader merges + FF-pushes from THROWAWAY worktrees detached at origin/<main>
// (landOnePass/landTrainPass), so it never advances the canonical CHECKOUT's own
// <main> ref. Left alone that ref drifts arbitrarily far behind origin/<main> — the
// operator then has to reconcile by hand, and the stale tracked tasks/ store makes
// the taskdb ID-merge driver reconcile against an old base. syncCanonicalToOrigin
// fast-forwards the canonical checkout to origin/<main> after each land so this box
// stays current automatically (the manual reconcile, codified).
//
// SAFE-BY-DEFAULT, BEST-EFFORT, NEVER FATAL — the land already succeeded; this is
// housekeeping on top, so every failure path logs and returns. It is REF +
// TRACKED-TREE ONLY and NEVER thaws: git hooks are suppressed so the live
// taskdb.sqlite the active waves on this box read is never rebuilt out from under
// them (the DB self-reconciles on the next clean checkout/merge). It performs a PURE
// fast-forward only:
//   - a DIVERGED local branch (carries a commit origin lacks) SKIPS — never rebase,
//     never --force;
//   - a genuine local edit to a TRACKED file the FF would overwrite SKIPS — never
//     discard unlanded work to advance the ref (a stale edit whose content already
//     equals origin is reset to HEAD, since the FF re-applies the identical bytes);
//   - untracked files origin ADDS at the same path (a task file minted here that has
//     SINCE landed — origin's copy is authoritative) are set aside (backed up, then
//     removed) so they don't block the checkout; genuinely-local-only untracked drift
//     (absent from origin) is left in place to land later.
func syncCanonicalToOrigin(repo, mainBranch string) {
	originRef := "origin/" + mainBranch

	// Only move the ref when the canonical checkout is actually ON mainBranch — a
	// detached HEAD or a different checked-out branch is not ours to fast-forward.
	cur, err := runGit(repo, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		fmt.Printf("canonical-sync: skipped (cannot read HEAD): %v\n", compactErr(err))
		return
	}
	if strings.TrimSpace(cur) != mainBranch {
		fmt.Printf("canonical-sync: skipped (checkout on %q, not %q)\n", strings.TrimSpace(cur), mainBranch)
		return
	}

	// Refresh the remote-tracking ref (we just pushed it; cheap, tolerate a blip).
	_ = runGitIgnore(repo, "fetch", "origin", mainBranch)

	localSHA := gitRevParse(repo, mainBranch)
	originSHA := gitRevParse(repo, originRef)
	if localSHA == "" || originSHA == "" {
		fmt.Printf("canonical-sync: skipped (cannot resolve %s / %s)\n", mainBranch, originRef)
		return
	}
	if localSHA == originSHA {
		return // already current — quiet no-op
	}
	if !isAncestor(repo, localSHA, originSHA) {
		fmt.Printf("canonical-sync: SKIPPED — local %s (%s) has commits not on %s; manual reconcile needed\n",
			mainBranch, short(localSHA, 12), originRef)
		return
	}

	// Blocker class 1: tracked files with local modifications the FF would touch.
	dirty, derr := gitDiffNames(repo, "HEAD")
	if derr != nil {
		fmt.Printf("canonical-sync: skipped (tracked-diff read failed): %v\n", compactErr(derr))
		return
	}
	var restore []string
	for _, p := range dirty {
		if gitPathUnchangedBetween(repo, "HEAD", originRef, p) {
			continue // not in the FF delta; the local edit is preserved untouched
		}
		if gitWorktreeMatchesRef(repo, originRef, p) {
			restore = append(restore, p) // stale edit that already landed: reset is a net no-op
			continue
		}
		fmt.Printf("canonical-sync: SKIPPED — local edit to tracked %q conflicts with the incoming fast-forward; manual reconcile needed\n", p)
		return
	}

	// Blocker class 2: untracked files origin ADDS at the same path. Set aside
	// (backed up); origin's landed copy is authoritative. Local-only untracked drift
	// (absent from origin) is preserved.
	colliding, cerr := untrackedAlsoInRef(repo, originRef)
	if cerr != nil {
		fmt.Printf("canonical-sync: skipped (untracked scan failed): %v\n", compactErr(cerr))
		return
	}
	backupDir := ""
	moved := map[string]string{}
	if len(colliding) > 0 {
		root, rerr := mergeWorktreeRoot()
		if rerr != nil {
			fmt.Printf("canonical-sync: skipped (no scratch root for set-aside): %v\n", compactErr(rerr))
			return
		}
		backupDir = filepath.Join(root, "ds-canonical-sync-"+short(originSHA, 12))
		if err := os.MkdirAll(backupDir, 0o755); err != nil {
			fmt.Printf("canonical-sync: skipped (cannot create set-aside dir): %v\n", compactErr(err))
			return
		}
	}
	for _, p := range colliding {
		dst := filepath.Join(backupDir, strings.ReplaceAll(p, string(filepath.Separator), "__"))
		if err := os.Rename(filepath.Join(repo, p), dst); err != nil {
			fmt.Printf("canonical-sync: SKIPPED — could not set aside %q: %v (restoring)\n", p, compactErr(err))
			restoreMovedFiles(repo, moved)
			return
		}
		moved[p] = dst
	}

	// Reset the stale-but-landed tracked edits so the FF is unobstructed.
	for _, p := range restore {
		_ = runGitIgnore(repo, "checkout", "HEAD", "--", p)
	}

	// The fast-forward — hooks SUPPRESSED so no post-merge thaw rebuilds the live DB.
	noHooks, herr := emptyHooksDir()
	if herr != nil {
		fmt.Printf("canonical-sync: skipped (no empty hooks dir): %v (restoring)\n", compactErr(herr))
		restoreMovedFiles(repo, moved)
		return
	}
	if out, ferr := runGit(repo, "-c", "core.hooksPath="+noHooks, "merge", "--ff-only", originRef); ferr != nil {
		fmt.Printf("canonical-sync: fast-forward failed (non-fatal): %v\n%s\n(restoring set-aside files)\n", compactErr(ferr), strings.TrimSpace(out))
		restoreMovedFiles(repo, moved)
		return
	}

	msg := fmt.Sprintf("canonical-sync: advanced %s %s -> %s (%s commit(s)); live DB untouched (no thaw)",
		mainBranch, short(localSHA, 12), short(originSHA, 12), gitRevListCount(repo, localSHA+".."+originSHA))
	if len(moved) > 0 {
		msg += fmt.Sprintf("; set aside %d landed untracked file(s) under %s", len(moved), backupDir)
	}
	fmt.Println(msg)
}

// gitRevParse resolves ref to a full sha in dir, or "" on any error.
func gitRevParse(dir, ref string) string {
	out, err := runGit(dir, "rev-parse", ref)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// gitRevListCount returns the commit count for a range (e.g. "a..b"), or "?" on error.
func gitRevListCount(dir, rng string) string {
	out, err := runGit(dir, "rev-list", "--count", rng)
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(out)
}

// gitDiffNames lists tracked paths in dir that differ from ref in the working tree
// or index (staged AND unstaged), NUL-split so paths with spaces stay intact.
func gitDiffNames(dir, ref string) ([]string, error) {
	out, err := runGit(dir, "diff", "-z", "--name-only", ref)
	if err != nil {
		return nil, err
	}
	return splitNUL(out), nil
}

// gitPathUnchangedBetween reports whether path is IDENTICAL between commit-ishes a
// and b — i.e. a fast-forward a→b would NOT touch it.
func gitPathUnchangedBetween(dir, a, b, path string) bool {
	_, err := runGit(dir, "diff", "--quiet", a, b, "--", path)
	return err == nil // exit 0 = no diff
}

// gitWorktreeMatchesRef reports whether the WORKING-TREE copy of path equals ref's.
func gitWorktreeMatchesRef(dir, ref, path string) bool {
	_, err := runGit(dir, "diff", "--quiet", ref, "--", path)
	return err == nil
}

// untrackedAlsoInRef lists untracked, non-ignored paths in dir that ALSO exist in
// ref's tree (the FF would try to create them, overwriting the local untracked copy).
func untrackedAlsoInRef(dir, ref string) ([]string, error) {
	out, err := runGit(dir, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return nil, err
	}
	var hits []string
	for _, p := range splitNUL(out) {
		if _, e := runGit(dir, "cat-file", "-e", ref+":"+p); e == nil {
			hits = append(hits, p)
		}
	}
	return hits, nil
}

// splitNUL splits a NUL-delimited git output into non-empty fields.
func splitNUL(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "\x00") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// restoreMovedFiles puts set-aside untracked files back (best-effort rollback when
// the fast-forward is aborted, so the sync NEVER loses a file it moved).
func restoreMovedFiles(repo string, moved map[string]string) {
	for p, dst := range moved {
		_ = os.Rename(dst, filepath.Join(repo, p))
	}
}

// emptyHooksDir returns a stable empty directory to point core.hooksPath at, which
// suppresses git hooks (notably the taskdb post-merge thaw) for one command.
func emptyHooksDir() (string, error) {
	root, err := mergeWorktreeRoot()
	if err != nil {
		return "", err
	}
	d := filepath.Join(root, "ds-no-hooks")
	if err := os.MkdirAll(d, 0o755); err != nil {
		return "", err
	}
	return d, nil
}

// unmergedPaths returns the unmerged paths after a failed merge as a slice,
// NUL-split so a path containing spaces is one element (git diff -z, NOT
// whitespace Fields — a tasks/ path is space-free today but a non-tasks/ path
// that must still BLOCK could carry one, and a mis-split there could wrongly
// pass the tasks/-only gate). The empty trailing element from the NUL terminator
// is dropped.
func unmergedPaths(wt string) ([]string, error) {
	out, err := runGit(wt, "diff", "-z", "--name-only", "--diff-filter=U")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, p := range strings.Split(out, "\x00") {
		if p != "" {
			files = append(files, p)
		}
	}
	return files, nil
}

// conflictedFiles returns a comma-joined list of unmerged paths after a failed
// merge, for the conflict detail. Wraps unmergedPaths; on a git error it returns
// "" exactly like the previous diff-based form.
func conflictedFiles(wt string) string {
	files, err := unmergedPaths(wt)
	if err != nil || len(files) == 0 {
		return ""
	}
	return strings.Join(files, ", ")
}

// isTasksJSON reports whether p is a tasks/{task,note}-*.json coordination file —
// the disposable, re-freezable-from-the-live-DB projection the union merge driver
// reconciles id-by-id. A modify/delete conflict on ONLY such paths is always
// safely auto-resolvable by honoring main's prune; any other path is real work.
func isTasksJSON(p string) bool {
	if !strings.HasPrefix(p, "tasks/") {
		return false
	}
	base := p[len("tasks/"):]
	if !strings.HasSuffix(base, ".json") {
		return false
	}
	return strings.HasPrefix(base, "task-") || strings.HasPrefix(base, "note-")
}

// partitionConflicts splits unmerged paths into those OUTSIDE tasks/ (real code/
// doc conflicts that MUST still block a land) and those under tasks/ (disposable
// coordination state that is auto-resolvable). A path under tasks/ that is NOT a
// task-/note-*.json (e.g. a hand-added file) counts as outside — only the known
// disposable shape is auto-resolved.
func partitionConflicts(paths []string) (outside, tasksJSON []string) {
	for _, p := range paths {
		if isTasksJSON(p) {
			tasksJSON = append(tasksJSON, p)
		} else {
			outside = append(outside, p)
		}
	}
	return outside, tasksJSON
}

// resolveTasksOnlyConflict auto-resolves a merge whose unmerged set is ENTIRELY
// tasks/{task,note}-*.json, honoring main's intentional prunes, and completes the
// merge commit. It is called ONLY after partitionConflicts has confirmed there is
// no path outside tasks/ — a tasks/-only conflict is always safely resolvable
// because tasks/*.json are disposable and re-freezable from the live SQLite DB,
// and the union driver (merge=taskdb) already reconciles every modify/modify row
// id-by-id during the merge.
//
// The unmerged set at this point is one of two shapes per path:
//   - modify/delete (tree-level, the driver was NEVER invoked): `git status
//     --porcelain` shows it as DU (deleted in HEAD/main, modified on branch) or
//     UD (deleted on branch, modified in HEAD/main). We honor main's view: for DU
//     `git rm` the path (main dropped it; the branch's status edit is moot); for
//     UD `git add` the path (main keeps it; the branch's deletion loses — the
//     tracked version is already in the worktree, staging it accepts main's).
//   - a residual UU/AA the union driver already settled in-tree — `git add` it.
//
// After staging every path the unmerged set MUST be empty; a residual unmerged
// path (e.g. a dropped-vs-done collision the driver REFUSES, cmd_mergejson.go) is
// a real semantic conflict and is reported back so the caller still BLOCKS. The
// list of auto-resolved paths is returned for loud logging.
func resolveTasksOnlyConflict(wt string, tasksJSON []string) (resolved []string, err error) {
	// Classify each unmerged path by its porcelain XY code so we honor the right
	// side of a modify/delete (DU vs UD) and union-settle modify/modify (UU/AA).
	statuses, serr := mergeConflictStatus(wt)
	if serr != nil {
		return nil, fmt.Errorf("reading conflict status: %w", serr)
	}
	for _, p := range tasksJSON {
		switch statuses[p] {
		case "DU", "DD":
			// Deleted in HEAD/main (DU: modified on branch; DD: also deleted on
			// branch): take main's deletion — the branch's edit to a pruned task
			// is moot.
			if out, rerr := runGit(wt, "rm", "--", p); rerr != nil {
				return nil, fmt.Errorf("git rm %s: %v\n%s", p, rerr, out)
			}
		default:
			// UD (deleted on branch — keep main's tracked version, already in the
			// tree) or a UU/AA the union driver already settled: stage as-is.
			if out, aerr := runGit(wt, "add", "--", p); aerr != nil {
				return nil, fmt.Errorf("git add %s: %v\n%s", p, aerr, out)
			}
		}
		resolved = append(resolved, p)
	}

	// The set must now be empty; a residual unmerged path means the union driver
	// REFUSED a real semantic conflict (e.g. dropped-vs-done) — let the caller
	// block on it instead of force-committing over it.
	residual, rerr := unmergedPaths(wt)
	if rerr != nil {
		return nil, fmt.Errorf("re-reading unmerged set: %w", rerr)
	}
	if len(residual) != 0 {
		return nil, fmt.Errorf("residual unmerged paths after tasks/ auto-resolve (union driver refused): %s",
			strings.Join(residual, ", "))
	}

	// Complete the merge commit, keeping origin/<main> as parent #1 (the worktree
	// HEAD that the failed `git merge` left in a MERGING state) so the result is
	// still FF-pushable. --no-edit keeps the prepared merge message.
	if out, cerr := runGit(wt, "commit", "--no-edit"); cerr != nil {
		return nil, fmt.Errorf("git commit (complete tasks/-only merge): %v\n%s", cerr, out)
	}
	return resolved, nil
}

// mergeOutcome is the classified result of mergeEntryBranch: the merge either
// succeeded outright (clean), was completed by auto-resolving a tasks/-only
// conflict (autoResolved lists the paths), or BLOCKED on a real conflict (a
// non-tasks/ path, or a tasks/ path the union driver refused) with blockDetail
// carrying the operator-facing reason.
type mergeOutcome struct {
	autoResolved []string // tasks/ paths auto-resolved (empty on a clean merge)
	blocked      bool     // a real conflict that must NOT auto-land
	blockDetail  string   // discriminating detail for the blocked row
}

// mergeEntryBranch merges branchSHA into the worktree's current HEAD (origin/
// <main>, parent #1) as a --no-ff commit and classifies the result. On a clean
// merge it returns a zero mergeOutcome. On a conflict it inspects the unmerged
// set: a tasks/-ONLY conflict is auto-resolved in place (honoring main's prune)
// and the merge commit completed (ok=true, outcome.autoResolved populated); a
// conflict touching any non-tasks/ path — or a tasks/ path the union driver
// refuses — leaves the worktree merge-ABORTED and returns ok=true with
// outcome.blocked=true and a discriminating blockDetail. ok=false is reserved for
// an infrastructure error enumerating the conflict (the caller falls back to the
// raw conflict path). Shared by the initial land and the pushLand retry re-merge
// so both honor the seed's tasks/-prune auto-resolve identically.
func mergeEntryBranch(wt string, entry *LandEntry, branchSHA string) (outcome mergeOutcome, ok bool, mergeOut string, err error) {
	out, merr := runGit(wt, "merge", "--no-ff", "-m",
		fmt.Sprintf("Merge %s (landq #%d)", entry.Branch, entry.ID), branchSHA)
	if merr == nil {
		return mergeOutcome{}, true, out, nil // clean merge
	}
	paths, perr := unmergedPaths(wt)
	if perr != nil || len(paths) == 0 {
		// Couldn't enumerate the conflict: signal the caller to take the raw path.
		return mergeOutcome{}, false, out, fmt.Errorf("merge conflict (paths unenumerable): %v", merr)
	}
	outside, tasksJSON := partitionConflicts(paths)
	if len(outside) == 0 {
		resolved, rerr := resolveTasksOnlyConflict(wt, tasksJSON)
		if rerr == nil {
			return mergeOutcome{autoResolved: resolved}, true, out, nil
		}
		// A residual semantic conflict the union driver refused: abort and BLOCK.
		_ = runGitIgnore(wt, "merge", "--abort")
		return mergeOutcome{
			blocked:     true,
			blockDetail: "tasks/-prune conflict (union driver refused): " + compactErr(rerr),
		}, true, out, nil
	}
	// At least one non-tasks/ path: a REAL code conflict. Abort and BLOCK, but
	// discriminate the real clash from the disposable noise in the detail.
	_ = runGitIgnore(wt, "merge", "--abort")
	detail := "code conflict: " + strings.Join(outside, ", ")
	if len(tasksJSON) > 0 {
		detail += fmt.Sprintf(" (+%d tasks/ path(s))", len(tasksJSON))
	}
	return mergeOutcome{blocked: true, blockDetail: detail}, true, out, nil
}

// mergeConflictStatus returns a map of path -> two-letter porcelain XY status for
// the unmerged entries (e.g. "DU", "UD", "UU"), NUL-split so a path with spaces
// stays intact. Only unmerged states (those with at least one U, plus DD/AA) are
// returned; merged/clean entries are skipped.
func mergeConflictStatus(wt string) (map[string]string, error) {
	out, err := runGit(wt, "status", "--porcelain", "-z")
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, rec := range strings.Split(out, "\x00") {
		if len(rec) < 4 {
			continue
		}
		xy := rec[:2]
		path := rec[3:] // skip the XY + single space separator
		switch xy {
		case "DD", "AU", "UD", "UA", "DU", "AA", "UU":
			m[path] = xy
		}
	}
	return m, nil
}

// gateResult classifies a per-row gate run so landOnePass can distinguish a real
// RED gate (a clean non-zero exit — the branch's build genuinely failed) from a
// TRANSIENT/infrastructure failure (the gate timed out, the toolchain was missing
// from PATH, or the process died on a signal — none of which means the branch is
// bad). Only a real red gate parks the row terminally; transient outcomes requeue
// it so the queue self-recovers instead of permanently burning the branch.
type gateResult struct {
	out       string // combined gate output
	exitCode  int    // process exit code (-1 if it never ran / died on a signal)
	ok        bool   // true iff the gate exited 0
	timedOut  bool   // the gate exceeded the deadline (transient)
	transient bool   // a non-red infrastructure failure (timeout, ENOENT/127, signal death, resource exhaustion)
	exhausted string // non-empty = the resource-exhaustion marker found in out (ENOSPC/EDQUOT/ENOMEM)
}

// runGate runs the gate command once via `sh -c` in the merged worktree, under a
// deadline. The child is put in its own process group (Setpgid) so a timeout can
// SIGKILL the WHOLE tree (-pgid) — a bare Process.Kill() would leave the sh -c's
// go/cargo grandchildren running and leak them. A non-positive timeout means no
// deadline. The returned gateResult classifies the outcome (see gateResult).
func runGate(wt, gate string, timeout time.Duration) gateResult {
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", gate)
	cmd.Dir = wt
	// Scrubbed environment: the full ambient env minus a small denylist of
	// agent-forwarding handles (scrubGateEnv). NOT an allowlist — the gate's
	// go/cargo builds must fetch modules through the egress gateway, which needs
	// the ambient proxy/SSL/GO*/CARGO* env.
	cmd.Env = scrubGateEnv(os.Environ())
	// Own process group so a deadline kill reaps the whole subtree.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// On the context deadline, SIGKILL the negative pgid (the whole group) rather
	// than just the sh -c, so go/cargo grandchildren die too.
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	out, err := cmd.CombinedOutput()
	res := gateResult{out: string(out), exitCode: -1}
	if err == nil {
		res.ok = true
		res.exitCode = 0
		return res
	}
	// A deadline overrun: ctx.Err() is DeadlineExceeded. Treat as transient.
	if ctx.Err() == context.DeadlineExceeded {
		res.timedOut = true
		res.transient = true
		return res
	}
	// A missing toolchain (sh couldn't even start, or exit 127 from `command not
	// found`) and a signal death are infrastructure failures, not a red gate.
	if exitErr, isExit := err.(*exec.ExitError); isExit {
		if code := exitErr.ExitCode(); code >= 0 {
			res.exitCode = code
		}
		if ws, isWS := exitErr.ProcessState.Sys().(syscall.WaitStatus); isWS && ws.Signaled() {
			res.transient = true // killed by a signal (OOM-kill, etc.)
		}
		if res.exitCode == 127 {
			res.transient = true // `command not found` from the shell
		}
	} else {
		// sh itself could not be exec'd (ErrNotFound/ENOENT): infrastructure.
		res.transient = true
	}
	// A build that ran out of DISK/QUOTA/MEMORY exits non-zero cleanly, so every
	// check above lets it through as a RED gate — i.e. "this branch is broken",
	// which is a lie. That is not hypothetical: row #6658 parked [failed] in 10s
	// with `link: mapping output file failed: disk quota exceeded`, and the exact
	// same gate on the exact same commit went green as soon as TMPDIR moved off
	// the full tmpfs. Blaming the branch for the box being out of room sends the
	// next reader to debug code that was never wrong.
	if marker, hit := gateOutputIndicatesExhaustion(res.out); hit {
		res.transient = true
		res.exhausted = marker
	}
	return res
}

// gateExhaustionMarkers are resource-exhaustion errnos as they surface in build
// output. Deliberately narrow — each is an unambiguous "the machine ran out of
// something" signal that a genuine compile/test failure does not produce:
//
//	ENOSPC  "no space left on device"
//	EDQUOT  "disk quota exceeded"
//	ENOMEM  "cannot allocate memory"
//
// Kept lowercase; the caller folds case before matching.
//
// FALSE-POSITIVE POSTURE: a gate whose own test output QUOTES one of these
// strings would be misread as exhaustion. The cost of that is bounded and cheap —
// the row is requeued rather than parked, and --max-attempts still stops it from
// retrying forever. The reverse error (silently blaming a branch for a full disk)
// is the expensive one, so we bias here deliberately.
var gateExhaustionMarkers = []string{
	"no space left on device",
	"disk quota exceeded",
	"cannot allocate memory",
}

// gateScratchDir reports the directory the gate's compiler scratch actually
// lands in, for the operator-facing exhaustion message. Go honours GOTMPDIR over
// TMPDIR for $WORK, and falls back to /tmp when neither is set — and "/tmp" in
// that message is itself the diagnosis, since that is the tmpfs this whole guard
// exists for.
func gateScratchDir() string {
	if d := strings.TrimSpace(os.Getenv("GOTMPDIR")); d != "" {
		return d
	}
	if d := strings.TrimSpace(os.Getenv("TMPDIR")); d != "" {
		return d
	}
	return "/tmp (unset — this is very likely the problem)"
}

// gateOutputIndicatesExhaustion reports whether gate output carries a
// resource-exhaustion signature, returning the marker that matched so the row's
// detail can name the real cause instead of "gate red". Pure, for table tests.
func gateOutputIndicatesExhaustion(out string) (string, bool) {
	lower := strings.ToLower(out)
	for _, m := range gateExhaustionMarkers {
		if strings.Contains(lower, m) {
			return m, true
		}
	}
	return "", false
}

// scrubGateEnv returns env with a small DENYLIST of variables removed before the
// gate command runs. We drop SSH agent-forwarding handles (SSH_AUTH_SOCK,
// SSH_AGENT_PID) so an untrusted gate build can't reach back through the
// operator's ssh-agent to sign/authenticate with their keys, while RETAINING
// everything the build legitimately needs — PATH/HOME and, critically, the
// egress-gateway plumbing (HTTPS_PROXY, HTTP_PROXY, SSL_CERT_FILE, GO*, CARGO*)
// that lets go/cargo fetch modules.
//
// NOTE: a strict ALLOWLIST (keep only a named-safe set, drop everything else) is
// the stronger isolation, but it is DEFERRED on purpose. The gate runs real
// go/cargo builds that pull dependencies THROUGH the egress gateway, and that
// path depends on a broad, evolving set of ambient proxy/SSL/toolchain env vars;
// a too-narrow allowlist would silently break EVERY landing's module fetch. We
// take the safe denylist now and leave the allowlist as a follow-up to be sized
// against the real egress-build environment.
func scrubGateEnv(env []string) []string {
	deny := map[string]bool{
		"SSH_AUTH_SOCK": true,
		"SSH_AGENT_PID": true,
	}
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if deny[k] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// gateTail returns the last ~2000 chars of gate output, for the failed-detail
// (the full log can be huge; the tail is what an operator reads). Empty output
// gets an explicit marker so the detail is never a bare "gate red: ".
func gateTail(out string) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return "(no gate output)"
	}
	const max = 2000
	if len(out) <= max {
		return out
	}
	return "…" + out[len(out)-max:]
}
