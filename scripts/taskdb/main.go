// SPDX-License-Identifier: Apache-2.0
// taskdb — a fast, lockable, git-friendly task and note store.
//
// See docs/21-taskdb-design.md for the full design. The live store is
// taskdb.sqlite (gitignored); the committed store is tasks/*.json, produced
// by `freeze` and consumed by `thaw`. Git hooks keep the two in sync across
// commits and branch switches.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	// Help needs no database.
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		usage()
		return
	}

	// setup bootstraps the repo (git hooks, staleness report) and must work on a
	// fresh clone before any thaw, so it runs before openDB and does its own,
	// richer reporting — no passive nudge.
	if cmd == "setup" {
		if err := cmdSetup(args); err != nil {
			fmt.Fprintf(os.Stderr, "taskdb: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// merge-json is the git merge driver for tasks/*.json. git invokes it in a
	// clean merge context (no live DB needed, possibly mid-merge with the DB
	// locked), so it runs BEFORE openDB and touches only the three files git
	// hands it.
	if cmd == "merge-json" {
		if err := cmdMergeJSON(args); err != nil {
			fmt.Fprintf(os.Stderr, "taskdb: %v\n", err)
			os.Exit(1)
		}
		return
	}

	db, err := openDB()
	if err != nil {
		fmt.Fprintf(os.Stderr, "taskdb: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Against a read-only snapshot (mode-0444 taskdb.sqlite) read verbs run
	// normally; refuse DB-mutating verbs up front so the failure names the
	// snapshot instead of surfacing a bare engine error from mid-transaction.
	if dbReadOnly {
		if verb := writeVerb(cmd, args); verb != "" {
			fmt.Fprintf(os.Stderr, "taskdb: %v\n", readOnlyError(verb))
			os.Exit(1)
		}
	}

	// Best-effort repo health on every live invocation: auto-install the git
	// hooks on a fresh clone, warn (without clobbering) on a conflicting
	// hooksPath, and warn when .bin/taskdb is stale. Silent in the steady
	// state. Skipped for the long-lived MCP server (it shouldn't mutate git
	// config at startup) and for read-only snapshots (a wave sandbox must not
	// touch the real repo's config).
	if !dbReadOnly && cmd != "mcp" && cmd != "serve-api" {
		repoNudge()
	}

	switch cmd {
	case "task":
		err = cmdTask(db, args)
	case "note":
		err = cmdNote(db, args)
	case "worktree":
		err = cmdWorktree(db, args)
	case "run":
		err = cmdRun(db, args)
	case "doc":
		err = cmdDoc(db, args)
	case "work":
		err = cmdWork(db, args)
	case "audit":
		err = cmdAudit(db, args)
	case "mcp":
		err = cmdMCP(db, args)
	case "serve-api":
		err = cmdServeAPI(db, args)
	case "lockserver":
		err = cmdLockserver(db, args)
	case "landq":
		err = cmdLandq(db, args)
	case "wave-event":
		err = cmdWaveEvent(db, args)
	case "wave":
		err = cmdWave(db, args)
	case "bench":
		err = cmdBench(db, args)
	case "tui":
		err = cmdTUI(db, args)
	case "freeze":
		err = cmdFreeze(db, args)
	case "stage-owned":
		err = cmdStageOwned(db, args)
	case "thaw":
		err = cmdThaw(db, args)
	case "status":
		err = cmdStatus(db, args)
	default:
		fmt.Fprintf(os.Stderr, "taskdb: unknown command %q\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "taskdb: %v\n", err)
		os.Exit(1)
	}
}

// writeVerb returns a human label for a command that mutates the database (or
// the tracked tasks/*.json, for freeze) when invoked with these args, or ""
// for a pure read. It gates the read-only-snapshot refusal in main: read verbs
// (task get/list/tree/search, note list, status, doc get/search, audit *, run
// list, worktree list) return "" and run; everything that writes is refused.
//
// Subcommands not listed default to write-classified (fail closed) so a new
// mutating verb is refused against a snapshot until it is explicitly proven a
// read here — the safe direction for a frozen DB.
func writeVerb(cmd string, args []string) string {
	// Read-only top-level commands: always allowed against a snapshot.
	switch cmd {
	case "status", "audit", "tui", "work", "help", "-h", "--help":
		// work is a read-only triage view (no writes, no locks); always allowed.
		return ""
	case "wave-event", "wave":
		// Telemetry writes ONLY to the remote Postgres (wave_events +
		// lock_heartbeats), never the local DB — so a 444 read-only sandbox
		// snapshot may emit it. The `wave` SDK verb group (report/status/tail) is
		// the same remote-only seam. Classify as a read (allowed against a snapshot).
		return ""
	case "landq":
		// The landing queue writes ONLY to the remote Postgres (land_queue),
		// never the local DB — same rationale as wave-event: a 444 read-only
		// sandbox snapshot may enqueue/read it because it touches no local task
		// content or DAG (the git branch refs are the authority). Classify as a
		// read so the whole landq command is allowed against a snapshot.
		return ""
	case "bench":
		// wavebench reads ONLY the remote wave_events / land_queue tables (the
		// doc-27 Lever-0 land_retry scorer), never the local DB — same remote-only
		// seam as wave-event/landq. A read; allowed against a 0444 snapshot.
		return ""
	case "freeze", "thaw", "stage-owned":
		// freeze rewrites tracked tasks/*.json; thaw rewrites the DB; stage-owned
		// writes tasks/*.json + the git index. None is meaningful against a
		// read-only wave-sandbox snapshot.
		return cmd
	case "mcp", "serve-api":
		// The MCP servers (stdio + the serve-api HTTP face) are long-lived and
		// multiplex read and write tools; they are out of scope for the per-verb
		// gate and refuse individual writes at the engine. Let them start.
		return ""
	case "lockserver":
		// lockserver verbs operate on the REMOTE Postgres registry, not the
		// local DB; the read subset (status/check/tunnel) never writes either
		// store. migrate/reap/unlock mirror clears into the local DB, so refuse
		// those against a 0444 snapshot.
		sub := ""
		if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
			sub = args[0]
		}
		switch sub {
		case "status", "locks", "check", "tunnel", "":
			return ""
		default:
			return "lockserver " + sub
		}
	}

	// Per-subcommand reads, keyed by "<cmd> <sub>". Anything with a subcommand
	// not in this set is treated as a write (fail closed).
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub = args[0]
	}
	readSubs := map[string]bool{
		"task get":      true,
		"task list":     true,
		"task search":   true,
		"note list":     true,
		"worktree list": true,
		"run list":      true,
		"doc get":       true,
		"doc search":    true,
	}
	key := cmd + " " + sub
	if readSubs[key] {
		return ""
	}
	if sub == "" {
		// No subcommand given: the command will print its own usage error; don't
		// pre-empt that with a read-only refusal.
		return ""
	}
	return key
}

func usage() {
	fmt.Print(`taskdb — task & note store

USAGE
  taskdb <command> [args]

TASK COMMANDS
  task add     --title T [--body B] [--parent ID] [--priority 0-3]
  task get     <id>
  task list    [--status S] [--parent ID] [--ready] [--tree] [--json]
  task set     <id> --status <open|in-progress|done|blocked>
  task lock    <id> --session <sid>
  task unlock  <id> [--session <sid>] [--force]
  task edit    <id> [--title T] [--body B] [--priority N] [--parent ID|none]
  task dep     <id> --on <id>    declare a dependency (rejects cycles)
  task undep   <id> --on <id>    remove a dependency
  task rm      <id>
  task claim   [<id>] --session <sid> [--json]    atomically claim a ready task
  task release <id> --session <sid> --status <open|blocked|done> [--note T]
  task reap    [--age 30m] [--requeue] [--dry-run] [--json]
  task search  <query> [--limit 20] [--raw] [--json]

NOTE COMMANDS
  note add    [--task ID] --body B [--author A]
  note list   [--task ID] [--json]
  note rm     <id>

WORKTREE COMMANDS
  worktree register   <task-id> --path <abs> --branch <b> --base <commit> [--json]
  worktree list       [--json]
  worktree unregister <task-id> [--clear-branch]
  worktree prune      [--dry-run] [--json]

RUN COMMANDS
  run record  --task ID --session S --status <done|blocked|stuck|at_limit|error|timeout|killed|discarded>
              [--worktree P] [--model M] [--cost X] [--turns N] [--in-tokens N]
              [--out-tokens N] [--exit-code N] [--started RFC3339] [--note T] [--json]
  run list    [--task ID] [--limit 50] [--json]

DOC COMMANDS
  doc sync    [--prune] [--json]
  doc search  <query> [--limit 10] [--scope docs|tasks|all] [--raw] [--json]
              [--semantic --embedder-cmd CMD]    cosine-ranked embeddings search
  doc get     <path-or-suffix> [--section S] [--outline] [--json]
  doc link    <task-id> <doc-path> [--section S]
  doc embed   [--embedder-cmd CMD] [--prune] [--json]    index new/changed chunks

AUDIT COMMANDS
  audit drift  [--json]    docs changed since their last doc-audit watermark
  audit stuck  [--age 24h] [--json]    stale locks, stuck tasks, dead worktrees
  audit dag    [--json]    cycles, bad deps, unsourced tasks, poison tasks
  audit all    [--json]    all three, findings grouped by workstream root
  audit work   (alias of the top-level 'work' command — see WORK below)

WORK (triage the ready frontier — read-only; takes no locks, writes nothing)
  work  [--substantive] [--epic ID] [--tag bucket] [--all] [--json]
        bucket the --ready frontier (bookkeeping/gated/strategic/docs/substantive)
        and surface the substantive set grouped by root epic, flagging tasks a
        lock holder or .claude/worktrees/agent-* tree is actively contending.
        Buckets are config-driven (TASKDB_WORK_BUCKETS / scripts/taskdb/work-buckets.json).

MCP
  mcp  [--profile worker|curator] [--session S]    stdio MCP server (worker default)
  serve-api [--addr 127.0.0.1:7757] [--profile worker|session|curator]
            [--session-header X-DS-Session] [--allow-nonloopback]
            the taskdb verb set over HTTP (Streamable MCP) for an in-VM agent:
            per-request session from the boundary-injected header; loopback-only
            unless --allow-nonloopback. profile 'session' = worker + task_claim.

LOCK SERVER (shared cross-machine task locking via Postgres over an SSH tunnel)
  lockserver status  [--json]    held locks across ALL machines (the shared truth)
  lockserver check   [--json]    diagnose config, tunnel reachability, schema
  lockserver migrate             apply the lock schema to the shared DB (idempotent)
  lockserver tunnel  [--open]    print (or --open: run) the ssh tunnel command
  lockserver reap    [--age 30m] [--dry-run] [--json]    clear stale shared locks
  lockserver unlock  <task-id> [--session S] [--force]   release one shared lock
  (enabled by default via lockserver.json; TASKDB_LOCK_DISABLE=1 forces local-only,
   TASKDB_LOCK_DSN overrides the connection. FAIL-OPEN by default: falls back to
   local locks if unreachable. TASKDB_LOCK_REQUIRED=1 opts into FAIL-CLOSED dispatch
   — a claim/lock instead REFUSES with a non-zero exit when the server is enabled
   but unreachable, acquiring NO local-only lock; DISABLE wins over REQUIRED.)

LANDING QUEUE (doc 27 Lever 3 — serialized fast-forward landing onto main)
  landq enqueue --branch B [--base SHA] [--tasks "id id"] [--wave W] [--run R]
                [--priority N] [--session S] [--json]
                queue a gate-green branch to land; idempotent (a branch with an
                active row is a no-op). FAIL-OPEN: a disabled/unreachable server
                is a quiet exit-0 no-op (land directly), never a blocked wave.
  landq list    [--status S] [--limit N] [--json]    the queue, newest first
  landq status  [--json]    queue depth by status (also folded into taskdb status)
  landq run     [--once] [--dry-run] [--gate CMD] [--main main] [--age 30m] [--batch N] [--session S]
                the SERIAL runner: elect the __land_leader__ sentinel, drain the
                queue one branch at a time, FF-landing each onto <main>. NOT
                fail-open (errors loudly if the server is unreachable); a second
                concurrent runner exits quietly. --dry-run never pushes main.
                --batch N (DEFAULT 1 = serial, byte-identical to today) enables the
                DORMANT merge-train: land up to N branches under ONE gate per pass
                with split-bisection on red. >1 is a BENCH-GATED operator choice —
                turn it on only when wavebench shows real-gates/landing > 1.3 (doc
                27 §3 Deferred).
  landq reap    [--age 30m] [--dry-run] [--json]    return orphaned 'landing' rows to queued
  landq cancel  <id>    stop a queued|landing entry (-> cancelled)
  landq requeue <id>    re-queue a failed|conflict|cancelled entry (-> queued)
  landq leader  [--json]    who holds the __land_leader__ sentinel — is the runner up?
                {leader|null, host, held_secs, reachable}; fail-open like list/status.

WAVE SDK (agent-scriptable orchestration over the wave telemetry seam; remote-only,
          fail-open — never the local DB. Legacy wave-event / wave-event list unchanged.)
  wave report [--wave W --run R --unit U --task ID --phase P --event E --status S
               --session S --agent A --tokens N --note T] [--json]
                record ONE transition (== wave-event write). --json → {recorded,reachable,task}
  wave report --batch <path|->  [--json]    record a JSON array of events in ONE tx
  wave status [--wave W] [--run R] [--unit U] [--json]
                pre-rolled LIVE per-unit status: rollup joined with activity-aware
                staleness. --json → {units:[{unit,task,phase,status,event,events,
                updated_at,stale,active_secs}],reachable}
  wave tail   [--wave W] [--run R] [--limit N] [--follow] [--json]
                recent events newest-first; --follow polls ~2s and streams new ones

BENCH (doc 27 Lever 0 — land-phase CONFLICT-LOSS scoring; read-only over wave_events)
  bench score [--wave W] [--since DUR] [--json]    land_retry over the phase='land'
                stream (extra land attempts beyond the first success per branch;
                ≈0 on a healthy serial queue). FAIL-OPEN like wave-event/landq list.

TUI
  tui  [--view dag|epics|ready]    full-screen task-graph explorer (read-only):
                                   dep chains & entrypoints, epic tree, ready queue

SETUP
  setup           install git hooks (core.hooksPath=scripts/hooks; conflict-safe),
                  register the tasks/*.json merge driver, and report whether
                  .bin/taskdb is stale. Safe to re-run (do this once per clone,
                  on EVERY machine, for the merge driver to take effect).

LIFECYCLE
  freeze [--gc]   SQLite → tasks/*.json   (pre-commit hook). ADDITIVE by default:
                  writes/updates this DB's rows, never deletes a file for an id
                  this DB lacks (so a diverged DB can't drop another's tasks).
                  --gc also removes orphan files — deliberate single-owner cleanup.
  stage-owned <id>...   freeze + git-add EXACTLY the named tasks' files (+ their
                  notes) — the safe one-command form of "stage only what you own;
                  never 'git add tasks/'". Commit the result with --no-verify.
  thaw  [--force] tasks/*.json → SQLite   (post-checkout/merge/rewrite hooks);
                  refuses if the rebuild would drop live-only tasks unless --force
  merge-json <O> <A> <B> [P]   git merge driver for tasks/*.json (registered by
                  setup): ID-stable 3-way union — status most-progressed-wins
                  (done>blocked>in-progress>open), depends_on unioned, never drops
                  a task either side has. Invoked by git, not by hand.
  status  [--json]   show task counts and held locks; --json emits counts + ready +
                  notes + landing-queue depth + held locks (with staleness) as one object

All commands accept --json where a machine-readable form makes sense.
`)
}
