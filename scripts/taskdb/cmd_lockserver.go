// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// cmd_lockserver.go is the operator surface for the shared Postgres lock
// registry: connect/diagnose (check), one-time schema apply (migrate), view
// the cross-machine held locks (status), print/open the SSH tunnel (tunnel),
// and admin lock cleanup (reap/unlock). Nothing here touches task content — the
// git repo stays the authority; this only inspects and clears lock rows.

func cmdLockserver(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb lockserver <status|check|migrate|tunnel|reap|unlock>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status", "locks":
		return lockserverStatus(db, rest)
	case "check":
		return lockserverCheck(rest)
	case "migrate", "init":
		return lockserverMigrate(rest)
	case "tunnel":
		return lockserverTunnel(rest)
	case "reap":
		return lockserverReap(db, rest)
	case "unlock":
		return lockserverUnlock(db, rest)
	default:
		return fmt.Errorf("unknown lockserver subcommand: %s", sub)
	}
}

// mustLockServer connects to the shared server, erroring (not falling back to
// local) when it is disabled or unreachable — an explicit lockserver command
// wants the real remote state, not a silent local substitute.
func mustLockServer() (*lockServer, error) {
	cfg, err := loadLockConfig()
	if err != nil {
		return nil, err
	}
	if cfg == nil || !cfg.Enabled {
		return nil, fmt.Errorf("shared lock server is disabled (TASKDB_LOCK_DISABLE set, or \"enabled\":false in lockserver.json)")
	}
	ls, err := openLockServer(cfg)
	if err != nil {
		return nil, fmt.Errorf("cannot reach shared lock server: %v\n  open the tunnel first:  %s", compactErr(err), cfg.tunnelCmd())
	}
	return ls, nil
}

// lockserverStatusRow is one held lock joined with the local task title and its
// wave-telemetry heartbeat freshness. ActiveSecs is the age of the holder's
// freshest heartbeat (-1 when none); Stale is the ACTIVITY-aware flag (a lock
// past the age cutoff but with a recent heartbeat is NOT stale).
type lockserverStatusRow struct {
	RemoteLock
	Title      string `json:"title,omitempty"`
	AgeSecs    int64  `json:"age_secs"`
	ActiveSecs int64  `json:"active_secs"` // age of last telemetry heartbeat; -1 = none
	Stale      bool   `json:"stale"`
	Known      bool   `json:"known_locally"`
}

func lockserverStatus(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("lockserver status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ls, err := mustLockServer()
	if err != nil {
		return err
	}
	defer ls.close()

	present, err := ls.schemaPresent()
	if err != nil {
		return err
	}
	if !present {
		return fmt.Errorf("lock schema not applied yet — run: taskdb lockserver migrate")
	}
	locks, err := ls.list()
	if err != nil {
		return err
	}
	// Activity-aware staleness (shared by the dashboard, which shells out to this
	// --json): a lock is stale only if its lock-age is past the cutoff AND its
	// holder has no recent wave-telemetry heartbeat. heartbeatAgesByTask never
	// errors fatally (an un-migrated DB just yields no beats → lock-age fallback).
	hb, _ := ls.heartbeatAgesByTask()
	now := time.Now()
	rows := make([]lockserverStatusRow, 0, len(locks))
	for _, l := range locks {
		age := now.Sub(l.LockedAt)
		r := lockserverStatusRow{RemoteLock: l, AgeSecs: int64(age.Seconds()), ActiveSecs: -1}
		beat, ok := hb[l.TaskID]
		if ok {
			r.ActiveSecs = int64(beat.Seconds())
		}
		r.Stale = lockStale(age, beat, ok)
		if t, err := getTask(db, l.TaskID); err == nil {
			r.Title = t.Title
			r.Known = true
		}
		rows = append(rows, r)
	}
	if *asJSON {
		return printJSON(rows)
	}
	fmt.Printf("shared lock server: %s\n", ls.cfg.redactedDSN())
	if len(rows) == 0 {
		fmt.Println("locks: none held across all machines")
		return nil
	}
	fmt.Printf("locks: %d held across all machines\n", len(rows))
	for _, r := range rows {
		title := r.Title
		if !r.Known {
			title = "(not in this checkout)"
		}
		marker := ""
		if r.Stale {
			marker = "  ⚠ STALE"
		} else if r.ActiveSecs >= 0 && r.AgeSecs > int64(staleLockThreshold.Seconds()) {
			// Old by age but kept fresh by wave telemetry — say why it's NOT stale.
			marker = fmt.Sprintf("  · active %s ago", time.Duration(r.ActiveSecs)*time.Second)
		}
		fmt.Printf("  [%s] %s — %s on %s, held %s%s\n",
			r.TaskID, title, r.LockedBy, r.Host,
			time.Duration(r.AgeSecs)*time.Second, marker)
	}
	return nil
}

func lockserverCheck(args []string) error {
	fs := flag.NewFlagSet("lockserver check", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	strict := fs.Bool("strict", false, "exit non-zero if cross-machine locking is enabled but NOT usable (unreachable tunnel or missing schema) — a wave pre-flight gate so a batch never dispatches blind to other clones/machines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, cfgErr := loadLockConfig()

	type checkResult struct {
		Enabled    bool   `json:"enabled"`
		DSN        string `json:"dsn"`
		TunnelCmd  string `json:"tunnel_cmd"`
		Reachable  bool   `json:"reachable"`
		SchemaOK   bool   `json:"schema_present"`
		LockCount  int    `json:"lock_count"`
		ConfigErr  string `json:"config_error,omitempty"`
		ConnectErr string `json:"connect_error,omitempty"`
	}
	res := checkResult{}
	if cfgErr != nil {
		res.ConfigErr = cfgErr.Error()
	}
	if cfg != nil {
		res.Enabled = cfg.Enabled
		res.DSN = cfg.redactedDSN()
		res.TunnelCmd = cfg.tunnelCmd()
	}
	if cfg != nil && cfg.Enabled {
		ls, err := openLockServer(cfg)
		if err != nil {
			res.ConnectErr = compactErr(err)
		} else {
			defer ls.close()
			res.Reachable = true
			if present, err := ls.schemaPresent(); err == nil {
				res.SchemaOK = present
			}
			if locks, err := ls.list(); err == nil {
				res.LockCount = len(locks)
			}
		}
	}

	if *asJSON {
		return printJSON(res)
	}
	ok := func(b bool) string {
		if b {
			return "✓"
		}
		return "✗"
	}
	fmt.Printf("enabled:        %s\n", ok(res.Enabled))
	fmt.Printf("dsn:            %s\n", res.DSN)
	fmt.Printf("tunnel:         %s\n", res.TunnelCmd)
	fmt.Printf("reachable:      %s\n", ok(res.Reachable))
	fmt.Printf("schema present: %s\n", ok(res.SchemaOK))
	if res.Reachable {
		fmt.Printf("locks held:     %d\n", res.LockCount)
	}
	if res.ConfigErr != "" {
		fmt.Printf("config error:   %s\n", res.ConfigErr)
	}
	if res.ConnectErr != "" {
		fmt.Printf("connect error:  %s\n", res.ConnectErr)
		fmt.Printf("  ⇒ open the tunnel:  %s\n", res.TunnelCmd)
	} else if res.Reachable && !res.SchemaOK {
		fmt.Printf("  ⇒ apply the schema:  taskdb lockserver migrate\n")
	}

	if *strict {
		return strictGateError(res.Enabled, res.Reachable, res.SchemaOK, res.TunnelCmd)
	}
	return nil
}

// strictGateError is the `lockserver check --strict` wave pre-flight decision.
// Only an *enabled but unusable* server is a failure: with per-clone DBs (incl.
// `git clone --local` worktrees), a down tunnel means fail-open local-only locks
// that coordinate NOTHING across clones, so a multi-clone wave dispatched then
// would double-claim. A deliberately disabled server (TASKDB_LOCK_DISABLE /
// config) is intentional solo work and passes; a reachable+migrated server
// passes. A non-nil error makes the command exit non-zero so a wave can do
// `taskdb lockserver check --strict || abort`.
func strictGateError(enabled, reachable, schemaOK bool, tunnelCmd string) error {
	if !enabled {
		return nil
	}
	if !reachable {
		return fmt.Errorf("lock server enabled but UNREACHABLE — cross-clone/cross-machine locks are OFF (fail-open local-only); open the tunnel before dispatching a wave:\n  %s", tunnelCmd)
	}
	if !schemaOK {
		return fmt.Errorf("lock server reachable but schema MISSING — run `taskdb lockserver migrate` before dispatching a wave")
	}
	return nil
}

func lockserverMigrate(args []string) error {
	if err := rejectUnknownFlags(args, "taskdb lockserver migrate"); err != nil {
		return err
	}
	ls, err := mustLockServer()
	if err != nil {
		return err
	}
	defer ls.close()
	if err := ls.migrate(); err != nil {
		return fmt.Errorf("applying lock schema: %w", err)
	}
	fmt.Printf("lock schema applied to %s\n", ls.cfg.redactedDSN())
	return nil
}

func lockserverTunnel(args []string) error {
	fs := flag.NewFlagSet("lockserver tunnel", flag.ContinueOnError)
	open := fs.Bool("open", false, "run the ssh tunnel in the foreground (blocks)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadLockConfig()
	if err != nil {
		return err
	}
	if cfg == nil {
		return fmt.Errorf("no lock-server config")
	}
	cmd := cfg.tunnelCmd()
	if !*open {
		fmt.Println(cmd)
		fmt.Fprintln(os.Stderr, "# keep this running in its own terminal, then run taskdb normally")
		fmt.Fprintln(os.Stderr, "# or:  taskdb lockserver tunnel --open")
		return nil
	}
	fmt.Fprintf(os.Stderr, "opening tunnel: %s\n(ctrl-c to close)\n", cmd)
	s := cfg.SSH
	c := exec.Command("ssh", "-N", "-L",
		fmt.Sprintf("%d:%s:%d", nonZero(s.LocalPort, 5433), orDefault(s.RemotePGHost, "127.0.0.1"), nonZero(s.RemotePGPort, 5432)),
		fmt.Sprintf("%s@%s", s.User, s.Host))
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

func lockserverReap(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("lockserver reap", flag.ContinueOnError)
	age := fs.Duration("age", staleLockThreshold, "release locks older than this")
	session := fs.String("session", "", "reap ONLY locks held by this exact session id, any age (wave-boundary cleanup); supersedes --age")
	dryRun := fs.Bool("dry-run", false, "report without releasing")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ls, err := mustLockServer()
	if err != nil {
		return err
	}
	defer ls.close()

	// reason describes WHY a lock was reaped, for the human-readable line.
	reason := "stale shared lock"
	var reaped []string
	switch {
	case *session != "":
		// Session-scoped, age-independent: release exactly this holder's locks.
		// This is the wave-boundary / agent-exit cleanup path — the coordinator
		// knows the precise TASKDB_SESSION it provisioned and releases it by name
		// the instant the unit/wave ends, never waiting out staleLockThreshold.
		// The match is EXACT (never a prefix), so a sibling wave's holds are safe.
		reason = fmt.Sprintf("held by session %s", *session)
		if *dryRun {
			locks, err := ls.list()
			if err != nil {
				return err
			}
			for _, l := range locks {
				if l.LockedBy == *session {
					reaped = append(reaped, l.TaskID)
				}
			}
		} else {
			reaped, err = ls.reapSession(*session)
			if err != nil {
				return err
			}
			for _, id := range reaped {
				clearLockLocal(db, id)
			}
		}
	case *dryRun:
		// Preview MUST use the same predicate as the armed path (reap ->
		// reapLockStaleSQL), not a hand-rolled locked_at comparison. The old
		// client-side filter differed in two ways that both made it LIE:
		//   - no __land_leader__ exclusion, so it previewed reaping the leader
		//     sentinel that reap() is forbidden to touch (never-evict-the-leader).
		//   - no lock_heartbeats awareness, so a live heartbeating holder past
		//     the age cutoff previewed as reapable while reap() correctly spared it.
		// Measured 2026-08-13: `reap --age 1h --dry-run` reported "would reap
		// __land_leader__" while the armed `reap --age 1h` reported "nothing to
		// reap" — on a box whose landing queue was wedged behind that exact lock,
		// so the preview sent the operator down a path that could not work.
		// listStaleLocks is reap()'s read-only twin over the identical SQL.
		reaped, err = ls.listStaleLocks(*age)
		if err != nil {
			return err
		}
	default:
		reaped, err = ls.reap(*age)
		if err != nil {
			return err
		}
		for _, id := range reaped {
			clearLockLocal(db, id)
		}
	}
	if *asJSON {
		if reaped == nil {
			reaped = []string{}
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
		fmt.Printf("%s %s (%s)\n", verb, id, reason)
	}
	return nil
}

func lockserverUnlock(db *sql.DB, args []string) error {
	id, rest, err := peelID(args, "taskdb lockserver unlock <task-id> [--session S] [--force]")
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("lockserver unlock", flag.ContinueOnError)
	session := fs.String("session", "", "holding session (omit only with --force)")
	force := fs.Bool("force", false, "release regardless of holder")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if !*force && *session == "" {
		return fmt.Errorf("--session required unless --force is set")
	}
	ls, err := mustLockServer()
	if err != nil {
		return err
	}
	defer ls.close()
	// The id may be a prefix known to this checkout; resolve when possible.
	if full, err := resolveTaskID(db, id); err == nil {
		id = full
	}
	released, err := ls.release(id, *session, *force)
	if err != nil {
		return err
	}
	if !released && !*force {
		return fmt.Errorf("lock for %s not found or not held by that session", id)
	}
	clearLockLocal(db, id)
	fmt.Printf("released shared lock for %s\n", id)
	return nil
}

func nonZero(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
