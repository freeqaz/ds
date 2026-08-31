// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"time"
)

const staleLockThreshold = 30 * time.Minute

func cmdStatus(db *sql.DB, args []string) error {
	// status takes only --json; reject other stray tokens (e.g. --help) instead of
	// ignoring them, matching the thaw/freeze footgun fix. --json emits the whole
	// status (counts + ready + notes + landq depth + held locks with staleness) as
	// one machine-readable object; the default human table is UNCHANGED.
	fs := flag.NewFlagSet("taskdb status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *asJSON {
		return cmdStatusJSON(db)
	}
	var counts = map[string]int{}
	rows, err := db.Query(`SELECT status, COUNT(*) FROM tasks GROUP BY status`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var s string
		var c int
		if err := rows.Scan(&s, &c); err != nil {
			rows.Close()
			return err
		}
		counts[s] = c
	}
	rows.Close()

	var total int
	db.QueryRow(`SELECT COUNT(*) FROM tasks`).Scan(&total)
	var noteCount int
	db.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&noteCount)

	var ready int
	db.QueryRow(`SELECT COUNT(*) FROM tasks t WHERE ` + readyWhere).Scan(&ready)

	dropped := ""
	if counts["dropped"] > 0 {
		// Only surfaced when present, so the steady-state line keeps its shape.
		dropped = fmt.Sprintf(" · dropped %d", counts["dropped"])
	}
	fmt.Printf("tasks: %d total  (open %d · in-progress %d · blocked %d · done %d%s)\n",
		total, counts["open"], counts["in-progress"], counts["blocked"], counts["done"], dropped)
	fmt.Printf("ready: %d  (open, unlocked, all deps done)\n", ready)
	fmt.Printf("notes: %d\n", noteCount)

	// Landing queue depth (best-effort, fail-open). Printed BEFORE the locks
	// block — that block has early returns (the remote-locks path), so a line
	// after it would be skipped. Silent when empty/disabled/unreachable so the
	// steady-state status shape is preserved; any error path prints nothing.
	if cfg, _ := loadLockConfig(); cfg != nil && cfg.Enabled {
		if ls, err := openLockServer(cfg); err == nil {
			if rows, err := ls.listLand("queued", 0); err == nil && len(rows) > 0 {
				fmt.Printf("landq: %d queued\n", len(rows))
			}
			ls.close()
		}
	}

	// Locks. When a shared lock server is enabled and reachable, the locks
	// section reports the cross-machine truth (read-only — no mirror writes, so
	// status stays safe against a read-only snapshot). If configured but
	// unreachable, note it and fall through to the local view.
	if cfg, _ := loadLockConfig(); cfg != nil && cfg.Enabled {
		if ls, err := openLockServer(cfg); err == nil {
			defer ls.close()
			return printRemoteLocks(db, ls)
		} else {
			fmt.Printf("locks: shared server unreachable (%s) — showing LOCAL view; open tunnel: %s\n",
				compactErr(err), cfg.tunnelCmd())
		}
	}

	lockRows, err := db.Query(`SELECT id, title, locked_by, locked_at FROM tasks WHERE locked_by IS NOT NULL ORDER BY locked_at`)
	if err != nil {
		return err
	}
	defer lockRows.Close()
	var locks []*Task
	for lockRows.Next() {
		var t Task
		var lockedBy sql.NullString
		var lockedAt sql.NullInt64
		if err := lockRows.Scan(&t.ID, &t.Title, &lockedBy, &lockedAt); err != nil {
			return err
		}
		t.LockedBy = lockedBy.String
		t.LockedAt = lockedAt.Int64
		locks = append(locks, &t)
	}

	if len(locks) == 0 {
		fmt.Println("locks: none")
		return nil
	}
	fmt.Printf("locks: %d held\n", len(locks))
	now := time.Now()
	for _, t := range locks {
		age := now.Sub(msToTime(t.LockedAt))
		stale := ""
		if age > staleLockThreshold {
			stale = "  ⚠ STALE"
		}
		fmt.Printf("  [%s] %s — %s, held %s%s\n", t.ID, t.Title, t.LockedBy, age.Round(time.Second), stale)
	}
	return nil
}

// statusLock is one held lock in the `status --json` payload (cross-machine when
// the shared server is reachable, else the local view), with the same
// activity-aware staleness verdict the human table shows.
type statusLock struct {
	TaskID   string `json:"task_id"`
	Title    string `json:"title"`
	LockedBy string `json:"locked_by"`
	Host     string `json:"host,omitempty"`
	HeldSecs int64  `json:"held_secs"`
	Stale    bool   `json:"stale"`
}

// cmdStatusJSON emits the full status as one JSON object: task counts, ready
// count, note count, landing-queue depth, and held locks (with staleness). It
// mirrors the human path's data sources but is purely additive — the default
// table (cmdStatus) is untouched. Fail-open on the remote sections (a down
// tunnel falls back to the local lock view), exactly like the human path.
func cmdStatusJSON(db *sql.DB) error {
	counts := map[string]int{}
	rows, err := db.Query(`SELECT status, COUNT(*) FROM tasks GROUP BY status`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var s string
		var c int
		if err := rows.Scan(&s, &c); err != nil {
			rows.Close()
			return err
		}
		counts[s] = c
	}
	rows.Close()

	var total, noteCount, ready int
	db.QueryRow(`SELECT COUNT(*) FROM tasks`).Scan(&total)
	db.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&noteCount)
	db.QueryRow(`SELECT COUNT(*) FROM tasks t WHERE ` + readyWhere).Scan(&ready)

	type payload struct {
		Tasks      map[string]int `json:"tasks"`       // counts by status
		Total      int            `json:"total"`       // total tasks
		Ready      int            `json:"ready"`       // ready frontier size
		Notes      int            `json:"notes"`       // note count
		LandqDepth map[string]int `json:"landq_depth"` // landing-queue rows by status (empty if disabled/unreachable)
		LandqTotal int            `json:"landq_total"` // total landing-queue rows
		Locks      []statusLock   `json:"locks"`       // held locks (shared view when reachable, else local)
		LocksScope string         `json:"locks_scope"` // "shared" | "local"
		Reachable  bool           `json:"reachable"`   // shared lock server reachable
	}
	out := payload{
		Tasks:      counts,
		Total:      total,
		Ready:      ready,
		Notes:      noteCount,
		LandqDepth: map[string]int{},
		Locks:      []statusLock{},
		LocksScope: "local",
	}

	// Landing-queue depth + held locks from the shared server when reachable;
	// fail-open to the local lock view otherwise.
	now := time.Now()
	if cfg, _ := loadLockConfig(); cfg != nil && cfg.Enabled {
		if ls, oerr := openLockServer(cfg); oerr == nil {
			defer ls.close()
			out.Reachable = true
			if lrows, lerr := ls.listLand("", 0); lerr == nil {
				for _, r := range lrows {
					out.LandqDepth[r.Status]++
					out.LandqTotal++
				}
			}
			if locks, lerr := ls.list(); lerr == nil {
				out.LocksScope = "shared"
				hb, _ := ls.heartbeatAgesByTask()
				for _, l := range locks {
					age := now.Sub(l.LockedAt)
					beat, ok := hb[l.TaskID]
					title := ""
					if t, gerr := getTask(db, l.TaskID); gerr == nil {
						title = t.Title
					}
					out.Locks = append(out.Locks, statusLock{
						TaskID:   l.TaskID,
						Title:    title,
						LockedBy: l.LockedBy,
						Host:     l.Host,
						HeldSecs: int64(age / time.Second),
						Stale:    lockStale(age, beat, ok),
					})
				}
				return printJSON(out)
			}
		}
	}

	// Local lock view (shared server disabled/unreachable or list() failed).
	lockRows, err := db.Query(`SELECT id, title, locked_by, locked_at FROM tasks WHERE locked_by IS NOT NULL ORDER BY locked_at`)
	if err != nil {
		return err
	}
	defer lockRows.Close()
	for lockRows.Next() {
		var t Task
		var lockedBy sql.NullString
		var lockedAt sql.NullInt64
		if err := lockRows.Scan(&t.ID, &t.Title, &lockedBy, &lockedAt); err != nil {
			return err
		}
		age := now.Sub(msToTime(lockedAt.Int64))
		out.Locks = append(out.Locks, statusLock{
			TaskID:   t.ID,
			Title:    t.Title,
			LockedBy: lockedBy.String,
			HeldSecs: int64(age / time.Second),
			Stale:    age > staleLockThreshold,
		})
	}
	return printJSON(out)
}

// printRemoteLocks renders the shared lock server's held locks in the status
// style, joining each lock with the local task title when this checkout knows
// the task. Read-only: it never writes either store.
func printRemoteLocks(db *sql.DB, ls *lockServer) error {
	locks, err := ls.list()
	if err != nil {
		return err
	}
	if len(locks) == 0 {
		fmt.Println("locks: none held across all machines (shared lock server)")
		return nil
	}
	// Activity-aware staleness: a lock past the age cutoff is only ⚠ STALE if its
	// holder ALSO has no recent wave-telemetry heartbeat. An actively-progressing
	// wave heartbeats every transition, so it stops being flagged stale on age
	// alone. A lock with no heartbeat at all falls back to pure lock-age
	// (backwards-compatible with pre-telemetry holds).
	hb, _ := ls.heartbeatAgesByTask()
	fmt.Printf("locks: %d held across all machines (shared lock server)\n", len(locks))
	now := time.Now()
	for _, l := range locks {
		age := now.Sub(l.LockedAt)
		beat, ok := hb[l.TaskID]
		stale := ""
		if lockStale(age, beat, ok) {
			stale = "  ⚠ STALE"
		} else if ok && age > staleLockThreshold {
			// Old by age but kept fresh by telemetry — show why it's NOT stale.
			stale = fmt.Sprintf("  · active %s ago", beat.Round(time.Second))
		}
		title := "(not in this checkout)"
		if t, err := getTask(db, l.TaskID); err == nil {
			title = t.Title
		}
		fmt.Printf("  [%s] %s — %s on %s, held %s%s\n",
			l.TaskID, title, l.LockedBy, l.Host, age.Round(time.Second), stale)
	}
	return nil
}

// lockStale decides whether a held lock is stale, given its lock-age and — when
// hasHeartbeat is true — the age of its holder's freshest wave-telemetry
// heartbeat. The rule:
//   - no heartbeat recorded (hasHeartbeat=false) → fall back to pure lock-age
//     (legacy behavior, backwards-compatible with pre-telemetry holds).
//   - a heartbeat recorded → stale ONLY if BOTH the lock-age AND the last
//     heartbeat are past the threshold. An active wave heartbeats every
//     transition, so even a SUB-SECOND-fresh beat (hbAge≈0) clears the
//     age-based stale flag — absence is signalled by hasHeartbeat, never by a
//     hbAge sentinel (a real, fresh heartbeat legitimately has age ~0).
func lockStale(age, hbAge time.Duration, hasHeartbeat bool) bool {
	if !hasHeartbeat {
		return age > staleLockThreshold
	}
	return age > staleLockThreshold && hbAge > staleLockThreshold
}
