// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
)

// readyWhere selects tasks an agent may pick up right now: open, unclaimed,
// every dependency in a TERMINAL state (done or dropped), and not a container
// (tasks with children are epics — they complete when their children do, they
// aren't dispatched themselves). A dropped task is itself never ready (the
// status filter is `= 'open'`), and a DROPPED dependency no longer blocks its
// dependents: dropping is a deliberate terminal decision, so a downstream task
// must not be stranded forever waiting on work that was abandoned (the same way
// `done` unblocks it). Queries using it must alias the tasks table as t.
const readyWhere = `t.status = 'open' AND t.locked_by IS NULL
	AND NOT EXISTS (
		SELECT 1 FROM task_deps d JOIN tasks dt ON dt.id = d.depends_on
		WHERE d.task_id = t.id AND dt.status NOT IN ('done','dropped'))
	AND NOT EXISTS (SELECT 1 FROM tasks c WHERE c.parent_id = t.id)`

// loadAllDeps returns the full dependency edge map: task ID → sorted list of
// the task IDs it depends on. The graph is small; loading it whole keeps
// cycle checks and freeze simple.
func loadAllDeps(db *sql.DB) (map[string][]string, error) {
	rows, err := db.Query(`SELECT task_id, depends_on FROM task_deps ORDER BY task_id, depends_on`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	deps := map[string][]string{}
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			return nil, err
		}
		deps[from] = append(deps[from], to)
	}
	return deps, rows.Err()
}

// depPath returns a chain of task IDs from `from` to `to` following
// depends_on edges (inclusive of both ends), or nil if `to` is unreachable.
// Used to reject cycle-creating edges with a readable path in the error.
func depPath(db *sql.DB, from, to string) ([]string, error) {
	edges, err := loadAllDeps(db)
	if err != nil {
		return nil, err
	}
	parent := map[string]string{from: ""}
	queue := []string{from}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == to {
			var path []string
			for n := cur; n != ""; n = parent[n] {
				path = append([]string{n}, path...)
			}
			return path, nil
		}
		for _, next := range edges[cur] {
			if _, seen := parent[next]; !seen {
				parent[next] = cur
				queue = append(queue, next)
			}
		}
	}
	return nil, nil
}

// ancestorPath returns the parent_id chain from `from` up to `to` (inclusive
// of both ends), or nil if `to` is not an ancestor of `from`. Used to reject
// reparenting a task under its own descendant. A seen-set guards against
// walking a pre-existing corrupt cycle forever.
func ancestorPath(db *sql.DB, from, to string) ([]string, error) {
	path := []string{from}
	seen := map[string]bool{from: true}
	cur := from
	for {
		if cur == to {
			return path, nil
		}
		var next sql.NullString
		err := db.QueryRow(`SELECT parent_id FROM tasks WHERE id=?`, cur).Scan(&next)
		if err == sql.ErrNoRows || (err == nil && !next.Valid) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if seen[next.String] {
			return nil, nil
		}
		seen[next.String] = true
		cur = next.String
		path = append(path, cur)
	}
}

// dependentsOf returns the IDs of tasks that depend on id (reverse edges).
func dependentsOf(db *sql.DB, id string) ([]string, error) {
	rows, err := db.Query(`SELECT task_id FROM task_deps WHERE depends_on = ? ORDER BY task_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// attachDeps fills the DependsOn field on each task from the edge map.
func attachDeps(db *sql.DB, tasks []*Task) error {
	deps, err := loadAllDeps(db)
	if err != nil {
		return err
	}
	for _, t := range tasks {
		t.DependsOn = deps[t.ID]
	}
	return nil
}
