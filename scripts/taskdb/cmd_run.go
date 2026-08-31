// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"strings"
	"time"
)

func cmdRun(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb run <record|list>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "record":
		return runRecord(db, rest)
	case "list":
		return runList(db, rest)
	default:
		return fmt.Errorf("unknown run subcommand: %s", sub)
	}
}

// runRecord writes one agent_runs row in a single shot. The dispatcher calls
// it AFTER the agent exits — there is deliberately no start/finish pair, so a
// dispatcher crash can never strand a half-open row.
func runRecord(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("run record", flag.ContinueOnError)
	task := fs.String("task", "", "task the run was for (required)")
	session := fs.String("session", "", "session ID that held the lock (required)")
	status := fs.String("status", "", "run outcome (required)")
	worktree := fs.String("worktree", "", "worktree path the agent ran in")
	model := fs.String("model", "", "model used")
	cost := fs.Float64("cost", 0, "cost in USD")
	turns := fs.Int64("turns", 0, "number of turns")
	inTokens := fs.Int64("in-tokens", 0, "input tokens")
	outTokens := fs.Int64("out-tokens", 0, "output tokens")
	exitCode := fs.Int64("exit-code", 0, "agent process exit code")
	started := fs.String("started", "", "run start time, RFC3339 (default: now)")
	note := fs.String("note", "", "one-line verdict context")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *task == "" {
		return fmt.Errorf("--task is required")
	}
	if *session == "" {
		return fmt.Errorf("--session is required")
	}
	if *status == "" {
		return fmt.Errorf("--status is required")
	}
	validStatuses := map[string]bool{"done": true, "blocked": true, "stuck": true, "at_limit": true, "error": true, "timeout": true, "killed": true, "discarded": true}
	if !validStatuses[*status] {
		return fmt.Errorf("invalid status %q; must be one of: done, blocked, stuck, at_limit, error, timeout, killed, discarded", *status)
	}
	taskID, err := resolveTaskID(db, *task)
	if err != nil {
		return fmt.Errorf("--task: %w", err)
	}

	// Telemetry columns are nullable and their zero values are meaningful
	// (exit code 0 most of all), so presence — not value — decides NULL.
	provided := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { provided[f.Name] = true })

	now := time.Now().UTC()
	startedAt := now
	if *started != "" {
		t, err := time.Parse(time.RFC3339, *started)
		if err != nil {
			return fmt.Errorf("--started: %w", err)
		}
		startedAt = t.UTC()
	}

	id := newID()
	r := &AgentRun{
		ID: id, TaskID: taskID, Session: *session,
		WorktreePath: *worktree, Model: *model, Status: *status,
		StartedAt: startedAt, FinishedAt: now, Note: *note,
	}
	var costV, turnsV, inV, outV, exitV any = nil, nil, nil, nil, nil
	if provided["cost"] {
		costV = *cost
		r.CostUSD = cost
	}
	if provided["turns"] {
		turnsV = *turns
		r.NumTurns = turns
	}
	if provided["in-tokens"] {
		inV = *inTokens
		r.InputTokens = inTokens
	}
	if provided["out-tokens"] {
		outV = *outTokens
		r.OutputTokens = outTokens
	}
	if provided["exit-code"] {
		exitV = *exitCode
		r.ExitCode = exitCode
	}

	_, err = db.Exec(
		`INSERT INTO agent_runs(id,task_id,session,worktree_path,model,status,exit_code,num_turns,cost_usd,input_tokens,output_tokens,started_at,finished_at,note)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, taskID, *session, *worktree, *model, *status,
		exitV, turnsV, costV, inV, outV,
		timeToMs(startedAt), timeToMs(now), *note,
	)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(r)
	}
	fmt.Printf("recorded run %s for task %s (%s)\n", id, taskID, *status)
	return nil
}

func runList(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("run list", flag.ContinueOnError)
	task := fs.String("task", "", "filter by task ID")
	limit := fs.Int("limit", 50, "max rows")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	q := `SELECT id, task_id, session, worktree_path, model, status, exit_code, num_turns, cost_usd, input_tokens, output_tokens, started_at, finished_at, note FROM agent_runs WHERE 1=1`
	var params []any
	if *task != "" {
		taskID, err := resolveTaskID(db, *task)
		if err != nil {
			return fmt.Errorf("--task: %w", err)
		}
		q += ` AND task_id = ?`
		params = append(params, taskID)
	}
	q += ` ORDER BY finished_at DESC, id DESC LIMIT ?`
	params = append(params, *limit)

	rows, err := db.Query(q, params...)
	if err != nil {
		return err
	}
	defer rows.Close()

	var runs []*AgentRun
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return err
		}
		runs = append(runs, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if *asJSON {
		return printJSON(runs)
	}
	if len(runs) == 0 {
		fmt.Println("no runs")
		return nil
	}
	for _, r := range runs {
		var telemetry []string
		if r.CostUSD != nil {
			telemetry = append(telemetry, fmt.Sprintf("$%.2f", *r.CostUSD))
		}
		if r.NumTurns != nil {
			telemetry = append(telemetry, fmt.Sprintf("%d turns", *r.NumTurns))
		}
		if r.ExitCode != nil {
			telemetry = append(telemetry, fmt.Sprintf("exit %d", *r.ExitCode))
		}
		suffix := ""
		if len(telemetry) > 0 {
			suffix = fmt.Sprintf(" (%s)", strings.Join(telemetry, ", "))
		}
		fmt.Printf("[%s] task %s — %s by %s, finished %s%s\n",
			r.ID, r.TaskID, r.Status, r.Session, r.FinishedAt.Format(time.RFC3339), suffix)
		if r.Note != "" {
			fmt.Printf("  %s\n", strings.ReplaceAll(r.Note, "\n", "\n  "))
		}
	}
	return nil
}
