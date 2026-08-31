// SPDX-License-Identifier: Apache-2.0
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"strings"
	"time"
)

func cmdNote(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb note <add|list|rm>")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "add":
		return noteAdd(db, rest)
	case "list":
		return noteList(db, rest)
	case "rm":
		return noteRm(db, rest)
	default:
		return fmt.Errorf("unknown note subcommand: %s", sub)
	}
}

func noteAdd(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("note add", flag.ContinueOnError)
	task := fs.String("task", "", "associated task ID")
	body := fs.String("body", "", "note body (required)")
	author := fs.String("author", "", "session ID or 'human'")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *body == "" {
		return fmt.Errorf("--body is required")
	}
	// Resolve (and validate) the referenced task, for a clearer error than an
	// FK failure and so notes accept the same prefix handles tasks do.
	taskRef := *task
	if taskRef != "" {
		resolved, err := resolveTaskID(db, taskRef)
		if err != nil {
			return err
		}
		taskRef = resolved
	}

	id := newID()
	now := time.Now().UTC()
	var taskID any = nil
	if taskRef != "" {
		taskID = taskRef
	}
	_, err := execRetry(db,
		`INSERT INTO notes(id,task_id,body,author,created_at) VALUES(?,?,?,?,?)`,
		id, taskID, *body, *author, timeToMs(now),
	)
	if err != nil {
		return err
	}
	n := &Note{ID: id, TaskID: taskRef, Body: *body, Author: *author, CreatedAt: now}
	if *asJSON {
		return printJSON(n)
	}
	fmt.Printf("added note %s\n", id)
	return nil
}

func noteList(db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("note list", flag.ContinueOnError)
	task := fs.String("task", "", "filter by task ID")
	asJSON := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	q := `SELECT id, task_id, body, author, created_at FROM notes WHERE 1=1`
	var params []any
	if *task != "" {
		taskID, err := resolveTaskID(db, *task)
		if err != nil {
			return err
		}
		q += ` AND task_id = ?`
		params = append(params, taskID)
	}
	q += ` ORDER BY created_at`

	rows, err := db.Query(q, params...)
	if err != nil {
		return err
	}
	defer rows.Close()

	var notes []*Note
	for rows.Next() {
		n, err := scanNote(rows)
		if err != nil {
			return err
		}
		notes = append(notes, n)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	if *asJSON {
		return printJSON(notes)
	}
	if len(notes) == 0 {
		fmt.Println("no notes")
		return nil
	}
	for _, n := range notes {
		author := n.Author
		if author == "" {
			author = "?"
		}
		fmt.Printf("[%s] %s (%s)\n", n.ID, n.CreatedAt.Format(time.RFC3339), author)
		fmt.Printf("  %s\n", strings.ReplaceAll(n.Body, "\n", "\n  "))
	}
	return nil
}

func noteRm(db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: taskdb note rm <id>")
	}
	id, rest, err := peelID(args, "taskdb note rm <id>")
	if err != nil {
		return err
	}
	if err := rejectUnknownFlags(rest, "taskdb note rm <id>"); err != nil {
		return err
	}
	res, err := execRetry(db, `DELETE FROM notes WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("note %s not found", id)
	}
	fmt.Printf("deleted note %s\n", id)
	return nil
}
