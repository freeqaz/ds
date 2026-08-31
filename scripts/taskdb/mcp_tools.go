// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// mcp_tools.go registers the per-profile tool surface on an mcp.Server. Every
// handler is a thin adapter over the shared query cores (cores.go, cmd_doc.go):
// the typed In/Out struct pair lets the SDK infer the JSON input/output schema,
// and returning a nil *CallToolResult makes it marshal the Out value as both
// structuredContent and JSON text (recon-feasibility §A).
//
// Profiles are the trust boundary (docs/22 §5). The worker server registers the
// 8 read/report tools and nothing else; an agent literally cannot call a write
// tool that was never added. The curator server adds the 7 mutating tools. The
// "session" profile (an in-VM agent reaching the host over the taskdb sync API,
// cmd_serve_api.go) is worker + task_claim only: it can orient, note, report,
// and take work, but never curate the DAG.
//
// Out structs initialize slices to empty (not nil) so the inferred schema is a
// clean `array`, not `["null","array"]`, and the dispatcher/curator workflows
// see [] rather than null on an empty result.

// registerTools wires the tool set for the given profile onto srv. session is
// the server's identity (author of notes/reports, holder check for releases).
func registerTools(srv *mcp.Server, db *sql.DB, session, profile string) {
	// Worker surface (also available to the curator): orient, search, report.
	mcp.AddTool(srv, &mcp.Tool{Name: "task_ready", Description: "List tasks dispatchable now (open, unlocked, all deps done, no children), highest priority first."}, mcpToolReady(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "task_get", Description: "Context pack for one task: the task, its deps/dependents, notes, linked docs, and last 3 run outcomes."}, mcpToolGet(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "task_note", Description: "Append a durable note to a task (the scratchpad that survives retries). Author is this session."}, mcpToolNote(db, session))
	mcp.AddTool(srv, &mcp.Tool{Name: "task_report", Description: "The single structured exit ramp. Records a status claim + summary; does NOT flip task status (the dispatcher verifies)."}, mcpToolReport(db, session))
	mcp.AddTool(srv, &mcp.Tool{Name: "task_search", Description: "Full-text search over task titles/bodies to find prior art or duplicates before adding."}, mcpToolTaskSearch(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "doc_search", Description: "Full-text search over the docs wiki (bm25, with snippets). Implicit incremental reindex first, so results are never stale."}, mcpToolDocSearch(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "doc_get", Description: "Fetch a doc by path or unique suffix: whole body, a section, or just the heading outline."}, mcpToolDocGet(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "doc_sync", Description: "Explicitly reindex the docs wiki after editing a doc (correctness never depends on it: search/get resync)."}, mcpToolDocSync(db))

	// Beyond the worker surface, exactly two profiles widen it; an unknown
	// profile stays worker-only (fail closed to least privilege).
	if profile != "session" && profile != "curator" {
		return
	}

	// task_claim is the one status flip (open→in-progress) a guest session needs
	// to take a ready task. It is shared by the in-VM "session" profile and the
	// host "curator" profile; the claim routes to the SAME shared lock server
	// keyed by session, so a VM claim is indistinguishable from a host claim.
	mcp.AddTool(srv, &mcp.Tool{Name: "task_claim", Description: "Atomically claim a ready task (or a targeted one) for this session, flipping it to in-progress."}, mcpToolClaim(db, session))

	if profile == "session" {
		// worker + claim: an agent inside a gated VM can orient, search, note,
		// report, and take work, but cannot curate the DAG (add/edit/set-status/
		// dep/undep/doc-link are never registered → uncallable).
		return
	}

	// Curator surface: the remaining mutating tools, with the same validation and
	// error wording as the CLI (they call the same cores).
	mcp.AddTool(srv, &mcp.Tool{Name: "task_add", Description: "Create a task. Rejects a body with no Sources: line — the citation convention is enforced at the boundary."}, mcpToolAdd(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "task_edit", Description: "Edit a task's title, body, and/or priority."}, mcpToolEdit(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "task_set_status", Description: "Set a task's status (open|in-progress|done|blocked|dropped) for curation; dropped is terminal and clears any lock."}, mcpToolSetStatus(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "task_dep", Description: "Declare that one task depends on another. Rejects edges that would create a cycle."}, mcpToolDep(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "task_undep", Description: "Remove a dependency edge between two tasks."}, mcpToolUndep(db))
	mcp.AddTool(srv, &mcp.Tool{Name: "doc_link", Description: "Append a doc citation to a task's trailing Sources: line and re-derive its links."}, mcpToolDocLink(db))
}

// --- worker tools -----------------------------------------------------------

type mcpReadyIn struct {
	Limit int `json:"limit,omitempty" jsonschema:"max tasks to return (default 20)"`
}
type mcpReadyOut struct {
	Count int     `json:"count"`
	Tasks []*Task `json:"tasks"`
}

func mcpToolReady(db *sql.DB) mcp.ToolHandlerFor[mcpReadyIn, mcpReadyOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpReadyIn) (*mcp.CallToolResult, mcpReadyOut, error) {
		out := mcpReadyOut{Tasks: []*Task{}}
		limit := in.Limit
		if limit <= 0 {
			limit = 20
		}
		q := `SELECT id, title, body, status, priority, parent_id, branch, locked_by, locked_at, created_at, updated_at
			FROM tasks t WHERE ` + readyWhere + ` ORDER BY t.priority DESC, t.id LIMIT ?`
		rows, err := db.Query(q, limit)
		if err != nil {
			return nil, out, err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanTask(rows)
			if err != nil {
				return nil, out, err
			}
			out.Tasks = append(out.Tasks, t)
		}
		if err := rows.Err(); err != nil {
			return nil, out, err
		}
		if err := attachDeps(db, out.Tasks); err != nil {
			return nil, out, err
		}
		out.Count = len(out.Tasks)
		return nil, out, nil
	}
}

type mcpGetIn struct {
	ID string `json:"id" jsonschema:"task ID or unambiguous prefix"`
}
type mcpGetOut struct {
	*taskContext
	Dependents []string `json:"dependents"`
	Notes      []*Note  `json:"notes"`
}

func mcpToolGet(db *sql.DB) mcp.ToolHandlerFor[mcpGetIn, mcpGetOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpGetIn) (*mcp.CallToolResult, mcpGetOut, error) {
		out := mcpGetOut{Dependents: []string{}, Notes: []*Note{}}
		id, err := resolveTaskID(db, in.ID)
		if err != nil {
			return nil, out, err
		}
		t, err := getTask(db, id)
		if err != nil {
			return nil, out, err
		}
		ctx, err := taskContextOf(db, t)
		if err != nil {
			return nil, out, err
		}
		out.taskContext = ctx
		deps, err := dependentsOf(db, id)
		if err != nil {
			return nil, out, err
		}
		if deps != nil {
			out.Dependents = deps
		}
		notes, err := mcpNotesFor(db, id)
		if err != nil {
			return nil, out, err
		}
		out.Notes = notes
		return nil, out, nil
	}
}

type mcpNoteIn struct {
	ID   string `json:"id" jsonschema:"task ID or unambiguous prefix"`
	Body string `json:"body" jsonschema:"the note text (markdown)"`
}
type mcpNoteOut struct {
	NoteID string `json:"note_id"`
	TaskID string `json:"task_id"`
}

func mcpToolNote(db *sql.DB, session string) mcp.ToolHandlerFor[mcpNoteIn, mcpNoteOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpNoteIn) (*mcp.CallToolResult, mcpNoteOut, error) {
		var out mcpNoteOut
		if in.Body == "" {
			return nil, out, fmt.Errorf("body is required")
		}
		id, err := resolveTaskID(db, in.ID)
		if err != nil {
			return nil, out, err
		}
		noteID := newID()
		if _, err := db.Exec(
			`INSERT INTO notes(id,task_id,body,author,created_at) VALUES(?,?,?,?,?)`,
			noteID, id, in.Body, session, timeToMs(time.Now()),
		); err != nil {
			return nil, out, err
		}
		out.NoteID = noteID
		out.TaskID = id
		return nil, out, nil
	}
}

type mcpReportIn struct {
	ID                string   `json:"id" jsonschema:"task ID or unambiguous prefix"`
	Status            string   `json:"status" jsonschema:"done|blocked|stuck|at_limit"`
	Summary           string   `json:"summary" jsonschema:"what happened, >= 20 chars"`
	Followups         []string `json:"followups,omitempty" jsonschema:"new follow-up tasks the curator should consider"`
	NoChangesExpected bool     `json:"no_changes_expected,omitempty" jsonschema:"true if this task legitimately produces no diff (skips the dispatcher diff gate, flagged for human review)"`
}
type mcpReportOut struct {
	ReportID string `json:"report_id"`
	TaskID   string `json:"task_id"`
	Status   string `json:"status"`
}

func mcpToolReport(db *sql.DB, session string) mcp.ToolHandlerFor[mcpReportIn, mcpReportOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpReportIn) (*mcp.CallToolResult, mcpReportOut, error) {
		var out mcpReportOut
		valid := map[string]bool{"done": true, "blocked": true, "stuck": true, "at_limit": true}
		if !valid[in.Status] {
			return nil, out, fmt.Errorf("invalid status %q; must be one of: done, blocked, stuck, at_limit", in.Status)
		}
		if len(in.Summary) < 20 {
			return nil, out, fmt.Errorf("summary too short (%d chars); a report summary must be at least 20 chars", len(in.Summary))
		}
		id, err := resolveTaskID(db, in.ID)
		if err != nil {
			return nil, out, err
		}
		// The reporter must hold the task's lock — same guard and wording as
		// task release. A report DOES NOT flip task status and DOES NOT exec
		// git: the dispatcher's verification gate is the sole done-authority.
		t, err := getTask(db, id)
		if err != nil {
			return nil, out, err
		}
		if t.LockedBy != session {
			return nil, out, fmt.Errorf("task %s not found or not locked by your session", id)
		}

		followups := in.Followups
		if followups == nil {
			followups = []string{}
		}
		fjson, err := json.Marshal(followups)
		if err != nil {
			return nil, out, err
		}
		noChanges := 0
		if in.NoChangesExpected {
			noChanges = 1
		}
		now := timeToMs(time.Now())

		tx, err := db.Begin()
		if err != nil {
			return nil, out, err
		}
		defer tx.Rollback()
		reportID := newID()
		if _, err := tx.Exec(
			`INSERT INTO task_reports(id,task_id,session,status,summary,followups,no_changes_expected,created_at) VALUES(?,?,?,?,?,?,?,?)`,
			reportID, id, session, in.Status, in.Summary, string(fjson), noChanges, now,
		); err != nil {
			return nil, out, err
		}
		// A frozen breadcrumb mirrors the ephemeral report so the conclusion
		// survives drop-and-thaw even though task_reports does not.
		if _, err := tx.Exec(
			`INSERT INTO notes(id,task_id,body,author,created_at) VALUES(?,?,?,?,?)`,
			newID(), id, fmt.Sprintf("report(%s): %s", in.Status, in.Summary), session, now,
		); err != nil {
			return nil, out, err
		}
		if err := tx.Commit(); err != nil {
			return nil, out, err
		}
		out.ReportID = reportID
		out.TaskID = id
		out.Status = in.Status
		return nil, out, nil
	}
}

type mcpTaskSearchIn struct {
	Query string `json:"query" jsonschema:"search text (wrapped as a phrase unless raw)"`
	Limit int    `json:"limit,omitempty" jsonschema:"max results (default 20)"`
	Raw   bool   `json:"raw,omitempty" jsonschema:"pass the query to FTS5 verbatim"`
}
type mcpTaskSearchOut struct {
	Count int     `json:"count"`
	Tasks []*Task `json:"tasks"`
}

func mcpToolTaskSearch(db *sql.DB) mcp.ToolHandlerFor[mcpTaskSearchIn, mcpTaskSearchOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpTaskSearchIn) (*mcp.CallToolResult, mcpTaskSearchOut, error) {
		out := mcpTaskSearchOut{Tasks: []*Task{}}
		limit := in.Limit
		if limit <= 0 {
			limit = 20
		}
		tasks, err := searchTasks(db, in.Query, limit, in.Raw)
		if err != nil {
			return nil, out, err
		}
		out.Tasks = tasks
		out.Count = len(tasks)
		return nil, out, nil
	}
}

type mcpDocSearchIn struct {
	Query string `json:"query" jsonschema:"search text (wrapped as a phrase unless raw)"`
	Limit int    `json:"limit,omitempty" jsonschema:"max results (default 10)"`
	Scope string `json:"scope,omitempty" jsonschema:"docs|tasks|all (default docs)"`
	Raw   bool   `json:"raw,omitempty" jsonschema:"pass the query to FTS5 verbatim"`
	// Semantic switches from FTS5 keyword search to the hybrid searchsvc /search
	// path (with ServiceURL set) or the local cosine path. ServiceURL points at a
	// running searchsvc instance; when set AND reachable the /search hybrid hits
	// are returned, FAILING OPEN to the local cosine search when it is
	// unreachable/erroring — never a hard failure.
	Semantic   bool   `json:"semantic,omitempty" jsonschema:"rank by embedding similarity (hybrid via service_url, else local cosine)"`
	ServiceURL string `json:"service_url,omitempty" jsonschema:"running searchsvc base URL; hybrid /search when reachable, fails open to local"`
}
type mcpDocSearchOut struct {
	Count int             `json:"count"`
	Hits  []*docSearchHit `json:"hits"`
}

func mcpToolDocSearch(db *sql.DB) mcp.ToolHandlerFor[mcpDocSearchIn, mcpDocSearchOut] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in mcpDocSearchIn) (*mcp.CallToolResult, mcpDocSearchOut, error) {
		out := mcpDocSearchOut{Hits: []*docSearchHit{}}
		limit := in.Limit
		if limit <= 0 {
			limit = 10
		}
		// Semantic + a reachable service URL → the hybrid searchsvc /search path,
		// FAILING OPEN to local search when the service is unset/unreachable. The
		// service hits already carry Kind (doc|task|note) so the renderer is the
		// same struct path; no scope filter applies (the service ranks the whole
		// corpus).
		if in.Semantic && strings.TrimSpace(in.ServiceURL) != "" {
			if hits, ok := trySearchService(ctx, in.ServiceURL, in.Query, limit); ok {
				out.Hits = hits
				out.Count = len(hits)
				return nil, out, nil
			}
			// ok == false: a loud degraded banner was emitted; fall through to the
			// local FTS path so the tool still returns results.
		}
		scope := in.Scope
		if scope == "" {
			scope = "docs"
		}
		switch scope {
		case "docs", "tasks", "all":
		default:
			return nil, out, fmt.Errorf("invalid scope %q; must be one of: docs, tasks, all", scope)
		}
		hits, err := searchDocs(db, in.Query, scope, limit, in.Raw)
		if err != nil {
			return nil, out, err
		}
		out.Hits = hits
		out.Count = len(hits)
		return nil, out, nil
	}
}

type mcpDocGetIn struct {
	Path    string `json:"path" jsonschema:"doc path or unique suffix"`
	Section string `json:"section,omitempty" jsonschema:"return chunks whose heading has this prefix"`
	Outline bool   `json:"outline,omitempty" jsonschema:"return only the heading outline"`
}
type mcpDocGetOut struct {
	Path     string      `json:"path"`
	Title    string      `json:"title,omitempty"`
	Hash     string      `json:"hash"`
	Outline  []string    `json:"outline"`
	Body     string      `json:"body,omitempty"`
	Sections []*DocChunk `json:"sections,omitempty"`
}

func mcpToolDocGet(db *sql.DB) mcp.ToolHandlerFor[mcpDocGetIn, mcpDocGetOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpDocGetIn) (*mcp.CallToolResult, mcpDocGetOut, error) {
		out := mcpDocGetOut{Outline: []string{}}
		doc, body, chunks, err := getDoc(db, in.Path, in.Section)
		if err != nil {
			return nil, out, err
		}
		out.Path = doc.Path
		out.Title = doc.Title
		out.Hash = doc.Hash
		if ol := docOutline(doc); ol != nil {
			out.Outline = ol
		}
		switch {
		case in.Section != "":
			out.Sections = chunks
		case !in.Outline:
			out.Body = body
		}
		return nil, out, nil
	}
}

type mcpDocSyncIn struct {
	Prune *bool `json:"prune,omitempty" jsonschema:"also drop index rows for deleted files (default true)"`
}

func mcpToolDocSync(db *sql.DB) mcp.ToolHandlerFor[mcpDocSyncIn, docSyncResult] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpDocSyncIn) (*mcp.CallToolResult, docSyncResult, error) {
		// Honor the advertised prune parameter; default true when omitted (a *bool
		// distinguishes "omitted" from an explicit false, since the wire zero-value
		// of a plain bool is false). Matches the CLI's --prune default.
		prune := true
		if in.Prune != nil {
			prune = *in.Prune
		}
		res, err := syncDocs(db, prune)
		if err != nil {
			return nil, docSyncResult{}, err
		}
		return nil, *res, nil
	}
}

// --- curator tools ----------------------------------------------------------

type mcpClaimIn struct {
	ID string `json:"id,omitempty" jsonschema:"specific task to claim; omit to take the highest-priority ready task"`
}
type mcpClaimOut struct {
	Claimed bool  `json:"claimed"`
	Task    *Task `json:"task,omitempty"`
	// ReapedLocks carries the task ids of any stale foreign locks the claim-time
	// auto-reap (TASKDB_LOCK_AUTOREAP_AGE) freed on the way in, so an MCP caller
	// sees a reap instead of it living only on the server's stderr. omitempty →
	// absent on the common no-reap claim.
	ReapedLocks []string `json:"reaped_locks,omitempty"`
}

func mcpToolClaim(db *sql.DB, session string) mcp.ToolHandlerFor[mcpClaimIn, mcpClaimOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpClaimIn) (*mcp.CallToolResult, mcpClaimOut, error) {
		var out mcpClaimOut
		var resolved string
		if in.ID != "" {
			r, err := resolveTaskID(db, in.ID)
			if err != nil {
				return nil, out, err
			}
			resolved = r
		}
		t, reaped, err := claimTaskReaped(db, session, resolved)
		if err == sql.ErrNoRows {
			// Not an error: an empty/not-ready queue is a normal answer. A reap can
			// still have happened even when the queue then drained, so surface it.
			out.ReapedLocks = reaped
			return nil, out, nil
		}
		if err != nil {
			return nil, out, err
		}
		out.Claimed = true
		out.Task = t
		out.ReapedLocks = reaped
		return nil, out, nil
	}
}

type mcpAddIn struct {
	Title    string `json:"title" jsonschema:"task title"`
	Body     string `json:"body" jsonschema:"task body — MUST contain a Sources: line citing docs"`
	Parent   string `json:"parent,omitempty" jsonschema:"parent task ID"`
	Priority int    `json:"priority,omitempty" jsonschema:"0-3"`
}
type mcpAddOut struct {
	ID string `json:"id"`
}

func mcpToolAdd(db *sql.DB) mcp.ToolHandlerFor[mcpAddIn, mcpAddOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpAddIn) (*mcp.CallToolResult, mcpAddOut, error) {
		var out mcpAddOut
		if in.Title == "" {
			return nil, out, fmt.Errorf("title is required")
		}
		// The Sources: convention is enforced at the trust boundary: a task
		// without a citation parses to zero source links (sources.go).
		if len(parseSources(in.Body)) == 0 {
			return nil, out, fmt.Errorf("task body must contain a Sources: line citing at least one doc (e.g. 'Sources: doc 21')")
		}
		var parentID any = nil
		if in.Parent != "" {
			resolved, err := resolveTaskID(db, in.Parent)
			if err != nil {
				return nil, out, fmt.Errorf("parent: %w", err)
			}
			parentID = resolved
		}
		id := newID()
		now := timeToMs(time.Now())
		if _, err := db.Exec(
			`INSERT INTO tasks(id,title,body,status,priority,parent_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`,
			id, in.Title, in.Body, StatusOpen, in.Priority, parentID, now, now,
		); err != nil {
			return nil, out, err
		}
		if err := docRederiveTask(db, id, in.Body); err != nil {
			return nil, out, err
		}
		out.ID = id
		return nil, out, nil
	}
}

type mcpEditIn struct {
	ID       string `json:"id" jsonschema:"task ID or unambiguous prefix"`
	Title    string `json:"title,omitempty" jsonschema:"new title"`
	Body     string `json:"body,omitempty" jsonschema:"new body"`
	Priority *int   `json:"priority,omitempty" jsonschema:"new priority 0-3"`
}
type mcpEditOut struct {
	ID string `json:"id"`
}

func mcpToolEdit(db *sql.DB) mcp.ToolHandlerFor[mcpEditIn, mcpEditOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpEditIn) (*mcp.CallToolResult, mcpEditOut, error) {
		var out mcpEditOut
		id, err := resolveTaskID(db, in.ID)
		if err != nil {
			return nil, out, err
		}
		t, err := getTask(db, id)
		if err != nil {
			return nil, out, err
		}
		if in.Title != "" {
			t.Title = in.Title
		}
		if in.Body != "" {
			t.Body = in.Body
		}
		if in.Priority != nil {
			t.Priority = *in.Priority
		}
		if _, err := db.Exec(`UPDATE tasks SET title=?, body=?, priority=?, updated_at=? WHERE id=?`,
			t.Title, t.Body, t.Priority, timeToMs(time.Now()), id); err != nil {
			return nil, out, err
		}
		// A body edit can change the Sources: line; keep the link index honest.
		if in.Body != "" {
			if err := docRederiveTask(db, id, t.Body); err != nil {
				return nil, out, err
			}
		}
		out.ID = id
		return nil, out, nil
	}
}

type mcpSetStatusIn struct {
	ID     string `json:"id" jsonschema:"task ID or unambiguous prefix"`
	Status string `json:"status" jsonschema:"open|in-progress|done|blocked|dropped"`
}
type mcpSetStatusOut struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func mcpToolSetStatus(db *sql.DB) mcp.ToolHandlerFor[mcpSetStatusIn, mcpSetStatusOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpSetStatusIn) (*mcp.CallToolResult, mcpSetStatusOut, error) {
		var out mcpSetStatusOut
		valid := map[string]bool{"open": true, "in-progress": true, "done": true, "blocked": true, "dropped": true}
		if !valid[in.Status] {
			return nil, out, fmt.Errorf("invalid status %q; must be one of: open, in-progress, done, blocked, dropped", in.Status)
		}
		id, err := resolveTaskID(db, in.ID)
		if err != nil {
			return nil, out, err
		}
		// Dropping is terminal — clear any local lock so a dropped task never
		// shows a stale holder. Match the CLI `task drop`: force-release the SHARED
		// registry too, else an MCP drop of a cross-machine-held task leaves a
		// phantom Postgres hold for up to staleLockThreshold (~30 min). Best-effort
		// (force=true overrides any holder); a down tunnel must not block the drop,
		// the local clear below still stands.
		set := `UPDATE tasks SET status=?, updated_at=? WHERE id=?`
		if in.Status == string(StatusDropped) {
			set = `UPDATE tasks SET status=?, updated_at=?, locked_by=NULL, locked_at=NULL WHERE id=?`
			// A drop is a removal, not a claim: IGNORE a TASKDB_LOCK_REQUIRED
			// fail-closed refusal (stay fail-open) so a down tunnel never blocks
			// the drop — the local clear above still stands.
			if ls, _ := lockServerOrLocal(); ls != nil {
				_, _ = ls.release(id, "", true)
				ls.close()
			}
		}
		res, err := db.Exec(set, in.Status, timeToMs(time.Now()), id)
		if err != nil {
			return nil, out, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil, out, fmt.Errorf("task %s not found", id)
		}
		out.ID = id
		out.Status = in.Status
		return nil, out, nil
	}
}

type mcpDepIn struct {
	ID string `json:"id" jsonschema:"the dependent task"`
	On string `json:"on" jsonschema:"the task that must be done first"`
}
type mcpDepOut struct {
	ID string `json:"id"`
	On string `json:"on"`
}

func mcpToolDep(db *sql.DB) mcp.ToolHandlerFor[mcpDepIn, mcpDepOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpDepIn) (*mcp.CallToolResult, mcpDepOut, error) {
		var out mcpDepOut
		id, err := resolveTaskID(db, in.ID)
		if err != nil {
			return nil, out, err
		}
		dep, err := resolveTaskID(db, in.On)
		if err != nil {
			return nil, out, fmt.Errorf("on: %w", err)
		}
		if id == dep {
			return nil, out, fmt.Errorf("task %s cannot depend on itself", id)
		}
		// Same cycle guard as the CLI: there is no second write path, so the
		// DAG invariant holds here too (would create a cycle: a → b).
		if path, err := depPath(db, dep, id); err != nil {
			return nil, out, err
		} else if path != nil {
			return nil, out, fmt.Errorf("would create a cycle: %s → %s", id, joinArrow(path))
		}
		if _, err := db.Exec(`INSERT OR IGNORE INTO task_deps(task_id,depends_on) VALUES(?,?)`, id, dep); err != nil {
			return nil, out, err
		}
		if _, err := db.Exec(`UPDATE tasks SET updated_at=? WHERE id=?`, timeToMs(time.Now()), id); err != nil {
			return nil, out, err
		}
		out.ID = id
		out.On = dep
		return nil, out, nil
	}
}

type mcpUndepIn struct {
	ID string `json:"id" jsonschema:"the dependent task"`
	On string `json:"on" jsonschema:"the dependency to remove"`
}
type mcpUndepOut struct {
	ID string `json:"id"`
	On string `json:"on"`
}

func mcpToolUndep(db *sql.DB) mcp.ToolHandlerFor[mcpUndepIn, mcpUndepOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpUndepIn) (*mcp.CallToolResult, mcpUndepOut, error) {
		var out mcpUndepOut
		id, err := resolveTaskID(db, in.ID)
		if err != nil {
			return nil, out, err
		}
		dep, err := resolveTaskID(db, in.On)
		if err != nil {
			return nil, out, fmt.Errorf("on: %w", err)
		}
		res, err := db.Exec(`DELETE FROM task_deps WHERE task_id=? AND depends_on=?`, id, dep)
		if err != nil {
			return nil, out, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil, out, fmt.Errorf("task %s does not depend on %s", id, dep)
		}
		if _, err := db.Exec(`UPDATE tasks SET updated_at=? WHERE id=?`, timeToMs(time.Now()), id); err != nil {
			return nil, out, err
		}
		out.ID = id
		out.On = dep
		return nil, out, nil
	}
}

type mcpDocLinkIn struct {
	ID      string `json:"id" jsonschema:"task ID or unambiguous prefix"`
	DocPath string `json:"doc_path" jsonschema:"doc path or unique suffix to cite"`
	Section string `json:"section,omitempty" jsonschema:"section fragment to cite (e.g. \"§4\")"`
}
type mcpDocLinkOut struct {
	TaskID   string `json:"task_id"`
	Citation string `json:"citation"`
}

func mcpToolDocLink(db *sql.DB) mcp.ToolHandlerFor[mcpDocLinkIn, mcpDocLinkOut] {
	return func(_ context.Context, _ *mcp.CallToolRequest, in mcpDocLinkIn) (*mcp.CallToolResult, mcpDocLinkOut, error) {
		var out mcpDocLinkOut
		id, err := resolveTaskID(db, in.ID)
		if err != nil {
			return nil, out, err
		}
		if _, err := syncDocs(db, true); err != nil {
			return nil, out, err
		}
		doc, err := docResolve(db, in.DocPath)
		if err != nil {
			return nil, out, err
		}
		t, err := getTask(db, id)
		if err != nil {
			return nil, out, err
		}
		citation := doc.Path
		if in.Section != "" {
			citation += " " + in.Section
		}
		t.Body = docAppendCitation(t.Body, citation)
		if _, err := db.Exec(`UPDATE tasks SET body=?, updated_at=? WHERE id=?`, t.Body, timeToMs(time.Now()), id); err != nil {
			return nil, out, err
		}
		if err := docRederiveTask(db, id, t.Body); err != nil {
			return nil, out, err
		}
		out.TaskID = id
		out.Citation = citation
		return nil, out, nil
	}
}

// --- helpers (mcp-prefixed to avoid cross-file symbol collisions) -----------

// mcpNotesFor returns a task's notes oldest-first for the context pack. Empty
// (not nil) so the Out schema stays a clean array.
func mcpNotesFor(db *sql.DB, taskID string) ([]*Note, error) {
	rows, err := db.Query(`SELECT id, task_id, body, author, created_at FROM notes WHERE task_id=? ORDER BY created_at`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Note{}
	for rows.Next() {
		n, err := scanNote(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// joinArrow renders a dependency chain like the CLI's cycle error does.
func joinArrow(path []string) string {
	s := ""
	for i, p := range path {
		if i > 0 {
			s += " → "
		}
		s += p
	}
	return s
}
