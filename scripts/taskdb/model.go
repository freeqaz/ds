// SPDX-License-Identifier: Apache-2.0
package main

import "time"

type Status string

const (
	StatusOpen       Status = "open"
	StatusInProgress Status = "in-progress"
	StatusDone       Status = "done"
	StatusBlocked    Status = "blocked"
	// StatusDropped is terminal: the task was abandoned rather than completed.
	// It replaces routine file-deletion (docs/23 Proposal B) — a drop stays in
	// tasks/*.json as a tombstone so a stale side can never resurrect it, and it
	// never becomes ready (like done). A drop PROPAGATES through the merge driver
	// (it beats open/in-progress/blocked), but a dropped-vs-done collision on the
	// SAME id is a genuine conflict the merge driver refuses to auto-resolve.
	StatusDropped Status = "dropped"
)

// isTerminalStatus reports whether a status string is a terminal state — the
// task is finished and will never become ready again. Both `done` (completed)
// and `dropped` (abandoned) are terminal. Callers that take the raw DB string
// (the audit pass) use this; the typed equivalent is `s.IsTerminal()`.
func isTerminalStatus(s string) bool {
	return s == string(StatusDone) || s == string(StatusDropped)
}

// IsTerminal reports whether this status is a terminal state (done or dropped).
func (s Status) IsTerminal() bool { return s == StatusDone || s == StatusDropped }

type Task struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Body      string    `json:"body,omitempty"`
	Status    Status    `json:"status"`
	Priority  int       `json:"priority"`
	ParentID  string    `json:"parent_id,omitempty"`
	Branch    string    `json:"branch,omitempty"`
	DependsOn []string  `json:"depends_on,omitempty"`
	LockedBy  string    `json:"-"`
	LockedAt  int64     `json:"-"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Note struct {
	ID        string    `json:"id"`
	TaskID    string    `json:"task_id,omitempty"`
	Body      string    `json:"body"`
	Author    string    `json:"author,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Worktree is a machine-local registry row: which task owns which provisioned
// worktree. Never frozen; `worktree prune` reconciles against disk.
type Worktree struct {
	Path       string    `json:"path"`
	TaskID     string    `json:"task_id"`
	Branch     string    `json:"branch"`
	BaseRef    string    `json:"base_ref"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// AgentRun is one run-ledger row, written single-shot by the dispatcher after
// the agent exits. Never frozen; durable conclusions go to notes.
type AgentRun struct {
	ID           string    `json:"id"`
	TaskID       string    `json:"task_id"`
	Session      string    `json:"session"`
	WorktreePath string    `json:"worktree_path,omitempty"`
	Model        string    `json:"model,omitempty"`
	Status       string    `json:"status"`
	ExitCode     *int64    `json:"exit_code,omitempty"`
	NumTurns     *int64    `json:"num_turns,omitempty"`
	CostUSD      *float64  `json:"cost_usd,omitempty"`
	InputTokens  *int64    `json:"input_tokens,omitempty"`
	OutputTokens *int64    `json:"output_tokens,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	Note         string    `json:"note,omitempty"`
}

// TaskReport is an agent's structured exit claim (MCP task_report). It never
// flips task status — the dispatcher's verification gate is the authority.
type TaskReport struct {
	ID                string    `json:"id"`
	TaskID            string    `json:"task_id"`
	Session           string    `json:"session"`
	Status            string    `json:"status"`
	Summary           string    `json:"summary"`
	Followups         []string  `json:"followups"`
	NoChangesExpected bool      `json:"no_changes_expected,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// Doc is a derived index row over a markdown file on disk; the file is the
// only truth. Hash is the git blob SHA-1 of the current bytes.
type Doc struct {
	ID        int64     `json:"id"`
	Path      string    `json:"path"`
	Title     string    `json:"title,omitempty"`
	Hash      string    `json:"hash"`
	Headings  string    `json:"headings,omitempty"`
	Mtime     time.Time `json:"mtime"`
	IndexedAt time.Time `json:"indexed_at"`
}

// DocChunk is one H2-boundary slice of a doc (seq 0 = preamble). Its hash is
// the blob SHA-1 of the chunk text — the embeddings cache key later.
type DocChunk struct {
	ID      int64  `json:"id"`
	DocID   int64  `json:"doc_id"`
	Path    string `json:"path"`
	Heading string `json:"heading,omitempty"`
	Seq     int    `json:"seq"`
	Body    string `json:"body"`
	Hash    string `json:"hash"`
}
