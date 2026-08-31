// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	sqlite "modernc.org/sqlite"
)

// syscallEROFS is the "read-only file system" errno, matched alongside
// os.ErrPermission when probing whether the snapshot is writable.
var syscallEROFS = syscall.EROFS

// dbReadOnly records that openDB fell back to a read-only snapshot (a
// mode-0444 taskdb.sqlite with no -wal/-shm sidecars, as provisioned into the
// wave sandboxes). Read verbs run normally; write verbs are refused up front
// with readOnlyError so the failure names the snapshot instead of surfacing a
// bare "attempt to write a readonly database (8)" from deep in a transaction.
var dbReadOnly bool

// dbReadOnlyPath is the on-disk path of the read-only snapshot, for the
// refusal message.
var dbReadOnlyPath string

// readOnlyError is the single-line refusal returned to any write verb run
// against a read-only snapshot. It names the snapshot path so the operator
// knows the live DB was never reached.
func readOnlyError(verb string) error {
	return fmt.Errorf("%s: refusing to write — taskdb.sqlite is a read-only snapshot (%s); writes need the live database, not the 0444 wave-sandbox copy", verb, dbReadOnlyPath)
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		gitPath := filepath.Join(dir, ".git")
		if fi, err := os.Stat(gitPath); err == nil {
			if fi.IsDir() {
				return dir, nil
			}
			// In a linked worktree .git is a regular file pointing at the
			// primary checkout. By default (D130) resolve to the primary root so
			// every worktree shares the one live taskdb.sqlite (locks coordinate
			// nothing if each agent has a private DB).
			//
			// OPT-IN (TASKDB_WORKTREE_LOCAL): keep the worktree on its OWN root
			// (its own taskdb.sqlite + tasks/) instead of redirecting. This is
			// the inert foundation step toward worktree-local stores — the
			// follow-on machinery (full-closure thaw / worktree-local freeze /
			// queue land) is NOT wired here. `dir` is the worktree's own
			// top-level, the value already in hand before the redirect. The
			// explicit TASKDB_DB override (see dbPathEnvVars) still wins ahead of
			// all of this.
			if worktreeLocalEnabled() {
				return dir, nil
			}
			return linkedWorktreeRoot(gitPath)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("not inside a git repository")
		}
		dir = parent
	}
}

// linkedWorktreeRoot parses a worktree's .git file — a single
// `gitdir: <abs>/.git/worktrees/<name>` pointer — and returns the primary
// checkout root by stripping the `/.git/worktrees/<name>` suffix.
func linkedWorktreeRoot(gitFile string) (string, error) {
	b, err := os.ReadFile(gitFile)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		gitdir, ok := strings.CutPrefix(strings.TrimSpace(line), "gitdir:")
		if !ok {
			continue
		}
		gitdir = strings.TrimSpace(gitdir)
		// A relative pointer (git sometimes writes `gitdir: ../../.git/worktrees/x`)
		// is relative to the directory holding the .git file; resolving it against
		// CWD would split-brain the shared DB depending on where taskdb is invoked.
		if !filepath.IsAbs(gitdir) {
			gitdir = filepath.Join(filepath.Dir(gitFile), gitdir)
		}
		gitdir = filepath.Clean(gitdir)
		wtDir := filepath.Dir(gitdir) // <root>/.git/worktrees
		gitDir := filepath.Dir(wtDir) // <root>/.git
		if filepath.Base(wtDir) != "worktrees" || filepath.Base(gitDir) != ".git" {
			return "", fmt.Errorf("unrecognized gitdir pointer %q in %s", gitdir, gitFile)
		}
		return filepath.Dir(gitDir), nil
	}
	return "", fmt.Errorf("no gitdir pointer in %s", gitFile)
}

// worktreeLocalEnabled reports whether TASKDB_WORKTREE_LOCAL opts a linked
// worktree out of the D130 primary-checkout redirect, keeping it on its OWN
// root (own taskdb.sqlite + tasks/). Default (unset/empty/falsey) preserves the
// redirect byte-for-byte. Parsing is an explicit ALLOW-list — only "1", "true",
// "yes", "on" (case-insensitive, trimmed) enable it — so an accidental/garbage
// value reads as OFF rather than silently flipping the store (deliberately
// stricter than the deny-list truthyEnv used for the lock-server toggles).
func worktreeLocalEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("TASKDB_WORKTREE_LOCAL"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// dbPathEnvVars are the environment overrides for the taskdb database path,
// honored AHEAD of repoRoot(). This is the §5.1 unit-cannot-write-the-live-DB
// hook: in a linked-worktree wave unit, repoRoot() resolves to the PRIMARY
// checkout (so the orchestrator's writes reach the one live DB), which means a
// stray UNIT taskdb write would also hit the live DB. wave_worktree.sh writes a
// 0444 read-only snapshot into the unit worktree and exports one of these vars
// pointing at it; the unit recipe sources that env file, so every unit taskdb
// invocation resolves to the snapshot and any write is refused by the read-only
// path. The orchestrator runs taskdb WITHOUT these set, so it still reaches the
// live DB. Both names are accepted (TASKDB_DB is canonical; TASKDB_DBPATH is a
// caller-compat alias) and the first non-empty one wins.
var dbPathEnvVars = []string{"TASKDB_DB", "TASKDB_DBPATH"}

func dbPath() (string, error) {
	for _, ev := range dbPathEnvVars {
		if p := os.Getenv(ev); p != "" {
			return p, nil
		}
	}
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "taskdb.sqlite"), nil
}

func tasksDir() (string, error) {
	root, err := repoRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "tasks"), nil
}

func openDB() (*sql.DB, error) {
	path, err := dbPath()
	if err != nil {
		return nil, err
	}
	// A mode-0444 taskdb.sqlite (the read-only wave-sandbox snapshot) cannot be
	// opened read-write: journal_mode(WAL) and any initSchema CREATE would fail
	// with "attempt to write a readonly database (8)" and take every read verb
	// down with them. When the file exists but is unwritable, open a read-only
	// connection instead and let read verbs through; write verbs are refused up
	// front (see readOnlyError / write-verb routing in main.go).
	if dbFileUnwritable(path) {
		return openReadOnlyDB(path)
	}
	// modernc.org/sqlite only honors _pragma=... DSN params; the mattn-style
	// _journal_mode/_foreign_keys forms are silently ignored.
	//
	// _txlock=immediate makes every db.Begin() transaction take the write lock at
	// BEGIN rather than deferring it to the first write. Our write transactions
	// read before they write (cmdThaw SELECTs live claims, then DELETEs; the MCP
	// report tx is INSERT-only but shares the path). A deferred BEGIN takes a read
	// snapshot on that first SELECT; if another connection commits before our
	// first write, the upgrade fails with SQLITE_BUSY_SNAPSHOT (517), which
	// busy_timeout does NOT retry — the txn just errors out. Acquiring the write
	// lock up front instead lets busy_timeout(15000) absorb the contention at
	// BEGIN. claimTask is a single autocommit UPDATE (not a db.Begin tx), so it is
	// unaffected. _txlock=immediate is supported in modernc v1.38.2 (probed).
	//
	// busy_timeout(15000): defense-in-depth under many concurrent agents. The
	// engine itself spins up to 15s before surfacing SQLITE_BUSY, and execRetry /
	// queryRetry (below) wrap the autocommit write path with a further bounded
	// app-layer backoff for the residue that still slips through (held writers,
	// BUSY_SNAPSHOT on a deferred upgrade). The retry is the primary fix; the
	// raised timeout is a conservative cushion, not a substitute.
	db, err := sql.Open("sqlite", path+"?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(15000)")
	if err != nil {
		return nil, err
	}
	if err := initSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// dbFileUnwritable reports whether path exists but cannot be opened for
// writing — the read-only snapshot case (mode 0444, or a read-only mount). A
// missing file is writable-by-creation (returns false) so the normal
// read-write path creates it; any open error other than a permission/read-only
// denial also returns false and defers to the read-write path, which surfaces
// the real error.
func dbFileUnwritable(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false // missing (or unstattable): let the RW path create/report it
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err == nil {
		f.Close()
		return false
	}
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscallEROFS)
}

// openReadOnlyDB opens path as an immutable, read-only SQLite database. The
// wave snapshot ships without -wal/-shm sidecars, so immutable=1 is safe (and
// skips the shm/lock setup that WAL would otherwise demand on a 0444 file);
// mode=ro plus the query_only(1) pragma make any stray write fail at the
// engine, on top of the up-front readOnlyError refusal. journal_mode(WAL),
// _txlock=immediate and initSchema are deliberately omitted: each writes.
func openReadOnlyDB(path string) (*sql.DB, error) {
	// Build a file: URI so SQLITE_OPEN_URI honors mode/immutable. Without the
	// file: prefix modernc strips the query string from the path and these
	// params never reach the engine; url.URL handles spaces/specials in path.
	u := url.URL{Scheme: "file", Path: path}
	u.RawQuery = "immutable=1&mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	// Force the connection open now so a genuinely corrupt/unreadable snapshot
	// fails here rather than on the first read verb.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("open read-only snapshot %s: %w", path, err)
	}
	dbReadOnly = true
	dbReadOnlyPath = path
	return db, nil
}

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS tasks (
	id         TEXT PRIMARY KEY,
	title      TEXT NOT NULL,
	body       TEXT NOT NULL DEFAULT '',
	status     TEXT NOT NULL DEFAULT 'open',
	priority   INTEGER NOT NULL DEFAULT 0,
	parent_id  TEXT REFERENCES tasks(id) ON DELETE SET NULL,
	branch     TEXT NOT NULL DEFAULT '',
	locked_by  TEXT,
	locked_at  INTEGER,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
	id         TEXT PRIMARY KEY,
	task_id    TEXT REFERENCES tasks(id) ON DELETE CASCADE,
	body       TEXT NOT NULL,
	author     TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS task_deps (
	task_id    TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
	depends_on TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
	PRIMARY KEY (task_id, depends_on)
);

-- Everything below is ephemeral or derived (see docs/22): plain indexed
-- task_id columns, no foreign keys to tasks(id) — thaw's DELETE FROM tasks
-- must neither cascade these away nor fail RESTRICT.

-- EPHEMERAL: machine-local worktree registry (same class as lock state).
CREATE TABLE IF NOT EXISTS worktrees (
	path         TEXT PRIMARY KEY,
	task_id      TEXT NOT NULL,
	branch       TEXT NOT NULL,
	base_ref     TEXT NOT NULL,
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_worktrees_task ON worktrees(task_id);

-- EPHEMERAL: run ledger. The dispatcher is the sole writer, after the agent
-- exits (single-shot, no half-open rows). Durable conclusions go to notes.
CREATE TABLE IF NOT EXISTS agent_runs (
	id            TEXT PRIMARY KEY,
	task_id       TEXT NOT NULL,
	session       TEXT NOT NULL,
	worktree_path TEXT NOT NULL DEFAULT '',
	model         TEXT NOT NULL DEFAULT '',
	status        TEXT NOT NULL,
	exit_code     INTEGER,
	num_turns     INTEGER,
	cost_usd      REAL,
	input_tokens  INTEGER,
	output_tokens INTEGER,
	started_at    INTEGER NOT NULL,
	finished_at   INTEGER NOT NULL,
	note          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_agent_runs_task ON agent_runs(task_id);

-- EPHEMERAL: the agent's structured exit claim (MCP task_report). Recording
-- ≠ status flip: only the dispatcher's verification flips task status.
CREATE TABLE IF NOT EXISTS task_reports (
	id                  TEXT PRIMARY KEY,
	task_id             TEXT NOT NULL,
	session             TEXT NOT NULL,
	status              TEXT NOT NULL,
	summary             TEXT NOT NULL,
	followups           TEXT NOT NULL DEFAULT '[]',
	no_changes_expected INTEGER NOT NULL DEFAULT 0,
	created_at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_reports_task ON task_reports(task_id);

-- DERIVED: doc index. docs/*.md on disk are the only truth; rebuilt by
-- doc sync. hash = git blob SHA-1 (gitBlobSHA), so drift diffs are
-- recoverable via git diff <old-blob> <new-blob>.
CREATE TABLE IF NOT EXISTS docs (
	id         INTEGER PRIMARY KEY,
	path       TEXT NOT NULL UNIQUE,
	title      TEXT NOT NULL DEFAULT '',
	hash       TEXT NOT NULL,
	headings   TEXT NOT NULL DEFAULT '',
	mtime      INTEGER NOT NULL,
	indexed_at INTEGER NOT NULL
);

-- DERIVED: H2-boundary chunks. Chunk 0 = preamble (before the first H2).
-- chunk.hash (blob sha of chunk text) is the embeddings seam.
-- CANONICAL SOURCE: scripts/taskdb/schema/doc_chunks.sql. This embedded copy is
-- the runtime path (no file-IO on openDB); schema_canonical_test.go asserts the
-- two stay byte-equivalent (modulo whitespace / IF NOT EXISTS). Change one,
-- change the other.
CREATE TABLE IF NOT EXISTS doc_chunks (
	id      INTEGER PRIMARY KEY,
	doc_id  INTEGER NOT NULL,
	path    TEXT NOT NULL,
	heading TEXT NOT NULL DEFAULT '',
	seq     INTEGER NOT NULL,
	body    TEXT NOT NULL,
	hash    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_doc_chunks_doc ON doc_chunks(doc_id);
-- hash is the embeddings/provenance seam: serve.py's heal does WHERE hash IN (...)
-- over a batch; without this it full-scans doc_chunks per batch (bgem3w9).
CREATE INDEX IF NOT EXISTS idx_doc_chunks_hash ON doc_chunks(hash);

CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(
	heading, body, path UNINDEXED,
	content='doc_chunks', content_rowid='id', tokenize='porter unicode61');
-- External-content FTS demands the ('delete', old…) idiom on delete/update;
-- skipping it silently corrupts the index.
CREATE TRIGGER IF NOT EXISTS docs_ai AFTER INSERT ON doc_chunks BEGIN
	INSERT INTO docs_fts(rowid, heading, body, path)
		VALUES (new.id, new.heading, new.body, new.path);
END;
CREATE TRIGGER IF NOT EXISTS docs_ad AFTER DELETE ON doc_chunks BEGIN
	INSERT INTO docs_fts(docs_fts, rowid, heading, body, path)
		VALUES ('delete', old.id, old.heading, old.body, old.path);
END;
CREATE TRIGGER IF NOT EXISTS docs_au AFTER UPDATE ON doc_chunks BEGIN
	INSERT INTO docs_fts(docs_fts, rowid, heading, body, path)
		VALUES ('delete', old.id, old.heading, old.body, old.path);
	INSERT INTO docs_fts(rowid, heading, body, path)
		VALUES (new.id, new.heading, new.body, new.path);
END;

-- DERIVED: task search over the existing tasks table (implicit rowid; the
-- TEXT PK is not WITHOUT ROWID). The UPDATE OF column list keeps lock and
-- status flips from churning the index.
CREATE VIRTUAL TABLE IF NOT EXISTS tasks_fts USING fts5(
	title, body, content='tasks', content_rowid='rowid', tokenize='porter unicode61');
CREATE TRIGGER IF NOT EXISTS tasks_ai AFTER INSERT ON tasks BEGIN
	INSERT INTO tasks_fts(rowid, title, body) VALUES (new.rowid, new.title, new.body);
END;
CREATE TRIGGER IF NOT EXISTS tasks_ad AFTER DELETE ON tasks BEGIN
	INSERT INTO tasks_fts(tasks_fts, rowid, title, body)
		VALUES ('delete', old.rowid, old.title, old.body);
END;
CREATE TRIGGER IF NOT EXISTS tasks_au AFTER UPDATE OF title, body ON tasks BEGIN
	INSERT INTO tasks_fts(tasks_fts, rowid, title, body)
		VALUES ('delete', old.rowid, old.title, old.body);
	INSERT INTO tasks_fts(rowid, title, body) VALUES (new.rowid, new.title, new.body);
END;

-- DERIVED: task↔doc edges, parsed from "Sources:" body lines on every doc
-- sync. The task body is the single source of truth; this is a pure index.
CREATE TABLE IF NOT EXISTS task_sources (
	task_id  TEXT NOT NULL,
	doc_path TEXT NOT NULL,
	section  TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (task_id, doc_path, section)
);
CREATE INDEX IF NOT EXISTS idx_task_sources_doc ON task_sources(doc_path);

-- DERIVED: tiny key/value scratch for sync bookkeeping (e.g. the task-body
-- fingerprint that gates the task_sources rebuild). Same class as the doc
-- index — never frozen, rebuilt on demand.
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`)
	if err != nil {
		return err
	}
	// Embeddings seam (docs/22 §8, D9): additive cache keyed on the chunk
	// content hash, idempotent, NEVER frozen. Lives in embeddings.go so the
	// semantic-search seam stays self-contained; created here so the table is
	// present whenever the DB is opened, and re-running it is a no-op.
	return ensureEmbeddingsSchema(db)
}

func msToTime(ms int64) time.Time {
	return time.Unix(0, ms*int64(time.Millisecond)).UTC()
}

func timeToMs(t time.Time) int64 {
	return t.UnixMilli()
}

func scanTask(rows *sql.Rows) (*Task, error) {
	var t Task
	var createdMs, updatedMs int64
	var lockedBy sql.NullString
	var lockedAt sql.NullInt64
	var parentID sql.NullString
	err := rows.Scan(
		&t.ID, &t.Title, &t.Body, &t.Status, &t.Priority,
		&parentID, &t.Branch, &lockedBy, &lockedAt, &createdMs, &updatedMs,
	)
	if err != nil {
		return nil, err
	}
	t.CreatedAt = msToTime(createdMs)
	t.UpdatedAt = msToTime(updatedMs)
	if parentID.Valid {
		t.ParentID = parentID.String
	}
	if lockedBy.Valid {
		t.LockedBy = lockedBy.String
	}
	if lockedAt.Valid {
		t.LockedAt = lockedAt.Int64
	}
	return &t, nil
}

func scanNote(rows *sql.Rows) (*Note, error) {
	var n Note
	var createdMs int64
	var taskID sql.NullString
	err := rows.Scan(&n.ID, &taskID, &n.Body, &n.Author, &createdMs)
	if err != nil {
		return nil, err
	}
	n.CreatedAt = msToTime(createdMs)
	if taskID.Valid {
		n.TaskID = taskID.String
	}
	return &n, nil
}

func scanWorktree(rows *sql.Rows) (*Worktree, error) {
	var w Worktree
	var createdMs, lastUsedMs int64
	err := rows.Scan(&w.Path, &w.TaskID, &w.Branch, &w.BaseRef, &createdMs, &lastUsedMs)
	if err != nil {
		return nil, err
	}
	w.CreatedAt = msToTime(createdMs)
	w.LastUsedAt = msToTime(lastUsedMs)
	return &w, nil
}

func scanRun(rows *sql.Rows) (*AgentRun, error) {
	var r AgentRun
	var exitCode, numTurns, inTokens, outTokens sql.NullInt64
	var cost sql.NullFloat64
	var startedMs, finishedMs int64
	err := rows.Scan(
		&r.ID, &r.TaskID, &r.Session, &r.WorktreePath, &r.Model, &r.Status,
		&exitCode, &numTurns, &cost, &inTokens, &outTokens,
		&startedMs, &finishedMs, &r.Note,
	)
	if err != nil {
		return nil, err
	}
	if exitCode.Valid {
		r.ExitCode = &exitCode.Int64
	}
	if numTurns.Valid {
		r.NumTurns = &numTurns.Int64
	}
	if cost.Valid {
		r.CostUSD = &cost.Float64
	}
	if inTokens.Valid {
		r.InputTokens = &inTokens.Int64
	}
	if outTokens.Valid {
		r.OutputTokens = &outTokens.Int64
	}
	r.StartedAt = msToTime(startedMs)
	r.FinishedAt = msToTime(finishedMs)
	return &r, nil
}

func scanReport(rows *sql.Rows) (*TaskReport, error) {
	var r TaskReport
	var followups string
	var noChanges int
	var createdMs int64
	err := rows.Scan(&r.ID, &r.TaskID, &r.Session, &r.Status, &r.Summary, &followups, &noChanges, &createdMs)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(followups), &r.Followups); err != nil {
		return nil, fmt.Errorf("report %s followups: %w", r.ID, err)
	}
	r.NoChangesExpected = noChanges != 0
	r.CreatedAt = msToTime(createdMs)
	return &r, nil
}

func scanDoc(rows *sql.Rows) (*Doc, error) {
	var d Doc
	var mtimeMs, indexedMs int64
	err := rows.Scan(&d.ID, &d.Path, &d.Title, &d.Hash, &d.Headings, &mtimeMs, &indexedMs)
	if err != nil {
		return nil, err
	}
	d.Mtime = msToTime(mtimeMs)
	d.IndexedAt = msToTime(indexedMs)
	return &d, nil
}

func scanChunk(rows *sql.Rows) (*DocChunk, error) {
	var c DocChunk
	err := rows.Scan(&c.ID, &c.DocID, &c.Path, &c.Heading, &c.Seq, &c.Body, &c.Hash)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// --- SQLITE_BUSY retry ladder (F1) ----------------------------------------
//
// db.go sets busy_timeout, but that only covers the engine's own internal
// spin; it does NOT retry SQLITE_BUSY_SNAPSHOT (517) on a deferred-upgrade
// write, and under many concurrent agents a hard SQLITE_BUSY (5) / SQLITE_LOCKED
// (6) still leaks through after the timeout elapses. With no app-layer retry an
// agent's autocommit write (`task set`, `claim`, `note add`, a dep edge) returns
// a bare "database is locked (5)" exit-1, which an agent loop misreads as a
// spurious idle/failure. execRetry / queryRetry wrap the autocommit write path
// with the same bounded backoff ladder the pre-commit hook uses (0.2/0.4/0.8/
// 1.6/3.2s, capped). They retry ONLY a BUSY/locked failure — never a genuine
// constraint/FK/syntax error — and on exhaustion return the original error so
// the failure stays honest rather than looping forever.

// busyRetryDelays is the backoff ladder (mirrors the pre-commit hook's
// 0.2/0.4/0.8/1.6s, with one extra 3.2s rung capped for the heaviest waves).
// len == attempts-after-the-first, so the statement runs up to len+1 times.
var busyRetryDelays = []time.Duration{
	200 * time.Millisecond,
	400 * time.Millisecond,
	800 * time.Millisecond,
	1600 * time.Millisecond,
	3200 * time.Millisecond,
}

// isBusyErr reports whether err is a SQLITE_BUSY / SQLITE_LOCKED failure (the
// only retryable class). It matches on the modernc driver result code when
// available — the PRIMARY result code is the low 8 bits, so every extended
// BUSY/LOCKED variant (BUSY_SNAPSHOT 517, BUSY_RECOVERY 261, LOCKED_SHAREDCACHE
// 262, …) masks to SQLITE_BUSY (5) or SQLITE_LOCKED (6) — and falls back to the
// message text only when the error is not a *sqlite.Error (e.g. wrapped by a
// caller). A genuine constraint/FK/syntax error has a different code and is
// NEVER matched, so it is never retried.
func isBusyErr(err error) bool {
	if err == nil {
		return false
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() & 0xFF {
		case 5, 6: // SQLITE_BUSY, SQLITE_LOCKED (primary result codes)
			return true
		}
		return false
	}
	// Fallback for a non-driver-typed error: the canonical SQLite message text.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked")
}

// execRetry runs db.Exec, retrying ONLY on SQLITE_BUSY/locked with the bounded
// busyRetryDelays backoff. Use it for autocommit single-statement writes whose
// re-run is idempotent on a BUSY failure (a BUSY means the statement never
// reached the write lock, so no row was touched — re-running it is exactly
// equivalent to running it once). Genuine errors (constraint/FK/syntax) return
// immediately. On exhaustion the LAST (original-class) error is returned.
func execRetry(db *sql.DB, query string, args ...any) (sql.Result, error) {
	var res sql.Result
	var err error
	for attempt := 0; ; attempt++ {
		res, err = db.Exec(query, args...)
		if err == nil || !isBusyErr(err) || attempt >= len(busyRetryDelays) {
			return res, err
		}
		time.Sleep(busyRetryDelays[attempt])
	}
}

// queryRetry runs db.Query, retrying ONLY on SQLITE_BUSY/locked with the same
// bounded backoff. It is for autocommit write-via-RETURNING statements
// (claimLocal's UPDATE…RETURNING): the UPDATE is atomic, so a BUSY means it
// never acquired the write lock and updated NO row — re-running re-evaluates the
// whole ready-select+update and still claims AT MOST one task (exact-once is
// preserved; there is no path where a retry double-claims). The returned
// *sql.Rows is the caller's to Close. On exhaustion the original error returns.
func queryRetry(db *sql.DB, query string, args ...any) (*sql.Rows, error) {
	var rows *sql.Rows
	var err error
	for attempt := 0; ; attempt++ {
		rows, err = db.Query(query, args...)
		if err == nil || !isBusyErr(err) || attempt >= len(busyRetryDelays) {
			return rows, err
		}
		time.Sleep(busyRetryDelays[attempt])
	}
}

// gitBlobSHA returns the git blob SHA-1 of b — sha1 over "blob <len>\x00" +
// bytes, hex-encoded — so doc drift diffs stay recoverable via
// `git diff <old-blob> <new-blob>` / `git cat-file`.
func gitBlobSHA(b []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
