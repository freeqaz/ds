// SPDX-License-Identifier: Apache-2.0
package main

// lockserver.go is the shared-lock-server seam: it lets concurrent agents on
// different machines coordinate task locks through a single Postgres registry,
// reached over an SSH tunnel (a locked-down forward-only account). It is the
// ONLY part of taskdb that talks to Postgres, and Postgres holds NOTHING but
// lock rows — the git repo (tasks/*.json) stays the single authority for task
// content, dependencies, and the DAG. Losing the lock database loses no
// durable work; every row is reconstructable by simply re-locking.
//
// Policy (set by the team, see scripts/taskdb/README.md "Shared lock server"):
//   - DISABLED by default via the committed example lockserver.json, so a
//     fresh clone locks locally (per-clone SQLite) and never dials out;
//   - opt in by editing lockserver.json with your own registry's coordinates,
//     or just by exporting TASKDB_LOCK_DSN (which both overrides the connection
//     string and enables remote locking);
//   - TASKDB_LOCK_DISABLE=1 forces local-only locking regardless of the file;
//   - FAIL-OPEN (the DEFAULT): if the server is enabled but unreachable (e.g.
//     the dev hasn't opened their tunnel), taskdb prints ONE loud degraded-mode
//     banner and falls back to per-machine SQLite locks rather than blocking
//     work;
//   - TASKDB_LOCK_REQUIRED=1 opts into FAIL-CLOSED dispatch: when the server is
//     enabled-but-unreachable, a claim/lock REFUSES (non-zero exit, acquires NO
//     local-only lock) instead of falling back, so a claim that cannot register
//     cross-machine never silently coordinates nothing. DISABLE wins over
//     REQUIRED (TASKDB_LOCK_DISABLE=1 is intentional solo work — REQUIRED is
//     moot when the server is deliberately off). Orthogonal to and
//     complementary with `lockserver check --strict` (a wave pre-flight gate;
//     this is per-claim enforcement).
//
// Locks remain runtime-only on both sides: the SQLite locked_by/locked_at
// columns are a write-through MIRROR of the remote holder so the existing
// readyWhere / list / tui / task_report code paths keep reading local columns
// unchanged. Acquisition under contention is the only operation that must be
// atomic across machines, and that always goes to Postgres first.

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// pq is imported by NAME (not blank) so claimNextLandBatch can use pq.Array to
	// pass an id-set to a Postgres `= ANY($n::bigint[])`. A named import still runs
	// the driver's init() that registers "postgres" with database/sql, so the
	// existing sql.Open("postgres", …) callers are unaffected.
	"github.com/lib/pq"
)

//go:embed lockserver.sql
var lockSchemaSQL string

//go:embed lockserver.json
var defaultLockConfigJSON []byte

// lockConfig is the parsed lockserver.json (plus env overrides). Only the
// Postgres block and the SSH block (for the tunnel-command helper) matter.
type lockConfig struct {
	Enabled  bool      `json:"enabled"`
	SSH      sshConfig `json:"ssh"`
	Postgres pgConfig  `json:"postgres"`

	// dsnOverride, when set from TASKDB_LOCK_DSN, is used verbatim and wins
	// over the Postgres block.
	dsnOverride string `json:"-"`
}

type sshConfig struct {
	Host         string `json:"host"`
	User         string `json:"user"`
	RemotePGHost string `json:"remote_pg_host"`
	RemotePGPort int    `json:"remote_pg_port"`
	LocalPort    int    `json:"local_port"`
}

type pgConfig struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	DBName         string `json:"dbname"`
	User           string `json:"user"`
	Password       string `json:"password"`
	SSLMode        string `json:"sslmode"`
	ConnectTimeout int    `json:"connect_timeout"`
}

var (
	lockCfgOnce sync.Once
	lockCfg     *lockConfig
	lockCfgErr  error
	degradeOnce sync.Once
)

// loadLockConfig resolves the effective lock-server configuration, once per
// process. Resolution order:
//  1. TASKDB_LOCK_DISABLE truthy → disabled (local-only), regardless of file.
//  2. base config: <repoRoot>/scripts/taskdb/lockserver.json if present
//     (live-editable), else the embedded default.
//  3. TASKDB_LOCK_DSN set → enabled with that DSN verbatim.
//
// A missing file AND a parse error both fall back to the embedded default so a
// fresh checkout still works; a genuine env/parse problem is returned so the
// caller can warn.
func loadLockConfig() (*lockConfig, error) {
	lockCfgOnce.Do(func() { lockCfg, lockCfgErr = resolveLockConfig() })
	return lockCfg, lockCfgErr
}

// resolveLockConfig does the actual resolution (loadLockConfig memoizes it via
// sync.Once). Factored out so tests can exercise the env/file/override branches
// without the process-global cache.
func resolveLockConfig() (*lockConfig, error) {
	if truthyEnv("TASKDB_LOCK_DISABLE") {
		return &lockConfig{Enabled: false}, nil
	}
	raw := defaultLockConfigJSON
	if root, err := repoRoot(); err == nil {
		p := filepath.Join(root, "scripts", "taskdb", "lockserver.json")
		if b, err := os.ReadFile(p); err == nil {
			raw = b
		}
	}
	var cfg lockConfig
	var cfgErr error
	if err := json.Unmarshal(raw, &cfg); err != nil {
		// Fall back to the embedded default rather than bricking locking on a
		// malformed on-disk edit, but surface the error.
		cfgErr = fmt.Errorf("parsing lockserver.json: %w", err)
		_ = json.Unmarshal(defaultLockConfigJSON, &cfg)
	}
	if dsn := strings.TrimSpace(os.Getenv("TASKDB_LOCK_DSN")); dsn != "" {
		cfg.dsnOverride = dsn
		cfg.Enabled = true
	}
	return &cfg, cfgErr
}

func truthyEnv(k string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// dsn builds a lib/pq keyword/value connection string. Keyword/value form
// (not a URL) is used so passwords with URL-special characters need no
// escaping beyond the single-quote rule pq documents.
func (c *lockConfig) dsn() string {
	if c.dsnOverride != "" {
		return c.dsnOverride
	}
	p := c.Postgres
	ct := p.ConnectTimeout
	if ct <= 0 {
		ct = 5
	}
	ssl := p.SSLMode
	if ssl == "" {
		ssl = "disable"
	}
	var b strings.Builder
	kv := func(k, v string) {
		// pq: wrap in single quotes, backslash-escaping \ and '.
		v = strings.ReplaceAll(v, `\`, `\\`)
		v = strings.ReplaceAll(v, `'`, `\'`)
		fmt.Fprintf(&b, "%s='%s' ", k, v)
	}
	kv("host", p.Host)
	fmt.Fprintf(&b, "port=%d ", p.Port)
	kv("dbname", p.DBName)
	kv("user", p.User)
	kv("password", p.Password)
	kv("sslmode", ssl)
	fmt.Fprintf(&b, "connect_timeout=%d", ct)
	return strings.TrimSpace(b.String())
}

// redactedDSN is dsn() with the password masked, for diagnostics/logging.
func (c *lockConfig) redactedDSN() string {
	if c.dsnOverride != "" {
		// Best-effort mask of password=... in a raw override.
		return maskPassword(c.dsnOverride)
	}
	masked := *c
	masked.Postgres.Password = "***"
	return masked.dsn()
}

func maskPassword(dsn string) string {
	// Handle both URL (password in userinfo) and keyword/value forms cheaply.
	out := dsn
	for _, marker := range []string{"password='", "password="} {
		if i := strings.Index(out, marker); i >= 0 {
			rest := out[i+len(marker):]
			end := len(rest)
			for j, r := range rest {
				if marker == "password=" && (r == ' ') {
					end = j
					break
				}
				if marker == "password='" && r == '\'' {
					end = j
					break
				}
			}
			out = out[:i+len(marker)] + "***" + rest[end:]
		}
	}
	return out
}

// tunnelCmd returns the exact ssh command a dev runs to open the lock-server
// tunnel, derived from the SSH block.
func (c *lockConfig) tunnelCmd() string {
	s := c.SSH
	rhost := s.RemotePGHost
	if rhost == "" {
		rhost = "127.0.0.1"
	}
	rport := s.RemotePGPort
	if rport == 0 {
		rport = 5432
	}
	lport := s.LocalPort
	if lport == 0 {
		lport = 5433
	}
	return fmt.Sprintf("ssh -N -L %d:%s:%d %s@%s", lport, rhost, rport, s.User, s.Host)
}

func (c *lockConfig) connectTimeout() time.Duration {
	ct := c.Postgres.ConnectTimeout
	if ct <= 0 {
		ct = 5
	}
	// Pad the context deadline a hair over pq's own connect_timeout so the
	// driver's error wins over a context cancel.
	return time.Duration(ct+1) * time.Second
}

// RemoteLock is one row of the shared registry.
type RemoteLock struct {
	TaskID   string    `json:"task_id"`
	LockedBy string    `json:"locked_by"`
	Host     string    `json:"host,omitempty"`
	LockedAt time.Time `json:"locked_at"`
	Note     string    `json:"note,omitempty"`
}

// RemoteTombstone is one task_done row: a short-lived record that a task reached
// a terminal state (done|dropped) somewhere in the fleet, used to skip/refuse a
// claim of work another clone already finished before this clone has pulled the
// terminal state (docs/23 Proposal A). Disposable soft state, like RemoteLock —
// never frozen to tasks/*.json, reconstructable, reaped by age.
type RemoteTombstone struct {
	TaskID string    `json:"task_id"`
	Status string    `json:"status"`
	By     string    `json:"by,omitempty"`
	Host   string    `json:"host,omitempty"`
	At     time.Time `json:"at"`
}

// lockServer is a connected handle to the shared Postgres lock registry.
type lockServer struct {
	db  *sql.DB
	cfg *lockConfig
}

// openLockServer connects and pings within the configured connect timeout.
func openLockServer(cfg *lockConfig) (*lockServer, error) {
	db, err := sql.Open("postgres", cfg.dsn())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.connectTimeout())
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &lockServer{db: db, cfg: cfg}, nil
}

func (ls *lockServer) close() {
	if ls != nil && ls.db != nil {
		ls.db.Close()
	}
}

// lockServerOrLocal resolves the policy for a lock-MUTATING verb (lock, unlock,
// claim, release, reap). The three outcomes are:
//   - (ls, nil):  remote locking is enabled AND reachable — use ls (caller must
//     ls.close() it);
//   - (nil, nil): use LOCAL SQLite locking — either remote is disabled (silent)
//     or it is enabled-but-unreachable AND fail-open applies (the DEFAULT: a
//     one-time degraded banner is printed and we fall back);
//   - (nil, err): FAIL-CLOSED refusal — remote is enabled-but-unreachable AND
//     TASKDB_LOCK_REQUIRED is set. The caller's claim/lock verb must propagate
//     this error so the command exits non-zero WITHOUT acquiring a local lock.
//     Non-claim paths (drop's best-effort force-release, reap's admin cleanup)
//     deliberately IGNORE the error and treat it as (nil) → skip the remote op.
func lockServerOrLocal() (*lockServer, error) {
	cfg, err := loadLockConfig()
	if err != nil {
		warnDegraded("taskdb lock-server: %v — using LOCAL-ONLY locks", err)
	}
	if cfg == nil || !cfg.Enabled {
		return nil, nil // disabled (incl. TASKDB_LOCK_DISABLE): silent local-only
	}
	ls, openErr := openLockServer(cfg)
	return lockPolicyDecision(cfg, ls, openErr)
}

// lockPolicyDecision is the PURE policy core of lockServerOrLocal, split out so
// the four behavior cases (reachable / unreachable+fail-open / unreachable+
// fail-closed / disabled-handled-by-caller) are unit-testable without a live
// Postgres. cfg is the resolved (necessarily Enabled) config; ls/openErr are the
// result of openLockServer. It performs the (side-effecting) degraded-banner
// print on the fail-open branch, matching the original inline behavior exactly.
//
// REQUIRED is read here (truthyEnv) rather than baked into cfg so a long-lived
// MCP process picks up the env as set per the process, mirroring how DISABLE/DSN
// are resolved from the environment.
func lockPolicyDecision(cfg *lockConfig, ls *lockServer, openErr error) (*lockServer, error) {
	if openErr == nil {
		return ls, nil // reachable
	}
	if truthyEnv("TASKDB_LOCK_REQUIRED") {
		// FAIL-CLOSED (opt-in): refuse rather than coordinate nothing. No local
		// lock is acquired — the caller propagates this error to a non-zero exit.
		return nil, lockRequiredError(cfg.tunnelCmd(), openErr)
	}
	// FAIL-OPEN (default): one loud banner, then local-only.
	warnDegraded("shared lock server unreachable: %v\n"+
		"  ⇒ falling back to LOCAL-ONLY locks — cross-machine coordination is OFF for this command.\n"+
		"  ⇒ open the tunnel to restore coordination:  %s\n"+
		"  ⇒ or silence this by setting TASKDB_LOCK_DISABLE=1 for intentional solo work.",
		compactErr(openErr), cfg.tunnelCmd())
	return nil, nil
}

// lockRequiredError builds the loud, actionable fail-closed refusal returned
// when TASKDB_LOCK_REQUIRED is set and the shared lock server is enabled but
// unreachable. It names the flag, the tunnel command, and the three overrides
// (open the tunnel / unset REQUIRED / set DISABLE for intentional solo work) so
// an operator can self-serve. Pure (no I/O) for table-testability; deliberately
// distinct from strictGateError — the two gates are orthogonal.
func lockRequiredError(tunnelCmd string, cause error) error {
	return fmt.Errorf("shared lock server unreachable and TASKDB_LOCK_REQUIRED=1 — REFUSING to fall back to a LOCAL-ONLY lock that coordinates nothing cross-machine (%s)\n"+
		"  ⇒ open the tunnel to restore coordination:  %s\n"+
		"  ⇒ or unset TASKDB_LOCK_REQUIRED to allow fail-open local-only locks (the default)\n"+
		"  ⇒ or set TASKDB_LOCK_DISABLE=1 for intentional solo work (DISABLE wins over REQUIRED)",
		compactErr(cause), tunnelCmd)
}

// warnDegraded prints a one-time loud banner to stderr (once per process), so a
// degraded long-lived MCP server logs it once rather than on every claim.
func warnDegraded(format string, a ...any) {
	degradeOnce.Do(func() {
		fmt.Fprintf(os.Stderr, "⚠ taskdb: "+format+"\n", a...)
	})
}

func compactErr(err error) string {
	return strings.TrimSpace(strings.ReplaceAll(err.Error(), "\n", " "))
}

// devHost is the human-facing holder identity recorded alongside the session.
func devHost() string {
	if d := strings.TrimSpace(os.Getenv("TASKDB_DEV")); d != "" {
		return d
	}
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "unknown"
}

// --- remote registry operations ---

// migrate applies the embedded lock schema (idempotent CREATE TABLE/INDEX).
func (ls *lockServer) migrate() error {
	_, err := ls.db.Exec(lockSchemaSQL)
	return err
}

// schemaPresent reports whether the task_locks table exists yet.
func (ls *lockServer) schemaPresent() (bool, error) {
	var n int
	err := ls.db.QueryRow(
		`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = current_schema() AND table_name = 'task_locks'`,
	).Scan(&n)
	return n > 0, err
}

// landSchemaPresent reports whether the land_queue table exists yet, so the
// landq verbs can nudge `lockserver migrate` on an un-migrated DB instead of
// failing blind. Mirrors schemaPresent().
func (ls *lockServer) landSchemaPresent() (bool, error) {
	var n int
	err := ls.db.QueryRow(
		`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = current_schema() AND table_name = 'land_queue'`,
	).Scan(&n)
	return n > 0, err
}

// acquire atomically claims taskID for session. Returns (true, nil, nil) on
// success; (false, holder, nil) when already held by someone else.
func (ls *lockServer) acquire(taskID, session, host string) (bool, *RemoteLock, error) {
	var got string
	err := ls.db.QueryRow(
		`INSERT INTO task_locks (task_id, locked_by, host, locked_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (task_id) DO NOTHING
		 RETURNING task_id`,
		taskID, session, host,
	).Scan(&got)
	if err == sql.ErrNoRows {
		h, herr := ls.holder(taskID)
		return false, h, herr
	}
	if err != nil {
		return false, nil, err
	}
	return true, nil, nil
}

// refreshLock bumps locked_at=now() for a lock the SAME session already holds —
// the idempotent same-session relock refresh (F4). It is session-scoped (WHERE
// locked_by = session) so it can ONLY refresh a row this session still holds; a
// lock a peer took in the meantime, or an absent row, matches zero rows and
// returns (false, nil). Returns whether a row was refreshed.
func (ls *lockServer) refreshLock(taskID, session string) (bool, error) {
	res, err := ls.db.Exec(
		`UPDATE task_locks SET locked_at = now() WHERE task_id = $1 AND locked_by = $2`,
		taskID, session,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// release drops the lock for taskID. Without force, only the holding session
// may release (WHERE locked_by=session). Returns whether a row was removed.
func (ls *lockServer) release(taskID, session string, force bool) (bool, error) {
	var got string
	err := ls.db.QueryRow(
		`DELETE FROM task_locks WHERE task_id = $1 AND ($3 OR locked_by = $2) RETURNING task_id`,
		taskID, session, force,
	).Scan(&got)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// holder returns the current lock for taskID, or nil if unlocked.
func (ls *lockServer) holder(taskID string) (*RemoteLock, error) {
	var l RemoteLock
	err := ls.db.QueryRow(
		`SELECT task_id, locked_by, host, locked_at, note FROM task_locks WHERE task_id = $1`,
		taskID,
	).Scan(&l.TaskID, &l.LockedBy, &l.Host, &l.LockedAt, &l.Note)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// list returns every held lock, oldest first.
func (ls *lockServer) list() ([]RemoteLock, error) {
	rows, err := ls.db.Query(
		`SELECT task_id, locked_by, host, locked_at, note FROM task_locks ORDER BY locked_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RemoteLock{}
	for rows.Next() {
		var l RemoteLock
		if err := rows.Scan(&l.TaskID, &l.LockedBy, &l.Host, &l.LockedAt, &l.Note); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// --- wave telemetry (additive; never touches task_locks) ---

// WaveEvent is one intra-workflow transition the task-wave engine records
// through an already-running agent. It is disposable coordination/observability
// state, exactly like a lock row: the git repo stays the authority for task
// content. All fields are optional except a phase or event to be meaningful.
// The json tags are the wire shape the dashboard reads (wave-event list --json).
type WaveEvent struct {
	Wave       string `json:"wave"`
	RunID      string `json:"run_id"`
	UnitKey    string `json:"unit_key"`
	TaskID     string `json:"task_id"`
	Phase      string `json:"phase"`
	AgentLabel string `json:"agent_label"`
	Event      string `json:"event"`
	Status     string `json:"status"`
	Session    string `json:"session"`
	Host       string `json:"host"`
	Tokens     int64  `json:"tokens"`
	Note       string `json:"note"`
	// Ts is the server-clock event time, set on reads (empty on the write path).
	Ts string `json:"ts,omitempty"`
}

// WaveUnitRollup is a per-(wave,unit) progress summary the dashboard groups on:
// the latest phase/status a unit reached, how many events it has, and when it
// last moved — joined to the task by id on the dashboard side.
type WaveUnitRollup struct {
	Wave       string `json:"wave"`
	RunID      string `json:"run_id"`
	UnitKey    string `json:"unit_key"`
	TaskID     string `json:"task_id"`
	LastPhase  string `json:"last_phase"`
	LastStatus string `json:"last_status"`
	LastEvent  string `json:"last_event"`
	EventCount int    `json:"event_count"`
	UpdatedAt  string `json:"updated_at"`
}

// WaveRun is a per-(wave,run_id) HISTORICAL summary: one row per workflow run the
// telemetry stream ever recorded, regardless of how long ago it ran. Where
// `listEvents`/`unitRollup` feed the live overview off the recent-event tail (so
// an old run that scrolled out of the cap vanishes), `listRuns` aggregates the
// WHOLE append-only wave_events table, so the dashboard can browse every past run
// — not just what is live now. Terminal/Landed distill the run's outcome from its
// own end events. Read-only; the json tags are the wire shape the dashboard reads
// (wave-event runs --json).
type WaveRun struct {
	Wave  string `json:"wave"`
	RunID string `json:"run_id"`
	// StartedAt/LastTs bound the run: MIN/MAX(ts) across all its events.
	StartedAt string `json:"started_at"`
	LastTs    string `json:"last_ts"`
	// EventCount is every telemetry row in the run; UnitCount the distinct units.
	EventCount int `json:"event_count"`
	UnitCount  int `json:"unit_count"`
	// Terminal: the run emitted a land/finalize `end` (it finished, vs died
	// mid-flight). Landed: it reached a phase='land' status='landed' — the
	// strongest "this run shipped to main" signal.
	Terminal bool `json:"terminal"`
	Landed   bool `json:"landed"`
}

// --- serialized landing queue (additive; never touches task_locks semantics) ---

// landLeaderSentinel is the literal task_id used to elect the single landing
// writer. The runner acquire()s it into task_locks (INSERT..ON CONFLICT DO
// NOTHING — the winner is the leader); a dead leader's sentinel is reaped by age
// exactly like a stale task lock, so leader election needs no election schema.
const landLeaderSentinel = "__land_leader__"

// LandEntry is one row of the land_queue: a gate-green branch waiting to be
// fast-forward-landed onto main by the serial runner. Like a lock or wave-event
// row it is disposable coordination state — the git branch refs are the sole
// authority, and losing these rows loses no durable work (the next wave
// re-enqueues). The json tags are the wire shape the landq CLI reads. StartedAt
// and FinishedAt model the nullable TIMESTAMPTZ columns as *string (a NULL scans
// cleanly, and reads render them as a string like WaveEvent.Ts); both are empty
// on the enqueue path.
type LandEntry struct {
	ID          int64   `json:"id"`
	Branch      string  `json:"branch"`
	BaseSHA     string  `json:"base_sha,omitempty"`
	TaskIDs     string  `json:"task_ids,omitempty"`
	Gate        string  `json:"gate,omitempty"` // gate command run in the merged worktree before FF-push; '' = the runner falls back to its static --gate
	Wave        string  `json:"wave,omitempty"`
	RunID       string  `json:"run_id,omitempty"`
	Priority    int     `json:"priority"`
	Status      string  `json:"status"`
	RequestedBy string  `json:"requested_by,omitempty"`
	Host        string  `json:"host,omitempty"`
	Runner      string  `json:"runner,omitempty"`
	Attempts    int     `json:"attempts"`
	MergeCommit string  `json:"merge_commit,omitempty"`
	Detail      string  `json:"detail,omitempty"`
	EnqueuedAt  string  `json:"enqueued_at,omitempty"`
	StartedAt   *string `json:"started_at,omitempty"`
	FinishedAt  *string `json:"finished_at,omitempty"`
}

// enqueueLand inserts a 'queued' land_queue row for e.Branch, idempotently. The
// uq_land_queue_active PARTIAL unique index (WHERE status IN ('queued','landing'))
// admits exactly ONE active row per branch, so a re-enqueue while a row is still
// in flight is a no-op: the INSERT..ON CONFLICT names that index's predicate
// explicitly (a bare ON CONFLICT (branch) would NOT match a partial index) and DO
// NOTHING; on the no-row return we SELECT the existing active row's id and report
// enqueued=false. On a fresh insert enqueued=true. Mirrors acquire()'s
// INSERT..ON CONFLICT DO NOTHING RETURNING shape — the winner takes the slot.
//
// DEDUP IS BRANCH-ONLY, AND THAT IS INTENTIONAL (#14). The active-row uniqueness
// keys on the BRANCH NAME alone, so a re-enqueue of the SAME branch is a no-op —
// exactly the property a wave's idempotent retry (or a double-enqueue) relies on:
// re-queueing while the first row is still queued/landing must not stack a second
// land of the same work. The theoretical footgun — two DIFFERENT contents pushed
// under the SAME branch name colliding on this slot — is made rare upstream: the
// producer mints a UNIQUE integration-branch name per wave/run, so same-name/
// different-content reuse essentially does not occur in practice. If it ever did,
// the loser's content simply waits for the active row to clear and re-enqueues.
func (ls *lockServer) enqueueLand(e LandEntry) (id int64, enqueued bool, err error) {
	err = ls.db.QueryRow(
		`INSERT INTO land_queue (branch, base_sha, task_ids, gate, wave, run_id, priority, status, requested_by, host)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,'queued',$8,$9)
		 ON CONFLICT (branch) WHERE status IN ('queued','landing') DO NOTHING
		 RETURNING id`,
		e.Branch, e.BaseSHA, e.TaskIDs, e.Gate, e.Wave, e.RunID, e.Priority, e.RequestedBy, e.Host,
	).Scan(&id)
	if err == sql.ErrNoRows {
		// An active row already holds the slot — report its id, enqueued=false.
		serr := ls.db.QueryRow(
			`SELECT id FROM land_queue
			  WHERE branch = $1 AND status IN ('queued','landing')
			  ORDER BY id DESC LIMIT 1`,
			e.Branch,
		).Scan(&id)
		if serr != nil {
			return 0, false, serr
		}
		return id, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// listLand returns land_queue rows newest-first (id DESC), optionally narrowed to
// one status. limit<=0 means no limit (the queue is small). The runner's
// pick-order is a later task's concern; this is the operator/dashboard read.
// Read-only. The three TIMESTAMPTZ columns are read via to_char() like listEvents;
// the nullable started_at/finished_at scan through sql.NullString into the *string
// fields so a NULL renders as omitted rather than failing the Scan.
func (ls *lockServer) listLand(status string, limit int) ([]LandEntry, error) {
	q := `SELECT id, branch, base_sha, task_ids, gate, wave, run_id, priority, status,
	              requested_by, host, runner, attempts, merge_commit, detail,
	              to_char(enqueued_at, 'YYYY-MM-DD"T"HH24:MI:SSOF'),
	              to_char(started_at,  'YYYY-MM-DD"T"HH24:MI:SSOF'),
	              to_char(finished_at, 'YYYY-MM-DD"T"HH24:MI:SSOF')
	         FROM land_queue
	        WHERE ($1='' OR status=$1)
	        ORDER BY id DESC`
	args := []any{status}
	if limit > 0 {
		q += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := ls.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LandEntry{}
	for rows.Next() {
		var e LandEntry
		var started, finished sql.NullString
		if err := rows.Scan(&e.ID, &e.Branch, &e.BaseSHA, &e.TaskIDs, &e.Gate, &e.Wave, &e.RunID,
			&e.Priority, &e.Status, &e.RequestedBy, &e.Host, &e.Runner, &e.Attempts,
			&e.MergeCommit, &e.Detail, &e.EnqueuedAt, &started, &finished); err != nil {
			return nil, err
		}
		if started.Valid {
			s := started.String
			e.StartedAt = &s
		}
		if finished.Valid {
			f := finished.String
			e.FinishedAt = &f
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// deleteLandByBranch removes EVERY land_queue row for a branch, returning the
// count. Unexported, test-only cleanup so a round-trip test leaves no rows behind
// in the shared DB (there is no `landq cancel` verb yet — that lands in a later
// task). Never called by the CLI.
func (ls *lockServer) deleteLandByBranch(branch string) (int64, error) {
	res, err := ls.db.Exec(`DELETE FROM land_queue WHERE branch = $1`, branch)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- done-tombstone registry (additive; the status-aware-claim, docs/23 Prop A) ---
//
// A terminal completion (release to done/dropped, or the landing queue FF-landing
// a branch) writes a SHORT-LIVED task_done tombstone keyed by task_id; the claim
// path consults it and skips/refuses a candidate the local clone has not yet
// pulled, closing the "redo work another clone already finished" window (docs/23
// §1.1, risk #2). RESOLVED decisions implemented here (do NOT re-open):
//
//   - OQ-A1 (skip vs refuse): an AUTO-claim (`task list --ready`/`task claim` with
//     no explicit id) SILENTLY SKIPS a gating tombstoned candidate; an EXPLICIT
//     `claim <id>` / `lock <id>` REFUSES with a loud, actionable error naming the
//     completing status/host/time and the `git pull` / reopen escape hatches.
//   - OQ-A2 (TTL): tombstoneTTL() defaults to 24h, env-tunable via
//     TASKDB_TOMBSTONE_TTL (Go duration). reapTombstones(age) ages out rows; it is
//     wired into the standing reap path (reapLocksRemote) AND fired opportunistically
//     at the top of claimRemote — both best-effort, mirroring lock reap()/
//     reapStaleLanding self-cleaning.
//   - OQ-A3 (reopen clears): a deliberate reopen (done -> open/in-progress, via a
//     non-terminal release or `task set --status open`) DELETEs the tombstone so
//     claim offers the task again. The freshness comparison ALSO self-heals before
//     the DELETE fires: once the clone's local updated_at >= the tombstone's `at`
//     (the clone pulled the terminal/reopened row), the tombstone no longer gates.
//
// FRESHNESS SEMANTICS (the load-bearing reader rule, see claimRemote): a tombstone
// GATES a candidate only when tombstone.At is STRICTLY NEWER than the candidate's
// local updated_at — i.e. this clone has NOT yet pulled+thawed the terminal state
// (its local row predates the registry's record of completion). A clone that HAS
// pulled the done/dropped row, or whose reopen bumped updated_at past `at`, has
// updated_at >= At and is correctly NOT gated. Worst case is a redundant skip,
// never a lost task — the same fail-toward-availability posture as locks.
//
// DEFERRED (note only — docs/23 §2 "Optionally mirror"): mirroring the tombstone
// into local SQLite so `list --ready` also HIDES a tombstoned task. The claim-path
// skip below already closes the CORRECTNESS risk; the list cosmetic is a follow-up.

// tombstoneTTL is the age past which a done-tombstone is reaped (OQ-A2). Defaults
// to 24h — comfortably longer than a normal pull cycle so the tombstone outlives
// the window before a clone pulls the terminal state — and is env-tunable via
// TASKDB_TOMBSTONE_TTL (any Go duration, e.g. "12h", "90m"). A malformed or
// non-positive value falls back to the 24h default (never zero, which would reap
// every tombstone instantly).
func tombstoneTTL() time.Duration {
	const def = 24 * time.Hour
	v := strings.TrimSpace(os.Getenv("TASKDB_TOMBSTONE_TTL"))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return def
	}
	return d
}

// autoReapAge is the age past which an ORPHANED shared lock is AUTOMATICALLY
// aged out — with no operator running a reap verb — by the opportunistic reap
// paths (claimRemote's top-of-claim sweep and the landq leader's idle loop).
// Defaults to 2h, deliberately LOOSER than the 30m manual `lockserver reap`
// default because lock_heartbeats emission is not yet universal (docs/23 OQ4,
// re-scoped 2026-07-02): a longer default keeps a live-but-quiet, non-emitting
// holder from being evicted while still bounding how long a truly-orphaned wave
// lock lingers. Env-tunable via TASKDB_LOCK_AUTOREAP_AGE (any Go duration, e.g.
// "1h", "90m"). A NON-POSITIVE value or the literal "off" DISABLES the automatic
// reap entirely (returns 0 — callers guard on `> 0`); a malformed value also
// disables (returns 0) so a typo can never silently reap at some surprise age.
// The predicate itself (reapLockStaleSQL, reused unchanged by reap()) is
// activity-aware and sentinel-excluding, so a live heartbeating holder past this
// age and the __land_leader__ sentinel are never reaped regardless of the age.
func autoReapAge() time.Duration {
	const def = 2 * time.Hour
	v := strings.TrimSpace(os.Getenv("TASKDB_LOCK_AUTOREAP_AGE"))
	if v == "" {
		return def
	}
	if strings.EqualFold(v, "off") {
		return 0
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0
	}
	return d
}

// upsertTombstone records (or refreshes) the done-tombstone for taskID. The
// PRIMARY KEY collapses repeated completions of the same id to one row, and `at`
// is re-stamped to now() on every write so a re-completion extends the TTL. Used
// by the release path (cores.go) and the landing-queue real-land branch
// (cmd_landq.go), both best-effort.
func (ls *lockServer) upsertTombstone(taskID, status, by, host string) error {
	_, err := ls.db.Exec(
		`INSERT INTO task_done (task_id, status, by, host, at)
		 VALUES ($1, $2, $3, $4, now())
		 ON CONFLICT (task_id) DO UPDATE
		   SET status = EXCLUDED.status, by = EXCLUDED.by, host = EXCLUDED.host, at = now()`,
		taskID, status, by, host,
	)
	return err
}

// deleteTombstone clears the done-tombstone for taskID (OQ-A3: a deliberate
// reopen). Idempotent — deleting an absent row is fine.
func (ls *lockServer) deleteTombstone(taskID string) error {
	_, err := ls.db.Exec(`DELETE FROM task_done WHERE task_id = $1`, taskID)
	return err
}

// tombstonedTasks returns every current tombstone keyed by task_id, for the
// one-snapshot claim consult (like syncLocksFromRemote's ls.list()). On an
// UN-migrated DB (task_done absent) or any query error it returns an EMPTY map,
// NOT an error — the caller then gates nothing and falls back to today's
// unguarded claim, exactly mirroring heartbeatAgesByTask's degrade-to-no-data
// posture so a new binary on an old DB never fails.
func (ls *lockServer) tombstonedTasks() (map[string]RemoteTombstone, error) {
	rows, err := ls.db.Query(`SELECT task_id, status, by, host, at FROM task_done`)
	if err != nil {
		// Table absent (un-migrated old DB) or any query error → no tombstone
		// data; the caller gates nothing. Never fatal.
		return map[string]RemoteTombstone{}, nil
	}
	defer rows.Close()
	out := map[string]RemoteTombstone{}
	for rows.Next() {
		var ts RemoteTombstone
		if err := rows.Scan(&ts.TaskID, &ts.Status, &ts.By, &ts.Host, &ts.At); err != nil {
			return out, nil
		}
		out[ts.TaskID] = ts
	}
	return out, rows.Err()
}

// isTombstoned returns the tombstone for taskID, or (nil, nil) when none exists —
// the single-row read for the explicit-id refuse path (taskLock). On an
// un-migrated DB / query error it returns (nil, nil) so an explicit lock degrades
// to today's unguarded behavior rather than failing.
func (ls *lockServer) isTombstoned(taskID string) (*RemoteTombstone, error) {
	var ts RemoteTombstone
	err := ls.db.QueryRow(
		`SELECT task_id, status, by, host, at FROM task_done WHERE task_id = $1`,
		taskID,
	).Scan(&ts.TaskID, &ts.Status, &ts.By, &ts.Host, &ts.At)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		// Un-migrated DB or any read error → no tombstone data; never fatal.
		return nil, nil
	}
	return &ts, nil
}

// reapTombstones DELETEs every tombstone older than age and returns the reaped
// task ids (mirrors reap() for locks). Best-effort callers ignore the error.
func (ls *lockServer) reapTombstones(age time.Duration) ([]string, error) {
	secs := int64(age.Seconds())
	if secs < 0 {
		secs = 0
	}
	rows, err := ls.db.Query(
		`DELETE FROM task_done WHERE at < now() - make_interval(secs => $1) RETURNING task_id`,
		secs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// tombstoneGates reports whether ts (a tombstone for the candidate) should GATE a
// claim of a candidate whose local row was last updated at localUpdated. It gates
// only when the tombstone is STRICTLY NEWER than the local row — the clone has
// not yet pulled the terminal state. A nil tombstone never gates. Pure (no I/O)
// so the freshness rule is unit-testable and stated in exactly one place.
func tombstoneGates(ts *RemoteTombstone, localUpdated time.Time) bool {
	return ts != nil && ts.At.After(localUpdated)
}

// tombstoneRefusal builds the loud, actionable error returned when an EXPLICIT
// `claim <id>` / `lock <id>` targets a tombstoned (completed-elsewhere) task
// (OQ-A1). It names the completing status/host/time and the two escape hatches
// (`git pull` to sync, or reopen to clear). Pure for table-testability.
func tombstoneRefusal(taskID string, ts *RemoteTombstone) error {
	return fmt.Errorf("task %s was completed elsewhere (status=%s by %s @%s) — REFUSING to re-claim work another clone already finished\n"+
		"  ⇒ 'git pull' to sync the terminal state, then re-list\n"+
		"  ⇒ or reopen it (`taskdb task set %s --status open`) to clear the tombstone and claim it again",
		taskID, ts.Status, tombstoneWho(ts), ts.At.Format(time.RFC3339), taskID)
}

// tombstoneWho renders the human attribution for the refusal: host (and session
// when distinct), falling back to "another clone" when neither is recorded.
func tombstoneWho(ts *RemoteTombstone) string {
	switch {
	case ts.Host != "" && ts.By != "" && ts.Host != ts.By:
		return ts.Host + " (" + ts.By + ")"
	case ts.Host != "":
		return ts.Host
	case ts.By != "":
		return ts.By
	default:
		return "another clone"
	}
}

// --- serial landing runner (additive; the consumer side of land_queue) ---
//
// These six methods are everything `taskdb landq run` needs from Postgres. They
// reuse the EXISTING task_locks / lock_heartbeats machinery for leader election
// and liveness (no new election schema), and touch ONLY land_queue rows for the
// queue itself — task_locks/wave_events/lock_heartbeats semantics are unchanged.

// acquireLandLeader elects the single landing writer by acquire()-ing the literal
// landLeaderSentinel into task_locks (INSERT..ON CONFLICT DO NOTHING — the winner
// is the leader). A thin wrapper over acquire() so the sentinel rides the exact
// same atomic-claim, age-reap and `lockserver unlock`/`reap` machinery as a real
// task lock. won=false returns the current holder (for a helpful "another runner
// holds it" message).
func (ls *lockServer) acquireLandLeader(session, host string) (won bool, holder *RemoteLock, err error) {
	return ls.acquire(landLeaderSentinel, session, host)
}

// heartbeatLandLeader keeps a LIVE leader from being aged out mid-land. It does
// two things, both best-effort:
//
//  1. Records a 'heartbeat' wave-event for the sentinel (recordEvent upserts
//     lock_heartbeats when session+task_id are both set), the observability trail.
//  2. Bumps the sentinel's task_locks.locked_at to now() — the column the generic
//     age-reap (reap()) actually compares — so a long land or a slow idle daemon
//     reads as fresh, not stale. This UPDATE is SESSION-SCOPED (WHERE locked_by =
//     session) so a just-reaped leader can NEVER resurrect a sentinel a NEW leader
//     has since won; it only refreshes a sentinel THIS leader still holds.
//
// Callers run it once per loop iteration BEFORE the (potentially slow) merge+gate
// AND on every idle tick, and treat its error as non-fatal. reap() additionally
// EXCLUDES the sentinel from the blanket age-DELETE (belt-and-suspenders), so the
// sentinel is cleared only by releaseLandLeader (clean SIGTERM) or an explicit
// `lockserver unlock __land_leader__ --force` (the documented crash path) — this
// heartbeat keeps a per-row staleness view honest for any other consumer.
func (ls *lockServer) heartbeatLandLeader(session string) error {
	if _, err := ls.db.Exec(
		`UPDATE task_locks SET locked_at = now() WHERE task_id = $1 AND locked_by = $2`,
		landLeaderSentinel, session,
	); err != nil {
		return err
	}
	return ls.recordEvent(WaveEvent{
		TaskID:  landLeaderSentinel,
		Session: session,
		Phase:   "land",
		Event:   "heartbeat",
		Host:    devHost(),
	})
}

// landLeaderTakeoverEligible reports whether an OBSERVED sentinel holder is
// provably dead and may therefore be taken over by a candidate leader.
//
// WHY this is sound: a live leader calls heartbeatLandLeader on every loop
// iteration, on every idle tick, AND (since the continuous-heartbeat fix) on a
// ticker for the whole duration of the merge+gate. So locked_at is refreshed on
// the order of seconds no matter what the leader is doing. A locked_at that has
// not moved for staleAfter — which callers pin well above the gate timeout — is
// hundreds of missed beats and cannot belong to a running leader.
//
// This is the gap that stranded the queue for 11h41m on 2026-08-18: the box
// rebooted at 21:14 while a leader held the sentinel, SIGKILL skipped the
// deferred releaseLandLeader, and because reap() deliberately EXCLUDES the
// sentinel from the blanket age-DELETE nothing ever reclaimed it. Every
// subsequent runner dutifully reported "another runner holds it" and exited 0,
// so the election timer spun every 2 minutes for half a day without landing
// anything and without anything looking wrong.
//
// Pure (no DB, no clock of its own) so the boundary conditions are table-tested.
// nil holder = unlocked, which is not a takeover (plain acquire() wins that).
func landLeaderTakeoverEligible(holder *RemoteLock, now time.Time, staleAfter time.Duration) bool {
	if holder == nil || staleAfter <= 0 {
		return false
	}
	return now.Sub(holder.LockedAt) > staleAfter
}

// takeoverLandLeader atomically steals a sentinel whose heartbeat has been silent
// longer than staleAfter, transferring it to session/host.
//
// The UPDATE is a compare-and-swap guarded on BOTH the holder we observed and the
// staleness predicate, evaluated server-side against the DB's own clock:
//
//   - `locked_by = prevHolder` means two candidates racing the same dead leader
//     cannot both win — the first flips locked_by, the second matches zero rows.
//     It also means a leader that revived and heartbeated between our read and
//     this write keeps its sentinel (locked_at moved, predicate fails).
//   - `locked_at < now() - staleAfter` is re-checked IN THE WRITE rather than
//     trusted from the caller's earlier read, so a slow candidate cannot act on a
//     stale observation.
//
// Taking the sentinel from a process that is somehow still alive would be a
// double-writer on main, so note the second line of defence: the run loop
// re-validates ownership (ls.holder(...).LockedBy == sess) before every land and
// exits rather than race. A zombie leader that wakes up after a takeover
// therefore stops itself instead of pushing.
//
// Returns won=false (nil error) when the row was not eligible — the ordinary
// "the incumbent is alive" outcome, not a failure.
func (ls *lockServer) takeoverLandLeader(session, host, prevHolder string, staleAfter time.Duration) (bool, error) {
	if staleAfter <= 0 || prevHolder == "" {
		return false, nil
	}
	res, err := ls.db.Exec(
		`UPDATE task_locks
		    SET locked_by = $1, host = $2, locked_at = now()
		  WHERE task_id = $3
		    AND locked_by = $4
		    AND locked_at < now() - make_interval(secs => $5)`,
		session, host, landLeaderSentinel, prevHolder, staleAfter.Seconds(),
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// releaseLandLeader drops the sentinel on the runner's clean exit, freeing the
// slot immediately for the next runner rather than waiting out the age-reap. A
// thin wrapper over release() WITHOUT force, so it only releases a sentinel this
// session still holds (a reaped-and-re-won leader is left untouched).
func (ls *lockServer) releaseLandLeader(session string) (bool, error) {
	return ls.release(landLeaderSentinel, session, false)
}

// claimNextLand atomically claims the next 'queued' row for runner, flipping it
// to 'landing'. One transaction: SELECT ... FOR UPDATE SKIP LOCKED picks the
// oldest highest-priority queued row (idx_land_queue_pick order) while skipping a
// row another connection is mid-claim on, then UPDATE marks it landing, stamps
// runner+started_at and bumps attempts. Returns (nil, nil) when the queue is
// drained — the same "nothing to do" contract claimRemote signals with
// sql.ErrNoRows, but here a plain nil entry (no sentinel error) so the runner
// loop reads it directly. The returned *LandEntry reflects the post-UPDATE row.
func (ls *lockServer) claimNextLand(runner string) (*LandEntry, error) {
	tx, err := ls.db.Begin()
	if err != nil {
		return nil, err
	}
	var id int64
	err = tx.QueryRow(
		`SELECT id FROM land_queue
		  WHERE status = 'queued'
		  ORDER BY priority DESC, id
		  LIMIT 1
		  FOR UPDATE SKIP LOCKED`,
	).Scan(&id)
	if err == sql.ErrNoRows {
		tx.Rollback()
		return nil, nil
	}
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	var e LandEntry
	var started, finished sql.NullString
	err = tx.QueryRow(
		`UPDATE land_queue
		    SET status = 'landing', runner = $1, started_at = now(), attempts = attempts + 1
		  WHERE id = $2
		  RETURNING id, branch, base_sha, task_ids, gate, wave, run_id, priority, status,
		            requested_by, host, runner, attempts, merge_commit, detail,
		            to_char(enqueued_at, 'YYYY-MM-DD"T"HH24:MI:SSOF'),
		            to_char(started_at,  'YYYY-MM-DD"T"HH24:MI:SSOF'),
		            to_char(finished_at, 'YYYY-MM-DD"T"HH24:MI:SSOF')`,
		runner, id,
	).Scan(&e.ID, &e.Branch, &e.BaseSHA, &e.TaskIDs, &e.Gate, &e.Wave, &e.RunID, &e.Priority,
		&e.Status, &e.RequestedBy, &e.Host, &e.Runner, &e.Attempts, &e.MergeCommit,
		&e.Detail, &e.EnqueuedAt, &started, &finished)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	if started.Valid {
		s := started.String
		e.StartedAt = &s
	}
	if finished.Valid {
		f := finished.String
		e.FinishedAt = &f
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &e, nil
}

// claimNextLandBatch atomically claims UP TO n oldest 'queued' rows for runner,
// flipping each to 'landing' — the BATCH analogue of claimNextLand, used ONLY by
// the merge-train pass (landq run --batch N>1, doc 27 §3 Deferred). It is DORMANT
// in the default serial runner: with --batch 1 the runner never calls this and
// takes the byte-identical claimNextLand path. One transaction, mirroring
// claimNextLand's shape: SELECT ... ORDER BY priority DESC, id LIMIT $n FOR UPDATE
// SKIP LOCKED picks the n highest-priority oldest queued rows (the idx_land_queue_
// pick order) while skipping rows another connection is mid-claim on, then a single
// UPDATE ... WHERE id = ANY($ids) RETURNING flips that id-set to 'landing', stamps
// runner+started_at and bumps attempts. The returned slice is in PICK ORDER
// (priority DESC, id) so the train assembles members in the same deterministic
// order the serial runner would have landed them one-by-one. Returns an EMPTY slice
// (not nil-error) when the queue is drained. n<=1 delegates to claimNextLand for
// exactness (so a degenerate batch is identical to the serial claim).
func (ls *lockServer) claimNextLandBatch(runner string, n int) ([]*LandEntry, error) {
	if n <= 1 {
		e, err := ls.claimNextLand(runner)
		if err != nil {
			return nil, err
		}
		if e == nil {
			return []*LandEntry{}, nil
		}
		return []*LandEntry{e}, nil
	}

	tx, err := ls.db.Begin()
	if err != nil {
		return nil, err
	}
	// Pick up to n queued rows in the runner's pick order, locking them so a peer
	// runner (nearly impossible under the single-writer sentinel, but SKIP LOCKED
	// keeps it safe) skips this set rather than blocking.
	rows, err := tx.Query(
		`SELECT id FROM land_queue
		  WHERE status = 'queued'
		  ORDER BY priority DESC, id
		  LIMIT $1
		  FOR UPDATE SKIP LOCKED`,
		n,
	)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			tx.Rollback()
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		tx.Rollback()
		return nil, err
	}
	rows.Close()
	if len(ids) == 0 {
		tx.Rollback()
		return []*LandEntry{}, nil // queue drained
	}

	// Flip the whole picked id-set to 'landing' in ONE UPDATE, returning the
	// post-update rows. Postgres forbids ORDER BY in UPDATE ... RETURNING, so the
	// RETURNING order is UNSPECIFIED — we collect the rows into a by-id map and then
	// re-emit them in `ids` order below. `ids` was filled by the SELECT above in the
	// pick order (priority DESC, id), so the returned slice is deterministically in
	// pick order. pq.Array marshals the []int64 to a Postgres bigint[].
	upd, err := tx.Query(
		`UPDATE land_queue
		    SET status = 'landing', runner = $1, started_at = now(), attempts = attempts + 1
		  WHERE id = ANY($2)
		  RETURNING id, branch, base_sha, task_ids, gate, wave, run_id, priority, status,
		            requested_by, host, runner, attempts, merge_commit, detail,
		            to_char(enqueued_at, 'YYYY-MM-DD"T"HH24:MI:SSOF'),
		            to_char(started_at,  'YYYY-MM-DD"T"HH24:MI:SSOF'),
		            to_char(finished_at, 'YYYY-MM-DD"T"HH24:MI:SSOF')`,
		runner, pq.Array(ids),
	)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	byID := make(map[int64]*LandEntry, len(ids))
	for upd.Next() {
		var e LandEntry
		var started, finished sql.NullString
		if err := upd.Scan(&e.ID, &e.Branch, &e.BaseSHA, &e.TaskIDs, &e.Gate, &e.Wave, &e.RunID,
			&e.Priority, &e.Status, &e.RequestedBy, &e.Host, &e.Runner, &e.Attempts,
			&e.MergeCommit, &e.Detail, &e.EnqueuedAt, &started, &finished); err != nil {
			upd.Close()
			tx.Rollback()
			return nil, err
		}
		if started.Valid {
			s := started.String
			e.StartedAt = &s
		}
		if finished.Valid {
			f := finished.String
			e.FinishedAt = &f
		}
		ec := e
		byID[ec.ID] = &ec
	}
	if err := upd.Err(); err != nil {
		upd.Close()
		tx.Rollback()
		return nil, err
	}
	upd.Close()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// Emit in the SELECT's pick order (priority DESC, id) by walking `ids`.
	out := make([]*LandEntry, 0, len(ids))
	for _, id := range ids {
		if e := byID[id]; e != nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// landStatusOpts is the functional-options accumulator for setLandStatus — it
// lets a single UPDATE optionally also set detail, merge_commit, finished_at,
// runner and/or started_at without a combinatorial set of method signatures.
type landStatusOpts struct {
	detail      *string
	mergeCommit *string
	finished    bool
	runner      *string
	startedNull bool
}

// landStatusOpt mutates a landStatusOpts. See withDetail/withMergeCommit/finished.
type landStatusOpt func(*landStatusOpts)

// withDetail records a human-readable detail string (conflicted files, gate tail)
// alongside the new status.
func withDetail(detail string) landStatusOpt {
	return func(o *landStatusOpts) { o.detail = &detail }
}

// withMergeCommit records the landed merge-commit SHA alongside the new status.
func withMergeCommit(sha string) landStatusOpt {
	return func(o *landStatusOpts) { o.mergeCommit = &sha }
}

// landFinished stamps finished_at=now() alongside the new status (a terminal
// transition: landed/conflict/failed/cancelled).
func landFinished() landStatusOpt {
	return func(o *landStatusOpts) { o.finished = true }
}

// landRunner sets the runner column (clear it with "" when requeuing a row from
// 'landing' back to 'queued' so the next claim re-stamps it cleanly).
func landRunner(runner string) landStatusOpt {
	return func(o *landStatusOpts) { o.runner = &runner }
}

// landStartedNull NULLs started_at alongside the new status — paired with
// landRunner("") to reset a 'landing' row to a clean 'queued' (the same reset
// reapStaleLanding applies), so a transient-gate requeue is repicked, not aged.
func landStartedNull() landStatusOpt {
	return func(o *landStatusOpts) { o.startedNull = true }
}

// setLandStatus transitions one land_queue row to status, optionally also setting
// detail/merge_commit/finished_at/runner/started_at via the functional options.
// The SET list is built dynamically from the supplied options so the common "just
// flip status" call stays a one-column UPDATE. Mirrors reap()/release()'s
// direct-UPDATE shape.
func (ls *lockServer) setLandStatus(id int64, status string, opts ...landStatusOpt) error {
	var o landStatusOpts
	for _, opt := range opts {
		opt(&o)
	}
	set := []string{"status = $1"}
	args := []any{status}
	if o.detail != nil {
		args = append(args, *o.detail)
		set = append(set, fmt.Sprintf("detail = $%d", len(args)))
	}
	if o.mergeCommit != nil {
		args = append(args, *o.mergeCommit)
		set = append(set, fmt.Sprintf("merge_commit = $%d", len(args)))
	}
	if o.runner != nil {
		args = append(args, *o.runner)
		set = append(set, fmt.Sprintf("runner = $%d", len(args)))
	}
	if o.startedNull {
		set = append(set, "started_at = NULL")
	}
	if o.finished {
		set = append(set, "finished_at = now()")
	}
	args = append(args, id)
	q := fmt.Sprintf(`UPDATE land_queue SET %s WHERE id = $%d`,
		strings.Join(set, ", "), len(args))
	_, err := ls.db.Exec(q, args...)
	return err
}

// reapStaleLanding returns orphaned 'landing' rows (a dead runner that never
// finished) back to 'queued' so the next runner re-attempts them, mirroring
// reap()'s age-by-interval shape on task_locks. A row is stale when its
// started_at is older than age; it is reset to queued with runner cleared and
// started_at NULLed (a fresh started_at is stamped on the next claim). Returns the
// requeued ids. The runner calls this once per loop (BEFORE claiming) so a crashed
// peer's in-flight row is recovered. Liveness for the LIVE leader is the
// sentinel's heartbeat (heartbeatLandLeader), not started_at, so a live but slow
// land is NOT reaped by this — only a row whose started_at simply aged out.
func (ls *lockServer) reapStaleLanding(age time.Duration) ([]int64, error) {
	secs := int64(age.Seconds())
	if secs < 0 {
		secs = 0
	}
	rows, err := ls.db.Query(
		`UPDATE land_queue
		    SET status = 'queued', runner = '', started_at = NULL
		  WHERE status = 'landing' AND started_at < now() - make_interval(secs => $1)
		  RETURNING id`,
		secs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// listStaleLanding is the READ-ONLY companion to reapStaleLanding: it returns the
// ids of the orphaned 'landing' rows that reapStaleLanding WOULD requeue at this
// age, WITHOUT mutating anything. It uses the EXACT same server-side staleness
// predicate (started_at < now() - make_interval(secs => $1)) but a SELECT instead
// of an UPDATE, so the dry-run preview can never disagree with the real reap. This
// is the right shape for `landq reap --dry-run` — it never round-trips a to_char
// timestamp through a Go layout (Postgres `to_char(..., 'OF')` renders a whole-hour
// UTC offset as "+00", which no single Go reference layout parses), exactly as the
// `lockserver reap --dry-run` precedent compares native time.Time rather than
// string-parsing. Returns the would-reap ids.
func (ls *lockServer) listStaleLanding(age time.Duration) ([]int64, error) {
	secs := int64(age.Seconds())
	if secs < 0 {
		secs = 0
	}
	rows, err := ls.db.Query(
		`SELECT id FROM land_queue
		  WHERE status = 'landing' AND started_at < now() - make_interval(secs => $1)
		  ORDER BY id`,
		secs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// cancelLand is the operator stop: transition a 'queued'|'landing' row to
// 'cancelled' (stamping finished_at). The status guard in the WHERE clause IS the
// legal-transition contract — only an active row can be cancelled, so a row that
// already 'landed'/'failed'/'cancelled' (or a non-existent id) matches zero rows
// and reports false so the CLI can surface a real "not found / not in a
// cancellable state" error rather than silently no-op. setLandStatus is an
// unconditional UPDATE-by-id and so CANNOT carry this guard; cancelLand must.
// Returns RowsAffected()==1 (mirrors deleteLandByBranch's res.RowsAffected()).
func (ls *lockServer) cancelLand(id int64) (bool, error) {
	res, err := ls.db.Exec(
		`UPDATE land_queue
		    SET status = 'cancelled', finished_at = now()
		  WHERE id = $1 AND status IN ('queued','landing')`,
		id,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// requeueLand is the operator re-drive: transition a terminal-ish
// 'failed'|'conflict'|'cancelled' row back to 'queued', clearing runner,
// started_at, finished_at and detail so the runner repicks it cleanly (the same
// reset reapStaleLanding applies, but from the terminal states an operator drives
// by hand rather than the age-reap). The status guard is the legal-transition
// contract: a 'queued'/'landing'/'landed' row (or a non-existent id) matches zero
// rows and reports false so the CLI surfaces a real "not in a requeueable state"
// error. Returns RowsAffected()==1.
func (ls *lockServer) requeueLand(id int64) (bool, error) {
	res, err := ls.db.Exec(
		`UPDATE land_queue
		    SET status = 'queued', runner = '', started_at = NULL, finished_at = NULL, detail = ''
		  WHERE id = $1 AND status IN ('failed','conflict','cancelled')`,
		id,
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

// recordEvent appends one telemetry row to wave_events AND upserts the holder's
// lock_heartbeats freshness row (when the event names a session+task), in a
// single transaction so the heartbeat is never out of step with the stream.
// Best-effort by contract: callers run it fail-open.
func (ls *lockServer) recordEvent(e WaveEvent) error {
	tx, err := ls.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(
		`INSERT INTO wave_events
		   (wave, run_id, unit_key, task_id, phase, agent_label, event, status, session, host, tokens, note)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		e.Wave, e.RunID, e.UnitKey, e.TaskID, e.Phase, e.AgentLabel,
		e.Event, e.Status, e.Session, e.Host, e.Tokens, e.Note,
	); err != nil {
		tx.Rollback()
		return err
	}
	// Heartbeat only when we can attribute the event to a holder (session+task).
	if e.Session != "" && e.TaskID != "" {
		if _, err := tx.Exec(
			`INSERT INTO lock_heartbeats (session, task_id, wave, run_id, phase, host, last_activity)
			 VALUES ($1,$2,$3,$4,$5,$6, now())
			 ON CONFLICT (session, task_id) DO UPDATE
			   SET wave=EXCLUDED.wave, run_id=EXCLUDED.run_id, phase=EXCLUDED.phase,
			       host=EXCLUDED.host, last_activity=now()`,
			e.Session, e.TaskID, e.Wave, e.RunID, e.Phase, e.Host,
		); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// recordEvents appends a BATCH of telemetry rows in ONE transaction — the bulk
// twin of recordEvent for `taskdb wave report --batch`, so an agent can flush a
// whole turn's transitions in a single round trip (and all-or-nothing: a mid-batch
// error rolls the whole flush back). Each row also upserts its holder's
// lock_heartbeats freshness row when it names a session+task, exactly like the
// single-row path. Best-effort by contract: callers run it fail-open. An empty
// batch is a no-op (no transaction).
func (ls *lockServer) recordEvents(events []WaveEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := ls.db.Begin()
	if err != nil {
		return err
	}
	for _, e := range events {
		if _, err := tx.Exec(
			`INSERT INTO wave_events
			   (wave, run_id, unit_key, task_id, phase, agent_label, event, status, session, host, tokens, note)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			e.Wave, e.RunID, e.UnitKey, e.TaskID, e.Phase, e.AgentLabel,
			e.Event, e.Status, e.Session, e.Host, e.Tokens, e.Note,
		); err != nil {
			tx.Rollback()
			return err
		}
		if e.Session != "" && e.TaskID != "" {
			if _, err := tx.Exec(
				`INSERT INTO lock_heartbeats (session, task_id, wave, run_id, phase, host, last_activity)
				 VALUES ($1,$2,$3,$4,$5,$6, now())
				 ON CONFLICT (session, task_id) DO UPDATE
				   SET wave=EXCLUDED.wave, run_id=EXCLUDED.run_id, phase=EXCLUDED.phase,
				       host=EXCLUDED.host, last_activity=now()`,
				e.Session, e.TaskID, e.Wave, e.RunID, e.Phase, e.Host,
			); err != nil {
				tx.Rollback()
				return err
			}
		}
	}
	return tx.Commit()
}

// heartbeatAgesByTask returns, for every task with a recorded heartbeat, the age
// of its FRESHEST heartbeat (server clock) — the basis for the activity-aware
// staleness signal. A task with no heartbeat is simply absent from the map, so
// callers fall back to lock-age (backwards-compatible with pre-telemetry rows).
func (ls *lockServer) heartbeatAgesByTask() (map[string]time.Duration, error) {
	rows, err := ls.db.Query(
		`SELECT task_id, EXTRACT(EPOCH FROM (now() - max(last_activity)))::bigint
		   FROM lock_heartbeats WHERE task_id <> '' GROUP BY task_id`,
	)
	if err != nil {
		// Table absent (un-migrated old DB) or any query error → no heartbeat
		// data; callers fall back to lock-age. Never fatal.
		return map[string]time.Duration{}, nil
	}
	defer rows.Close()
	out := map[string]time.Duration{}
	for rows.Next() {
		var id string
		var secs int64
		if err := rows.Scan(&id, &secs); err != nil {
			return out, nil
		}
		if secs < 0 {
			secs = 0
		}
		out[id] = time.Duration(secs) * time.Second
	}
	return out, rows.Err()
}

// listEvents returns the recent telemetry tail (newest first), optionally
// narrowed to one wave/run. Bounded by limit. Read-only.
func (ls *lockServer) listEvents(wave, runID string, limit int) ([]WaveEvent, error) {
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	q := `SELECT wave, run_id, unit_key, task_id, phase, agent_label, event, status,
	              session, host, tokens, note, to_char(ts, 'YYYY-MM-DD"T"HH24:MI:SSOF')
	         FROM wave_events WHERE ($1='' OR wave=$1) AND ($2='' OR run_id=$2)
	        ORDER BY ts DESC, id DESC LIMIT $3`
	rows, err := ls.db.Query(q, wave, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WaveEvent{}
	for rows.Next() {
		var e WaveEvent
		if err := rows.Scan(&e.Wave, &e.RunID, &e.UnitKey, &e.TaskID, &e.Phase,
			&e.AgentLabel, &e.Event, &e.Status, &e.Session, &e.Host, &e.Tokens,
			&e.Note, &e.Ts); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// landStats is the doc-27 Lever-0 land-phase tally landRetryStats derives from the
// phase='land' wave_events stream. Dispatched counts every land attempt (a
// 'landing' transition: claimed/landing OR push-retry/landing); LandedBranches is
// the count of DISTINCT land_queue row-keys that reached 'landed'; LandRetry is the
// extra-attempt residue Dispatched-LandedBranches (the CONFLICT-LOSS land_retry
// term, clamped >= 0). Conflicts/Failures are diagnostic breakdowns of failed
// transitions.
type landStats struct {
	Dispatched     int
	LandedBranches int
	LandRetry      int
	Conflicts      int
	Failures       int
}

// landRetryStats reads the phase='land' wave_events stream (optionally narrowed to
// one wave and/or a trailing `since` window) and computes the doc-27 §6 land_retry
// term. Read-only — it never writes any table, so an old binary and a new binary
// see the same pre-existing rows. The exact derivation is documented in
// cmd_bench.go: Dispatched = #(status='landing') events; landed branch-keys are the
// '#<id>' tokens parsed from each landed event's note; LandRetry = Dispatched minus
// the distinct landed branch count (clamped >= 0, since a --since window can clip a
// branch's 'landing' outside it while its 'landed' falls inside). An un-migrated DB
// or query error is returned to the fail-open caller, which degrades.
func (ls *lockServer) landRetryStats(wave string, since time.Duration) (landStats, error) {
	var sinceSecs float64
	if since > 0 {
		sinceSecs = since.Seconds()
	}
	q := `SELECT event, status, note
	         FROM wave_events
	        WHERE phase='land'
	          AND ($1='' OR wave=$1)
	          AND ($2<=0 OR ts >= now() - make_interval(secs => $2))
	        ORDER BY ts ASC, id ASC`
	rows, err := ls.db.Query(q, wave, sinceSecs)
	if err != nil {
		return landStats{}, err
	}
	defer rows.Close()

	var st landStats
	landed := map[string]struct{}{}
	for rows.Next() {
		var event, status, note string
		if err := rows.Scan(&event, &status, &note); err != nil {
			return landStats{}, err
		}
		switch status {
		case "landing":
			// claimed/landing (a fresh claim attempt) and push-retry/landing (an
			// in-claim re-push) are both 'a land attempt was made'.
			st.Dispatched++
		case "landed":
			landed[parseLandBranchKey(note)] = struct{}{}
		case "conflict":
			st.Conflicts++
		case "failed":
			st.Failures++
		}
	}
	if err := rows.Err(); err != nil {
		return landStats{}, err
	}
	st.LandedBranches = len(landed)
	st.LandRetry = st.Dispatched - st.LandedBranches
	if st.LandRetry < 0 {
		st.LandRetry = 0
	}
	return st, nil
}

// parseLandBranchKey extracts the stable per-branch key from emitLandEvent's note,
// formatted "landq #<id> <branch>". The '#<id>' is the land_queue BIGSERIAL row id,
// which a requeue REUSES — so all of a branch's retries share one key. Defensive:
// if the note has no '#<id>' token (a future note-format change), the whole note is
// used as the key so distinct notes still don't collide. Parsing lives in this one
// helper so a note-format change touches a single place.
func parseLandBranchKey(note string) string {
	i := strings.IndexByte(note, '#')
	if i < 0 {
		return note
	}
	rest := note[i+1:]
	// The id token runs to the first space (the branch name follows it).
	if j := strings.IndexByte(rest, ' '); j >= 0 {
		return rest[:j]
	}
	return rest
}

// unitRollup summarizes progress per (wave, run, unit): the latest phase/status
// each unit reached and its event count. DISTINCT ON picks the freshest row per
// group; the count is a correlated aggregate. Optionally narrowed to one
// wave/run. Read-only.
func (ls *lockServer) unitRollup(wave, runID string) ([]WaveUnitRollup, error) {
	q := `SELECT DISTINCT ON (wave, run_id, unit_key)
	              wave, run_id, unit_key, task_id, phase, status, event,
	              to_char(ts, 'YYYY-MM-DD"T"HH24:MI:SSOF'),
	              (SELECT count(*) FROM wave_events e2
	                WHERE e2.wave=e1.wave AND e2.run_id=e1.run_id AND e2.unit_key=e1.unit_key)
	         FROM wave_events e1
	        WHERE unit_key <> '' AND ($1='' OR wave=$1) AND ($2='' OR run_id=$2)
	        ORDER BY wave, run_id, unit_key, ts DESC, id DESC`
	rows, err := ls.db.Query(q, wave, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WaveUnitRollup{}
	for rows.Next() {
		var r WaveUnitRollup
		if err := rows.Scan(&r.Wave, &r.RunID, &r.UnitKey, &r.TaskID, &r.LastPhase,
			&r.LastStatus, &r.LastEvent, &r.UpdatedAt, &r.EventCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// listRuns aggregates the FULL wave_events table into one summary row per
// (wave, run_id) — the historical-run index the dashboard's "past runs" view is
// built on. Unlike listEvents/unitRollup (which read the recent-event tail, so a
// run that scrolled past the cap disappears), this GROUPs over the whole stream,
// so every run that ever emitted telemetry is listed, newest activity first.
// Rows with neither a wave nor a run_id are excluded — those are the landq
// leader's bare heartbeats (task_id='__land_leader__'), not workflow runs.
// Optionally narrowed to one wave label. Read-only — never writes any table.
func (ls *lockServer) listRuns(wave string, limit int) ([]WaveRun, error) {
	if limit <= 0 || limit > 5000 {
		limit = 500
	}
	q := `SELECT wave, run_id,
	              to_char(min(ts), 'YYYY-MM-DD"T"HH24:MI:SSOF'),
	              to_char(max(ts), 'YYYY-MM-DD"T"HH24:MI:SSOF'),
	              count(*),
	              count(DISTINCT unit_key) FILTER (WHERE unit_key <> ''),
	              bool_or(event='end' AND phase IN ('land','finalize')),
	              bool_or(phase='land' AND status='landed')
	         FROM wave_events
	        WHERE (wave <> '' OR run_id <> '') AND ($1='' OR wave=$1)
	        GROUP BY wave, run_id
	        ORDER BY max(ts) DESC, wave
	        LIMIT $2`
	rows, err := ls.db.Query(q, wave, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WaveRun{}
	for rows.Next() {
		var r WaveRun
		if err := rows.Scan(&r.Wave, &r.RunID, &r.StartedAt, &r.LastTs,
			&r.EventCount, &r.UnitCount, &r.Terminal, &r.Landed); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// unitActivity is the per-(wave,run,unit) freshness pair `wave status` joins onto
// the rollup: eventAge is how long since the unit's freshest wave_events row, and
// (when hasHeartbeat) hbAge is how long since its task's freshest lock_heartbeats
// row. Both are server-computed (EXTRACT(EPOCH ...)) so the client never parses a
// timestamp string — the same activity-aware-staleness inputs printRemoteLocks
// feeds lockStale(), but keyed per unit instead of per lock.
type unitActivity struct {
	EventAge     time.Duration
	HBAge        time.Duration
	HasHeartbeat bool
}

// unitActivityAges returns, per unit key (within the optional wave/run filter),
// the unit's event-freshness age and — when its task has a heartbeat — its
// heartbeat age. Keyed by unit_key (the rollup's unit identity within one
// wave/run). Read-only; an un-migrated DB or query error yields an empty map so
// the caller degrades to "no activity data" rather than failing.
func (ls *lockServer) unitActivityAges(wave, runID string) (map[string]unitActivity, error) {
	q := `SELECT e.unit_key,
	             EXTRACT(EPOCH FROM (now() - max(e.ts)))::bigint AS event_age,
	             EXTRACT(EPOCH FROM (now() - max(h.last_activity)))::bigint AS hb_age
	        FROM wave_events e
	        LEFT JOIN lock_heartbeats h ON h.task_id = e.task_id AND e.task_id <> ''
	       WHERE e.unit_key <> '' AND ($1='' OR e.wave=$1) AND ($2='' OR e.run_id=$2)
	       GROUP BY e.unit_key`
	rows, err := ls.db.Query(q, wave, runID)
	if err != nil {
		return map[string]unitActivity{}, nil
	}
	defer rows.Close()
	out := map[string]unitActivity{}
	for rows.Next() {
		var unit string
		var eventAge int64
		var hbAge sql.NullInt64
		if err := rows.Scan(&unit, &eventAge, &hbAge); err != nil {
			return out, nil
		}
		if eventAge < 0 {
			eventAge = 0
		}
		ua := unitActivity{EventAge: time.Duration(eventAge) * time.Second}
		if hbAge.Valid {
			a := hbAge.Int64
			if a < 0 {
				a = 0
			}
			ua.HBAge = time.Duration(a) * time.Second
			ua.HasHeartbeat = true
		}
		out[unit] = ua
	}
	return out, rows.Err()
}

// reapLockStaleSQL is the activity-aware staleness predicate shared by the
// mutating reap() and the reapLocksRemote dry-run preview (cores.go), so the
// preview can NEVER disagree with the DELETE. It mirrors lockStale() (the
// `status`/dashboard display rule, cmd_lifecycle.go): a held lock is stale only
// when its task_locks.locked_at is older than the age cutoff AND its FRESHEST
// lock_heartbeats.last_activity is also older — with an age-only fallback when
// the task has NO heartbeat rows (a crashed, non-heartbeating agent's lock must
// still age out, so age stays the OUTER bound). $1 is the age in seconds; the
// landing-leader sentinel ($2 = __land_leader__) is excluded by the caller. The
// LEFT JOIN + GROUP BY collapses a task's heartbeats to one max(last_activity);
// MAX(...) IS NULL is the no-heartbeat case (fall back to age-only via the OR).
const reapLockStaleSQL = `
	SELECT l.task_id
	  FROM task_locks l
	  LEFT JOIN lock_heartbeats h ON h.task_id = l.task_id
	 WHERE l.task_id <> $2
	 GROUP BY l.task_id, l.locked_at
	HAVING l.locked_at < now() - make_interval(secs => $1)
	   AND (MAX(h.last_activity) IS NULL
	        OR MAX(h.last_activity) < now() - make_interval(secs => $1))`

// reap force-releases locks older than age (server clock), returning the freed
// task IDs. ACTIVITY-AWARE (F2): a lock is reaped only when BOTH its locked_at
// AND its freshest lock_heartbeats.last_activity are older than age — matching
// the lockStale() display rule (cmd_lifecycle.go), so a live, heartbeating agent
// past the 30m age cutoff is NOT reaped (it shows NOT stale in `status`, and was
// previously reaped out from under itself). A lock with NO heartbeat rows falls
// back to age-only (the crashed non-heartbeating agent's lock still ages out —
// age is the outer bound). The DELETE selects the stale id-set via the shared
// reapLockStaleSQL predicate and removes exactly those rows.
//
// The landing-leader sentinel (__land_leader__) is EXCLUDED from this age-reap:
// a routine `lockserver reap` / audit-stuck pass must never evict a live,
// mid-backlog leader as a side effect and open a double-writer window on main.
// The sentinel is cleared only by releaseLandLeader (clean SIGTERM) or an
// explicit `lockserver unlock __land_leader__ --force` (the documented
// crash-recovery path) — see heartbeatLandLeader and LANDQ-RUNBOOK.md.
func (ls *lockServer) reap(age time.Duration) ([]string, error) {
	secs := int64(age.Seconds())
	if secs < 0 {
		secs = 0
	}
	rows, err := ls.db.Query(
		`DELETE FROM task_locks
		  WHERE task_id IN (`+reapLockStaleSQL+`)
		 RETURNING task_id`,
		secs, landLeaderSentinel,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// reapLockStaleTargetSQL is the TARGET-SCOPED sibling of reapLockStaleSQL: the
// SAME activity-aware, sentinel-excluding staleness predicate, plus an
// `l.task_id = $3` filter so only ONE task's lock is ever considered. It backs
// reapTarget (the claim-time cheap path) exactly as reapLockStaleSQL backs the
// full-table reap()/listStaleLocks(). Keeping the two predicates textually
// parallel (same $1 age / $2 sentinel / LEFT JOIN + GROUP BY + HAVING shape)
// means a live heartbeating holder and the __land_leader__ sentinel are excluded
// on BOTH paths — the target scope narrows the row set, it never relaxes the
// activity/sentinel guards. Because $2 still excludes the sentinel, a
// target-scoped reap of __land_leader__ (target == sentinel) selects nothing.
const reapLockStaleTargetSQL = `
	SELECT l.task_id
	  FROM task_locks l
	  LEFT JOIN lock_heartbeats h ON h.task_id = l.task_id
	 WHERE l.task_id <> $2
	   AND l.task_id = $3
	 GROUP BY l.task_id, l.locked_at
	HAVING l.locked_at < now() - make_interval(secs => $1)
	   AND (MAX(h.last_activity) IS NULL
	        OR MAX(h.last_activity) < now() - make_interval(secs => $1))`

// reapTarget is the TARGET-SCOPED companion to reap(): it frees ONLY taskID's
// lock, and only when that lock is stale under the SAME activity-aware +
// sentinel-excluding predicate the full-table reap() uses (via
// reapLockStaleTargetSQL). It is the cheaper claim-time path — one candidate
// row considered instead of a full-table DELETE-scan of every foreign lock —
// so a large parallel wave of specific-task claims no longer each sweep the
// whole table. reap() stays the standing GLOBAL broom (the landq idle loop and
// the auto-claim path). Returns the freed ids: 0 elements when taskID's lock is
// live/absent, or exactly [taskID] when it was stale and removed. A
// target-scoped reap of the __land_leader__ sentinel is a no-op (the $2
// exclusion), preserving the ratified never-evict-the-leader invariant.
func (ls *lockServer) reapTarget(taskID string, age time.Duration) ([]string, error) {
	secs := int64(age.Seconds())
	if secs < 0 {
		secs = 0
	}
	rows, err := ls.db.Query(
		`DELETE FROM task_locks
		  WHERE task_id IN (`+reapLockStaleTargetSQL+`)
		 RETURNING task_id`,
		secs, landLeaderSentinel, taskID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// listStaleLocks is the READ-ONLY companion to reap(): it returns the task ids
// reap() WOULD free at this age, using the EXACT same activity-aware
// reapLockStaleSQL predicate (and the same sentinel exclusion), so the
// `lockserver reap --dry-run` preview can never disagree with the mutation. It
// is the server-side analogue of listStaleLanding for land_queue rows.
func (ls *lockServer) listStaleLocks(age time.Duration) ([]string, error) {
	secs := int64(age.Seconds())
	if secs < 0 {
		secs = 0
	}
	rows, err := ls.db.Query(reapLockStaleSQL+` ORDER BY l.task_id`, secs, landLeaderSentinel)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// reapSession force-releases EVERY remote lock held by an exact session id,
// regardless of age. This is the wave-boundary cleanup: a coordinator that
// provisioned its fleet with a known TASKDB_SESSION (the richer
// <host>-<unit|wt>-<wave>-<unit-key> identity) can release exactly its own
// holds when the wave finishes (or a unit's agent exits), without waiting out
// the age-based staleLockThreshold and without touching any other coordinator's
// or machine's holds. Match is an exact session-string equality, so the
// per-unit identity must be precise; a prefix match would risk reaping a
// sibling wave's holds. Returns the task ids released.
func (ls *lockServer) reapSession(session string) ([]string, error) {
	rows, err := ls.db.Query(
		`DELETE FROM task_locks WHERE locked_by = $1 RETURNING task_id`,
		session,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// --- local SQLite mirror helpers ---
//
// The remote registry is authoritative for acquisition; these keep the local
// lock columns in step so list/tui/readyWhere/task_report read consistent
// state without each needing to query Postgres. Mirror writes never touch
// updated_at (which is frozen to JSON) — only the json:"-" lock columns — so
// mirroring another machine's hold produces no tasks/*.json churn.

// mirrorLockLocal force-sets the local lock columns to a known holder (remote
// is authoritative, so no WHERE guard). session is the holding session.
func mirrorLockLocal(localDB *sql.DB, taskID, session string, at time.Time) {
	localDB.Exec(
		`UPDATE tasks SET locked_by = ?, locked_at = ? WHERE id = ?`,
		session, timeToMs(at), taskID,
	)
}

// clearLockLocal clears the local mirror for taskID.
func clearLockLocal(localDB *sql.DB, taskID string) {
	localDB.Exec(`UPDATE tasks SET locked_by = NULL, locked_at = NULL WHERE id = ?`, taskID)
}

// localLock is a held local mirror row (id + holding session) used by
// syncLocksFromRemote to decide what to re-register vs clear on reconnect.
type localLock struct {
	id      string
	session string
}

// shouldReRegisterOutageLock is the PURE policy for the F3 reconcile: given a
// local-only held lock (one the remote registry does not list) and THIS clone's
// claiming session, decide whether it is an outage lock WE took and may attempt
// to re-register remotely. True only when the lock is held by OUR OWN session;
// a stale mirror of a PEER's hold (locked_by != session), or an unknown session
// (session == ""), is NOT ours to re-INSERT — re-registering under a peer's name
// would resurrect a lock that machine legitimately released/was reaped, so it is
// cleared as before. Split out (no I/O) so the session-scoping rule is stated in
// one place and unit-testable without a live Postgres, mirroring lockPolicyDecision.
func shouldReRegisterOutageLock(ll localLock, session string) bool {
	return session != "" && ll.session == session
}

// syncLocksFromRemote reconciles the local lock columns against the remote
// holder set: set the mirror for every remote hold of a task we know about, and
// for any LOCAL-only held lock the remote does not list, RE-REGISTER (when WE
// hold it) it remotely before clearing (F3). Best-effort and mirror-only (no
// updated_at churn). Run before candidate selection in a remote claim so
// readyWhere reflects holds taken on other machines; session is THIS clone's
// claiming session (cores.go passes it through claimRemote).
//
// F3 — RE-REGISTER OUTAGE LOCKS ON RECOVERY. A lock taken during a tunnel outage
// (the fail-open local-only path) was never INSERTed into the remote registry,
// so a naive "clear every local lock the remote doesn't list" would silently
// drop a genuinely-held lock on the first successful sync after the outage. For a
// local-only lock held by OUR OWN session (locked_by == session) we instead first
// attempt a remote INSERT..ON CONFLICT (task_id) DO NOTHING (acquire) to
// re-register it, and only clearLockLocal/yield when the INSERT LOST the race —
// i.e. another machine legitimately holds it now (we banner loudly and mirror the
// real holder). A local-only lock that is a stale MIRROR of ANOTHER session's
// hold (locked_by != session) is NOT ours to re-register — re-INSERTing under a
// peer's name would resurrect a lock that machine legitimately released/was
// reaped — so it is CLEARED exactly as before. Stays FAIL-OPEN: an error talking
// to the remote during re-register leaves the local lock INTACT (we never clear
// on a remote error), so a flapping tunnel never strands held work.
func syncLocksFromRemote(localDB *sql.DB, ls *lockServer, session string) error {
	locks, err := ls.list()
	if err != nil {
		return err
	}
	held := make(map[string]RemoteLock, len(locks))
	for _, l := range locks {
		held[l.TaskID] = l
		mirrorLockLocal(localDB, l.TaskID, l.LockedBy, l.LockedAt)
	}
	rows, err := localDB.Query(`SELECT id, locked_by FROM tasks WHERE locked_by IS NOT NULL`)
	if err != nil {
		return err
	}
	var localOnly []localLock
	for rows.Next() {
		var ll localLock
		if err := rows.Scan(&ll.id, &ll.session); err != nil {
			rows.Close()
			return err
		}
		if _, ok := held[ll.id]; !ok {
			localOnly = append(localOnly, ll)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	host := devHost()
	for _, ll := range localOnly {
		// Only OUR session's local-only lock is an outage lock we may re-register.
		// A stale mirror of a peer's hold (locked_by != session) is cleared as
		// before — never re-INSERTed under the peer's name.
		if !shouldReRegisterOutageLock(ll, session) {
			clearLockLocal(localDB, ll.id)
			continue
		}
		// Re-register the outage-era local lock. acquire is INSERT..ON CONFLICT
		// DO NOTHING RETURNING, so:
		//   ok           → we (re)registered it remotely; KEEP the local lock.
		//   !ok, holder  → another machine legitimately holds it; clear+mirror+banner.
		//   err          → remote trouble; FAIL-OPEN, leave the local lock intact.
		ok, holder, aerr := ls.acquire(ll.id, ll.session, host)
		if aerr != nil {
			continue // fail-open: never clear a held lock on a remote error
		}
		if ok {
			continue // re-registered cross-machine; local lock now backed remotely
		}
		// Lost the race: someone else holds it. Yield the local lock to the real holder.
		if holder != nil {
			warnDegraded("task %s was locked locally during an outage but %s now holds it cross-machine — yielding the local lock",
				ll.id, holder.LockedBy)
			mirrorLockLocal(localDB, ll.id, holder.LockedBy, holder.LockedAt)
		} else {
			clearLockLocal(localDB, ll.id)
		}
	}
	return nil
}

// --- remote-backed claim ---

// selectReadyCandidates returns the dispatchable tasks (readyWhere) in priority
// order, optionally narrowed to one id. Unlike claimLocal it does not mutate —
// the remote acquire decides the winner.
func selectReadyCandidates(db *sql.DB, optionalID string) ([]*Task, error) {
	q := `SELECT id, title, body, status, priority, parent_id, branch, locked_by, locked_at, created_at, updated_at
		FROM tasks t WHERE ` + readyWhere
	var args []any
	if optionalID != "" {
		q += ` AND t.id = ?`
		args = append(args, optionalID)
	}
	q += ` ORDER BY t.priority DESC, t.id`
	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Task
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// logClaimReap makes a claim-time auto-reap OBSERVABLE: it emits one stderr line
// per freed lock (mirroring the landq idle loop's freed-id logging in
// cmd_landq.go, "auto-reaped stale orphaned lock <id> (age > <age>)") plus a
// one-line count summary, then returns the count. Silent when nothing was freed,
// so the overwhelmingly-common no-op claim adds zero noise; loud exactly when a
// vanished foreign lock is aged out, so the event is never swallowed the way the
// prior `_, _ = ls.reap(a)` did. Writes to STDERR (not stdout) so it never
// corrupts a claim's machine-readable stdout payload. Returned count lets a
// caller or test surface the reaped total without scraping stderr.
func logClaimReap(freed []string, age time.Duration) int {
	for _, id := range freed {
		fmt.Fprintf(os.Stderr, "taskdb: claim-time auto-reaped stale orphaned lock %s (age > %s)\n", id, age)
	}
	if n := len(freed); n > 0 {
		fmt.Fprintf(os.Stderr, "taskdb: claim-time auto-reap freed %d stale lock(s)\n", n)
		return n
	}
	return 0
}

// recordClaimReap emits ONE best-effort wave_events row marking a claim-time
// auto-reap, so dashboards/rollups (which never scrape stderr) see that a claim
// aged out a vanished foreign lock — the trace logClaimReap only writes to
// stderr. event=reap, phase=claim, attributed to the CLAIMING session; the freed
// ids ride the note. TaskID is left EMPTY on purpose: recordEvent upserts a
// lock_heartbeats freshness row only when both session AND task_id are set, and
// the claimer does NOT hold the reaped locks — writing a heartbeat for it against
// a just-freed task would be a false liveness signal. Fail-open by contract: the
// caller ignores the returned error, and a zero-reap claim is a silent no-op so
// the overwhelmingly-common quiet path adds no wave_events noise.
func (ls *lockServer) recordClaimReap(session, host string, freed []string, age time.Duration) error {
	if len(freed) == 0 {
		return nil
	}
	return ls.recordEvent(WaveEvent{
		Phase:   "claim",
		Event:   "reap",
		Session: session,
		Host:    host,
		Note: fmt.Sprintf("claim-time auto-reaped %d stale lock(s) (age > %s): %s",
			len(freed), age, strings.Join(freed, ", ")),
	})
}

// claimRemote claims a ready task with the shared server as the authority. It is
// the signature-stable wrapper over claimRemoteReaped, kept for callers that do
// not consume the claim-time reaped-lock ids (existing tests, any non-observing
// path). See claimRemoteReaped for the walk semantics.
func claimRemote(db *sql.DB, ls *lockServer, session, host, optionalID string) (*Task, error) {
	t, _, err := claimRemoteReaped(db, ls, session, host, optionalID)
	return t, err
}

// claimRemoteReaped claims a ready task with the shared server as the authority.
// It syncs the local mirror, then walks ready candidates in priority order trying
// to acquire each remotely; the first success is flipped to in-progress locally
// (mirroring the lock) and returned. A candidate locked out from under us is
// mirrored and skipped. sql.ErrNoRows signals a drained/contended queue, the
// same contract as claimLocal.
//
// It ALSO returns the ids of any stale foreign locks the opportunistic top-of-
// claim auto-reap freed (nil when TASKDB_LOCK_AUTOREAP_AGE disables it or nothing
// was stale), so an MCP/CLI caller can surface the reap instead of it living only
// on stderr. The freed set is independent of whether THIS call went on to claim a
// task — a reap can free locks even when the queue then drains.
func claimRemoteReaped(db *sql.DB, ls *lockServer, session, host, optionalID string) (*Task, []string, error) {
	// Opportunistically age out ORPHANED foreign locks (docs/23 OQ4, re-scoped
	// 2026-07-02) so a crashed wave's stale hold never permanently blocks a claim
	// of its task — the activity-aware, sentinel-excluding predicate means a live
	// heartbeating holder and __land_leader__ are never touched. This runs BEFORE
	// the mirror refresh below so a reaped lock is gone from ls.list() and is never
	// re-mirrored locally — the freed task is then claimable in THIS same call, not
	// only the next one. Mirrors the reapTombstones sweep's posture: fail-open (a
	// reap error never blocks a claim), and a no-op when TASKDB_LOCK_AUTOREAP_AGE
	// disables it (<=0/off).
	//
	// A SPECIFIC-TASK claim (`claim <id>`) scopes the sweep to just that target via
	// reapTarget — the cheap path that considers one row instead of DELETE-scanning
	// every stale foreign lock, which matters under large parallel waves. An
	// AUTO-claim (no id) walks all ready candidates, so it keeps the full-table
	// reap() as its broom; the landq idle loop remains the standing global broom on
	// both paths. Either way the freed ids are surfaced on stderr (logClaimReap)
	// rather than silently swallowed, so a vanished foreign lock leaves a trace.
	var reaped []string
	if a := autoReapAge(); a > 0 {
		if optionalID != "" {
			reaped, _ = ls.reapTarget(optionalID, a)
		} else {
			reaped, _ = ls.reap(a)
		}
		logClaimReap(reaped, a)
		// Best-effort wave_events trace so the reap is observable off-stderr; never
		// gates the claim (the error is deliberately dropped).
		_ = ls.recordClaimReap(session, host, reaped, a)
	}

	// Best-effort mirror refresh so readyWhere excludes other machines' holds; pass
	// our session so F3 re-registers only OUR outage-era local locks (never a peer's
	// stale mirror).
	_ = syncLocksFromRemote(db, ls, session)

	// Opportunistically age out stale tombstones (OQ-A2) — cheap, bounded, keeps
	// task_done small without a dedicated cron, mirroring how reap()/
	// reapStaleLanding self-clean. Best-effort: a reap error never blocks a claim.
	_, _ = ls.reapTombstones(tombstoneTTL())

	// One snapshot of the done-tombstones (docs/23 Proposal A), like
	// syncLocksFromRemote's ls.list() — so the per-candidate consult below adds no
	// extra round trip. An un-migrated DB / error yields an empty map (no gating),
	// so an old DB degrades to today's unguarded claim rather than failing.
	tombstones, _ := ls.tombstonedTasks()

	cands, err := selectReadyCandidates(db, optionalID)
	if err != nil {
		return nil, reaped, err
	}
	for _, t := range cands {
		// Status-aware claim (OQ-A1): a tombstone GATES this candidate only when it
		// is STRICTLY NEWER than the local row's updated_at — this clone has not yet
		// pulled+thawed the terminal state. For an AUTO-claim (no explicit id) SKIP
		// to the next ready task; for an EXPLICIT `claim <id>` REFUSE loudly so a
		// re-claim of work another clone finished is never silent.
		if ts, ok := tombstones[t.ID]; ok {
			if tsCopy := ts; tombstoneGates(&tsCopy, t.UpdatedAt) {
				if optionalID != "" {
					return nil, reaped, tombstoneRefusal(t.ID, &tsCopy)
				}
				continue // auto-claim: silently skip the completed-elsewhere task
			}
		}
		ok, holder, err := ls.acquire(t.ID, session, host)
		if err != nil {
			return nil, reaped, err
		}
		if !ok {
			if holder != nil {
				mirrorLockLocal(db, t.ID, holder.LockedBy, holder.LockedAt)
			}
			continue // locked elsewhere; try the next candidate
		}
		now := timeToMs(time.Now())
		if _, err := db.Exec(
			`UPDATE tasks SET status='in-progress', locked_by=?, locked_at=?, updated_at=? WHERE id=?`,
			session, now, now, t.ID,
		); err != nil {
			// We hold the remote lock but failed to record locally; release the
			// remote lock so the task isn't orphaned-locked, then surface it.
			ls.release(t.ID, session, true)
			return nil, reaped, err
		}
		claimed, err := getTask(db, t.ID)
		return claimed, reaped, err
	}
	return nil, reaped, sql.ErrNoRows
}
