package store

import (
	"context"
	"database/sql"
	"sort"
	"sync"
	"time"
)

// This file adds the M2 queryable session-context / prompt store (doc 02 §8;
// doc 05 §5 M2 "Queryable session context/prompts"; doc 15 §5.6). Plans already
// live behind the §5.6 Repository (records.go Plan + the *Plan methods on
// Memory/Postgres); prompts and free-form session context are the rest of doc
// 02 §8 ("Seeding and saving session context/prompts… should be queryable,
// associated with outputs").
//
// It is delivered as a SEPARATE seam (ContextStore) with its own in-memory and
// database/sql impls rather than by widening the shared Repository interface, so
// the shared store files (repository.go / memory.go / postgres.go) stay
// untouched. The two seams sit side by side behind the same D6/D33 posture: one
// external control-plane Postgres, a replaceable interface, an in-memory
// reference impl pinned to a database/sql impl by a shared conformance check.
// A control-plane binary that wants both holds a Repository and a ContextStore
// over the same *sql.DB.

// Prompt is one recorded prompt a session ran with (doc 02 §8). It is
// ATTRIBUTED to its owning session (SessionUUID, required) and ordered within
// that session by Seq, so a reader can replay a session's prompt history. Label
// is the optional reuse handle ("I reuse that stuff all the time", doc 02 §8).
// Prompts are recorded artifacts, not edited in place; PutPrompt is idempotent
// on ID.
type Prompt struct {
	ID          string
	SessionUUID string // owning session — attribution (doc 02 §8); required
	Role        string // user | system | assistant (free tag; "" defaults to "user")
	Seq         int64  // per-session ordering
	Label       string // optional reuse label
	Body        []byte // the prompt text, opaque here
	CreatedAt   time.Time
}

// SessionContext is one queryable, savable/seedable context blob for a session,
// tagged by Kind (doc 02 §8). One blob per (SessionUUID, Kind): saving a kind
// replaces the session's prior context of that kind. The Kind tag is the
// queryable facet (e.g. "init-script", "task", "notes"); attribution is the
// owning SessionUUID.
type SessionContext struct {
	SessionUUID string // owning session — attribution (doc 02 §8); required
	Kind        string // context facet, queryable; required
	Body        []byte // the context blob, opaque here
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ContextStore is the replaceable persistence seam (D33) over the doc 02 §8
// prompt + session-context rows, beside the §5.6 session/plan records the
// Repository fronts. The in-memory and database/sql implementations satisfy it
// identically; the shared conformance suite pins that equivalence. Every method
// takes a context so the Postgres impl can honor cancellation and surface
// ErrUnavailable on connection loss, the same degraded-mode contract as
// Repository (doc 15 §3).
type ContextStore interface {
	// PutPrompt records a prompt, ATTRIBUTED to its session (doc 02 §8). ID and
	// SessionUUID are required (ErrInvalid otherwise). It is idempotent on ID:
	// re-putting the same ID is a FULL replace of the row (CreatedAt included),
	// unlike PutContext which preserves the original birth time. CreatedAt is
	// stamped if zero. The in-memory and Postgres impls replace identically.
	PutPrompt(ctx context.Context, p Prompt) (Prompt, error)

	// GetPrompt returns a prompt by ID, or ErrNotFound.
	GetPrompt(ctx context.Context, id string) (Prompt, error)

	// ListPrompts returns a session's prompts in (Seq, ID) order — the replayable
	// prompt history. An empty sessionUUID returns ErrInvalid (prompts are always
	// queried by their attributed session).
	ListPrompts(ctx context.Context, sessionUUID string) ([]Prompt, error)

	// PutContext saves a session context blob under (SessionUUID, Kind),
	// REPLACING any prior context of that kind for the session (doc 02 §8 — save
	// is a replace). SessionUUID and Kind are required (ErrInvalid otherwise).
	// CreatedAt is preserved across replaces; UpdatedAt is stamped each save.
	PutContext(ctx context.Context, c SessionContext) (SessionContext, error)

	// GetContext returns the (sessionUUID, kind) blob, or ErrNotFound.
	GetContext(ctx context.Context, sessionUUID, kind string) (SessionContext, error)

	// ListContext returns a session's context blobs in Kind order — the queryable
	// per-session view (doc 02 §8). An empty sessionUUID returns ErrInvalid.
	ListContext(ctx context.Context, sessionUUID string) ([]SessionContext, error)
}

// --- in-memory ContextStore ---

// MemoryContext is the in-memory ContextStore reference impl. It is the
// reference the database/sql impl is held to by the shared conformance suite
// (RunContextConformance). It is safe for concurrent use and takes an injectable
// clock so the suite is deterministic, mirroring Memory's wiring.
//
// sessionExists is the §5.6/D33 orphan-write guard: the live schema
// (0008_session_context.sql) carries REFERENCES sessions(session_uuid) on both
// prompts and session_context, so live Postgres REJECTS an orphan PutPrompt /
// PutContext (a non-empty session_uuid with no existing sessions row) with an FK
// violation. The in-memory store does not own the sessions table — that lives in
// the §5.6 Repository (Memory) — so it consults this injected existence predicate
// to reach the SAME verdict, keeping the two impls indistinguishable (the
// attribution intent of doc 02 §8: context and prompts exist only for real
// sessions). When nil, no existence check is performed (the standalone
// MemoryContext with no session set wired); the in-memory Repository wires it via
// Memory.ContextStore so the aggregate enforces attribution exactly as Postgres's
// FK does.
type MemoryContext struct {
	mu            sync.Mutex
	prompts       map[string]Prompt         // by id
	contexts      map[ctxKey]SessionContext // by (session_uuid, kind)
	now           func() time.Time
	sessionExists func(sessionUUID string) bool // orphan-write guard; nil = unchecked
}

// ctxKey is the (session_uuid, kind) composite primary key for session_context.
type ctxKey struct {
	session string
	kind    string
}

// NewMemoryContext returns an empty in-memory ContextStore using time.Now. It is
// NOT wired to a session set, so it does not enforce the orphan-write guard;
// obtain an attribution-enforcing store from Memory.ContextStore (or wire an
// existence predicate with NewMemoryContextSessions).
func NewMemoryContext() *MemoryContext { return NewMemoryContextClock(time.Now) }

// NewMemoryContextClock returns an empty in-memory ContextStore using the
// supplied clock, with no session-existence guard wired.
func NewMemoryContextClock(now func() time.Time) *MemoryContext {
	return NewMemoryContextSessions(now, nil)
}

// NewMemoryContextSessions returns an empty in-memory ContextStore using the
// supplied clock and an orphan-write guard. When sessionExists is non-nil,
// PutPrompt / PutContext REJECT a write whose session_uuid names no existing
// session with ErrInvalid — the in-memory mirror of the live
// REFERENCES sessions(session_uuid) FK (§5.6/D33). When nil, no check is made.
func NewMemoryContextSessions(now func() time.Time, sessionExists func(sessionUUID string) bool) *MemoryContext {
	if now == nil {
		now = time.Now
	}
	return &MemoryContext{
		prompts:       make(map[string]Prompt),
		contexts:      make(map[ctxKey]SessionContext),
		now:           now,
		sessionExists: sessionExists,
	}
}

var _ ContextStore = (*MemoryContext)(nil)

// requireSession is the in-memory mirror of the live
// REFERENCES sessions(session_uuid) FK (§5.6/D33): when a session set is wired,
// a write attributed to a session that does not exist is an orphan write and is
// REJECTED with ErrInvalid — the same sentinel the live FK violation maps to
// (mapErr, SQLSTATE 23503), so callers cannot tell the impls apart. The
// sessionUUID-required check is the caller's responsibility (PutPrompt /
// PutContext enforce non-empty before reaching here); this guards only the
// existence half. It takes no lock — sessionExists is supplied by the owning
// Repository (Memory), which guards its own session map.
func (m *MemoryContext) requireSession(sessionUUID string) error {
	if m.sessionExists == nil {
		return nil // no session set wired: existence is unchecked
	}
	if !m.sessionExists(sessionUUID) {
		return wrap(ErrInvalid, "session %s does not exist (orphan write rejected, doc 02 §8 attribution / §5.6 FK)", sessionUUID)
	}
	return nil
}

func (m *MemoryContext) PutPrompt(ctx context.Context, p Prompt) (Prompt, error) {
	if err := ctx.Err(); err != nil {
		return Prompt{}, err
	}
	if p.ID == "" {
		return Prompt{}, wrap(ErrInvalid, "prompt requires an id")
	}
	if p.SessionUUID == "" {
		return Prompt{}, wrap(ErrInvalid, "prompt requires a session_uuid (attribution, doc 02 §8)")
	}
	if p.Role == "" {
		p.Role = "user"
	}
	if err := m.requireSession(p.SessionUUID); err != nil {
		return Prompt{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = m.now()
	}
	p.Body = cloneBytes(p.Body)
	m.prompts[p.ID] = p
	return clonePrompt(p), nil
}

func (m *MemoryContext) GetPrompt(ctx context.Context, id string) (Prompt, error) {
	if err := ctx.Err(); err != nil {
		return Prompt{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.prompts[id]
	if !ok {
		return Prompt{}, wrap(ErrNotFound, "prompt %s", id)
	}
	return clonePrompt(p), nil
}

func (m *MemoryContext) ListPrompts(ctx context.Context, sessionUUID string) ([]Prompt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if sessionUUID == "" {
		return nil, wrap(ErrInvalid, "ListPrompts requires a session_uuid")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Prompt, 0)
	for _, p := range m.prompts {
		if p.SessionUUID != sessionUUID {
			continue
		}
		out = append(out, clonePrompt(p))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (m *MemoryContext) PutContext(ctx context.Context, c SessionContext) (SessionContext, error) {
	if err := ctx.Err(); err != nil {
		return SessionContext{}, err
	}
	if c.SessionUUID == "" {
		return SessionContext{}, wrap(ErrInvalid, "session context requires a session_uuid (attribution, doc 02 §8)")
	}
	if c.Kind == "" {
		return SessionContext{}, wrap(ErrInvalid, "session context requires a kind (the queryable facet)")
	}
	if err := m.requireSession(c.SessionUUID); err != nil {
		return SessionContext{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	k := ctxKey{session: c.SessionUUID, kind: c.Kind}
	// Save is a replace under (session_uuid, kind); preserve the original
	// CreatedAt so the row's birth time survives a re-save.
	if prev, ok := m.contexts[k]; ok && !prev.CreatedAt.IsZero() {
		c.CreatedAt = prev.CreatedAt
	} else if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	c.Body = cloneBytes(c.Body)
	m.contexts[k] = c
	return cloneContext(c), nil
}

func (m *MemoryContext) GetContext(ctx context.Context, sessionUUID, kind string) (SessionContext, error) {
	if err := ctx.Err(); err != nil {
		return SessionContext{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.contexts[ctxKey{session: sessionUUID, kind: kind}]
	if !ok {
		return SessionContext{}, wrap(ErrNotFound, "session context %s/%s", sessionUUID, kind)
	}
	return cloneContext(c), nil
}

func (m *MemoryContext) ListContext(ctx context.Context, sessionUUID string) ([]SessionContext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if sessionUUID == "" {
		return nil, wrap(ErrInvalid, "ListContext requires a session_uuid")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]SessionContext, 0)
	for k, c := range m.contexts {
		if k.session != sessionUUID {
			continue
		}
		out = append(out, cloneContext(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kind < out[j].Kind })
	return out, nil
}

// --- database/sql ContextStore ---

// PostgresContext is the database/sql ContextStore impl. Like Postgres it takes
// an INJECTED *sql.DB (D33: the driver choice is the operator's — this package
// imports no driver, so orchestrator/go.mod stays stdlib-only) and is exercised
// against live Postgres only by the conformance suite behind DS_PG_DSN (a
// deferred manual step, never run in the sandbox). Its schema is
// orchestrator/migrations/0008_session_context.sql.
type PostgresContext struct {
	db  *sql.DB
	now func() time.Time
}

// NewPostgresContext wraps an already-open *sql.DB using time.Now.
func NewPostgresContext(db *sql.DB) *PostgresContext {
	return NewPostgresContextClock(db, time.Now)
}

// NewPostgresContextClock wraps db with an injectable clock.
func NewPostgresContextClock(db *sql.DB, now func() time.Time) *PostgresContext {
	if now == nil {
		now = time.Now
	}
	return &PostgresContext{db: db, now: now}
}

var _ ContextStore = (*PostgresContext)(nil)

const sqlUpsertPrompt = `
INSERT INTO prompts (id, session_uuid, role, seq, label, body, created_at)
VALUES ($1,$2,$3,$4,$5,$6,$7)
ON CONFLICT (id) DO UPDATE SET
  session_uuid=EXCLUDED.session_uuid, role=EXCLUDED.role, seq=EXCLUDED.seq,
  label=EXCLUDED.label, body=EXCLUDED.body, created_at=EXCLUDED.created_at`

const sqlGetPrompt = `
SELECT id, session_uuid, role, seq, label, body, created_at FROM prompts WHERE id = $1`

const sqlListPrompts = `
SELECT id, session_uuid, role, seq, label, body, created_at
FROM prompts WHERE session_uuid = $1 ORDER BY seq, id`

const sqlUpsertContext = `
INSERT INTO session_context (session_uuid, kind, body, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (session_uuid, kind) DO UPDATE SET
  body=EXCLUDED.body, updated_at=EXCLUDED.updated_at`

const sqlGetContext = `
SELECT session_uuid, kind, body, created_at, updated_at
FROM session_context WHERE session_uuid = $1 AND kind = $2`

const sqlListContext = `
SELECT session_uuid, kind, body, created_at, updated_at
FROM session_context WHERE session_uuid = $1 ORDER BY kind`

func (p *PostgresContext) PutPrompt(ctx context.Context, pr Prompt) (Prompt, error) {
	if pr.ID == "" {
		return Prompt{}, wrap(ErrInvalid, "prompt requires an id")
	}
	if pr.SessionUUID == "" {
		return Prompt{}, wrap(ErrInvalid, "prompt requires a session_uuid (attribution, doc 02 §8)")
	}
	if pr.Role == "" {
		pr.Role = "user"
	}
	if pr.CreatedAt.IsZero() {
		pr.CreatedAt = p.now()
	}
	if _, err := p.db.ExecContext(ctx, sqlUpsertPrompt,
		pr.ID, pr.SessionUUID, pr.Role, pr.Seq, pr.Label, pr.Body, pr.CreatedAt,
	); err != nil {
		return Prompt{}, mapContextErr(err)
	}
	return clonePrompt(pr), nil
}

func (p *PostgresContext) GetPrompt(ctx context.Context, id string) (Prompt, error) {
	pr, err := scanPromptFrom(p.db.QueryRowContext(ctx, sqlGetPrompt, id))
	if err != nil {
		return Prompt{}, mapErr(err)
	}
	return pr, nil
}

func (p *PostgresContext) ListPrompts(ctx context.Context, sessionUUID string) ([]Prompt, error) {
	if sessionUUID == "" {
		return nil, wrap(ErrInvalid, "ListPrompts requires a session_uuid")
	}
	rows, err := p.db.QueryContext(ctx, sqlListPrompts, sessionUUID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]Prompt, 0)
	for rows.Next() {
		pr, err := scanPromptFrom(rows)
		if err != nil {
			return nil, mapErr(err)
		}
		out = append(out, pr)
	}
	return out, mapErr(rows.Err())
}

func (p *PostgresContext) PutContext(ctx context.Context, c SessionContext) (SessionContext, error) {
	if c.SessionUUID == "" {
		return SessionContext{}, wrap(ErrInvalid, "session context requires a session_uuid (attribution, doc 02 §8)")
	}
	if c.Kind == "" {
		return SessionContext{}, wrap(ErrInvalid, "session context requires a kind (the queryable facet)")
	}
	now := p.now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	// The DO UPDATE leaves created_at untouched (the INSERT value only seeds a
	// fresh row), so a re-save preserves the original birth time the same way
	// the in-memory impl does.
	if _, err := p.db.ExecContext(ctx, sqlUpsertContext,
		c.SessionUUID, c.Kind, c.Body, c.CreatedAt, c.UpdatedAt,
	); err != nil {
		return SessionContext{}, mapContextErr(err)
	}
	// Read back so the returned CreatedAt reflects the preserved original on a
	// replace, matching the in-memory contract.
	return p.GetContext(ctx, c.SessionUUID, c.Kind)
}

func (p *PostgresContext) GetContext(ctx context.Context, sessionUUID, kind string) (SessionContext, error) {
	c, err := scanContextFrom(p.db.QueryRowContext(ctx, sqlGetContext, sessionUUID, kind))
	if err != nil {
		return SessionContext{}, mapErr(err)
	}
	return c, nil
}

func (p *PostgresContext) ListContext(ctx context.Context, sessionUUID string) ([]SessionContext, error) {
	if sessionUUID == "" {
		return nil, wrap(ErrInvalid, "ListContext requires a session_uuid")
	}
	rows, err := p.db.QueryContext(ctx, sqlListContext, sessionUUID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]SessionContext, 0)
	for rows.Next() {
		c, err := scanContextFrom(rows)
		if err != nil {
			return nil, mapErr(err)
		}
		out = append(out, c)
	}
	return out, mapErr(rows.Err())
}

// isFKViolation reports whether a database/sql / driver error is a foreign-key
// violation (SQLSTATE 23503). The detection is driver-agnostic (the SQLSTATE
// string + the human FK phrase surface across stdlib-compatible drivers) so the
// module stays stdlib-only, mirroring mapErr's 23505 detection. It is the shared
// predicate behind every in-memory↔live FK-parity mapping (mapFKErr), so the
// detection lives in ONE place rather than duplicated per write path.
func isFKViolation(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(), "23503", "foreign key constraint", "violates foreign key")
}

// mapFKErr is the shared FK→ErrInvalid mapper: a live foreign-key violation
// (SQLSTATE 23503) becomes ErrInvalid — the SAME sentinel the in-memory
// existence guards (MemoryContext.requireSession, Memory.sessionExistsLocked)
// return — so an orphan write is rejected indistinguishably across the in-memory
// and Postgres impls (a caller that errors.Is(err, ErrInvalid) cannot tell them
// apart). Any non-FK error falls through to mapErr's existing translation
// (ErrConflict on 23505, ErrUnavailable on a dropped connection, etc.). This is
// the single helper the doc 02 §8 ContextStore write paths and the §5.6
// Repository FK edges (plans.session_uuid 0004, sessions.parent_session_uuid
// 0001, the prompts/session_context edges 0008) share rather than each
// re-deriving the SQLSTATE-23503 test.
func mapFKErr(err error) error {
	if err == nil {
		return nil
	}
	if isFKViolation(err) {
		return wrap(ErrInvalid, "%v", err)
	}
	return mapErr(err)
}

// mapContextErr extends the shared mapErr with the §5.6/D33 orphan-write mapping
// for the doc 02 §8 write paths: the prompts / session_context REFERENCES
// sessions(session_uuid) FK (0008_session_context.sql) fails an orphan write
// with SQLSTATE 23503, which mapErr leaves as a raw driver error. Here it becomes
// ErrInvalid via the shared mapFKErr helper.
//
// COUPLING (pinned by the single-FK-per-table guard test, sessioncontext_test.go
// TestSingleFKPerContextTable): 0008_session_context.sql carries EXACTLY ONE FK
// per table — session_uuid REFERENCES sessions — so a 23503 on a prompts /
// session_context write is unambiguously the attribution-orphan FK, and mapping
// it to the attribution ErrInvalid is exact. A FUTURE second FK on either table
// (e.g. a label-catalog or kind-vocabulary ref) would also raise 23503 and this
// mapper would silently misclassify it as the attribution ErrInvalid, hiding a
// different integrity failure behind the attribution sentinel. The guard test
// fails LOUDLY the day a second FK lands, forcing this detection to be re-pinned
// (to the constraint NAME) in lockstep before the new FK ships.
func mapContextErr(err error) error {
	return mapFKErr(err)
}

// --- scan helpers (rowScanner is declared in postgres.go) ---

func scanPromptFrom(rs rowScanner) (Prompt, error) {
	var pr Prompt
	if err := rs.Scan(&pr.ID, &pr.SessionUUID, &pr.Role, &pr.Seq, &pr.Label, &pr.Body, &pr.CreatedAt); err != nil {
		return Prompt{}, err
	}
	return pr, nil
}

func scanContextFrom(rs rowScanner) (SessionContext, error) {
	var c SessionContext
	if err := rs.Scan(&c.SessionUUID, &c.Kind, &c.Body, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return SessionContext{}, err
	}
	return c, nil
}

// --- clone helpers (the store never hands out aliases of its own state) ---

func clonePrompt(p Prompt) Prompt {
	p.Body = cloneBytes(p.Body)
	return p
}

func cloneContext(c SessionContext) SessionContext {
	c.Body = cloneBytes(c.Body)
	return c
}
