package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Postgres is the database/sql Repository implementation. It takes an INJECTED
// *sql.DB (D33: the driver choice is the operator's — this package imports no
// driver, so orchestrator/go.mod stays stdlib-only). The owner wires a driver
// (e.g. pgx's stdlib shim or lib/pq) at the binary boundary and hands the open
// pool here; live-Postgres integration is exercised only by the conformance
// suite behind DS_PG_DSN (a deferred manual step, never run in the sandbox).
//
// SQL is written for PostgreSQL ($N placeholders, ON CONFLICT, bigserial). The
// schema it targets is orchestrator/migrations/*.sql.
type Postgres struct {
	db  *sql.DB
	now func() time.Time
}

// NewPostgres wraps an already-open *sql.DB. The clock defaults to time.Now;
// the conformance suite injects a deterministic clock for TTL assertions via
// NewPostgresClock.
func NewPostgres(db *sql.DB) *Postgres { return NewPostgresClock(db, time.Now) }

// NewPostgresClock wraps db with an injectable clock.
func NewPostgresClock(db *sql.DB, now func() time.Time) *Postgres {
	if now == nil {
		now = time.Now
	}
	return &Postgres{db: db, now: now}
}

var _ Repository = (*Postgres)(nil)

// mapErr translates database/sql / driver errors into the package sentinels.
// Connection-level failures surface as ErrUnavailable so callers stall cleanly
// in the doc 15 §3 Postgres-down degraded mode rather than buffering writes.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return wrap(ErrNotFound, "no rows")
	}
	if errors.Is(err, sql.ErrConnDone) || errors.Is(err, context.DeadlineExceeded) {
		return wrap(ErrUnavailable, "%v", err)
	}
	// Unique-violation detection without a driver dependency: Postgres SQLSTATE
	// 23505 surfaces in the error string across stdlib-compatible drivers.
	if msg := err.Error(); containsAny(msg, "23505", "duplicate key", "unique constraint") {
		return wrap(ErrConflict, "%v", err)
	}
	return err
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if indexOf(s, sub) >= 0 {
			return true
		}
	}
	return false
}

// indexOf is a tiny substring search (avoids importing strings for one call).
func indexOf(s, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// --- sessions ---

func (p *Postgres) CreateSession(ctx context.Context, s Session) (Session, error) {
	if s.Ref.SessionUUID == "" {
		return Session{}, wrap(ErrInvalid, "session_uuid is required")
	}
	if s.State == "" {
		s.State = SessionPending
	}
	if !s.State.Valid() {
		return Session{}, wrap(ErrInvalid, "unknown session state %q", s.State)
	}
	if err := checkSuspend(s.State, s.SuspendReason); err != nil {
		return Session{}, err
	}
	now := p.now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now
	if len(s.IndexHistory) == 0 {
		s.IndexHistory = []IndexEpoch{{
			HostID:           s.Ref.HostID,
			HostSessionIndex: s.Ref.HostSessionIndex,
			TapName:          s.Ref.TapName,
			StartedAt:        now,
		}}
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	// Idempotency-on-UUID + burned-index check, in-transaction.
	existing, err := p.getSessionTx(ctx, tx, s.Ref.SessionUUID)
	switch {
	case err == nil:
		if existing.Ref != s.Ref {
			return Session{}, wrap(ErrConflict, "session %s already exists with a different SessionRef", s.Ref.SessionUUID)
		}
		return existing, nil
	case !errors.Is(err, ErrNotFound):
		return Session{}, err
	}

	burned, err := p.indexBurnedTx(ctx, tx, s.Ref.HostID, s.Ref.HostSessionIndex)
	if err != nil {
		return Session{}, err
	}
	if burned {
		return Session{}, wrap(ErrInvalid, "host_session_index %d already burned on host %s", s.Ref.HostSessionIndex, s.Ref.HostID)
	}

	grants, err := json.Marshal(s.Grants)
	if err != nil {
		return Session{}, wrap(ErrInvalid, "marshal grants: %v", err)
	}
	if _, err := tx.ExecContext(ctx, sqlInsertSession,
		s.Ref.SessionUUID, s.Ref.HostID, int64(s.Ref.HostSessionIndex), s.Ref.TapName,
		s.EnvConfigRef, s.ImageID, s.IdentityRef, s.CARef, s.DigestRef, s.DigestAcked,
		s.PolicyAppliedSeq, grants,
		s.WriterSeat, string(s.WriterRole), s.Attended, string(s.AttachState),
		nullStr(s.ParentSessionUUID), string(s.State), nullSuspend(s.SuspendReason),
		s.RolePin.Name, s.RolePin.Version, s.RolePin.ContentHash, s.RolePin.WideningsInert,
		nullTime(s.MintExpiry),
		s.CreatedAt, s.ReadyAt, s.AttachedAt, s.DestroyedAt, s.UpdatedAt,
	); err != nil {
		// sessions.parent_session_uuid REFERENCES sessions (0001, nullable self-ref):
		// a non-empty parent naming no session is an orphan, rejected by the live FK
		// (SQLSTATE 23503). Route through the shared mapFKErr so it returns ErrInvalid
		// — the SAME sentinel the in-memory guard returns — preserving D33 parity. Any
		// non-FK error (23505 conflict, dropped connection) falls through to mapErr.
		return Session{}, mapFKErr(err)
	}
	for _, e := range s.IndexHistory {
		if err := p.insertEpochTx(ctx, tx, s.Ref.SessionUUID, e); err != nil {
			return Session{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Session{}, mapErr(err)
	}
	return cloneSession(s), nil
}

func (p *Postgres) GetSession(ctx context.Context, sessionUUID string) (Session, error) {
	return p.getSessionTx(ctx, p.db, sessionUUID)
}

func (p *Postgres) UpdateSession(ctx context.Context, sessionUUID string, u SessionUpdate) (Session, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	cur, err := p.getSessionTx(ctx, tx, sessionUUID)
	if err != nil {
		return Session{}, err
	}
	applyUpdate(&cur, u)
	// The minted-credential expiry horizon (migration 0010) applies alongside the rest
	// of the update via the MintExpiry-owning apply (session.go) — kept identical to the
	// in-memory path (D33 conformance parity). NIL leaves it unchanged.
	applyMintExpiry(&cur, u)
	if !cur.State.Valid() {
		return Session{}, wrap(ErrInvalid, "unknown session state %q", cur.State)
	}
	if err := checkSuspend(cur.State, cur.SuspendReason); err != nil {
		return Session{}, err
	}
	cur.UpdatedAt = p.now()

	grants, err := json.Marshal(cur.Grants)
	if err != nil {
		return Session{}, wrap(ErrInvalid, "marshal grants: %v", err)
	}
	if _, err := tx.ExecContext(ctx, sqlUpdateSession,
		cur.EnvConfigRef, cur.ImageID, cur.IdentityRef, cur.CARef, cur.DigestRef, cur.DigestAcked,
		cur.PolicyAppliedSeq, grants,
		cur.WriterSeat, string(cur.WriterRole), cur.Attended, string(cur.AttachState),
		string(cur.State), nullSuspend(cur.SuspendReason),
		cur.RolePin.Name, cur.RolePin.Version, cur.RolePin.ContentHash, cur.RolePin.WideningsInert,
		nullTime(cur.MintExpiry),
		cur.ReadyAt, cur.AttachedAt, cur.DestroyedAt, cur.UpdatedAt,
		sessionUUID,
	); err != nil {
		return Session{}, mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return Session{}, mapErr(err)
	}
	return cloneSession(cur), nil
}

func (p *Postgres) AppendIndexEpoch(ctx context.Context, sessionUUID string, e IndexEpoch) (Session, error) {
	if e.HostID == "" {
		return Session{}, wrap(ErrInvalid, "index epoch requires a host_id")
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return Session{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	cur, err := p.getSessionTx(ctx, tx, sessionUUID)
	if err != nil {
		return Session{}, err
	}
	burned, err := p.indexBurnedTx(ctx, tx, e.HostID, e.HostSessionIndex)
	if err != nil {
		return Session{}, err
	}
	if burned {
		return Session{}, wrap(ErrInvalid, "host_session_index %d already burned on host %s", e.HostSessionIndex, e.HostID)
	}
	now := p.now()
	if e.StartedAt.IsZero() {
		e.StartedAt = now
	}
	// Close the open epoch.
	if _, err := tx.ExecContext(ctx, sqlCloseOpenEpoch, now, sessionUUID); err != nil {
		return Session{}, mapErr(err)
	}
	if err := p.insertEpochTx(ctx, tx, sessionUUID, e); err != nil {
		return Session{}, err
	}
	if _, err := tx.ExecContext(ctx, sqlUpdateSessionRef,
		e.HostID, int64(e.HostSessionIndex), e.TapName, now, sessionUUID,
	); err != nil {
		return Session{}, mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return Session{}, mapErr(err)
	}

	cur.IndexHistory = append(cur.IndexHistory, e)
	if n := len(cur.IndexHistory); n >= 2 && cur.IndexHistory[n-2].EndedAt == nil {
		end := now
		cur.IndexHistory[n-2].EndedAt = &end
	}
	cur.Ref.HostID = e.HostID
	cur.Ref.HostSessionIndex = e.HostSessionIndex
	cur.Ref.TapName = e.TapName
	cur.UpdatedAt = now
	return cloneSession(cur), nil
}

func (p *Postgres) ListSessions(ctx context.Context, f SessionFilter) ([]Session, error) {
	// The keyset-cursor values ($7/$8) are gated by the SET flag ($6 = NOT $6 short-circuits
	// the comparison) so they are passed unconditionally — a zero CreatedAt / empty UUID is
	// never evaluated when the cursor is unset. The LIMIT param maps PageSize <= 0 to -1 (the
	// CASE-to-NULL "no limit" single-shot path) and a positive PageSize to itself.
	limitParam := int64(-1)
	if f.PageSize > 0 {
		limitParam = int64(f.PageSize)
	}
	rows, err := p.db.QueryContext(ctx, sqlListSessions,
		nullStr(f.HostID), nullStr(string(f.State)), nullStr(f.ParentSessionUUID), f.IncludeDestroyed,
		nullStr(f.LaunchingUser),
		f.PageToken.Set, f.PageToken.CreatedAt, f.PageToken.UUID,
		limitParam,
	)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()

	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, mapErr(err)
		}
		hist, err := p.loadEpochs(ctx, p.db, s.Ref.SessionUUID)
		if err != nil {
			return nil, err
		}
		s.IndexHistory = hist
		out = append(out, s)
	}
	return out, mapErr(rows.Err())
}

// --- policy_log ---

func (p *Postgres) AppendPolicy(ctx context.Context, row PolicyLogRow) (PolicyLogRow, error) {
	if row.Actor == "" {
		return PolicyLogRow{}, wrap(ErrInvalid, "policy_log row requires an actor (D36)")
	}
	if row.Kind == "" {
		row.Kind = PolicyKindAppend
	}
	if row.CreatedAt.IsZero() {
		row.CreatedAt = p.now()
	}
	err := p.db.QueryRowContext(ctx, sqlInsertPolicy,
		string(row.Kind), row.Actor, row.ContentHash, row.Payload,
		nullStr(row.SessionUUID), row.ExpiresAt, row.CreatedAt,
	).Scan(&row.Seq)
	if err != nil {
		return PolicyLogRow{}, mapErr(err)
	}
	return clonePolicy(row), nil
}

func (p *Postgres) ListPolicy(ctx context.Context, fromSeq int64, limit int) ([]PolicyLogRow, error) {
	lim := int64(-1)
	if limit > 0 {
		lim = int64(limit)
	}
	rows, err := p.db.QueryContext(ctx, sqlListPolicy, fromSeq, lim)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	return scanPolicyRows(rows)
}

func (p *Postgres) LiveGrants(ctx context.Context, sessionUUID string, now time.Time) ([]PolicyLogRow, error) {
	rows, err := p.db.QueryContext(ctx, sqlLiveGrants, sessionUUID, string(PolicyKindAskGrant), now)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	return scanPolicyRows(rows)
}

// --- env_configs ---

func (p *Postgres) PutEnvConfig(ctx context.Context, c EnvConfig) (EnvConfig, error) {
	if c.Ref == "" {
		return EnvConfig{}, wrap(ErrInvalid, "env config requires a ref")
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = p.now()
	}
	if _, err := p.db.ExecContext(ctx, sqlUpsertEnv,
		c.Ref, c.RepoRef, c.SpecHash, c.InlineSpec, c.ImageID,
		c.CoupledPin, c.PackVersion, c.PackExclusion, c.CreatedAt,
	); err != nil {
		return EnvConfig{}, mapErr(err)
	}
	return cloneEnv(c), nil
}

func (p *Postgres) GetEnvConfig(ctx context.Context, ref string) (EnvConfig, error) {
	var c EnvConfig
	err := p.db.QueryRowContext(ctx, sqlGetEnv, ref).Scan(
		&c.Ref, &c.RepoRef, &c.SpecHash, &c.InlineSpec, &c.ImageID,
		&c.CoupledPin, &c.PackVersion, &c.PackExclusion, &c.CreatedAt,
	)
	if err != nil {
		return EnvConfig{}, mapErr(err)
	}
	return c, nil
}

// --- plans ---

func (p *Postgres) PutPlan(ctx context.Context, pl Plan) (Plan, error) {
	if pl.ID == "" {
		return Plan{}, wrap(ErrInvalid, "plan requires an id")
	}
	now := p.now()
	if pl.CreatedAt.IsZero() {
		pl.CreatedAt = now
	}
	pl.UpdatedAt = now
	if _, err := p.db.ExecContext(ctx, sqlUpsertPlan,
		pl.ID, nullStr(pl.SessionUUID), pl.Title, pl.Body, pl.CreatedAt, pl.UpdatedAt,
	); err != nil {
		// plans.session_uuid REFERENCES sessions (0004, nullable): a non-empty
		// session_uuid naming no session is an orphan, rejected by the live FK
		// (SQLSTATE 23503). Route through the shared mapFKErr so it returns ErrInvalid
		// — the SAME sentinel the in-memory guard returns — preserving D33 parity. Any
		// non-FK error (23505 conflict, dropped connection) falls through to mapErr.
		return Plan{}, mapFKErr(err)
	}
	return clonePlan(pl), nil
}

func (p *Postgres) GetPlan(ctx context.Context, id string) (Plan, error) {
	return scanPlanRow(p.db.QueryRowContext(ctx, sqlGetPlan, id))
}

func (p *Postgres) ListPlans(ctx context.Context, sessionUUID string) ([]Plan, error) {
	rows, err := p.db.QueryContext(ctx, sqlListPlans, nullStr(sessionUUID))
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []Plan
	for rows.Next() {
		pl, err := scanPlan(rows)
		if err != nil {
			return nil, mapErr(err)
		}
		out = append(out, pl)
	}
	return out, mapErr(rows.Err())
}

// --- metering_events ---

func (p *Postgres) AppendMeteringEvent(ctx context.Context, e MeteringEvent) error {
	if e.EventID == "" {
		return wrap(ErrInvalid, "metering event requires an event_id (idempotency key)")
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = p.now()
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	existing, err := scanMeteringRow(tx.QueryRowContext(ctx, sqlGetMetering, e.EventID))
	switch {
	case err == nil:
		if !meteringEqual(existing, e) {
			return wrap(ErrConflict, "metering event %s already recorded with a different body", e.EventID)
		}
		return nil // idempotent
	case !errors.Is(err, ErrNotFound):
		return err
	}
	if _, err := tx.ExecContext(ctx, sqlInsertMetering,
		e.EventID, e.SessionUUID, e.Kind, string(e.State), e.OccurredAt, e.Payload,
	); err != nil {
		return mapErr(err)
	}
	return mapErr(tx.Commit())
}

func (p *Postgres) ListMeteringEvents(ctx context.Context, sessionUUID string) ([]MeteringEvent, error) {
	rows, err := p.db.QueryContext(ctx, sqlListMetering, nullStr(sessionUUID))
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []MeteringEvent
	for rows.Next() {
		e, err := scanMetering(rows)
		if err != nil {
			return nil, mapErr(err)
		}
		out = append(out, e)
	}
	return out, mapErr(rows.Err())
}

// --- principals ---

func (p *Postgres) CreatePrincipal(ctx context.Context, pr Principal) (Principal, error) {
	if pr.ID == "" {
		return Principal{}, wrap(ErrInvalid, "principal id is required")
	}
	if pr.IdPSubject == "" || pr.Org == "" {
		return Principal{}, wrap(ErrInvalid, "principal requires an idp_subject and org")
	}
	if err := validateRoles(pr.Roles); err != nil {
		return Principal{}, err
	}
	now := p.now()
	if pr.CreatedAt.IsZero() {
		pr.CreatedAt = now
	}
	pr.UpdatedAt = now

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return Principal{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	// Idempotency-on-ID, in-transaction: an identical re-create is a success.
	existing, err := scanPrincipalRow(tx.QueryRowContext(ctx, sqlGetPrincipal, pr.ID))
	switch {
	case err == nil:
		if existing.IdPSubject == pr.IdPSubject && existing.Org == pr.Org && rolesEqual(existing.Roles, pr.Roles) {
			return existing, nil
		}
		return Principal{}, wrap(ErrConflict, "principal %s already exists with a different record", pr.ID)
	case !errors.Is(err, ErrNotFound):
		return Principal{}, err
	}

	roles, err := json.Marshal(rolesOrEmpty(pr.Roles))
	if err != nil {
		return Principal{}, wrap(ErrInvalid, "marshal roles: %v", err)
	}
	// The UNIQUE(idp_subject, org) collision surfaces as ErrConflict via mapErr
	// (SQLSTATE 23505); the role CHECK violation surfaces as a generic error and
	// is also guarded above by validateRoles so it never reaches the DB.
	if _, err := tx.ExecContext(ctx, sqlInsertPrincipal,
		pr.ID, pr.IdPSubject, pr.Org, roles, pr.DisplayName, pr.CreatedAt, pr.UpdatedAt,
	); err != nil {
		return Principal{}, mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return Principal{}, mapErr(err)
	}
	return clonePrincipal(pr), nil
}

func (p *Postgres) GetPrincipal(ctx context.Context, id string) (Principal, error) {
	return scanPrincipalRow(p.db.QueryRowContext(ctx, sqlGetPrincipal, id))
}

func (p *Postgres) GetPrincipalByIdP(ctx context.Context, idpSubject, org string) (Principal, error) {
	return scanPrincipalRow(p.db.QueryRowContext(ctx, sqlGetPrincipalByIdP, idpSubject, org))
}

func (p *Postgres) SetPrincipalRoles(ctx context.Context, id string, roles []PrincipalRole) (Principal, error) {
	if err := validateRoles(roles); err != nil {
		return Principal{}, err
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return Principal{}, mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	cur, err := scanPrincipalRow(tx.QueryRowContext(ctx, sqlGetPrincipal, id))
	if err != nil {
		return Principal{}, err
	}
	roleJSON, err := json.Marshal(rolesOrEmpty(roles))
	if err != nil {
		return Principal{}, wrap(ErrInvalid, "marshal roles: %v", err)
	}
	now := p.now()
	if _, err := tx.ExecContext(ctx, sqlUpdatePrincipalRoles, roleJSON, now, id); err != nil {
		return Principal{}, mapErr(err)
	}
	if err := tx.Commit(); err != nil {
		return Principal{}, mapErr(err)
	}
	cur.Roles = cloneRoles(roles)
	cur.UpdatedAt = now
	return cur, nil
}

// --- session → launching_principal linkage ---

func (p *Postgres) SetSessionLaunchingPrincipal(ctx context.Context, sessionUUID, principalID string) error {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = tx.Rollback() }()

	// The session must exist (ErrNotFound otherwise).
	if _, err := p.getSessionTx(ctx, tx, sessionUUID); err != nil {
		return err
	}
	if principalID != "" {
		// Soft-FK guard mirroring the nullable column's REFERENCES: a non-empty
		// link must name a real principal.
		var one int
		switch err := tx.QueryRowContext(ctx, sqlPrincipalExists, principalID).Scan(&one); {
		case errors.Is(err, sql.ErrNoRows):
			return wrap(ErrInvalid, "launching principal %s does not exist", principalID)
		case err != nil:
			return mapErr(err)
		}
	}
	if _, err := tx.ExecContext(ctx, sqlSetLaunchingPrincipal, nullStr(principalID), p.now(), sessionUUID); err != nil {
		return mapErr(err)
	}
	return mapErr(tx.Commit())
}

func (p *Postgres) GetSessionLaunchingPrincipal(ctx context.Context, sessionUUID string) (string, error) {
	var ref sql.NullString
	err := p.db.QueryRowContext(ctx, sqlGetLaunchingPrincipal, sessionUUID).Scan(&ref)
	if err != nil {
		return "", mapErr(err)
	}
	if ref.Valid {
		return ref.String, nil // a set link
	}
	return "", nil // the nullable / no-link case
}

// --- transaction-scoped helpers ---

// querier is satisfied by both *sql.DB and *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (p *Postgres) getSessionTx(ctx context.Context, q querier, sessionUUID string) (Session, error) {
	s, err := scanSessionRow(q.QueryRowContext(ctx, sqlGetSession, sessionUUID))
	if err != nil {
		return Session{}, mapErr(err)
	}
	hist, err := p.loadEpochs(ctx, q, sessionUUID)
	if err != nil {
		return Session{}, err
	}
	s.IndexHistory = hist
	return s, nil
}

func (p *Postgres) indexBurnedTx(ctx context.Context, q querier, hostID string, idx uint64) (bool, error) {
	var n int
	err := q.QueryRowContext(ctx, sqlIndexBurned, hostID, int64(idx)).Scan(&n)
	if err != nil {
		return false, mapErr(err)
	}
	return n > 0, nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (p *Postgres) insertEpochTx(ctx context.Context, ex execer, sessionUUID string, e IndexEpoch) error {
	_, err := ex.ExecContext(ctx, sqlInsertEpoch,
		sessionUUID, e.HostID, int64(e.HostSessionIndex), e.TapName,
		e.GuestIP, string(e.GuestIPFamily), e.OverlayPath, e.StartedAt, e.EndedAt,
	)
	return mapErr(err)
}

func (p *Postgres) loadEpochs(ctx context.Context, q querier, sessionUUID string) ([]IndexEpoch, error) {
	rows, err := q.QueryContext(ctx, sqlListEpochs, sessionUUID)
	if err != nil {
		return nil, mapErr(err)
	}
	defer func() { _ = rows.Close() }()
	var out []IndexEpoch
	for rows.Next() {
		var (
			e      IndexEpoch
			family string
			ended  sql.NullTime
			idx    int64
		)
		if err := rows.Scan(&e.HostID, &idx, &e.TapName, &e.GuestIP, &family, &e.OverlayPath, &e.StartedAt, &ended); err != nil {
			return nil, mapErr(err)
		}
		e.HostSessionIndex = uint64(idx)
		e.GuestIPFamily = IPFamily(family)
		if ended.Valid {
			t := ended.Time
			e.EndedAt = &t
		}
		out = append(out, e)
	}
	return out, mapErr(rows.Err())
}

// --- scan helpers ---

// rowScanner is satisfied by *sql.Row and *sql.Rows.
type rowScanner interface{ Scan(dest ...any) error }

func scanSession(rs rowScanner) (Session, error)        { return scanSessionFrom(rs) }
func scanSessionRow(r *sql.Row) (Session, error)        { return scanSessionFrom(r) }
func scanPlan(rs rowScanner) (Plan, error)              { return scanPlanFrom(rs) }
func scanMetering(rs rowScanner) (MeteringEvent, error) { return scanMeteringFrom(rs) }

func scanPlanRow(r *sql.Row) (Plan, error) {
	pl, err := scanPlanFrom(r)
	if err != nil {
		return Plan{}, mapErr(err)
	}
	return pl, nil
}

func scanMeteringRow(r *sql.Row) (MeteringEvent, error) {
	e, err := scanMeteringFrom(r)
	if err != nil {
		return MeteringEvent{}, mapErr(err)
	}
	return e, nil
}

func scanSessionFrom(rs rowScanner) (Session, error) {
	var (
		s        Session
		idx      int64
		parent   sql.NullString
		writerRl string
		attachSt string
		suspend  sql.NullString
		ready    sql.NullTime
		attached sql.NullTime
		destroy  sql.NullTime
		mintExp  sql.NullTime
		grants   []byte
	)
	err := rs.Scan(
		&s.Ref.SessionUUID, &s.Ref.HostID, &idx, &s.Ref.TapName,
		&s.EnvConfigRef, &s.ImageID, &s.IdentityRef, &s.CARef, &s.DigestRef, &s.DigestAcked,
		&s.PolicyAppliedSeq, &grants,
		&s.WriterSeat, &writerRl, &s.Attended, &attachSt,
		&parent, &s.State, &suspend,
		&s.RolePin.Name, &s.RolePin.Version, &s.RolePin.ContentHash, &s.RolePin.WideningsInert,
		&mintExp,
		&s.CreatedAt, &ready, &attached, &destroy, &s.UpdatedAt,
	)
	if err != nil {
		return Session{}, err
	}
	s.Ref.HostSessionIndex = uint64(idx)
	s.WriterRole = AttachRole(writerRl)
	s.AttachState = AttachRole(attachSt)
	if parent.Valid {
		s.ParentSessionUUID = parent.String
	}
	if suspend.Valid {
		s.SuspendReason = SuspendReason(suspend.String)
	}
	if len(grants) > 0 {
		if err := json.Unmarshal(grants, &s.Grants); err != nil {
			return Session{}, fmt.Errorf("unmarshal grants: %w", err)
		}
	}
	if ready.Valid {
		t := ready.Time
		s.ReadyAt = &t
	}
	if attached.Valid {
		t := attached.Time
		s.AttachedAt = &t
	}
	if destroy.Valid {
		t := destroy.Time
		s.DestroyedAt = &t
	}
	// mint_expiry (migration 0010): a NULL column is the "no TTL tracked" not-set posture
	// and leaves MintExpiry the zero value; a non-NULL instant is the durable
	// routable-window / teardown-re-mint horizon (doc 16 §5.4).
	if mintExp.Valid {
		s.MintExpiry = mintExp.Time
	}
	return s, nil
}

func scanPolicyRows(rows *sql.Rows) ([]PolicyLogRow, error) {
	var out []PolicyLogRow
	for rows.Next() {
		var (
			r       PolicyLogRow
			kind    string
			session sql.NullString
			expires sql.NullTime
		)
		if err := rows.Scan(&r.Seq, &kind, &r.Actor, &r.ContentHash, &r.Payload, &session, &expires, &r.CreatedAt); err != nil {
			return nil, mapErr(err)
		}
		r.Kind = PolicyKind(kind)
		if session.Valid {
			r.SessionUUID = session.String
		}
		if expires.Valid {
			t := expires.Time
			r.ExpiresAt = &t
		}
		out = append(out, r)
	}
	return out, mapErr(rows.Err())
}

func scanPlanFrom(rs rowScanner) (Plan, error) {
	var (
		pl      Plan
		session sql.NullString
	)
	if err := rs.Scan(&pl.ID, &session, &pl.Title, &pl.Body, &pl.CreatedAt, &pl.UpdatedAt); err != nil {
		return Plan{}, err
	}
	if session.Valid {
		pl.SessionUUID = session.String
	}
	return pl, nil
}

func scanMeteringFrom(rs rowScanner) (MeteringEvent, error) {
	var (
		e     MeteringEvent
		state string
	)
	if err := rs.Scan(&e.EventID, &e.SessionUUID, &e.Kind, &state, &e.OccurredAt, &e.Payload); err != nil {
		return MeteringEvent{}, err
	}
	e.State = SessionState(state)
	return e, nil
}

// scanPrincipalRow scans one principals row, mapping sql.ErrNoRows to
// ErrNotFound and decoding the jsonb roles column with encoding/json (the same
// driver-agnostic path sessions.grants uses — no Postgres array driver needed,
// so the module stays stdlib-only).
func scanPrincipalRow(r *sql.Row) (Principal, error) {
	var (
		pr      Principal
		roles   []byte
		display sql.NullString
	)
	err := r.Scan(&pr.ID, &pr.IdPSubject, &pr.Org, &roles, &display, &pr.CreatedAt, &pr.UpdatedAt)
	if err != nil {
		return Principal{}, mapErr(err)
	}
	if display.Valid {
		pr.DisplayName = display.String
	}
	if len(roles) > 0 {
		if err := json.Unmarshal(roles, &pr.Roles); err != nil {
			return Principal{}, fmt.Errorf("unmarshal roles: %w", err)
		}
	}
	return pr, nil
}

// rolesOrEmpty returns a non-nil slice so the jsonb column stores `[]` rather
// than `null` for a roleless principal (mirrors sessions.grants' '[]' default).
func rolesOrEmpty(r []PrincipalRole) []PrincipalRole {
	if r == nil {
		return []PrincipalRole{}
	}
	return r
}

// nullStr maps "" to a SQL NULL so optional FK-ish columns stay NULL not "".
func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullSuspend maps the empty (not-suspended) reason to SQL NULL.
func nullSuspend(r SuspendReason) any {
	if r == SuspendReasonNone {
		return nil
	}
	return string(r)
}

// nullTime maps a ZERO time.Time to a SQL NULL (the not-set posture) and a non-zero
// instant to itself. It is the value-typed counterpart of the *time.Time → sql.NullTime
// mapping ready_at/attached_at/destroyed_at use on the read path — the §5.6 mint_expiry
// column (migration 0010) is a value-typed time.Time on the record whose zero value IS
// the "no TTL tracked" not-set state, so it persists as NULL rather than the epoch.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
