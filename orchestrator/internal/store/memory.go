package store

import (
	"context"
	"sort"
	"sync"
	"time"
)

// Memory is the in-memory Repository implementation. It is the reference impl:
// it passes the shared conformance suite now, and the database/sql impl is held
// to the same suite behind DS_PG_DSN later. It is safe for concurrent use.
//
// The clock is injectable so the conformance suite can pin TTL expiry
// deterministically; it defaults to time.Now.
type Memory struct {
	mu sync.Mutex

	sessions   map[string]*Session      // by session UUID
	envs       map[string]EnvConfig     // by ref
	plans      map[string]Plan          // by id
	metering   map[string]MeteringEvent // by event id
	principals map[string]*Principal    // by principal ID

	// launchingPrincipal is the nullable session→principal linkage (doc 04 §5
	// attribution shape): sessionUUID -> principalID. Absence = no launching
	// principal (the nullable case), so the map never stores empty values.
	launchingPrincipal map[string]string

	policy  []PolicyLogRow // append-only, seq-ordered
	nextSeq int64

	// burnedIdx tracks every host_session_index ever bound on each host
	// (current or historical) so allocation can refuse to recycle one (D66).
	burnedIdx map[string]map[uint64]struct{} // hostID -> set of indices

	now func() time.Time
}

// NewMemory returns an empty in-memory store using time.Now as its clock.
func NewMemory() *Memory { return NewMemoryClock(time.Now) }

// NewMemoryClock returns an empty in-memory store using the supplied clock.
func NewMemoryClock(now func() time.Time) *Memory {
	if now == nil {
		now = time.Now
	}
	return &Memory{
		sessions:           make(map[string]*Session),
		envs:               make(map[string]EnvConfig),
		plans:              make(map[string]Plan),
		metering:           make(map[string]MeteringEvent),
		principals:         make(map[string]*Principal),
		launchingPrincipal: make(map[string]string),
		burnedIdx:          make(map[string]map[uint64]struct{}),
		now:                now,
	}
}

var _ Repository = (*Memory)(nil)

// HasSession reports whether a session record exists for sessionUUID. It is the
// in-memory existence predicate the ContextStore consults for the §5.6/D33
// orphan-write guard (the live REFERENCES sessions(session_uuid) FK on the
// prompts / session_context tables): a prompt or context blob may be attributed
// only to a real session (doc 02 §8). An empty sessionUUID is never an existing
// session. Safe for concurrent use.
func (m *Memory) HasSession(sessionUUID string) bool {
	if sessionUUID == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessionExistsLocked(sessionUUID)
}

// sessionExistsLocked reports whether a sessions row exists for sessionUUID. It
// is the lock-free core of HasSession, shared by the in-memory mirrors of the
// REFERENCES sessions(session_uuid) FK edges that fire INSIDE a write that
// already holds m.mu (PutPlan's plans.session_uuid edge — 0004 — and
// CreateSession's parent_session_uuid self-ref — 0001). An empty sessionUUID is
// never an existing session. The caller holds m.mu.
func (m *Memory) sessionExistsLocked(sessionUUID string) bool {
	if sessionUUID == "" {
		return false
	}
	_, ok := m.sessions[sessionUUID]
	return ok
}

// ContextStore returns an in-memory ContextStore (doc 02 §8 prompts +
// session_context) wired to THIS Repository's session set, so PutPrompt /
// PutContext reject an orphan write exactly as the live FK does — the aggregate
// in-memory store enforces the same attribution invariant as Postgres. It shares
// the Repository's clock. Each call returns a fresh, empty ContextStore over the
// same session set; a control-plane binary that wants both holds a Memory and the
// MemoryContext it hands out.
func (m *Memory) ContextStore() *MemoryContext {
	return NewMemoryContextSessions(m.now, m.HasSession)
}

// --- sessions ---

func (m *Memory) CreateSession(ctx context.Context, s Session) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
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

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.sessions[s.Ref.SessionUUID]; ok {
		// Idempotent on session_uuid: identical Ref returns the existing row;
		// a conflicting Ref is a real collision.
		if existing.Ref != s.Ref {
			return Session{}, wrap(ErrConflict, "session %s already exists with a different SessionRef", s.Ref.SessionUUID)
		}
		return cloneSession(*existing), nil
	}

	// Burned-never-recycled: refuse an index already seen on its host.
	if m.indexBurned(s.Ref.HostID, s.Ref.HostSessionIndex) {
		return Session{}, wrap(ErrInvalid, "host_session_index %d already burned on host %s", s.Ref.HostSessionIndex, s.Ref.HostID)
	}

	// Parent-link orphan guard: the in-memory mirror of the nullable self-ref FK
	// sessions.parent_session_uuid REFERENCES sessions(session_uuid) (0001). NULL
	// is legal (a root session), so an EMPTY parent is never an orphan; only a
	// NON-EMPTY parent that names no existing session is. Live Postgres rejects it
	// with an FK violation (SQLSTATE 23503); here it is ErrInvalid, the same
	// sentinel that violation maps to, so the impls are indistinguishable. Checked
	// on the create (INSERT-equivalent) path only — the idempotent short-circuit
	// above returns the existing row without re-validating, matching the pg INSERT.
	if s.ParentSessionUUID != "" && !m.sessionExistsLocked(s.ParentSessionUUID) {
		return Session{}, wrap(ErrInvalid, "parent_session_uuid %s does not exist (orphan parent-link rejected, §5.6 FK 0001)", s.ParentSessionUUID)
	}

	now := m.now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now
	// Seed the current index epoch from Ref if the caller did not supply history.
	if len(s.IndexHistory) == 0 {
		s.IndexHistory = []IndexEpoch{{
			HostID:           s.Ref.HostID,
			HostSessionIndex: s.Ref.HostSessionIndex,
			TapName:          s.Ref.TapName,
			StartedAt:        now,
		}}
	}

	stored := cloneSession(s)
	m.sessions[s.Ref.SessionUUID] = &stored
	m.burnIndex(s.Ref.HostID, s.Ref.HostSessionIndex)
	return cloneSession(stored), nil
}

func (m *Memory) GetSession(ctx context.Context, sessionUUID string) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionUUID]
	if !ok {
		return Session{}, wrap(ErrNotFound, "session %s", sessionUUID)
	}
	return cloneSession(*s), nil
}

func (m *Memory) UpdateSession(ctx context.Context, sessionUUID string, u SessionUpdate) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionUUID]
	if !ok {
		return Session{}, wrap(ErrNotFound, "session %s", sessionUUID)
	}

	next := cloneSession(*s)
	applyUpdate(&next, u)
	// The minted-credential expiry horizon (migration 0010) applies alongside the rest
	// of the update — its apply lives in the MintExpiry-owning file (session.go) so the
	// frozen records.go carries only the field registration. NIL leaves it unchanged.
	applyMintExpiry(&next, u)
	if !next.State.Valid() {
		return Session{}, wrap(ErrInvalid, "unknown session state %q", next.State)
	}
	if err := checkSuspend(next.State, next.SuspendReason); err != nil {
		return Session{}, err
	}
	next.UpdatedAt = m.now()
	*s = next
	return cloneSession(next), nil
}

func (m *Memory) AppendIndexEpoch(ctx context.Context, sessionUUID string, e IndexEpoch) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	if e.HostID == "" {
		return Session{}, wrap(ErrInvalid, "index epoch requires a host_id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[sessionUUID]
	if !ok {
		return Session{}, wrap(ErrNotFound, "session %s", sessionUUID)
	}
	if m.indexBurned(e.HostID, e.HostSessionIndex) {
		return Session{}, wrap(ErrInvalid, "host_session_index %d already burned on host %s", e.HostSessionIndex, e.HostID)
	}

	now := m.now()
	if e.StartedAt.IsZero() {
		e.StartedAt = now
	}
	next := cloneSession(*s)
	// Close the current epoch.
	if n := len(next.IndexHistory); n > 0 && next.IndexHistory[n-1].EndedAt == nil {
		end := now
		next.IndexHistory[n-1].EndedAt = &end
	}
	next.IndexHistory = append(next.IndexHistory, e)
	next.Ref.HostID = e.HostID
	next.Ref.HostSessionIndex = e.HostSessionIndex
	next.Ref.TapName = e.TapName
	next.UpdatedAt = now

	*s = next
	m.burnIndex(e.HostID, e.HostSessionIndex)
	return cloneSession(next), nil
}

func (m *Memory) ListSessions(ctx context.Context, f SessionFilter) ([]Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		if !matchSession(*s, f) {
			continue
		}
		// LaunchingUser filter (the §3.1 attribution narrowing, pushed down): resolve the
		// session's launching principal to its IdP subject through the store's own linkage +
		// principal records and keep only the exact matches. A session with no launching
		// principal — or one whose link dangles to a missing principal — never matches a
		// non-empty filter. This is the same predicate ResolveLaunchingUserClaim's match test
		// applies, so the LIMIT below bounds the FILTERED set (the N+1-per-page the handler did
		// over the resolver seam collapses into this one read).
		if f.LaunchingUser != "" && !m.launchingUserMatchesLocked(s.Ref.SessionUUID, f.LaunchingUser) {
			continue
		}
		out = append(out, cloneSession(*s))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].Ref.SessionUUID > out[j].Ref.SessionUUID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	// Keyset LIMIT: applied AFTER the stable newest-first sort (and after the cursor skip
	// matchSession already did) so the returned page is the newest-first prefix past the
	// cursor. PageSize <= 0 returns ALL (the back-compat single-shot path).
	if f.PageSize > 0 && len(out) > f.PageSize {
		out = out[:f.PageSize]
	}
	return out, nil
}

// launchingUserMatchesLocked reports whether sessionUUID's launching principal resolves to
// the given IdP subject (the §3.1 `launching_user` claim VALUE). It is the in-store
// counterpart of ResolveLaunchingUserClaim's match test, used by the ListSessions
// launching_user filter: a session with no launching principal (empty link), or one whose
// link dangles to a missing principal, never matches — the same non-match the handler's
// resolver-backed filter produced for those cases. The caller holds m.mu.
func (m *Memory) launchingUserMatchesLocked(sessionUUID, subject string) bool {
	principalID := m.launchingPrincipal[sessionUUID]
	if principalID == "" {
		return false // no launching principal (the nullable case)
	}
	pr, ok := m.principals[principalID]
	if !ok {
		return false // dangling link — excluded, never leaked
	}
	return pr.IdPSubject == subject
}

// --- policy_log ---

func (m *Memory) AppendPolicy(ctx context.Context, row PolicyLogRow) (PolicyLogRow, error) {
	if err := ctx.Err(); err != nil {
		return PolicyLogRow{}, err
	}
	if row.Actor == "" {
		return PolicyLogRow{}, wrap(ErrInvalid, "policy_log row requires an actor (D36)")
	}
	if row.Kind == "" {
		row.Kind = PolicyKindAppend
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextSeq++
	row.Seq = m.nextSeq
	if row.CreatedAt.IsZero() {
		row.CreatedAt = m.now()
	}
	stored := clonePolicy(row)
	m.policy = append(m.policy, stored)
	return clonePolicy(stored), nil
}

func (m *Memory) ListPolicy(ctx context.Context, fromSeq int64, limit int) ([]PolicyLogRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PolicyLogRow, 0)
	for _, r := range m.policy {
		if r.Seq <= fromSeq {
			continue
		}
		out = append(out, clonePolicy(r))
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (m *Memory) LiveGrants(ctx context.Context, sessionUUID string, now time.Time) ([]PolicyLogRow, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]PolicyLogRow, 0)
	for _, r := range m.policy {
		if r.Kind != PolicyKindAskGrant || r.SessionUUID != sessionUUID {
			continue
		}
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue // expired
		}
		out = append(out, clonePolicy(r))
	}
	return out, nil
}

// --- env_configs ---

func (m *Memory) PutEnvConfig(ctx context.Context, c EnvConfig) (EnvConfig, error) {
	if err := ctx.Err(); err != nil {
		return EnvConfig{}, err
	}
	if c.Ref == "" {
		return EnvConfig{}, wrap(ErrInvalid, "env config requires a ref")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = m.now()
	}
	c.InlineSpec = cloneBytes(c.InlineSpec)
	m.envs[c.Ref] = c
	return cloneEnv(c), nil
}

func (m *Memory) GetEnvConfig(ctx context.Context, ref string) (EnvConfig, error) {
	if err := ctx.Err(); err != nil {
		return EnvConfig{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.envs[ref]
	if !ok {
		return EnvConfig{}, wrap(ErrNotFound, "env config %s", ref)
	}
	return cloneEnv(c), nil
}

// --- plans ---

func (m *Memory) PutPlan(ctx context.Context, p Plan) (Plan, error) {
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	if p.ID == "" {
		return Plan{}, wrap(ErrInvalid, "plan requires an id")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Owning-session orphan guard: the in-memory mirror of the nullable FK
	// plans.session_uuid REFERENCES sessions(session_uuid) (0004). The column is
	// nullable (a plan may be unscoped), so an EMPTY session_uuid is legal; only a
	// NON-EMPTY session_uuid naming no existing session is an orphan. Live Postgres
	// rejects it (SQLSTATE 23503); here it is ErrInvalid, the same sentinel, so the
	// impls are indistinguishable.
	if p.SessionUUID != "" && !m.sessionExistsLocked(p.SessionUUID) {
		return Plan{}, wrap(ErrInvalid, "session %s does not exist (orphan plan write rejected, §5.6 FK 0004)", p.SessionUUID)
	}
	now := m.now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	p.Body = cloneBytes(p.Body)
	m.plans[p.ID] = p
	return clonePlan(p), nil
}

func (m *Memory) GetPlan(ctx context.Context, id string) (Plan, error) {
	if err := ctx.Err(); err != nil {
		return Plan{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.plans[id]
	if !ok {
		return Plan{}, wrap(ErrNotFound, "plan %s", id)
	}
	return clonePlan(p), nil
}

func (m *Memory) ListPlans(ctx context.Context, sessionUUID string) ([]Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Plan, 0)
	for _, p := range m.plans {
		if sessionUUID != "" && p.SessionUUID != sessionUUID {
			continue
		}
		out = append(out, clonePlan(p))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// --- metering_events ---

func (m *Memory) AppendMeteringEvent(ctx context.Context, e MeteringEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.EventID == "" {
		return wrap(ErrInvalid, "metering event requires an event_id (idempotency key)")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.metering[e.EventID]; ok {
		if !meteringEqual(existing, e) {
			return wrap(ErrConflict, "metering event %s already recorded with a different body", e.EventID)
		}
		return nil // idempotent no-op
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = m.now()
	}
	e.Payload = cloneBytes(e.Payload)
	m.metering[e.EventID] = e
	return nil
}

func (m *Memory) ListMeteringEvents(ctx context.Context, sessionUUID string) ([]MeteringEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]MeteringEvent, 0)
	for _, e := range m.metering {
		if sessionUUID != "" && e.SessionUUID != sessionUUID {
			continue
		}
		out = append(out, cloneMetering(e))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].EventID < out[j].EventID
		}
		return out[i].OccurredAt.Before(out[j].OccurredAt)
	})
	return out, nil
}

// --- principals ---

func (m *Memory) CreatePrincipal(ctx context.Context, p Principal) (Principal, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, err
	}
	if p.ID == "" {
		return Principal{}, wrap(ErrInvalid, "principal id is required")
	}
	if p.IdPSubject == "" || p.Org == "" {
		return Principal{}, wrap(ErrInvalid, "principal requires an idp_subject and org")
	}
	if err := validateRoles(p.Roles); err != nil {
		return Principal{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if existing, ok := m.principals[p.ID]; ok {
		// Idempotent on ID: an identical re-create returns the existing row; a
		// differing one under the same ID is a real collision.
		if existing.IdPSubject == p.IdPSubject && existing.Org == p.Org && rolesEqual(existing.Roles, p.Roles) {
			return clonePrincipal(*existing), nil
		}
		return Principal{}, wrap(ErrConflict, "principal %s already exists with a different record", p.ID)
	}
	// UNIQUE(idp_subject, org): the same human in the same org is one principal.
	for _, ex := range m.principals {
		if ex.IdPSubject == p.IdPSubject && ex.Org == p.Org {
			return Principal{}, wrap(ErrConflict, "principal for idp_subject %q in org %q already exists", p.IdPSubject, p.Org)
		}
	}

	now := m.now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	stored := clonePrincipal(p)
	m.principals[p.ID] = &stored
	return clonePrincipal(stored), nil
}

func (m *Memory) GetPrincipal(ctx context.Context, id string) (Principal, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.principals[id]
	if !ok {
		return Principal{}, wrap(ErrNotFound, "principal %s", id)
	}
	return clonePrincipal(*p), nil
}

func (m *Memory) GetPrincipalByIdP(ctx context.Context, idpSubject, org string) (Principal, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.principals {
		if p.IdPSubject == idpSubject && p.Org == org {
			return clonePrincipal(*p), nil
		}
	}
	return Principal{}, wrap(ErrNotFound, "principal for idp_subject %q in org %q", idpSubject, org)
}

func (m *Memory) SetPrincipalRoles(ctx context.Context, id string, roles []PrincipalRole) (Principal, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, err
	}
	if err := validateRoles(roles); err != nil {
		return Principal{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.principals[id]
	if !ok {
		return Principal{}, wrap(ErrNotFound, "principal %s", id)
	}
	p.Roles = cloneRoles(roles)
	p.UpdatedAt = m.now()
	return clonePrincipal(*p), nil
}

// --- session → launching_principal linkage ---

func (m *Memory) SetSessionLaunchingPrincipal(ctx context.Context, sessionUUID, principalID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sessionUUID]; !ok {
		return wrap(ErrNotFound, "session %s", sessionUUID)
	}
	if principalID == "" {
		delete(m.launchingPrincipal, sessionUUID) // clear the nullable link
		return nil
	}
	if _, ok := m.principals[principalID]; !ok {
		return wrap(ErrInvalid, "launching principal %s does not exist", principalID)
	}
	m.launchingPrincipal[sessionUUID] = principalID
	return nil
}

func (m *Memory) GetSessionLaunchingPrincipal(ctx context.Context, sessionUUID string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sessionUUID]; !ok {
		return "", wrap(ErrNotFound, "session %s", sessionUUID)
	}
	return m.launchingPrincipal[sessionUUID], nil // "" = nullable / no link
}

// --- internal helpers ---

func (m *Memory) indexBurned(hostID string, idx uint64) bool {
	set, ok := m.burnedIdx[hostID]
	if !ok {
		return false
	}
	_, burned := set[idx]
	return burned
}

func (m *Memory) burnIndex(hostID string, idx uint64) {
	set, ok := m.burnedIdx[hostID]
	if !ok {
		set = make(map[uint64]struct{})
		m.burnedIdx[hostID] = set
	}
	set[idx] = struct{}{}
}
