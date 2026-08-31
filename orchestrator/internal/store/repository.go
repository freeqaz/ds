package store

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors. Callers branch on these (errors.Is) rather than on a
// concrete implementation's error strings, so the in-memory and Postgres impls
// are interchangeable behind the interface (D33).
var (
	// ErrNotFound is returned when a lookup misses.
	ErrNotFound = errors.New("store: not found")

	// ErrConflict is returned for uniqueness / idempotency-key collisions whose
	// payload differs from the existing row (e.g. re-creating a session UUID with
	// a different SessionRef, or a metering EventID re-emitted with a different
	// body). Re-issuing an identical write is NOT a conflict — every create verb
	// is idempotent on session_uuid (doc 15 §4.1).
	ErrConflict = errors.New("store: conflict")

	// ErrInvalid is returned when an argument violates a frozen invariant (an
	// unknown SessionState, a policy_breach suspend with no reason, an attempt to
	// recycle a burned host_session_index, etc.).
	ErrInvalid = errors.New("store: invalid argument")

	// ErrUnavailable signals the degraded mode of doc 15 §3: Postgres is down, so
	// new creates/asks/grants/suspend-acks must STALL cleanly. The store surfaces
	// unavailability rather than buffering writes that fake durability — callers
	// stall, the store never fakes durability.
	ErrUnavailable = errors.New("store: unavailable")
)

// SessionUpdate is the partial-update payload for UpdateSession. Only non-nil
// fields are applied, so the create/destroy choreographies can advance one
// facet at a time (policy posture, then digest ack, then the gated READY flip)
// without read-modify-write races in the caller. The store applies all set
// fields atomically and stamps UpdatedAt.
type SessionUpdate struct {
	State         *SessionState
	SuspendReason *SuspendReason

	EnvConfigRef *string
	ImageID      *string

	IdentityRef *string
	CARef       *string
	DigestRef   *string
	DigestAcked *bool

	PolicyAppliedSeq *int64
	Grants           *[]Grant // replaces the live grant list (resolved sweep view)

	WriterSeat  *string
	WriterRole  *AttachRole
	Attended    *bool
	AttachState *AttachRole

	// RolePin sets the doc 18 §7 pinned-role triple (migration 0009). Non-nil
	// replaces the whole pin atomically (the triple is immutable per session, so
	// it is written once by the create choreography — never partially mutated).
	// Nil leaves the persisted pin unchanged.
	RolePin *RolePin

	// MintExpiry sets the doc 15 §5.6 / doc 16 §5.4 minted-credential / CA EXPIRY
	// horizon (migration 0010). NIL leaves the persisted horizon unchanged (the
	// leave-alone case — e.g. a posture update that does not touch the mint); a NON-NIL
	// pointer SETS the horizon to the value it carries, INCLUDING the zero time, which
	// persists as SQL NULL (the "no TTL tracked" not-set posture). It is a plain
	// *time.Time rather than an *OptTime because the horizon is never CLEARED in place —
	// it is written from the §4.1 step-5 MintResult.Expiry alongside IdentityRef/CARef
	// and re-written from the §4.2 re-mint, both of which set the current horizon (a
	// re-mint with no TTL sets the zero/NULL not-set posture, never a separate "clear").
	MintExpiry *time.Time

	ReadyAt     *OptTime
	AttachedAt  *OptTime
	DestroyedAt *OptTime
}

// OptTime lets a SessionUpdate distinguish "leave this timestamp alone" (the
// outer *OptTime is nil) from "set or clear it" (the outer pointer is non-nil,
// carrying a value to set or an explicit nil V to clear). Use SetTime/ClearTime
// to construct one.
type OptTime struct{ V *time.Time }

// SetTime returns an *OptTime that sets the timestamp to t.
func SetTime(t time.Time) *OptTime { return &OptTime{V: &t} }

// ClearTime returns an *OptTime that clears the timestamp (sets it to nil).
func ClearTime() *OptTime { return &OptTime{V: nil} }

// Repository is the replaceable persistence seam over the control plane's
// external Postgres (D6/D33). The in-memory and database/sql implementations
// satisfy it identically; the shared conformance suite (conformance_test.go)
// pins that equivalence. Every method takes a context so the Postgres impl can
// honor cancellation/timeouts and surface ErrUnavailable on connection loss.
type Repository interface {
	// --- sessions (the §5.6 record) ---

	// CreateSession writes a new session record (§4.1 step 2). It is idempotent
	// on Ref.SessionUUID: re-creating with an identical Ref+initial fields returns
	// the existing row; re-creating with a CONFLICTING Ref returns ErrConflict.
	// host_session_index is burned-never-recycled: reusing an index already seen
	// on its host (current or historical) returns ErrInvalid.
	CreateSession(ctx context.Context, s Session) (Session, error)

	// GetSession returns the record by session UUID, or ErrNotFound.
	GetSession(ctx context.Context, sessionUUID string) (Session, error)

	// UpdateSession applies the set fields of u atomically and returns the
	// updated record. The create choreography uses it for the policy-posture
	// update, the digest-ack gate flip, and the gated READY transition; destroy
	// uses it for the teardown timestamps. ErrNotFound if the session is unknown;
	// ErrInvalid for an unknown state or an inconsistent suspend reason.
	UpdateSession(ctx context.Context, sessionUUID string, u SessionUpdate) (Session, error)

	// AppendIndexEpoch closes the current index epoch and opens a new one on the
	// target host (migration / park re-placement, §5.6). It updates Ref to the
	// new binding and appends the prior binding to IndexHistory. The new index is
	// burned-never-recycled on the target host too. ErrNotFound / ErrInvalid.
	AppendIndexEpoch(ctx context.Context, sessionUUID string, e IndexEpoch) (Session, error)

	// ListSessions returns records matching f (zero-value f = all), newest first.
	ListSessions(ctx context.Context, f SessionFilter) ([]Session, error)

	// --- policy_log (append-only, the single seq namespace; D36) ---

	// AppendPolicy appends one row, assigning the next monotonically increasing
	// seq. Actor MUST be non-empty (recorded on every row, D36); empty actor is
	// ErrInvalid. The append is the only mutation policy_log admits — rows are
	// never updated or deleted. Returns the row with its assigned Seq.
	AppendPolicy(ctx context.Context, row PolicyLogRow) (PolicyLogRow, error)

	// ListPolicy returns rows with Seq > fromSeq in ascending seq order, capped
	// at limit (limit <= 0 = no cap). fromSeq = 0 returns from the start; this is
	// the WatchPolicies(from_seq) replay shape.
	ListPolicy(ctx context.Context, fromSeq int64, limit int) ([]PolicyLogRow, error)

	// LiveGrants returns the non-expired ask-grant rows for a session as of now
	// (the resolved live grant view the create choreography and reconciler read).
	LiveGrants(ctx context.Context, sessionUUID string, now time.Time) ([]PolicyLogRow, error)

	// --- env_configs (RecordEnvConfig reference shape; §9) ---

	PutEnvConfig(ctx context.Context, c EnvConfig) (EnvConfig, error)
	GetEnvConfig(ctx context.Context, ref string) (EnvConfig, error)

	// --- plans (reserved, M2) ---

	PutPlan(ctx context.Context, p Plan) (Plan, error)
	GetPlan(ctx context.Context, id string) (Plan, error)
	ListPlans(ctx context.Context, sessionUUID string) ([]Plan, error)

	// --- metering_events (idempotent stream; D57) ---

	// AppendMeteringEvent records one event idempotently on EventID: re-emitting
	// the same EventID with an identical body is a no-op success; a differing body
	// under the same EventID is ErrConflict.
	AppendMeteringEvent(ctx context.Context, e MeteringEvent) error
	ListMeteringEvents(ctx context.Context, sessionUUID string) ([]MeteringEvent, error)

	// --- principals (the human principal record; doc 16 §3.2, D45/D56/D57) ---

	// CreatePrincipal writes a new human-principal record (IdP subject + org +
	// role set). ID is required; (IdPSubject, Org) is the unique business key, so
	// re-creating that pair with a DIFFERENT identity returns ErrConflict (the
	// 0006_principals.sql UNIQUE(idp_subject, org) collision). A role outside the
	// §3.2 vocabulary returns ErrInvalid (the SQL role CHECK mirror). Create is
	// idempotent on ID: re-creating with the same ID and an identical record
	// returns the existing row.
	CreatePrincipal(ctx context.Context, p Principal) (Principal, error)

	// GetPrincipal returns the record by its stable ID, or ErrNotFound.
	GetPrincipal(ctx context.Context, id string) (Principal, error)

	// GetPrincipalByIdP returns the record for an (IdP subject, org) pair — the
	// `launching_user`-claim resolution lookup (doc 16 §3.2/§11.2) — or
	// ErrNotFound. The same subject in a different org is a different principal.
	GetPrincipalByIdP(ctx context.Context, idpSubject, org string) (Principal, error)

	// SetPrincipalRoles replaces a principal's role set atomically and returns the
	// updated record. ErrNotFound if the principal is unknown; ErrInvalid if any
	// role is outside the §3.2 vocabulary. The full seat/viewer taxonomy is
	// deliberately not modeled here (D57/D61); this is the minimal role-set update.
	SetPrincipalRoles(ctx context.Context, id string, roles []PrincipalRole) (Principal, error)

	// --- session → launching_principal linkage (the doc 04 §5 attribution shape) ---

	// SetSessionLaunchingPrincipal links a session to the principal that launched
	// it — the persisted referent of the workload identity's `launching_user`
	// claim (doc 16 §3.1/§3.2). It is the LINKAGE SHAPE ONLY: this method records
	// the reference; the MintWorkloadIdentity side that resolves the claim FROM it
	// is a separate, out-of-scope task. Passing an empty principalID CLEARS the
	// link (the reference is nullable — a pre-mint or system session has none).
	// ErrNotFound if the session is unknown; ErrInvalid if a non-empty principalID
	// names no principal (the soft-FK guard, mirrored by the nullable column's
	// REFERENCES in 0006).
	SetSessionLaunchingPrincipal(ctx context.Context, sessionUUID, principalID string) error

	// GetSessionLaunchingPrincipal returns the linked principal's ID for a
	// session, or "" when the session has no launching principal (the nullable
	// case). ErrNotFound if the session itself is unknown. This is the storage
	// half of the §3.3 agent-inventory join (who launched what); the read-path
	// query that surfaces it through the dashboard is out of scope here.
	GetSessionLaunchingPrincipal(ctx context.Context, sessionUUID string) (string, error)
}

// SessionFilter narrows ListSessions. Zero value matches all.
//
// The host/state/parent/destroyed predicates are pure functions of the record. The
// LaunchingUser, PageToken, and PageSize fields push the §5.3 console read's
// attribution filter + keyset pagination DOWN into the store so the handler issues ONE
// bounded store query per page (instead of enumerating the whole filtered slice and
// resolving launching_user per-row, the N+1-per-page the in-process path did). All
// three are ADDITIVE: a zero value (empty LaunchingUser, unset PageToken, PageSize <= 0)
// reproduces the historical "return ALL matching, newest-first" behavior every other
// caller relies on.
type SessionFilter struct {
	HostID            string       // exact host match
	State             SessionState // exact state match
	ParentSessionUUID string       // children of a given parent
	IncludeDestroyed  bool         // when false, SessionDestroyed records are omitted

	// LaunchingUser narrows to the sessions launched by the principal whose IdP
	// subject (the §3.1 `launching_user` claim VALUE, doc 16 §3.1/§3.2) equals it.
	// Empty = no launching-user filter (fleet-wide). The store resolves each session's
	// launching principal → IdP subject through its own session→principal linkage +
	// principal records and keeps only the EXACT matches: a session with no launching
	// principal, or one whose link dangles to a missing principal, never matches a
	// non-empty filter (the same narrowing ResolveLaunchingUserClaim's match test makes,
	// pushed into this one read so the LIMIT applies to the FILTERED set).
	LaunchingUser string

	// PageToken is the keyset-scan cursor. When set, the scan returns only sessions that
	// sort STRICTLY AFTER it in the stable newest-first order (created_at DESC,
	// session_uuid DESC) — the next page is exactly the records after the previous page's
	// last, so the walk neither duplicates the boundary record nor skips a record tied on
	// created_at. The zero value (Set == false) starts from the newest record.
	PageToken SessionPageCursor

	// PageSize bounds the page (the keyset LIMIT), applied AFTER the stable newest-first
	// order so the page is the newest-first prefix past the cursor. PageSize <= 0 returns
	// ALL matching records (the back-compat single-shot path — pagination is opt-in).
	PageSize int
}

// SessionPageCursor names a position in the stable newest-first session order
// (created_at DESC, session_uuid DESC) for the SessionFilter keyset scan. Set == false
// is the start-from-newest (no cursor) state. CreatedAt carries the FULL precision both
// stores sort on (the in-memory store compares time.Time.After/Equal; the Postgres store
// orders a microsecond timestamptz), so the cursor's comparison key is byte-identical to
// the store sort key and a same-instant pair is ordered by session_uuid exactly as the
// store orders it (never collapsed past the store's sub-second resolution).
type SessionPageCursor struct {
	Set       bool
	CreatedAt time.Time
	UUID      string
}
