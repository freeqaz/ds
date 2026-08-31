package store

import "time"

// This file carries the persisted record SHAPES the Repository fronts (doc 15
// §5.6). The lifecycle-state vocabulary itself is NOT declared here — it lives
// in types.go as the frozen §3 SessionState set, and the vocabpin package
// (internal/store/vocabpin) pins it, token-for-token, against the
// internal/sessions §3 transition table so drift
// fails the build. These structs join that vocabulary to the rest of the
// record (the SessionRef quartet, index history, policy posture, attach state).

// SuspendReason is the doc 15 §3 / §5.1 SUSPENDED(reason) taxonomy (D35 state,
// D77 narrowing: policy_breach is genuine-threat classes only). It is meaningful
// only while a record is in SessionSuspended.
type SuspendReason string

const (
	SuspendReasonNone         SuspendReason = ""
	SuspendReasonUser         SuspendReason = "user"
	SuspendReasonPolicyBreach SuspendReason = "policy_breach"
	SuspendReasonRebalance    SuspendReason = "rebalance"
)

// Valid reports whether r is empty (not suspended) or one of the three frozen
// reason classes.
func (r SuspendReason) Valid() bool {
	switch r {
	case SuspendReasonNone, SuspendReasonUser, SuspendReasonPolicyBreach, SuspendReasonRebalance:
		return true
	default:
		return false
	}
}

// AttachRole is the D61 one-writer/N-reader seat class recorded on the session
// record (the writer seat lives in the record; D61 driver handoff is a record
// mutation with attribution — doc 15 §5.4).
type AttachRole string

const (
	RoleNone   AttachRole = ""
	RoleWriter AttachRole = "WRITER"
	RoleReader AttachRole = "READER"
)

// IPFamily tags the family-agnostic guest IP bytes (D75: never fixed32).
type IPFamily string

const (
	IPFamilyUnspecified IPFamily = ""
	IPFamilyV4          IPFamily = "v4"
	IPFamilyV6          IPFamily = "v6"
)

// SessionRef is the Stage-0-frozen quartet (D66/D44) — the authoritative
// index→UUID join key that LOG-2 attribution, metering, the console hierarchy
// and fleet routing all join through. host_session_index is allocated from a
// persistent monotonic per-host counter and is BURNED, NEVER RECYCLED within
// the flow-log retention window (doc 15 §5.6).
type SessionRef struct {
	SessionUUID      string // continuity key across migration/park
	HostID           string // host-scoped; changes on migration
	HostSessionIndex uint64 // never recycled; host-scoped; changes on migration
	TapName          string // dstap-<idx>, ≤15 chars IFNAMSIZ (D66)
}

// IndexEpoch is one row of the per-host index history (doc 15 §5.6): migration
// and park re-placement give a session a new host index/tap on the target, and
// flow-log joins are per-host-epoch, so the record keeps every binding it held.
type IndexEpoch struct {
	HostID           string
	HostSessionIndex uint64
	TapName          string
	GuestIP          []byte // family-agnostic bytes (D75)
	GuestIPFamily    IPFamily
	// OverlayPath is the per-session qcow2 CoW overlay the host cloned for this
	// binding (D29 — the delta store + durability unit, doc 15 §4.1 step 4/7). It is
	// recorded on the epoch ALONGSIDE the index/tap/guest-IP so the §4.2 teardown can
	// dispose the REAL overlay after a control-plane RESTART: the in-memory create-time
	// HostAllocation.OverlayPath does not survive a restart, so a destroy that resolves
	// its host-side state from the PERSISTED record (storeDestroyStateLookup →
	// destroyRequestFromRecord) must read the overlay from the durable epoch — otherwise
	// it drives DestroyRequest.OverlayPath="" and leaks the CoW overlay (the M0 gap this
	// closes). It is empty for a binding recorded before the overlay clone (§4.1 step 7);
	// a migrated/parked re-placement records a fresh overlay on its new epoch, so the
	// open (current) epoch always carries the live overlay to dispose.
	OverlayPath string
	StartedAt   time.Time
	EndedAt     *time.Time // nil = current epoch
}

// Grant is one live entry of the session's grant list as projected onto the
// record for D72 sweep visibility. The authoritative ask-grant row lives in
// policy_log under the single seq namespace (doc 15 §4.3); this is the resolved
// live view the create choreography and reconciler read.
type Grant struct {
	Seq       int64     // the policy_log seq this grant rides (single namespace, D36)
	Actor     string    // recorded on every grant (D36)
	Rule      string    // the allow target / matched rule
	ExpiresAt time.Time // ask-grants are TTL'd, session-scoped, die with the session
}

// Session is the doc 15 §5.6 session record — the authoritative control-plane
// row. Retained, never deleted within the flow-log retention window (D66);
// DestroySession finalizes timestamps but keeps the row.
type Session struct {
	Ref SessionRef // the Stage-0 quartet

	// Environment & image (D7/D74).
	EnvConfigRef string // reference into env_configs (RecordEnvConfig, §9)
	ImageID      string // resolved content-addressed (repo, ref, spec-hash) → image ID

	// Identity / CA / digest references (D22/D17/D73). Opaque here — mechanics
	// live in doc 16; this record only joins them.
	IdentityRef string
	CARef       string
	DigestRef   string
	DigestAcked bool // §4.1 step 6 gate: routability blocks until this lands

	// Policy posture (D72 sweep visibility). The host applied_seq the create
	// choreography placed against, plus the resolved live grant list.
	PolicyAppliedSeq int64
	Grants           []Grant

	// Attach / writer-seat / attendedness state (D18/D78). WriterSeat names the
	// holder of the one writer seat (D61); Attended is the §5.5 computed signal
	// (M0/M1 interim: writer-attached-only).
	WriterSeat  string
	WriterRole  AttachRole
	Attended    bool
	AttachState AttachRole // the seat class last issued an attach handle

	// Parent-session link (D18 fan-out, D61 hierarchy). Empty for root sessions.
	ParentSessionUUID string

	// RolePin is the doc 18 §7 pinned-role triple the never-recycled session
	// record carries (D66/D89–D96), persisted by migration 0009. It is the SINGLE
	// sanctioned additive registration onto this frozen-shared struct (the store
	// unfreeze for the PinnedRole persistence task); the type and all its
	// semantics live in session.go. A zero RolePin is the "no pin written yet"
	// pre-create state — the create choreography writes the explicit
	// `default@<current>` triple when it resolves the recorded default (doc 18 §7:
	// "Default is recorded, not null"; the EMPTY triple is the pre-pin state,
	// never the recorded-default state).
	RolePin RolePin

	// MintExpiry is the doc 15 §5.6 / doc 16 §5.4 minted-credential / interception-CA
	// EXPIRY horizon the never-recycled session record carries (D22/D82), persisted by
	// migration 0010 (the second sanctioned additive registration onto this
	// frozen-shared struct, after RolePin — the store unfreeze for the credential-TTL
	// persistence task). The type-and-zero-value semantics live in session.go alongside
	// the RolePin discipline. A ZERO MintExpiry (MintExpiry.IsZero()) is the "no TTL
	// tracked" not-set posture — the create choreography writes the resolved horizon
	// from the §4.1 step-5 MintResult.Expiry only when the mint surfaced one; the §4.2
	// teardown/resume re-mint path reads this PERSISTED horizon (doc 16 §5.4: an expired
	// credential re-mints on resume) rather than reconstructing it from create-local
	// state. Persisted as a nullable timestamptz: the zero value maps to SQL NULL and
	// back, exactly the way ready_at / attached_at / destroyed_at map their not-set
	// timestamps.
	MintExpiry time.Time

	// Lifecycle (D57 metering derives from these transitions).
	State         SessionState
	SuspendReason SuspendReason // meaningful only while State == SessionSuspended

	CreatedAt   time.Time
	ReadyAt     *time.Time
	AttachedAt  *time.Time
	DestroyedAt *time.Time // teardown finalization (§4.2 step 6); row retained
	UpdatedAt   time.Time

	// Per-host index history (migration/park re-placement, §5.6). The current
	// epoch mirrors Ref; prior epochs record released bindings.
	IndexHistory []IndexEpoch
}

// PolicyKind tags a policy_log row. The bigserial seq is THE single policy
// version namespace (D36) regardless of kind.
type PolicyKind string

const (
	// PolicyKindAppend is an ordinary composed-policy append (AppendPolicy).
	PolicyKindAppend PolicyKind = "append"
	// PolicyKindAskGrant is a session-scoped TTL'd ask-grant (ApproveAsk, §4.3).
	// Ask-grants are policy artifacts under the same seq, swept derived state.
	PolicyKindAskGrant PolicyKind = "ask_grant"
)

// PolicyLogRow is one append-only policy_log entry (D36 — the log IS the audit
// trail). Seq is assigned by the store (bigserial), monotonically increasing,
// and is the single policy version namespace end to end. Actor is recorded on
// EVERY row.
type PolicyLogRow struct {
	Seq         int64 // store-assigned; monotonically increasing; never reused
	Kind        PolicyKind
	Actor       string // recorded on every row (D36)
	ContentHash string // snapshot identity component (seq, content_hash, composed policy)
	Payload     []byte // composed policy document, or the grant body for ask-grants

	// Ask-grant fields (set only for PolicyKindAskGrant rows). Session-scoped,
	// TTL'd; the grant dies with the session (§4.3).
	SessionUUID string
	ExpiresAt   *time.Time

	CreatedAt time.Time
}

// EnvConfig is the RecordEnvConfig reference shape (doc 15 §9). Only the
// reference shape is owned here; the env-spec document format itself is UNOWNED
// (doc 15 OQ10). The coupled invariants are recorded so the CC-pin ↔ pack
// exclusion coupling cannot silently split (D74/D49).
type EnvConfig struct {
	Ref           string // stable handle returned to RecordEnvConfig callers
	RepoRef       string // repo ref + hash, or empty when InlineSpec is used
	SpecHash      string // env-spec hash
	InlineSpec    []byte // inline spec body when not repo-referenced
	ImageID       string // resolved content-addressed image ID
	CoupledPin    string // CC pin (≥ 2.1.116, D74) recorded with the image
	PackVersion   string // session-pack version (D74)
	PackExclusion string // the downloads.claude.ai excluded-from-pack invariant (D49)
	CreatedAt     time.Time
}

// Plan is a plan-store row (planstore.v1 is M2; the table is reserved so the
// schema is complete from M0 — doc 15 §5.6).
type Plan struct {
	ID          string
	SessionUUID string // owning session, when scoped
	Title       string
	Body        []byte
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// MeteringEvent is one row of the D57 idempotent event stream (wired from M0).
// Billing derives from session-record state transitions: active states accrue
// per second; SUSPENDED/PARKED ≈ free; socket-hold counts active. EventID is
// the idempotency key — re-emitting the same EventID is a no-op.
type MeteringEvent struct {
	EventID     string // idempotency key (D57: idempotent event stream)
	SessionUUID string
	Kind        string       // e.g. "state_transition", "sample"
	State       SessionState // the state the session entered, for transition events
	OccurredAt  time.Time
	Payload     []byte // e.g. the D37 RSS/CPU/IO sample, opaque here
}
