// SPDX-License-Identifier: Apache-2.0

// The per-session grant-fetch protocol (doc 16 §5.1, §5.4, §9; D39/D76).
//
// The ds-tlsproxy SWAP EXECUTOR fetches grants from this service PER-SESSION,
// never per-request (§9 — steady-state requests pay zero added RTT), and caches
// them ≤ session lifetime (§5.1, the bounded D76 in-memory exposure). The
// load-bearing availability property (§5.1): a store outage stalls NEW grant
// fetches only — an in-flight session whose grant is already cached rides its
// cache and never consults the backend again.
//
// Lifecycle (§5.4): grants EVICT on the suspend signal; they SURVIVE park/resume
// and are RE-VALIDATED against session liveness + TTL on resume (an expired
// cached grant is dropped so the caller re-mints).
//
// All in-memory, synthetic (D50). The wire seam to the swap executor freezes
// with the M1 credential-swap design (§9); this is the OSS substrate behind it.
package grantservice

import (
	"errors"
	"sync"
	"time"

	// attachv1 is consumed READ-ONLY for the §5.4 SUSPENDED(reason) cause (D35/D77):
	// the frozen attach.v1 SuspendReason enum classifies WHY a session was suspended.
	// Projection only — no re-declare, no new enum (D80: proto/gen/go is the ONE legal
	// cross-tree import; grant-service already takes that dep for the GrantFetch types).
	attachv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/attach/v1"
)

// errParkedSession is returned by Fetch when a session is parked: a parked
// session does not fetch NEW grants (it rides what it cached pre-park) — a new
// fetch resumes only after Resume re-validates liveness.
var errParkedSession = errors.New("grantservice: session parked; resume before new fetch")

// ErrSessionNotLive is returned when a fetch is attempted for a suspended or
// unknown session — fail-closed: no live session ⇒ no grant fetch.
var ErrSessionNotLive = errors.New("grantservice: session not live")

// ErrGrantRefMismatch is returned by Fetch when the presented grant_ref is not
// the contract handle for the (session, service) being fetched — the READER-side
// fail-closed of the §9 GrantRef contract. A grant_ref the mint side WROTE with
// FormatGrantRef parses back to exactly its session×service; anything else
// (malformed, or for a different binding) is a definitive non-match, never a
// silently-wrong store lookup.
var ErrGrantRefMismatch = errors.New("grantservice: grant_ref does not match session/service binding")

// ErrResumeApprovalRequired is returned by the plain Resume path for a session
// whose recorded last-suspend reason is SUSPEND_REASON_POLICY_BREACH (§8.2; D35):
// a genuine-threat (BIC) suspension's resume authority is HUMAN APPROVAL, not the
// plain resume path. The caller must route through ResumeWithApproval carrying an
// explicit approval attestation. USER/REBALANCE/no-recorded-reason suspensions
// resume on the plain path UNCHANGED — the split is POLICY_BREACH-only.
var ErrResumeApprovalRequired = errors.New("grantservice: resume of a policy-breach-suspended session requires human approval (§8.2, D35)")

// ResumeApproval is a NON-SECRET human-approval attestation (doc 16 §5.2) that
// authorizes resuming a session whose recorded last-suspend reason is a
// genuine-threat SUSPEND_REASON_POLICY_BREACH (§8.2; D35). It is a CLASSIFICATION
// MARKER, never a credential: it carries WHO approved plus an audit reference, and
// never secret material. The zero value is "no attestation" — it does NOT
// authorize a POLICY_BREACH resume (the fail-closed default the plain Resume path
// enforces).
type ResumeApproval struct {
	// Approver identifies the human authority that approved the resume (a principal
	// id / handle) — non-secret, for the audit trail (D36).
	Approver string
	// Reference is a free-form NON-SECRET audit reference for the approval (e.g. a
	// ticket or ask-grant id); optional.
	Reference string
}

// IsPresent reports whether the attestation carries an actual approving authority
// — the gate the POLICY_BREACH resume path checks. A zero-value attestation (no
// Approver) is ABSENT and does not authorize a genuine-threat resume.
func (a ResumeApproval) IsPresent() bool { return a.Approver != "" }

// cachedGrant is one session-cached grant: the real credential plus the grant's
// TTL, so resume re-validation (§5.4) can drop an expired entry without a
// backend round-trip.
type cachedGrant struct {
	cred   Credential
	expiry time.Time // the grant TTL; cache lifetime ≤ session
}

// sessionState tracks a session's liveness for the §5.4 lifecycle. A session is
// LIVE (fetches and serves), PARKED (rides cache, no new fetches until resume),
// or evicted entirely (suspend drops the whole entry).
type sessionLiveness int

const (
	live sessionLiveness = iota
	parked
)

// sessionCache holds one session's grants and its liveness bit. The cache is the
// D76 in-memory hold: fetched credentials live here for at most the session.
type sessionCache struct {
	state    sessionLiveness
	grants   map[string]cachedGrant // service_id -> cached grant
	deadline time.Time              // session lifetime; the cache ceiling (≤ session)
}

// Service is the per-session grant-fetch front for the swap executor. It owns
// the session caches and the D39 backend behind them.
type Service struct {
	now     func() time.Time
	backend Backend

	mu       sync.Mutex
	sessions map[string]*sessionCache
	// lastSuspend records the frozen attach.v1 SUSPENDED(reason) cause of the MOST
	// RECENT suspend of a session (§5.4; D35/D77). It is keyed by session_uuid and
	// SURVIVES the eviction (unlike the session cache entry, which Suspend drops), so
	// the cause a session was evicted for stays read-back-able via LastSuspendReason
	// after the grants are gone — the §8.2 resume-authority split reads it. The value
	// is a NON-SECRET classification (doc 16 §5.2), never credential material.
	lastSuspend map[string]attachv1.SuspendReason
}

// Option configures a Service.
type Option func(*Service)

// WithClock pins the service clock (tests use this for TTL/expiry determinism).
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

// New builds a grant service over the given D39 backend (the local file/KV fake
// at the OSS tier).
func New(backend Backend, opts ...Option) *Service {
	s := &Service{
		now:         time.Now,
		backend:     backend,
		sessions:    make(map[string]*sessionCache),
		lastSuspend: make(map[string]attachv1.SuspendReason),
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// RegisterSession admits a session for grant fetching, with a session-lifetime
// deadline that bounds the cache (≤ session, §5.1). Called when the mint
// sub-sequence (§6.1) hands the session's grant set to the swap path. A session
// must be registered before any Fetch (fail-closed: unknown ⇒ not live).
func (s *Service) RegisterSession(sessionUUID string, deadline time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionUUID] = &sessionCache{
		state:    live,
		grants:   make(map[string]cachedGrant),
		deadline: deadline,
	}
}

// Fetch is the STRING-keyed per-session grant-fetch protocol (§9). It returns
// the real credential for (sessionUUID, serviceID, grantRef), fetching from the
// D39 backend on a cache MISS and serving from the session cache on a HIT. The
// grant's TTL bounds the cached entry.
//
// The §5.1 availability semantics are enforced by the shared fetchForRecord core
// below:
//   - CACHE HIT: served from memory, the backend is NOT consulted — so an
//     in-flight session rides its cache through a store outage.
//   - CACHE MISS + store DOWN: ErrStoreUnavailable propagates — a NEW fetch
//     stalls, exactly and only NEW fetches.
//
// Fail-closed: an unknown/suspended session is ErrSessionNotLive; a parked
// session refuses NEW fetches (errParkedSession) but its already-cached grants
// still serve.
//
// Fetch is a thin behavior-preserving ADAPTER over the record-keyed core: it
// wraps the presented (grantRef, serviceID) in a frozen grant RECORD and hands
// it to fetchForRecord, so the string path and the FetchForRecord record path
// resolve to the IDENTICAL Backend.Fetch call (keyed on the record's grant_ref).
// The record it builds carries a reference, never secret material (D8/D39).
func (s *Service) Fetch(sessionUUID, serviceID, grantRef string, grantExpiry time.Time) (Credential, error) {
	return s.fetchForRecord(sessionUUID, serviceID, &GrantRecord{GrantRef: grantRef, ServiceId: serviceID}, grantExpiry)
}

// FetchForRecord is the RECORD-keyed per-session grant-fetch entry point: the
// caller holds a frozen dreamserpent.identity.v1.Grant (grantref.go's
// GrantRecord) and fetches its real credential without re-deriving the store
// key. It keys the backend lookup on the record's own grant_ref
// (grantRecordRef) and the session cache on the record's own service_id — the
// grant model speaks the frozen contract end to end, not just the raw string.
//
// It resolves to the IDENTICAL Backend.Fetch call as the string-keyed Fetch (a
// record built {GrantRef, ServiceId} drives the same core). The reader-side
// fail-closed guard is expressed against the record (grantRecordMatches): a
// mis-bound record — one whose grant_ref does not parse back to
// (sessionUUID, record.ServiceId) — is a definitive non-match
// (ErrGrantRefMismatch), never a silently-wrong store lookup. A nil record keys
// the empty grant_ref/service, which fails closed through the same guard.
func (s *Service) FetchForRecord(sessionUUID string, rec *GrantRecord, grantExpiry time.Time) (Credential, error) {
	return s.fetchForRecord(sessionUUID, rec.GetServiceId(), rec, grantExpiry)
}

// fetchForRecord is the shared record-keyed fetch core both Fetch and
// FetchForRecord resolve to. It keys the D39 backend lookup on the held record's
// grant_ref (grantRecordRef) and the session cache on serviceID, enforcing the
// §5.1 availability semantics and the §5.4 lifecycle exactly as before — the
// only change from the prior string-keyed body is that the store key and the
// reader-side guard are now expressed against the frozen grant RECORD.
func (s *Service) fetchForRecord(sessionUUID, serviceID string, rec *GrantRecord, grantExpiry time.Time) (Credential, error) {
	now := s.now()

	// GrantRef contract guard (the READER side of the §9 seam), record-typed: the
	// record's grant_ref MUST be the contract handle for exactly this
	// (session, service) binding. The mint side WROTE it with FormatGrantRef;
	// ParseGrantRef (inside grantRecordMatches) is its vendored inverse. A record
	// whose grant_ref does not parse to this session×service — malformed, drifted,
	// or MIS-BOUND (grant_ref and service_id disagreeing) — is a definitive
	// non-match (fail-closed) → ErrGrantRefMismatch, never a silently-wrong store
	// lookup. The golden round-trip test pins the format so drift is caught at test
	// time before it ever reaches here.
	if !grantRecordMatches(rec, sessionUUID, serviceID) {
		return Credential{}, ErrGrantRefMismatch
	}

	// The D39 store key is the record's OWN grant_ref — the single value both the
	// string path and the record path resolve to for Backend.Fetch.
	grantRef := grantRecordRef(rec)

	s.mu.Lock()
	sess := s.sessions[sessionUUID]
	if sess == nil {
		s.mu.Unlock()
		return Credential{}, ErrSessionNotLive
	}
	// Session-lifetime ceiling: a session past its deadline holds no live cache.
	if !sess.deadline.IsZero() && !now.Before(sess.deadline) {
		s.mu.Unlock()
		return Credential{}, ErrSessionNotLive
	}
	// CACHE HIT: serve from memory, never touching the backend. This is what lets
	// an in-flight session ride a store outage (§5.1). An expired cached grant is
	// treated as a miss (TTL re-validation).
	if cg, ok := sess.grants[serviceID]; ok {
		if cg.expiry.IsZero() || now.Before(cg.expiry) {
			cred := cloneCred(cg.cred)
			s.mu.Unlock()
			return cred, nil
		}
		// Expired: drop it and fall through to a fresh fetch.
		delete(sess.grants, serviceID)
	}
	// CACHE MISS. A parked session does not fetch NEW grants — it may only ride
	// what it cached before park (handled by the hit path above).
	if sess.state == parked {
		s.mu.Unlock()
		return Credential{}, errParkedSession
	}
	s.mu.Unlock()

	// Per-session fetch from the D39 backend (NEVER per-request: the caller calls
	// Fetch once per session×service and rides the cache afterwards). A store
	// outage here stalls THIS new fetch only.
	cred, err := s.backend.Fetch(grantRef)
	if err != nil {
		return Credential{}, err
	}

	// Cache the result, bounded by the grant TTL and the session deadline.
	expiry := grantExpiry
	if !sess.deadline.IsZero() && (expiry.IsZero() || expiry.After(sess.deadline)) {
		expiry = sess.deadline
	}
	s.mu.Lock()
	// Re-read: the session may have been suspended during the backend round-trip.
	sess = s.sessions[sessionUUID]
	if sess == nil {
		s.mu.Unlock()
		return Credential{}, ErrSessionNotLive
	}
	sess.grants[serviceID] = cachedGrant{cred: cred, expiry: expiry}
	out := cloneCred(cred)
	s.mu.Unlock()
	return out, nil
}

// SuspendWithReason EVICTS a session's grants on the suspend signal (§5.4) AND
// RECORDS the frozen attach.v1 SUSPENDED(reason) cause (D35/D77) that drove the
// eviction, so WHY the session was evicted (USER offboarding vs POLICY_BREACH
// genuine-threat vs REBALANCE) is read-back-able via LastSuspendReason after the
// grants are gone. EVICTION BEHAVIOR IS UNCHANGED — the whole cache entry is
// dropped exactly as before, so a subsequent fetch fails closed (ErrSessionNotLive)
// until the session is re-registered; only the CAUSE is now recorded. This is the
// active-eviction half of "TTL-as-revocation plus active eviction" (§5.4). The
// recorded reason is a NON-SECRET classification (doc 16 §5.2), never credential
// material. The reason is projected READ-ONLY from the frozen enum (D80: proto/gen/go
// the only cross-tree import) — no re-declare, no new enum.
func (s *Service) SuspendWithReason(sessionUUID string, reason attachv1.SuspendReason) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionUUID)
	s.lastSuspend[sessionUUID] = reason
}

// Suspend EVICTS a session's grants on the suspend signal (§5.4): the whole
// cache entry is dropped, so a subsequent fetch fails closed (ErrSessionNotLive)
// until the session is re-registered. This is the active-eviction half of
// "TTL-as-revocation plus active eviction" (§5.4).
//
// Suspend is the USER-reason SHIM over SuspendWithReason: an unqualified suspend
// records the offboarding/user-initiated cause (SUSPEND_REASON_USER — §11.2 fires
// the existing suspend signal), so the sessionUUID-only callers keep their exact
// shape while the recorded cause stays truthful. Callers that carry a genuine-threat
// classification (POLICY_BREACH) or a rebalance call SuspendWithReason directly.
func (s *Service) Suspend(sessionUUID string) {
	s.SuspendWithReason(sessionUUID, attachv1.SuspendReason_SUSPEND_REASON_USER)
}

// LastSuspendReason returns the frozen attach.v1 SUSPENDED(reason) cause recorded
// for the most recent Suspend/SuspendWithReason of the session (§5.4; D35/D77),
// read-only, and whether such a record exists (false for a session never
// suspended). The recorded cause SURVIVES the eviction that dropped the session
// cache, so the §8.2 resume-authority split can read WHY a session was suspended
// (USER offboarding resumes differently than a POLICY_BREACH BIC suspension). The
// returned reason is a NON-SECRET classification (doc 16 §5.2), never credential
// material — a pure projection of the frozen enum.
func (s *Service) LastSuspendReason(sessionUUID string) (attachv1.SuspendReason, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.lastSuspend[sessionUUID]
	return r, ok
}

// Park marks a session parked (§5.4): its cached grants SURVIVE (the cache entry
// is kept), but the session fetches no NEW grants until Resume. This is the
// snapshot+park path — distinct from Suspend, which evicts.
func (s *Service) Park(sessionUUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess := s.sessions[sessionUUID]; sess != nil {
		sess.state = parked
	}
}

// Resume re-validates a parked session against session liveness + TTLs (§5.4)
// and returns it to LIVE. Cached grants past their TTL are dropped so the caller
// re-mints (the "expired creds re-mint" half of §5.4). A session whose
// session-lifetime deadline has passed is NOT resumed (fail-closed:
// ErrSessionNotLive) — a dead session does not silently come back.
//
// newDeadline optionally extends the session-lifetime ceiling on resume (a
// resumed session has a fresh lifetime); pass the zero time to keep the existing
// deadline.
//
// §8.2 resume-authority split (D35): a session whose recorded last-suspend reason
// is the genuine-threat SUSPEND_REASON_POLICY_BREACH FAILS CLOSED on this plain
// path (ErrResumeApprovalRequired) — a BIC suspension's resume authority is human
// approval, routed through ResumeWithApproval. USER, REBALANCE, and
// no-recorded-reason suspensions resume on THIS path with their signature AND
// semantics UNCHANGED.
func (s *Service) Resume(sessionUUID string, newDeadline time.Time) error {
	return s.resume(sessionUUID, newDeadline, ResumeApproval{})
}

// ResumeWithApproval is the §8.2 approval-gated resume surface (D35): it resumes a
// session whose recorded last-suspend reason is a genuine-threat POLICY_BREACH
// under an EXPLICIT human-approval attestation, and otherwise behaves EXACTLY like
// Resume. A POLICY_BREACH session resumes here only when approval.IsPresent(); a
// zero-value (absent) attestation fails closed on the POLICY_BREACH path exactly as
// the plain Resume does. USER/REBALANCE/no-recorded-reason paths IGNORE the
// attestation and resume unchanged. The attestation is a NON-SECRET marker (doc 16
// §5.2) — who approved plus an audit reference, never a credential. This is purely
// ADDITIVE: Resume(sessionUUID, newDeadline)'s signature and its semantics for every
// non-POLICY_BREACH path are intact.
func (s *Service) ResumeWithApproval(sessionUUID string, newDeadline time.Time, approval ResumeApproval) error {
	return s.resume(sessionUUID, newDeadline, approval)
}

// resume is the shared resume core both Resume (no attestation) and
// ResumeWithApproval resolve to. It applies the §8.2 authority split first — a
// POLICY_BREACH-recorded session without a present approval attestation fails closed
// (ErrResumeApprovalRequired) — then runs the EXISTING liveness + TTL re-validation
// unchanged. The authority gate reads only the read-back-able lastSuspend record
// (which SURVIVES the suspend eviction), so it fires whether the session was
// re-registered or is simply gone; a present attestation (or a non-POLICY_BREACH /
// no-recorded-reason cause) skips the gate and falls through to the pre-existing body.
func (s *Service) resume(sessionUUID string, newDeadline time.Time, approval ResumeApproval) error {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// §8.2 resume-authority split (D35): a session whose recorded last-suspend reason
	// is the genuine-threat POLICY_BREACH may be resumed ONLY under an explicit
	// human-approval attestation — the plain path fails closed. USER, REBALANCE, and
	// no-recorded-reason suspensions are unaffected and resume exactly as before. The
	// attestation is a NON-SECRET marker (doc 16 §5.2), never credential material. The
	// record is left in place (last-write-wins, unpruned, §5.4) so the audit cause
	// stays read-back-able; a subsequent USER/REBALANCE suspend overwrites it.
	if r, ok := s.lastSuspend[sessionUUID]; ok &&
		r == attachv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH && !approval.IsPresent() {
		return ErrResumeApprovalRequired
	}
	sess := s.sessions[sessionUUID]
	if sess == nil {
		return ErrSessionNotLive
	}
	if !newDeadline.IsZero() {
		sess.deadline = newDeadline
	}
	// Liveness re-validation: a session past its (post-resume) deadline is dead.
	if !sess.deadline.IsZero() && !now.Before(sess.deadline) {
		delete(s.sessions, sessionUUID)
		return ErrSessionNotLive
	}
	// TTL re-validation: drop any cached grant past its own TTL (expired creds
	// re-mint, §5.4).
	for svc, cg := range sess.grants {
		if !cg.expiry.IsZero() && !now.Before(cg.expiry) {
			delete(sess.grants, svc)
		}
	}
	sess.state = live
	return nil
}

// CachedServices reports the service_ids a session currently holds in cache —
// read-only, for tests/observability. Order is not guaranteed.
func (s *Service) CachedServices(sessionUUID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess := s.sessions[sessionUUID]
	if sess == nil {
		return nil
	}
	out := make([]string, 0, len(sess.grants))
	for svc := range sess.grants {
		out = append(out, svc)
	}
	return out
}

// cloneCred returns a defensive copy so a caller can never mutate a cached
// secret in place.
func cloneCred(c Credential) Credential {
	return Credential{Secret: append([]byte(nil), c.Secret...), Location: c.Location}
}
