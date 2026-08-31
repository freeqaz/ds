// SPDX-License-Identifier: Apache-2.0

// The D22 Validate seam logic (doc 16 §4 / §9 / §11.1 step 3).
//
// Validate is the one frozen contract every substrate satisfies (D22). The M0
// shim's check is: signature (the presented JWT verifies against the session's
// minted workload key) + freshness (within the token's nbf..exp window) +
// SESSION LIVENESS (the record is not revoked/expired) + grant lookup (the
// service_id has a grant). Any failure is a DENY carrying a machine-readable
// reason, surfaced as the D77 in-band structured 403 (block+log default) — never
// a silent drop, never a VM suspension for an ordinary policy question.
//
// The minimal CA ships no CRL/OCSP, so a stolen-but-unexpired credential is
// caught HERE by the liveness check, not by revocation (doc 16 §5.4): once
// RevokeSession flips the record, Validate fails closed immediately.
package mint

import (
	"time"
)

// Machine-readable DENY reasons (the D77 in-band-403 reason codes). Stable
// strings so a consumer routes around or awaits approval deterministically.
const (
	ReasonUnknownSession   = "unknown_session"
	ReasonSessionRevoked   = "session_revoked"
	ReasonSessionExpired   = "session_expired"
	ReasonSignatureInvalid = "signature_invalid"
	ReasonCredentialStale  = "credential_stale" // outside nbf..exp
	ReasonOutOfGrant       = "out_of_grant"     // no grant for service_id
	ReasonMalformed        = "malformed_credential"
	// ReasonScopeInsufficient is the D22 DENY reason when the presented sub-token's
	// D127 scopes (doc 23 §6 `ds_scopes`) do NOT cover a scope the requested
	// operation asserted via ValidateRequest.desired_scopes. It is the second
	// enforcement point of the D127 taxonomy (the first being policy-core's
	// `v1:network:egress` egress gate); the caller maps the operation to its
	// required scope(s) off the §6 table and the validator asserts coverage here.
	ReasonScopeInsufficient = "scope_insufficient"
)

// Verdict mirrors the proto ValidateVerdict without importing it on the native
// path; server.go maps it onto the generated enum.
type Verdict int

const (
	VerdictAllow Verdict = iota
	VerdictDeny
)

// ValidateResult is the native Validate outcome (doc 16 §4 response shape:
// verdict ALLOW | DENY{machine_readable_reason}, grant_ref, expiry).
type ValidateResult struct {
	Verdict               Verdict
	MachineReadableReason string // populated only on DENY (the D77 reason)
	GrantRef              string // populated only on ALLOW
	Expiry                time.Time
}

// deny builds a DENY result carrying the machine-readable reason. Centralizing
// it keeps every failure path fail-closed and shaped identically (D77).
func deny(reason string) ValidateResult {
	return ValidateResult{Verdict: VerdictDeny, MachineReadableReason: reason}
}

// Validate runs the D22 check for one presented credential against a session and
// a target service. presentedCredential is the format-opaque token (the M0 shim
// emits the workload JWT); sessionUUID and serviceID are the swap executor's
// presentation context. Fails CLOSED on every error branch.
//
// This is the scope-UNqualified entry: it asserts signature + freshness +
// liveness + grant only (no D127 scope predicate). It is preserved verbatim so
// every existing caller keeps the frozen semantics; a caller that needs the
// doc 23 §6 scope assertion uses [Shim.ValidateScoped].
func (s *Shim) Validate(presentedCredential []byte, sessionUUID, serviceID string) ValidateResult {
	return s.validate(presentedCredential, sessionUUID, serviceID, nil)
}

// ValidateScoped runs the D22 check AND the D127 scope predicate (doc 23 §6, the
// `Validate`-seam enforcement point): after the signature/freshness/liveness/grant
// checks pass, it asserts the presented sub-token's scopes COVER every scope in
// desiredScopes (the required scope(s) the caller mapped the requested operation
// to off the §6 table). A missing scope is a DENY carrying
// [ReasonScopeInsufficient] — surfaced as the D77 in-band 403 like every other
// verdict. An EMPTY desiredScopes makes no scope assertion (identical to
// [Shim.Validate]); a non-empty desiredScopes against a credential that carries
// no scopes (a workload JWT / placeholder token — neither carries `ds_scopes`)
// fails CLOSED, since an unscoped credential can never cover a demanded scope.
func (s *Shim) ValidateScoped(presentedCredential []byte, sessionUUID, serviceID string, desiredScopes []string) ValidateResult {
	return s.validate(presentedCredential, sessionUUID, serviceID, desiredScopes)
}

// validate is the shared D22 implementation. desiredScopes is the D127 scope
// predicate (nil / empty = no scope assertion, the scope-unqualified path).
func (s *Shim) validate(presentedCredential []byte, sessionUUID, serviceID string, desiredScopes []string) ValidateResult {
	now := s.now()

	// SESSION-TOKEN ROUTING (doc 19 §3/§5): a scoped base token (MintSessionToken)
	// is an Ed25519-signed Biscuit — structurally NOT a workload JWS and NOT an
	// X.509 cert — so it takes its own validation leg and NEVER falls through to
	// the workload-key verification below. This is the load-bearing doc 19 §13
	// negative property: a session token validates only as the scoped credential
	// it is, never as workload identity, never as interception material. The route
	// is keyed on the substrate signer's signature check (IsSessionToken), so a
	// forged/foreign token that is not a valid Biscuit under THIS shim's third
	// context never reaches this leg — it falls to the workload path and fails
	// closed there (malformed/signature_invalid).
	if s.tokenSigner != nil && s.IsSessionToken(presentedCredential) {
		return s.validateSessionToken(presentedCredential, sessionUUID, serviceID, now, desiredScopes)
	}

	// SCOPE FAIL-CLOSED for non-scoped credentials (doc 23 §6): a workload JWT
	// (§3.1) and a per-service placeholder token (§5.1) carry NO D127 `ds_scopes`
	// claim, so they can never COVER a demanded scope. When the caller asserts a
	// non-empty desired-scope set against one of these, deny scope_insufficient
	// rather than silently ignoring the assertion — the enforcement point is
	// fail-closed. An empty desiredScopes leaves these legs unchanged.
	if len(desiredScopes) > 0 {
		return deny(ReasonScopeInsufficient)
	}

	// PLACEHOLDER ROUTING (§5.1): a per-service placeholder token (MintGrants) is
	// structurally NOT a workload JWS, so it takes its own validation leg and
	// NEVER falls through to the workload-key verification below. This is the
	// load-bearing negative property: a placeholder validates only as the grant
	// presentation it is — never as workload identity, never as interception
	// material (it has the wrong shape for both).
	if IsPlaceholder(presentedCredential) {
		return s.validatePlaceholder(presentedCredential, sessionUUID, serviceID, now)
	}

	s.mu.Lock()
	rec := s.sessions[sessionUUID]
	// Snapshot the fields Validate reads, then release the lock before crypto.
	var (
		state    sessionState
		expiry   time.Time
		reason   string
		identity string
		grantRef string
		hasGrant bool
	)
	known := rec != nil
	if rec != nil {
		state = rec.state
		expiry = rec.expiry
		reason = rec.revokeReason
		identity = rec.identity
		grantRef, hasGrant = rec.grants[serviceID]
	}
	s.mu.Unlock()

	// LIVENESS: unknown session fails closed (no record => no live identity).
	if !known {
		return deny(ReasonUnknownSession)
	}
	// LIVENESS: revoked session fails closed immediately (doc 16 §5.4). The
	// operator-supplied revoke reason rides through on the D77 channel.
	if state == sessionRevoked {
		if reason == "" {
			reason = ReasonSessionRevoked
		}
		return deny(reason)
	}
	// LIVENESS: an expired session is dead — TTL-as-revocation (doc 16 §5.4).
	if !expiry.IsZero() && now.After(expiry) {
		return deny(ReasonSessionExpired)
	}
	// SIGNATURE: route the workload leg through the WorkloadAuthority seam (the M1
	// own-CA impl by default; a SPIRE-backed impl when swapped — doc 05 §7 edge 5).
	// The authority owns the format-opaque signature + claims half of the frozen D22
	// check; this Validate call keeps the liveness/freshness/grant decision. The
	// expected SPIFFE name is the session's minted identity (the §3.1 name on the
	// record), so the verify binds the presentation to this session's name. A
	// session that never minted a workload key surfaces errNoWorkloadKey, mapped to
	// signature_invalid (the pre-extraction pub==nil branch).
	claims, err := s.workloadAuthority.VerifyPresented(presentedCredential, identity, now)
	if err != nil {
		// Distinguish a structurally bad token from a bad signature for the
		// machine-readable reason, but both fail closed.
		if err == errMalformedJWT {
			return deny(ReasonMalformed)
		}
		return deny(ReasonSignatureInvalid)
	}
	// SIGNATURE binding: the token must name THIS session (defense against a
	// valid-but-cross-session token replayed under another session_ref).
	if claims.SessionUUID != sessionUUID {
		return deny(ReasonSignatureInvalid)
	}
	// FRESHNESS: within the token's nbf..exp window.
	nowUnix := toUnix(now)
	if nowUnix < claims.NotBefore || nowUnix >= claims.Expiry {
		return deny(ReasonCredentialStale)
	}
	// GRANT LOOKUP: the service_id must have a grant for this session (§4).
	if !hasGrant {
		return deny(ReasonOutOfGrant)
	}

	return ValidateResult{
		Verdict:  VerdictAllow,
		GrantRef: grantRef,
		Expiry:   expiry,
	}
}

// validateSessionToken is the doc 19 §3/§5 session-token leg of the Validate
// seam. It folds the scoped base token into the existing semantics (doc 19 §5):
// SIGNATURE = the substrate chain/signature check (done in Verify); FRESHNESS =
// the token's own expiry claim; SESSION LIVENESS = unchanged, keyed on the
// token's root session_uuid claim (doc 16 §5.4 — RevokeSession on the root fails
// the whole chain immediately, doc 19 §7); GRANT LOOKUP = the session grant for
// service_id INTERSECTED with the token's attenuated service scope (doc 19 §8 —
// an attenuated child can never exercise a session grant outside its blocks).
//
// It NEVER falls through to the workload-JWT path, so a session token can only
// ever validate as the scoped credential it is — never as workload identity,
// never as interception material (the doc 19 §13 negative property). Fails CLOSED
// on every branch (D77).
func (s *Shim) validateSessionToken(presented []byte, sessionUUID, serviceID string, now time.Time, desiredScopes []string) ValidateResult {
	// SIGNATURE + the token's own authorization (the embedded scope checks).
	claims, _, err := s.tokenSigner.Verify(presented)
	if err != nil {
		return deny(ReasonSignatureInvalid)
	}
	// BINDING: the token must name THIS session (defense against a valid-but-
	// cross-session token replayed under another session_ref, doc 19 §7).
	if claims.SessionUUID != sessionUUID {
		return deny(ReasonSignatureInvalid)
	}

	s.mu.Lock()
	rec := s.sessions[sessionUUID]
	var (
		state    sessionState
		expiry   time.Time
		reason   string
		grantRef string
		hasGrant bool
		hasToken bool
		known    = rec != nil
	)
	if rec != nil {
		state = rec.state
		expiry = rec.expiry
		reason = rec.revokeReason
		grantRef, hasGrant = rec.grants[serviceID]
		hasToken = rec.hasSessionToken
	}
	s.mu.Unlock()

	// LIVENESS: an unknown session — or a session that never had a base token
	// minted (so this presented token cannot be one THIS shim issued for it) —
	// fails closed. Both keep a token from validating under a session it was not
	// minted for.
	if !known || !hasToken {
		return deny(ReasonUnknownSession)
	}
	// LIVENESS: revoked session fails closed immediately (doc 16 §5.4 / doc 19 §7).
	if state == sessionRevoked {
		if reason == "" {
			reason = ReasonSessionRevoked
		}
		return deny(reason)
	}
	// LIVENESS: an expired session is dead — TTL-as-revocation (doc 16 §5.4).
	if !expiry.IsZero() && now.After(expiry) {
		return deny(ReasonSessionExpired)
	}
	// WHOLE-CHAIN LIVENESS on the ROOT session (doc 19 §7): a DESCENDANT token (one
	// carrying a RootSession claim distinct from the session it is presented under)
	// fails closed the instant the ORIGINATING session is revoked or expires —
	// "RevokeSession on the root makes every child token fail closed immediately."
	// Per-child revocation already keyed on the presented session above; this is the
	// second key. The check is skipped for the base token (no RootSession) and when
	// the root IS the presented session (already checked). A root the shim has no
	// record of is NOT a failure here — the descendant's own liveness governs (the
	// root may live in another shim/host; this shim revokes only what it knows).
	if root := claims.RootSession; root != "" && root != sessionUUID {
		if reason, dead := s.rootSessionDead(root, now); dead {
			return deny(reason)
		}
	}
	// FRESHNESS: within the token's own expiry (TTL = session lifetime, doc 19 §3).
	if !claims.Expiry.IsZero() && !now.Before(claims.Expiry) {
		return deny(ReasonCredentialStale)
	}
	// GRANT LOOKUP ∩ TOKEN SCOPE (doc 19 §8): the service_id must have a session
	// grant AND fall within the token's asserted service scope. An attenuated
	// child narrows Services, so a grant outside the child's blocks is denied even
	// though the session holds it (the monotonic-narrowing property, doc 19 §4).
	if !hasGrant {
		return deny(ReasonOutOfGrant)
	}
	if !tokenScopeAllows(claims.Services, serviceID) {
		return deny(ReasonOutOfGrant)
	}
	// D127 SCOPE PREDICATE (doc 23 §6, the Validate-seam enforcement point): the
	// token's `ds_scopes` must COVER every scope the requested operation asserted
	// via desired_scopes. A missing scope denies scope_insufficient. An EMPTY
	// desiredScopes makes no assertion (backward-compatible with the pre-scope
	// path). This is applied LAST — after signature/liveness/grant — so a scope
	// denial is only ever reached by an otherwise-valid presentation.
	if !scopesCovered(claims.Scopes, desiredScopes) {
		return deny(ReasonScopeInsufficient)
	}

	return ValidateResult{
		Verdict:  VerdictAllow,
		GrantRef: grantRef,
		Expiry:   expiry,
	}
}

// scopesCovered reports whether the token's held scopes COVER every required
// scope (doc 23 §6: "the validator asserts that the requested operation is
// covered by the token's ds_scopes"). An EMPTY required set is covered
// vacuously (no scope assertion). A required scope absent from held denies —
// the fail-closed direction (a held superset of an empty required set passes;
// a required scope the token does not carry fails). Exact string match against
// the D127 taxonomy strings (the `v1:` versioned scope constants); an unknown
// required string can never be covered, so it fails closed.
func scopesCovered(held, required []string) bool {
	if len(required) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(held))
	for _, h := range held {
		set[h] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}

// rootSessionDead reports whether the chain's ORIGINATING session is revoked or
// expired in THIS shim's store (doc 19 §7 whole-chain liveness). It returns the
// D77 machine-readable reason and true when the root is dead. An UNKNOWN root
// (this shim never recorded it — it may live on another host) is NOT dead here: a
// descendant token's own liveness already governs, and the fleet-scope revocation
// list (doc 19 §7) is the cross-host channel, not this local check. Snapshots under
// the lock, then decides lock-free (the established Validate discipline).
func (s *Shim) rootSessionDead(rootUUID string, now time.Time) (reason string, dead bool) {
	s.mu.Lock()
	rec := s.sessions[rootUUID]
	var (
		state        sessionState
		expiry       time.Time
		revokeReason string
	)
	known := rec != nil
	if rec != nil {
		state = rec.state
		expiry = rec.expiry
		revokeReason = rec.revokeReason
	}
	s.mu.Unlock()

	if !known {
		return "", false
	}
	if state == sessionRevoked {
		if revokeReason == "" {
			revokeReason = ReasonSessionRevoked
		}
		return revokeReason, true
	}
	if !expiry.IsZero() && now.After(expiry) {
		return ReasonSessionExpired, true
	}
	return "", false
}

// tokenScopeAllows reports whether the token's asserted service scope admits
// serviceID. An EMPTY scope asserts no service narrowing — the token defers
// entirely to the session grants (the base-token default when no Services were
// requested). A non-empty scope is a CEILING: serviceID must be a member (doc 19
// §8 grant ∩ token-scope intersection). This is the monotonic-narrowing check —
// an attenuated child's narrower set can only shrink what validates.
func tokenScopeAllows(scope []string, serviceID string) bool {
	if len(scope) == 0 {
		return true
	}
	for _, svc := range scope {
		if svc == serviceID {
			return true
		}
	}
	return false
}
