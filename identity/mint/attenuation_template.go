// SPDX-License-Identifier: Apache-2.0

// The offline-attenuation TEMPLATE VOCABULARY for D18 fan-out (doc 19 §4, D100).
//
// THE GAP THIS CLOSES. AttenuateSessionToken (sessiontoken.go) takes a raw
// SessionTokenAttenuation record and the substrate appends it as a narrowing
// block. That is the mechanism. doc 19 §4 / D52 require the CONTENT of that
// narrowing be generated from TYPED RECORDS ONLY — "a fixed caveat/block template
// vocabulary derived from the grant model (identity × service × scope × TTL) and
// the role template (§11)". This file is that vocabulary: typed constructors that
// PRODUCE a SessionTokenAttenuation from the four grant-model dimensions, so a
// caller (the orchestrator/wrapper at CreateChildSession, doc 15 §5.3) never
// hand-authors a narrowing — there is no string-typed Datalog or free-form caveat
// surface to author against (the D52 v0 posture, doc 16 §5.1 carried here).
//
// PURE, ZERO MINT RPCs (doc 19 §4). Every constructor here is a pure function over
// typed records: it allocates no token, signs nothing, and never touches the mint
// or the network. The derived SessionTokenAttenuation is fed to the existing
// offline AttenuateSessionToken path — the killer fit (one strictly-narrower child
// per subagent VM with zero round-trips, doc 19 §1/§4). The MONOTONIC-narrowing
// guarantee is the substrate's (Attenuate fails a widening closed); this layer
// builds only narrowing records, but is NOT the trust boundary for that property —
// the substrate is (a malformed template still cannot widen a token).
//
// THE FOUR GRANT-MODEL DIMENSIONS (doc 19 §4: identity × service × scope × TTL).
// A child-session derivation narrows along exactly these axes:
//   - IDENTITY  — the child's own session_uuid becomes the next parent_session hop
//     (the cryptographic identity-lineage, doc 19 §4/§9); the launching
//     user is INHERITED unchanged (root attribution never widens or
//     forks, doc 04 §5).
//   - SERVICE   — the child's service set is ⊆ the parent's grant-relevant scope.
//   - SCOPE     — carried as the service set today (v0); the role template (§11) is
//     the reserved hook for a richer per-role scope vocabulary.
//   - TTL       — the child horizon is shorter-or-equal (doc 19 §4).
//
// THE ROLE-TEMPLATE SEAM (doc 19 §11, doc 18 §8 — RESERVED, NOT DESIGNED HERE).
// doc 19 §11 reserves exactly one coupling: a role MAY carry a default token-scope
// / attenuation template keyed by role_ref, consumed at doc 15 §4.1 step 5. Role
// SEMANTICS, authority, and lifecycle are entirely doc 18's; this doc "consumes
// the template and designs nothing further". So RoleAttenuationTemplate below is a
// TYPED SEAM RECORD, not a role engine: it carries the same four narrowing
// dimensions a role's default template would supply, and a RoleTemplateResolver
// hook turns a role_ref into one. v0 ships NO resolver (nil = the role contributes
// no default narrowing); doc 18 installs the real one without changing this shape.
package mint

import "time"

// RoleAttenuationTemplate is the doc 19 §11 role-template SEAM record: the typed,
// default narrowing a role MAY contribute at a fan-out hop, keyed by role_ref. It
// carries ONLY the doc 19 §4 grant-model dimensions a role's default token-scope
// template is allowed to supply (doc 18 §8) — never free-form policy, never a
// string-typed caveat (D52). All fields are OPTIONAL defaults a child derivation
// folds in; an empty template contributes no narrowing. Role semantics/authority/
// lifecycle live in doc 18 — this is the consumption record only (doc 19 §11).
type RoleAttenuationTemplate struct {
	// Services is the role's default service ceiling (the SERVICE/SCOPE axes). When
	// set, a child derived under this role is narrowed to its INTERSECTION with the
	// parent scope — a role can only ever shrink, never widen, the parent set (the
	// monotonic-narrowing invariant, doc 19 §4). Nil = the role asserts no service
	// default (the parent scope, possibly further narrowed by an explicit request,
	// governs).
	Services []string
	// MaxTTL is the role's default TTL ceiling (the TTL axis). When non-zero, a
	// child's horizon is clamped to at most parentExpiry-or-now + MaxTTL — a role
	// can shorten, never lengthen, the child lifetime. Zero = no role TTL default.
	MaxTTL time.Duration
}

// RoleTemplateResolver is the doc 19 §11 / doc 18 §8 role-template HOOK: it turns a
// role_ref into the role's default attenuation template. v0 ships NO resolver (a
// nil hook means a role contributes no default narrowing); the agent-roles design
// pass (doc 18) installs the real one WITHOUT changing this shape — the only
// coupling doc 19 creates (doc 19 §11: "consumes the template and designs nothing
// further"). It returns (template, ok): ok=false means the role_ref is unknown to
// the resolver, which is NOT an error — the derivation proceeds with no role
// default (fail-OPEN on the role axis is safe BECAUSE the substrate fails any
// resulting widening closed regardless).
type RoleTemplateResolver func(roleRef string) (RoleAttenuationTemplate, bool)

// ChildSessionParams is the TYPED input to a fan-out derivation (doc 19 §4): the
// per-child-VM narrowing the orchestrator/wrapper supplies at CreateChildSession
// (doc 15 §5.3). It is the only authoring surface — there is no Datalog/caveat
// string to write (D52). Every field maps to one grant-model dimension; the
// derivation composes them with the parent's claims and the role template into a
// SessionTokenAttenuation that can only NARROW.
type ChildSessionParams struct {
	// ChildSessionUUID is the child VM's session (the IDENTITY axis): it becomes the
	// child token's session scope and is appended as the chain's next parent_session
	// hop (doc 19 §4/§9). REQUIRED — a fan-out hop without a child identity is not a
	// child derivation.
	ChildSessionUUID string
	// Services is the explicit per-child service narrowing (the SERVICE axis). When
	// set it is intersected with the parent scope AND the role default; nil means
	// "no explicit narrowing on this axis" (the parent scope, possibly clamped by
	// the role default, governs). It can only ever SHRINK the effective set.
	Services []string
	// TTL is the explicit per-child lifetime (the TTL axis); the child expiry is
	// derivedNow+TTL, clamped to never exceed the parent expiry or the role MaxTTL.
	// Zero means "inherit the parent horizon (subject to the role MaxTTL clamp)".
	TTL time.Duration
	// TaskRef is the child's task reference (doc 19 §4): the recorded prompt/plan the
	// subagent runs (doc 04 §3). Carried verbatim into the child claim.
	TaskRef string
	// RoleRef keys the role-template seam (doc 19 §11). When non-empty AND a
	// RoleTemplateResolver is installed, the role's default template folds its
	// narrowing in. Empty or no resolver = no role default (v0 default).
	RoleRef string
}

// BuildChildAttenuation composes the per-child params, the parent's effective
// claims, and the role-template seam into a TYPED SessionTokenAttenuation — the
// doc 19 §4 template vocabulary, generated from records only (D52, no hand-authored
// caveats). It is PURE: no token, no signature, no mint RPC. The result is fed to
// AttenuateSessionToken, which performs the actual offline append and is the trust
// boundary for monotonic narrowing (a template that somehow over-asks still cannot
// widen the token — Attenuate fails it closed).
//
// FOLD ORDER (each step can only narrow):
//  1. SERVICE/SCOPE — start from the parent's effective service scope; intersect
//     with the role default (if any), then with the explicit per-child set (if
//     any). Intersection is monotone: the result is ⊆ every input, so ⊆ parent.
//  2. TTL — the child horizon is the soonest of: the parent expiry, derivedNow +
//     the explicit per-child TTL (if any), and derivedNow + the role MaxTTL (if
//     any). "Soonest" can only shorten.
//  3. IDENTITY — the child session_uuid (the next parent_session hop) and task_ref
//     are carried verbatim (these ADD lineage, they do not widen authority).
//
// derivedNow is the derivation instant (the caller's clock — the wrapper's, since
// this is offline and issuer-free). parentExpiry is the parent token's horizon
// (bundle.Expiry); parentServices is the parent's effective service scope
// (claims.Services from a Verify, or the base request set). resolver may be nil.
func BuildChildAttenuation(
	p ChildSessionParams,
	parentExpiry time.Time,
	parentServices []string,
	derivedNow time.Time,
	resolver RoleTemplateResolver,
) SessionTokenAttenuation {
	var role RoleAttenuationTemplate
	if p.RoleRef != "" && resolver != nil {
		if tmpl, ok := resolver(p.RoleRef); ok {
			role = tmpl
		}
	}

	// (1) SERVICE/SCOPE: intersect parent ∩ role-default ∩ explicit. Each
	// intersection is monotone, so the result is ⊆ the parent scope. We only emit a
	// narrowed Services list when SOME axis actually constrains it — if neither the
	// role nor the explicit request asserts a service set, we leave it nil (inherit
	// the parent scope) so the substrate sees "no service narrowing on this hop".
	services := narrowServices(parentServices, role.Services, p.Services)

	// (2) TTL: the child horizon is the SOONEST of parentExpiry, now+explicitTTL,
	// and now+roleMaxTTL. Zero on either knob means "that knob imposes no clamp".
	expiry := narrowExpiry(parentExpiry, derivedNow, p.TTL, role.MaxTTL)

	return SessionTokenAttenuation{
		ChildSessionUUID: p.ChildSessionUUID,
		Services:         services,
		Expiry:           expiry,
		TaskRef:          p.TaskRef,
	}
}

// narrowServices intersects the parent scope with the optional role default and
// the optional explicit per-child set. A nil constraint means "this axis imposes
// no ceiling"; if NO axis below the parent asserts a set, the result is nil ("no
// service narrowing on this hop" — the substrate keeps the parent scope). The
// result is always ⊆ parent (intersection is monotone), so the substrate's
// subset check can never reject a record this function builds.
func narrowServices(parent, role, explicit []string) []string {
	// Build the effective ceiling below the parent: role ∩ explicit, where a nil
	// operand drops out (imposes no ceiling).
	var want []string
	switch {
	case role == nil && explicit == nil:
		// Neither sub-axis narrows: inherit the parent scope (nil = no narrowing).
		return nil
	case role == nil:
		want = explicit
	case explicit == nil:
		want = role
	default:
		want = intersect(role, explicit)
	}
	// Intersect with the parent scope so the result can never exceed it. An empty
	// parent scope means "parent asserts no service ceiling" (the base-token
	// default), so the want set stands as the (narrowing) child scope.
	if len(parent) == 0 {
		return dedupe(want)
	}
	return intersect(parent, want)
}

// narrowExpiry returns the SOONEST of the parent expiry and the now-relative
// explicit / role TTL clamps. A zero TTL knob imposes no clamp; a zero parentExpiry
// means "parent asserts no horizon" (so a clamp, if any, governs). The result is a
// zero time only when NO axis constrains the horizon (the substrate then keeps the
// parent expiry).
func narrowExpiry(parentExpiry, now time.Time, explicitTTL, roleMaxTTL time.Duration) time.Time {
	var out time.Time
	consider := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if out.IsZero() || t.Before(out) {
			out = t
		}
	}
	consider(parentExpiry)
	if explicitTTL > 0 {
		consider(now.Add(explicitTTL))
	}
	if roleMaxTTL > 0 {
		consider(now.Add(roleMaxTTL))
	}
	// If the only constraint is the parent expiry, leave the attenuation expiry
	// zero — that tells the substrate "no TTL narrowing on this hop" (it keeps the
	// parent horizon), which is identical in effect and avoids re-asserting the
	// parent's own expiry as a "narrowing".
	if out.Equal(parentExpiry) {
		return time.Time{}
	}
	return out
}

// intersect returns the elements of a that also appear in b, de-duplicated and in
// a's order (deterministic output for the golden/audit path). It is the monotone
// service-scope narrowing primitive.
func intersect(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, x := range b {
		set[x] = struct{}{}
	}
	var out []string
	seen := make(map[string]struct{}, len(a))
	for _, x := range a {
		if _, ok := set[x]; !ok {
			continue
		}
		if _, dup := seen[x]; dup {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

// dedupe returns s with duplicates removed, preserving first-seen order (so the
// derived scope is deterministic for the audit/golden path).
func dedupe(s []string) []string {
	if s == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(s))
	var out []string
	for _, x := range s {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

// DeriveChildSession is the convenience fan-out entrypoint (doc 19 §4): it builds
// the typed child attenuation from params + the parent bundle's effective scope and
// applies the OFFLINE AttenuateSessionToken in one call — the orchestrator/wrapper
// surface at CreateChildSession (doc 15 §5.3). ZERO mint RPCs: it derives the
// narrowing record (pure, this file) and appends it via the substrate's offline
// path (no network). The parent's effective service scope is read from the parent
// token's own claims via the substrate Verify, so the child scope is genuinely ⊆
// the parent's blocks — not a caller-asserted value.
//
// resolver may be nil (v0: no role default). derivedNow is the wrapper's clock; a
// zero value uses the shim clock (the only shim dependency — still no mint RPC).
func (s *Shim) DeriveChildSession(parent *SessionTokenBundle, p ChildSessionParams, resolver RoleTemplateResolver, derivedNow time.Time) (*SessionTokenBundle, error) {
	if s.tokenSigner == nil {
		return nil, errNoSigner
	}
	if parent == nil || len(parent.Token) == 0 {
		return nil, errNoParentToken
	}
	if p.ChildSessionUUID == "" {
		return nil, errNoChildSession
	}
	// Read the parent's EFFECTIVE service scope from its own claims (the substrate
	// signature check runs here — still no mint RPC, no network). This makes the
	// derived child scope provably ⊆ the parent's blocks.
	parentClaims, _, err := s.tokenSigner.Verify(parent.Token)
	if err != nil {
		return nil, err
	}
	if derivedNow.IsZero() {
		derivedNow = s.now()
	}
	narrow := BuildChildAttenuation(p, parent.Expiry, parentClaims.Services, derivedNow, resolver)
	return s.AttenuateSessionToken(parent, narrow)
}
