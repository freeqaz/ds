package policylog

// This file is the ASK-ROUTING call-site (doc 15 §4.3 / §6.2 step 4, the
// PolicyService.ApproveAsk leg, D45/D53): the path that RECEIVES a human's
// approval decision for an ask-a-human request and routes it into the policy_log
// write. It is the in-process seam the PolicyService.ApproveAsk RPC will adapt to
// mechanically when the proto lands (PolicyService is unfrozen; this is the
// in-process shape, never a proto body).
//
// The §6.2 ask-response-as-grant rule (D45/D53) is the structural constraint this
// routing leg enforces: a human's allow-once / allow-always / deny choice is NOT
// a response channel — it becomes a TTL'd grant on the policy stream, or (for a
// deny) no grant at all. So the routing splits on the decision:
//
//   - ALLOW (allow-once / allow-always): resolve the approver principal, then gate
//     and stamp via ApproveAsk — the existing gate+attribution seam (askapproval.go).
//     The MayApprove role-gate (D45) is enforced inside ApproveAsk: a non-approver
//     is refused with ErrNotApprover and NO row is written. An authorized approval
//     appends the attributed PolicyKindAskGrant row.
//   - DENY: appends NO allow grant (§6.2 step 4 — "the wrapper answers deny
//     directly"). The no-allow-grant guarantee is ABSOLUTE — a deny never produces
//     an allow on the policy stream. A deny DOES, when a D77 machine-readable
//     reason is carried (DenyReason set, D118), write a session-scoped DENY MEMO
//     so a retry fast-fails on the recorded denial instead of re-prompting; that
//     write is the symmetric counterpart of the allow grant (same write path, the
//     denier recorded in Actor — DenyAsk in denymemo.go). With no reason carried
//     the deny stays the legacy no-write path: the wrapper answers deny directly
//     and there is nothing on the policy stream to attribute.
//
// It adds NO contract surface beyond askapproval.go's: allows still ride the
// existing PolicyKindAskGrant append, gated by MayApprove and attributed to the
// approver. The ask READ direction (CC raising the ask, the wrapper projecting it
// to attach.v1, the human choosing) is out of scope — this is only the
// write-direction routing of an already-made decision.

import (
	"context"
	"fmt"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// approverResolver is the narrow read-seam the routing leg needs to turn the
// approver's principal ID (carried on the decision) into the resolved principal
// the role-gate runs against. Dependency-injected as an interface so the routing
// depends only on the one lookup it consumes, and either store impl
// (*store.Memory / *store.Postgres) or a test fake satisfies it. ErrNotFound for
// an unknown approver ID.
type approverResolver interface {
	GetPrincipal(ctx context.Context, id string) (store.Principal, error)
}

// askRouter is the seam composition the routing leg holds: the approver lookup
// (to resolve the principal) and the policy append (to land an allowed grant).
// Both store impls satisfy this; a test pairs a principal fake with the
// askapproval appender fake.
type askRouter interface {
	approverResolver
	policyAppender
}

// AskDecision is one of the three §6.2 human choices the routing leg dispatches
// on (PHASE3 P8 maps these onto CC's behavior × decisionClassification; here we
// model only the write-direction effect: allow-once / allow-always → grant,
// deny → no grant).
type AskDecision string

const (
	// AskDecisionAllowOnce is the session-scoped grant that dies with the session
	// (D45 allow-once): an authorized approval appends a TTL'd ask-grant.
	AskDecisionAllowOnce AskDecision = "allow_once"
	// AskDecisionAllowAlways is the org-admin-acceptance proposal (D45 allow-always):
	// it still appends a session-scoped ask-grant here (the fleet-wide promotion is
	// the separate org-admin-acceptance path, never auto-applied); the routing
	// stamps the approver and the grant body the ask path composed.
	AskDecisionAllowAlways AskDecision = "allow_always"
	// AskDecisionDeny appends NO allow grant (§6.2 step 4): the wrapper answers deny
	// directly. The routing performs no policy_log write.
	AskDecisionDeny AskDecision = "deny"
)

// IsAllow reports whether the decision appends an allow grant (allow-once /
// allow-always) versus deny (no grant). An unrecognized decision is treated as
// NOT an allow (fail-closed: never write an allow grant for an unknown choice).
func (d AskDecision) IsAllow() bool {
	switch d {
	case AskDecisionAllowOnce, AskDecisionAllowAlways:
		return true
	default:
		return false
	}
}

// AskRouting carries the write-direction inputs of one routed ask decision: the
// approver's principal ID (the routing resolves it to gate on MayApprove), the
// session the grant is scoped to, the matched allow rule (D45 scope), the grant
// TTL, the reserved D119 consent class, and the grant body the ask path composed.
// It is the in-process shape the PolicyService.ApproveAsk RPC adapts to later.
type AskRouting struct {
	Decision            AskDecision        // the §6.2 human choice (allow-once / allow-always / deny)
	ApproverPrincipalID string             // the principal that made the decision (resolved + role-gated)
	SessionUUID         string             // the session the grant is scoped to (§4.3)
	Rule                string             // the matched allow target (D45 grant scope)
	ExpiresAt           store.OptTime      // the grant TTL (the grant dies with the session)
	Consent             store.ConsentClass // reserved D119 consent class (defaults unspecified)
	Payload             []byte             // the grant body the ask path composed (rule + scope + consent)

	// DenyReason is the D77 machine-readable reason carried on a DENY decision
	// (D118): when set, a deny ALSO writes a session-scoped deny memo so a retry
	// fast-fails on the recorded denial. When EMPTY (the legacy shape), a deny
	// stays the no-write path — the wrapper answers deny directly with nothing on
	// the policy stream. It is meaningful only for AskDecisionDeny; an allow
	// ignores it. This keeps the deny-memo behavior strictly additive: callers
	// that do not carry a reason see the pre-D118 no-write deny unchanged.
	DenyReason string
}

// AskRoutingFromResolution is the WIRE between the ask-routing ENTRY
// (ResolveAskRouting, askroute_resolve.go) and this WRITE path (RouteAskDecision):
// it stamps the RESOLVED approver from an AskResolution onto the AskRouting whose
// ApproverPrincipalID RouteAskDecision/ApproveAsk attribute the persisted grant
// Actor to. This is the call-site that closes D45 attribution: for an ALLOW-ALWAYS
// ask the resolved approver is the ORG-ADMIN acceptor (res.EscalatedToOrgAdmin,
// res.ApproverPrincipalID = the org-admin — never the launching user), so feeding
// res.ApproverPrincipalID into AskRouting.ApproverPrincipalID makes the persisted
// PolicyKindAskGrant row's Actor the org-admin, not the launcher. For an allow-once
// / deny the resolution carries the launching-user default, so that path is
// attributed to the launcher unchanged.
//
// The grant BODY the ask path composed (rule, TTL, reserved consent class, payload,
// and any D77/D118 deny reason) is passed alongside the resolution — AskResolution
// is the routing decision (who approves + where it dispatches), not the grant body,
// so the body inputs stay the caller's to fill. The decision (the human's
// allow-once / allow-always / deny choice) is also passed in: it governs the
// allow-vs-deny dispatch inside RouteAskDecision and must match the decision class
// the resolution was computed for (the caller resolves and routes the same choice).
//
// It is PURE structural plumbing — no resolver, no store, no I/O. It exists so the
// call-site cannot accidentally hand RouteAskDecision the launching user for an
// allow-always (the D45 footgun the unit closes): the only approver it can carry is
// the one the resolution resolved.
func AskRoutingFromResolution(
	res AskResolution,
	decision AskDecision,
	rule string,
	expiresAt store.OptTime,
	consent store.ConsentClass,
	payload []byte,
	denyReason string,
) AskRouting {
	return AskRouting{
		Decision:            decision,
		ApproverPrincipalID: res.ApproverPrincipalID, // resolved approver: org-admin for allow-always (D45), launcher otherwise
		SessionUUID:         res.SessionUUID,
		Rule:                rule,
		ExpiresAt:           expiresAt,
		Consent:             consent,
		Payload:             payload,
		DenyReason:          denyReason,
	}
}

// AskRoutingResult reports the outcome of one routed decision: whether a grant
// was written and, when it was, the appended ask-grant row (carrying the
// store-assigned seq and the approver in Actor). For a deny, Granted is false and
// Row is the zero row — no policy_log write happened.
type AskRoutingResult struct {
	Granted bool               // true iff an allow grant was appended (allow-once / allow-always)
	Denied  bool               // true iff a session-scoped deny memo was appended (D118, deny + DenyReason set)
	Row     store.PolicyLogRow // the appended ask-grant row when Granted, or the deny-memo row when Denied; zero otherwise
}

// RouteAskDecision is the §4.3 / §6.2-step-4 ask-ROUTING call-site: it receives a
// human's ask decision and routes it into the policy_log write direction,
// enforcing the §6.2 ask-response-as-grant rule (D45/D53):
//
//   - DENY (or any non-allow decision): appends NO ALLOW grant — ever. When a D77
//     machine-readable reason is carried (DenyReason set, D118) it ALSO resolves
//     the denier principal, gates it on MayApprove (DenyAsk), and appends a
//     session-scoped deny memo so a retry fast-fails on the recorded denial;
//     returns Denied=true with the memo row (Granted stays false). When NO reason
//     is carried it stays the legacy no-write deny: the wrapper answers deny
//     directly, nothing is written, returns Granted=false / Denied=false with a
//     nil error. An UNRECOGNIZED decision is treated as a deny with no reason
//     (fail-closed: no write at all).
//   - ALLOW (allow-once / allow-always): resolves the approver principal by ID
//     (GetPrincipal; an unknown approver is ErrNotFound), then routes through
//     ApproveAsk — which GATES on the resolved principal's MayApprove role
//     (refusing a non-approver with ErrNotApprover, NO row written) and, when
//     authorized, appends the ask-grant row attributed to the approver (Actor =
//     approver principal ID, the D36 audit column). Returns Granted=true with the
//     appended row carrying the store-assigned seq.
//
// The role-gate and the attribution both live in ApproveAsk (the seam this
// routing wraps); this leg adds the decision dispatch (allow vs deny) and the
// approver resolution that turns the carried principal ID into the gated
// principal. It writes NO grant for a non-approver and NO grant for a deny — the
// two ways an ask does not become an allow on the policy stream.
func RouteAskDecision(ctx context.Context, r askRouter, ask AskRouting) (AskRoutingResult, error) {
	if !ask.Decision.IsAllow() {
		// No ALLOW grant on the policy stream — ever, for deny or any unrecognized
		// decision (the no-allow-grant guarantee, §6.2 step 4).
		//
		// D118 deny memo: an explicit DENY carrying a D77 machine-readable reason
		// ALSO writes a session-scoped deny memo so a retry fast-fails on the
		// recorded denial. The denier is the principal that made the decision
		// (ApproverPrincipalID), resolved and gated on MayApprove inside DenyAsk —
		// symmetric with the allow path. With no reason carried (the legacy shape)
		// or any non-deny/unrecognized decision, nothing is written: the wrapper
		// answers deny directly and there is nothing to attribute (fail-closed).
		if ask.Decision == AskDecisionDeny && ask.DenyReason != "" {
			denier, err := r.GetPrincipal(ctx, ask.ApproverPrincipalID)
			if err != nil {
				return AskRoutingResult{}, fmt.Errorf("resolve denier %s for deny on session %s: %w",
					ask.ApproverPrincipalID, ask.SessionUUID, err)
			}
			row, err := DenyAsk(ctx, r, denier, ask.SessionUUID, ask.Rule, ask.DenyReason, ask.ExpiresAt, ask.Payload)
			if err != nil {
				// ErrNotApprover (role-gate refusal) or an append failure — surfaced,
				// never swallowed. No allow grant was written in any case.
				return AskRoutingResult{}, err
			}
			return AskRoutingResult{Granted: false, Denied: true, Row: row}, nil
		}
		return AskRoutingResult{Granted: false}, nil
	}
	approver, err := r.GetPrincipal(ctx, ask.ApproverPrincipalID)
	if err != nil {
		return AskRoutingResult{}, fmt.Errorf("resolve approver %s for ask on session %s: %w",
			ask.ApproverPrincipalID, ask.SessionUUID, err)
	}
	row, err := ApproveAsk(ctx, r, approver, ask.SessionUUID, ask.Rule, ask.ExpiresAt, ask.Consent, ask.Payload)
	if err != nil {
		// ErrNotApprover (role-gate refusal) or an append failure — surfaced, never
		// swallowed into a silent allow.
		return AskRoutingResult{}, err
	}
	return AskRoutingResult{Granted: true, Row: row}, nil
}

// GrantBody groups the grant-BODY inputs the ask path composed — the inputs that
// describe WHAT is granted (the matched rule, the TTL, the reserved D119 consent
// class, the composed payload) and, for a deny, the D77/D118 machine-readable
// reason. It is the exact set of body parameters AskRoutingFromResolution already
// takes positionally; ResolveAndRoute folds them into one value so the convenience
// call stays readable. It carries NO approver and NO session: those are the
// RESOLUTION's to fill (who approves + which session), the structural separation
// that closes the D45 footgun — the body can never name the launching user as the
// approver, because the body has no approver field at all.
type GrantBody struct {
	Rule       string             // the matched allow target (D45 grant scope)
	ExpiresAt  store.OptTime      // the grant TTL (the grant dies with the session)
	Consent    store.ConsentClass // reserved D119 consent class (defaults unspecified)
	Payload    []byte             // the grant body the ask path composed (rule + scope + consent)
	DenyReason string             // D77 machine-readable reason on a DENY (D118); ignored for an allow
}

// ResolveAndRoute is the one-call ASK PATH (doc 15 §4.3 / doc 16 §8.2, D45): it
// folds the three steps — ResolveAskRouting (resolve WHO approves + WHERE it
// dispatches, askroute_resolve.go) → AskRoutingFromResolution (stamp the resolved
// approver onto the write-direction routing) → RouteAskDecision (gate + attribute
// the policy_log write) — so the ATTRIBUTION-PRESERVING path is the ONLY way to
// route an ask. The in-process PolicyService.ApproveAsk seam adapts into THIS, not
// into the three steps individually.
//
// Why fold them: the D45 footgun is handing RouteAskDecision the LAUNCHING USER as
// the approver for an ALLOW-ALWAYS — which must escalate to the org-admin acceptor
// (ResolveOrgAdminAcceptor), never the launcher. The three-step path closes it only
// if every call-site threads the RESOLVED approver from ResolveAskRouting into the
// routing; a call-site that builds an AskRouting by hand can still name the wrong
// approver. ResolveAndRoute removes that opportunity: the approver the write
// attributes is ALWAYS the one ResolveAskRouting resolved (the org-admin for
// allow-always, the launching user otherwise) because the only AskRouting it routes
// is the one AskRoutingFromResolution stamps from that resolution. The body inputs
// (GrantBody) describe WHAT is granted, never WHO grants it.
//
// It adds NO contract surface beyond the existing three calls and reuses the
// existing seams: resolver is the askApproverResolver ResolveAskRouting consumes
// (launching-user + org-admin lookups), router is the askRouter RouteAskDecision
// consumes (GetPrincipal + AppendPolicy). Either store impl (*store.Memory /
// *store.Postgres) satisfies both directly; a test pairs synthetic fakes (D50).
//
// The decision is passed ONCE and used for both halves — it governs the approver
// resolution (allow-always → org-admin escalation) AND the allow-vs-deny dispatch,
// so resolution and routing can never be computed for two different choices. A
// resolution error (no session, no default approver, no eligible org-admin —
// fail-closed) short-circuits before any write; the returned result then carries
// the routing outcome (Granted/Denied + the appended row) verbatim.
func ResolveAndRoute(
	ctx context.Context,
	resolver askApproverResolver,
	router askRouter,
	ask *boundaryv1.AskUserRequest,
	decision AskDecision,
	attended Attendedness,
	body GrantBody,
) (AskResolution, AskRoutingResult, error) {
	res, err := ResolveAskRouting(ctx, resolver, ask, decision, attended)
	if err != nil {
		// Fail-closed resolution (ErrNoSession / ErrNoDefaultApprover /
		// ErrNoOrgAdminAcceptor / a surfaced lookup error) — never reaches the write.
		return AskResolution{}, AskRoutingResult{}, err
	}
	routing := AskRoutingFromResolution(res, decision, body.Rule, body.ExpiresAt, body.Consent, body.Payload, body.DenyReason)
	result, err := RouteAskDecision(ctx, router, routing)
	if err != nil {
		return res, AskRoutingResult{}, err
	}
	return res, result, nil
}
