// SPDX-License-Identifier: Apache-2.0

package policylog

// This file is the ASK-ROUTING ENTRY (doc 16 §8.2, D45/D78/TLS-1): the pure
// decision that RECEIVES an inbound one-way boundaryv1.AskUserRequest and resolves
//
//  1. WHO approves — the DEFAULT APPROVER is the launching user (resolved through
//     the session->principal linkage, injected as a narrow read seam), and an
//     ALLOW-ALWAYS ask ESCALATES to an org-admin acceptor per D45
//     (posture-delegable; FAIL-CLOSED when no eligible org-admin exists); and
//  2. WHERE the ask is dispatched — an ATTENDED session gets the client-wrapper
//     prompt (the TLS-1 30-60s socket-hold rides this), an UNATTENDED session gets
//     an async notification; genuine rung-2 asks PARK per D46 (resume-on-answer,
//     never timing out into allow/kill — modeled here as a target, not enforced).
//
// It is the ROUTING+ATTRIBUTION surface that FEEDS the already-landed
// RouteAskDecision/ApproveAsk write path (askrouting.go/askapproval.go): this
// computes the approver to attribute and the dispatch target; the human's
// allow/deny decision is then routed through RouteAskDecision unchanged. It
// consumes the FROZEN one-way ask transport (boundaryv1.AskUserRequest) and the
// frozen identity event types ONLY (askevents.go projects the events); it
// introduces NO second response contract (doc 16 §8.2 — approvals return solely as
// TTL'd allow grants on the policy stream) and NEVER edits proto.
//
// Everything here is a PURE decision over injected inputs: the session->principal
// resolver and the org-admin acceptor are narrow read seams (interfaces), so the
// routing depends only on the lookups it consumes and a synthetic fake satisfies
// it in tests (D50). No store import, no live anything.

import (
	"context"
	"fmt"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// launchingUserResolver is the narrow read seam that turns the asking session into
// its DEFAULT APPROVER — the launching user (doc 16 §8.2: "default approver = the
// launching user"). It mirrors store.ResolveLaunchingUserClaim's contract exactly
// so either store impl (*store.Memory / *store.Postgres) satisfies it, while the
// routing depends only on the one lookup it consumes (a synthetic fake satisfies it
// in tests, D50):
//
//   - ok == true: the session has a launching principal; the claim carries its
//     PrincipalID (the approver to attribute), IdP Subject, and Org.
//   - ok == false, nil error: the session exists but has no launching principal
//     (the nullable pre-mint / system-session case). There is no default approver
//     to resolve — FAIL-CLOSED (no fabricated approver, the §3.1 "IdP-asserted or
//     absent, never self-declared" contract).
//   - non-nil error: the session is unknown or the link dangles — surfaced, never
//     silently treated as "no approver".
type launchingUserResolver interface {
	ResolveLaunchingUserClaim(ctx context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error)
}

// orgAdminResolver is the narrow read seam that resolves an ALLOW-ALWAYS ask to an
// eligible ORG-ADMIN acceptor (doc 16 §8.2 / D45: "Allow-always escalates to
// org-admin acceptance, delegable by posture"). It is injected so the org's
// org-admin election — and any posture delegation of it — stays the org/posture
// layer's concern, never hardcoded here; the routing only asks "given this session,
// who is the eligible org-admin acceptor?":
//
//   - ok == true: an eligible org-admin exists; the principal is the acceptor the
//     allow-always grant is attributed to.
//   - ok == false, nil error: NO eligible org-admin — the FAIL-CLOSED case (D45).
//     The routing refuses to resolve an approver; an allow-always with no eligible
//     org-admin must NOT silently fall back to the launching user.
//   - non-nil error: a lookup failure — surfaced.
//
// It mirrors store.ResolveOrgAdminAcceptor's contract exactly so the LIVE store impls
// (*store.Memory / *store.Postgres) satisfy it directly: the store resolves the
// session's org (its launching principal's org) and returns the eligible org-admin
// MayApprove() admits via RoleOrgAdmin (store/inventory.go). The D45 escalation thus
// resolves against the real store, not just a synthetic fake — see the live-backing
// assertion below — while a synthetic fake still satisfies the seam in tests (D50).
type orgAdminResolver interface {
	ResolveOrgAdminAcceptor(ctx context.Context, sessionUUID string) (store.Principal, bool, error)
}

// Compile-time proof that the LIVE store impls back the ask-routing approver seams:
// both *store.Memory and *store.Postgres satisfy the full askApproverResolver (the
// launching-user DEFAULT approver via ResolveLaunchingUserClaim AND the D45
// allow-always org-admin escalation via ResolveOrgAdminAcceptor). This is the wire
// from ResolveAskRouting to the real store — the routing depends only on the seam,
// but the seam is now backed by the persisted record, not solely a synthetic fake.
var (
	_ askApproverResolver = (*store.Memory)(nil)
	_ askApproverResolver = (*store.Postgres)(nil)
)

// askApproverResolver is the seam composition the routing entry holds: the
// launching-user lookup (the default approver) and the org-admin acceptor lookup
// (the allow-always escalation). A test pairs synthetic fakes for both; the live
// orchestrator supplies the store-backed launching-user resolver and a
// posture-backed org-admin acceptor.
type askApproverResolver interface {
	launchingUserResolver
	orgAdminResolver
}

// postureElectionResolver is the RESERVED posture-delegated org-admin election seam
// (doc 16 §8.2, D45: "Allow-always escalates to org-admin acceptance, DELEGABLE BY
// POSTURE"). It is the narrow INJECTED override the routing consults FIRST for an
// allow-always ask — ahead of the store's lowest-id default (ResolveOrgAdminAcceptor)
// — so a future org/posture layer can override WHICH eligible org-admin an
// allow-always routes to without re-touching the store resolver. It mirrors the
// store.PostureElection hook shape's intent at the routing boundary (where D45 places
// the org/posture concern), but is its OWN narrow seam here so the routing depends
// only on the one lookup it consumes and a synthetic fake satisfies it (D50):
//
//   - ok == true: the posture layer elected THIS org-admin as the acceptor; the
//     allow-always grant is attributed to it (EscalatedToOrgAdmin stays true — it is
//     still the D45 org-admin escalation, merely a posture-delegated WHICH).
//   - ok == false, nil error: NO posture override for this session — the routing FALLS
//     BACK to ResolveOrgAdminAcceptor (the lowest-id fail-closed default). This is the
//     ADDITIVE contract: absent an override the resolution is byte-identical to today.
//   - non-nil error: a posture-lookup failure — surfaced wrapped, never swallowed into
//     the default (a posture layer that errors must not silently degrade to lowest-id).
//
// It is injected as an OPTIONAL seam (WithPostureElection on ResolveAskRouting's
// variadic tail); when none is supplied the routing behaves EXACTLY as before — the
// lowest-id org-admin default. A nil resolver is treated as "no override" (no panic).
// The one-call ResolveAndRoute convenience keeps its FIXED positional signature and
// does not thread this option today (it always takes the lowest-id default), so its
// landed callers compile unchanged; a future change can add the option there too.
type postureElectionResolver interface {
	ElectOrgAdminAcceptor(ctx context.Context, sessionUUID string) (store.Principal, bool, error)
}

// resolveOpts carries the OPTIONAL injected seams the ask-routing entry consults.
// Today it holds the posture-election override; it defaults to the zero value (no
// override → lowest-id default), so adding it never changes the resolution for any
// caller that supplies no option. It is the additive extension point that keeps the
// ResolveAskRouting positional signature stable (its options ride a variadic tail) and
// leaves ResolveAndRoute's signature untouched (D45 "delegable by posture" reserved
// without a signature break).
type resolveOpts struct {
	posture postureElectionResolver
}

// ResolveOption configures an OPTIONAL ask-routing seam (the variadic tail of
// ResolveAskRouting). It is the additive injection point: with no options the routing
// behavior is byte-identical to the lowest-id default.
type ResolveOption func(*resolveOpts)

// WithPostureElection injects the posture-delegated org-admin election seam (D45):
// the routing consults it FIRST for an allow-always ask and falls back to the
// lowest-id org-admin default (ResolveOrgAdminAcceptor) when it returns no override.
// A nil resolver is a no-op (the default election stands), so passing it is always
// safe. ABSENT this option the resolution is byte-identical to today.
func WithPostureElection(p postureElectionResolver) ResolveOption {
	return func(o *resolveOpts) { o.posture = p }
}

// Attendedness is the D78 attendedness signal the routing entry dispatches on. It
// is the orchestrator-computed signal (doc 16 §8.1: "the orchestrator owns
// computing the signal and pushing it host-ward"), PASSED IN to this decision —
// the routing owns what attended MEANS for dispatch (§8.2), not how it is computed.
type Attendedness int

const (
	// AttendednessUnknown is the zero value: the signal was not supplied. It is
	// treated as UNATTENDED (fail-closed: never assume a human is watching).
	AttendednessUnknown Attendedness = iota
	// AttendednessAttended = a human holds the one writer seat and produced input
	// within the D78 T-window (org-tunable POL-1 value). Spectators never count.
	AttendednessAttended
	// AttendednessUnattended = no attending writer. New asks downgrade to immediate
	// block+log; genuine rung-2 asks park (D78/D46).
	AttendednessUnattended
)

// Attended reports whether the signal is the attended state. Only the explicit
// attended value counts; unknown/unattended are both not-attended (fail-closed).
func (a Attendedness) Attended() bool { return a == AttendednessAttended }

// AskDispatchTarget is WHERE a resolved ask is dispatched (doc 16 §8.2): the
// attended/unattended split off the D78 signal.
type AskDispatchTarget string

const (
	// AskDispatchPrompt routes to the D18 client-wrapper prompt (attended). The
	// TLS-1 attended unknown-domain 30-60s socket-hold rides this path — the VM
	// keeps running while the human decides (doc 16 §8.2 / TLS-1).
	AskDispatchPrompt AskDispatchTarget = "client_prompt"
	// AskDispatchAsyncNotify routes to an async notification (unattended). A genuine
	// rung-2 ask PARKS per the D46 tiered budget and resumes on answer — never times
	// out into allow or kill (doc 16 §8.2 / D46). Modeled here as the unattended
	// target; the park/resume bookkeeping is the orchestrator-doc seam.
	AskDispatchAsyncNotify AskDispatchTarget = "async_notify"
)

// AskResolution is the resolved routing decision for one inbound ask: the approver
// to attribute (resolved per the default-approver / allow-always rule), the
// dispatch target (resolved off the D78 signal), and the session the ask is scoped
// to. It is the input the caller hands to RouteAskDecision once the human answers,
// and the value askevents.go projects onto the identity-plane ask events.
type AskResolution struct {
	// SessionUUID is the asking session (from the inbound AskUserRequest's
	// SessionRef) — the §8.2 / §4.3 scope key carried onto every ask event.
	SessionUUID string
	// ApproverPrincipalID is the resolved approver to attribute: the launching user
	// for allow-once / a genuine ask, or the org-admin acceptor for allow-always
	// (D45). Stamped onto AskApproved/AskDenied (askevents.go).
	ApproverPrincipalID string
	// EscalatedToOrgAdmin reports whether the approver was resolved via the D45
	// allow-always org-admin escalation (true) versus the launching-user default
	// (false). Audit/telemetry signal; the attribution itself rides
	// ApproverPrincipalID.
	EscalatedToOrgAdmin bool
	// Target is the attended->prompt / unattended->async-notify dispatch (§8.2),
	// resolved off the passed-in D78 attendedness signal.
	Target AskDispatchTarget
	// ResourceKind / ResourceName carry the boundary-side ask payload (the FQDN /
	// service id and its kind) verbatim from the inbound AskUserRequest, so the
	// identity-plane events tag the same resource the boundary asked about (§8.2).
	ResourceKind string
	ResourceName string
}

// ErrNoSession is returned when an inbound AskUserRequest carries no session (a nil
// SessionRef or empty session_uuid): there is nothing to scope the ask to and no
// way to resolve the launching user — fail-closed.
var ErrNoSession = fmt.Errorf("policylog: ask request carries no session (cannot resolve approver)")

// ErrNoDefaultApprover is returned when the asking session has no launching
// principal to resolve as the default approver (the nullable pre-mint /
// system-session case). An ask cannot be attributed to a fabricated approver, so
// the routing fails closed rather than inventing one.
var ErrNoDefaultApprover = fmt.Errorf("policylog: session has no launching principal to act as default approver (D45)")

// ErrNoOrgAdminAcceptor is returned when an ALLOW-ALWAYS ask finds no eligible
// org-admin to accept the escalation (doc 16 §8.2 / D45 fail-closed). Allow-always
// must NOT fall back to the launching user, so with no eligible org-admin the
// routing refuses to resolve an approver.
var ErrNoOrgAdminAcceptor = fmt.Errorf("policylog: no eligible org-admin acceptor for allow-always escalation (D45 fail-closed)")

// ResolveAskRouting is the ASK-ROUTING ENTRY (doc 16 §8.2): given the inbound
// FROZEN one-way boundaryv1.AskUserRequest, the human's DECISION CLASS (which
// governs whether the approver is the launching-user default or the D45
// org-admin escalation), and the PASSED-IN D78 attendedness signal, it resolves the
// approver to attribute and the dispatch target. It is a pure decision over the
// injected resolvers; it writes nothing and introduces no second response contract.
//
// Approver resolution (doc 16 §8.2 / D45):
//   - allow-once / deny / a genuine rung-2 ask: the DEFAULT APPROVER = the launching
//     user, resolved through ResolveLaunchingUserClaim. No launching principal
//     (ok == false) is ErrNoDefaultApprover — fail-closed, never a fabricated
//     approver.
//   - allow-always: ESCALATES to an org-admin acceptor via ResolveOrgAdminAcceptor
//     (posture-delegable, the resolver's concern). No eligible org-admin
//     (ok == false) is ErrNoOrgAdminAcceptor — fail-closed, never a silent fallback
//     to the launching user.
//
// Dispatch resolution (doc 16 §8.2 / D78): attended -> AskDispatchPrompt (the TLS-1
// socket-hold rides it), unattended/unknown -> AskDispatchAsyncNotify (a genuine
// rung-2 ask parks per D46). The split keys off the passed-in signal only.
//
// Posture delegation (doc 16 §8.2 / D45 "delegable by posture"): an OPTIONAL
// posture-election seam (WithPostureElection) is consulted FIRST for an allow-always
// ask and OVERRIDES which eligible org-admin the grant attributes to; it falls back
// to the lowest-id org-admin default (ResolveOrgAdminAcceptor) on no override. The
// seam is a trailing variadic option so this signature is UNCHANGED for the landed
// ResolveAndRoute / AskRoutingFromResolution callers — with no option supplied the
// resolution is byte-identical to the lowest-id default.
func ResolveAskRouting(
	ctx context.Context,
	r askApproverResolver,
	ask *boundaryv1.AskUserRequest,
	decision AskDecision,
	attended Attendedness,
	opts ...ResolveOption,
) (AskResolution, error) {
	var o resolveOpts
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	if ask == nil {
		return AskResolution{}, ErrNoSession
	}
	sessionUUID := ask.GetSession().GetSessionUuid()
	if sessionUUID == "" {
		return AskResolution{}, ErrNoSession
	}

	res := AskResolution{
		SessionUUID:  sessionUUID,
		Target:       dispatchTarget(attended),
		ResourceKind: ask.GetResourceKind(),
		ResourceName: ask.GetResourceName(),
	}

	if decision == AskDecisionAllowAlways {
		// D45: allow-always escalates to org-admin acceptance (posture-delegable).
		admin, ok, err := electOrgAdminAcceptor(ctx, r, o.posture, sessionUUID)
		if err != nil {
			return AskResolution{}, err
		}
		if !ok {
			return AskResolution{}, ErrNoOrgAdminAcceptor // fail-closed, no launching-user fallback
		}
		res.ApproverPrincipalID = admin.ID
		res.EscalatedToOrgAdmin = true
		return res, nil
	}

	// Default approver = the launching user (allow-once / deny / genuine ask).
	claim, ok, err := r.ResolveLaunchingUserClaim(ctx, sessionUUID)
	if err != nil {
		return AskResolution{}, fmt.Errorf("resolve launching user for session %s: %w", sessionUUID, err)
	}
	if !ok {
		return AskResolution{}, ErrNoDefaultApprover // fail-closed, no fabricated approver
	}
	res.ApproverPrincipalID = claim.PrincipalID
	return res, nil
}

// electOrgAdminAcceptor resolves the org-admin acceptor for an allow-always ask (the
// D45 escalation), consulting the OPTIONAL posture-election seam FIRST and falling
// back to the store's lowest-id default. This is the posture-delegation point (D45
// "delegable by posture"): the posture layer overrides WHICH eligible org-admin is
// elected without the store resolver being re-touched.
//
//   - posture != nil and it returns an override (ok==true): that elected acceptor
//     wins — the posture delegation chose WHICH eligible org-admin, ahead of lowest-id.
//   - posture is nil, or it returns ok==false (no override for this session): FALL BACK
//     to ResolveOrgAdminAcceptor (the lowest-id fail-closed default). With no posture
//     seam this is the ONLY path taken — byte-identical to before.
//   - a posture-lookup error surfaces wrapped and short-circuits: a posture layer that
//     errors must NOT silently degrade to the lowest-id default.
//
// A returned ok==false from BOTH the posture seam and the store default is the D45
// fail-closed case the caller maps to ErrNoOrgAdminAcceptor (no launching-user
// fallback).
func electOrgAdminAcceptor(
	ctx context.Context,
	r orgAdminResolver,
	posture postureElectionResolver,
	sessionUUID string,
) (store.Principal, bool, error) {
	if posture != nil {
		admin, ok, err := posture.ElectOrgAdminAcceptor(ctx, sessionUUID)
		if err != nil {
			return store.Principal{}, false, fmt.Errorf("posture-elect org-admin acceptor for session %s: %w", sessionUUID, err)
		}
		if ok {
			return admin, true, nil // posture override wins, ahead of the lowest-id default
		}
		// ok==false → no posture override; fall through to the store's lowest-id default.
	}
	admin, ok, err := r.ResolveOrgAdminAcceptor(ctx, sessionUUID)
	if err != nil {
		return store.Principal{}, false, fmt.Errorf("resolve org-admin acceptor for session %s: %w", sessionUUID, err)
	}
	return admin, ok, nil
}

// dispatchTarget maps the D78 attendedness signal to the §8.2 dispatch split:
// attended -> the client-wrapper prompt (TLS-1 socket-hold rides it), everything
// else (unattended / unknown) -> async notification (a genuine rung-2 ask parks per
// D46). Fail-closed: only the explicit attended state routes to the prompt.
func dispatchTarget(a Attendedness) AskDispatchTarget {
	if a.Attended() {
		return AskDispatchPrompt
	}
	return AskDispatchAsyncNotify
}
