// SPDX-License-Identifier: Apache-2.0

package policylog

// This file is the LIVE ASK-ROUTING CALL-SITE on the in-process PolicyService
// (doc 15 §4.3 / §6.2 step 4, doc 16 §8.2): it WIRES the three wave-1 decision
// libraries — which until now shipped as pure functions with NO production
// caller — into one method on Service that takes an inbound, frozen, one-way
// boundaryv1.AskUserRequest and runs it through the full
//
//	resolve -> dispatch -> approve/deny/hold -> LOG-1 emit
//
// flow, replacing the placeholder where Service exposed only the gate-only
// ApproveAsk leg. It is the single integration step that makes the wave valuable
// end to end (the resolve/denymemo/holds units are otherwise un-called).
//
// The legs, in order (each delegating to an already-landed library — this file
// adds NO new decision logic, only the call-site that strings them together):
//
//  1. RESOLVE (askroute_resolve.go): ResolveAskRouting turns the inbound ask +
//     the human's decision class + the D78 attendedness signal into the approver
//     to attribute (the launching user, or the org-admin acceptor for an
//     allow-always per D45) and the §8.2 dispatch target
//     (client_prompt / async_notify). Fail-closed on no session / no default
//     approver / no eligible org-admin.
//  2. DISPATCH (askhold.go): off the SAME attendedness signal + the injected
//     POL-1 Window/PauseBudget, askhold.Decide computes the TLS-1 socket-hold vs
//     immediate block+log for an ordinary unknown-domain ask, and a GENUINE
//     rung-2 ask drives the untimed D46 park through the injected park seam
//     (NewParked / Resume off a human answer) — never timing out into allow/kill.
//     The dispatch is the WHERE; it opens no socket itself (the boundary owns the
//     mechanics) and writes no grant (an approval lands out-of-band on the policy
//     stream).
//  3. APPROVE/DENY (askrouting.go + denymemo.go): the human's verdict routes
//     through RouteAskDecision — an ALLOW appends the attributed ask-grant
//     (gated on MayApprove inside ApproveAsk), a DENY carrying a D77
//     machine-readable reason appends the session-scoped deny memo AND, before
//     re-prompting, a retry FAST-FAILS against a live recorded deny memo
//     (LiveDenyMemo) so no fresh ask and ZERO new allow grant result.
//  4. LOG-1 EMIT (askevents.go): the resolved ask projects onto the identity-plane
//     ProjectAsk{Issued,Approved,Denied} LOG-1 events and is handed to the
//     injected telemetry sink — fingerprint/metadata only, never credential
//     material (doc 16 §9).
//
// It is STRICTLY ADDITIVE: no proto edit, no second response contract (doc 16
// §8.2 — approvals return solely as TTL'd allow grants on the policy stream), no
// new store column. Every injected seam is a narrow interface a synthetic fake
// satisfies (D50); the LIVE store impls (*store.Memory / *store.Postgres) back
// the resolver/router/deny-memo seams directly. Honors D45/D46/D77/D78/TLS-1
// exactly as the libraries encode them.

import (
	"context"
	"fmt"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// AskEventSink is the LOG-1 telemetry seam the ask-routing call-site emits onto
// (doc 16 §9): one call per projected identity-plane ask event, in flow order
// (Issued first, then Approved or Denied). The ds-flowlog / LOG-5 adapter
// satisfies it by relaying each event onto the log_events stream; a test
// satisfies it by collecting the projections. The events are fingerprint /
// metadata only — the session join key, the resource metadata, the approver
// principal handle, and a deny reason string — never any credential material.
//
// Emit errors are surfaced by the caller of EmitX but never block the policy
// write that already happened: the routing decision and the grant/memo are the
// system of record, the LOG-1 projection is an observation. A nil sink is
// tolerated (the projection is computed and discarded) so the call-site is
// usable before the telemetry adapter is wired.
type AskEventSink interface {
	AskIssued(ctx context.Context, ev *identityv1.AskIssued) error
	AskApproved(ctx context.Context, ev *identityv1.AskApproved) error
	AskDenied(ctx context.Context, ev *identityv1.AskDenied) error
}

// askParkRouter is the OPTIONAL injected seam that enters a GENUINE rung-2 ask
// into the durable D46 park (the untimed park/resume machine, owned by the
// control plane's parkMachine over askhold.NewParked/Resume — doc 16 §8.2). The
// ask-routing call-site DECIDES that a rung-2 ask parks (off ask.Rung2) and
// hands it to this seam; it does NOT own the durable join (that is the
// orchestrator-doc parkstore seam). The control plane's *parkMachine satisfies
// this exact shape (Park(sessionUUID, ask, now)); a test satisfies it by
// recording the entered parks.
//
// It is OPTIONAL: when no park router is injected the call-site still computes
// the rung-2 dispatch decision (DispatchPark) but enters no durable park — the
// decision stands, only the durable enrollment is skipped (the same nil-tolerant
// posture askhold.NewParked itself takes). This keeps policylog free of a hard
// dependency on the control-plane park machine while letting the live wiring
// inject it.
type askParkRouter interface {
	Park(sessionUUID string, ask askhold.Ask, now time.Time) (askhold.Parked, error)
}

// AskDispatch is the resolved WHERE for an inbound ask, computed off the D78
// attendedness signal + the injected POL-1 budget (doc 16 §8.2). It carries the
// §8.2 routing target (from ResolveAskRouting) AND the askhold dispatch decision
// (the socket-hold-vs-block verb for an ordinary ask, or the park enrollment for
// a genuine rung-2 ask), so the caller sees both the attribution-side target and
// the boundary-side disposition in one value.
type AskDispatch struct {
	// Target is the §8.2 attended->client_prompt / unattended->async_notify
	// dispatch resolved by ResolveAskRouting off the attendedness signal.
	Target AskDispatchTarget

	// Hold is the askhold socket-hold-vs-block decision for an ORDINARY
	// unknown-domain ask (attended -> OutcomeHold for the POL-1 Window total,
	// unattended -> OutcomeBlockLog with the D77 reason). It is the zero Decision
	// when the ask is a genuine rung-2 ask (those park, not socket-hold).
	Hold askhold.Decision

	// Parked carries the entered D46 park when the ask is a GENUINE rung-2 ask
	// AND a park router was injected (DispatchPark true). It is the zero Parked
	// otherwise. The park is UNTIMED — it resumes only on a human answer, never on
	// a clock (D46/D77).
	Parked askhold.Parked

	// DispatchPark reports whether this ask took the rung-2 PARK path (true) vs
	// the ordinary socket-hold/block path (false). It is computed off ask.Rung2,
	// independent of whether a park router was injected — so a caller can see "this
	// was a rung-2 ask" even when no durable park backing is wired.
	DispatchPark bool
}

// AskFlowResult is the outcome of one routed inbound ask: the resolution (who
// approves + the §8.2 target), the dispatch disposition (the askhold decision /
// park), and the policy-log write outcome (granted / denied / fast-failed). It is
// the single value the in-process PolicyService.RouteAsk hands back to the gRPC
// adapter (and the value a test asserts against).
type AskFlowResult struct {
	// Resolution is the resolved approver + dispatch target + resource metadata
	// (ResolveAskRouting output). Stamped onto the LOG-1 events.
	Resolution AskResolution

	// Dispatch is the resolved WHERE (target + askhold hold/park disposition).
	Dispatch AskDispatch

	// Routing is the policy-log write outcome (RouteAskDecision result): Granted
	// when an allow grant was appended, Denied when a deny memo was appended, the
	// zero result for a no-write deny or a fast-fail.
	Routing AskRoutingResult

	// FastFailed is true when the ask SHORT-CIRCUITED on a live recorded deny memo
	// (LiveDenyMemo, D118): the retry fast-fails on the prior denial, NO fresh ask
	// is routed and ZERO new allow grant is written. When true, Routing is the zero
	// result and FastFailReason carries the D77 machine-readable reason.
	FastFailed bool

	// FastFailReason is the D77 machine-readable reason a fast-failed retry carries
	// (from the live deny memo). Empty unless FastFailed.
	FastFailReason string
}

// askRouteRouter is the seam composition RouteAsk holds for the WRITE direction:
// the approver lookup + the policy append (askRouter, for RouteAskDecision) PLUS
// the deny-memo read (denyMemoReader, for the LiveDenyMemo fast-fail). Both store
// impls (*store.Memory / *store.Postgres) satisfy all three; a test pairs the
// synthetic fakes. It is deliberately the UNION of the existing narrow seams — it
// adds NO method to any frozen surface.
type askRouteRouter interface {
	askRouter
	denyMemoReader
}

// RouteAskParams carries the inputs of one inbound-ask routing pass that are not
// the request itself: the human's decision class, the D78 attendedness signal,
// the rung-2 classification, the injected POL-1 budget, the consent class to tag
// the LOG-1 events with, and the grant/deny body the ask path composed. It groups
// them so RouteAsk's signature stays readable and additive (new optional inputs
// ride here, never a positional break).
type RouteAskParams struct {
	// Decision is the human's §6.2 choice (allow-once / allow-always / deny). It
	// governs BOTH the approver resolution (allow-always -> org-admin escalation,
	// D45) and the allow-vs-deny write dispatch — passed once, used for both halves
	// so resolution and routing can never be computed for two different choices.
	Decision AskDecision

	// Attended is the D78 attendedness signal the orchestrator computed and passed
	// in (doc 16 §8.1). It forks BOTH the §8.2 dispatch target and the askhold
	// socket-hold-vs-block decision. Fail-closed: unknown is treated as unattended.
	Attended Attendedness

	// Rung2 marks a GENUINE rung-2 ask (a blocklist hit / an explicit suspend rule,
	// D77) — the class that PARKS per D46 rather than taking the TLS-1 socket-hold.
	// Ordinary unknown-domain asks leave it false.
	Rung2 bool

	// Window is the injected POL-1 TLS-1 socket-hold budget (notify+decision+commit)
	// askhold.Decide opens the hold for; never a hardcoded constant (doc 16 §8.2).
	Window askhold.Window

	// Consent is the reserved D60/D119 consent class tag carried onto the LOG-1 ask
	// events (doc 16 §9). Defaults to unspecified.
	Consent boundaryv1.AskConsentClass

	// Body is the grant/deny body the ask path composed (the matched rule, TTL,
	// reserved consent class, payload, and any D77/D118 deny reason). It describes
	// WHAT is granted/denied, never WHO grants it — the approver is the resolution's
	// to fill (the structural separation that closes the D45 footgun).
	Body GrantBody
}

// RouteAsk is the LIVE ask-routing call-site (doc 15 §4.3 / §6.2 step 4, doc 16
// §8.2): it takes the inbound, frozen, one-way boundaryv1.AskUserRequest and runs
// the full resolve -> dispatch -> approve/deny/hold -> LOG-1 emit flow, returning
// the AskFlowResult. It is the method the PolicyService.ApproveAsk RPC adapts to
// when the proto lands (PolicyService is unfrozen; this is the in-process shape).
//
// The flow, in order:
//
//   - DENY FAST-FAIL (D118): a DENY decision first consults the LIVE session-scoped
//     deny memos (LiveDenyMemo). If a prior denial is recorded, the retry
//     FAST-FAILS — no fresh ask is resolved, no dispatch is opened, and ZERO new
//     allow grant or memo is written; the result carries FastFailed + the D77
//     reason. (Allow decisions never fast-fail; a human re-approving overrides.)
//   - RESOLVE: ResolveAskRouting computes the approver (launching user, or the
//     org-admin acceptor for allow-always per D45) + the §8.2 dispatch target off
//     the attendedness signal. A fail-closed resolution error (no session / no
//     default approver / no eligible org-admin) short-circuits before any write.
//   - LOG-1 ISSUED: the resolved ask projects onto AskIssued and is emitted (the
//     ask was raised; no approver stamped yet).
//   - DISPATCH: off the attendedness signal + the POL-1 Window, a GENUINE rung-2
//     ask enters the untimed D46 park (via the injected park router, when present);
//     an ordinary ask gets the askhold socket-hold-vs-block decision. The dispatch
//     opens no socket and writes no grant — it is the WHERE.
//   - VERDICT: RouteAskDecision routes the human's decision into the policy_log
//     write (an allow appends the attributed ask-grant, a deny+reason appends the
//     deny memo, a bare deny writes nothing — the no-allow-grant guarantee is
//     absolute).
//   - LOG-1 APPROVED/DENIED: the verdict projects onto AskApproved (on a grant) or
//     AskDenied (on a deny, carrying the D77 reason) and is emitted.
//
// A LOG-1 emit error is surfaced (the projection is part of the audit obligation)
// but only AFTER the policy write it observes has landed — the write is the system
// of record. A nil sink skips the emit. A nil park router skips the durable park
// enrollment (the dispatch decision still stands).
func (s *Service) RouteAsk(
	ctx context.Context,
	router askRouteRouter,
	resolver askApproverResolver,
	sink AskEventSink,
	park askParkRouter,
	ask *boundaryv1.AskUserRequest,
	p RouteAskParams,
) (AskFlowResult, error) {
	if ask == nil {
		return AskFlowResult{}, ErrNoSession
	}
	now := s.now()

	// (0) DENY FAST-FAIL (D118): a retry of an already-denied ask short-circuits on
	// the live recorded deny memo — no fresh ask, no dispatch, ZERO new allow grant.
	if p.Decision == AskDecisionDeny {
		sessionUUID := ask.GetSession().GetSessionUuid()
		if sessionUUID != "" {
			memoRow, denied, err := LiveDenyMemo(ctx, router, sessionUUID, now)
			if err != nil && !denied {
				// A read fault (not the fast-fail sentinel) is surfaced — never
				// silently treated as "no memo" (that would re-prompt the human).
				return AskFlowResult{}, fmt.Errorf("ask deny fast-fail check for session %s: %w", sessionUUID, err)
			}
			if denied {
				// The prior denial governs: fast-fail with the recorded D77 reason,
				// writing nothing. The grant count is unchanged (zero new allow).
				return AskFlowResult{
					FastFailed:     true,
					FastFailReason: denyMemoReason(memoRow),
				}, nil
			}
		}
	}

	// (1) RESOLVE: who approves + the §8.2 dispatch target (fail-closed on errors).
	res, err := ResolveAskRouting(ctx, resolver, ask, p.Decision, p.Attended)
	if err != nil {
		return AskFlowResult{}, err
	}

	result := AskFlowResult{Resolution: res}

	// (2) LOG-1 ISSUED: the ask was raised (no approver stamped yet).
	if sink != nil {
		if err := sink.AskIssued(ctx, ProjectAskIssued(res, p.Consent)); err != nil {
			return AskFlowResult{}, fmt.Errorf("emit AskIssued for session %s: %w", res.SessionUUID, err)
		}
	}

	// (3) DISPATCH: rung-2 parks (untimed, D46); an ordinary ask socket-holds/blocks.
	result.Dispatch = s.dispatch(res, ask, p, park, now)

	// (4) VERDICT: route the human's decision into the policy_log write.
	routing, err := RouteAskDecision(ctx, router, AskRoutingFromResolution(
		res, p.Decision, p.Body.Rule, p.Body.ExpiresAt, p.Body.Consent, p.Body.Payload, p.Body.DenyReason))
	if err != nil {
		return AskFlowResult{}, err
	}
	result.Routing = routing

	// (5) LOG-1 APPROVED / DENIED: stamp the verdict onto the identity events.
	if sink != nil {
		if err := s.emitVerdict(ctx, sink, res, p, routing); err != nil {
			return AskFlowResult{}, err
		}
	}

	return result, nil
}

// dispatch computes the WHERE for the inbound ask (doc 16 §8.2): a GENUINE rung-2
// ask enters the untimed D46 park (via the injected router when present — the
// decision stands either way); an ordinary unknown-domain ask gets the askhold
// socket-hold-vs-block decision off the attendedness signal + the POL-1 Window.
// It opens no socket and writes no grant — it is purely the disposition decision.
//
// The askhold.Ask is projected DIRECTLY from the frozen inbound request via
// askhold.FromProto (so the POL-3 matched_rule_id rides onto the deny reason),
// not from the AskResolution — the resolution is the attribution decision (who
// approves + where it routes), and the matched-rule-id is the boundary's payload
// the dispatch reads read-only.
func (s *Service) dispatch(res AskResolution, ask *boundaryv1.AskUserRequest, p RouteAskParams, park askParkRouter, now time.Time) AskDispatch {
	d := AskDispatch{Target: res.Target}
	hAsk := askhold.FromProto(ask, p.Rung2)

	if p.Rung2 {
		// Genuine rung-2 ask -> untimed park (D46). The routing DECIDES the park;
		// the durable join is the injected park router's (nil-tolerant: the decision
		// stands, only the durable enrollment is skipped).
		d.DispatchPark = true
		if park != nil {
			if parked, err := park.Park(res.SessionUUID, hAsk, now); err == nil {
				d.Parked = parked
			}
			// A park error never un-parks the ask (askhold guarantees the PARKED
			// safe state on a record fault); the dispatch still reports DispatchPark.
		}
		return d
	}

	// Ordinary unknown-domain ask -> the TLS-1 socket-hold vs immediate block+log
	// decision off the attendedness signal + the injected POL-1 Window.
	d.Hold = askhold.Decide(hAsk, askhold.Attendedness{
		Attended: p.Attended.Attended(),
		AsOf:     now,
	}, p.Window, now)
	return d
}

// emitVerdict projects the routed verdict onto the LOG-1 identity events and emits
// it: AskApproved on a grant (carrying the resolved approver — the org-admin for
// an allow-always, the launcher otherwise), AskDenied on a deny (carrying the
// approver + the D77 machine-readable reason). A no-write deny / unrecognized
// decision emits nothing past Issued (there is no verdict to attribute).
func (s *Service) emitVerdict(
	ctx context.Context,
	sink AskEventSink,
	res AskResolution,
	p RouteAskParams,
	routing AskRoutingResult,
) error {
	switch {
	case routing.Granted:
		if err := sink.AskApproved(ctx, ProjectAskApproved(res, p.Consent)); err != nil {
			return fmt.Errorf("emit AskApproved for session %s: %w", res.SessionUUID, err)
		}
	case routing.Denied:
		if err := sink.AskDenied(ctx, ProjectAskDenied(res, p.Body.DenyReason, p.Consent)); err != nil {
			return fmt.Errorf("emit AskDenied for session %s: %w", res.SessionUUID, err)
		}
	}
	return nil
}

// Compile-time proof that the LIVE store impls back the ask-routing WRITE seam
// (the approver lookup + policy append + deny-memo read RouteAsk consumes): both
// *store.Memory and *store.Postgres satisfy askRouteRouter directly, so the live
// call-site runs against the persisted record, not solely a synthetic fake.
var (
	_ askRouteRouter = (*store.Memory)(nil)
	_ askRouteRouter = (*store.Postgres)(nil)
)
