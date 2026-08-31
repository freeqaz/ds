// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"errors"
	"fmt"
)

// This file is the OFFBOARDING fallback ladder of doc 16 §11.2 — the seam that
// lets a human deprovisioned at the IdP have their live agents stopped. The path
// degrades gracefully by what the IdP exposes (§11.2 "Offboarding — the fallback
// ladder"):
//
//  1. SCIM / session-revocation signals where available — the platform
//     subscribes (Subscriber seam below) and marks the principal disabled at the
//     lowest latency.
//  2. Re-check at grant issuance (THE UNIVERSAL FLOOR) — where push signals are
//     absent (or belt-and-suspenders), RecheckActive re-validates the subject
//     against the IdP at every grant issuance / re-auth, so a deprovisioned human
//     stops receiving new grants and a removed group drops its role. This rung
//     needs no IdP push support, so it holds for every OIDC provider.
//  3. Live-session suspension via the EXISTING suspend signal — on a confirmed
//     offboarding the platform fires the existing D35 SUSPENDED(reason) signal
//     against that user's live sessions (SuspendSink below). NO new state is
//     introduced: this is wired as DATA/INTERFACE onto the landed suspend signal
//     (orchestrator/internal/store SessionSuspended / SuspendReason "user").
//
// How deep the revocation propagates is doc 16 §14 OQ10 (IdP-revocation
// propagation depth) and is OPEN. This spec adopts the proposed default
// (SCIM-where-available, grant-issuance re-check as the universal floor,
// live-session suspension on confirmed offboarding) and does NOT deepen it.

// ErrOffboarding wraps a fault in the offboarding ladder (a re-check that could
// not reach the IdP, a suspend-sink failure). It is distinct from ErrAuth so a
// caller can tell "could not confirm active" from "the human failed to auth".
var ErrOffboarding = errors.New("idp: offboarding ladder error")

// OffboardingSignal is one inbound IdP deprovisioning event (rung 1). It is the
// SHAPE the Subscriber delivers — a SCIM `active=false`/delete or an IdP
// session-revocation/risk event, normalized to the (subject, org) the §3.2
// principal is keyed on. Kind is advisory provenance for the audit trail.
type OffboardingSignal struct {
	Org     string
	Subject string // the OIDC `sub` of the deprovisioned human
	Kind    SignalKind
}

// SignalKind tags an OffboardingSignal's provenance (audit only; the platform
// reacts identically — it marks the principal disabled and suspends live
// sessions — regardless of which kind arrives).
type SignalKind string

const (
	SignalSCIMDeprovision  SignalKind = "scim_deprovision"  // SCIM active=false / DELETE
	SignalSessionRevoked   SignalKind = "session_revoked"   // IdP session-revocation event
	SignalRiskDeactivation SignalKind = "risk_deactivation" // IdP risk-driven deactivation
)

// Subscriber is the rung-1 seam: the IdP-signal source the platform subscribes
// to WHERE AVAILABLE (SCIM / session-revocation). It is an interface, not a
// concrete client, because IdPs differ — Okta SCIM, an Entra subscription, etc.
// are each a config-side implementation behind this one seam (the D55 "config,
// not code" property). An IdP with no such signal source simply has no
// Subscriber wired, and the ladder rests on rung 2 (the universal floor).
//
// Subscribe blocks delivering signals to handle until ctx is cancelled or the
// source ends; it returns the terminating error (nil on clean ctx cancel). This
// is the seam shape only — a concrete SCIM/webhook subscriber is a config-side
// follow-on (and would live in the paid brokerage per D85), not built here.
type Subscriber interface {
	Subscribe(ctx context.Context, handle func(OffboardingSignal) error) error
}

// SuspendSink is the rung-3 seam onto the EXISTING suspend signal (doc 16 §11.2
// step 3; D35 SUSPENDED(reason)). The orchestrator implements it over its landed
// state machine (orchestrator/internal/store SessionSuspended + SuspendReason
// "user", via the suspend choreography) — this module wires the CALL as
// DATA/INTERFACE and introduces NO new state. SuspendUserSessions fires the
// existing signal against every live session of (org, subject); grants evict on
// suspend (§5.4) and rung-conditional flush_session severs established flows
// (D68/D72, the revocation-latency chain — cited, never re-implemented here).
//
// It is deliberately the narrow one-method seam the offboarding path needs, not
// the orchestrator's full store: identity/idp must not import the orchestrator,
// so the concrete sink is injected by the platform wiring (the auth side).
type SuspendSink interface {
	SuspendUserSessions(ctx context.Context, org, subject, reason string) error
}

// SuspendReasonUser is the D35 SUSPENDED(reason) value an offboarding suspension
// carries. It mirrors orchestrator/internal/store.SuspendReasonUser token-for-
// token (the value crosses the seam as DATA, the same discipline the launching_
// user claim crosses the proto seam as data) — an offboarded human's sessions
// are suspended under the existing "user" reason, NOT a new offboarding state.
const SuspendReasonUser = "user"

// ActiveChecker is the rung-2 seam: it re-validates that a subject is still
// active at the IdP (and re-reads group claims) at grant issuance (doc 16 §11.2
// rung 2, the universal floor). Where the IdP exposes a user-status / SCIM-read
// endpoint, a config-side implementation checks it; otherwise the natural floor
// is that the next device-code/refresh re-auth re-checks status and groups (a
// deprovisioned human cannot complete that re-auth). This seam lets the grant
// path re-check WITHOUT a full re-auth where the IdP supports a status read.
//
// CheckActive returns the human's current active flag and current roles (the
// re-read group→role mapping). A removed group drops its role at the next
// issuance; a deactivated user returns active=false, so the grant path denies
// the new grant. ctx-scoped; a transport fault is ErrOffboarding (the grant path
// fails closed — it does not issue a grant it could not re-validate).
type ActiveChecker interface {
	CheckActive(ctx context.Context, org, subject string) (active bool, roles []PlatformRole, err error)
}

// Offboarder assembles the ladder. It holds the optional rung-1 Subscriber, the
// rung-2 ActiveChecker (the universal floor), and the rung-3 SuspendSink. The
// platform wires a concrete sink (the orchestrator's suspend signal) and the
// available checker/subscriber; an IdP with no push signal leaves Subscriber nil
// and the ladder rests on the floor.
type Offboarder struct {
	org        string
	subscriber Subscriber    // rung 1 (optional; nil where the IdP has no signal)
	checker    ActiveChecker // rung 2 (the universal floor)
	sink       SuspendSink   // rung 3 (the existing suspend signal)
}

// NewOffboarder constructs the ladder for an org. checker (rung 2) and sink
// (rung 3) are required — they are the floor and the action; subscriber (rung 1)
// is optional. A nil checker or sink is a wiring fault (ErrOffboarding).
func NewOffboarder(org string, checker ActiveChecker, sink SuspendSink, subscriber Subscriber) (*Offboarder, error) {
	if checker == nil {
		return nil, fmt.Errorf("%w: an ActiveChecker (rung 2, the universal floor) is required", ErrOffboarding)
	}
	if sink == nil {
		return nil, fmt.Errorf("%w: a SuspendSink (rung 3, the existing suspend signal) is required", ErrOffboarding)
	}
	return &Offboarder{org: org, subscriber: subscriber, checker: checker, sink: sink}, nil
}

// RecheckActive is rung 2 (the universal floor): it re-validates subject at the
// IdP at grant issuance and returns whether a NEW grant may issue plus the
// re-read roles. A deprovisioned human (active=false) returns ok=false, so the
// grant path denies and — because the human is confirmed off — escalates to a
// live-session suspension (the caller chains to ConfirmOffboarding). A removed
// group simply returns fewer roles; the principal's role set narrows at the next
// upsert. A checker transport fault is surfaced (fail-closed: no grant issues on
// an unverifiable subject).
func (o *Offboarder) RecheckActive(ctx context.Context, subject string) (ok bool, roles []PlatformRole, err error) {
	active, roles, err := o.checker.CheckActive(ctx, o.org, subject)
	if err != nil {
		return false, nil, fmt.Errorf("%w: re-check at grant issuance for %q: %v", ErrOffboarding, subject, err)
	}
	return active, roles, nil
}

// ConfirmOffboarding is rung 3: on a confirmed offboarding it fires the EXISTING
// suspend signal against the human's live sessions (SUSPENDED(user)). It is the
// single action the ladder takes — whether the offboarding was detected by a
// rung-1 push signal or a rung-2 re-check, the response is this one existing
// signal, NOT a new state. Resume authority for an offboarding suspension is
// human approval per the §8.2 parking model (an offboarded user's sessions do
// not silently resume) — that authority lives with the suspend choreography the
// sink fronts, not here.
func (o *Offboarder) ConfirmOffboarding(ctx context.Context, subject string) error {
	if err := o.sink.SuspendUserSessions(ctx, o.org, subject, SuspendReasonUser); err != nil {
		return fmt.Errorf("%w: suspend live sessions for %q: %v", ErrOffboarding, subject, err)
	}
	return nil
}

// WatchSignals runs rung 1 where a Subscriber is wired: it subscribes to IdP
// deprovisioning signals and, on each, confirms the offboarding (fires the
// suspend signal). It blocks until ctx is cancelled or the source ends. With no
// Subscriber wired it returns immediately — the ladder rests on rungs 2–3. A
// per-signal suspend failure is surfaced through the handler's error so the
// subscriber's retry policy (config-side) governs; the watch itself continues.
func (o *Offboarder) WatchSignals(ctx context.Context) error {
	if o.subscriber == nil {
		return nil // no push source; the floor (rung 2) carries offboarding
	}
	return o.subscriber.Subscribe(ctx, func(sig OffboardingSignal) error {
		if sig.Org != "" && sig.Org != o.org {
			return nil // not our org
		}
		return o.ConfirmOffboarding(ctx, sig.Subject)
	})
}
