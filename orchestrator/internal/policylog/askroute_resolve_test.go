// SPDX-License-Identifier: Apache-2.0

package policylog

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// approverResolverFake is a synthetic askApproverResolver: it resolves the
// launching user (the default approver) and the org-admin acceptor (the D45
// allow-always escalation) from scripted maps, so the routing entry's
// default-approver / escalation / fail-closed behavior can be asserted without a
// live store (D50). The store's own linkage semantics are covered by its
// conformance suite; this exercises only the ROUTING decision.
type approverResolverFake struct {
	// launching maps sessionUUID -> the launching-user claim (the default approver).
	// A session ABSENT from the map resolves ok==false (no launching principal —
	// the nullable pre-mint/system-session case). A session whose value is in
	// launchingErr resolves to that error (unknown session / dangling link).
	launching    map[string]store.LaunchingUserClaim
	launchingErr map[string]error

	// orgAdmin maps sessionUUID -> the eligible org-admin acceptor. A session ABSENT
	// from the map resolves ok==false (no eligible org-admin — the fail-closed
	// case). orgAdminErr scripts a lookup failure.
	orgAdmin    map[string]store.Principal
	orgAdminErr map[string]error
}

func (f approverResolverFake) ResolveLaunchingUserClaim(_ context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error) {
	if err := f.launchingErr[sessionUUID]; err != nil {
		return store.LaunchingUserClaim{}, false, err
	}
	claim, ok := f.launching[sessionUUID]
	return claim, ok, nil
}

func (f approverResolverFake) ResolveOrgAdminAcceptor(_ context.Context, sessionUUID string) (store.Principal, bool, error) {
	if err := f.orgAdminErr[sessionUUID]; err != nil {
		return store.Principal{}, false, err
	}
	admin, ok := f.orgAdmin[sessionUUID]
	return admin, ok, nil
}

// postureElectionFake is a synthetic postureElectionResolver (D45 "delegable by
// posture"): it elects a posture-delegated org-admin acceptor from a scripted map,
// so the routing entry's posture-OVERRIDE-ahead-of-lowest-id / fall-back-on-no-
// override behavior can be asserted without a live posture layer (none exists yet —
// the seam is RESERVED). A session ABSENT from the map resolves ok==false (no
// override → the routing falls back to the store's lowest-id default); electErr
// scripts a posture-lookup failure.
type postureElectionFake struct {
	elected  map[string]store.Principal
	electErr map[string]error
}

func (f postureElectionFake) ElectOrgAdminAcceptor(_ context.Context, sessionUUID string) (store.Principal, bool, error) {
	if err := f.electErr[sessionUUID]; err != nil {
		return store.Principal{}, false, err
	}
	admin, ok := f.elected[sessionUUID]
	return admin, ok, nil
}

// askReq builds a synthetic inbound boundaryv1.AskUserRequest for the given session
// and resource (the frozen one-way ask transport, doc 16 §8.2).
func askReq(sessionUUID, kind, name string) *boundaryv1.AskUserRequest {
	return &boundaryv1.AskUserRequest{
		Session:      &boundaryv1.SessionRef{SessionUuid: sessionUUID},
		ResourceKind: kind,
		ResourceName: name,
	}
}

// TestResolveAskRouting_DefaultApproverIsLaunchingUser proves the doc 16 §8.2
// default: for allow-once / deny / a genuine ask, the resolved approver is the
// LAUNCHING USER (resolved through the session->principal linkage), and the resource
// metadata rides onto the resolution verbatim.
func TestResolveAskRouting_DefaultApproverIsLaunchingUser(t *testing.T) {
	f := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			"sess-1": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
		},
	}
	for _, dec := range []AskDecision{AskDecisionAllowOnce, AskDecisionDeny} {
		got, err := ResolveAskRouting(context.Background(), f,
			askReq("sess-1", "domain", "github.com"), dec, AttendednessAttended)
		if err != nil {
			t.Fatalf("ResolveAskRouting(%s): unexpected error: %v", dec, err)
		}
		if got.ApproverPrincipalID != "p-ada" {
			t.Errorf("[%s] ApproverPrincipalID = %q, want the launching user %q", dec, got.ApproverPrincipalID, "p-ada")
		}
		if got.EscalatedToOrgAdmin {
			t.Errorf("[%s] EscalatedToOrgAdmin = true, want false for the launching-user default", dec)
		}
		if got.SessionUUID != "sess-1" || got.ResourceKind != "domain" || got.ResourceName != "github.com" {
			t.Errorf("[%s] resolution metadata = %+v, want session/kind/name carried verbatim", dec, got)
		}
	}
}

// TestResolveAskRouting_AllowAlwaysEscalatesToOrgAdmin proves the D45 allow-always
// escalation: an allow-always ask resolves the approver to the ORG-ADMIN acceptor
// (NOT the launching user), with EscalatedToOrgAdmin set.
func TestResolveAskRouting_AllowAlwaysEscalatesToOrgAdmin(t *testing.T) {
	f := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			"sess-1": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
		},
		orgAdmin: map[string]store.Principal{
			"sess-1": {ID: "p-admin", IdPSubject: "okta|admin", Org: "acme",
				Roles: []store.PrincipalRole{store.RoleOrgAdmin}},
		},
	}
	got, err := ResolveAskRouting(context.Background(), f,
		askReq("sess-1", "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended)
	if err != nil {
		t.Fatalf("ResolveAskRouting(allow-always): unexpected error: %v", err)
	}
	if got.ApproverPrincipalID != "p-admin" {
		t.Errorf("ApproverPrincipalID = %q, want the org-admin acceptor %q (D45)", got.ApproverPrincipalID, "p-admin")
	}
	if !got.EscalatedToOrgAdmin {
		t.Error("EscalatedToOrgAdmin = false, want true for an allow-always escalation")
	}
}

// TestResolveAskRouting_AllowAlwaysFailsClosedWithoutOrgAdmin proves the D45
// fail-closed rule: an allow-always ask with NO eligible org-admin acceptor is
// ErrNoOrgAdminAcceptor — it must NOT silently fall back to the launching user.
func TestResolveAskRouting_AllowAlwaysFailsClosedWithoutOrgAdmin(t *testing.T) {
	f := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			// A launching user EXISTS — proving the failure is the missing org-admin,
			// not a missing launching user, and that no fallback occurs.
			"sess-1": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
		},
		// orgAdmin map empty -> ResolveOrgAdminAcceptor returns ok==false.
	}
	_, err := ResolveAskRouting(context.Background(), f,
		askReq("sess-1", "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended)
	if !errors.Is(err, ErrNoOrgAdminAcceptor) {
		t.Fatalf("ResolveAskRouting error = %v, want ErrNoOrgAdminAcceptor (D45 fail-closed)", err)
	}
}

// TestResolveAskRouting_NoLaunchingPrincipalFailsClosed proves the §3.1 fail-closed
// rule: a session with no launching principal (the nullable pre-mint / system case)
// has no default approver — ErrNoDefaultApprover, never a fabricated approver.
func TestResolveAskRouting_NoLaunchingPrincipalFailsClosed(t *testing.T) {
	f := approverResolverFake{} // no launching principals registered
	_, err := ResolveAskRouting(context.Background(), f,
		askReq("sess-orphan", "domain", "github.com"), AskDecisionAllowOnce, AttendednessAttended)
	if !errors.Is(err, ErrNoDefaultApprover) {
		t.Fatalf("ResolveAskRouting error = %v, want ErrNoDefaultApprover", err)
	}
}

// TestResolveAskRouting_TargetSplitsOnAttendedness proves the doc 16 §8.2 / D78
// dispatch split keyed off the PASSED-IN attendedness signal: attended -> the
// client-wrapper prompt (the TLS-1 socket-hold rides it), unattended/unknown ->
// async notification (a genuine rung-2 ask parks per D46). The approver resolution
// is identical across the split (the target is the only thing that changes).
func TestResolveAskRouting_TargetSplitsOnAttendedness(t *testing.T) {
	f := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			"sess-1": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
		},
	}
	cases := []struct {
		name    string
		signal  Attendedness
		wantTgt AskDispatchTarget
	}{
		{"attended->prompt", AttendednessAttended, AskDispatchPrompt},
		{"unattended->async-notify", AttendednessUnattended, AskDispatchAsyncNotify},
		{"unknown->async-notify (fail-closed)", AttendednessUnknown, AskDispatchAsyncNotify},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveAskRouting(context.Background(), f,
				askReq("sess-1", "domain", "github.com"), AskDecisionAllowOnce, tc.signal)
			if err != nil {
				t.Fatalf("ResolveAskRouting: unexpected error: %v", err)
			}
			if got.Target != tc.wantTgt {
				t.Errorf("Target = %q, want %q for signal %v", got.Target, tc.wantTgt, tc.signal)
			}
			if got.ApproverPrincipalID != "p-ada" {
				t.Errorf("ApproverPrincipalID = %q, want the launching user regardless of attendedness", got.ApproverPrincipalID)
			}
		})
	}
}

// TestResolveAskRouting_MissingSessionFailsClosed proves the routing fails closed on
// an ask with no session (a nil request, a nil SessionRef, or an empty
// session_uuid): there is nothing to scope to and no way to resolve an approver.
func TestResolveAskRouting_MissingSessionFailsClosed(t *testing.T) {
	f := approverResolverFake{}
	cases := []struct {
		name string
		ask  *boundaryv1.AskUserRequest
	}{
		{"nil request", nil},
		{"nil session ref", &boundaryv1.AskUserRequest{ResourceKind: "domain", ResourceName: "x"}},
		{"empty session uuid", &boundaryv1.AskUserRequest{Session: &boundaryv1.SessionRef{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ResolveAskRouting(context.Background(), f, tc.ask, AskDecisionAllowOnce, AttendednessAttended)
			if !errors.Is(err, ErrNoSession) {
				t.Fatalf("ResolveAskRouting error = %v, want ErrNoSession", err)
			}
		})
	}
}

// TestResolveAskRouting_ResolverErrorsSurface proves a launching-user or org-admin
// lookup ERROR (unknown session / dangling link / lookup failure) surfaces wrapped,
// never swallowed into a silent or fabricated approver.
func TestResolveAskRouting_ResolverErrorsSurface(t *testing.T) {
	t.Run("launching-user error surfaces", func(t *testing.T) {
		f := approverResolverFake{launchingErr: map[string]error{"sess-x": store.ErrNotFound}}
		_, err := ResolveAskRouting(context.Background(), f,
			askReq("sess-x", "domain", "x"), AskDecisionAllowOnce, AttendednessAttended)
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("error = %v, want wrapping store.ErrNotFound", err)
		}
	})
	t.Run("org-admin error surfaces", func(t *testing.T) {
		f := approverResolverFake{orgAdminErr: map[string]error{"sess-x": store.ErrNotFound}}
		_, err := ResolveAskRouting(context.Background(), f,
			askReq("sess-x", "domain", "x"), AskDecisionAllowAlways, AttendednessAttended)
		if !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("error = %v, want wrapping store.ErrNotFound", err)
		}
	})
}

// TestResolveAskRouting_PostureElectionOverridesLowestIdDefault proves the D45
// "delegable by posture" seam: an INJECTED posture-election resolver is consulted
// FIRST for an allow-always ask and OVERRIDES the lowest-id org-admin default — the
// resolved approver is the posture-elected acceptor, NOT the store's lowest-id
// org-admin. EscalatedToOrgAdmin stays true (it is still the D45 org-admin
// escalation, merely a posture-delegated WHICH).
func TestResolveAskRouting_PostureElectionOverridesLowestIdDefault(t *testing.T) {
	f := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			"sess-1": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
		},
		orgAdmin: map[string]store.Principal{
			// The store's lowest-id default would elect THIS org-admin...
			"sess-1": {ID: "p-admin-low", IdPSubject: "okta|low", Org: "acme",
				Roles: []store.PrincipalRole{store.RoleOrgAdmin}},
		},
	}
	posture := postureElectionFake{
		elected: map[string]store.Principal{
			// ...but the posture layer overrides it to a DIFFERENT eligible org-admin.
			"sess-1": {ID: "p-admin-posture", IdPSubject: "okta|posture", Org: "acme",
				Roles: []store.PrincipalRole{store.RoleOrgAdmin}},
		},
	}
	got, err := ResolveAskRouting(context.Background(), f,
		askReq("sess-1", "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		WithPostureElection(posture))
	if err != nil {
		t.Fatalf("ResolveAskRouting(allow-always, posture): unexpected error: %v", err)
	}
	if got.ApproverPrincipalID != "p-admin-posture" {
		t.Errorf("ApproverPrincipalID = %q, want the POSTURE-elected acceptor %q (ahead of lowest-id %q, D45)",
			got.ApproverPrincipalID, "p-admin-posture", "p-admin-low")
	}
	if !got.EscalatedToOrgAdmin {
		t.Error("EscalatedToOrgAdmin = false, want true — a posture-delegated election is still a D45 org-admin escalation")
	}
}

// TestResolveAskRouting_NoPostureOverrideFallsBackToLowestId proves the ADDITIVE
// fall-back: when the posture seam returns NO override for the session (ok==false),
// the routing falls back to the lowest-id org-admin default — the resolution is
// BYTE-IDENTICAL to the no-posture-seam case. Asserted by comparing, value-for-value,
// the resolution WITH a non-overriding posture seam against the resolution with NO
// option at all (the landed default path).
func TestResolveAskRouting_NoPostureOverrideFallsBackToLowestId(t *testing.T) {
	f := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			"sess-1": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
		},
		orgAdmin: map[string]store.Principal{
			"sess-1": {ID: "p-admin", IdPSubject: "okta|admin", Org: "acme",
				Roles: []store.PrincipalRole{store.RoleOrgAdmin}},
		},
	}
	// A posture seam that has NO override for sess-1 (map empty → ok==false).
	posture := postureElectionFake{}

	withSeam, err := ResolveAskRouting(context.Background(), f,
		askReq("sess-1", "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		WithPostureElection(posture))
	if err != nil {
		t.Fatalf("ResolveAskRouting(allow-always, non-overriding posture): unexpected error: %v", err)
	}
	// The landed default path: NO option supplied — the byte-identical baseline.
	baseline, err := ResolveAskRouting(context.Background(), f,
		askReq("sess-1", "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended)
	if err != nil {
		t.Fatalf("ResolveAskRouting(allow-always, no option): unexpected error: %v", err)
	}
	if withSeam != baseline {
		t.Errorf("non-overriding posture seam changed the resolution:\n with seam = %+v\n baseline  = %+v\nabsent an override the resolution MUST be byte-identical to the lowest-id default",
			withSeam, baseline)
	}
	if withSeam.ApproverPrincipalID != "p-admin" {
		t.Errorf("ApproverPrincipalID = %q, want the lowest-id default %q on no posture override", withSeam.ApproverPrincipalID, "p-admin")
	}
}

// TestResolveAskRouting_NilPostureSeamIsLowestIdDefault proves a NIL injected posture
// resolver is a safe no-op (no panic) and yields the lowest-id default — the
// additive contract: supplying the option with a nil resolver behaves exactly as if
// the option were never passed.
func TestResolveAskRouting_NilPostureSeamIsLowestIdDefault(t *testing.T) {
	f := approverResolverFake{
		orgAdmin: map[string]store.Principal{
			"sess-1": {ID: "p-admin", IdPSubject: "okta|admin", Org: "acme",
				Roles: []store.PrincipalRole{store.RoleOrgAdmin}},
		},
	}
	got, err := ResolveAskRouting(context.Background(), f,
		askReq("sess-1", "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		WithPostureElection(nil)) // nil resolver → no override, no panic
	if err != nil {
		t.Fatalf("ResolveAskRouting(allow-always, nil posture): unexpected error: %v", err)
	}
	if got.ApproverPrincipalID != "p-admin" || !got.EscalatedToOrgAdmin {
		t.Errorf("nil posture seam: got %+v, want the lowest-id default p-admin with EscalatedToOrgAdmin", got)
	}
}

// TestResolveAskRouting_PostureOnlyConsultedForAllowAlways proves the posture seam is
// consulted ONLY on the allow-always escalation arm: for allow-once / deny the
// approver is the launching user and the posture resolver is never reached (a posture
// fake that would FAIL if consulted leaves the default-approver resolution untouched).
func TestResolveAskRouting_PostureOnlyConsultedForAllowAlways(t *testing.T) {
	f := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			"sess-1": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
		},
	}
	// This posture seam ERRORS if consulted — proving allow-once never reaches it.
	posture := postureElectionFake{electErr: map[string]error{"sess-1": store.ErrNotFound}}
	for _, dec := range []AskDecision{AskDecisionAllowOnce, AskDecisionDeny} {
		got, err := ResolveAskRouting(context.Background(), f,
			askReq("sess-1", "domain", "github.com"), dec, AttendednessAttended,
			WithPostureElection(posture))
		if err != nil {
			t.Fatalf("[%s] ResolveAskRouting: posture was consulted on a non-allow-always arm: %v", dec, err)
		}
		if got.ApproverPrincipalID != "p-ada" || got.EscalatedToOrgAdmin {
			t.Errorf("[%s] got %+v, want the launching-user default (posture not consulted)", dec, got)
		}
	}
}

// TestResolveAskRouting_PostureErrorSurfaces proves a posture-lookup ERROR surfaces
// wrapped and short-circuits — a posture layer that errors must NOT silently degrade
// to the lowest-id default (which would otherwise resolve a real org-admin here).
func TestResolveAskRouting_PostureErrorSurfaces(t *testing.T) {
	f := approverResolverFake{
		orgAdmin: map[string]store.Principal{
			// A lowest-id default IS available — proving the error is the posture
			// failure, not a missing org-admin, and that no silent fallback occurs.
			"sess-1": {ID: "p-admin", IdPSubject: "okta|admin", Org: "acme",
				Roles: []store.PrincipalRole{store.RoleOrgAdmin}},
		},
	}
	posture := postureElectionFake{electErr: map[string]error{"sess-1": store.ErrInvalid}}
	_, err := ResolveAskRouting(context.Background(), f,
		askReq("sess-1", "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		WithPostureElection(posture))
	if !errors.Is(err, store.ErrInvalid) {
		t.Fatalf("ResolveAskRouting error = %v, want wrapping store.ErrInvalid (posture failure must not degrade to lowest-id)", err)
	}
}

// TestResolveAskRouting_PostureOverrideStillFailsClosedOnNoAcceptor proves the D45
// fail-closed rule survives the posture seam: when NEITHER the posture seam NOR the
// store default yields an acceptor, the result is ErrNoOrgAdminAcceptor — never a
// launching-user fallback. (Posture has no override AND the store has no org-admin.)
func TestResolveAskRouting_PostureOverrideStillFailsClosedOnNoAcceptor(t *testing.T) {
	f := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			// A launching user exists — proving no silent fallback to it occurs.
			"sess-1": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
		},
		// orgAdmin empty → store default ok==false.
	}
	posture := postureElectionFake{} // no override
	_, err := ResolveAskRouting(context.Background(), f,
		askReq("sess-1", "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		WithPostureElection(posture))
	if !errors.Is(err, ErrNoOrgAdminAcceptor) {
		t.Fatalf("ResolveAskRouting error = %v, want ErrNoOrgAdminAcceptor (D45 fail-closed survives the posture seam)", err)
	}
}

// TestAttendednessAttended pins the predicate: only the explicit attended state is
// attended; unknown and unattended are both not-attended (fail-closed).
func TestAttendednessAttended(t *testing.T) {
	if !AttendednessAttended.Attended() {
		t.Error("AttendednessAttended.Attended() = false, want true")
	}
	if AttendednessUnattended.Attended() || AttendednessUnknown.Attended() {
		t.Error("unattended/unknown must report not-attended (fail-closed)")
	}
}
