// SPDX-License-Identifier: Apache-2.0

package policylog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// routeRouterFake is a synthetic askRouteRouter for the RouteAsk call-site: it
// resolves approver principals (GetPrincipal), records appended policy_log rows
// (AppendPolicy), AND surfaces the live deny memos it has itself recorded
// (LiveDenyMemos) — so a deny-then-retry FAST-FAIL is exercised end to end against
// a single backing, with the appended deny memo feeding its own read. No live
// store, no IO (D50); the store's own append/read semantics are covered by its
// conformance suite, this exercises only the wiring.
type routeRouterFake struct {
	principals map[string]store.Principal
	rows       []store.PolicyLogRow
	seq        int64
}

func newRouteRouterFake(ps ...store.Principal) *routeRouterFake {
	m := make(map[string]store.Principal, len(ps))
	for _, p := range ps {
		m[p.ID] = p
	}
	return &routeRouterFake{principals: m}
}

func (f *routeRouterFake) GetPrincipal(_ context.Context, id string) (store.Principal, error) {
	p, ok := f.principals[id]
	if !ok {
		return store.Principal{}, store.ErrNotFound
	}
	return p, nil
}

func (f *routeRouterFake) AppendPolicy(_ context.Context, row store.PolicyLogRow) (store.PolicyLogRow, error) {
	f.seq++
	row.Seq = f.seq
	f.rows = append(f.rows, row)
	return row, nil
}

// LiveDenyMemos returns the not-yet-expired deny-memo rows it has recorded for the
// session — the exact predicate store.(*Memory).LiveDenyMemos applies, so the
// fast-fail read is faithful.
func (f *routeRouterFake) LiveDenyMemos(_ context.Context, sessionUUID string, now time.Time) ([]store.PolicyLogRow, error) {
	var out []store.PolicyLogRow
	for _, r := range f.rows {
		if r.Kind != store.PolicyKindDenyMemo || r.SessionUUID != sessionUUID {
			continue
		}
		if r.ExpiresAt != nil && !r.ExpiresAt.After(now) {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// grantRows returns only the appended ALLOW grants — the "zero new allow grant"
// assertion counts these.
func (f *routeRouterFake) grantRows() []store.PolicyLogRow {
	var out []store.PolicyLogRow
	for _, r := range f.rows {
		if r.Kind == store.PolicyKindAskGrant {
			out = append(out, r)
		}
	}
	return out
}

// resolverFake pairs the launching-user default-approver lookup with the
// org-admin escalation lookup (askApproverResolver), scripted from maps.
type resolverFake struct {
	launching map[string]store.LaunchingUserClaim
	orgAdmin  map[string]store.Principal
}

func (f resolverFake) ResolveLaunchingUserClaim(_ context.Context, sessionUUID string) (store.LaunchingUserClaim, bool, error) {
	c, ok := f.launching[sessionUUID]
	return c, ok, nil
}

func (f resolverFake) ResolveOrgAdminAcceptor(_ context.Context, sessionUUID string) (store.Principal, bool, error) {
	p, ok := f.orgAdmin[sessionUUID]
	return p, ok, nil
}

// collectSink records the LOG-1 ask events in emit order, so the flow's emit leg
// is asserted (Issued first, then Approved or Denied).
type collectSink struct {
	issued   []*identityv1.AskIssued
	approved []*identityv1.AskApproved
	denied   []*identityv1.AskDenied
}

func (s *collectSink) AskIssued(_ context.Context, ev *identityv1.AskIssued) error {
	s.issued = append(s.issued, ev)
	return nil
}

func (s *collectSink) AskApproved(_ context.Context, ev *identityv1.AskApproved) error {
	s.approved = append(s.approved, ev)
	return nil
}

func (s *collectSink) AskDenied(_ context.Context, ev *identityv1.AskDenied) error {
	s.denied = append(s.denied, ev)
	return nil
}

// recordingParkRouter records every Park call so the rung-2 dispatch leg is
// asserted (it satisfies askParkRouter, the *parkMachine shape).
type recordingParkRouter struct {
	parked []askhold.Parked
}

func (r *recordingParkRouter) Park(sessionUUID string, ask askhold.Ask, now time.Time) (askhold.Parked, error) {
	p := askhold.Parked{SessionUUID: sessionUUID, Ask: ask, ParkedAt: now, Phase: askhold.ParkPhaseParked}
	r.parked = append(r.parked, p)
	return p, nil
}

func launcherClaim() map[string]store.LaunchingUserClaim {
	return map[string]store.LaunchingUserClaim{
		"sess-1": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
	}
}

func attendedAsk(session string) *boundaryv1.AskUserRequest {
	return &boundaryv1.AskUserRequest{
		Session:       &boundaryv1.SessionRef{SessionUuid: session},
		ResourceKind:  "domain",
		ResourceName:  "github.com",
		MatchedRuleId: "rule-42",
	}
}

func tlsWindow() askhold.Window {
	return askhold.Window{Notify: 5 * time.Second, Decision: 40 * time.Second, Commit: 5 * time.Second}
}

// TestRouteAsk_AttendedAllowResolvesDispatchesEmits proves the headline flow: an
// inbound ATTENDED allow-once ask RESOLVES (launching-user approver), DISPATCHES
// (TLS-1 socket-hold off the attendedness signal + the POL-1 Window), routes the
// APPROVE verdict (an attributed ask-grant), and EMITS the LOG-1 Issued+Approved
// events stamped with the resolved approver.
func TestRouteAsk_AttendedAllowResolvesDispatchesEmits(t *testing.T) {
	router := newRouteRouterFake(approverPrincipal())
	resolver := resolverFake{launching: launcherClaim()}
	sink := &collectSink{}
	svc := NewService(store.NewMemory(), passthroughComposer{})

	exp := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	res, err := svc.RouteAsk(context.Background(), router, resolver, sink, nil,
		attendedAsk("sess-1"), RouteAskParams{
			Decision: AskDecisionAllowOnce,
			Attended: AttendednessAttended,
			Window:   tlsWindow(),
			Consent:  boundaryv1.AskConsentClass_ASK_CONSENT_CLASS_SESSION,
			Body: GrantBody{
				Rule:      "allow github.com",
				ExpiresAt: *store.SetTime(exp),
				Payload:   []byte(`{"rule":"allow github.com"}`),
			},
		})
	if err != nil {
		t.Fatalf("RouteAsk: %v", err)
	}

	// RESOLVE: the launching user is the approver (no escalation).
	if res.Resolution.ApproverPrincipalID != "p-ada" {
		t.Errorf("approver = %q, want the launching user p-ada", res.Resolution.ApproverPrincipalID)
	}
	if res.Resolution.EscalatedToOrgAdmin {
		t.Error("EscalatedToOrgAdmin = true, want false for an allow-once launching-user default")
	}

	// DISPATCH: attended -> client_prompt target + an open socket-hold for Window.Total.
	if res.Dispatch.Target != AskDispatchPrompt {
		t.Errorf("dispatch target = %q, want %q (attended)", res.Dispatch.Target, AskDispatchPrompt)
	}
	if res.Dispatch.Hold.Outcome != askhold.OutcomeHold {
		t.Errorf("hold outcome = %v, want OutcomeHold (attended)", res.Dispatch.Hold.Outcome)
	}
	if res.Dispatch.Hold.HoldFor != tlsWindow().Total() {
		t.Errorf("hold-for = %v, want the POL-1 Window total %v", res.Dispatch.Hold.HoldFor, tlsWindow().Total())
	}
	if res.Dispatch.DispatchPark {
		t.Error("DispatchPark = true, want false for an ordinary unknown-domain ask")
	}

	// VERDICT: an attributed ask-grant landed.
	if !res.Routing.Granted {
		t.Fatal("Routing.Granted = false, want an appended ask-grant")
	}
	if got := router.grantRows(); len(got) != 1 || got[0].Actor != "p-ada" {
		t.Fatalf("grant rows = %+v, want exactly one with Actor p-ada", got)
	}

	// EMIT: LOG-1 Issued then Approved, the approval stamped with the resolved approver.
	if len(sink.issued) != 1 || len(sink.approved) != 1 || len(sink.denied) != 0 {
		t.Fatalf("emitted events = issued:%d approved:%d denied:%d, want 1/1/0",
			len(sink.issued), len(sink.approved), len(sink.denied))
	}
	if sink.issued[0].GetSessionRef().GetSessionUuid() != "sess-1" || sink.issued[0].GetResourceName() != "github.com" {
		t.Errorf("AskIssued = %+v, want session sess-1 + resource github.com", sink.issued[0])
	}
	if sink.approved[0].GetApproverPrincipal() != "p-ada" {
		t.Errorf("AskApproved approver = %q, want p-ada", sink.approved[0].GetApproverPrincipal())
	}
	if sink.approved[0].GetConsentClass() != identityv1.ConsentClass_CONSENT_CLASS_SESSION {
		t.Errorf("AskApproved consent = %v, want SESSION (carried from the ask params)", sink.approved[0].GetConsentClass())
	}
}

// TestRouteAsk_AllowAlwaysEscalatesToOrgAdmin proves the D45 escalation rides
// through the live call-site: an allow-always ask attributes the grant AND the
// LOG-1 approval to the ORG-ADMIN acceptor, never the launching user.
func TestRouteAsk_AllowAlwaysEscalatesToOrgAdmin(t *testing.T) {
	orgAdmin := store.Principal{ID: "p-admin", IdPSubject: "okta|admin", Org: "acme",
		Roles: []store.PrincipalRole{store.RoleOrgAdmin}}
	router := newRouteRouterFake(orgAdmin)
	resolver := resolverFake{
		launching: launcherClaim(),
		orgAdmin:  map[string]store.Principal{"sess-1": orgAdmin},
	}
	sink := &collectSink{}
	svc := NewService(store.NewMemory(), passthroughComposer{})

	res, err := svc.RouteAsk(context.Background(), router, resolver, sink, nil,
		attendedAsk("sess-1"), RouteAskParams{
			Decision: AskDecisionAllowAlways,
			Attended: AttendednessAttended,
			Window:   tlsWindow(),
			Body:     GrantBody{Rule: "allow github.com", Payload: []byte(`{}`)},
		})
	if err != nil {
		t.Fatalf("RouteAsk(allow-always): %v", err)
	}
	if !res.Resolution.EscalatedToOrgAdmin || res.Resolution.ApproverPrincipalID != "p-admin" {
		t.Fatalf("resolution = %+v, want EscalatedToOrgAdmin + approver p-admin (D45)", res.Resolution)
	}
	if got := router.grantRows(); len(got) != 1 || got[0].Actor != "p-admin" {
		t.Fatalf("grant rows = %+v, want exactly one attributed to the org-admin p-admin", got)
	}
	if len(sink.approved) != 1 || sink.approved[0].GetApproverPrincipal() != "p-admin" {
		t.Errorf("AskApproved approver = %+v, want the org-admin p-admin (D45)", sink.approved)
	}
}

// TestRouteAsk_DenyWritesMemoAndEmitsDenied proves the deny leg: a DENY carrying a
// D77 reason appends a session-scoped deny memo (NOT an allow grant), emits the
// LOG-1 AskDenied with the reason, and grants zero allows.
func TestRouteAsk_DenyWritesMemoAndEmitsDenied(t *testing.T) {
	router := newRouteRouterFake(approverPrincipal())
	resolver := resolverFake{launching: launcherClaim()}
	sink := &collectSink{}
	svc := NewService(store.NewMemory(), passthroughComposer{})

	res, err := svc.RouteAsk(context.Background(), router, resolver, sink, nil,
		attendedAsk("sess-1"), RouteAskParams{
			Decision: AskDecisionDeny,
			Attended: AttendednessAttended,
			Window:   tlsWindow(),
			Body:     GrantBody{Rule: "deny evil.com", DenyReason: "domain-blocklisted", Payload: []byte("domain-blocklisted")},
		})
	if err != nil {
		t.Fatalf("RouteAsk(deny): %v", err)
	}
	if !res.Routing.Denied || res.Routing.Granted {
		t.Fatalf("routing = %+v, want Denied (a deny memo), never Granted", res.Routing)
	}
	if got := router.grantRows(); len(got) != 0 {
		t.Fatalf("a deny must write ZERO allow grants, got %d", len(got))
	}
	if len(sink.denied) != 1 || sink.denied[0].GetMachineReadableReason() != "domain-blocklisted" {
		t.Errorf("AskDenied = %+v, want one carrying the D77 reason domain-blocklisted", sink.denied)
	}
}

// TestRouteAsk_RepeatDenyFastFailsWithZeroNewAllow is the ACCEPTANCE test: a deny
// records a memo; a REPEAT denied ask for the same session FAST-FAILS via
// LiveDenyMemo — no fresh resolve, no new write, and ZERO new allow grant. The
// grant count stays zero across both passes.
func TestRouteAsk_RepeatDenyFastFailsWithZeroNewAllow(t *testing.T) {
	router := newRouteRouterFake(approverPrincipal())
	resolver := resolverFake{launching: launcherClaim()}
	sink := &collectSink{}
	svc := NewService(store.NewMemory(), passthroughComposer{})
	// Pin the clock far before any TTL so the recorded memo is live on the retry.
	svc.SetClock(func() time.Time { return time.Date(2026, 6, 12, 9, 0, 0, 0, time.UTC) })

	params := RouteAskParams{
		Decision: AskDecisionDeny,
		Attended: AttendednessAttended,
		Window:   tlsWindow(),
		Body: GrantBody{
			Rule:       "deny evil.com",
			DenyReason: "domain-blocklisted",
			ExpiresAt:  *store.SetTime(time.Date(2026, 6, 12, 18, 0, 0, 0, time.UTC)),
			Payload:    []byte("domain-blocklisted"),
		},
	}

	// First deny: records the memo.
	first, err := svc.RouteAsk(context.Background(), router, resolver, sink, nil, attendedAsk("sess-1"), params)
	if err != nil {
		t.Fatalf("first RouteAsk(deny): %v", err)
	}
	if first.FastFailed {
		t.Fatal("the FIRST deny must NOT fast-fail (no prior memo)")
	}
	if !first.Routing.Denied {
		t.Fatal("the first deny must record a deny memo")
	}
	denyMemosAfterFirst := len(router.rows)

	// Repeat deny for the same session: fast-fails on the live recorded memo.
	repeat, err := svc.RouteAsk(context.Background(), router, resolver, sink, nil, attendedAsk("sess-1"), params)
	if err != nil {
		t.Fatalf("repeat RouteAsk(deny): %v", err)
	}
	if !repeat.FastFailed {
		t.Fatal("the REPEAT deny must FAST-FAIL on the live deny memo (D118)")
	}
	if repeat.FastFailReason != "domain-blocklisted" {
		t.Errorf("fast-fail reason = %q, want the recorded D77 reason domain-blocklisted", repeat.FastFailReason)
	}
	// ZERO new write on the fast-fail: no second memo, no allow grant, and the
	// resolution/emit legs never ran.
	if len(router.rows) != denyMemosAfterFirst {
		t.Errorf("fast-fail wrote a new row: rows went %d -> %d", denyMemosAfterFirst, len(router.rows))
	}
	if got := router.grantRows(); len(got) != 0 {
		t.Fatalf("ZERO allow grants must exist across both passes, got %d", len(got))
	}
	if repeat.Routing.Granted || repeat.Routing.Denied {
		t.Errorf("fast-fail routing = %+v, want the zero result (no write)", repeat.Routing)
	}
}

// TestRouteAsk_UnattendedBlocksAndAsyncNotifies proves the D78 unattended fork at
// the call-site: an UNATTENDED ask dispatches to async_notify AND the askhold
// decision is OutcomeBlockLog (immediate block+log, no socket-hold) carrying the
// D77 unattended reason — even when the decision class is an allow.
func TestRouteAsk_UnattendedBlocksAndAsyncNotifies(t *testing.T) {
	router := newRouteRouterFake(approverPrincipal())
	resolver := resolverFake{launching: launcherClaim()}
	svc := NewService(store.NewMemory(), passthroughComposer{})

	res, err := svc.RouteAsk(context.Background(), router, resolver, nil, nil,
		attendedAsk("sess-1"), RouteAskParams{
			Decision: AskDecisionAllowOnce,
			Attended: AttendednessUnattended,
			Window:   tlsWindow(),
			Body:     GrantBody{Rule: "allow github.com", Payload: []byte(`{}`)},
		})
	if err != nil {
		t.Fatalf("RouteAsk(unattended): %v", err)
	}
	if res.Dispatch.Target != AskDispatchAsyncNotify {
		t.Errorf("dispatch target = %q, want async_notify (unattended)", res.Dispatch.Target)
	}
	if res.Dispatch.Hold.Outcome != askhold.OutcomeBlockLog {
		t.Errorf("hold outcome = %v, want OutcomeBlockLog (unattended-from-the-start)", res.Dispatch.Hold.Outcome)
	}
	if res.Dispatch.Hold.Reason.Code != askhold.DenyUnattended {
		t.Errorf("block reason = %q, want DenyUnattended", res.Dispatch.Hold.Reason.Code)
	}
	if res.Dispatch.Hold.Reason.MatchedRuleID != "rule-42" {
		t.Errorf("block reason matched-rule = %q, want rule-42 (from the inbound ask)", res.Dispatch.Hold.Reason.MatchedRuleID)
	}
}

// TestRouteAsk_Rung2DrivesPark proves the rung-2 dispatch leg: a GENUINE rung-2
// ask ENTERS the untimed D46 park via the injected park router (never a
// socket-hold), and DispatchPark is reported.
func TestRouteAsk_Rung2DrivesPark(t *testing.T) {
	router := newRouteRouterFake(approverPrincipal())
	resolver := resolverFake{launching: launcherClaim()}
	park := &recordingParkRouter{}
	svc := NewService(store.NewMemory(), passthroughComposer{})

	res, err := svc.RouteAsk(context.Background(), router, resolver, nil, park,
		attendedAsk("sess-1"), RouteAskParams{
			Decision: AskDecisionAllowOnce,
			Attended: AttendednessAttended,
			Rung2:    true,
			Window:   tlsWindow(),
			Body:     GrantBody{Rule: "allow github.com", Payload: []byte(`{}`)},
		})
	if err != nil {
		t.Fatalf("RouteAsk(rung-2): %v", err)
	}
	if !res.Dispatch.DispatchPark {
		t.Fatal("DispatchPark = false, want true for a genuine rung-2 ask")
	}
	if res.Dispatch.Hold.Outcome != askhold.OutcomeUnspecified {
		t.Errorf("a rung-2 ask must NOT socket-hold; hold = %v, want the zero decision", res.Dispatch.Hold.Outcome)
	}
	if len(park.parked) != 1 || park.parked[0].SessionUUID != "sess-1" {
		t.Fatalf("park calls = %+v, want exactly one for sess-1", park.parked)
	}
	if park.parked[0].Phase != askhold.ParkPhaseParked {
		t.Errorf("parked phase = %v, want ParkPhaseParked (untimed, D46)", park.parked[0].Phase)
	}
	if !park.parked[0].Ask.Rung2 {
		t.Error("parked ask Rung2 = false, want true (the ask was projected from the inbound request)")
	}
}

// TestRouteAsk_FailClosedNoSession proves the fail-closed guard: an inbound ask
// with no session resolves nothing and writes nothing (ErrNoSession).
func TestRouteAsk_FailClosedNoSession(t *testing.T) {
	router := newRouteRouterFake(approverPrincipal())
	resolver := resolverFake{launching: launcherClaim()}
	svc := NewService(store.NewMemory(), passthroughComposer{})

	_, err := svc.RouteAsk(context.Background(), router, resolver, nil, nil,
		&boundaryv1.AskUserRequest{ResourceKind: "domain", ResourceName: "github.com"},
		RouteAskParams{Decision: AskDecisionAllowOnce, Attended: AttendednessAttended, Window: tlsWindow()})
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("RouteAsk(no session) = %v, want ErrNoSession (fail-closed)", err)
	}
	if len(router.rows) != 0 {
		t.Fatalf("a fail-closed ask must write no row, got %d", len(router.rows))
	}
}
