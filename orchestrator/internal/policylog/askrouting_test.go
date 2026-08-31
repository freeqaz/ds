package policylog

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/storetest"
)

// routerFake is a synthetic askRouter: it resolves approver principals from a
// scripted map (GetPrincipal) and records appended rows (AppendPolicy, reusing
// the appenderFake semantics), so the ask-routing leg's decision dispatch,
// approver resolution, role-gate, and attribution can be asserted without a live
// store. The store's own lookup/append semantics are covered by its conformance
// suite; this exercises only the ROUTING.
type routerFake struct {
	principals map[string]store.Principal
	appender   appenderFake
}

func newRouterFake(ps ...store.Principal) *routerFake {
	m := make(map[string]store.Principal, len(ps))
	for _, p := range ps {
		m[p.ID] = p
	}
	return &routerFake{principals: m}
}

func (f *routerFake) GetPrincipal(_ context.Context, id string) (store.Principal, error) {
	p, ok := f.principals[id]
	if !ok {
		return store.Principal{}, store.ErrNotFound
	}
	return p, nil
}

func (f *routerFake) AppendPolicy(ctx context.Context, row store.PolicyLogRow) (store.PolicyLogRow, error) {
	return f.appender.AppendPolicy(ctx, row)
}

// TestRouteAskDecision_AllowAttributesApprover proves the allow path routes
// through the gate+attribution seam: an authorized approver's allow-once decision
// resolves the principal, gates open on MayApprove, and appends an ask-grant row
// whose Actor IS the approver — Granted true with the appended row.
func TestRouteAskDecision_AllowAttributesApprover(t *testing.T) {
	f := newRouterFake(approverPrincipal())
	exp := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	got, err := RouteAskDecision(context.Background(), f, AskRouting{
		Decision:            AskDecisionAllowOnce,
		ApproverPrincipalID: "p-ada",
		SessionUUID:         "sess-1",
		Rule:                "allow github.com",
		ExpiresAt:           *store.SetTime(exp),
		Payload:             []byte(`{"rule":"allow github.com"}`),
	})
	if err != nil {
		t.Fatalf("RouteAskDecision(allow): unexpected error: %v", err)
	}
	if !got.Granted {
		t.Fatal("Granted = false, want true for an authorized allow")
	}
	if len(f.appender.rows) != 1 {
		t.Fatalf("expected exactly one appended row, got %d", len(f.appender.rows))
	}
	if got.Row.Actor != "p-ada" {
		t.Errorf("row Actor = %q, want the approver principal ID %q", got.Row.Actor, "p-ada")
	}
	if got.Row.Kind != store.PolicyKindAskGrant {
		t.Errorf("row Kind = %q, want %q", got.Row.Kind, store.PolicyKindAskGrant)
	}
	if got.Row.SessionUUID != "sess-1" {
		t.Errorf("row SessionUUID = %q, want %q", got.Row.SessionUUID, "sess-1")
	}
	if got.Row.ExpiresAt == nil || !got.Row.ExpiresAt.Equal(exp) {
		t.Errorf("row ExpiresAt = %v, want %v", got.Row.ExpiresAt, exp)
	}
	if got.Row.Seq == 0 {
		t.Error("row Seq = 0, want a store-assigned seq")
	}
}

// TestRouteAskDecision_RefusesNonApprover proves the role-gate inside the routing
// leg: a principal that may not approve is refused with ErrNotApprover and NO
// policy_log row is written — the routing never turns a non-approver's allow into
// a grant on the policy stream.
func TestRouteAskDecision_RefusesNonApprover(t *testing.T) {
	f := newRouterFake(nonApproverPrincipal())
	_, err := RouteAskDecision(context.Background(), f, AskRouting{
		Decision:            AskDecisionAllowOnce,
		ApproverPrincipalID: "p-eve",
		SessionUUID:         "sess-1",
		Rule:                "allow evil.com",
		Payload:             []byte(`{}`),
	})
	if !errors.Is(err, ErrNotApprover) {
		t.Fatalf("RouteAskDecision error = %v, want ErrNotApprover", err)
	}
	if len(f.appender.rows) != 0 {
		t.Fatalf("a refused approval must write no row, got %d", len(f.appender.rows))
	}
}

// TestRouteAskDecision_DenyWritesNoGrant proves the §6.2-step-4 deny rule: a deny
// decision appends NO allow grant — Granted false, no policy_log write, and the
// approver is not even resolved (deny is answered directly by the wrapper).
func TestRouteAskDecision_DenyWritesNoGrant(t *testing.T) {
	// An approver-roled principal is present, but a DENY still writes nothing.
	f := newRouterFake(approverPrincipal())
	got, err := RouteAskDecision(context.Background(), f, AskRouting{
		Decision:            AskDecisionDeny,
		ApproverPrincipalID: "p-ada",
		SessionUUID:         "sess-1",
		Rule:                "allow github.com",
		Payload:             []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("RouteAskDecision(deny): unexpected error: %v", err)
	}
	if got.Granted {
		t.Error("Granted = true, want false for a deny (no allow grant)")
	}
	if len(f.appender.rows) != 0 {
		t.Fatalf("a deny must write no row, got %d", len(f.appender.rows))
	}
}

// TestRouteAskDecision_DenyWithReasonWritesMemo proves the D118 deny-memo branch:
// a DENY carrying a D77 machine-readable reason resolves the denier, gates it on
// MayApprove, and appends EXACTLY ONE PolicyKindDenyMemo row attributed to the
// denier — Denied true, Granted false, and ZERO allow grants. The deny memo NEVER
// becomes an allow grant on the policy stream.
func TestRouteAskDecision_DenyWithReasonWritesMemo(t *testing.T) {
	f := newRouterFake(approverPrincipal())
	exp := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	got, err := RouteAskDecision(context.Background(), f, AskRouting{
		Decision:            AskDecisionDeny,
		ApproverPrincipalID: "p-ada",
		SessionUUID:         "sess-deny",
		Rule:                "deny evil.com",
		ExpiresAt:           *store.SetTime(exp),
		DenyReason:          "domain-blocklisted",
		Payload:             []byte("domain-blocklisted"),
	})
	if err != nil {
		t.Fatalf("RouteAskDecision(deny+reason): %v", err)
	}
	if got.Granted {
		t.Error("Granted = true, want false — a deny never appends an allow grant")
	}
	if !got.Denied {
		t.Error("Denied = false, want true when a deny carries a D77 reason (D118)")
	}
	if len(f.appender.rows) != 1 {
		t.Fatalf("a deny+reason must write exactly one row, got %d", len(f.appender.rows))
	}
	if got.Row.Kind != store.PolicyKindDenyMemo {
		t.Errorf("row Kind = %q, want %q", got.Row.Kind, store.PolicyKindDenyMemo)
	}
	if got.Row.Kind == store.PolicyKindAskGrant {
		t.Errorf("the deny memo must never be an allow grant")
	}
	if got.Row.Actor != "p-ada" {
		t.Errorf("row Actor = %q, want the denier principal ID p-ada", got.Row.Actor)
	}
	if got.Row.SessionUUID != "sess-deny" {
		t.Errorf("row SessionUUID = %q, want sess-deny", got.Row.SessionUUID)
	}
	if string(got.Row.Payload) != "domain-blocklisted" {
		t.Errorf("row payload lost the D77 reason: got %q", string(got.Row.Payload))
	}
}

// TestRouteAskDecision_DenyWithReasonRefusesNonApprover proves the deny-memo write
// is role-gated symmetrically with the allow path: a non-approver denial carrying
// a reason is refused with ErrNotApprover and writes NO row.
func TestRouteAskDecision_DenyWithReasonRefusesNonApprover(t *testing.T) {
	f := newRouterFake(nonApproverPrincipal())
	_, err := RouteAskDecision(context.Background(), f, AskRouting{
		Decision:            AskDecisionDeny,
		ApproverPrincipalID: "p-eve",
		SessionUUID:         "sess-deny",
		Rule:                "deny evil.com",
		DenyReason:          "domain-blocklisted",
		Payload:             []byte("domain-blocklisted"),
	})
	if !errors.Is(err, ErrNotApprover) {
		t.Fatalf("RouteAskDecision(deny+reason, non-approver) error = %v, want ErrNotApprover", err)
	}
	if len(f.appender.rows) != 0 {
		t.Fatalf("a refused deny must write no row, got %d", len(f.appender.rows))
	}
}

// TestRouteAskDecision_DenyWithoutReasonStaysNoWrite proves the legacy deny path
// is preserved: a DENY with NO reason carried writes nothing (Granted and Denied
// both false), exactly as before D118 — the additive behavior never fires without
// an explicit reason.
func TestRouteAskDecision_DenyWithoutReasonStaysNoWrite(t *testing.T) {
	f := newRouterFake(approverPrincipal())
	got, err := RouteAskDecision(context.Background(), f, AskRouting{
		Decision:            AskDecisionDeny,
		ApproverPrincipalID: "p-ada",
		SessionUUID:         "sess-deny",
		Rule:                "deny evil.com",
		Payload:             []byte("{}"),
	})
	if err != nil {
		t.Fatalf("RouteAskDecision(deny, no reason): %v", err)
	}
	if got.Granted || got.Denied {
		t.Errorf("result = %+v, want neither granted nor denied for a reasonless deny", got)
	}
	if len(f.appender.rows) != 0 {
		t.Fatalf("a reasonless deny must write no row, got %d", len(f.appender.rows))
	}
}

// TestRouteAskDecision_DenyWithReason_MemoryStore proves the deny-memo branch
// wires against the REAL store: an authorized deny+reason lands a retrievable
// deny memo and adds NO allow grant.
func TestRouteAskDecision_DenyWithReason_MemoryStore(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	if _, err := repo.CreatePrincipal(ctx, approverPrincipal()); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	exp := time.Now().Add(time.Hour)
	got, err := RouteAskDecision(ctx, repo, AskRouting{
		Decision:            AskDecisionDeny,
		ApproverPrincipalID: "p-ada",
		SessionUUID:         "sess-mem-deny",
		Rule:                "deny evil.com",
		ExpiresAt:           *store.SetTime(exp),
		DenyReason:          "domain-blocklisted",
		Payload:             []byte("domain-blocklisted"),
	})
	if err != nil {
		t.Fatalf("RouteAskDecision(memory deny+reason): %v", err)
	}
	if got.Granted || !got.Denied {
		t.Fatalf("result = %+v, want denied (not granted)", got)
	}
	memos, err := repo.LiveDenyMemos(ctx, "sess-mem-deny", time.Now())
	if err != nil {
		t.Fatalf("LiveDenyMemos: %v", err)
	}
	if len(memos) != 1 || memos[0].Actor != "p-ada" {
		t.Fatalf("LiveDenyMemos = %+v, want one memo attributed to p-ada", memos)
	}
	grants, err := repo.LiveGrants(ctx, "sess-mem-deny", time.Now())
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("a deny+reason must add no allow grant, got %d", len(grants))
	}
}

// TestRouteAskDecision_AllowAlwaysAppendsGrant proves allow-always still appends a
// session-scoped attributed grant here (the fleet-wide org-admin-acceptance
// promotion is a separate path; the routing writes the session-scoped grant and
// stamps the approver). An org-admin gates open (D45 escalation).
func TestRouteAskDecision_AllowAlwaysAppendsGrant(t *testing.T) {
	admin := store.Principal{
		ID: "p-admin", IdPSubject: "okta|admin", Org: "acme",
		Roles: []store.PrincipalRole{store.RoleOrgAdmin},
	}
	f := newRouterFake(admin)
	got, err := RouteAskDecision(context.Background(), f, AskRouting{
		Decision:            AskDecisionAllowAlways,
		ApproverPrincipalID: "p-admin",
		SessionUUID:         "sess-2",
		Rule:                "allow *",
		Payload:             []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("RouteAskDecision(allow-always): %v", err)
	}
	if !got.Granted || got.Row.Actor != "p-admin" {
		t.Errorf("allow-always result = %+v, want granted attributed to p-admin", got)
	}
}

// TestAskRoutingFromResolution_AllowAlwaysAttributesOrgAdmin is the D45 attribution
// proof for this unit: it routes an ALLOW-ALWAYS decision through the FULL wire —
// ResolveAskRouting resolves the org-admin acceptor, AskRoutingFromResolution carries
// that resolved approver onto AskRouting.ApproverPrincipalID, and RouteAskDecision /
// ApproveAsk attribute the persisted grant. The audited Actor on the appended
// allow-always grant row MUST be the resolved ORG-ADMIN (p-admin), NOT the launching
// user (p-ada) — the launcher is present and could approve, but allow-always escalates
// to org-admin acceptance and the persisted attribution follows the resolution.
func TestAskRoutingFromResolution_AllowAlwaysAttributesOrgAdmin(t *testing.T) {
	ctx := context.Background()
	const (
		sessionUUID  = "sess-aa"
		launcherID   = "p-ada"   // the launching user — the DEFAULT approver, NOT who allow-always attributes to
		orgAdminID   = "p-admin" // the resolved org-admin acceptor — the D45 allow-always Actor
		orgName      = "acme"
		resourceName = "github.com"
	)

	// The resolver entry: an allow-always ask escalates to the org-admin acceptor.
	// The fake pairs a launching-user claim (the launcher) with an org-admin acceptor
	// for this session, so ResolveAskRouting resolves the org-admin for allow-always.
	resolver := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			sessionUUID: {PrincipalID: launcherID, Subject: "okta|ada", Org: orgName},
		},
		orgAdmin: map[string]store.Principal{
			sessionUUID: {ID: orgAdminID, IdPSubject: "okta|admin", Org: orgName, Roles: []store.PrincipalRole{store.RoleOrgAdmin}},
		},
	}
	ask := askReq(sessionUUID, "", resourceName)

	res, err := ResolveAskRouting(ctx, resolver, ask, AskDecisionAllowAlways, AttendednessAttended)
	if err != nil {
		t.Fatalf("ResolveAskRouting(allow-always): %v", err)
	}
	if !res.EscalatedToOrgAdmin {
		t.Fatalf("EscalatedToOrgAdmin = false, want true for an allow-always ask (D45)")
	}
	if res.ApproverPrincipalID != orgAdminID {
		t.Fatalf("resolved ApproverPrincipalID = %q, want the org-admin %q", res.ApproverPrincipalID, orgAdminID)
	}

	// The wire under test: the resolved approver flows into AskRouting.ApproverPrincipalID.
	exp := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	routing := AskRoutingFromResolution(res, AskDecisionAllowAlways, "allow *",
		*store.SetTime(exp), store.ConsentClassUnspecified, []byte(`{"rule":"allow *"}`), "")
	if routing.ApproverPrincipalID != orgAdminID {
		t.Fatalf("AskRouting.ApproverPrincipalID = %q, want the resolved org-admin %q (D45 — never the launcher %q)",
			routing.ApproverPrincipalID, orgAdminID, launcherID)
	}
	if routing.SessionUUID != sessionUUID {
		t.Errorf("AskRouting.SessionUUID = %q, want %q", routing.SessionUUID, sessionUUID)
	}

	// The persisted grant: ApproveAsk attributes the Actor to the org-admin. Both the
	// launcher AND the org-admin are registered as eligible approvers, so the test
	// proves the ATTRIBUTION followed the resolution (org-admin), not merely that
	// *some* approver passed the gate.
	writer := newRouterFake(
		store.Principal{ID: launcherID, IdPSubject: "okta|ada", Org: orgName, Roles: []store.PrincipalRole{store.RoleLauncher}},
		store.Principal{ID: orgAdminID, IdPSubject: "okta|admin", Org: orgName, Roles: []store.PrincipalRole{store.RoleOrgAdmin}},
	)
	got, err := RouteAskDecision(ctx, writer, routing)
	if err != nil {
		t.Fatalf("RouteAskDecision(allow-always via resolution): %v", err)
	}
	if !got.Granted {
		t.Fatal("Granted = false, want true for an authorized allow-always")
	}
	if len(writer.appender.rows) != 1 {
		t.Fatalf("expected exactly one appended grant row, got %d", len(writer.appender.rows))
	}
	if got.Row.Kind != store.PolicyKindAskGrant {
		t.Errorf("row Kind = %q, want %q", got.Row.Kind, store.PolicyKindAskGrant)
	}
	if got.Row.Actor != orgAdminID {
		t.Errorf("allow-always grant Actor = %q, want the resolved org-admin %q — NOT the launching user %q (D45)",
			got.Row.Actor, orgAdminID, launcherID)
	}
	if got.Row.Actor == launcherID {
		t.Errorf("allow-always grant Actor was attributed to the LAUNCHING USER %q — D45 violation", launcherID)
	}
}

// TestAskRoutingFromResolution_AllowOnceAttributesLauncher is the symmetric proof
// that the launcher attribution is preserved: an allow-once resolution carries the
// launching-user default, AskRoutingFromResolution carries it onto the routing, and
// the persisted grant Actor is the LAUNCHER — allow-once is NOT escalated to the
// org-admin. This guards against over-escalating every grant to org-admin.
func TestAskRoutingFromResolution_AllowOnceAttributesLauncher(t *testing.T) {
	ctx := context.Background()
	const (
		sessionUUID = "sess-ao"
		launcherID  = "p-ada"
		orgName     = "acme"
	)
	resolver := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			sessionUUID: {PrincipalID: launcherID, Subject: "okta|ada", Org: orgName},
		},
		// An org-admin exists, but allow-once must NOT escalate to it.
		orgAdmin: map[string]store.Principal{
			sessionUUID: {ID: "p-admin", IdPSubject: "okta|admin", Org: orgName, Roles: []store.PrincipalRole{store.RoleOrgAdmin}},
		},
	}
	ask := askReq(sessionUUID, "", "")

	res, err := ResolveAskRouting(ctx, resolver, ask, AskDecisionAllowOnce, AttendednessAttended)
	if err != nil {
		t.Fatalf("ResolveAskRouting(allow-once): %v", err)
	}
	if res.EscalatedToOrgAdmin {
		t.Fatalf("EscalatedToOrgAdmin = true, want false for allow-once (the launcher default, not D45 escalation)")
	}
	if res.ApproverPrincipalID != launcherID {
		t.Fatalf("resolved ApproverPrincipalID = %q, want the launching user %q", res.ApproverPrincipalID, launcherID)
	}

	routing := AskRoutingFromResolution(res, AskDecisionAllowOnce, "allow github.com",
		store.OptTime{}, store.ConsentClassUnspecified, []byte(`{}`), "")
	if routing.ApproverPrincipalID != launcherID {
		t.Fatalf("AskRouting.ApproverPrincipalID = %q, want the launching user %q for allow-once", routing.ApproverPrincipalID, launcherID)
	}

	writer := newRouterFake(
		store.Principal{ID: launcherID, IdPSubject: "okta|ada", Org: orgName, Roles: []store.PrincipalRole{store.RoleLauncher}},
	)
	got, err := RouteAskDecision(ctx, writer, routing)
	if err != nil {
		t.Fatalf("RouteAskDecision(allow-once via resolution): %v", err)
	}
	if !got.Granted || got.Row.Actor != launcherID {
		t.Errorf("allow-once result = %+v, want granted attributed to the launcher %q", got, launcherID)
	}
}

// TestAskRoutingFromResolution_CarriesGrantBody proves the bridge faithfully carries
// the grant-body inputs the ask path composed (decision, rule, TTL, consent, payload,
// deny reason) alongside the resolved approver — none are dropped or swapped.
func TestAskRoutingFromResolution_CarriesGrantBody(t *testing.T) {
	exp := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	res := AskResolution{SessionUUID: "sess-body", ApproverPrincipalID: "p-admin", EscalatedToOrgAdmin: true}
	routing := AskRoutingFromResolution(res, AskDecisionAllowAlways, "allow *.example.com",
		*store.SetTime(exp), store.ConsentClassUnspecified, []byte(`{"rule":"allow *.example.com"}`), "")

	if routing.Decision != AskDecisionAllowAlways {
		t.Errorf("Decision = %q, want %q", routing.Decision, AskDecisionAllowAlways)
	}
	if routing.ApproverPrincipalID != "p-admin" {
		t.Errorf("ApproverPrincipalID = %q, want p-admin", routing.ApproverPrincipalID)
	}
	if routing.SessionUUID != "sess-body" {
		t.Errorf("SessionUUID = %q, want sess-body", routing.SessionUUID)
	}
	if routing.Rule != "allow *.example.com" {
		t.Errorf("Rule = %q, want allow *.example.com", routing.Rule)
	}
	if routing.ExpiresAt.V == nil || !routing.ExpiresAt.V.Equal(exp) {
		t.Errorf("ExpiresAt = %v, want %v", routing.ExpiresAt.V, exp)
	}
	if string(routing.Payload) != `{"rule":"allow *.example.com"}` {
		t.Errorf("Payload = %q, want the composed grant body", string(routing.Payload))
	}
	if routing.DenyReason != "" {
		t.Errorf("DenyReason = %q, want empty for an allow", routing.DenyReason)
	}
}

// TestRouteAskDecision_UnknownApprover proves an unknown approver ID is surfaced
// as a resolution error (store.ErrNotFound), never swallowed into a silent allow,
// and writes no row.
func TestRouteAskDecision_UnknownApprover(t *testing.T) {
	f := newRouterFake() // no principals registered
	_, err := RouteAskDecision(context.Background(), f, AskRouting{
		Decision:            AskDecisionAllowOnce,
		ApproverPrincipalID: "p-ghost",
		SessionUUID:         "sess-1",
		Payload:             []byte(`{}`),
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("RouteAskDecision error = %v, want wrapping store.ErrNotFound", err)
	}
	if len(f.appender.rows) != 0 {
		t.Fatalf("an unresolved approver must write no row, got %d", len(f.appender.rows))
	}
}

// TestRouteAskDecision_UnrecognizedDecisionFailsClosed proves an unrecognized
// decision is treated as NOT an allow (fail-closed): no grant is written and the
// approver is not resolved — never default a stray decision value into an allow.
func TestRouteAskDecision_UnrecognizedDecisionFailsClosed(t *testing.T) {
	f := newRouterFake(approverPrincipal())
	got, err := RouteAskDecision(context.Background(), f, AskRouting{
		Decision:            AskDecision("garbage"),
		ApproverPrincipalID: "p-ada",
		SessionUUID:         "sess-1",
		Payload:             []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("RouteAskDecision(unrecognized): unexpected error: %v", err)
	}
	if got.Granted || len(f.appender.rows) != 0 {
		t.Fatalf("an unrecognized decision must fail closed (no grant), got %+v / %d rows", got, len(f.appender.rows))
	}
}

// TestRouteAskDecision_WithMemoryStore proves the routing wires against the REAL
// store seams (GetPrincipal + AppendPolicy): an authorized allow lands a
// retrievable ask-grant attributed to the approver, a non-approver's allow writes
// nothing, and a deny writes nothing.
func TestRouteAskDecision_WithMemoryStore(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()

	if _, err := repo.CreatePrincipal(ctx, approverPrincipal()); err != nil {
		t.Fatalf("CreatePrincipal approver: %v", err)
	}
	if _, err := repo.CreatePrincipal(ctx, nonApproverPrincipal()); err != nil {
		t.Fatalf("CreatePrincipal non-approver: %v", err)
	}

	exp := time.Now().Add(time.Hour)
	got, err := RouteAskDecision(ctx, repo, AskRouting{
		Decision:            AskDecisionAllowOnce,
		ApproverPrincipalID: "p-ada",
		SessionUUID:         "sess-mem",
		Rule:                "allow github.com",
		ExpiresAt:           *store.SetTime(exp),
		Payload:             []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("RouteAskDecision(memory allow): %v", err)
	}
	if !got.Granted || got.Row.Actor != "p-ada" || got.Row.Kind != store.PolicyKindAskGrant {
		t.Fatalf("memory allow result = %+v, want granted ask_grant attributed to p-ada", got)
	}

	grants, err := repo.LiveGrants(ctx, "sess-mem", time.Now())
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].Actor != "p-ada" {
		t.Fatalf("LiveGrants = %+v, want one grant attributed to p-ada", grants)
	}

	// A non-approver's allow writes nothing through the real store.
	if _, err := RouteAskDecision(ctx, repo, AskRouting{
		Decision:            AskDecisionAllowOnce,
		ApproverPrincipalID: "p-eve",
		SessionUUID:         "sess-mem",
		Rule:                "allow evil.com",
		Payload:             []byte(`{}`),
	}); !errors.Is(err, ErrNotApprover) {
		t.Fatalf("non-approver routing error = %v, want ErrNotApprover", err)
	}

	// A deny writes nothing either.
	if _, err := RouteAskDecision(ctx, repo, AskRouting{
		Decision:            AskDecisionDeny,
		ApproverPrincipalID: "p-ada",
		SessionUUID:         "sess-mem",
		Rule:                "allow github.com",
		Payload:             []byte(`{}`),
	}); err != nil {
		t.Fatalf("RouteAskDecision(memory deny): %v", err)
	}

	grants, err = repo.LiveGrants(ctx, "sess-mem", time.Now())
	if err != nil {
		t.Fatalf("LiveGrants after refusal+deny: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("refused allow + deny must add no grant, got %d live grants", len(grants))
	}
}

// linkLaunchingUser is a test helper that registers a session, its launching
// principal, and (optionally) the eligible org-admin acceptor in a real Memory
// store, so ResolveAskRouting resolves the launching user / the D45 org-admin
// escalation against the persisted record (not a synthetic fake). It returns the
// store ready to feed ResolveAndRoute as BOTH the resolver and the router (Memory
// satisfies askApproverResolver and askRouter).
func linkLaunchingUser(t *testing.T, sessionUUID string, launcher store.Principal, orgAdmin *store.Principal) *store.Memory {
	t.Helper()
	ctx := context.Background()
	repo := store.NewMemory()
	if _, err := repo.CreatePrincipal(ctx, launcher); err != nil {
		t.Fatalf("CreatePrincipal launcher: %v", err)
	}
	if orgAdmin != nil {
		if _, err := repo.CreatePrincipal(ctx, *orgAdmin); err != nil {
			t.Fatalf("CreatePrincipal org-admin: %v", err)
		}
	}
	if _, err := repo.CreateSession(ctx, store.Session{Ref: store.SessionRef{SessionUUID: sessionUUID}}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if err := repo.SetSessionLaunchingPrincipal(ctx, sessionUUID, launcher.ID); err != nil {
		t.Fatalf("SetSessionLaunchingPrincipal: %v", err)
	}
	return repo
}

// TestResolveAndRoute_AllowAlwaysAttributesOrgAdmin_MemoryStore is the unit's
// acceptance proof: ResolveAndRoute folds resolution+routing into ONE call and the
// D45 attribution is preserved through the REAL store. An allow-always ask escalates
// to the org-admin acceptor (ResolveOrgAdminAcceptor), and the persisted ask-grant
// row's Actor — retrieved back through the store's own LiveGrants projection — IS the
// org-admin (p-admin), NOT the launching user (p-ada). The launcher is registered and
// is itself a permitted approver, so the test proves the ATTRIBUTION followed the
// resolution, closing the launching-user footgun: there is no path through
// ResolveAndRoute that lets a hand-built routing name the launcher for an allow-always.
func TestResolveAndRoute_AllowAlwaysAttributesOrgAdmin_MemoryStore(t *testing.T) {
	ctx := context.Background()
	const (
		sessionUUID = "sess-rar-aa"
		launcherID  = "p-ada"   // launching user — the DEFAULT approver, NOT who allow-always attributes to
		orgAdminID  = "p-admin" // resolved org-admin acceptor — the D45 allow-always Actor
		orgName     = "acme"
	)
	launcher := store.Principal{ID: launcherID, IdPSubject: "okta|ada", Org: orgName, Roles: []store.PrincipalRole{store.RoleLauncher}}
	admin := store.Principal{ID: orgAdminID, IdPSubject: "okta|admin", Org: orgName, Roles: []store.PrincipalRole{store.RoleOrgAdmin}}
	repo := linkLaunchingUser(t, sessionUUID, launcher, &admin)

	exp := time.Now().Add(time.Hour)
	res, result, err := ResolveAndRoute(ctx, repo, repo,
		askReq(sessionUUID, "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		GrantBody{Rule: "allow *", ExpiresAt: *store.SetTime(exp), Payload: []byte(`{"rule":"allow *"}`)})
	if err != nil {
		t.Fatalf("ResolveAndRoute(allow-always, memory): %v", err)
	}
	if !res.EscalatedToOrgAdmin || res.ApproverPrincipalID != orgAdminID {
		t.Fatalf("resolution = %+v, want escalated to the org-admin %q", res, orgAdminID)
	}
	if !result.Granted {
		t.Fatal("Granted = false, want true for an authorized allow-always")
	}
	if result.Row.Actor != orgAdminID {
		t.Errorf("grant Actor = %q, want the resolved org-admin %q — NOT the launcher %q (D45)", result.Row.Actor, orgAdminID, launcherID)
	}
	if result.Row.Actor == launcherID {
		t.Errorf("allow-always grant attributed to the LAUNCHING USER %q — D45 violation", launcherID)
	}

	// The org-admin Actor is retrievable through the REAL store's own projection.
	grants, err := repo.LiveGrants(ctx, sessionUUID, time.Now())
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("ResolveAndRoute(allow-always) must land exactly one grant, got %d", len(grants))
	}
	if grants[0].Actor != orgAdminID {
		t.Errorf("persisted grant Actor = %q, want the org-admin %q (attribution preserved through the store)", grants[0].Actor, orgAdminID)
	}
	if grants[0].Kind != store.PolicyKindAskGrant {
		t.Errorf("persisted row Kind = %q, want %q", grants[0].Kind, store.PolicyKindAskGrant)
	}
}

// TestResolveAndRoute_AllowOnceAttributesLauncher_MemoryStore is the symmetric proof
// that ResolveAndRoute does NOT over-escalate: an allow-once ask resolves the
// launching-user default and the persisted grant Actor is the LAUNCHER, even though an
// eligible org-admin exists for the session. Only allow-always escalates (D45).
func TestResolveAndRoute_AllowOnceAttributesLauncher_MemoryStore(t *testing.T) {
	ctx := context.Background()
	const (
		sessionUUID = "sess-rar-ao"
		launcherID  = "p-ada"
		orgName     = "acme"
	)
	launcher := store.Principal{ID: launcherID, IdPSubject: "okta|ada", Org: orgName, Roles: []store.PrincipalRole{store.RoleLauncher}}
	// An org-admin EXISTS for the session, proving allow-once does not escalate to it.
	admin := store.Principal{ID: "p-admin", IdPSubject: "okta|admin", Org: orgName, Roles: []store.PrincipalRole{store.RoleOrgAdmin}}
	repo := linkLaunchingUser(t, sessionUUID, launcher, &admin)

	res, result, err := ResolveAndRoute(ctx, repo, repo,
		askReq(sessionUUID, "domain", "github.com"), AskDecisionAllowOnce, AttendednessAttended,
		GrantBody{Rule: "allow github.com", Payload: []byte(`{}`)})
	if err != nil {
		t.Fatalf("ResolveAndRoute(allow-once, memory): %v", err)
	}
	if res.EscalatedToOrgAdmin {
		t.Fatalf("EscalatedToOrgAdmin = true, want false for allow-once (the launcher default)")
	}
	if !result.Granted || result.Row.Actor != launcherID {
		t.Fatalf("allow-once result = %+v, want granted attributed to the launcher %q", result, launcherID)
	}
	grants, err := repo.LiveGrants(ctx, sessionUUID, time.Now())
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].Actor != launcherID {
		t.Fatalf("LiveGrants = %+v, want one grant attributed to the launcher %q", grants, launcherID)
	}
}

// TestResolveAndRoute_DenyWritesNoGrant proves the folded call preserves the
// §6.2-step-4 deny rule end to end: a reasonless deny resolves the launching-user
// default but routes to no policy_log write — Granted and Denied both false, no grant.
func TestResolveAndRoute_DenyWritesNoGrant(t *testing.T) {
	ctx := context.Background()
	const (
		sessionUUID = "sess-rar-deny"
		launcherID  = "p-ada"
	)
	launcher := store.Principal{ID: launcherID, IdPSubject: "okta|ada", Org: "acme", Roles: []store.PrincipalRole{store.RoleLauncher}}
	repo := linkLaunchingUser(t, sessionUUID, launcher, nil)

	_, result, err := ResolveAndRoute(ctx, repo, repo,
		askReq(sessionUUID, "domain", "evil.com"), AskDecisionDeny, AttendednessAttended,
		GrantBody{Rule: "deny evil.com", Payload: []byte(`{}`)})
	if err != nil {
		t.Fatalf("ResolveAndRoute(deny): %v", err)
	}
	if result.Granted || result.Denied {
		t.Errorf("result = %+v, want neither granted nor denied for a reasonless deny", result)
	}
	grants, err := repo.LiveGrants(ctx, sessionUUID, time.Now())
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("a deny must add no grant, got %d", len(grants))
	}
}

// TestResolveAndRoute_ResolutionFailsClosedBeforeWrite proves a fail-closed
// RESOLUTION short-circuits before any write: an allow-always with NO eligible
// org-admin is ErrNoOrgAdminAcceptor (never a launching-user fallback), the router is
// never reached, and nothing is appended. The synthetic resolver pairs a present
// launching user with NO org-admin so the failure is unambiguously the missing
// org-admin; an appender fake proves the write path is never touched.
func TestResolveAndRoute_ResolutionFailsClosedBeforeWrite(t *testing.T) {
	resolver := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			"sess-x": {PrincipalID: "p-ada", Subject: "okta|ada", Org: "acme"},
		},
		// orgAdmin empty -> ResolveOrgAdminAcceptor returns ok==false (fail-closed).
	}
	router := newRouterFake(approverPrincipal())
	res, result, err := ResolveAndRoute(context.Background(), resolver, router,
		askReq("sess-x", "domain", "evil.com"), AskDecisionAllowAlways, AttendednessAttended,
		GrantBody{Rule: "allow *", Payload: []byte(`{}`)})
	if !errors.Is(err, ErrNoOrgAdminAcceptor) {
		t.Fatalf("ResolveAndRoute error = %v, want ErrNoOrgAdminAcceptor (D45 fail-closed)", err)
	}
	if res.ApproverPrincipalID != "" || result.Granted || result.Denied {
		t.Errorf("a fail-closed resolution must yield zero result, got res=%+v result=%+v", res, result)
	}
	if len(router.appender.rows) != 0 {
		t.Fatalf("a fail-closed resolution must never reach the write, got %d rows", len(router.appender.rows))
	}
}

// TestResolveAndRoute_RouteErrorSurfaces proves a routing-stage failure surfaces with
// the resolution still returned (so the caller can audit who WAS resolved): an
// allow-once whose resolved launcher is NOT a permitted approver in the router store
// is refused with ErrNotApprover and writes no grant. The resolver resolves the
// launcher; the router holds the same ID but stripped of any approver role.
func TestResolveAndRoute_RouteErrorSurfaces(t *testing.T) {
	resolver := approverResolverFake{
		launching: map[string]store.LaunchingUserClaim{
			"sess-x": {PrincipalID: "p-eve", Subject: "okta|eve", Org: "acme"},
		},
	}
	router := newRouterFake(nonApproverPrincipal()) // p-eve is a viewer, not an approver
	res, result, err := ResolveAndRoute(context.Background(), resolver, router,
		askReq("sess-x", "domain", "github.com"), AskDecisionAllowOnce, AttendednessAttended,
		GrantBody{Rule: "allow github.com", Payload: []byte(`{}`)})
	if !errors.Is(err, ErrNotApprover) {
		t.Fatalf("ResolveAndRoute error = %v, want ErrNotApprover", err)
	}
	if res.ApproverPrincipalID != "p-eve" {
		t.Errorf("resolution should still report the resolved approver p-eve, got %q", res.ApproverPrincipalID)
	}
	if result.Granted {
		t.Error("Granted = true, want false for a refused approval")
	}
	if len(router.appender.rows) != 0 {
		t.Fatalf("a refused approval must write no row, got %d", len(router.appender.rows))
	}
}

// TestResolveAndRoute_CarriesGrantBody proves the GrantBody inputs (rule, TTL,
// consent, payload) are threaded through the fold onto the persisted grant unchanged
// — the body describes WHAT is granted and is carried verbatim, while WHO/WHICH-session
// come solely from the resolution.
func TestResolveAndRoute_CarriesGrantBody(t *testing.T) {
	ctx := context.Background()
	const (
		sessionUUID = "sess-rar-body"
		launcherID  = "p-ada"
	)
	launcher := store.Principal{ID: launcherID, IdPSubject: "okta|ada", Org: "acme", Roles: []store.PrincipalRole{store.RoleLauncher}}
	repo := linkLaunchingUser(t, sessionUUID, launcher, nil)

	exp := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	payload := []byte(`{"rule":"allow github.com"}`)
	_, result, err := ResolveAndRoute(ctx, repo, repo,
		askReq(sessionUUID, "domain", "github.com"), AskDecisionAllowOnce, AttendednessAttended,
		GrantBody{Rule: "allow github.com", ExpiresAt: *store.SetTime(exp), Consent: store.ConsentClassUnspecified, Payload: payload})
	if err != nil {
		t.Fatalf("ResolveAndRoute(body): %v", err)
	}
	if !result.Granted {
		t.Fatal("Granted = false, want true")
	}
	if result.Row.SessionUUID != sessionUUID {
		t.Errorf("row SessionUUID = %q, want %q", result.Row.SessionUUID, sessionUUID)
	}
	if result.Row.ExpiresAt == nil || !result.Row.ExpiresAt.Equal(exp) {
		t.Errorf("row ExpiresAt = %v, want %v", result.Row.ExpiresAt, exp)
	}
	if string(result.Row.Payload) != string(payload) {
		t.Errorf("row Payload = %q, want the composed grant body %q", string(result.Row.Payload), string(payload))
	}
}

// TestResolveAndRoute_AllowAlwaysAttributesOrgAdmin_PostgresStore is the *store.Postgres
// twin of the Memory proof (TestResolveAndRoute_AllowAlwaysAttributesOrgAdmin_MemoryStore):
// the D45 allow-always attribution must follow the resolution through the REAL Postgres
// store too, not only the in-memory one. Both store impls satisfy askApproverResolver +
// askRouter via the compile-time var checks at the top of askrouting.go / askroute_resolve.go,
// but until now NO test exercised the folded ResolveAndRoute against the Postgres org-admin
// election (ResolveOrgAdminAcceptor) + the LiveGrants projection. This closes that gap: an
// allow-always ask routed through ResolveAndRoute over *store.Postgres escalates to the
// org-admin acceptor and the persisted ask-grant row's Actor — read back through the store's
// own LiveGrants — IS the org-admin (p-admin), NOT the launching user (p-ada).
//
// SYNTHETIC GATE (D50): the twin is DS_ORCH_PG_DSN-gated and SKIPS cleanly when no live
// Postgres is reachable (no DSN, an unregistered driver, or an unreachable DB) — so the
// default `go test ./...` gate runs NO live DB. A live run is a DEFERRED MANUAL STEP an
// operator enables by exporting DS_ORCH_PG_DSN (and registering a driver via
// DS_ORCH_PG_DRIVER, D33 — this module stays stdlib-only and imports no Postgres driver).
// The compile-time satisfies-interface proof (var _ askApproverResolver / askRouter =
// (*store.Postgres)(nil), already in the package) is what holds in the sandbox gate; this
// test ADDS the live behavioral proof for when the DB is present.
func TestResolveAndRoute_AllowAlwaysAttributesOrgAdmin_PostgresStore(t *testing.T) {
	ctx := context.Background()
	repo := linkLaunchingUserPostgres(t)

	const (
		sessionUUID = "policylog-rar-pg-aa-1"
		launcherID  = "p-ada"   // launching user — the DEFAULT approver, NOT who allow-always attributes to
		orgAdminID  = "p-admin" // resolved org-admin acceptor — the D45 allow-always Actor
		orgName     = "acme"
	)
	launcher := store.Principal{ID: launcherID, IdPSubject: "okta|ada-pg", Org: orgName, Roles: []store.PrincipalRole{store.RoleLauncher}}
	admin := store.Principal{ID: orgAdminID, IdPSubject: "okta|admin-pg", Org: orgName, Roles: []store.PrincipalRole{store.RoleOrgAdmin}}

	// Seed the same fixture linkLaunchingUser builds for Memory, but in the live store.
	mustNoPGErr(t, func() error { _, e := repo.CreatePrincipal(ctx, launcher); return e }())
	mustNoPGErr(t, func() error { _, e := repo.CreatePrincipal(ctx, admin); return e }())
	mustNoPGErr(t, func() error {
		_, e := repo.CreateSession(ctx, store.Session{Ref: store.SessionRef{SessionUUID: sessionUUID}})
		return e
	}())
	mustNoPGErr(t, repo.SetSessionLaunchingPrincipal(ctx, sessionUUID, launcherID))

	exp := time.Now().Add(time.Hour)
	res, result, err := ResolveAndRoute(ctx, repo, repo,
		askReq(sessionUUID, "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		GrantBody{Rule: "allow *", ExpiresAt: *store.SetTime(exp), Payload: []byte(`{"rule":"allow *"}`)})
	if err != nil {
		t.Fatalf("ResolveAndRoute(allow-always, postgres): %v", err)
	}
	if !res.EscalatedToOrgAdmin || res.ApproverPrincipalID != orgAdminID {
		t.Fatalf("resolution = %+v, want escalated to the org-admin %q", res, orgAdminID)
	}
	if !result.Granted {
		t.Fatal("Granted = false, want true for an authorized allow-always")
	}
	if result.Row.Actor != orgAdminID {
		t.Errorf("grant Actor = %q, want the resolved org-admin %q — NOT the launcher %q (D45)", result.Row.Actor, orgAdminID, launcherID)
	}
	if result.Row.Actor == launcherID {
		t.Errorf("allow-always grant attributed to the LAUNCHING USER %q — D45 violation", launcherID)
	}

	// The org-admin Actor is retrievable through the live store's OWN LiveGrants
	// projection — the attribution followed the resolution all the way to the
	// persisted Postgres row (mirrors the Memory proof against the real engine).
	grants, err := repo.LiveGrants(ctx, sessionUUID, time.Now())
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("ResolveAndRoute(allow-always) must land exactly one grant, got %d", len(grants))
	}
	if grants[0].Actor != orgAdminID {
		t.Errorf("persisted grant Actor = %q, want the org-admin %q (attribution preserved through Postgres)", grants[0].Actor, orgAdminID)
	}
	if grants[0].Kind != store.PolicyKindAskGrant {
		t.Errorf("persisted row Kind = %q, want %q", grants[0].Kind, store.PolicyKindAskGrant)
	}
}

// linkLaunchingUserPostgres opens a live *store.Postgres the SAME way
// controlplane.NewPostgresStore does (sql.Open + store.NewPostgres), applies the
// orchestrator migrations, and cleans this twin's own rows — so the Postgres org-admin
// proof seeds against the persisted record, mirroring linkLaunchingUser's Memory setup.
// It SKIPS — never fails — without DS_ORCH_PG_DSN, an unregistered driver, or an
// unreachable DB, so the default `go test ./...` gate is a clean no-op (D50). It uses
// the DS_ORCH_PG_DSN / DS_ORCH_PG_DRIVER env (distinct from the DS_PG_DSN suites' truncate
// lifecycle) and deletes ONLY the keys this twin creates — it never truncates the shared
// tables. Returns the store ready to feed ResolveAndRoute as BOTH the resolver and router
// (Postgres satisfies askApproverResolver and askRouter).
func linkLaunchingUserPostgres(t *testing.T) *store.Postgres {
	t.Helper()
	// The sql.Open + 5s-ping + skip dance is single-sourced through storetest.OpenOrSkip;
	// this twin keeps its OWN env var (DS_ORCH_PG_DSN / DS_ORCH_PG_DRIVER, distinct from the
	// DS_PG_DSN suites' truncate lifecycle) and its OWN three D50/D33-worded skip strings
	// (passed via SkipMessages so the wording stays byte-identical), plus its OWN post-open
	// steps: applyPolicylogMigrations + the per-twin row cleanup + store.NewPostgres wrap.
	db := storetest.OpenOrSkip(t, "DS_ORCH_PG_DSN", "DS_ORCH_PG_DRIVER", storetest.SkipMessages{
		Unset:   "DS_ORCH_PG_DSN not set: skipping live-Postgres org-admin attribution twin (deferred manual step, D50)",
		OpenErr: "sql.Open(%q): %v — register a Postgres driver at the binary boundary (DS_ORCH_PG_DRIVER, D33) to run this",
		PingErr: "ping %s: %v — Postgres unreachable; deferred manual step (set DS_ORCH_PG_DSN to a reachable DB)",
	})

	applyCtx, applyCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer applyCancel()
	applyPolicylogMigrations(applyCtx, t, db)

	// This twin owns its own session_uuid / principal-id space; remove its rows before
	// and after so the proof is independent of prior state and leaves the DB as found.
	const sessionUUID = "policylog-rar-pg-aa-1"
	cleanupPolicylogTwin(applyCtx, db, sessionUUID)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cleanupPolicylogTwin(c, db, sessionUUID)
	})

	return store.NewPostgres(db)
}

// policylogMigrationName matches the orchestrator/migrations apply-ordering convention
// (a zero-padded 4-digit sequence prefix == apply order), so LEXICAL filename order ==
// NUMERIC apply order. Single-sourced from storetest.MigrationNamePattern — the same
// *regexp.Regexp postgres_open_conformance_test.go and apply_smoke_test.go use.
var policylogMigrationName = storetest.MigrationNamePattern

// policylogMigrationsDir is the migrations directory relative to this package
// (orchestrator/internal/policylog → orchestrator/migrations).
const policylogMigrationsDir = "../../migrations"

// applyPolicylogMigrations applies orchestrator/migrations/NNNN_*.sql in lexical order,
// re-runnably (a schema_migrations ledger skips already-applied files — the apply.sh
// re-run posture), so applying the set to a populated DB is a safe no-op and a fresh DB
// gets the full schema in order. Each file rides its own single-transaction Exec with the
// ledger insert (a half-applied file never records as done). A failure here is a real
// conformance failure (the store could not take the schema), not a skip.
func applyPolicylogMigrations(ctx context.Context, t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());`,
	); err != nil {
		t.Fatalf("create schema_migrations ledger: %v", err)
	}
	for _, name := range policylogMigrationFiles(t) {
		version := name[:len(name)-len(".sql")]
		var applied bool
		if err := db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`, version,
		).Scan(&applied); err != nil {
			t.Fatalf("check schema_migrations for %s: %v", version, err)
		}
		if applied {
			continue
		}
		ddl, err := os.ReadFile(filepath.Join(policylogMigrationsDir, name))
		if err != nil {
			t.Fatalf("read migration %s: %v", name, err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin tx for migration %s: %v", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(ddl)); err != nil {
			_ = tx.Rollback()
			t.Fatalf("apply migration %s: %v", name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback()
			t.Fatalf("record migration %s in ledger: %v", version, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit migration %s: %v", name, err)
		}
	}
}

// policylogMigrationFiles returns the NNNN_*.sql migration basenames in lexical order
// (== apply order). It reads the directory by FILENAME (imports no .sql, edits nothing).
func policylogMigrationFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(policylogMigrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir %s: %v", policylogMigrationsDir, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if policylogMigrationName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		t.Fatalf("no NNNN_*.sql migrations found in %s", policylogMigrationsDir)
	}
	sort.Strings(names)
	return names
}

// cleanupPolicylogTwin removes this twin's own rows (its policy_log grants, session, the
// seeded index epochs, and the two principals it creates) so the proof is independent of
// prior state and leaves the target DB as it found it. It never truncates the shared
// tables (the DS_PG_DSN suites own that lifecycle); it deletes only the keys this twin
// creates, in FK-safe order — sessions reference principals(id) via launching_principal,
// and policy_log / session_index_epochs reference sessions(session_uuid), so the session
// rows drop before the principals (roles are a jsonb column on principals, NOT a separate
// table). Best effort: a missing schema or row is not an error here (cleanup runs before
// the migrations on first entry).
func cleanupPolicylogTwin(ctx context.Context, db *sql.DB, sessionUUID string) {
	stmts := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM policy_log WHERE session_uuid = $1`, []any{sessionUUID}},
		{`DELETE FROM session_index_epochs WHERE session_uuid = $1`, []any{sessionUUID}},
		{`DELETE FROM sessions WHERE session_uuid = $1`, []any{sessionUUID}},
		{`DELETE FROM principals WHERE id = $1`, []any{"p-ada"}},
		{`DELETE FROM principals WHERE id = $1`, []any{"p-admin"}},
	}
	for _, s := range stmts {
		// Ignore "relation does not exist" / missing-row: cleanup may run before the
		// migrations on first entry, and an absent row is the desired post-state.
		_, _ = db.ExecContext(ctx, s.sql, s.args...)
	}
}

// mustNoPGErr fails the test on a non-nil error from a live-Postgres seed step. It is the
// twin's local fatal-on-error helper (the store package's own mustNoErr is unexported and
// in a different package), kept here so the Postgres twin is self-contained.
func mustNoPGErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("postgres twin setup: %v", err)
	}
}
