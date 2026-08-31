// SPDX-License-Identifier: Apache-2.0

package idp

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// flows_test.go drives the two mint-time human-auth flows of doc 16 §11.2 — the
// CLI device-code grant and the web redirect flow — plus the §11.2 group→role
// mapping and the offboarding ladder, all against the fake OIDC server (D50).

// TestDeviceFlow_Success proves the RFC 8628 device-code flow end to end: the
// CLI gets a prompt to show the human, polls while the IdP returns
// authorization_pending, and once the human "completes auth in the browser"
// (approveDevice) converges on a validated AuthResult whose subject is the
// launching_user value and whose roles are the §11.2 group→role mapping.
func TestDeviceFlow_Success(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	cfg := f.config("acme", map[string]PlatformRole{
		"eng-platform-admins": RoleOrgAdmin,
		"eng-all":             RoleLauncher,
	})
	p := providerForFake(t, f, cfg, time.Now())

	f.scriptDevice("dev-code-1", map[string]any{
		"sub":    "okta|ada",
		"email":  "ada@acme.example",
		"groups": []string{"eng-all", "eng-platform-admins"},
	})

	flow := NewDeviceFlow(p).withSleep(func(time.Duration) {})

	// Approve on the 2nd poll: stays pending for one poll, then succeeds.
	polls := 0
	flow.sleep = func(time.Duration) {
		polls++
		if polls == 2 {
			f.approveDevice("dev-code-1")
		}
	}

	var shown DevicePrompt
	res, err := flow.Authenticate(context.Background(), func(p DevicePrompt) { shown = p })
	if err != nil {
		t.Fatalf("device flow: %v", err)
	}
	if shown.UserCode == "" || shown.VerificationURI == "" {
		t.Errorf("prompt not shown to the human: %+v", shown)
	}
	if res.Subject != "okta|ada" {
		t.Errorf("Subject = %q, want okta|ada (the launching_user value)", res.Subject)
	}
	if res.Org != "acme" {
		t.Errorf("Org = %q, want acme", res.Org)
	}
	wantRoles := []PlatformRole{RoleLauncher, RoleOrgAdmin} // §3.2 order
	if !reflect.DeepEqual(res.Roles, wantRoles) {
		t.Errorf("Roles = %v, want %v (group→role mapping)", res.Roles, wantRoles)
	}
}

// TestDeviceFlow_Denied proves a human who denies consent yields ErrAuth (launch
// refused, no principal) — the access_denied terminal of RFC 8628 §3.5.
func TestDeviceFlow_Denied(t *testing.T) {
	f := newFakeOIDC(t, "RS256", "ds-client")
	p := providerForFake(t, f, f.config("acme", nil), time.Now())
	f.scriptDevice("dev-deny", map[string]any{"sub": "okta|x"})

	// Make the device endpoint hand out "dev-deny" and the token endpoint deny.
	f.denyDevice("dev-deny")

	flow := NewDeviceFlow(p).withSleep(func(time.Duration) {})
	_, err := flow.Authenticate(context.Background(), nil)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("denied device auth should be ErrAuth, got %v", err)
	}
}

// TestRedirectFlow_Seam proves the web redirect-flow SEAM (the D18 web client is
// a separate epic): AuthURL builds a PKCE authorization redirect, and Exchange
// swaps the code for an ID token and converges on the SAME AuthResult shape as
// the device flow (§11.2: both flows converge on the same claim mapping).
func TestRedirectFlow_Seam(t *testing.T) {
	f := newFakeOIDC(t, "ES256", "ds-client")
	cfg := f.config("acme", map[string]PlatformRole{"readers": RoleViewer})
	p := providerForFake(t, f, cfg, time.Now())

	rf := NewRedirectFlow(p)
	ar := AuthRequest{
		RedirectURI:   "https://platform.example/callback",
		State:         "state-1",
		Nonce:         "nonce-1",
		CodeChallenge: "challenge-1",
	}
	authURL, err := rf.AuthURL(context.Background(), ar)
	if err != nil {
		t.Fatalf("AuthURL: %v", err)
	}
	for _, want := range []string{
		"response_type=code", "code_challenge_method=S256",
		"state=state-1", "nonce=nonce-1", "client_id=ds-client",
	} {
		if !strings.Contains(authURL, want) {
			t.Errorf("auth URL %q missing %q", authURL, want)
		}
	}

	f.scriptAuthCode("auth-code-1", map[string]any{
		"sub": "okta|grace", "nonce": "nonce-1", "groups": []string{"readers"},
	})
	res, err := rf.Exchange(context.Background(), ar, "auth-code-1", "verifier-1")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if res.Subject != "okta|grace" {
		t.Errorf("Subject = %q, want okta|grace", res.Subject)
	}
	if !reflect.DeepEqual(res.Roles, []PlatformRole{RoleViewer}) {
		t.Errorf("Roles = %v, want [viewer]", res.Roles)
	}
}

// TestMapGroups proves the §11.2 group→role mapping: mapped groups yield roles
// in §3.2 order, de-duplicated; an UNMAPPED group confers NO role (fail-closed).
func TestMapGroups(t *testing.T) {
	cfg := Config{GroupRoleMap: map[string]PlatformRole{
		"eng-platform-admins": RoleOrgAdmin,
		"eng-frontend":        RoleLauncher,
		"eng-backend":         RoleLauncher, // duplicate role
		"read-only":           RoleViewer,
	}}
	got := cfg.MapGroups([]string{"eng-frontend", "eng-backend", "eng-platform-admins", "unmapped-group", "read-only"})
	want := []PlatformRole{RoleLauncher, RoleViewer, RoleOrgAdmin} // §3.2 order, deduped
	if !reflect.DeepEqual(got, want) {
		t.Errorf("MapGroups = %v, want %v", got, want)
	}
	// An entirely-unmapped group list confers nothing (fail-closed default).
	if roles := cfg.MapGroups([]string{"nobody", "nothing"}); len(roles) != 0 {
		t.Errorf("unmapped groups conferred roles %v, want none", roles)
	}
}

// --- offboarding ladder ---

// stubChecker / stubSink / stubSubscriber are synthetic offboarding seams.
type stubChecker struct {
	active bool
	roles  []PlatformRole
	err    error
	calls  []string
}

func (c *stubChecker) CheckActive(_ context.Context, _, subject string) (bool, []PlatformRole, error) {
	c.calls = append(c.calls, subject)
	return c.active, c.roles, c.err
}

type stubSink struct {
	suspended []string
	reason    string
	err       error
}

func (s *stubSink) SuspendUserSessions(_ context.Context, _, subject, reason string) error {
	if s.err != nil {
		return s.err
	}
	s.suspended = append(s.suspended, subject)
	s.reason = reason
	return nil
}

type stubSubscriber struct {
	signals []OffboardingSignal
}

func (s *stubSubscriber) Subscribe(_ context.Context, handle func(OffboardingSignal) error) error {
	for _, sig := range s.signals {
		if err := handle(sig); err != nil {
			return err
		}
	}
	return nil
}

// TestOffboarding_RecheckFloor proves rung 2 (the universal floor): an active
// subject re-checks ok=true with re-read roles; a deprovisioned subject
// re-checks ok=false, so the grant path denies.
func TestOffboarding_RecheckFloor(t *testing.T) {
	checker := &stubChecker{active: true, roles: []PlatformRole{RoleLauncher}}
	sink := &stubSink{}
	o, err := NewOffboarder("acme", checker, sink, nil)
	if err != nil {
		t.Fatalf("NewOffboarder: %v", err)
	}
	ok, roles, err := o.RecheckActive(context.Background(), "okta|ada")
	if err != nil || !ok {
		t.Fatalf("active subject: ok=%v err=%v, want ok=true", ok, err)
	}
	if !reflect.DeepEqual(roles, []PlatformRole{RoleLauncher}) {
		t.Errorf("re-read roles = %v, want [launcher]", roles)
	}

	checker.active = false
	ok, _, err = o.RecheckActive(context.Background(), "okta|ada")
	if err != nil {
		t.Fatalf("deprovisioned re-check err: %v", err)
	}
	if ok {
		t.Error("deprovisioned subject re-checked ok=true, want ok=false (deny new grant)")
	}
}

// TestOffboarding_RecheckFailsClosed proves a checker transport fault is
// surfaced (fail-closed) — the grant path does not issue on an unverifiable
// subject.
func TestOffboarding_RecheckFailsClosed(t *testing.T) {
	checker := &stubChecker{err: errors.New("idp unreachable")}
	o, _ := NewOffboarder("acme", checker, &stubSink{}, nil)
	if _, _, err := o.RecheckActive(context.Background(), "okta|ada"); !errors.Is(err, ErrOffboarding) {
		t.Fatalf("checker fault should be ErrOffboarding, got %v", err)
	}
}

// TestOffboarding_ConfirmFiresSuspend proves rung 3: a confirmed offboarding
// fires the EXISTING suspend signal under SUSPENDED(user) — no new state.
func TestOffboarding_ConfirmFiresSuspend(t *testing.T) {
	sink := &stubSink{}
	o, _ := NewOffboarder("acme", &stubChecker{}, sink, nil)
	if err := o.ConfirmOffboarding(context.Background(), "okta|ada"); err != nil {
		t.Fatalf("ConfirmOffboarding: %v", err)
	}
	if len(sink.suspended) != 1 || sink.suspended[0] != "okta|ada" {
		t.Errorf("suspended = %v, want [okta|ada]", sink.suspended)
	}
	if sink.reason != SuspendReasonUser {
		t.Errorf("suspend reason = %q, want %q (existing D35 user reason)", sink.reason, SuspendReasonUser)
	}
}

// TestOffboarding_WatchSignals proves rung 1: a SCIM/session signal drives a
// suspension through the same existing signal; with no Subscriber the watch is a
// no-op (the floor carries offboarding).
func TestOffboarding_WatchSignals(t *testing.T) {
	sink := &stubSink{}
	sub := &stubSubscriber{signals: []OffboardingSignal{
		{Org: "acme", Subject: "okta|bob", Kind: SignalSCIMDeprovision},
		{Org: "other", Subject: "okta|notours", Kind: SignalSessionRevoked}, // wrong org → ignored
	}}
	o, _ := NewOffboarder("acme", &stubChecker{}, sink, sub)
	if err := o.WatchSignals(context.Background()); err != nil {
		t.Fatalf("WatchSignals: %v", err)
	}
	if len(sink.suspended) != 1 || sink.suspended[0] != "okta|bob" {
		t.Errorf("suspended = %v, want only [okta|bob] (other org ignored)", sink.suspended)
	}

	// No Subscriber wired: WatchSignals is a no-op (floor carries offboarding).
	o2, _ := NewOffboarder("acme", &stubChecker{}, &stubSink{}, nil)
	if err := o2.WatchSignals(context.Background()); err != nil {
		t.Errorf("WatchSignals with no subscriber should be a no-op, got %v", err)
	}
}

// TestNewOffboarder_RequiresFloorAndAction proves the wiring guard: rung 2
// (checker) and rung 3 (sink) are required; rung 1 (subscriber) is optional.
func TestNewOffboarder_RequiresFloorAndAction(t *testing.T) {
	if _, err := NewOffboarder("acme", nil, &stubSink{}, nil); !errors.Is(err, ErrOffboarding) {
		t.Errorf("nil checker should be ErrOffboarding, got %v", err)
	}
	if _, err := NewOffboarder("acme", &stubChecker{}, nil, nil); !errors.Is(err, ErrOffboarding) {
		t.Errorf("nil sink should be ErrOffboarding, got %v", err)
	}
}
