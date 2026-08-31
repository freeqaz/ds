package policylog

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// passthroughComposer is a trivial SnapshotComposer for the WatchPolicies serving
// tests: it stamps seq onto a snapshot whose content_hash is derived from the row
// count up to seq, so the replay choreography (cursor, idempotence, ordering, one-
// subscriber-per-host) is asserted independently of the deny-wins fold (covered in
// composer_test.go).
type passthroughComposer struct{}

func (passthroughComposer) ComposeAt(_ context.Context, seq int64, rows []store.PolicyLogRow, _ time.Time) (Snapshot, error) {
	return ComposeSnapshot(seq, ComposedPolicy{}, nil), nil
}

// collectEmitter records every emitted snapshot in order.
type collectEmitter struct{ snaps []Snapshot }

func (e *collectEmitter) Emit(_ context.Context, s Snapshot) error {
	e.snaps = append(e.snaps, s)
	return nil
}

func seqsOf(snaps []Snapshot) []int64 {
	out := make([]int64, len(snaps))
	for i, s := range snaps {
		out[i] = s.Seq
	}
	return out
}

// TestAppendPolicy_RecordsActor proves the §5.3 append leg stamps the actor and
// the store assigns the bigserial seq (D36/D72).
func TestAppendPolicy_RecordsActor(t *testing.T) {
	st := store.NewMemory()
	svc := NewService(st, passthroughComposer{})

	row, err := svc.AppendPolicy(context.Background(), store.PolicyLogRow{Actor: "org-admin", Payload: []byte(`{}`)})
	if err != nil {
		t.Fatalf("AppendPolicy: %v", err)
	}
	if row.Actor != "org-admin" {
		t.Errorf("Actor = %q, want %q", row.Actor, "org-admin")
	}
	if row.Seq == 0 {
		t.Error("Seq = 0, want a store-assigned bigserial")
	}
	if row.Kind != store.PolicyKindAppend {
		t.Errorf("Kind = %q, want %q (default for an authored append)", row.Kind, store.PolicyKindAppend)
	}
}

// TestAppendPolicy_RefusesEmptyActor proves the audit-trail invariant (D36): an
// empty actor is refused before any write, so no unattributed row is persisted.
func TestAppendPolicy_RefusesEmptyActor(t *testing.T) {
	st := store.NewMemory()
	svc := NewService(st, passthroughComposer{})

	_, err := svc.AppendPolicy(context.Background(), store.PolicyLogRow{Actor: ""})
	if !errors.Is(err, ErrActorRequired) {
		t.Fatalf("error = %v, want ErrActorRequired", err)
	}
	rows, _ := st.ListPolicy(context.Background(), 0, 0)
	if len(rows) != 0 {
		t.Fatalf("a refused append must persist no row, got %d", len(rows))
	}
}

// TestWatchPolicies_ReplaysFromCursor proves the §5.3/D72 catch-up: WatchPolicies
// replays composed snapshots from fromSeq in ascending seq order, and a from_seq
// past part of the log skips the already-applied rows.
func TestWatchPolicies_ReplaysFromCursor(t *testing.T) {
	st := store.NewMemory()
	svc := NewService(st, passthroughComposer{})
	for i := 0; i < 3; i++ {
		if _, err := svc.AppendPolicy(context.Background(), store.PolicyLogRow{Actor: "a"}); err != nil {
			t.Fatal(err)
		}
	}

	// Full replay from 0 → seqs 1,2,3.
	e := &collectEmitter{}
	if err := svc.WatchPolicies(context.Background(), "host-1", 0, e); err != nil {
		t.Fatalf("WatchPolicies: %v", err)
	}
	if got := seqsOf(e.snaps); !equalInt64(got, []int64{1, 2, 3}) {
		t.Fatalf("full replay seqs = %v, want [1 2 3]", got)
	}

	// Catch-up from seq 1 → only 2,3 (the host already applied 1).
	e2 := &collectEmitter{}
	if err := svc.WatchPolicies(context.Background(), "host-1", 1, e2); err != nil {
		t.Fatalf("WatchPolicies(from=1): %v", err)
	}
	if got := seqsOf(e2.snaps); !equalInt64(got, []int64{2, 3}) {
		t.Fatalf("catch-up seqs = %v, want [2 3]", got)
	}
}

// TestWatchPolicies_ReplayIsIdempotent proves re-subscribing at the same from_seq
// yields byte-identical snapshots (same seq + content_hash) — a reconnecting host
// catches up to exactly the same state (D36 idempotent replay).
func TestWatchPolicies_ReplayIsIdempotent(t *testing.T) {
	st := store.NewMemory()
	svc := NewService(st, passthroughComposer{})
	for i := 0; i < 2; i++ {
		_, _ = svc.AppendPolicy(context.Background(), store.PolicyLogRow{Actor: "a"})
	}

	e1, e2 := &collectEmitter{}, &collectEmitter{}
	_ = svc.WatchPolicies(context.Background(), "host-1", 0, e1)
	_ = svc.WatchPolicies(context.Background(), "host-1", 0, e2)

	if len(e1.snaps) != len(e2.snaps) {
		t.Fatalf("replay lengths differ: %d vs %d", len(e1.snaps), len(e2.snaps))
	}
	for i := range e1.snaps {
		if e1.snaps[i].Seq != e2.snaps[i].Seq || e1.snaps[i].ContentHash != e2.snaps[i].ContentHash {
			t.Errorf("frame %d differs across replays: %+v vs %+v", i, e1.snaps[i], e2.snaps[i])
		}
	}
}

// TestWatchPolicies_OneSubscriberPerHost proves the D72 topology invariant: a
// SECOND concurrent subscription for a host already streaming is refused with
// ErrHostAlreadySubscribed; a different host is admitted; and a clean reconnect
// (after the first stream returned) is admitted.
func TestWatchPolicies_OneSubscriberPerHost(t *testing.T) {
	st := store.NewMemory()
	_, _ = NewService(st, passthroughComposer{}).AppendPolicy(context.Background(), store.PolicyLogRow{Actor: "a"})
	svc := NewService(st, passthroughComposer{})

	// Hold host-1's subscription open inside a blocking emitter, then attempt a
	// second subscribe for host-1 concurrently and assert it is refused.
	release := make(chan struct{})
	started := make(chan struct{})
	var firstErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		firstErr = svc.WatchPolicies(context.Background(), "host-1", 0, EmitterFunc(func(_ context.Context, _ Snapshot) error {
			close(started)
			<-release // hold the subscription open
			return nil
		}))
	}()
	<-started // the first subscription is live

	// Second subscribe for the SAME host → refused (D72).
	if err := svc.WatchPolicies(context.Background(), "host-1", 0, &collectEmitter{}); !errors.Is(err, ErrHostAlreadySubscribed) {
		t.Errorf("second subscribe for host-1 = %v, want ErrHostAlreadySubscribed", err)
	}
	// A DIFFERENT host is admitted concurrently.
	if err := svc.WatchPolicies(context.Background(), "host-2", 0, &collectEmitter{}); err != nil {
		t.Errorf("subscribe for host-2 = %v, want nil (a different host is fine)", err)
	}

	close(release)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("first WatchPolicies returned %v", firstErr)
	}

	// Clean reconnect for host-1 (the first stream returned) is admitted.
	if err := svc.WatchPolicies(context.Background(), "host-1", 0, &collectEmitter{}); err != nil {
		t.Errorf("reconnect for host-1 after a clean disconnect = %v, want nil", err)
	}
}

// TestWatchPolicies_RequiresHostID proves the subscriber identity is mandatory
// (D72 — the one subscriber is the host agent, identified by host_id).
func TestWatchPolicies_RequiresHostID(t *testing.T) {
	svc := NewService(store.NewMemory(), passthroughComposer{})
	if err := svc.WatchPolicies(context.Background(), "", 0, &collectEmitter{}); err == nil {
		t.Fatal("WatchPolicies with an empty host_id must error")
	}
}

// TestApproveAsk_OnService proves the service surfaces the §4.3 gate+attribution
// seam: an authorized approver appends a TTL'd session-scoped ask-grant whose
// Actor is the approver; a non-approver is refused with no row written.
func TestApproveAsk_OnService(t *testing.T) {
	st := store.NewMemory()
	svc := NewService(st, passthroughComposer{})
	exp := store.SetTime(time.Unix(9_999_999_999, 0))

	row, err := svc.ApproveAsk(context.Background(),
		store.Principal{ID: "p-ada", Roles: []store.PrincipalRole{store.RoleLauncher}},
		"sess-1", "allow github.com", *exp, store.ConsentClassUnspecified, []byte(`{}`))
	if err != nil {
		t.Fatalf("ApproveAsk (approver): %v", err)
	}
	if row.Kind != store.PolicyKindAskGrant || row.Actor != "p-ada" || row.SessionUUID != "sess-1" {
		t.Errorf("ask-grant row = %+v, want kind=ask_grant actor=p-ada session=sess-1", row)
	}

	_, err = svc.ApproveAsk(context.Background(),
		store.Principal{ID: "p-eve", Roles: []store.PrincipalRole{store.RoleViewer}},
		"sess-1", "allow github.com", store.OptTime{}, store.ConsentClassUnspecified, []byte(`{}`))
	if !errors.Is(err, ErrNotApprover) {
		t.Errorf("ApproveAsk (viewer) = %v, want ErrNotApprover", err)
	}
}

// TestRouteInboundAsk_AllowAlwaysAttributesOrgAdmin proves the Service-level inbound
// fold drives ResolveAndRoute (NOT the bare ApproveAsk): an INBOUND allow-always ask
// routed through Service.RouteInboundAsk escalates to the org-admin acceptor (D45) and
// the persisted ask-grant row's Actor — read back through the store's own LiveGrants
// projection — IS the org-admin, NOT the launching user. NewService AUTO-DETECTS the
// resolver/router seams off the *store.Memory it is constructed with, so the fold is
// armed against the same persisted backend with no extra wiring. This closes the D45
// footgun at the Service seam: there is no path through RouteInboundAsk that lets an
// allow-always be attributed to the launcher.
func TestRouteInboundAsk_AllowAlwaysAttributesOrgAdmin(t *testing.T) {
	ctx := context.Background()
	const (
		sessionUUID = "sess-svc-aa"
		launcherID  = "p-ada"   // launching user — the DEFAULT approver, NOT who allow-always attributes to
		orgAdminID  = "p-admin" // resolved org-admin acceptor — the D45 allow-always Actor
		orgName     = "acme"
	)
	launcher := store.Principal{ID: launcherID, IdPSubject: "okta|ada", Org: orgName, Roles: []store.PrincipalRole{store.RoleLauncher}}
	admin := store.Principal{ID: orgAdminID, IdPSubject: "okta|admin", Org: orgName, Roles: []store.PrincipalRole{store.RoleOrgAdmin}}
	repo := linkLaunchingUser(t, sessionUUID, launcher, &admin)

	// NewService auto-detects the ask-routing seams off the Memory store (no
	// WithAskRouting needed): the fold is armed against the same persisted backend.
	svc := NewService(repo, passthroughComposer{})

	exp := time.Now().Add(time.Hour)
	res, result, err := svc.RouteInboundAsk(ctx,
		askReq(sessionUUID, "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		GrantBody{Rule: "allow *", ExpiresAt: *store.SetTime(exp), Payload: []byte(`{"rule":"allow *"}`)})
	if err != nil {
		t.Fatalf("RouteInboundAsk(allow-always): %v", err)
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

	// The org-admin Actor is retrievable through the store's own projection — the
	// attribution followed the resolution all the way to the persisted row.
	grants, err := repo.LiveGrants(ctx, sessionUUID, time.Now())
	if err != nil {
		t.Fatalf("LiveGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("RouteInboundAsk(allow-always) must land exactly one grant, got %d", len(grants))
	}
	if grants[0].Actor != orgAdminID {
		t.Errorf("persisted grant Actor = %q, want the org-admin %q (attribution preserved through the store)", grants[0].Actor, orgAdminID)
	}
	if grants[0].Kind != store.PolicyKindAskGrant {
		t.Errorf("persisted row Kind = %q, want %q", grants[0].Kind, store.PolicyKindAskGrant)
	}
}

// TestRouteInboundAsk_AllowOnceAttributesLauncher is the symmetric proof that the
// Service fold does NOT over-escalate: an inbound allow-once ask resolves the
// launching-user default and the persisted grant Actor is the LAUNCHER, even though an
// eligible org-admin exists for the session. Only allow-always escalates (D45).
func TestRouteInboundAsk_AllowOnceAttributesLauncher(t *testing.T) {
	ctx := context.Background()
	const (
		sessionUUID = "sess-svc-ao"
		launcherID  = "p-ada"
		orgName     = "acme"
	)
	launcher := store.Principal{ID: launcherID, IdPSubject: "okta|ada", Org: orgName, Roles: []store.PrincipalRole{store.RoleLauncher}}
	admin := store.Principal{ID: "p-admin", IdPSubject: "okta|admin", Org: orgName, Roles: []store.PrincipalRole{store.RoleOrgAdmin}}
	repo := linkLaunchingUser(t, sessionUUID, launcher, &admin)
	svc := NewService(repo, passthroughComposer{})

	res, result, err := svc.RouteInboundAsk(ctx,
		askReq(sessionUUID, "domain", "github.com"), AskDecisionAllowOnce, AttendednessAttended,
		GrantBody{Rule: "allow github.com", Payload: []byte(`{}`)})
	if err != nil {
		t.Fatalf("RouteInboundAsk(allow-once): %v", err)
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

// TestRouteInboundAsk_WithAskRoutingOption proves the explicit wiring path: a Service
// constructed over a NARROWED store (the policy_log-only seam that does NOT satisfy the
// resolver/router seams, the shape main.go type-asserts) arms the fold via the
// WithAskRouting option, and the inbound allow-always still attributes the org-admin.
// This is the wiring point for the live binary when its store is narrowed past the
// resolver seams but a full store is available to drive the fold.
func TestRouteInboundAsk_WithAskRoutingOption(t *testing.T) {
	ctx := context.Background()
	const (
		sessionUUID = "sess-svc-opt"
		launcherID  = "p-ada"
		orgAdminID  = "p-admin"
		orgName     = "acme"
	)
	launcher := store.Principal{ID: launcherID, IdPSubject: "okta|ada", Org: orgName, Roles: []store.PrincipalRole{store.RoleLauncher}}
	admin := store.Principal{ID: orgAdminID, IdPSubject: "okta|admin", Org: orgName, Roles: []store.PrincipalRole{store.RoleOrgAdmin}}
	repo := linkLaunchingUser(t, sessionUUID, launcher, &admin)

	// Hand NewService a store narrowed to JUST the policy_log seam (no resolver/router),
	// so auto-detection finds nothing — then wire the fold explicitly off the full store.
	svc := NewService(narrowPolicyStore{repo}, passthroughComposer{}, WithAskRouting(repo, repo))

	res, result, err := svc.RouteInboundAsk(ctx,
		askReq(sessionUUID, "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		GrantBody{Rule: "allow *", Payload: []byte(`{}`)})
	if err != nil {
		t.Fatalf("RouteInboundAsk(allow-always, WithAskRouting): %v", err)
	}
	if !res.EscalatedToOrgAdmin || res.ApproverPrincipalID != orgAdminID {
		t.Fatalf("resolution = %+v, want escalated to the org-admin %q", res, orgAdminID)
	}
	if !result.Granted || result.Row.Actor != orgAdminID {
		t.Fatalf("allow-always result = %+v, want granted attributed to the org-admin %q (D45)", result, orgAdminID)
	}
}

// TestRouteInboundAsk_FailsClosedWithoutSeams proves the fold fails CLOSED when the
// ask-routing seams are not wired: a Service over a narrowed store (no resolver/router
// auto-detected) and no WithAskRouting returns ErrAskRoutingUnavailable and writes NO
// row — it never silently degrades to the bare ApproveAsk (which would reintroduce the
// D45 launching-user footgun the fold exists to close).
func TestRouteInboundAsk_FailsClosedWithoutSeams(t *testing.T) {
	ctx := context.Background()
	repo := store.NewMemory()
	svc := NewService(narrowPolicyStore{repo}, passthroughComposer{})

	_, _, err := svc.RouteInboundAsk(ctx,
		askReq("sess-svc-closed", "domain", "github.com"), AskDecisionAllowAlways, AttendednessAttended,
		GrantBody{Rule: "allow *", Payload: []byte(`{}`)})
	if !errors.Is(err, ErrAskRoutingUnavailable) {
		t.Fatalf("RouteInboundAsk without seams = %v, want ErrAskRoutingUnavailable", err)
	}
	rows, _ := repo.ListPolicy(ctx, 0, 0)
	if len(rows) != 0 {
		t.Fatalf("a fold that fails closed must persist no row, got %d", len(rows))
	}
}

// narrowPolicyStore wraps a store as JUST the policyStore seam (AppendPolicy /
// ListPolicy / LiveGrants), shadowing the embedded store's GetPrincipal /
// ResolveLaunchingUserClaim / ResolveOrgAdminAcceptor so it does NOT satisfy
// askApproverResolver / askRouter — mirroring the narrowed policy_log-only store
// main.go type-asserts the live store onto. It exists to prove NewService's
// auto-detection finds nothing on a narrowed store (the WithAskRouting / fail-closed
// paths) WITHOUT a method-promotion accident arming the fold.
type narrowPolicyStore struct{ st policyStore }

func (n narrowPolicyStore) AppendPolicy(ctx context.Context, row store.PolicyLogRow) (store.PolicyLogRow, error) {
	return n.st.AppendPolicy(ctx, row)
}

func (n narrowPolicyStore) ListPolicy(ctx context.Context, fromSeq int64, limit int) ([]store.PolicyLogRow, error) {
	return n.st.ListPolicy(ctx, fromSeq, limit)
}

func (n narrowPolicyStore) LiveGrants(ctx context.Context, sessionUUID string, now time.Time) ([]store.PolicyLogRow, error) {
	return n.st.LiveGrants(ctx, sessionUUID, now)
}

// Compile-time proof of the narrowing: narrowPolicyStore is a policyStore but is
// NEITHER an askApproverResolver NOR an askRouter (the seams NewService auto-detects).
var (
	_ policyStore = narrowPolicyStore{}
	// (narrowPolicyStore deliberately does NOT satisfy askApproverResolver / askRouter)
)

func equalInt64(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
