// SPDX-License-Identifier: Apache-2.0

package controlplane

// daemonwire_smoke_test.go is the DS_ORCH_LIVE-gated LIVE-SMOKE for the daemon-wire unit: it
// asserts BOTH runtime-activated DS_ORCH_LIVE seams the wave-1 enrollment landed but left
// undriven, now driven by the live daemon:
//
//   - LEG (b) — the §4.1 step-5 CREDENTIAL-TTL BACKSTOP arm (leg 1, doc 16 §5.4). Serve now
//     launches cp.RunMintExpiry as a joined daemon goroutine off loopCtx (alongside the idle
//     reaper + destroy re-driver). Under DS_ORCH_LIVE the wiring installs the credttl.go
//     MintReconverger, so the Serve-launched backstop re-converges a LIVE record whose persisted
//     §5.6 MintExpiry horizon is already past — raising AlarmCredentialTTLReconverge. Driven over
//     the new serveMintExpiryInterval test-seam (a fast tick) so the pass fires promptly.
//
//   - LEG (2)/(3) — the live inbound-ask ROUTING into the durable D46 park. cp.AskParkRouter (the
//     *parkMachine) is enrolled as the policylog ask-routing park router; a GENUINE rung-2 ask
//     routed through policylog.Service.RouteAsk(park=cp.AskParkRouter) lands in cp.ParkMachine —
//     the live RouteAsk park dispatch main.go's startAskFeed wires (the boundary AskUser transport
//     is the deferred step; the routing core is live and proven here, D50).
//
// The arm SKIPs clean when DS_ORCH_LIVE != 1 (CI gate-off), so the daemon goroutine launches but
// RunMintExpiry is a no-op and this smoke is dormant — exactly the additive, backwards-compatible
// posture the unit pins. D50: NO live VM/host-agent/podman — synthetic fakes + in-memory store.

import (
	"context"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/test/bufconn"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/askhold"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/policylog"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/reconciler"
	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// TestDaemonWire_LiveSmoke_BothLegs is the DS_ORCH_LIVE-gated live-smoke (skip-clean unarmed)
// asserting BOTH daemon-wire legs end to end over the production wiring (NewControlPlane) and the
// real Serve launch path.
//
// LEG (b): Serve drives cp.RunMintExpiry on the fast serveMintExpiryInterval seam; with the
// DS_ORCH_LIVE MintReconverger installed, the Serve-launched backstop fires a ReconcileMintExpiry
// pass over a stale-horizon record and raises AlarmCredentialTTLReconverge — proving the arm is
// launched by the live daemon (not merely defined). Serve then graceful-stops cleanly on cancel,
// joining the arm (no goroutine leak).
//
// LEG (2)/(3): a synthetic GENUINE rung-2 ask routed through policylog.Service.RouteAsk with
// park=cp.AskParkRouter lands in cp.ParkMachine — the durable D46 park enrollment the live
// inbound-ask feed (startAskFeed) drives.
func TestDaemonWire_LiveSmoke_BothLegs(t *testing.T) {
	if !daemonWireLive() {
		t.Skip("daemon-wire live-smoke is DS_ORCH_LIVE-gated (legs b + 2/3); CI gate-off skips clean unarmed")
	}

	alarm := &recordingTTLAlarm{}
	deps, st := enrollDeps(t, alarm, &fakeResumer{})
	cp, err := NewControlPlane(deps)
	if err != nil {
		t.Fatalf("NewControlPlane: %v", err)
	}

	// Under DS_ORCH_LIVE the *parkMachine MUST be enrolled as the live ask-park router (leg 3); the
	// ParkMachine itself is always built. Both are preconditions for the park leg below.
	if cp.AskParkRouter == nil {
		t.Fatal("leg (3): cp.AskParkRouter must be non-nil under DS_ORCH_LIVE (the *parkMachine ask-park router)")
	}
	if cp.ParkMachine == nil {
		t.Fatal("cp.ParkMachine must be non-nil (always wired by NewControlPlane)")
	}
	if cp.AskParkRouter != AskParkRouter(cp.ParkMachine) {
		t.Fatal("leg (3): the enrolled AskParkRouter must be the SAME *parkMachine cp.ParkMachine exposes (one durable park machine)")
	}

	// ----- LEG (b): the Serve-launched credential-TTL backstop arm fires -----

	// A LIVE (READY) record carrying a persisted horizon already in the PAST — the durable footprint
	// of the two miss windows credttl.go documents, the backstop re-converges.
	if _, err := st.CreateSession(context.Background(), store.Session{
		Ref:        store.SessionRef{SessionUUID: "s-dw-stale", HostID: testHostID, HostSessionIndex: 1, TapName: "dstap-1"},
		State:      store.SessionReady,
		MintExpiry: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed stale-horizon session: %v", err)
	}

	// Drive Serve's mint-expiry arm FAST via the new seam so the backstop fires promptly. The other
	// two sweeps are left at their production cadence (0 → derived) — only the arm under test ticks.
	withServeMintExpiryInterval(t, time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	lis := bufconn.Listen(1 << 20)
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, cp, lis) }()

	// Wait until the Serve-launched backstop raises the reconverge alarm (proving the arm is driven
	// by the live daemon, not just defined) within a short deadline.
	deadline := time.After(5 * time.Second)
	for !alarm.has(reconciler.AlarmCredentialTTLReconverge) {
		select {
		case <-deadline:
			cancel()
			t.Fatal("leg (b): Serve-launched credential-TTL backstop never fired (RunMintExpiry not launched off loopCtx?)")
		case err := <-served:
			t.Fatalf("Serve returned early (%v) before the backstop fired", err)
		case <-time.After(2 * time.Millisecond):
		}
	}

	// ----- LEG (2)/(3): a synthetic rung-2 ask routes into cp.ParkMachine via cp.AskParkRouter -----

	const askSession = "s-dw-ask"
	seedRoutableSession(t, st, askSession)

	svc := policylog.NewService(st, smokeComposer{})
	if _, err := svc.RouteAsk(
		context.Background(),
		st, // *store.Memory satisfies the ask-routing WRITE seam (approver append + deny-memo read)
		st, // and the approver resolver seam (launching-user + org-admin lookup)
		nil,
		cp.AskParkRouter, // THE live park router — the *parkMachine cp.ParkMachine exposes
		dwRung2Ask(askSession),
		policylog.RouteAskParams{
			Decision: policylog.AskDecisionAllowOnce,
			Attended: policylog.AttendednessAttended,
			Rung2:    true,
			Window:   smokeWindow(),
			Body:     policylog.GrantBody{Rule: "allow github.com", Payload: []byte(`{}`)},
		},
	); err != nil {
		t.Fatalf("leg (2)/(3): RouteAsk(rung-2, park=cp.AskParkRouter): %v", err)
	}

	// The genuine rung-2 ask MUST be parked in cp.ParkMachine (the durable D46 enrollment the live
	// inbound-ask feed drives) — keyed by the asking session.
	if _, ok := cp.ParkMachine.Lookup(askSession); !ok {
		t.Fatalf("leg (2)/(3): rung-2 ask did not land in cp.ParkMachine for session %q (the park router was not driven)", askSession)
	}

	// ----- both legs proven: Serve graceful-stops cleanly, joining the mint-expiry arm (no leak) -----
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve returned %v on clean shutdown, want nil (the mint-expiry arm must join, not leak)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return within 5s of cancel (the RunMintExpiry arm goroutine join hung — goroutine leak)")
	}
}

// withServeMintExpiryInterval drives Serve's credential-TTL backstop cadence FAST for the duration
// of a test (the package var defaults to 0 → the reconcile loop's full-resync cadence) and restores
// it on cleanup — the leg-(b) twin of withServeSweepIntervals for the new serveMintExpiryInterval
// seam.
func withServeMintExpiryInterval(t *testing.T, d time.Duration) {
	t.Helper()
	saved := serveMintExpiryInterval
	serveMintExpiryInterval = d
	t.Cleanup(func() { serveMintExpiryInterval = saved })
}

// seedRoutableSession seeds a session + its launching principal + the link so RouteAsk's
// ResolveAskRouting resolves the launching-user approver (the default for an allow-once / rung-2
// ask) — the minimum durable footprint a genuine inbound ask routes against.
func seedRoutableSession(t *testing.T, st *store.Memory, sessionUUID string) {
	t.Helper()
	ctx := context.Background()
	pr, err := st.CreatePrincipal(ctx, store.Principal{
		ID:         "p-dw-launcher",
		IdPSubject: "okta|dw-launcher",
		Org:        testOrg,
		Roles:      []store.PrincipalRole{store.RoleLauncher},
	})
	if err != nil {
		t.Fatalf("seed launching principal: %v", err)
	}
	if _, err := st.CreateSession(ctx, store.Session{
		Ref:   store.SessionRef{SessionUUID: sessionUUID, HostID: testHostID, HostSessionIndex: 2, TapName: "dstap-2"},
		State: store.SessionReady,
	}); err != nil {
		t.Fatalf("seed routable session: %v", err)
	}
	if err := st.SetSessionLaunchingPrincipal(ctx, sessionUUID, pr.ID); err != nil {
		t.Fatalf("link launching principal: %v", err)
	}
}

// dwRung2Ask builds a synthetic GENUINE rung-2 inbound ask (a blocklist hit / explicit suspend
// rule, D77) for the given session — the class that PARKS per D46 rather than taking the TLS-1
// socket-hold.
func dwRung2Ask(session string) *boundaryv1.AskUserRequest {
	return &boundaryv1.AskUserRequest{
		Session:       &boundaryv1.SessionRef{SessionUuid: session},
		ResourceKind:  "domain",
		ResourceName:  "github.com",
		MatchedRuleId: "rule-dw-rung2",
	}
}

// smokeWindow is the injected POL-1 TLS-1 socket-hold budget RouteAsk opens for an ordinary ask
// (a rung-2 ask parks, never socket-holds — but RouteAskParams carries the Window regardless).
func smokeWindow() askhold.Window {
	return askhold.Window{Notify: 5 * time.Second, Decision: 40 * time.Second, Commit: 5 * time.Second}
}

// smokeComposer is the fail-closed SnapshotComposer the smoke's policylog.Service is constructed
// with: the ask-routing dispatch (RouteAsk → cp.AskParkRouter) NEVER invokes the composer (it is
// the SEPARATE WatchPolicies compose leg), so an empty snapshot keeps the Service complete without
// pulling the ds-contracts decoders into the test.
type smokeComposer struct{}

func (smokeComposer) ComposeAt(_ context.Context, seq int64, _ []store.PolicyLogRow, _ time.Time) (policylog.Snapshot, error) {
	return policylog.Snapshot{Seq: seq}, nil
}

// daemonWireLive reports whether the DS_ORCH_LIVE arm is set (the same gate the wave-1 enrollment
// pins read). Factored to a helper so the skip line reads cleanly.
func daemonWireLive() bool { return os.Getenv("DS_ORCH_LIVE") == "1" }
