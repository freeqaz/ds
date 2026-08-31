// SPDX-License-Identifier: Apache-2.0

// Host-redeploy PRODUCTION-entrypoint test (doc 16 §6.3 default d; doc 15 — the
// orchestrator-owned host-lifecycle / redeploy path).
//
// THE GAP THIS CLOSES. hosthandoff_test.go drives runHostHandoffToConvergence
// DIRECTLY (the wrapper under test). This file drives the PRODUCTION caller,
// RunHostRedeploy, the missing prod call site — proving the prod entrypoint
// wraps runHostHandoffToConvergence with a real handoffRetryPolicy + the DEFAULT
// time-based ctxSleep (sleep=nil) + nil onAttempt and still drives a boundary
// host redeploy's digest handoff to convergence WHILE preserving the no-gap
// invariant. It reuses the synthetic fixtures + in-process digest-feed fakes
// that hosthandoff_test.go defines in this same package (hostConsumer,
// handoffJournal, dialHostFeed, preloadOldHost, synthLiveSessions,
// assertConvergenceInvariants, errSyntheticTransport, sessionCredsByUUID) — no
// new fakes, no live host.
//
// SYNTHETIC ONLY (D50): every credential id is a `ds-synth-*` token; there is no
// live host, no live boundary, no live claude. Any live host-redeploy leg is
// env-gated and skipped (a deferred manual step).

package sessions

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// flakyPublishClient is a thin, INTERNALLY-SYNCHRONIZED prod-shaped
// DigestFeedServiceClient wrapper (D50) that fails the first failPublishes
// DigestPublish calls with a transport error, then delegates every call to the
// wrapped real in-process client. It models a freshly-stood-up new host that is
// briefly unreachable and then becomes reachable on its OWN — the transient
// recovery a production redeploy heals WITHOUT the test-only onAttempt hook
// (production passes onAttempt=nil). Its own mutex guards the fault counter, so
// the bounded retry loop driving it never races (unlike concurrently mutating a
// shared hostConsumer's fault knob from a background goroutine).
type flakyPublishClient struct {
	identityv1.DigestFeedServiceClient // delegate (Revoke + the healthy publish)

	mu            sync.Mutex
	failPublishes int // remaining publishes to fail before healing
}

func (f *flakyPublishClient) DigestPublish(ctx context.Context, req *identityv1.DigestPublishRequest, opts ...grpc.CallOption) (*identityv1.DigestPublishResponse, error) {
	f.mu.Lock()
	if f.failPublishes > 0 {
		f.failPublishes--
		f.mu.Unlock()
		return nil, errSyntheticTransport
	}
	f.mu.Unlock()
	return f.DigestFeedServiceClient.DigestPublish(ctx, req, opts...)
}

// TestRunHostRedeploy_HappyPathConvergesNoGap is the core prod-caller acceptance
// proof. With both hosts healthy, the production entrypoint drives the redeploy
// to convergence on the FIRST attempt — the new host is loaded+acked for every
// live session and ONLY THEN is the old host revoked, with no instant at which a
// session is shadowed by neither host. It runs with Backoff:-1 (no wall-clock
// wait) so the happy path is deterministic without burning real time, while
// still exercising the default ctxSleep path (the loop never sleeps on a
// first-attempt convergence anyway).
func TestRunHostRedeploy_HappyPathConvergesNoGap(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	sessions := synthLiveSessions()
	preloadOldHost(t, oldClient, sessions)

	// Pre-redeploy: the OLD host shadows every live session; the NEW host is empty.
	for _, s := range sessions {
		if !oldH.shadows(s.uuid) {
			t.Fatalf("old host does not shadow %q before redeploy", s.uuid)
		}
		if newH.shadows(s.uuid) {
			t.Fatalf("new host already shadows %q before redeploy (should start empty)", s.uuid)
		}
	}

	res, err := RunHostRedeploy(context.Background(), HostRedeployRequest{
		NewHost:            newClient,
		OldHost:            oldClient,
		NewHostLoadedCount: newH.loadedCountUnder,
		Sessions:           sessions,
		NewKeyID:           synthNewKeyID,
		OldKeyID:           synthOldKeyID,
		Backoff:            -1, // no wall-clock wait; happy path converges on attempt 1
	})

	if err != nil {
		t.Fatalf("RunHostRedeploy happy path returned error: %v", err)
	}
	if !res.converged || !res.out.oldHostRevoked || !res.out.newHostHandedOff {
		t.Fatalf("happy-path redeploy did not converge cleanly: %+v", res)
	}
	if res.attempts != 1 {
		t.Errorf("healthy redeploy should converge in exactly 1 attempt, got %d", res.attempts)
	}

	// The no-gap invariant holds across the converging run (every committed
	// new-host publish precedes every old-host revoke for the same session).
	assertConvergenceInvariants(t, j, newH, oldH, sessions, synthNewKeyID)
}

// TestRunHostRedeploy_TransientNewHostFaultStillConverges proves the prod
// entrypoint's bounded, idempotent retry actually heals a transient blip on its
// OWN — without the test's onAttempt seam (production passes onAttempt=nil). A
// transport fault on the first publish is cleared by a background goroutine after
// a short real delay; the prod caller's default ctxSleep backoff paces the retry
// and the second (or later) attempt converges. This exercises the REAL backoff
// path (Backoff>0, default ctxSleep) end to end, proving the prod wiring — not a
// test no-op — drives convergence.
func TestRunHostRedeploy_TransientNewHostFaultStillConverges(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	oldClient := dialHostFeed(t, oldH)
	// The new host's FIRST publish is unreachable, then it heals on its own — the
	// flakyPublishClient wrapper models a host that briefly cannot be reached and
	// then becomes reachable, with no test-only onAttempt hook (production passes
	// onAttempt=nil). One failed publish is enough: attempt 1's step-1 publish for
	// the first session errors and fails closed BEFORE any session loads, so the
	// old host is never touched; attempt 2 finds the wrapper healed and converges.
	newClient := &flakyPublishClient{
		DigestFeedServiceClient: dialHostFeed(t, newH),
		failPublishes:           1,
	}

	sessions := synthLiveSessions()
	preloadOldHost(t, oldClient, sessions)

	res, err := RunHostRedeploy(context.Background(), HostRedeployRequest{
		NewHost:            newClient,
		OldHost:            oldClient,
		NewHostLoadedCount: newH.loadedCountUnder,
		Sessions:           sessions,
		NewKeyID:           synthNewKeyID,
		OldKeyID:           synthOldKeyID,
		MaxAttempts:        8,
		Backoff:            10 * time.Millisecond, // real, cancellable backoff via default ctxSleep
	})

	if err != nil {
		t.Fatalf("RunHostRedeploy should heal the transient fault, got error: %v", err)
	}
	if !res.converged || !res.out.oldHostRevoked {
		t.Fatalf("transient-fault redeploy did not converge: %+v", res)
	}
	if res.attempts < 2 {
		t.Errorf("a first-attempt fault must force at least one retry, got attempts=%d", res.attempts)
	}
	assertConvergenceInvariants(t, j, newH, oldH, sessions, synthNewKeyID)
}

// TestRunHostRedeploy_EmptyLiveSetIsRejected proves the pre-flight guard: a
// redeploy handed an empty live-session set returns errNoLiveSessions WITHOUT
// touching either host (no publish, no revoke). A redeploy with nothing to hand
// off is a caller bug (doc 15 is the authority for which sessions are live), so
// it fails loudly rather than "succeeding" with a no-op convergence.
func TestRunHostRedeploy_EmptyLiveSetIsRejected(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	res, err := RunHostRedeploy(context.Background(), HostRedeployRequest{
		NewHost:            newClient,
		OldHost:            oldClient,
		NewHostLoadedCount: newH.loadedCountUnder,
		Sessions:           nil, // empty live set
		NewKeyID:           synthNewKeyID,
		OldKeyID:           synthOldKeyID,
	})

	if !errors.Is(err, errNoLiveSessions) {
		t.Fatalf("empty live set must return errNoLiveSessions, got %v", err)
	}
	if res.converged || res.out.oldHostRevoked || res.attempts != 0 {
		t.Fatalf("empty-set pre-flight must not run any attempt: %+v", res)
	}
	// No wire call at all — the journal stays empty.
	if len(j.events) != 0 {
		t.Errorf("empty-set redeploy touched a host (%d journal events) — pre-flight must short-circuit before any wire call", len(j.events))
	}
}

// TestRunHostRedeploy_PersistentFaultFailsClosedNoGap proves the prod caller's
// bounded budget: a PERSISTENT new-host fault (never cleared) exhausts the
// attempt budget and the redeploy gives up FAIL-CLOSED — converged=false,
// oldHostRevoked=false, the last error an incompleteHandoffError, and the old
// host left fully shadowed and NEVER revoked (no gap even on a redeploy that
// never succeeds). Backoff:-1 keeps the exhaustion fast and wall-clock-free.
func TestRunHostRedeploy_PersistentFaultFailsClosedNoGap(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	newH.publishErr = errSyntheticTransport // never cleared — a persistent outage
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	sessions := synthLiveSessions()
	preloadOldHost(t, oldClient, sessions)

	const budget = 3
	res, err := RunHostRedeploy(context.Background(), HostRedeployRequest{
		NewHost:            newClient,
		OldHost:            oldClient,
		NewHostLoadedCount: newH.loadedCountUnder,
		Sessions:           sessions,
		NewKeyID:           synthNewKeyID,
		OldKeyID:           synthOldKeyID,
		MaxAttempts:        budget,
		Backoff:            -1, // no wait — exhaust fast
	})

	if res.converged {
		t.Fatalf("a persistent fault must NOT converge: %+v", res)
	}
	if res.attempts != budget {
		t.Errorf("want exactly %d attempts before giving up, got %d", budget, res.attempts)
	}
	if err == nil {
		t.Fatal("exhausted redeploy must surface the last error")
	}
	var ihe incompleteHandoffError
	if !errors.As(err, &ihe) {
		t.Errorf("want a fail-closed incompleteHandoffError after exhaustion, got %T: %v", err, err)
	}
	if res.out.oldHostRevoked {
		t.Fatalf("oldHostRevoked must stay false on exhaustion: %+v", res.out)
	}
	// NO GAP even when the redeploy never succeeds: the old host stays fully
	// shadowed and is NEVER revoked.
	for _, s := range sessions {
		if !oldH.shadows(s.uuid) {
			t.Errorf("old host stopped shadowing %q on a never-converging redeploy — gap risk", s.uuid)
		}
		if j.has("old", "revoke", s.uuid) {
			t.Errorf("a revoke was issued to the old host for %q despite the redeploy never converging", s.uuid)
		}
	}
}

// TestRunHostRedeploy_ContextCancelledEndsPromptly proves the prod entrypoint is
// context-cancellable: a context cancelled before the run ends the redeploy
// promptly with ctx.Err(), runs zero attempts, never converges, and never revokes
// the old host (which stays fully shadowed — no gap).
func TestRunHostRedeploy_ContextCancelledEndsPromptly(t *testing.T) {
	j := &handoffJournal{}
	oldH := newHostConsumer("old", j)
	newH := newHostConsumer("new", j)
	oldClient := dialHostFeed(t, oldH)
	newClient := dialHostFeed(t, newH)

	sessions := synthLiveSessions()
	preloadOldHost(t, oldClient, sessions)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the run even starts

	res, err := RunHostRedeploy(ctx, HostRedeployRequest{
		NewHost:            newClient,
		OldHost:            oldClient,
		NewHostLoadedCount: newH.loadedCountUnder,
		Sessions:           sessions,
		NewKeyID:           synthNewKeyID,
		OldKeyID:           synthOldKeyID,
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
	if res.converged || res.out.oldHostRevoked || res.attempts != 0 {
		t.Fatalf("a context cancelled before the run must do nothing: %+v", res)
	}
	for _, s := range sessions {
		if !oldH.shadows(s.uuid) {
			t.Errorf("old host stopped shadowing %q on a cancelled redeploy — gap risk", s.uuid)
		}
		if j.has("old", "revoke", s.uuid) {
			t.Errorf("a revoke was issued for %q on a cancelled redeploy", s.uuid)
		}
	}
}

// TestRunHostRedeploy_DefaultPolicyAppliesRedeployDefaults proves the zero-value
// overrides fold to the production redeploy defaults (defaultRedeployMaxAttempts
// + defaultRedeployBackoff) without the caller spelling them out. It checks
// resolvePolicy directly (the policy is otherwise internal to the wrapped loop),
// and confirms a request leaving MaxAttempts/Backoff zero takes the defaults
// while a negative Backoff is preserved (the operator-tight no-wait drain).
func TestRunHostRedeploy_DefaultPolicyAppliesRedeployDefaults(t *testing.T) {
	def := HostRedeployRequest{}.resolvePolicy()
	if def.maxAttempts != defaultRedeployMaxAttempts {
		t.Errorf("zero MaxAttempts should use default %d, got %d", defaultRedeployMaxAttempts, def.maxAttempts)
	}
	if def.backoff != defaultRedeployBackoff {
		t.Errorf("zero Backoff should use default %v, got %v", defaultRedeployBackoff, def.backoff)
	}

	// Explicit overrides win.
	over := HostRedeployRequest{MaxAttempts: 9, Backoff: 750 * time.Millisecond}.resolvePolicy()
	if over.maxAttempts != 9 || over.backoff != 750*time.Millisecond {
		t.Errorf("explicit overrides not honored: %+v", over)
	}

	// A negative Backoff is preserved (it disables the wait), not coerced to the
	// default — so an operator can drive a tight no-wait drain.
	noWait := HostRedeployRequest{Backoff: -1}.resolvePolicy()
	if noWait.backoff != -1 {
		t.Errorf("negative Backoff should be preserved (no-wait drain), got %v", noWait.backoff)
	}
	if noWait.maxAttempts != defaultRedeployMaxAttempts {
		t.Errorf("negative-Backoff request should still default MaxAttempts, got %d", noWait.maxAttempts)
	}
}

// TestRunHostRedeploy_LiveRedeployLeg_SkippedWithoutEnvGate documents the
// deferred manual step (D50): a LIVE host-redeploy leg — standing up a real KVM
// host, dialing the live host-agent ack-er over the real endpoint, observing a
// live redeploy converge — is env-gated behind DS_HOST_REDEPLOY_LIVE and SKIPPED
// here. There is no live host/boundary/KVM in this wave; the synthetic path above
// is the proof.
func TestRunHostRedeploy_LiveRedeployLeg_SkippedWithoutEnvGate(t *testing.T) {
	if os.Getenv("DS_HOST_REDEPLOY_LIVE") == "" {
		t.Skip("DS_HOST_REDEPLOY_LIVE unset: live host-redeploy leg is a deferred manual step (D50) — no live host/boundary/KVM in this wave")
	}
	t.Fatal("live host-redeploy leg not implemented in this wave — synthetic-only (D50); this gate exists to document the deferred manual step")
}
