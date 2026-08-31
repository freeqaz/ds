// SPDX-License-Identifier: Apache-2.0

// Host-redeploy production entrypoint (doc 16 §6.3 default d "re-key on host
// redeploy"; doc 15 — the orchestrator-owned host-lifecycle / redeploy path).
//
// THE GAP THIS CLOSES. hosthandoff.go landed the retry-to-convergence wrapper
// runHostHandoffToConvergence — the caller half of the controller's fail-closed
// retry contract: runHostHandoff fails CLOSED on a partial step and DOCUMENTS
// that the caller must retry the idempotent handoff, but the controller alone
// drives no retry. runHostHandoffToConvergence is that driver. Until now it had
// NO production call site — it was invoked ONLY from hosthandoff_test.go. This
// file is the missing PRODUCTION caller: the doc 16 §6.3 / doc 15 host-redeploy
// path invokes runHostHandoffToConvergence with a real handoffRetryPolicy
// (maxAttempts + backoff) and the DEFAULT time-based ctxSleep so a boundary host
// redeploy actually drives the idempotent digest handoff to convergence in
// production, not just in a test.
//
// WHAT THE PRODUCTION CALLER DIFFERS ON vs the test caller:
//
//   - it carries a REAL retry policy (a bounded attempt budget + a real wall-clock
//     backoff), not the test's maxAttempts/backoff:0;
//   - it lets runHostHandoffToConvergence fall back to its default ctxSleep (a
//     context-aware time.NewTimer wait), NOT a no-op noSleep — so a real redeploy
//     actually backs off between attempts while staying cancellable;
//   - it passes onAttempt=nil — production has no fault-injection hook; the
//     onAttempt seam exists only so a transient-failure-then-recovery test can
//     flip the synthetic knobs between attempts.
//
// SCOPE. This stays an ORCHESTRATOR-OWNED choreography (doc 15): it drives the
// FROZEN dreamserpent.identity.v1.DigestFeedService seam directly and observes
// the no-gap property from the wire; it never imports identity/digest (the only
// legal cross-tree import is proto/gen/go, D80) and never holds key material —
// it routes opaque digest entries and gates on acks (doc 16 §6.3). SYNTHETIC
// ONLY (D50) on the test side: standing up a real KVM host, dialing a live
// host-agent ack-er, observing a live redeploy is env-gated and a deferred
// manual step — there is no live host, boundary, or claude here. The production
// caller takes already-dialed DigestFeedService clients (the redeploy
// controller owns the dial against the real endpoints); this file only assembles
// the policy + default sleep and drives the convergence loop.

package sessions

import (
	"context"
	"errors"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// Production retry-to-convergence defaults for a boundary host redeploy. A
// redeploy is a rare, operator/controller-initiated event whose fail-closed legs
// are transient (a freshly stood-up host's ack not yet host-wide-visible, a
// mid-teardown transport blip) — so a SMALL bounded budget with a real backoff
// heals the common transient without hammering a genuinely-down host. The budget
// is bounded (the loop is never unbounded) and every attempt is idempotent, so a
// never-converging redeploy gives up fail-closed with the old host left fully
// shadowed (no gap), and the controller escalates/aborts.
const (
	// defaultRedeployMaxAttempts bounds the convergence loop. >=1; a handful of
	// attempts heals a transient new-host/old-host blip across a redeploy.
	defaultRedeployMaxAttempts = 5
	// defaultRedeployBackoff is the wall-clock wait BEFORE each retry (realized
	// through the default ctxSleep, so it stays cancellable). It paces retries so a
	// freshly stood-up host gets a beat to become host-wide-visible.
	defaultRedeployBackoff = 2 * time.Second
)

// errNoLiveSessions is returned by RunHostRedeploy when it is handed an empty
// live-session set. A redeploy with nothing to hand off is a caller bug (doc 15
// is the authority for which sessions are live, and a redeploy is only triggered
// when there are live sessions to carry) — surfacing it loudly is safer than
// silently "succeeding" with a no-op convergence that revokes nothing.
var errNoLiveSessions = errors.New("host-redeploy: no live sessions to hand off (doc 15 authority returned an empty live set)")

// HostRedeployRequest is the production wiring a doc 16 §6.3 / doc 15
// host-redeploy controller passes through to the digest-continuity choreography.
// It is the prod-shaped seam: the controller owns standing up the freshly
// redeployed NEW host and dialing both hosts' DigestFeedService endpoints; this
// type carries the already-dialed clients + the live-session set + the per-epoch
// key ids into the convergence driver. The controller never re-implements the
// no-gap ordering — it delegates to runHostHandoffToConvergence through
// RunHostRedeploy.
type HostRedeployRequest struct {
	// NewHost is the freshly redeployed host's digest-feed client — it starts
	// EMPTY and must be loaded+acked with the new-key digest set for every live
	// session before the old host is torn down.
	NewHost identityv1.DigestFeedServiceClient
	// OldHost is the retiring host's digest-feed client — already LOADED with the
	// old-key digests (the original mint-before-attach publish). It is revoked ONLY
	// after the new host fully shadows every session.
	OldHost identityv1.DigestFeedServiceClient
	// NewHostLoadedCount is the wire-observable per-instant probe the controller
	// uses to VERIFY a committed ack actually loaded the FULL digest set for a
	// session under the new key (not just a ≥1 "shadows" bit). In production this is
	// the redeploy controller's read against the new host's loaded set; in a test it
	// is a healthy hostConsumer's loadedCountUnder method.
	NewHostLoadedCount func(sessionUUID, keyID string) int
	// Sessions is the live-session set under handoff — the residual doc 15 fences
	// to the orchestrator (the authority for which sessions are live). Each carries
	// the credential tokens currently shadowed for it; the controller routes opaque
	// entries and never holds key material.
	Sessions []synthLiveSession
	// NewKeyID / OldKeyID are the post-redeploy and pre-redeploy per-host per-epoch
	// HMAC key ids (doc 16 §6.3) the new-key and old-key digest sets are stamped
	// under. They MUST differ — a redeploy advances the generation so a host never
	// reuses a key.
	NewKeyID string
	OldKeyID string

	// MaxAttempts / Backoff override the production retry policy when non-zero. A
	// zero MaxAttempts uses defaultRedeployMaxAttempts; a zero Backoff uses
	// defaultRedeployBackoff (a NEGATIVE Backoff disables the wait, for an operator
	// who wants a tight no-wait drain). Most callers leave both zero and take the
	// production defaults.
	MaxAttempts int
	Backoff     time.Duration
}

// resolvePolicy folds the request's optional overrides into a concrete
// production handoffRetryPolicy, applying the redeploy defaults for the zero
// values. A negative Backoff is preserved (it disables the wait); a zero Backoff
// takes the default.
func (r HostRedeployRequest) resolvePolicy() handoffRetryPolicy {
	maxAttempts := r.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = defaultRedeployMaxAttempts
	}
	backoff := r.Backoff
	if backoff == 0 {
		backoff = defaultRedeployBackoff
	}
	return handoffRetryPolicy{maxAttempts: maxAttempts, backoff: backoff}
}

// RunHostRedeploy is the PRODUCTION entrypoint the doc 16 §6.3 re-key-on-host-
// redeploy / doc 15 host-lifecycle controller calls to drive a boundary host
// redeploy's digest handoff to convergence. It is the missing prod call site for
// runHostHandoffToConvergence.
//
// It wraps runHostHandoffToConvergence with:
//   - a production handoffRetryPolicy (a bounded maxAttempts + a real wall-clock
//     backoff — req's overrides or the redeploy defaults);
//   - the DEFAULT time-based ctxSleep (sleep=nil → runHostHandoffToConvergence
//     falls back to its context-aware ctxSleep, so retries actually back off while
//     staying cancellable — NOT a test no-op);
//   - onAttempt=nil (production has no fault-injection hook).
//
// The convergence GUARANTEE is the wrapped loop's: each attempt either converges
// (oldHostRevoked=true → return), fails CLOSED with an incompleteHandoffError
// (back off and retry the idempotent handoff — the old host stays fully shadowed,
// no gap), or fails with a non-fail-closed error (return; a surprise is not for a
// blind retry). ctx is honored before every attempt and during every backoff
// wait, so a cancelled redeploy ends promptly with ctx.Err() and the old host is
// never torn down.
//
// It returns the handoffRetryResult so the controller can observe convergence,
// the attempt count, and the last error (nil on convergence). On a non-converged
// result the caller escalates/aborts the redeploy — the old host is left fully or
// partially loaded and every live session stays shadowed by at least one host.
//
// Pre-flight: an empty live-session set returns errNoLiveSessions WITHOUT
// touching either host (a redeploy with nothing to hand off is a caller bug, doc
// 15), and a cancelled ctx is surfaced before any wire call.
func RunHostRedeploy(ctx context.Context, req HostRedeployRequest) (handoffRetryResult, error) {
	if err := ctx.Err(); err != nil {
		return handoffRetryResult{err: err}, err
	}
	if len(req.Sessions) == 0 {
		return handoffRetryResult{err: errNoLiveSessions}, errNoLiveSessions
	}

	res := runHostHandoffToConvergence(
		ctx,
		req.NewHost, req.OldHost, req.NewHostLoadedCount,
		req.Sessions, req.NewKeyID, req.OldKeyID,
		req.resolvePolicy(),
		nil, // sleep=nil → the default context-aware ctxSleep (real, cancellable backoff)
		nil, // onAttempt=nil → no fault-injection hook in production
	)
	return res, res.err
}
