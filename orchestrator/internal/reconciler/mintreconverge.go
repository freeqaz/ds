// SPDX-License-Identifier: Apache-2.0

package reconciler

// mintreconverge.go — the PRODUCTION MintReconverger implementation the
// credential-TTL backstop (credttl.go) drives. credttl.go declared the NARROW
// MintReconverger seam + the WithMintReconverger builder + the ReconcileMintExpiry
// pass; this file supplies the concrete re-convergence ACTION the control-plane
// wiring installs behind that seam — kept in its OWN file so it does not collide
// with any in-flight credttl.go / reconciler.go edits (the additive-new-file
// discipline the rest of this package follows).
//
// WHAT THE BACKSTOP HANDS THIS SEAM (credttl.go). ReconcileMintExpiry lists the
// live (non-terminal) records, finds every one whose PERSISTED §5.6 MintExpiry
// horizon (migration 0010) is non-zero and ALREADY PAST, and calls
// ReconvergeMintExpiry(ctx, rec). That is the durable footprint of the two miss
// windows credttl.go documents: a horizon the in-process boot re-arm sweep MISSED
// (its ListSessions faulted at assembly) or a mid-resume re-mint that failed closed
// and left the session SUSPENDED with its expired horizon. No in-process timer is
// driving either; this seam re-establishes one.
//
// HOW IT RE-CONVERGES — RE-ARM THE IN-PROCESS SCHEDULER (doc 16 §5.4). The
// re-convergence is NOT a parallel re-mint codepath the reconciler owns (that would
// duplicate the mint mechanics the §4.1 step-5 / §4.2 resume already own and risk
// drifting from them). Instead it RE-ARMS the EXISTING in-process mintExpiryScheduler
// (controlplane/wiring.go) at the persisted horizon through its OnMintExpiry sink —
// the SAME mechanism the boot re-arm sweep (controlplane/mintexpiry_rearm.go) uses.
// A PAST horizon arms delay=0, so the scheduler's fire() runs promptly: it re-reads
// the persisted horizon, drops idempotently for a torn-down/terminal session, and
// otherwise re-mints through the production mint seam and persists the fresh horizon.
// So the backstop's job is purely to RE-ESTABLISH the timer the scheduler lost; the
// scheduler remains the single owner of the actual re-mint (the data-across-the-seam
// discipline credttl.go's MintReconverger doc spells out: "RE-ARMING the in-process
// scheduler at the persisted horizon ... so the re-mint fires promptly").
//
// IDEMPOTENT BY CONSTRUCTION. OnMintExpiry supersedes any prior timer for the same
// session UUID under a short mutex (at most one armed timer per live session), so a
// re-arm requested on consecutive backstop passes for the same still-stale record is
// harmless — it simply swaps the delay=0 timer for a fresh delay=0 timer, and the
// scheduler's fire() de-dups the re-mint on the persisted horizon. A re-arm after the
// scheduler is Stop()ped is dropped by the sink itself (the post-Stop inert posture).
//
// ADDITIVITY. It declares one NARROW sink seam (mintExpiryRearmSink — the OnMintExpiry
// shape the scheduler already exports), adds NO store method and NO Driver/Redriver
// widening, and is wired through the EXISTING WithMintReconverger option. With no
// reconverger wired ReconcileMintExpiry no-ops (credttl.go), so this file changes
// nothing about the pre-backstop in-process-timer path — it is purely the production
// action behind an already-additive seam.
//
// D50 / OFFLINE. The sink is an in-process function-shaped seam; tests drive it with a
// recording fake (no live mint, no VM/host-agent/podman). The real re-mint stays the
// scheduler's, exercised by the scheduler's own tests.

import (
	"context"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// mintExpiryRearmSink is the NARROW re-arm seam the production MintReconverger drives:
// exactly the OnMintExpiry shape the in-process mintExpiryScheduler
// (controlplane/wiring.go) already exports as sessions.MintExpirySink. Declaring it
// HERE (not importing the controlplane scheduler type, which would invert the
// package layering) keeps the reconciler depending only on the minimal sink surface —
// the same one-method-slice discipline the rest of the package follows
// (store.PolicyHeadSource over ListPolicy, liveGrantReader over LiveGrants). The
// concrete scheduler, a test fake, or any other re-arm target satisfies it.
type mintExpiryRearmSink interface {
	// OnMintExpiry (re-)arms the per-session teardown/re-mint timer at expiry. A PAST
	// expiry arms delay=0, so the scheduler's re-mint fires promptly (doc 16 §5.4).
	OnMintExpiry(sessionUUID string, expiry time.Time)
}

// schedulerRearmReconverger is the PRODUCTION MintReconverger (credttl.go): it
// re-converges a stale persisted horizon by RE-ARMING the in-process mint-expiry
// scheduler at that horizon. It owns no mint logic of its own — it re-establishes the
// timer the scheduler lost (the boot-sweep mechanism) and lets the scheduler's fire()
// re-read the persisted horizon and re-mint (doc 16 §5.4). It is the credential
// analogue of the SpineRunnerFunc/SpineContinuationFunc adapters: a thin seam binding
// that hands the durable record back to whatever owns credential re-convergence.
type schedulerRearmReconverger struct {
	sink mintExpiryRearmSink
}

// NewSchedulerRearmReconverger builds the production credential-TTL re-convergence seam
// over the in-process mint-expiry scheduler's OnMintExpiry sink. The control-plane
// capstone (wiring.go) constructs it behind DS_ORCH_LIVE and installs it via
// WithMintReconverger so the reconciler becomes the COARSE credential-TTL backstop
// behind the in-process scheduler (a horizon the boot re-arm missed, or a failed
// mid-resume re-mint, re-converges on the periodic cadence). A nil sink is a
// construction-time misconfiguration — it would silently swallow every re-arm — so the
// constructor refuses it fail-closed, exactly as the rest of the wiring refuses a nil
// required seam.
func NewSchedulerRearmReconverger(sink mintExpiryRearmSink) (*schedulerRearmReconverger, error) {
	if sink == nil {
		return nil, errNilRearmSink
	}
	return &schedulerRearmReconverger{sink: sink}, nil
}

// ReconvergeMintExpiry re-arms the in-process scheduler at the record's PERSISTED
// horizon so the re-mint fires promptly (a PAST horizon arms delay=0; doc 16 §5.4). It
// is the action behind credttl.go's narrow seam: the backstop already proved the record
// is live and its horizon is past, so this need only re-establish the timer — the
// scheduler's fire() does the persisted-horizon re-read + the actual re-mint + the
// idempotent drop for a torn-down session.
//
// It NEVER mutates state and NEVER tears down (credttl.go's invariant — a credential
// fault must not cost the session its VM): it arms a timer and returns. A zero/empty
// horizon never reaches here (ReconcileMintExpiry skips the no-TTL posture), but the
// sink's own OnMintExpiry guards the empty-UUID / zero-expiry case anyway, so a
// defensive call is a safe no-op. Returns nil — the re-arm is non-blocking and cannot
// fail synchronously (OnMintExpiry swaps a timer under a short mutex and returns); any
// later re-mint fault surfaces on the scheduler's own goroutine where the reconciler is
// itself the backstop, so a transient mint failure simply retries on the next pass (the
// idempotency MintReconverger's doc requires — OnMintExpiry supersedes the prior timer).
func (r *schedulerRearmReconverger) ReconvergeMintExpiry(_ context.Context, s store.Session) error {
	r.sink.OnMintExpiry(s.Ref.SessionUUID, s.MintExpiry)
	return nil
}

// Compile-time proof the production re-arm seam satisfies the narrow MintReconverger the
// backstop drives (credttl.go), so wiring.go can install it via WithMintReconverger.
var _ MintReconverger = (*schedulerRearmReconverger)(nil)

// errNilRearmSink is the fail-closed construction error for a nil re-arm sink. It is a
// package sentinel so the wiring (and a test) can assert the refusal without matching a
// free-form string.
var errNilRearmSink = constErr("reconciler: NewSchedulerRearmReconverger: nil mint-expiry re-arm sink (the credential-TTL backstop cannot re-arm a re-mint without it)")

// constErr is the package-local sentinel error type (stdlib-only, no third-party errors
// package) for this file's construction guard, mirroring credttl.go's free-diagnostic
// discipline.
type constErr string

func (e constErr) Error() string { return string(e) }
