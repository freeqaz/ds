package reconciler

// credttl.go — the CREDENTIAL-TTL BACKSTOP reconcile rule (doc 16 §5.4 / doc 15 §3).
//
// THE GAP IT CLOSES. The §3 conflict rules (conflict.go) converge VM PRESENCE —
// observed-vs-desired domain state — NOT minted-credential TTL. Credential horizon
// re-convergence today rides the IN-PROCESS mintExpiryScheduler timers (wiring.go,
// time.AfterFunc) re-armed across a restart by the BEST-EFFORT boot sweep
// (controlplane/mintexpiry_rearm.go). That leaves TWO miss windows where a LIVE
// session sits past its persisted MintExpiry with no owner driving a re-mint:
//
//   (1) BOOT-SWEEP MISS. reArmMintExpiry is best-effort + SINGLE-SHOT: if its
//       ListSessions faults at assembly, the in-process timers stay UNARMED for that
//       cycle (its own doc comment defers to "the reconciler remains the backstop").
//       A live session whose horizon falls in that restart window is never re-minted.
//
//   (2) MID-RESUME RE-MINT FAILURE. ParkResumeDriver.Resume re-mints an expired
//       credential BEFORE the host Resume verb (doc 16 §5.4); on a re-mint fault it
//       FAILS CLOSED, leaving the session SUSPENDED with its expired persisted
//       horizon (parkresume.go: "the session stays SUSPENDED for the reconciler to
//       re-drive"). No timer and no owner re-attempts the re-mint.
//
// Both leave the SAME durable footprint: a LIVE (non-terminal) record whose PERSISTED
// MintExpiry horizon is non-zero and already in the PAST, with no in-process timer
// driving it. This file makes that durable footprint LEVEL-TRIGGERED-convergeable: a
// reconcile pass detects it and drives a re-mint / re-arm through a NEW NARROW seam —
// so a stale/unarmed horizon re-converges WITHOUT the in-process timer (exactly the
// "the reconciler remains the backstop" contract those two sites already cite).
//
// ADDITIVITY DISCIPLINE (the same as the rest of this package):
//   - It reuses the EXISTING narrow RecordStore (ListSessions only — no per-UUID get,
//     no new store method, no Repository widening).
//   - The re-mint/re-arm action is a NEW narrow seam (MintReconverger) the reconciler
//     OWNS — it does NOT widen Driver (a hypervisor verb is not a mint) or Redriver
//     (re-creating a missing VM is a different convergence than re-minting a live one).
//   - It is wired through an ADDITIVE option (WithMintReconverger) so reconciler.New's
//     frozen/shared signature (wiring.go constructs it) is untouched; absent the seam
//     the pass is a documented no-op (the timer/boot-sweep path is unchanged).
//   - It honors the store.ErrUnavailable DEGRADED-mode stall posture (doc 15 §3): a
//     store outage STALLS the pass and raises AlarmDegraded — it NEVER destroys,
//     quarantines, or churns identity on a store outage.
//   - It SKIPS zero/not-set horizons (the no-TTL posture, MintExpiry.IsZero()), still
//     -FUTURE horizons (no premature churn), and terminal/DESTROYING records (no
//     identity churn during teardown) — mirroring the boot sweep's and the
//     coordinator's guards so the backstop and the timer converge on the SAME set.

import (
	"context"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// MintReconverger is the NARROW credential-TTL re-convergence seam the backstop drives
// when it finds a LIVE record whose persisted MintExpiry horizon has already passed
// (the two miss windows above). It is the credential analogue of Redriver: the
// reconciler does NOT re-implement the §4.1 step-5 mint or the §4.2/§5.4 resume re-mint
// — it hands the stale record back to whatever owns credential re-convergence.
//
// A production wiring satisfies it either by RE-ARMING the in-process scheduler at the
// persisted horizon (the scheduler's OnMintExpiry with a past horizon arms delay=0, so
// the re-mint fires promptly — doc 16 §5.4, the boot-sweep mechanism) or by driving a
// re-mint directly; the seam is abstract over WHICH so the reconciler stays ignorant of
// the mint mechanics (the data-across-the-seam discipline). A nil MintReconverger means
// "credential-TTL backstop unavailable in this wiring" — ReconcileMintExpiry then no-ops
// (with a documented degraded note path), exactly the way a nil Redriver disables the
// rule-b re-drive arm.
//
// It returns nil on a successfully-requested re-convergence (the seam swapped a timer /
// requested a re-mint); an error makes the backstop raise AlarmCredentialTTLReconverge
// with the fault detail and leave the record UNCHANGED for the next pass to retry —
// never a state mutation, never a teardown (a credential that cannot be re-minted right
// now must NOT cost the session its VM; doc 15 §3 "never auto-destroy" generalizes to
// "never auto-destroy on a credential fault").
type MintReconverger interface {
	// ReconvergeMintExpiry requests re-mint / re-arm of the credential horizon for a
	// record whose persisted MintExpiry is already past. Idempotent: a re-arm or
	// re-mint requested on the next pass for the same still-stale record is harmless
	// (the scheduler/minter dedupes on session_uuid + horizon), so a transient failure
	// simply retries next pass.
	ReconvergeMintExpiry(ctx context.Context, s store.Session) error
}

// AlarmCredentialTTLReconverge is the operator-visible event the credential-TTL
// backstop raises when it re-drives a stale persisted horizon (or fails to). It is the
// §3-audit-surface sibling of AlarmReconverge (state-regression re-converge) for the
// credential dimension — NOT a state-machine vocabulary term.
const AlarmCredentialTTLReconverge AlarmKind = "credential_ttl_reconverged"

// WithMintReconverger installs the credential-TTL re-convergence seam onto an
// already-constructed Reconciler and returns it (chaining-friendly). It is the ADDITIVE
// wiring point that keeps reconciler.New's frozen/shared signature untouched: the
// control-plane assembly (the next-wave wiring task, OUTSIDE this unit's files)
// constructs the Reconciler as today, then calls WithMintReconverger to arm the
// backstop with a seam that re-arms the scheduler / drives a re-mint. A nil mr clears
// the seam (the backstop becomes a no-op) — useful for a test that asserts the
// no-seam path. It mutates only the new field; the §3 VM-presence convergence and the
// lastBeat single-goroutine contract are untouched.
func (r *Reconciler) WithMintReconverger(mr MintReconverger) *Reconciler {
	r.mintReconverger = mr
	return r
}

// timeLayout is the deterministic horizon/clock format the backstop's audit detail
// stamps (RFC3339Nano so a sub-second horizon is unambiguous in the alarm string). It
// is a free diagnostic label, not a wire format.
const timeLayout = "2006-01-02T15:04:05.999999999Z07:00"

// ReconcileMintExpiry is the CREDENTIAL-TTL BACKSTOP PASS (doc 16 §5.4). It LISTS the
// live (non-terminal) session set and, for every record whose PERSISTED MintExpiry is
// non-zero and already PAST (vs the injected clock), drives re-mint / re-arm through the
// MintReconverger — so a horizon the boot sweep MISSED (window 1) or a re-mint failure
// left SUSPENDED (window 2) re-converges WITHOUT the in-process timer.
//
// It is a SEPARATE pass from Observe/Resync (those converge VM presence per host off a
// heartbeat's observed set; this converges credential TTL off the DURABLE record alone,
// needing no observed set — the horizon is a persisted column, not a host observation).
// The driving loop (the next-wave wiring task) runs it on the same periodic cadence as
// Resync; it is safe to call from the single reconcile goroutine (it touches no mutable
// reconciler state).
//
// DEGRADED MODE (doc 15 §3). A store.ErrUnavailable from the list is the Postgres-DOWN
// degraded mode: the pass STALLS (returns the degraded error after raising
// AlarmDegraded) — running sessions continue on their cached grants to expiry (D39), the
// backstop neither re-mints (it cannot read the horizons) nor destroys anything. Other
// faults are absorbed: a per-record re-converge failure raises an alarm and the pass
// continues, so one un-re-mintable session never stalls the rest of the fleet.
//
// NO-SEAM POSTURE. With no MintReconverger wired the pass is a documented no-op: it does
// NOT list (there is nothing to drive), returns nil, and leaves the timer/boot-sweep
// path as the sole credential-TTL mechanism — fully backwards-compatible with the
// pre-backstop wiring.
func (r *Reconciler) ReconcileMintExpiry(ctx context.Context) error {
	if r.mintReconverger == nil {
		// Backstop not wired: the in-process timer / boot sweep is the only mechanism.
		// No list, no churn — a true no-op (the pre-backstop behavior, unchanged).
		return nil
	}

	live, err := r.store.ListSessions(ctx, store.SessionFilter{IncludeDestroyed: false})
	if err != nil {
		if degraded(err) {
			r.raise(ctx, AlarmDegraded, "", "",
				"credential-TTL backstop: store unavailable; horizons not re-converged this pass (sessions ride cached grants to expiry, D39)")
			return err
		}
		return fail("credential-TTL backstop list", err)
	}

	now := r.now()
	for _, rec := range live {
		// SKIP terminal records the filter did not omit (defense in depth — a DESTROYED
		// record must never be re-minted) and DESTROYING (mid-teardown: re-minting churns
		// identity the §4.2 teardown is about to revoke; the boot sweep tolerates a
		// re-armed DESTROYING only because fire() drops it — the backstop skips it
		// outright so it never even requests the churn).
		if rec.State.IsTerminal() || rec.State == store.SessionDestroying {
			continue
		}
		// SKIP the no-TTL posture (zero horizon = no credential TTL tracked) and any
		// still-FUTURE horizon (not yet expired — the in-process timer, if armed, owns
		// it; the backstop fires only once the horizon has actually slipped past now).
		if rec.MintExpiry.IsZero() || !rec.MintExpiry.Before(now) {
			continue
		}
		// EXPIRED horizon on a live record — the two miss windows' footprint. Drive
		// re-mint / re-arm through the narrow seam. Never mutate state, never teardown:
		// a credential fault must not cost the session its VM (the §3 "never auto-destroy"
		// generalized to the credential dimension).
		detail := "persisted MintExpiry " + rec.MintExpiry.Format(timeLayout) +
			" already past (now " + now.Format(timeLayout) +
			"); re-converging credential horizon without the in-process timer (doc 16 §5.4 backstop)"
		if err := r.mintReconverger.ReconvergeMintExpiry(ctx, rec); err != nil {
			detail += "; re-converge request FAILED (will retry next pass; never auto-destroyed): " + err.Error()
		}
		r.raise(ctx, AlarmCredentialTTLReconverge, rec.Ref.SessionUUID, rec.Ref.HostID, detail)
	}
	return nil
}
