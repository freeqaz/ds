package hostagent

// sweep_runner.go is the host agent's POST-COMMIT REVOCATION SWEEP COORDINATOR
// (POL-4 part 3; D72/D53/D36, doc 13 §5 revocation-sweep row, doc 15 §5.2). It
// is the concrete Sweeper (apply.go) the ApplyCoordinator invokes AFTER the
// two-phase commit flips the three consumers to vN+1: it drives each consumer
// through its own post-commit sweep, collects each consumer's per-consumer
// swept seq, plumbs it through the SweepNotifier registry (sweepnotify.go), and
// returns the host-ward swept seq the round is now fully applied at.
//
// WHERE IT SITS IN THE D72 BARRIER (do not reopen):
//
//   - apply.go's ApplyCoordinator.Apply runs PREPARE then COMMIT, flips the
//     applied POINTER on a full commit, then calls c.sweeper.Sweep(ctx, snap)
//     (apply.go line 319). SweepRunner satisfies that Sweeper seam. The frozen
//     D72 rule is that apply_seq advances ONLY after the sweep completes — so
//     this runner is the readiness signal that lets the heartbeat's
//     min-over-three (heartbeat.go AppliedSeq) finally rise to vN+1.
//   - Each consumer's post-commit sweep re-evaluates its derived state against
//     vN+1 — allow4/allow6, the DNS-2b admission map, live ask-grants — evicting
//     everything vN+1 denies, severing conntrack/tunnels RUNG-CONDITIONALLY (D53,
//     flush at block-or-higher) through the ONE shared flush_session primitive
//     (ds-contracts). That sweep mechanism lives INSIDE each consumer (Rust); this
//     runner only DRIVES the three host-local sweep calls and folds their results.
//     It forks no severing path of its own (the single flush_session invariant).
//   - When a consumer finishes its sweep it reports a boundary
//     ServiceHealth.applied_seq in its sweep-completion report (the seq it is
//     FULLY SWEPT at, D72). The runner routes that seq through
//     SweepNotifier.NotifySwept, so the per-consumer swept state the heartbeat
//     folds through the frozen D72 min-over-three is kept current from exactly the
//     sweep-completion path — never from a mere commit.
//
// THE SEAM (host-local UDS gRPC; transport is FREE, doc 13 §6). The real
// per-consumer sweep client is the host agent's WatchSnapshots integration to
// ds-tlsproxy / nft-writer / ds-dnsgate, driving the Rust
// Consumer::sweep_and_advance_applied_seq(token) call (consumer_seam.go's Go↔Rust
// correspondence). It is a SEAM (an interface, the package's pinned-later idiom
// like ConsumerBarrier / SnapshotPersister): a test fake satisfies it in-memory;
// the real UDS gRPC clients are owner-landed. The snapshot crosses as the frozen
// boundaryv1.PolicySnapshot, never an on-wire type.
//
// FAIL-CLOSED (D72), the invariants the body enforces:
//
//   - The sweep is ALL-OR-NONE at the host level. If ANY consumer's sweep fails,
//     SweepRunner returns seq 0 and a non-nil error: the ApplyCoordinator then
//     HOLDS apply_seq at the prior version (apply.go), and the failing consumer is
//     marked DOWN in the registry so its contribution clamps the min to 0. The
//     consumers stay on vN+1 (already at-least-as-strict — fail-closed); only the
//     SEQ ADVANCE is withheld until the sweep re-drives.
//   - The returned swept seq is the host-ward MIN over the three consumers
//     (SweepNotifier.AppliedSeq) AFTER all three reported — never a per-consumer
//     value, never a vacuous high value. A consumer that reports seq 0 (its error
//     sentinel) drags the min to 0, so the runner returns 0 even if the others
//     swept higher.
//   - A consumer reporting a NON-MONOTONE swept seq is a wiring bug:
//     NotifySwept rejects a non-advancing seq for a still-HEALTHY consumer, and
//     SweepRunner surfaces that rejection as a sweep failure (it does not silently
//     regress the host-ward min behind an already-published value).
//
// NEVER-LOG-THE-SECRET: this runner moves only consumer names, seqs, and health —
// no composed policy bytes ever cross it; the snapshot stays opaque
// boundaryv1.PolicySnapshot bytes handed straight to the consumer sweep calls.

import (
	"context"
	"fmt"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// ConsumerSweep is the host agent's seam onto ONE of the three host-side
// consumers' POST-COMMIT revocation sweep — the host-agent side of the Rust
// Consumer::sweep_and_advance_applied_seq(token) call (consumer_seam.go's Go↔Rust
// correspondence). It is the sweep analog of ConsumerBarrier (Prepare/Commit):
// where ConsumerBarrier drives the two-phase flip, ConsumerSweep drives the
// follow-on sweep that makes apply_seq finally advance (D72).
//
// It is a SEAM (an interface, the package's pinned-later idiom): a test fake
// satisfies it in-memory; the real host-local UDS gRPC client to the consumer is
// owner-landed. The snapshot crosses as the frozen boundaryv1.PolicySnapshot.
//
// CONTRACT SweepAndAdvance honors:
//
//   - SweepAndAdvance(ctx, snap) is called ONLY after this consumer COMMITTED snap
//     (it is on vN+1). It re-evaluates the consumer's derived state against vN+1,
//     evicts everything vN+1 denies, and severs conntrack/tunnels rung-
//     conditionally (D53) via the ONE shared flush_session primitive (ds-
//     contracts) — all INSIDE the consumer. It returns the seq the consumer is now
//     FULLY SWEPT at (normally snap.Seq) — its boundary ServiceHealth.applied_seq
//     in the sweep-completion report.
//   - A non-nil error means the sweep could not complete (a severing fault, a lost
//     host-local connection). The runner then fails the host-wide sweep and marks
//     this consumer DOWN; apply_seq is HELD until the sweep re-drives (D72 fail-
//     closed). The consumer stays on vN+1 (at-least-as-strict) — the error
//     withholds the SEQ advance, it does not roll back the commit.
type ConsumerSweep interface {
	// Name is the consumer's stable identity (one of BoundaryDNSGate /
	// BoundaryTLSProxy / BoundaryNFTWriter) — used to route the swept seq into the
	// SweepNotifier registry under the right consumer and for error messages. It
	// never feeds policy evaluation.
	Name() string

	// SweepAndAdvance runs this consumer's post-commit revocation sweep against
	// snap (vN+1) and returns the seq it is fully swept at, or a non-nil error if
	// the sweep could not complete.
	SweepAndAdvance(ctx context.Context, snap *boundaryv1.PolicySnapshot) (sweptSeq uint64, err error)
}

// SweepRunner is the concrete Sweeper (apply.go) that drives the three host-side
// consumers' post-commit revocation sweep and folds their per-consumer swept
// seqs into the host-ward min via the SweepNotifier registry. It is constructed
// once per host agent with the three consumer sweep clients and the shared
// SweepNotifier the heartbeat reads, then handed to NewApplyCoordinator as the
// sweeper so Apply runs it post-commit (D72: apply_seq advances only post-sweep).
//
// It owns NO version pointer of its own — the host-ward swept seq is the MIN over
// the three consumers held in the SweepNotifier (the single source the heartbeat
// also folds), so the runner's return value and the wire value can never diverge.
//
// Concurrency: Sweep is invoked by the single apply pump (one apply — and thus
// one sweep — at a time per host; the barrier is host-serial). The SweepNotifier
// is independently mutex-guarded, so a concurrent heartbeat read of the registry
// never observes a half-updated per-consumer state.
type SweepRunner struct {
	// sweepOrder holds the three consumers in the FIXED admitter-last order
	// (ds-tlsproxy + nft-writer BEFORE ds-dnsgate) — the same make-before-break
	// order the commit walks (consumer_seam.go CommitOrder). The sweep re-evaluates
	// derived state, so sweeping the enforcers before the admitter keeps every
	// transient window fail-closed for the same reason the commit does.
	sweepOrder []ConsumerSweep
	notifier   *SweepNotifier
}

// NewSweepRunner builds the runner from the three consumer sweep clients and the
// shared SweepNotifier the heartbeat reads. The clients may be passed UNORDERED:
// the constructor orders them into the FIXED admitter-last sweep order (the two
// enforcers before the admitter, consumer_seam.go CommitOrder) so a caller never
// hand-sequences it.
//
// It requires EXACTLY the three named consumers, each present once, and a non-nil
// notifier: a missing, duplicate, or unrecognized client — or a nil notifier — is
// a wiring bug rejected fail-closed at construction (the same set NewApplyCoordinator
// and OrderBarriers enforce for the barrier side), never silently accepted.
func NewSweepRunner(notifier *SweepNotifier, clients ...ConsumerSweep) (*SweepRunner, error) {
	if notifier == nil {
		return nil, fmt.Errorf("hostagent: NewSweepRunner: nil sweep notifier (the heartbeat min-over-three has nowhere to read swept seqs)")
	}
	byName := make(map[string]ConsumerSweep, len(clients))
	for i, c := range clients {
		if c == nil {
			return nil, fmt.Errorf("hostagent: NewSweepRunner: nil consumer sweep client at position %d", i)
		}
		name := c.Name()
		switch name {
		case BoundaryDNSGate, BoundaryTLSProxy, BoundaryNFTWriter:
		default:
			return nil, fmt.Errorf("hostagent: NewSweepRunner: unrecognized consumer %q (want one of ds-tlsproxy, nft-writer, ds-dnsgate)", name)
		}
		if _, dup := byName[name]; dup {
			return nil, fmt.Errorf("hostagent: NewSweepRunner: duplicate consumer %q", name)
		}
		byName[name] = c
	}
	// Order into the FIXED admitter-last sweep order so the enforcers sweep before
	// the admitter (make-before-break, the same order the commit walks). A missing
	// consumer is caught here.
	ordered := make([]ConsumerSweep, 0, len(commitOrder))
	for _, name := range commitOrder {
		c, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("hostagent: NewSweepRunner: missing consumer %q (need all three of ds-tlsproxy, nft-writer, ds-dnsgate)", name)
		}
		ordered = append(ordered, c)
	}
	return &SweepRunner{sweepOrder: ordered, notifier: notifier}, nil
}

// Sweep drives the post-commit revocation sweep across the three consumers in the
// FIXED admitter-last order, folds each consumer's reported swept seq into the
// SweepNotifier, and returns the host-ward swept seq (the registry's
// min-over-three) the round is now fully applied at. It satisfies the Sweeper
// seam (apply.go) the ApplyCoordinator invokes post-commit.
//
// Return contract (D72 fail-closed):
//
//   - A nil snapshot is a caller programming error (Apply never reaches the
//     sweep with a nil snap) — rejected without touching any consumer, swept seq 0.
//   - ANY consumer sweep error → the consumer is marked DOWN in the registry (its
//     contribution clamps the min to 0) and Sweep returns (0, err). The host-wide
//     sweep is all-or-none: the seq advance is WITHHELD (the ApplyCoordinator
//     holds apply_seq at the prior version). The consumers stay on vN+1 (fail-
//     closed); only the seq advance waits for the sweep to re-drive.
//   - A consumer reporting a NON-MONOTONE swept seq is rejected by NotifySwept;
//     Sweep surfaces that as a sweep failure (seq 0, err) rather than regressing
//     the host-ward min behind an already-published value.
//   - All three swept and reported → Sweep returns the SweepNotifier's
//     min-over-three (SweepNotifier.AppliedSeq) — the same value the heartbeat
//     folds, so the runner's return and the wire value cannot diverge. A consumer
//     that reported the seq-0 sentinel drags that min to 0 even if the others
//     swept higher (the host cannot claim a swept version a consumer never
//     reached).
func (r *SweepRunner) Sweep(ctx context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	if snap == nil {
		return 0, fmt.Errorf("hostagent: sweep runner: nil snapshot")
	}

	// Drive each consumer's post-commit sweep in the FIXED admitter-last order and
	// plumb the result through the SweepNotifier. The sweep is all-or-none at the
	// host level: the FIRST consumer error fails the whole round (fail-closed) —
	// the consumer is marked DOWN so its contribution clamps the host-ward min to 0
	// and the ApplyCoordinator holds apply_seq.
	for _, c := range r.sweepOrder {
		sweptSeq, serr := c.SweepAndAdvance(ctx, snap)
		if serr != nil {
			// The consumer is on vN+1 (commit already happened) but its sweep did not
			// complete. Mark it DOWN so its contribution clamps the min to 0 (a fresh
			// completed sweep via NotifySwept later clears it). The seq advance is
			// withheld this round (D72).
			if nerr := r.notifier.NotifyUnhealthy(c.Name(), hostagentv1.HealthState_HEALTH_STATE_DOWN, "post-commit sweep failed"); nerr != nil {
				return 0, fmt.Errorf(
					"hostagent: sweep runner: sweep of %q failed for seq %d AND recording its unhealthy state failed (host-ward seq held at 0): sweep err: %w; notify err: %v",
					c.Name(), snap.GetSeq(), serr, nerr,
				)
			}
			return 0, fmt.Errorf(
				"hostagent: sweep runner: post-commit sweep of %q failed for seq %d (consumer on vN+1, apply_seq held until sweep re-drives): %w",
				c.Name(), snap.GetSeq(), serr,
			)
		}
		// Record the consumer's COMPLETED sweep at its reported swept seq — its
		// boundary ServiceHealth.applied_seq (D72: applied_seq advances only after the
		// sweep completes). NotifySwept marks it HEALTHY at sweptSeq (or DOWN at 0 for
		// the fail-closed sentinel), and REJECTS a non-monotone advance — surfaced
		// here as a sweep failure rather than a silent regression of the host-ward min.
		if nerr := r.notifier.NotifySwept(c.Name(), sweptSeq); nerr != nil {
			return 0, fmt.Errorf(
				"hostagent: sweep runner: recording sweep completion for %q at seq %d failed (host-ward seq held at 0): %w",
				c.Name(), sweptSeq, nerr,
			)
		}
	}

	// All three swept and reported — the host-ward swept seq is the registry's
	// min-over-three (the same value the heartbeat folds through the frozen D72
	// AppliedSeq). A seq-0 sentinel from any consumer drags this to 0.
	return r.notifier.AppliedSeq(), nil
}
