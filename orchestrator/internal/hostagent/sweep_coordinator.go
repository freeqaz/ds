package hostagent

// sweep_coordinator.go is the host agent's MULTI-CONSUMER POST-COMMIT REVOCATION
// SWEEP ORCHESTRATOR & policy re-evaluation driver (POL-4 part 3; D72/D53/D36,
// doc 13 §5 revocation-sweep row, doc 15 §5.2). It is a concrete Sweeper
// (apply.go) the ApplyCoordinator can invoke AFTER the two-phase commit flips the
// three consumers to vN+1: it drives each consumer's post-commit sweep path,
// collects each consumer's per-consumer swept seq IN ORDER, computes the
// min-over-three DIRECTLY (short-circuiting at the seq-0 sentinel or a sweep
// error), and returns that host-ward swept seq straight to the
// ApplyCoordinator.Sweep caller.
//
// RELATION TO sweep_runner.go (no overlap, complementary shapes). SweepRunner
// folds each consumer's swept seq THROUGH the SweepNotifier registry and returns
// the registry's min — it is the variant the heartbeat min-over-three reads from
// (it keeps the per-consumer ServiceHealth current). SweepCoordinator is the
// REGISTRY-FREE variant the spec's acceptance describes: it collects the swept
// seqs into a local slice, computes the min over exactly those seqs itself, and
// returns it without owning any per-consumer health state. Both satisfy the same
// Sweeper seam and reuse the same ConsumerSweep seam (sweep_runner.go); a host
// agent wires whichever post-commit shape it needs — the registry-coupled runner
// when the heartbeat must observe per-consumer sweep state, this leaner
// coordinator when the caller only needs the host-ward min returned (e.g. a
// caller that plumbs the heartbeat through its own path, or a conformance rig that
// asserts the bare min-over-three contract). Neither forks the single
// flush_session severing path (the sweep mechanism lives INSIDE each consumer).
//
// WHERE IT SITS IN THE D72 BARRIER (do not reopen):
//
//   - apply.go's ApplyCoordinator.Apply runs PREPARE then COMMIT, flips the
//     applied POINTER on a full commit, then calls c.sweeper.Sweep(ctx, snap).
//     SweepCoordinator satisfies that Sweeper seam. The frozen D72 rule is that
//     apply_seq advances ONLY after the sweep completes — so the value this
//     coordinator returns is exactly what the ApplyCoordinator publishes as the
//     round's applied seq (and on failure, the 0 that HOLDS apply_seq at the prior
//     version).
//   - Each consumer's post-commit sweep re-evaluates its derived state against
//     vN+1 — the ds-nft admit4/admit6 allow-set, the ds-dnsgate DNS-2b admission
//     map, and ds-dnsgate's live TTL-ask-grants — evicting everything vN+1 denies,
//     severing conntrack/tunnels RUNG-CONDITIONALLY (D53, flush at block-or-higher)
//     through the ONE shared flush_session primitive (ds-contracts). That sweep
//     mechanism lives INSIDE each consumer (Rust); this coordinator only DRIVES the
//     three host-local sweep calls and folds their reported seqs.
//   - The host moves to vN+1 only when ALL THREE consumers report a completed sweep
//     at a seq ≥ snap.Seq. The coordinator's returned min is that host-wide swept
//     seq; a consumer that reports the seq-0 sentinel (its "error or no sweep"
//     signal) drags the min to 0 — the host cannot claim a swept version a consumer
//     never reached (D72 fail-closed).
//
// THE SEAM (host-local UDS gRPC; transport is FREE, doc 13 §6). The per-consumer
// sweep client is the shared ConsumerSweep seam (sweep_runner.go) — the host-agent
// side of the Rust Consumer::sweep_and_advance_applied_seq(token) call
// (consumer_seam.go's Go↔Rust correspondence). A test fake satisfies it in-memory;
// the real UDS gRPC clients are owner-landed. The snapshot crosses as the frozen
// boundaryv1.PolicySnapshot, never an on-wire type.
//
// FAIL-CLOSED (D72), the invariants the body enforces:
//
//   - The sweep is ALL-OR-NONE at the host level. If ANY consumer's sweep returns
//     an error, the coordinator STOPS (it does not drive the remaining consumers)
//     and returns (0, err): the ApplyCoordinator then HOLDS apply_seq at the prior
//     version. The consumers stay on vN+1 (already at-least-as-strict — fail-closed);
//     only the SEQ ADVANCE is withheld until the sweep re-drives.
//   - The seq-0 sentinel is the consumer's "error or no sweep" signal: it is NOT a
//     transport error, so it is not surfaced as a Go error, but it STOPS the
//     collection (no later consumer can lift a min already pinned to 0) and the
//     coordinator returns (0, nil) — the host-ward swept seq is 0, so apply_seq is
//     held exactly as on an error, but without conflating a real fault with the
//     deliberate fail-closed sentinel.
//   - The returned swept seq is the MIN over the collected per-consumer seqs — never
//     a per-consumer value, never a vacuous high value. On the all-positive path
//     every consumer reports ≥ snap.Seq, so the min is ≥ snap.Seq (the host is
//     fully swept at the snapshot it just committed, or higher).
//
// NEVER-LOG-THE-SECRET: this coordinator moves only consumer names and seqs — no
// composed policy bytes ever cross it; the snapshot stays opaque
// boundaryv1.PolicySnapshot bytes handed straight to the consumer sweep calls.

import (
	"context"
	"fmt"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// SweepCoordinator is the registry-free concrete Sweeper (apply.go) that drives
// the three host-side consumers' post-commit revocation sweep IN the FIXED
// admitter-last order, collects each consumer's reported swept seq, and returns
// the min-over-three host-ward swept seq the round is now fully applied at. It is
// constructed once per host agent with the three consumer sweep clients
// (NewSweepCoordinator orders them) and handed to NewApplyCoordinator as the
// sweeper so Apply runs it post-commit (D72: apply_seq advances only post-sweep).
//
// It owns NO version pointer and NO per-consumer health registry of its own — it
// computes the min over the seqs it just collected and returns it. (The variant
// that keeps per-consumer ServiceHealth current for the heartbeat min-over-three
// is SweepRunner, sweep_runner.go.)
//
// Concurrency: Sweep is invoked by the single apply pump (one apply — and thus one
// sweep — at a time per host; the barrier is host-serial), and it holds no shared
// mutable state across calls, so it needs no internal lock.
type SweepCoordinator struct {
	// sweepOrder holds the three consumers in the FIXED admitter-last order
	// (ds-tlsproxy + nft-writer BEFORE ds-dnsgate) — the same make-before-break
	// order the commit walks (consumer_seam.go CommitOrder). Re-evaluating the
	// enforcers' derived state before the admitter's keeps every transient window
	// fail-closed for the same reason the commit order does.
	sweepOrder []ConsumerSweep
}

// NewSweepCoordinator builds the coordinator from the three consumer sweep
// clients. The clients may be passed UNORDERED: the constructor orders them into
// the FIXED admitter-last sweep order (the two enforcers before the admitter,
// consumer_seam.go CommitOrder) so a caller never hand-sequences it.
//
// It requires EXACTLY the three named consumers, each present once: a missing,
// duplicate, or unrecognized client is a wiring bug rejected fail-closed at
// construction (the same set NewApplyCoordinator, OrderBarriers, and NewSweepRunner
// enforce), never silently accepted.
func NewSweepCoordinator(clients ...ConsumerSweep) (*SweepCoordinator, error) {
	byName := make(map[string]ConsumerSweep, len(clients))
	for i, c := range clients {
		if c == nil {
			return nil, fmt.Errorf("hostagent: NewSweepCoordinator: nil consumer sweep client at position %d", i)
		}
		name := c.Name()
		switch name {
		case BoundaryDNSGate, BoundaryTLSProxy, BoundaryNFTWriter:
		default:
			return nil, fmt.Errorf("hostagent: NewSweepCoordinator: unrecognized consumer %q (want one of ds-tlsproxy, nft-writer, ds-dnsgate)", name)
		}
		if _, dup := byName[name]; dup {
			return nil, fmt.Errorf("hostagent: NewSweepCoordinator: duplicate consumer %q", name)
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
			return nil, fmt.Errorf("hostagent: NewSweepCoordinator: missing consumer %q (need all three of ds-tlsproxy, nft-writer, ds-dnsgate)", name)
		}
		ordered = append(ordered, c)
	}
	return &SweepCoordinator{sweepOrder: ordered}, nil
}

// Sweep drives the post-commit revocation sweep across the three consumers in the
// FIXED admitter-last order, collects each consumer's reported swept seq, and
// returns the host-ward swept seq — the MIN over the collected seqs — the round is
// now fully applied at. It satisfies the Sweeper seam (apply.go) the
// ApplyCoordinator invokes post-commit.
//
// Return contract (D72 fail-closed):
//
//   - A nil snapshot is a caller programming error (Apply never reaches the sweep
//     with a nil snap) — rejected without touching any consumer, swept seq 0.
//   - ANY consumer sweep error → the coordinator STOPS (it does not drive the
//     remaining consumers, since the host-wide sweep is all-or-none) and returns
//     (0, err). The ApplyCoordinator then HOLDS apply_seq at the prior version. The
//     consumers stay on vN+1 (fail-closed); only the seq advance waits for the
//     sweep to re-drive.
//   - A consumer reporting the seq-0 SENTINEL (its "error or no sweep" signal) is
//     NOT a transport error: it STOPS the collection (no later consumer can lift a
//     min already pinned to 0) and Sweep returns (0, nil) — apply_seq is held
//     exactly as on an error, but the deliberate fail-closed sentinel is not
//     conflated with a real fault.
//   - All three swept at a positive seq → Sweep returns the MIN over the three
//     reported seqs. Each consumer reports ≥ snap.Seq on this path, so the min is
//     ≥ snap.Seq — the host is fully swept at the snapshot it committed (or higher).
func (c *SweepCoordinator) Sweep(ctx context.Context, snap *boundaryv1.PolicySnapshot) (uint64, error) {
	if snap == nil {
		return 0, fmt.Errorf("hostagent: sweep coordinator: nil snapshot")
	}

	// Drive each consumer's post-commit sweep in the FIXED admitter-last order,
	// collecting the swept seqs as we go. The host-wide sweep is all-or-none:
	//   - a sweep ERROR stops the round and returns (0, err) (fail-closed: apply_seq
	//     is held by the ApplyCoordinator);
	//   - the seq-0 SENTINEL stops the round and returns (0, nil) (the min is already
	//     pinned to 0 — no later consumer can lift it — without conflating the
	//     deliberate sentinel with a transport fault).
	// On the all-positive path we keep the running min so the return value is the
	// min over EXACTLY the collected seqs.
	var min uint64
	for i, consumer := range c.sweepOrder {
		sweptSeq, serr := consumer.SweepAndAdvance(ctx, snap)
		if serr != nil {
			// The consumer is on vN+1 (the commit already happened) but its sweep did
			// not complete. The host-wide sweep fails all-or-none: stop here (do not
			// drive the remaining consumers) and return seq 0 so the ApplyCoordinator
			// holds apply_seq until the sweep re-drives (D72).
			return 0, fmt.Errorf(
				"hostagent: sweep coordinator: post-commit sweep of %q failed for seq %d (consumer on vN+1, apply_seq held until sweep re-drives): %w",
				consumer.Name(), snap.GetSeq(), serr,
			)
		}
		if sweptSeq == 0 {
			// The seq-0 sentinel: this consumer reported "error or no sweep". The
			// host-ward min is now pinned to 0 (a consumer cannot claim a swept version
			// it never reached, D72 fail-closed). No later consumer can lift it, so stop
			// and return 0 — NOT a Go error (the sentinel is a deliberate fail-closed
			// signal, distinct from a transport fault, matching the seq-0 contract the
			// SweepNotifier and the acceptance use).
			return 0, nil
		}
		// All-positive path: fold this consumer's seq into the running min.
		if i == 0 || sweptSeq < min {
			min = sweptSeq
		}
	}

	// Every consumer swept at a positive seq — the host-ward swept seq is the MIN
	// over the three reported seqs.
	return min, nil
}
