package hostagent

// apply.go is the host agent's orchestration of the D72 TWO-PHASE APPLY BARRIER
// (POL-4 part 1; D72/D36, doc 13 §5, doc 15 §5.2). It sits DOWNSTREAM of the
// atomic snapshot store (snapshotstore.go): once a snapshot is verified,
// persisted, and the host has advanced its RECEIVED version, the agent fans that
// snapshot to the THREE host-side consumers — ds-tlsproxy (dataplane/services/
// ds-tlsproxy), the NFTables programmer (nft-writer, dataplane/crates/ds-nft),
// and ds-dnsgate (dataplane/services/ds-dnsgate) — and drives them through a
// two-phase barrier so the host moves from vN to vN+1 all-or-none.
//
// THE FROZEN D72 BARRIER (do not reopen):
//
//   - PHASE 1 — PREPARE. Every consumer validates the new snapshot via its
//     embedded policy-core and STAGES a new evaluator while STILL SERVING vN (the
//     old snapshot). Prepare is the only fallible step; it runs for all three
//     consumers (here, in parallel) before any commit. If ANY consumer's prepare
//     fails, the apply ABORTS host-wide: NO consumer is committed, the host stays
//     FULLY on vN, and the applied version does not advance (all-or-none, D72).
//   - PHASE 2 — COMMIT. Consumers FLIP from vN to vN+1 in a FIXED, admitter-last
//     order: ds-tlsproxy and the NFT programmer flip BEFORE ds-dnsgate. This is
//     the make-before-break analog (doc 13 §5.2): the admitter (ds-dnsgate, which
//     opens new flows) flips LAST, so every transient mixed-version window during
//     the flip is FAIL-CLOSED — the enforcers are already on the new (at-least-as-
//     strict) policy before the admitter starts admitting under it. Each intra-
//     consumer flip is ATOMIC (a pointer swap, or one netlink txn for the NFT
//     programmer, per D72), so a single consumer never serves a torn policy.
//   - POST-COMMIT. Only after all three commit does the host's APPLIED version
//     advance. apply_seq itself advances ONLY after the post-commit revocation
//     SWEEP completes (D72; the heartbeat's applied_seq is the post-sweep MIN over
//     the three consumers, heartbeat.go) — this coordinator advances the applied
//     POINTER on commit and leaves sweep/seq-advance to the caller's sweep hook.
//
// This file owns ONLY the host-agent-side orchestration of that barrier. The
// per-consumer prepare/commit (deep parse via embedded policy-core, the pointer
// swap, the netlink txn) lives in the consumers behind the ConsumerBarrier seam;
// the post-commit revocation sweep (the single ds-contracts flush_session
// primitive) is a separate seam (Sweeper) the caller wires. NEVER-LOG-THE-SECRET:
// nothing here logs the composed document; it crosses as opaque bytes inside the
// frozen PolicySnapshot.

import (
	"context"
	"fmt"
	"sync"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// ConsumerBarrier is the host agent's seam onto ONE of the three host-side policy
// consumers' two-phase apply. It is the host-agent side of the boundary services'
// prepare/commit seams (e.g. ds-dnsgate.WatchSnapshots / ds-tlsproxy.WatchSnapshots
// and the linked nft-writer crate): Prepare maps to the consumer receiving the new
// snapshot and STAGING an evaluator while serving vN; Commit maps to the atomic
// flip to vN+1.
//
// It is a SEAM (an interface, the package's pinned-later idiom — like
// SnapshotPersister and HeartbeatDialer): a test fake satisfies it in-memory; the
// real host-local UDS gRPC clients to the three consumers are owner-landed. The
// snapshot crosses as the frozen boundaryv1.PolicySnapshot, never an on-wire type.
//
// CONTRACT both phases honor:
//
//   - Prepare(ctx, snap) validates and STAGES snap WITHOUT flipping — the consumer
//     keeps serving its current (vN) policy. It returns a PreparedSnapshot handle
//     that Commit consumes, or a non-nil error naming why the consumer cannot
//     accept snap (an invalid document, a staging failure). A prepare error is
//     fatal to the WHOLE host apply (fail-closed, all-or-none): the coordinator
//     never commits ANY consumer and the host stays on vN.
//   - Commit(ctx, prepared) ATOMICALLY flips the consumer from vN to vN+1 (pointer
//     swap / one netlink txn, D72). It is called ONLY with a PreparedSnapshot this
//     consumer's own Prepare returned, and ONLY after EVERY consumer prepared
//     successfully. Commit is the non-fallible-by-design half of the barrier
//     (the fallible validation already happened in prepare); a commit error is
//     surfaced but indicates a consumer-internal fault the host's recovery policy
//     handles — it does not retroactively un-prepare the others (see Apply).
type ConsumerBarrier interface {
	// Name is the consumer's stable identity (one of BoundaryDNSGate /
	// BoundaryTLSProxy / BoundaryNFTWriter) — used only for error messages and so
	// a coordinator can be asserted to commit in the right order; it never feeds
	// policy evaluation.
	Name() string

	// Prepare validates and stages snap while the consumer keeps serving vN. The
	// returned PreparedSnapshot is opaque to the coordinator (it just hands it back
	// to this same consumer's Commit). A non-nil error aborts the host-wide apply.
	//
	// snap carries BOTH the transported document bytes (snap.GetDocument()) and the
	// producer-pinned, separately-transported content_hash (snap.GetContentHash())
	// — the §5.1 identity tuple. The two ENFORCER consumers (the NFT programmer and
	// ds-dnsgate the admitter) thread that transported content_hash into the Rust
	// Consumer::prepare_verified non-vacuous identity gate (verify the bytes against
	// the SEPARATELY-transported hash BEFORE parse; a mismatch NACKs host-wide). The
	// snapshot store already verified this same content_hash against the transported
	// bytes on receipt (snapshotstore.go Accept, verify-before-fan-out) and NACKed any
	// mismatch — so by the time a snapshot reaches this fan-out its hash is present
	// and consistent with its bytes, and the downstream gate is never vacuous. The
	// hash is NEVER re-derived here.
	Prepare(ctx context.Context, snap *boundaryv1.PolicySnapshot) (PreparedSnapshot, error)

	// Commit atomically flips the consumer to the prepared snapshot (vN+1). It is
	// called only with a handle this consumer's Prepare returned, and only after
	// all consumers prepared.
	Commit(ctx context.Context, prepared PreparedSnapshot) error
}

// PreparedSnapshot is the opaque handle a consumer's Prepare returns and its own
// Commit consumes — the staged-but-not-flipped evaluator. The coordinator never
// inspects it; it only routes each handle back to the consumer that produced it,
// preserving the per-consumer atomic-flip contract (D72). It is an empty
// interface so any consumer impl (or test fake) can carry whatever staged state
// its flip needs.
type PreparedSnapshot interface{}

// Sweeper runs the POST-COMMIT revocation sweep (D72, doc 15 §5.2): after the
// host flips to vN+1 it re-evaluates derived state (allow4/allow6, the DNS-2b
// admission map, live ask-grants) against vN+1 and evicts everything vN+1 denies,
// severing conntrack/tunnels RUNG-CONDITIONALLY (D53) through the ONE shared
// flush_session primitive (ds-contracts). It is a SEAM the caller wires; this
// coordinator only invokes it after a successful commit and BEFORE it reports the
// apply as fully done — because apply_seq advances ONLY after the sweep completes
// (D72). A nil Sweeper means the caller advances seq through its own post-commit
// path; Apply then reports the commit but performs no sweep.
//
// Sweep returns the seq the host is now fully applied+swept at (normally
// snap.Seq) and a non-nil error if the sweep could not complete — in which case
// apply_seq MUST NOT advance past vN for this round (the caller does not publish
// snap.Seq to the heartbeat min). The commit already happened (the consumers are
// on vN+1, which is at-least-as-strict — fail-closed), so a sweep error does not
// roll the consumers back; it withholds the seq advance until the sweep is
// re-driven.
type Sweeper interface {
	Sweep(ctx context.Context, snap *boundaryv1.PolicySnapshot) (sweptSeq uint64, err error)
}

// ApplyCoordinator drives the D72 two-phase barrier over the three host-side
// consumers in their FIXED admitter-last commit order. It is constructed once per
// host agent with the three consumer barriers (already in commit order) and an
// optional post-commit sweeper, then driven by Apply for each newly-applied
// snapshot the store fans out.
//
// It owns the host's APPLIED version pointer — the version the consumers have
// committed to, distinct from the snapshot store's RECEIVED version
// (SnapshotStore.AppliedSeq) and from the heartbeat's post-sweep applied_seq min.
// appliedSeq here only advances on a fully-successful commit (and, when a sweeper
// is wired, only the swept seq is reported as the round's applied seq, since
// apply_seq advances post-sweep per D72).
//
// Concurrency: Apply is serialized by the single fan-out pump that drives it (one
// apply at a time per host — the barrier is inherently host-serial); the applied
// pointer is still guarded by a mutex so a concurrent AppliedSeq reader (e.g. the
// heartbeat builder) never observes a half-updated version.
type ApplyCoordinator struct {
	// commitOrder holds the three consumers in the FIXED admitter-last commit
	// order: ds-tlsproxy and nft-writer (the enforcers) BEFORE ds-dnsgate (the
	// admitter). Prepare runs over all of them (order-independent); Commit walks
	// this slice front-to-back, so its order IS the make-before-break order.
	commitOrder []ConsumerBarrier
	sweeper     Sweeper

	mu         sync.RWMutex
	appliedSeq uint64 // 0 until the first successful host-wide apply
	hasApplied bool
}

// NewApplyCoordinator builds the coordinator from the three consumer barriers in
// FIXED admitter-last COMMIT order and an optional post-commit sweeper.
//
// The caller passes the consumers already ordered for COMMIT: the two enforcers
// (ds-tlsproxy + nft-writer) first, the admitter (ds-dnsgate) LAST. The
// coordinator validates that exactly the three named consumers are present and
// that the admitter (ds-dnsgate) is committed LAST — a misordered or incomplete
// set is a wiring bug that would open a mixed-version hole, so it is rejected at
// construction (fail-closed), never silently accepted. A nil sweeper is allowed
// (the caller advances seq through its own post-commit sweep path).
func NewApplyCoordinator(commitOrder []ConsumerBarrier, sweeper Sweeper) (*ApplyCoordinator, error) {
	if len(commitOrder) != 3 {
		return nil, fmt.Errorf(
			"hostagent: NewApplyCoordinator: want exactly 3 consumers (ds-tlsproxy, nft-writer, ds-dnsgate) in commit order, got %d",
			len(commitOrder),
		)
	}
	seen := map[string]bool{}
	for i, c := range commitOrder {
		if c == nil {
			return nil, fmt.Errorf("hostagent: NewApplyCoordinator: nil consumer at commit position %d", i)
		}
		name := c.Name()
		switch name {
		case BoundaryDNSGate, BoundaryTLSProxy, BoundaryNFTWriter:
		default:
			return nil, fmt.Errorf("hostagent: NewApplyCoordinator: unrecognized consumer %q (want one of ds-dnsgate, ds-tlsproxy, nft-writer)", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("hostagent: NewApplyCoordinator: duplicate consumer %q in commit order", name)
		}
		seen[name] = true
	}
	if !seen[BoundaryDNSGate] || !seen[BoundaryTLSProxy] || !seen[BoundaryNFTWriter] {
		return nil, fmt.Errorf("hostagent: NewApplyCoordinator: commit order must contain all three of ds-tlsproxy, nft-writer, ds-dnsgate")
	}
	// The admitter (ds-dnsgate) MUST commit LAST so every mixed-version window is
	// fail-closed (D72 make-before-break). Anything else is a wiring bug.
	if commitOrder[len(commitOrder)-1].Name() != BoundaryDNSGate {
		return nil, fmt.Errorf(
			"hostagent: NewApplyCoordinator: ds-dnsgate (the admitter) MUST commit LAST (admitter-last, D72); got %q last",
			commitOrder[len(commitOrder)-1].Name(),
		)
	}
	return &ApplyCoordinator{
		commitOrder: commitOrder,
		sweeper:     sweeper,
	}, nil
}

// ApplyOutcome reports the result of one host-wide two-phase apply.
type ApplyOutcome struct {
	// Committed is true iff ALL three consumers prepared AND committed — the host
	// is now serving vN+1. False means the apply aborted in prepare (all-or-none:
	// no consumer committed) — the host stays fully on vN.
	Committed bool

	// AppliedSeq is the host's APPLIED version after this call. On a successful
	// apply WITH a sweeper it is the swept seq (apply_seq advances post-sweep,
	// D72); WITHOUT a sweeper it is snap.Seq (the caller runs sweep itself before
	// publishing to the heartbeat min). On an abort it is the PRIOR applied seq
	// (the host stays on vN — unchanged).
	AppliedSeq uint64

	// Swept is true iff a post-commit sweep ran AND completed for this apply. It
	// is false when no sweeper is wired (the caller sweeps) and false when the
	// commit aborted (nothing to sweep). When a sweeper is wired and Swept is
	// false on a committed apply, the sweep failed and AppliedSeq was held at the
	// prior version (apply_seq does not advance until the sweep completes, D72).
	Swept bool
}

// Apply drives the full D72 two-phase barrier for one verified snapshot: PREPARE
// all three consumers (in parallel; any failure aborts host-wide and the host
// stays on vN), then COMMIT in the FIXED admitter-last order (ds-tlsproxy +
// nft-writer before ds-dnsgate), then run the post-commit revocation sweep so
// apply_seq advances only after the sweep completes (D72).
//
// Return contract:
//
//   - PREPARE failure on ANY consumer → ApplyOutcome{Committed:false, AppliedSeq:
//     <prior>, Swept:false}, err != nil. NO consumer is committed (all-or-none).
//     The applied pointer does NOT advance — the host stays fully on vN. This is
//     the fail-closed path: a partially-preparable snapshot never flips a single
//     consumer.
//   - All prepared, all committed → the consumers are on vN+1. The applied pointer
//     advances. If a sweeper is wired, the post-commit sweep runs: on sweep
//     success AppliedSeq is the swept seq and Swept is true; on sweep FAILURE the
//     consumers stay on vN+1 (already at-least-as-strict, fail-closed) but
//     AppliedSeq is HELD at the prior version and Swept is false (apply_seq does
//     not advance until the sweep completes, D72), with err naming the sweep
//     defect. With no sweeper, AppliedSeq is snap.Seq and Swept is false (the
//     caller sweeps before publishing the seq to the heartbeat min).
//
// A nil snapshot is a programming error from the caller (the store never fans out
// a nil); it is rejected without touching any consumer.
func (c *ApplyCoordinator) Apply(ctx context.Context, snap *boundaryv1.PolicySnapshot) (ApplyOutcome, error) {
	prior := c.AppliedSeq()
	if snap == nil {
		return ApplyOutcome{Committed: false, AppliedSeq: prior, Swept: false},
			fmt.Errorf("hostagent: apply coordinator: nil snapshot")
	}

	// PHASE 1 — PREPARE all three consumers in PARALLEL while they all keep serving
	// vN. Each consumer's Prepare receives the WHOLE snap — the transported document
	// bytes (snap.GetDocument()) AND the producer-pinned, separately-transported
	// content_hash (snap.GetContentHash(); the §5.1 identity tuple, NEVER re-derived
	// here). That transported content_hash is exactly what the two ENFORCER consumers
	// (the NFT programmer + ds-dnsgate the admitter) thread into the Rust
	// Consumer::prepare_verified NON-VACUOUS identity gate: a verify-before-parse
	// against the separately-transported hash that CAN NACK (a HashMismatch aborts the
	// apply host-wide and the host stays on vN — re-hashing the bytes and comparing to
	// their own hash never could). The same content_hash snapshotstore.go verified on
	// receipt (Accept, verify-before-fan-out — a mismatch was already NACKed upstream,
	// so the hash threaded here is present and consistent with the bytes) flows, inside
	// snap, all the way to each consumer's prepare. Collect
	// each consumer's PreparedSnapshot handle (indexed by commit position so commit
	// re-uses the correct handle per consumer). Any prepare error — a HashMismatch
	// NACK included — aborts the WHOLE host apply (all-or-none, fail-closed): no commit
	// runs and the host stays fully on vN.
	prepared := make([]PreparedSnapshot, len(c.commitOrder))
	prepErrs := make([]error, len(c.commitOrder))
	var wg sync.WaitGroup
	wg.Add(len(c.commitOrder))
	for i, consumer := range c.commitOrder {
		go func(i int, consumer ConsumerBarrier) {
			defer wg.Done()
			p, err := consumer.Prepare(ctx, snap)
			prepared[i] = p
			prepErrs[i] = err
		}(i, consumer)
	}
	wg.Wait()

	// If ANY prepare failed, ABORT host-wide: commit NOTHING, host stays on vN.
	// The applied pointer is untouched — the host never advances past vN (D72
	// all-or-none).
	for i, err := range prepErrs {
		if err != nil {
			return ApplyOutcome{Committed: false, AppliedSeq: prior, Swept: false},
				fmt.Errorf(
					"hostagent: apply coordinator: prepare of %q failed for seq %d (host stays on vN, no consumer committed): %w",
					c.commitOrder[i].Name(), snap.GetSeq(), err,
				)
		}
	}

	// PHASE 2 — COMMIT in the FIXED admitter-last order: walk commitOrder
	// front-to-back, so ds-tlsproxy + nft-writer flip BEFORE ds-dnsgate (the
	// admitter). Each flip is atomic inside the consumer (pointer swap / netlink
	// txn, D72). A commit error here is a consumer-internal fault AFTER the host
	// committed to advancing (every consumer already prepared); it is surfaced, but
	// the already-flipped consumers stay on vN+1 (at-least-as-strict — fail-closed),
	// and the host's recovery policy re-drives. The applied pointer is NOT advanced
	// on a commit error (apply_seq does not move past vN until the round completes).
	for _, consumer := range c.commitOrder {
		if err := consumer.Commit(ctx, prepared[indexOf(c.commitOrder, consumer)]); err != nil {
			return ApplyOutcome{Committed: false, AppliedSeq: prior, Swept: false},
				fmt.Errorf(
					"hostagent: apply coordinator: commit of %q failed for seq %d (already-committed enforcers stay on vN+1, fail-closed): %w",
					consumer.Name(), snap.GetSeq(), err,
				)
		}
	}

	// All three committed — the host is serving vN+1. Advance the applied pointer.
	c.mu.Lock()
	c.appliedSeq = snap.GetSeq()
	c.hasApplied = true
	c.mu.Unlock()

	// POST-COMMIT SWEEP (D72): apply_seq advances ONLY after the sweep completes.
	// Without a sweeper the caller runs sweep on its own path; we report snap.Seq
	// applied (commit done) and Swept=false.
	if c.sweeper == nil {
		return ApplyOutcome{Committed: true, AppliedSeq: snap.GetSeq(), Swept: false}, nil
	}

	sweptSeq, serr := c.sweeper.Sweep(ctx, snap)
	if serr != nil {
		// The consumers are on vN+1 (fail-closed); the sweep did not complete, so
		// apply_seq must NOT advance past the prior version this round — hold the
		// REPORTED applied seq at the prior value (the caller does not publish
		// snap.Seq to the heartbeat min until the sweep is re-driven). The commit
		// itself succeeded, so Committed stays true.
		return ApplyOutcome{Committed: true, AppliedSeq: prior, Swept: false},
			fmt.Errorf(
				"hostagent: apply coordinator: post-commit sweep failed for seq %d (consumers on vN+1, apply_seq held at %d until sweep re-drives): %w",
				snap.GetSeq(), prior, serr,
			)
	}

	return ApplyOutcome{Committed: true, AppliedSeq: sweptSeq, Swept: true}, nil
}

// indexOf returns the position of consumer in order by identity (pointer
// equality), so Commit re-uses the PreparedSnapshot handle that consumer's own
// Prepare produced. The consumer set is exactly three and fixed at construction,
// so this is a trivial scan, not a hot path.
func indexOf(order []ConsumerBarrier, consumer ConsumerBarrier) int {
	for i := range order {
		if order[i] == consumer {
			return i
		}
	}
	return -1
}

// AppliedSeq returns the host's APPLIED version: the seq the three consumers have
// committed to (0 before the first successful host-wide apply). It is distinct
// from the snapshot store's RECEIVED seq (SnapshotStore.AppliedSeq) and is the
// pre-heartbeat-min input — the heartbeat's applied_seq is the post-sweep MIN
// over the three consumers (heartbeat.go), advancing only after each consumer's
// own sweep completes (D72).
func (c *ApplyCoordinator) AppliedSeq() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.appliedSeq
}

// HasApplied reports whether the host has completed at least one successful
// host-wide apply. Before that a booting host serves nothing beyond NFT-1
// default-deny (D72) — the coordinator has flipped no consumer to a composed
// policy yet.
func (c *ApplyCoordinator) HasApplied() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hasApplied
}
