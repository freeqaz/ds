package hostagent

// consumer_seam.go pins the GO SIDE of the frozen D72 two-phase apply seam
// (POL-4 part 2; D72/D36, doc 13 §5, doc 15 §5.2) and its cross-language
// correspondence with the canonical Rust contract in
// dataplane/crates/ds-contracts/src/consumer.rs.
//
// SINGLE-SOURCE (no re-declaration). The seam's two host-agent-side interfaces
// already live in apply.go — ConsumerBarrier (Prepare/Commit + the opaque
// PreparedSnapshot handle) and Sweeper (the post-commit revocation sweep) — and
// the three consumer identities live in heartbeat.go (BoundaryDNSGate /
// BoundaryTLSProxy / BoundaryNFTWriter). This file declares NO second copy of
// any of them; it adds only the ORDERING helper that makes the FIXED
// admitter-last commit order constructible without re-deriving it at each call
// site, plus the doc that fixes the Go↔Rust mapping so the two sides cannot
// drift behind a freeze.
//
// THE Go↔Rust SEAM CORRESPONDENCE (frozen):
//
//	Rust ds-contracts::consumer            Go hostagent
//	──────────────────────────────────     ──────────────────────────────────
//	Consumer::prepare(bytes, version)  ↔   ConsumerBarrier.Prepare(ctx, snap)
//	  → Result<ApplyToken, PrepareError>     → (PreparedSnapshot, error)
//	Consumer::commit(token)            ↔   ConsumerBarrier.Commit(ctx, prepared)
//	  → Result<(), ApplyError>               → error
//	Consumer::sweep_and_advance_       ↔   Sweeper.Sweep(ctx, snap)
//	  applied_seq(token)                     → (sweptSeq uint64, err error)
//	  → Result<PolicyVersion, ApplyError>
//
// The Rust ApplyToken is the per-consumer staged-evaluator claim ticket; on the
// Go side that handle is the opaque PreparedSnapshot the coordinator routes back
// to the same consumer's Commit (apply.go). The Rust PolicyVersion / the Go
// uint64 seq are the SAME D36 policy_log bigserial — the single policy version
// end to end (doc 13 §1 rule 3). There is NO FFI: the Go driver speaks to the
// Rust consumers over host-local UDS gRPC (the snapshot crosses as the frozen
// boundaryv1.PolicySnapshot), and each side binds to its own native seam shape
// above — the correspondence is a contract, enforced here in prose and by the
// boundary conformance rig, not a generated bridge.
//
// FAIL-CLOSED / D72 invariants this seam carries (the bodies enforce them in
// apply.go; this file names them so a reviewer sees them at the seam):
//
//   - PREPARE is the only fallible-by-design phase; ANY prepare failure aborts
//     the apply host-wide (all-or-none) and the host stays fully on vN.
//   - COMMIT flips in the FIXED admitter-last order — the two enforcers
//     (ds-tlsproxy + nft-writer) BEFORE the admitter (ds-dnsgate) — so every
//     transient mixed-version window is fail-closed (make-before-break).
//   - applied_seq advances ONLY after the post-commit sweep completes; the
//     heartbeat reports the MIN over the three consumers (heartbeat.go).
//
// NEVER-LOG-THE-SECRET: nothing on this seam logs the composed document.

import "fmt"

// CommitOrder is the FIXED admitter-last commit order the D72 barrier requires
// (doc 13 §5.2): the two ENFORCERS commit before the single ADMITTER, so the
// admitter (ds-dnsgate, which opens new flows) flips LAST and every transient
// mixed-version window is fail-closed. This is the canonical name ordering;
// NewApplyCoordinator validates that the ConsumerBarrier slice it is handed
// matches it (admitter last), and OrderBarriers below builds a correctly-ordered
// slice from an unordered set so a caller never hand-sequences it.
//
// The slice is value-cloned by the accessors; callers never mutate the package
// global.
var commitOrder = [3]string{BoundaryTLSProxy, BoundaryNFTWriter, BoundaryDNSGate}

// CommitOrder returns the three consumer identities in FIXED admitter-last
// commit order (ds-tlsproxy, nft-writer, ds-dnsgate). It is the single source
// for that ordering on the Go side — callers building a coordinator order their
// ConsumerBarriers by it (or via OrderBarriers) rather than re-encoding the
// rule, which keeps the make-before-break invariant in exactly one place.
func CommitOrder() []string {
	return []string{commitOrder[0], commitOrder[1], commitOrder[2]}
}

// IsAdmitter reports whether name is the single admitter (ds-dnsgate) — the
// consumer that MUST commit last (D72). The two enforcers (ds-tlsproxy,
// nft-writer) return false.
func IsAdmitter(name string) bool {
	return name == BoundaryDNSGate
}

// OrderBarriers returns the given consumer barriers in the FIXED admitter-last
// CommitOrder, ready to hand to NewApplyCoordinator. It is the constructor-time
// helper that turns an unordered set of the three barriers into the one legal
// commit sequence, so a caller never hand-sequences the order (a misordering
// would open a mixed-version hole — NewApplyCoordinator rejects it, but ordering
// here means the caller cannot get there).
//
// It requires EXACTLY the three named consumers, each present once: a missing,
// duplicate, or unrecognized barrier is a wiring bug rejected fail-closed (the
// same set NewApplyCoordinator enforces, caught one step earlier). The returned
// slice is safe to pass straight to NewApplyCoordinator.
func OrderBarriers(barriers ...ConsumerBarrier) ([]ConsumerBarrier, error) {
	byName := make(map[string]ConsumerBarrier, len(barriers))
	for i, b := range barriers {
		if b == nil {
			return nil, fmt.Errorf("hostagent: OrderBarriers: nil consumer at position %d", i)
		}
		name := b.Name()
		switch name {
		case BoundaryDNSGate, BoundaryTLSProxy, BoundaryNFTWriter:
		default:
			return nil, fmt.Errorf("hostagent: OrderBarriers: unrecognized consumer %q (want one of ds-tlsproxy, nft-writer, ds-dnsgate)", name)
		}
		if _, dup := byName[name]; dup {
			return nil, fmt.Errorf("hostagent: OrderBarriers: duplicate consumer %q", name)
		}
		byName[name] = b
	}
	ordered := make([]ConsumerBarrier, 0, len(commitOrder))
	for _, name := range commitOrder {
		b, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("hostagent: OrderBarriers: missing consumer %q (need all three of ds-tlsproxy, nft-writer, ds-dnsgate)", name)
		}
		ordered = append(ordered, b)
	}
	return ordered, nil
}
