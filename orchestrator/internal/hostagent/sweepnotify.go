package hostagent

// sweepnotify.go is the host agent's PER-CONSUMER SWEEP-COMPLETION REGISTRY
// (POL-4 part 1; D72, doc 13 §5, doc 15 §5.2). It is the DATA-PLUMBING seam
// between the three host-side policy consumers' POST-COMMIT revocation sweep
// (apply.go's Sweeper / the consumers' own sweep) and the frozen D72 heartbeat
// min-over-three (heartbeat.go's AppliedSeq).
//
// THE D72 SEMANTIC THIS PLUMBS (do not reopen):
//
//   - applied_seq advances ONLY after the sweep completes. The ApplyCoordinator
//     (apply.go) flips the three consumers to vN+1 in the make-before-break commit
//     order, then each consumer runs its post-commit revocation sweep (re-evaluate
//     allow4/allow6, the DNS-2b admission map, live ask-grants against vN+1 and
//     evict everything vN+1 denies, severing conntrack/tunnels rung-conditionally
//     via the ONE shared flush_session primitive, D53). A consumer's per-consumer
//     applied_seq is the seq it is FULLY swept at — NOT merely committed at.
//   - The host-ward Heartbeat.applied_seq is the MIN over EXACTLY the three named
//     consumers' per-consumer swept seq (D72; the frozen AppliedSeq in
//     heartbeat.go enforces the min-over-three, missing-consumer clamp, and
//     all-three-HEALTHY rule). This registry is the place the per-consumer swept
//     seqs LIVE between sweep-completion callbacks and the next heartbeat assembly.
//
// THE SEAM: the host agent's per-consumer boundary integrations (the host-local
// UDS gRPC clients to ds-tlsproxy / nft-writer / ds-dnsgate) call NotifySwept
// when a consumer reports its post-sweep completion (a boundary
// ServiceHealth.applied_seq in that consumer's sweep-completion report), and
// NotifyUnhealthy when a consumer is DEGRADED/DOWN (a sweep error, a lost
// connection). The heartbeat assembly reads Boundary() each cadence tick and
// folds it through the frozen AppliedSeq — so the top-level applied_seq the host
// reports can never advance past the min over the three consumers' SWEPT seqs.
//
// FAIL-CLOSED (D72): a consumer that has not yet reported a completed sweep
// contributes 0 (the missing-consumer clamp, enforced by AppliedSeq), so the host
// claims a swept version only when ALL THREE have reported a sweep at-or-above it.
// A consumer that reports a sweep at seq 0 (an error sentinel, or "no sweep yet")
// drags the min to 0. NEVER-LOG-THE-SECRET: this registry holds only consumer
// names, seqs, and health states — no composed policy bytes ever cross it.

import (
	"fmt"
	"sync"

	hostagentv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hostagent/v1"
)

// SweepNotifier is the host agent's per-consumer sweep-completion registry. It
// holds the latest post-sweep state (applied_seq + health) for each of the three
// named consumers (BoundaryDNSGate / BoundaryTLSProxy / BoundaryNFTWriter) and
// renders them as the []*ServiceHealth boundary list the heartbeat folds through
// the frozen D72 AppliedSeq min-over-three.
//
// It is constructed once per host agent (NewSweepNotifier) seeded with all three
// consumers in their fail-closed initial state (seq 0, not HEALTHY), so a host
// that has not yet completed a single round of sweeps reports applied_seq 0 — a
// booting host claims nothing beyond NFT-1 default-deny until its consumers have
// actually swept (D72).
//
// Concurrency: NotifySwept / NotifyUnhealthy are called from the per-consumer
// boundary-integration goroutines (one per consumer, plus the apply pump's sweep
// hook), while Boundary() / AppliedSeq() are read by the heartbeat builder on its
// cadence tick. All access is guarded by a single mutex; the rendered boundary
// list is a defensive copy so a heartbeat frame can never alias mutable registry
// state.
type SweepNotifier struct {
	mu       sync.RWMutex
	consumer map[string]*consumerSweepState
}

// consumerSweepState is one named consumer's latest reported sweep state. seq is
// the seq the consumer is FULLY SWEPT at (the per-consumer D72 min input); state
// is its health. A consumer only contributes a non-zero seq to the host-ward min
// when it is HEALTHY (the frozen AppliedSeq clamps a non-HEALTHY consumer to 0),
// so NotifyUnhealthy fail-closes the contribution without having to zero the seq.
type consumerSweepState struct {
	seq    uint64
	state  hostagentv1.HealthState
	detail string
}

// sweepConsumerNames are the EXACTLY three named consumers the registry tracks —
// the same set the frozen AppliedSeq takes its min over. Seeding all three at
// construction makes the missing-consumer clamp explicit: a consumer that has
// never reported is present in the map in its fail-closed initial state, so it
// is visibly "tracked, not yet swept" rather than silently absent.
var sweepConsumerNames = []string{BoundaryDNSGate, BoundaryTLSProxy, BoundaryNFTWriter}

// NewSweepNotifier builds the registry with all three named consumers seeded in
// their FAIL-CLOSED initial state: seq 0 and NOT HEALTHY (HEALTH_STATE_DOWN until
// a consumer reports a completed sweep). So before any sweep completes the
// heartbeat reports applied_seq 0 (the unschedulable floor D36 reads), never a
// vacuous high value (D72).
func NewSweepNotifier() *SweepNotifier {
	consumer := make(map[string]*consumerSweepState, len(sweepConsumerNames))
	for _, name := range sweepConsumerNames {
		consumer[name] = &consumerSweepState{
			seq:    0,
			state:  hostagentv1.HealthState_HEALTH_STATE_DOWN,
			detail: "no completed sweep reported yet",
		}
	}
	return &SweepNotifier{consumer: consumer}
}

// NotifySwept records that a consumer has reported a COMPLETED post-commit sweep
// at sweptSeq — its boundary ServiceHealth.applied_seq in the sweep-completion
// report (D72: applied_seq advances ONLY after the sweep completes). The consumer
// is marked HEALTHY at sweptSeq, so it now contributes sweptSeq to the host-ward
// min-over-three on the NEXT heartbeat.
//
// FAIL-CLOSED sentinel: a sweptSeq of 0 means the consumer reported an error or
// "no sweep" (the acceptance's seq=0 case). The registry records seq 0 AND marks
// the consumer DOWN, so its contribution is clamped to 0 by the frozen AppliedSeq
// either way and the host's applied_seq reflects 0 (it cannot claim a swept
// version a consumer never reached). A swept seq MUST NOT go BACKWARDS for a
// HEALTHY consumer (sweeps are monotone per the seq cursor); a lower-or-equal
// sweptSeq is rejected as a wiring bug rather than silently regressing the min,
// EXCEPT the 0 sentinel which is always honored as the fail-closed signal.
//
// An UNRECOGNIZED consumer name is rejected: only the three named consumers feed
// the D72 min, and a typo'd name would silently never contribute, masking a
// never-sweeping consumer behind the missing-consumer clamp forever.
func (n *SweepNotifier) NotifySwept(consumer string, sweptSeq uint64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	st, ok := n.consumer[consumer]
	if !ok {
		return fmt.Errorf("hostagent: sweep notifier: unrecognized consumer %q (want one of ds-dnsgate, ds-tlsproxy, nft-writer)", consumer)
	}
	if sweptSeq == 0 {
		// Fail-closed sentinel: a swept seq of 0 reports an error or "no sweep".
		// Mark the consumer DOWN at seq 0 so its contribution is clamped to 0 and
		// the host-ward applied_seq reflects 0 (D72 fail-closed).
		st.seq = 0
		st.state = hostagentv1.HealthState_HEALTH_STATE_DOWN
		st.detail = "reported sweep at seq 0 (error or no sweep)"
		return nil
	}
	// A completed sweep is monotone: a HEALTHY consumer that has already reported a
	// swept seq must not move backwards (the seq cursor only advances). A lower or
	// equal report from a still-HEALTHY consumer is a wiring bug — reject it rather
	// than regress the host-ward min behind a value the host already published.
	if st.state == hostagentv1.HealthState_HEALTH_STATE_HEALTHY && sweptSeq <= st.seq {
		return fmt.Errorf(
			"hostagent: sweep notifier: consumer %q reported non-advancing swept seq %d (already swept at %d; sweeps are monotone)",
			consumer, sweptSeq, st.seq,
		)
	}
	st.seq = sweptSeq
	st.state = hostagentv1.HealthState_HEALTH_STATE_HEALTHY
	st.detail = ""
	return nil
}

// NotifyUnhealthy marks a consumer DEGRADED or DOWN — a sweep that could not
// complete, a lost host-local connection, a consumer-internal fault. The
// consumer's contribution to the host-ward min is clamped to 0 by the frozen
// AppliedSeq (a non-HEALTHY consumer proves nothing), so the host's applied_seq
// drops to 0 until the consumer reports a fresh completed sweep via NotifySwept.
//
// The consumer's last-known swept seq is RETAINED for diagnostics (it still rides
// the boundary list's ServiceHealth.applied_seq for the orchestrator's view), but
// because the state is non-HEALTHY it cannot inflate the min — a sick consumer
// with a high stale seq drags the host-ward applied_seq DOWN, never up (D72
// fail-closed). state MUST be a non-HEALTHY HealthState; HEALTHY is rejected (use
// NotifySwept to mark a consumer healthy at a completed sweep).
func (n *SweepNotifier) NotifyUnhealthy(consumer string, state hostagentv1.HealthState, detail string) error {
	if state == hostagentv1.HealthState_HEALTH_STATE_HEALTHY {
		return fmt.Errorf("hostagent: sweep notifier: NotifyUnhealthy called with HEALTHY for %q (use NotifySwept to mark a completed sweep)", consumer)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	st, ok := n.consumer[consumer]
	if !ok {
		return fmt.Errorf("hostagent: sweep notifier: unrecognized consumer %q (want one of ds-dnsgate, ds-tlsproxy, nft-writer)", consumer)
	}
	st.state = state
	st.detail = detail
	return nil
}

// Boundary renders the three named consumers' current sweep state as the
// []*ServiceHealth list the heartbeat assembly folds into HostState.Boundary —
// the per-consumer applied_seq inputs to the frozen D72 min-over-three
// (AppliedSeq, heartbeat.go). The list is ALWAYS exactly the three named
// consumers in a STABLE order (sweepConsumerNames), so the heartbeat frame and
// the min are deterministic and a missing consumer can never silently drop off
// the list (it rides at seq 0 / DOWN — the missing-consumer clamp made visible).
//
// The returned slice and its elements are FRESH copies — the heartbeat frame
// never aliases mutable registry state, so a concurrent NotifySwept cannot mutate
// a frame already handed to the streaming loop.
func (n *SweepNotifier) Boundary() []*hostagentv1.ServiceHealth {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make([]*hostagentv1.ServiceHealth, 0, len(sweepConsumerNames))
	for _, name := range sweepConsumerNames {
		st := n.consumer[name]
		out = append(out, &hostagentv1.ServiceHealth{
			Name:       name,
			State:      st.state,
			AppliedSeq: st.seq,
			Detail:     st.detail,
		})
	}
	return out
}

// AppliedSeq returns the host-ward applied_seq the heartbeat WOULD report right
// now: the frozen D72 min-over-three folded over the current per-consumer sweep
// state (Boundary). It is a convenience read for the host agent / a test that
// wants the current min without assembling a whole frame — it routes through the
// SAME AppliedSeq the heartbeat uses, so the registry's view and the wire value
// can never diverge.
func (n *SweepNotifier) AppliedSeq() uint64 {
	return AppliedSeq(n.Boundary())
}
