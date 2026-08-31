// SPDX-License-Identifier: Apache-2.0

// Termination of the boundary→orchestrator suspend signal (doc 15 §4.3,
// [doc 09](09-boundary-build-plan.md) §8 Stage-0 freeze): the orchestrator
// consumes the FROZEN boundary.v1.SuspendSignal, maps the D77 reason class onto
// the hypervisor.v1.SuspendReason the driver acts on, carries the POL-3
// provenance into the hypervisor.v1.SuspendRequest, ACKS, and DEDUPS by the
// signal's dedup key so a re-delivered signal is an idempotent no-op (one threat
// drives one Suspend).
//
// THE CONTRACT (consume, never re-declare):
//   - INPUT is the FROZEN boundary.v1.SuspendSignal: a SessionRef, the D77
//     SuspendReasonClass {BLOCKLIST_HIT, ACTION_SUSPEND_RULE}, the POL-3
//     provenance carried as flattened fields (matched_rule_id, policy_layer,
//     policy_version), and the dedup key. Consumed via proto/gen/go (the one legal
//     cross-tree import, D80).
//   - OUTPUT is the FROZEN hypervisor.v1.SuspendRequest: session_uuid, the
//     D77-narrowed hypervisor.v1.SuspendReason {USER|POLICY_BREACH|REBALANCE}, and
//     the boundary.v1.Provenance (the boundary-owned struct the SuspendRequest
//     imports). This file builds the request; parkresume.go drives it on the driver.
//   - D77 NARROWING (doc 15 §3 note 3): POLICY_BREACH is the reason for the TWO
//     genuine-threat classes ONLY — a BLOCKLIST_HIT or an explicit action:suspend
//     rule. Both boundary classes map to hypervisor POLICY_BREACH (the boundary
//     SuspendReasonClass is ALREADY narrowed to the two genuine-threat classes by
//     the boundary; ordinary policy events never produce a SuspendSignal). The
//     unanswered genuine rung-2 ask PARKS and never times out into allow or kill —
//     that escalation is the D46 clock (escalationclock.go) + the resume-authority
//     gate (resumeauthority.go), not this terminator.
//   - PROVENANCE is REQUIRED for POLICY_BREACH (the "why was this suspended?"
//     answer the hypervisor.v1.SuspendRequest demands when reason == POLICY_BREACH)
//     and UNSET otherwise. A boundary SuspendSignal always carries provenance (it
//     fired on a matched rule), so this is a structural mapping, not a refusal —
//     but a signal that arrives with NO provenance under a genuine-threat class is
//     a fail-closed reject (the gate cannot answer "why").
//
// DEDUP / IDEMPOTENCY (the load-bearing contract, doc 15 §4.3): the boundary
// chooses the dedup_key so two signals for the same triggering event share it; the
// orchestrator collapses retransmits onto ONE Suspend drive. The terminator owns a
// dedup set keyed by that string — the FIRST delivery of a key returns a
// SuspendRequest to drive + Accepted=true; every RE-delivery of the same key
// returns Duplicate=true and NO request (the caller acks and does nothing). The
// dedup set is the only mutable state and is guarded for concurrent delivery.
//
// ACK. Every delivery is ACKED (the boundary's signal is a notification, not an
// RPC awaiting a verb result): Accept returns a SuspendAck the caller relays back
// to the boundary. A duplicate is acked too (the boundary may retransmit precisely
// because it did not see the first ack) — acking a duplicate is the idempotent
// no-op, never a second Suspend.
//
// ADDITIVE / NEW FILE ONLY. No §3 state/edge/reason re-declared; it consumes the
// two frozen enums + the frozen messages and edits no other sessions file.

package sessions

import (
	"fmt"
	"sync"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

// ErrSuspendSignalInvalid is the fail-closed reject for a structurally invalid
// SuspendSignal: a missing session ref / session UUID, an unspecified or
// unrecognized reason class (a SuspendSignal never legally carries UNSPECIFIED —
// the boundary only fires on a genuine-threat class), an empty dedup key (the
// orchestrator cannot collapse retransmits without it), or missing POL-3
// provenance under a genuine-threat class (the SuspendRequest demands provenance
// for POLICY_BREACH). The error names the defect so the boundary can correct it.
type ErrSuspendSignalInvalid struct{ msg string }

func (e *ErrSuspendSignalInvalid) Error() string {
	return "sessions: invalid boundary.v1.SuspendSignal: " + e.msg
}

// MapSuspendReasonClass maps the FROZEN boundary.v1.SuspendReasonClass (the D77
// taxonomy) onto the FROZEN hypervisor.v1.SuspendReason the driver acts on. Both
// genuine-threat classes — BLOCKLIST_HIT and ACTION_SUSPEND_RULE — map to
// POLICY_BREACH (doc 15 §3 note 3: policy_breach is NARROWED to exactly these two
// classes). The UNSPECIFIED / unrecognized class maps to the hypervisor
// UNSPECIFIED reason, which the terminator rejects fail-closed (a SuspendSignal
// never legally carries UNSPECIFIED).
//
// USER and REBALANCE are NOT boundary-originated reasons — a user-requested pause
// and a scheduler rebalance do not arrive as a boundary SuspendSignal — so the
// boundary class never maps onto them; they reach Suspend through other call
// paths (a user verb / the scheduler). This map is total over the boundary class
// enum and never silently invents a USER/REBALANCE from a threat class.
func MapSuspendReasonClass(class boundaryv1.SuspendReasonClass) hypervisorv1.SuspendReason {
	switch class {
	case boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_BLOCKLIST_HIT,
		boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_ACTION_SUSPEND_RULE:
		return hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH
	default:
		return hypervisorv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED
	}
}

// SuspendAck is the orchestrator's acknowledgement of a delivered SuspendSignal,
// relayed back to the boundary. It echoes the dedup key (so the boundary correlates
// the ack to the signal) and whether the delivery was the FIRST for that key
// (Accepted) or a collapsed retransmit (Duplicate). Both are acked; only Accepted
// carries a SuspendRequest to drive.
type SuspendAck struct {
	// DedupKey echoes the signal's dedup key (the boundary's correlation handle).
	DedupKey string
	// SessionUUID echoes the suspended session (for the boundary's trace).
	SessionUUID string
	// Duplicate reports whether this delivery was a collapsed retransmit of an
	// already-seen dedup key (an idempotent no-op — no Suspend driven).
	Duplicate bool
}

// SuspendAcceptance is the result of terminating a SuspendSignal: the ack to relay
// and, on the FIRST delivery of a dedup key, the hypervisor.v1.SuspendRequest the
// park/resume driver should drive on the placed host's driver. On a duplicate the
// Request is nil (Ack.Duplicate is true) — the caller acks and does nothing.
type SuspendAcceptance struct {
	// Ack is the acknowledgement to relay to the boundary (always present).
	Ack SuspendAck
	// Request is the hypervisor.v1.SuspendRequest to drive — set ONLY on the first
	// delivery of a dedup key; nil on a duplicate.
	Request *hypervisorv1.SuspendRequest
}

// SuspendSignalTerminator terminates the boundary→orchestrator suspend signal: it
// validates + maps the frozen SuspendSignal into a hypervisor.v1.SuspendRequest
// and dedups re-deliveries by the signal's dedup key. It owns the dedup set (its
// only state) and is safe for concurrent delivery. Construct via
// NewSuspendSignalTerminator.
type SuspendSignalTerminator struct {
	mu   sync.Mutex
	seen map[string]struct{} // dedup keys already terminated
}

// NewSuspendSignalTerminator returns a ready terminator with an empty dedup set.
func NewSuspendSignalTerminator() *SuspendSignalTerminator {
	return &SuspendSignalTerminator{seen: make(map[string]struct{})}
}

// Accept terminates one delivered boundary.v1.SuspendSignal:
//
//  1. VALIDATE the signal fail-closed — a present session ref + non-empty session
//     UUID, a recognized genuine-threat reason class (never UNSPECIFIED), a
//     non-empty dedup key, and POL-3 provenance present (the genuine-threat class
//     always carries it). A defect is *ErrSuspendSignalInvalid (no dedup entry
//     recorded — a malformed signal is not "seen", so a corrected retransmit under
//     the same key still terminates).
//  2. DEDUP by dedup_key — the FIRST delivery records the key and returns a
//     SuspendRequest to drive (Accepted, Duplicate=false); a RE-delivery of the
//     same key returns Duplicate=true with NO request (the idempotent no-op). The
//     dedup decision happens AFTER validation, so a duplicate is only a duplicate
//     of a previously-VALID delivery.
//  3. MAP the D77 class onto hypervisor.v1.SuspendReason (POLICY_BREACH for the two
//     genuine-threat classes) and CARRY the POL-3 provenance into the
//     SuspendRequest as the boundary.v1.Provenance the message imports (REQUIRED
//     for POLICY_BREACH).
//
// Every delivery is ACKED (Acceptance.Ack), duplicate or not.
func (t *SuspendSignalTerminator) Accept(sig *boundaryv1.SuspendSignal) (SuspendAcceptance, error) {
	if sig == nil {
		return SuspendAcceptance{}, &ErrSuspendSignalInvalid{msg: "nil signal"}
	}
	ref := sig.GetSession()
	if ref == nil || ref.GetSessionUuid() == "" {
		return SuspendAcceptance{}, &ErrSuspendSignalInvalid{msg: "missing session ref / session_uuid"}
	}
	sessionUUID := ref.GetSessionUuid()

	dedupKey := sig.GetDedupKey()
	if dedupKey == "" {
		return SuspendAcceptance{}, &ErrSuspendSignalInvalid{msg: fmt.Sprintf("empty dedup_key (session %s) — the orchestrator cannot collapse retransmits without it", sessionUUID)}
	}

	reason := MapSuspendReasonClass(sig.GetReasonClass())
	if reason == hypervisorv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED {
		return SuspendAcceptance{}, &ErrSuspendSignalInvalid{msg: fmt.Sprintf("unspecified/unrecognized reason class %v (session %s) — a SuspendSignal only fires on a genuine-threat class", sig.GetReasonClass(), sessionUUID)}
	}

	// POL-3 provenance is REQUIRED for POLICY_BREACH (the SuspendRequest's contract).
	// A genuine-threat signal always carries a matched rule; a signal with no
	// matched rule id cannot answer "why was this suspended?" and is rejected.
	prov := provenanceFromSignal(sig)
	if reason == hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH && prov == nil {
		return SuspendAcceptance{}, &ErrSuspendSignalInvalid{msg: fmt.Sprintf("POLICY_BREACH suspend for session %s carries no POL-3 provenance (matched_rule_id) — provenance is REQUIRED for POLICY_BREACH (fail-closed)", sessionUUID)}
	}

	t.mu.Lock()
	_, dup := t.seen[dedupKey]
	if !dup {
		t.seen[dedupKey] = struct{}{}
	}
	t.mu.Unlock()

	ack := SuspendAck{DedupKey: dedupKey, SessionUUID: sessionUUID, Duplicate: dup}
	if dup {
		// Collapsed retransmit: ack, drive nothing (the idempotent no-op).
		return SuspendAcceptance{Ack: ack}, nil
	}

	req := &hypervisorv1.SuspendRequest{
		SessionUuid: sessionUUID,
		Reason:      reason,
		Provenance:  prov,
	}
	return SuspendAcceptance{Ack: ack, Request: req}, nil
}

// Seen reports whether a dedup key has already been terminated (a re-delivery
// would be a no-op). For the park/resume driver's trace and tests; never a gate.
func (t *SuspendSignalTerminator) Seen(dedupKey string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, ok := t.seen[dedupKey]
	return ok
}

// provenanceFromSignal lifts the SuspendSignal's flattened POL-3 fields
// (matched_rule_id / policy_layer / policy_version) into the boundary.v1.Provenance
// struct the hypervisor.v1.SuspendRequest imports. It returns nil when the signal
// carries NO matched rule id (no provenance to answer "why") — the genuine-threat
// class then fails the required-provenance check; a USER/REBALANCE path (which
// never arrives here) would leave Provenance UNSET. The layer/version travel even
// when only the rule id is the load-bearing identifier.
func provenanceFromSignal(sig *boundaryv1.SuspendSignal) *boundaryv1.Provenance {
	if sig.GetMatchedRuleId() == "" {
		return nil
	}
	return &boundaryv1.Provenance{
		RuleId:        sig.GetMatchedRuleId(),
		PolicyLayer:   sig.GetPolicyLayer(),
		PolicyVersion: sig.GetPolicyVersion(),
	}
}
