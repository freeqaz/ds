// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"errors"
	"sync"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
	hypervisorv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/hypervisor/v1"
)

func blocklistSignal(sessionUUID, dedupKey string) *boundaryv1.SuspendSignal {
	return &boundaryv1.SuspendSignal{
		Session:         &boundaryv1.SessionRef{SessionUuid: sessionUUID},
		ReasonClass:     boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_BLOCKLIST_HIT,
		BlocklistSource: boundaryv1.BlocklistSource_BLOCKLIST_SOURCE_THREAT_INTEL,
		MatchedRuleId:   "rule-42",
		PolicyLayer:     "org",
		PolicyVersion:   7,
		DedupKey:        dedupKey,
	}
}

// TestMapSuspendReasonClass: both genuine-threat classes map to hypervisor
// POLICY_BREACH (D77 narrowing); UNSPECIFIED maps to UNSPECIFIED.
func TestMapSuspendReasonClass(t *testing.T) {
	cases := []struct {
		in   boundaryv1.SuspendReasonClass
		want hypervisorv1.SuspendReason
	}{
		{boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_BLOCKLIST_HIT, hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH},
		{boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_ACTION_SUSPEND_RULE, hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH},
		{boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_UNSPECIFIED, hypervisorv1.SuspendReason_SUSPEND_REASON_UNSPECIFIED},
	}
	for _, tc := range cases {
		if got := MapSuspendReasonClass(tc.in); got != tc.want {
			t.Fatalf("MapSuspendReasonClass(%v)=%v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestAcceptMapsReasonAndCarriesProvenance: a BLOCKLIST_HIT signal terminates to a
// POLICY_BREACH SuspendRequest carrying the POL-3 provenance lifted from the flattened
// signal fields.
func TestAcceptMapsReasonAndCarriesProvenance(t *testing.T) {
	term := NewSuspendSignalTerminator()
	acc, err := term.Accept(blocklistSignal("sess-1", "dedup-1"))
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if acc.Request == nil {
		t.Fatal("first delivery must carry a SuspendRequest")
	}
	if acc.Ack.Duplicate {
		t.Fatal("first delivery must not be a duplicate")
	}
	if acc.Request.GetReason() != hypervisorv1.SuspendReason_SUSPEND_REASON_POLICY_BREACH {
		t.Fatalf("reason=%v, want POLICY_BREACH", acc.Request.GetReason())
	}
	if acc.Request.GetSessionUuid() != "sess-1" {
		t.Fatalf("session=%q", acc.Request.GetSessionUuid())
	}
	prov := acc.Request.GetProvenance()
	if prov == nil {
		t.Fatal("POLICY_BREACH request must carry POL-3 provenance")
	}
	if prov.GetRuleId() != "rule-42" || prov.GetPolicyLayer() != "org" || prov.GetPolicyVersion() != 7 {
		t.Fatalf("provenance not lifted from signal: %+v", prov)
	}
	if acc.Ack.DedupKey != "dedup-1" || acc.Ack.SessionUUID != "sess-1" {
		t.Fatalf("ack does not echo signal: %+v", acc.Ack)
	}
}

// TestAcceptDedupIdempotency: a re-delivered signal under the same dedup key is an
// idempotent no-op — acked, but NO SuspendRequest to drive (one threat, one Suspend).
func TestAcceptDedupIdempotency(t *testing.T) {
	term := NewSuspendSignalTerminator()
	first, err := term.Accept(blocklistSignal("sess-1", "dedup-1"))
	if err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	if first.Request == nil {
		t.Fatal("first delivery must produce a request")
	}
	if !term.Seen("dedup-1") {
		t.Fatal("dedup key should be recorded after first accept")
	}

	// Re-deliver the SAME dedup key (even with a different rule id — the dedup key is
	// authoritative; the boundary collapses retransmits of one triggering event).
	redeliver := blocklistSignal("sess-1", "dedup-1")
	redeliver.MatchedRuleId = "rule-99"
	second, err := term.Accept(redeliver)
	if err != nil {
		t.Fatalf("re-delivery Accept: %v", err)
	}
	if !second.Ack.Duplicate {
		t.Fatal("re-delivery must be acked as a duplicate")
	}
	if second.Request != nil {
		t.Fatal("re-delivery must NOT produce a second SuspendRequest (idempotent no-op)")
	}
}

// TestAcceptDistinctKeysEachDrive: two distinct dedup keys each drive a Suspend.
func TestAcceptDistinctKeysEachDrive(t *testing.T) {
	term := NewSuspendSignalTerminator()
	a, _ := term.Accept(blocklistSignal("sess-1", "key-a"))
	b, _ := term.Accept(blocklistSignal("sess-1", "key-b"))
	if a.Request == nil || b.Request == nil {
		t.Fatal("distinct dedup keys must each drive a Suspend")
	}
	if a.Ack.Duplicate || b.Ack.Duplicate {
		t.Fatal("distinct keys are never duplicates")
	}
}

// TestAcceptProvenanceRequiredOnPolicyBreach: a genuine-threat (POLICY_BREACH) signal
// with NO matched rule id (no provenance) is a fail-closed reject — and is NOT recorded
// in the dedup set, so a corrected retransmit under the same key still terminates.
func TestAcceptProvenanceRequiredOnPolicyBreach(t *testing.T) {
	term := NewSuspendSignalTerminator()
	bad := blocklistSignal("sess-1", "dedup-x")
	bad.MatchedRuleId = "" // no provenance
	_, err := term.Accept(bad)
	var invalid *ErrSuspendSignalInvalid
	if !errors.As(err, &invalid) {
		t.Fatalf("expected ErrSuspendSignalInvalid for missing provenance, got %v", err)
	}
	if term.Seen("dedup-x") {
		t.Fatal("a rejected signal must NOT be recorded in the dedup set")
	}
	// A corrected retransmit under the same key terminates (not collapsed as a dup).
	good := blocklistSignal("sess-1", "dedup-x")
	acc, err := term.Accept(good)
	if err != nil {
		t.Fatalf("corrected retransmit: %v", err)
	}
	if acc.Request == nil || acc.Ack.Duplicate {
		t.Fatal("corrected retransmit must terminate as a first delivery")
	}
}

// TestAcceptRejectsStructuralDefects: nil signal, missing session ref, empty dedup
// key, and an unspecified reason class are all fail-closed rejects.
func TestAcceptRejectsStructuralDefects(t *testing.T) {
	term := NewSuspendSignalTerminator()
	cases := []struct {
		name string
		sig  *boundaryv1.SuspendSignal
	}{
		{"nil", nil},
		{"no session ref", &boundaryv1.SuspendSignal{ReasonClass: boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_BLOCKLIST_HIT, MatchedRuleId: "r", DedupKey: "k"}},
		{"empty session uuid", &boundaryv1.SuspendSignal{Session: &boundaryv1.SessionRef{}, ReasonClass: boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_BLOCKLIST_HIT, MatchedRuleId: "r", DedupKey: "k"}},
		{"empty dedup key", &boundaryv1.SuspendSignal{Session: &boundaryv1.SessionRef{SessionUuid: "s"}, ReasonClass: boundaryv1.SuspendReasonClass_SUSPEND_REASON_CLASS_BLOCKLIST_HIT, MatchedRuleId: "r"}},
		{"unspecified reason class", &boundaryv1.SuspendSignal{Session: &boundaryv1.SessionRef{SessionUuid: "s"}, MatchedRuleId: "r", DedupKey: "k"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := term.Accept(tc.sig)
			var invalid *ErrSuspendSignalInvalid
			if !errors.As(err, &invalid) {
				t.Fatalf("expected ErrSuspendSignalInvalid, got %v", err)
			}
		})
	}
}

// TestAcceptConcurrentDedup: concurrent delivery of the same key produces exactly ONE
// request across all goroutines (the dedup set is the single mutable state, guarded).
func TestAcceptConcurrentDedup(t *testing.T) {
	term := NewSuspendSignalTerminator()
	const n = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	requests := 0
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			acc, err := term.Accept(blocklistSignal("sess-1", "race-key"))
			if err != nil {
				t.Errorf("Accept: %v", err)
				return
			}
			if acc.Request != nil {
				mu.Lock()
				requests++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if requests != 1 {
		t.Fatalf("concurrent same-key delivery produced %d requests, want exactly 1", requests)
	}
}
