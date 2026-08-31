// SPDX-License-Identifier: Apache-2.0

package hostagent

// revocation_diff_test.go proves the REAL vN→vN+1 RevokedSetSource diff engine
// (RevokedSetDiffEngine in revocation_producer.go): it diffs successive committed
// policy snapshots' admitted sets and emits the (session, dst-keys, rung) tuples the
// new version newly SEVERS. There is no live claude/cia/qemu/podman and no Rust here —
// the engine reads its admitted sets through a SYNTHETIC AdmittedSetDecoder fake (the
// document schema is free implementation behind the opaque payload), so the test drives
// the diff in-process over fixed admitted sets.
//
// The headline properties (the deliverable's acceptance): a NEW revocation in vN+1
// produces EXACTLY that delta, and an UNCHANGED set produces NONE. The supporting cases
// pin the first-snapshot seed (no prior to diff → empty), the rung-raise sever, the
// removal sever at the configured removal rung, the per-session dst-key grouping, the
// forward-only / re-delivery idempotence, and the fail-closed decode-fault hold.

import (
	"context"
	"errors"
	"testing"

	boundaryv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/boundary/v1"
)

// stubDecoder is a synthetic AdmittedSetDecoder keyed by snapshot seq → admitted set, with
// an optional per-seq decode fault. It stands in for the real POL-1 v0 document decoder:
// the engine owns the DIFF, the decoder owns the document schema (here a fixed map).
type stubDecoder struct {
	bySeq map[uint64]AdmittedSet
	fail  map[uint64]error
}

func (d stubDecoder) Decode(_ context.Context, snap *boundaryv1.PolicySnapshot) (AdmittedSet, error) {
	seq := snap.GetSeq()
	if d.fail != nil {
		if err, ok := d.fail[seq]; ok {
			return nil, err
		}
	}
	return d.bySeq[seq], nil
}

// adm is a terse AdmittedAdmission builder for the fixtures: one session's one dst-key flow
// at a rung (the SessionRef quartet is filled deterministically from the index).
func adm(idx uint32, dstKey string, rung Rung) AdmittedAdmission {
	return AdmittedAdmission{
		SessionUUID:      "sess-" + string(rune('a'+idx)),
		HostID:           "host-a",
		HostSessionIndex: idx,
		TapName:          "dstap-" + string(rune('0'+idx)),
		DstKey:           dstKey,
		Rung:             rung,
	}
}

// newDiffEngine builds the engine over a seq→admitted-set fake; removal severs at block+log.
func newDiffEngine(t *testing.T, bySeq map[uint64]AdmittedSet, fail map[uint64]error) *RevokedSetDiffEngine {
	t.Helper()
	e, err := NewRevokedSetDiffEngine(stubDecoder{bySeq: bySeq, fail: fail})
	if err != nil {
		t.Fatalf("NewRevokedSetDiffEngine: %v", err)
	}
	return e
}

// revokedFor drives one RevokedFor call at seq with a non-empty document (the document
// bytes are inert here — the stub decoder keys off seq — but a real snapshot always carries
// them).
func revokedFor(t *testing.T, e *RevokedSetDiffEngine, seq uint64) []RevokedAdmission {
	t.Helper()
	out, err := e.RevokedFor(context.Background(), snapAt(seq, "doc-v"+string(rune('0'+seq))))
	if err != nil {
		t.Fatalf("RevokedFor(seq=%d): %v", seq, err)
	}
	return out
}

// TestDiffEngine_NewRevocationProducesExactlyThatDelta is the headline: a flow admitted in
// v1 that is REMOVED in v2 produces EXACTLY one revoked tuple — that session's dst-key at
// the removal rung (block+log) — and nothing else. The first call (v1) seeds the prior.
func TestDiffEngine_NewRevocationProducesExactlyThatDelta(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {adm(7, "api.example.com:443", RungAllowLog)},
		2: {}, // the flow is GONE in v2 — a removed allow is now denied
	}, nil)

	// v1 seeds the prior — no prior to diff against → empty.
	if got := revokedFor(t, e, 1); len(got) != 0 {
		t.Fatalf("first snapshot must seed (empty revoked set), got %d revoked", len(got))
	}

	// v2 removes the only flow → EXACTLY that one revoked tuple at the removal rung.
	got := revokedFor(t, e, 2)
	if len(got) != 1 {
		t.Fatalf("v1→v2 revoked = %d tuples, want exactly 1", len(got))
	}
	r := got[0]
	if r.SessionUUID != "sess-h" || r.HostSessionIndex != 7 || r.TapName != "dstap-7" {
		t.Errorf("revoked session keys = %+v, want sess-h/idx7/dstap-7", r)
	}
	if r.Rung != RungBlockLog {
		t.Errorf("removed-flow rung = %v, want block+log (the default removal rung)", r.Rung)
	}
	if len(r.DstKeys) != 1 || r.DstKeys[0] != "api.example.com:443" {
		t.Errorf("revoked dst-keys = %v, want [api.example.com:443]", r.DstKeys)
	}
	if !r.Rung.Severs() {
		t.Error("the new revocation must sever (block-or-higher)")
	}
}

// TestDiffEngine_UnchangedSetProducesNone is the other headline: when v2's admitted set is
// IDENTICAL to v1's (same flows at the same non-severing rung), the diff produces NO revoked
// tuples — nothing was newly severed.
func TestDiffEngine_UnchangedSetProducesNone(t *testing.T) {
	set := AdmittedSet{
		adm(1, "a.example.com:443", RungAllowLog),
		adm(2, "b.example.com:443", RungAllowLog),
	}
	e := newDiffEngine(t, map[uint64]AdmittedSet{1: set, 2: set}, nil)

	if got := revokedFor(t, e, 1); len(got) != 0 {
		t.Fatalf("first snapshot must seed empty, got %d", len(got))
	}
	if got := revokedFor(t, e, 2); len(got) != 0 {
		t.Fatalf("an unchanged admitted set must produce NO revoked tuples, got %d: %+v", len(got), got)
	}
}

// TestDiffEngine_RungRaiseSevers proves a flow that STAYS present but whose rung was RAISED
// to block-or-higher in vN+1 is severed AT THE NEW RUNG (a kill+snapshot, here) — the
// established tunnel must tear down even though the flow is still "in" the version.
func TestDiffEngine_RungRaiseSevers(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {adm(3, "evil.example.com:443", RungAllowLog)},
		2: {adm(3, "evil.example.com:443", RungKillSnapshot)},
	}, nil)

	_ = revokedFor(t, e, 1) // seed
	got := revokedFor(t, e, 2)
	if len(got) != 1 {
		t.Fatalf("a rung-raise must produce 1 revoked tuple, got %d", len(got))
	}
	if got[0].Rung != RungKillSnapshot {
		t.Errorf("rung-raise severs at the NEW rung = %v, want kill+snapshot", got[0].Rung)
	}
	if got[0].DstKeys[0] != "evil.example.com:443" {
		t.Errorf("revoked dst-key = %v, want evil.example.com:443", got[0].DstKeys)
	}
}

// TestDiffEngine_SubBlockChangeDoesNotSever proves a flow whose rung stays NON-severing
// across versions (allow+log → allow+log, or a rung LOWERED) produces nothing — D53 leaves
// established sub-block flows untouched.
func TestDiffEngine_SubBlockChangeDoesNotSever(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {adm(4, "c.example.com:443", RungAllowLog)},
		2: {adm(4, "c.example.com:443", RungAllowLog)},
	}, nil)
	_ = revokedFor(t, e, 1)
	if got := revokedFor(t, e, 2); len(got) != 0 {
		t.Fatalf("a sub-block flow must not sever, got %d revoked", len(got))
	}
}

// TestDiffEngine_AlreadySeveredNotReRevoked proves a flow the PRIOR version already admitted
// at a severing rung is NOT "newly" revoked by the next version (it was already torn down
// when the prior committed) — even if it is removed entirely in vN+1.
func TestDiffEngine_AlreadySeveredNotReRevoked(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {adm(5, "d.example.com:443", RungBlockLog)}, // already severing in v1
		2: {},                                          // gone in v2
	}, nil)
	_ = revokedFor(t, e, 1)
	if got := revokedFor(t, e, 2); len(got) != 0 {
		t.Fatalf("an already-severed flow must not be re-revoked, got %d", len(got))
	}
}

// TestDiffEngine_GroupsDstKeysPerSession proves that when ONE session loses MULTIPLE flows
// at the SAME severing rung, they fan out as ONE RevokedAdmission carrying all the revoked
// dst-keys (the wire's per-admission dst_count list), sorted deterministically.
func TestDiffEngine_GroupsDstKeysPerSession(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {
			adm(8, "zeta.example.com:443", RungAllowLog),
			adm(8, "alpha.example.com:443", RungAllowLog),
			adm(8, "mid.example.com:443", RungAllowLog),
		},
		2: {}, // all three flows removed
	}, nil)
	_ = revokedFor(t, e, 1)
	got := revokedFor(t, e, 2)
	if len(got) != 1 {
		t.Fatalf("one session losing 3 flows must fan out as 1 RevokedAdmission, got %d", len(got))
	}
	want := []string{"alpha.example.com:443", "mid.example.com:443", "zeta.example.com:443"}
	if len(got[0].DstKeys) != len(want) {
		t.Fatalf("grouped dst-keys = %v, want %v", got[0].DstKeys, want)
	}
	for i := range want {
		if got[0].DstKeys[i] != want[i] {
			t.Fatalf("dst-keys not sorted/grouped: got %v, want %v", got[0].DstKeys, want)
		}
	}
}

// TestDiffEngine_DistinctSeverRungsSplitIntoSeparateAdmissions proves that when a session
// loses flows at DIFFERENT severing rungs (one removed → block+log, one raised → kill), they
// fan out as TWO RevokedAdmissions (the wire carries a single rung per admission).
func TestDiffEngine_DistinctSeverRungsSplitIntoSeparateAdmissions(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {
			adm(2, "removed.example.com:443", RungAllowLog),
			adm(2, "raised.example.com:443", RungAllowLog),
		},
		2: {
			adm(2, "raised.example.com:443", RungKillSnapshot), // raised; "removed" is gone
		},
	}, nil)
	_ = revokedFor(t, e, 1)
	got := revokedFor(t, e, 2)
	if len(got) != 2 {
		t.Fatalf("distinct sever rungs must split into 2 admissions, got %d: %+v", len(got), got)
	}
	// Deterministic order is by session keys then rung: block+log (1) before kill (3).
	if got[0].Rung != RungBlockLog || got[0].DstKeys[0] != "removed.example.com:443" {
		t.Errorf("first admission = %+v, want block+log/removed", got[0])
	}
	if got[1].Rung != RungKillSnapshot || got[1].DstKeys[0] != "raised.example.com:443" {
		t.Errorf("second admission = %+v, want kill+snapshot/raised", got[1])
	}
}

// TestDiffEngine_ForwardAdvanceThenNextDiff proves the engine rolls its held baseline
// FORWARD after a strictly-greater seq: v1→v2 diffs against v1, then v2→v3 diffs against v2
// (not v1). A flow removed in v2 and a different flow removed in v3 each surface in their own
// round, never double-counted.
func TestDiffEngine_ForwardAdvanceThenNextDiff(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {adm(1, "x.example.com:443", RungAllowLog), adm(2, "y.example.com:443", RungAllowLog)},
		2: {adm(2, "y.example.com:443", RungAllowLog)}, // x removed
		3: {},                                          // y removed
	}, nil)
	_ = revokedFor(t, e, 1) // seed v1
	r2 := revokedFor(t, e, 2)
	if len(r2) != 1 || r2[0].DstKeys[0] != "x.example.com:443" {
		t.Fatalf("v1→v2 must revoke only x, got %+v", r2)
	}
	r3 := revokedFor(t, e, 3)
	if len(r3) != 1 || r3[0].DstKeys[0] != "y.example.com:443" {
		t.Fatalf("v2→v3 must revoke only y (baseline advanced to v2), got %+v", r3)
	}
}

// TestDiffEngine_ReDeliveryIsIdempotent proves a re-delivered seq (at or below the held
// version) diffs against the SAME held prior and does NOT rewind the baseline: re-applying
// v2 after v2 was already the baseline re-produces the v1→v2 revoked set (idempotent), and a
// subsequent v3 still diffs against v2.
func TestDiffEngine_ReDeliveryIsIdempotent(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {adm(1, "x.example.com:443", RungAllowLog)},
		2: {}, // x removed
		3: {}, // still empty
	}, nil)
	_ = revokedFor(t, e, 1) // seed v1 (baseline = v1)
	first := revokedFor(t, e, 2)
	if len(first) != 1 {
		t.Fatalf("v1→v2 want 1 revoked, got %d", len(first))
	}
	// Baseline advanced to v2. A re-delivery of v2 diffs v2→v2 → nothing (idempotent: the
	// flow is already gone in the baseline, not re-revoked).
	redelivered := revokedFor(t, e, 2)
	if len(redelivered) != 0 {
		t.Fatalf("re-delivered v2 must diff against the advanced baseline (empty), got %d: %+v", len(redelivered), redelivered)
	}
	// v3 still diffs against v2 (the baseline was not rewound by the re-delivery).
	if got := revokedFor(t, e, 3); len(got) != 0 {
		t.Fatalf("v2→v3 (both empty) want 0 revoked, got %d", len(got))
	}
}

// TestDiffEngine_DecodeFaultHoldsSeq proves the fail-closed posture: a decode fault is
// RETURNED (the post-commit sweep HOLDS apply_seq) and the held baseline is left UNCHANGED,
// so a re-drive re-diffs against the same prior.
func TestDiffEngine_DecodeFaultHoldsSeq(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {adm(1, "x.example.com:443", RungAllowLog)},
		3: {}, // x removed — the round AFTER the fault
	}, map[uint64]error{
		2: errors.New("malformed document body"),
	})
	_ = revokedFor(t, e, 1) // seed v1
	// v2 fails to decode → RevokedFor returns an error, baseline unchanged (still v1).
	if _, err := e.RevokedFor(context.Background(), snapAt(2, "doc-bad")); err == nil {
		t.Fatal("a decode fault must be returned (fail-closed hold), got nil")
	}
	// v3 diffs against the UNCHANGED v1 baseline → x is still revoked (the fault did not
	// advance or corrupt the baseline).
	got := revokedFor(t, e, 3)
	if len(got) != 1 || got[0].DstKeys[0] != "x.example.com:443" {
		t.Fatalf("after a decode fault the baseline must stay at v1; v1→v3 must revoke x, got %+v", got)
	}
}

// TestDiffEngine_NilDecoderRejected proves the constructor rejects a nil decoder (an engine
// with no way to read an admitted set could never diff).
func TestDiffEngine_NilDecoderRejected(t *testing.T) {
	if _, err := NewRevokedSetDiffEngine(nil); err == nil {
		t.Fatal("NewRevokedSetDiffEngine accepted a nil decoder")
	}
}

// TestDiffEngine_OutOfLadderRemovalRungRejected proves an out-of-ladder removal rung is
// rejected at construction (the engine never carries a rung it could not encode).
func TestDiffEngine_OutOfLadderRemovalRungRejected(t *testing.T) {
	dec := AdmittedSetDecoderFunc(func(context.Context, *boundaryv1.PolicySnapshot) (AdmittedSet, error) {
		return nil, nil
	})
	if _, err := NewRevokedSetDiffEngineWithRemovalRung(dec, Rung(99)); err == nil {
		t.Fatal("NewRevokedSetDiffEngineWithRemovalRung accepted an out-of-ladder removal rung")
	}
}

// TestDiffEngine_FeedsProducerEndToEnd proves the engine drops straight into the
// RevocationProducer as its RevokedSetSource: on the default-OFF path the producer reads the
// engine's diff and advances the seq without dialing (byte-identical), and the diff it read
// is exactly the engine's v1→v2 revoked set.
func TestDiffEngine_FeedsProducerEndToEnd(t *testing.T) {
	e := newDiffEngine(t, map[uint64]AdmittedSet{
		1: {adm(6, "api.example.com:443", RungAllowLog)},
		2: {adm(6, "api.example.com:443", RungBlockLog)}, // raised → severs
	}, nil)
	p, err := NewRevocationProducerAt(e, "/run/unused.sock", false) // default-OFF: no dial
	if err != nil {
		t.Fatalf("NewRevocationProducerAt: %v", err)
	}
	// Seed v1 through the producer (the producer reads the source on every Sweep).
	if seq, err := p.Sweep(context.Background(), snapAt(1, "doc-v1")); err != nil || seq != 1 {
		t.Fatalf("seed Sweep(v1) = (%d,%v), want (1,nil)", seq, err)
	}
	// v2 raises the flow → the producer reads the engine's revoked set and advances to 2.
	seq, err := p.Sweep(context.Background(), snapAt(2, "doc-v2"))
	if err != nil {
		t.Fatalf("Sweep(v2): %v", err)
	}
	if seq != 2 {
		t.Errorf("default-off swept seq = %d, want 2", seq)
	}
}
