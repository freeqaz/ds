package policylog

// Tests for the orchestrator-side fleet-digest PolicySink satisfier
// (fleetdigestsink.go). They drive the adapter against the REAL in-memory store
// fan-out (store.Memory's AppendPolicy/ListPolicy) and synthetic DigestEntry
// fixtures — no live host, no proto edit (D50; doc 16 §6.2/§9). They assert: the
// register→revoke round-trip lands ordered fleet-digest artifacts on the
// policy_log under monotonic seqs; the artifact is classified FleetDigestKind so
// the composer/sweep can find it without parsing the body; the payload is
// order-stable (D73 content-id); and the fail-closed shape holds (empty key id,
// nil/mis-scoped entry, store error → non-committed, nothing live).

import (
	"context"
	"errors"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// digestPolicySink restates identity/digest.PolicySink's method set EXACTLY (the
// orchestrator tree may not import identity/digest — the one-shared-module
// import-boundary gate — so this is the in-tree statement of that contract). The
// production satisfier *FleetDigestSink must implement it; the assertion below is
// the wave's "the adapter satisfies digest.PolicySink" acceptance, made over the
// mirrored, byte-for-byte-identical value types.
type digestPolicySink interface {
	AppendFleetDigest(ctx context.Context, art FleetDigestArtifact) (FleetDigestResult, error)
}

// compile-time: the adapter satisfies the digest.PolicySink-equivalent contract.
var _ digestPolicySink = (*FleetDigestSink)(nil)

// fleetEntry builds a synthetic DIGEST_SCOPE_FLEET entry under keyID with the
// given forbidden-class digest bytes. The digest bytes are opaque here (a fleet
// digest is a one-way keyed hash, doc 16 §6.2) — any bytes exercise the framing.
func fleetEntry(keyID string, digestBytes ...byte) *identityv1.DigestEntry {
	return &identityv1.DigestEntry{
		KeyId:  keyID,
		Digest: digestBytes,
		Scope:  identityv1.DigestScope_DIGEST_SCOPE_FLEET,
	}
}

func TestFleetDigestSink_RegisterThenRevoke_OrderedArtifacts(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	sink := NewFleetDigestSink(st, "secteam@dream-serpent")

	// REGISTER: a fleet-scope digest batch under key k1.
	regArt := FleetDigestArtifact{
		KeyID:   "k1",
		Entries: []*identityv1.DigestEntry{fleetEntry("k1", 0xde, 0xad), fleetEntry("k1", 0xbe, 0xef)},
		BatchID: "batch-reg-1",
	}
	regRes, err := sink.AppendFleetDigest(ctx, regArt)
	if err != nil {
		t.Fatalf("register: unexpected error: %v", err)
	}
	if !regRes.Committed {
		t.Fatalf("register: want committed, got %+v", regRes)
	}
	if regRes.Seq == 0 {
		t.Fatalf("register: want store-assigned seq > 0, got %d", regRes.Seq)
	}
	if regRes.KeyID != "k1" || regRes.BatchID != "batch-reg-1" {
		t.Fatalf("register: result provenance mismatch: %+v", regRes)
	}

	// REVOKE: retire k1's fleet digests (empty entry set, doc 16 §6.2). Rides the
	// SAME policy_log seq + the POL-4 sweep — a fresh, ordered append.
	revRes, err := sink.AppendFleetDigest(ctx, FleetDigestArtifact{KeyID: "k1", Entries: nil, BatchID: "batch-rev-1"})
	if err != nil {
		t.Fatalf("revoke: unexpected error: %v", err)
	}
	if !revRes.Committed {
		t.Fatalf("revoke: want committed, got %+v", revRes)
	}
	if revRes.Seq <= regRes.Seq {
		t.Fatalf("revoke: seq must advance past register (POL-4 ordered): reg=%d rev=%d", regRes.Seq, revRes.Seq)
	}

	// The policy_log carries two ordered FleetDigestKind artifacts, in order.
	rows, err := st.ListPolicy(ctx, 0, 0)
	if err != nil {
		t.Fatalf("ListPolicy: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 policy_log rows (register+revoke), got %d", len(rows))
	}
	for i, r := range rows {
		if r.Kind != FleetDigestKind {
			t.Errorf("row %d: kind = %q, want %q (composer/sweep classification)", i, r.Kind, FleetDigestKind)
		}
		if r.Actor != "secteam@dream-serpent" {
			t.Errorf("row %d: actor = %q, want recorded appender (D36 audit trail)", i, r.Actor)
		}
		if r.ContentHash == "" {
			t.Errorf("row %d: empty content hash (snapshot identity component)", i)
		}
		if len(r.Payload) == 0 {
			t.Errorf("row %d: empty payload", i)
		}
	}
	if rows[0].Seq >= rows[1].Seq {
		t.Errorf("seqs not strictly increasing: %d, %d", rows[0].Seq, rows[1].Seq)
	}
	if uint64(rows[0].Seq) != regRes.Seq || uint64(rows[1].Seq) != revRes.Seq {
		t.Errorf("returned seqs disagree with stored rows: reg=%d/%d rev=%d/%d",
			regRes.Seq, rows[0].Seq, revRes.Seq, rows[1].Seq)
	}
}

func TestFleetDigestSink_PayloadIsOrderStable(t *testing.T) {
	// Two artifacts with the SAME entry SET in different ORDER must produce the
	// same content hash (D73: digest-set version is a content id). The adapter
	// sorts the encoded entries before framing.
	e1 := fleetEntry("k1", 0x01, 0x02)
	e2 := fleetEntry("k1", 0x03, 0x04)

	a := FleetDigestArtifact{KeyID: "k1", Entries: []*identityv1.DigestEntry{e1, e2}, BatchID: "b"}
	b := FleetDigestArtifact{KeyID: "k1", Entries: []*identityv1.DigestEntry{e2, e1}, BatchID: "b"}

	pa, err := marshalFleetArtifact(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	pb, err := marshalFleetArtifact(b)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if string(pa) != string(pb) {
		t.Fatalf("entry-order changed the payload bytes (not content-id stable):\n a=%x\n b=%x", pa, pb)
	}

	// A DIFFERENT entry set must differ.
	c := FleetDigestArtifact{KeyID: "k1", Entries: []*identityv1.DigestEntry{e1}, BatchID: "b"}
	pc, err := marshalFleetArtifact(c)
	if err != nil {
		t.Fatalf("marshal c: %v", err)
	}
	if string(pc) == string(pa) {
		t.Fatalf("distinct entry sets produced identical payloads")
	}
}

func TestFleetDigestSink_FailClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("empty key id", func(t *testing.T) {
		st := store.NewMemory()
		sink := NewFleetDigestSink(st, "a")
		res, err := sink.AppendFleetDigest(ctx, FleetDigestArtifact{KeyID: "", BatchID: "b"})
		if !errors.Is(err, ErrEmptyKeyID) {
			t.Fatalf("want ErrEmptyKeyID, got %v", err)
		}
		if res.Committed {
			t.Fatalf("fail-closed: result must not be committed: %+v", res)
		}
		if rows, _ := st.ListPolicy(ctx, 0, 0); len(rows) != 0 {
			t.Fatalf("fail-closed: nothing must be appended, got %d rows", len(rows))
		}
	})

	t.Run("nil entry", func(t *testing.T) {
		st := store.NewMemory()
		sink := NewFleetDigestSink(st, "a")
		res, err := sink.AppendFleetDigest(ctx, FleetDigestArtifact{
			KeyID:   "k1",
			Entries: []*identityv1.DigestEntry{nil},
			BatchID: "b",
		})
		if err == nil {
			t.Fatalf("want error on nil entry")
		}
		if res.Committed {
			t.Fatalf("fail-closed: not committed; got %+v", res)
		}
		if rows, _ := st.ListPolicy(ctx, 0, 0); len(rows) != 0 {
			t.Fatalf("fail-closed: nothing appended, got %d rows", len(rows))
		}
	})

	t.Run("non-fleet scope entry", func(t *testing.T) {
		st := store.NewMemory()
		sink := NewFleetDigestSink(st, "a")
		sessionEntry := &identityv1.DigestEntry{KeyId: "k1", Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION}
		res, err := sink.AppendFleetDigest(ctx, FleetDigestArtifact{
			KeyID:   "k1",
			Entries: []*identityv1.DigestEntry{sessionEntry},
			BatchID: "b",
		})
		if err == nil {
			t.Fatalf("want error: session-scope entry on the fleet path (doc 16 §6.2)")
		}
		if res.Committed {
			t.Fatalf("fail-closed: not committed; got %+v", res)
		}
	})

	t.Run("store append error", func(t *testing.T) {
		sink := NewFleetDigestSink(errAppender{}, "a")
		res, err := sink.AppendFleetDigest(ctx, FleetDigestArtifact{
			KeyID:   "k1",
			Entries: []*identityv1.DigestEntry{fleetEntry("k1", 0x09)},
			BatchID: "b",
		})
		if err == nil {
			t.Fatalf("want propagated store error")
		}
		if res.Committed {
			t.Fatalf("fail-closed: a failed append must not report committed: %+v", res)
		}
		// provenance still echoed so the caller's error log names the artifact.
		if res.KeyID != "k1" || res.BatchID != "b" {
			t.Fatalf("provenance not echoed on failure: %+v", res)
		}
	})

	t.Run("nil sink", func(t *testing.T) {
		var sink *FleetDigestSink
		res, err := sink.AppendFleetDigest(ctx, FleetDigestArtifact{KeyID: "k1"})
		if err == nil {
			t.Fatalf("want error on nil sink")
		}
		if res.Committed {
			t.Fatalf("fail-closed: %+v", res)
		}
	})
}

// errAppender is a policyAppender whose AppendPolicy always fails — exercises the
// adapter's fail-closed propagation without a live store.
type errAppender struct{}

func (errAppender) AppendPolicy(ctx context.Context, row store.PolicyLogRow) (store.PolicyLogRow, error) {
	return store.PolicyLogRow{}, errors.New("synthetic append failure")
}

// TestFleetDigestSink_ServiceIsAppender pins that the live in-process
// PolicyService is a drop-in AppendPolicy seam for the adapter (the production
// fan-out): the adapter composes onto *Service, so a fleet-digest artifact lands
// on the SAME policy_log the one-per-host WatchPolicies subscriber replays.
func TestFleetDigestSink_ServiceIsAppender(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	svc := NewService(st, nil) // composer unused on the append leg
	sink := NewFleetDigestSink(svc, "secteam")

	res, err := sink.AppendFleetDigest(ctx, FleetDigestArtifact{
		KeyID:   "k1",
		Entries: []*identityv1.DigestEntry{fleetEntry("k1", 0xaa)},
		BatchID: "b",
	})
	if err != nil {
		t.Fatalf("append via Service: %v", err)
	}
	if !res.Committed || res.Seq == 0 {
		t.Fatalf("want committed artifact with assigned seq via Service: %+v", res)
	}
	rows, err := st.ListPolicy(ctx, 0, 0)
	if err != nil {
		t.Fatalf("ListPolicy: %v", err)
	}
	if len(rows) != 1 || rows[0].Kind != FleetDigestKind {
		t.Fatalf("want one FleetDigestKind row via Service path, got %+v", rows)
	}
}
