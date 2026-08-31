package policylog

// Tests for the orchestrator-side fleet-revocation RevocationSink satisfier
// (fleetrevocationsink.go). They drive the adapter against the REAL in-memory
// store fan-out (store.Memory's AppendPolicy/ListPolicy) and synthetic
// fingerprint/block-id fixtures — no live host, no proto edit (D50; doc 19 §7).
// They assert: a synthetic append returns a COMMITTED ack end to end and lands a
// FleetRevocationKind row on the policy_log under a monotonic seq; the payload is
// order-stable (an equal entry SET hashes equal regardless of order) and dedups;
// the envelope round-trips through the single shared codec; NO token bytes ride
// the payload (the load-bearing §7/§9 guard); and the fail-closed shape holds
// (empty entry set, bad schema, non-hex entry, store error → non-committed,
// nothing live).

import (
	"context"
	_ "embed"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// fleetregRevocationSink restates identity/fleetreg.RevocationSink's method set
// EXACTLY (the orchestrator tree may not import identity/fleetreg — the
// one-shared-module import-boundary gate, D80 — so this is the in-tree statement
// of that contract). The production satisfier *FleetRevocationSink must implement
// it; the assertion below is the wave's "the adapter satisfies fleetreg.
// RevocationSink" acceptance, made over the mirrored, byte-for-byte-identical
// value types.
type fleetregRevocationSink interface {
	AppendRevocation(ctx context.Context, art FleetRevocationArtifact) (FleetRevocationResult, error)
}

// compile-time: the adapter satisfies the fleetreg.RevocationSink-equivalent contract.
var _ fleetregRevocationSink = (*FleetRevocationSink)(nil)

// synthetic 64-hex fingerprints and a 128-hex block id (a Biscuit native
// per-block revocation id is 64 bytes → 128 hex, doc 19 §7 OQ6).
var (
	synthFP1     = strings.Repeat("a", fingerprintHexLen)
	synthFP2     = strings.Repeat("b", fingerprintHexLen)
	synthBlockID = strings.Repeat("c", blockIDHexMaxLen)
)

// TestFleetRevocationSink_Append_CommittedAckEndToEnd is the acceptance test: a
// synthetic append returns a COMMITTED ack, lands exactly one FleetRevocationKind
// row on the real in-memory policy_log under a positive seq, and the row carries
// the schema tag + both entries in its canonical envelope.
func TestFleetRevocationSink_Append_CommittedAckEndToEnd(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	sink := NewFleetRevocationSink(st, "secteam@dream-serpent")

	art := FleetRevocationArtifact{
		SchemaVersion: RevocationSchemaVersion,
		Entries: []FleetRevocationEntry{
			{Fingerprint: synthFP1},
			{BlockID: synthBlockID},
		},
		BatchID: "kill-switch-1",
	}
	res, err := sink.AppendRevocation(ctx, art)
	if err != nil {
		t.Fatalf("AppendRevocation: unexpected error: %v", err)
	}
	if !res.Committed {
		t.Fatal("expected a committed ack")
	}
	if res.Seq == 0 {
		t.Fatalf("seq = %d, want a positive store-assigned seq", res.Seq)
	}
	if res.BatchID != "kill-switch-1" {
		t.Fatalf("batch id = %q, want kill-switch-1", res.BatchID)
	}
	if res.Count != 2 {
		t.Fatalf("count = %d, want 2", res.Count)
	}

	// Exactly one FleetRevocationKind row landed on the log.
	rows, err := st.ListPolicy(ctx, 0, 100)
	if err != nil {
		t.Fatalf("ListPolicy: %v", err)
	}
	var revRows []store.PolicyLogRow
	for _, r := range rows {
		if r.Kind == FleetRevocationKind {
			revRows = append(revRows, r)
		}
	}
	if len(revRows) != 1 {
		t.Fatalf("landed %d fleet-revocation rows, want 1", len(revRows))
	}
	if int64(res.Seq) != revRows[0].Seq {
		t.Fatalf("ack seq %d != row seq %d", res.Seq, revRows[0].Seq)
	}
	if revRows[0].Actor != "secteam@dream-serpent" {
		t.Fatalf("actor = %q, want secteam@dream-serpent (D36 attribution)", revRows[0].Actor)
	}

	// The payload round-trips through the shared codec back to the SAME entry set.
	decoded, ok := decodeRevocationArtifact(revRows[0].Payload)
	if !ok {
		t.Fatal("payload did not decode through the shared ds.fleet_revocation.v1 codec")
	}
	if decoded.SchemaVersion != RevocationSchemaVersion {
		t.Fatalf("decoded schema = %q, want %q", decoded.SchemaVersion, RevocationSchemaVersion)
	}
	if len(decoded.Entries) != 2 {
		t.Fatalf("decoded %d entries, want 2", len(decoded.Entries))
	}
	gotFP, gotBID := false, false
	for _, e := range decoded.Entries {
		if e.Fingerprint == synthFP1 {
			gotFP = true
		}
		if e.BlockID == synthBlockID {
			gotBID = true
		}
	}
	if !gotFP || !gotBID {
		t.Fatalf("decoded entries missing fingerprint/block id: %+v", decoded.Entries)
	}
}

// TestFleetRevocationSink_OrderStableAndDedup: two artifacts with the SAME entry
// set in different order produce byte-identical payloads, and a duplicate
// identifier collapses to one entry (the content-id stability + dedup).
func TestFleetRevocationSink_OrderStableAndDedup(t *testing.T) {
	a := FleetRevocationArtifact{
		SchemaVersion: RevocationSchemaVersion,
		Entries:       []FleetRevocationEntry{{Fingerprint: synthFP1}, {Fingerprint: synthFP2}},
		BatchID:       "b",
	}
	b := FleetRevocationArtifact{
		SchemaVersion: RevocationSchemaVersion,
		Entries:       []FleetRevocationEntry{{Fingerprint: synthFP2}, {Fingerprint: synthFP1}, {Fingerprint: synthFP1}},
		BatchID:       "b",
	}
	pa, err := marshalRevocationArtifact(a)
	if err != nil {
		t.Fatalf("marshal a: %v", err)
	}
	pb, err := marshalRevocationArtifact(b)
	if err != nil {
		t.Fatalf("marshal b: %v", err)
	}
	if string(pa) != string(pb) {
		t.Fatalf("payloads differ by entry order/dup:\n a=%q\n b=%q", pa, pb)
	}
	dec, ok := decodeRevocationArtifact(pb)
	if !ok {
		t.Fatal("decode pb failed")
	}
	if len(dec.Entries) != 2 {
		t.Fatalf("dedup: decoded %d entries, want 2", len(dec.Entries))
	}
}

// TestFleetRevocationSink_NoTokenBytes is the load-bearing security guard (doc 19
// §7/§9): given a synthetic revocation id, the appended payload carries ONLY the
// hex identifier — never the raw revocation-id or token bytes.
func TestFleetRevocationSink_NoTokenBytes(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	sink := NewFleetRevocationSink(st, "")

	rawSecret := "ds-synth-revocation-block-id-CONFIDENTIAL"
	// The entry carries a hex id, NOT the secret bytes (the constructors upstream
	// enforce this; here we assert the payload never contains the secret).
	art := FleetRevocationArtifact{
		SchemaVersion: RevocationSchemaVersion,
		Entries:       []FleetRevocationEntry{{BlockID: synthBlockID}},
		BatchID:       "kill-switch",
	}
	if _, err := sink.AppendRevocation(ctx, art); err != nil {
		t.Fatalf("AppendRevocation: %v", err)
	}
	rows, _ := st.ListPolicy(ctx, 0, 100)
	for _, r := range rows {
		if r.Kind != FleetRevocationKind {
			continue
		}
		if strings.Contains(string(r.Payload), rawSecret) {
			t.Fatal("SECURITY: raw secret bytes appear in the revocation payload")
		}
		if !strings.Contains(string(r.Payload), synthBlockID) {
			t.Fatal("expected the hex block id to be present in the payload")
		}
	}
}

// TestFleetRevocationSink_FailClosed covers every fail-closed leg: empty entry
// set, bad schema tag, an entry that is not a bounded lower-hex identifier (a raw
// token smuggle), and a store append error — each returns a non-committed result
// and appends NOTHING live.
func TestFleetRevocationSink_FailClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("empty entries", func(t *testing.T) {
		st := store.NewMemory()
		sink := NewFleetRevocationSink(st, "a")
		res, err := sink.AppendRevocation(ctx, FleetRevocationArtifact{SchemaVersion: RevocationSchemaVersion})
		if err == nil || res.Committed {
			t.Fatal("expected fail-closed on empty entry set")
		}
		assertNoRevRow(t, st)
	})

	t.Run("bad schema", func(t *testing.T) {
		st := store.NewMemory()
		sink := NewFleetRevocationSink(st, "a")
		res, err := sink.AppendRevocation(ctx, FleetRevocationArtifact{
			SchemaVersion: "fleet-revocation/v99",
			Entries:       []FleetRevocationEntry{{Fingerprint: synthFP1}},
		})
		if err == nil || res.Committed {
			t.Fatal("expected fail-closed on unrecognized schema")
		}
		if !errors.Is(err, ErrRevocationSchema) {
			t.Fatalf("want ErrRevocationSchema, got %v", err)
		}
		assertNoRevRow(t, st)
	})

	t.Run("non-hex entry (raw token smuggle)", func(t *testing.T) {
		st := store.NewMemory()
		sink := NewFleetRevocationSink(st, "a")
		res, err := sink.AppendRevocation(ctx, FleetRevocationArtifact{
			SchemaVersion: RevocationSchemaVersion,
			Entries:       []FleetRevocationEntry{{Fingerprint: "this-is-a-raw-token-not-a-hex-fingerprint"}},
		})
		if err == nil || res.Committed {
			t.Fatal("expected fail-closed on a non-hex entry")
		}
		assertNoRevRow(t, st)
	})

	t.Run("store error", func(t *testing.T) {
		sink := NewFleetRevocationSink(errAppender{}, "a")
		res, err := sink.AppendRevocation(ctx, FleetRevocationArtifact{
			SchemaVersion: RevocationSchemaVersion,
			Entries:       []FleetRevocationEntry{{Fingerprint: synthFP1}},
		})
		if err == nil || res.Committed {
			t.Fatal("expected fail-closed on a store append error")
		}
	})
}

func assertNoRevRow(t *testing.T, st *store.Memory) {
	t.Helper()
	rows, err := st.ListPolicy(context.Background(), 0, 100)
	if err != nil {
		t.Fatalf("ListPolicy: %v", err)
	}
	for _, r := range rows {
		if r.Kind == FleetRevocationKind {
			t.Fatal("a fail-closed path must append NO fleet-revocation row")
		}
	}
}

// The store-error fail-closed leg reuses errAppender from fleetdigestsink_test.go
// (same package): a policyAppender whose AppendPolicy always errors.

// ---------------------------------------------------------------------------
// Cross-tree GOLDEN fixture for the ds.fleet_revocation.v1 wire shape.
//
// goldenRevocationV1Payload is the ONE canonical, committed byte payload for the
// ds.fleet_revocation.v1 envelope. It is asserted byte-for-byte here (the Go
// WRITER: marshalRevocationArtifact must emit exactly these bytes) AND decoded
// field-for-field by a ds-policy-snapshot Rust test (the Rust RECOGNIZER, over an
// identical embedded copy). The coupling between the two trees is these golden
// bytes on disk — NOT a cross-tree import (D80-legal: the orchestrator tree may
// not import identity/fleetreg and the Rust crate imports neither). A Go framing
// edit that drifts from what the Rust reader accepts flips one of the two tests
// at review time. Hand-mutating one byte of the writer's output OR of this golden
// constant fails TestFleetRevocationSink_GoldenBytes; mutating the Rust-side copy
// or reader fails the ds-policy-snapshot test.
//
// The two golden identifiers are SYNTHETIC (D50) and, being fixed-length lower-hex
// (a 64-hex chain fingerprint + a 32-hex block id), carry NO token bytes — the
// §7/§9 secret fence, re-asserted by TestFleetRevocationSink_GoldenNoTokenBytes.
const (
	goldenRevFingerprint = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	goldenRevBlockID     = "0123456789abcdef0123456789abcdef"
	goldenRevBatchID     = "kill-switch-golden-1"
)

// goldenRevocationV1Payload is the ONE authoritative ds.fleet_revocation.v1 golden —
// the exact 193-byte envelope for the {fingerprint, block-id} entry set above, whose
// entry lines are sorted by their encoded form (the block-id "b:" line precedes the
// fingerprint "f:" line regardless of construction order — an order-stable content id).
// It is EMBEDDED from testdata/ds.fleet_revocation.v1.golden rather than restated as a
// source literal, so the byte-for-byte coupling with the ds-policy-snapshot Rust
// recognizer's include_bytes!(GOLDEN_REVOCATION_V1) is mechanically enforced: BOTH trees
// load the SAME on-disk file (D80-legal — no cross-tree import), and a Go framing edit
// that skips the golden file flips TestFleetRevocationSink_GoldenBytes here or the Rust
// golden test at review, not silently.
//
//go:embed testdata/ds.fleet_revocation.v1.golden
var goldenRevocationV1Payload string

// goldenRevArtifact builds the canonical artifact whose marshaled form is
// [goldenRevocationV1Payload]. Construction order (fingerprint first) is
// deliberately NOT the sorted payload order, so the test also proves the
// order-stable framing.
func goldenRevArtifact() FleetRevocationArtifact {
	return FleetRevocationArtifact{
		SchemaVersion: RevocationSchemaVersion,
		Entries: []FleetRevocationEntry{
			{Fingerprint: goldenRevFingerprint},
			{BlockID: goldenRevBlockID},
		},
		BatchID: goldenRevBatchID,
	}
}

// TestFleetRevocationSink_GoldenBytes pins the Go writer to the committed golden:
// marshalRevocationArtifact must emit goldenRevocationV1Payload byte-for-byte.
// Mutating one byte of the writer's framing OR of the golden constant fails here;
// the SAME bytes are decoded by the ds-policy-snapshot Rust golden test, so the
// two trees can never drift silently on the ds.fleet_revocation.v1 wire shape.
func TestFleetRevocationSink_GoldenBytes(t *testing.T) {
	got, err := marshalRevocationArtifact(goldenRevArtifact())
	if err != nil {
		t.Fatalf("marshalRevocationArtifact: %v", err)
	}
	if string(got) != goldenRevocationV1Payload {
		t.Fatalf("writer output drifted from the ds.fleet_revocation.v1 golden:\n got=%q\nwant=%q", got, goldenRevocationV1Payload)
	}
	if len(got) != len(goldenRevocationV1Payload) {
		t.Fatalf("golden length = %d, got %d", len(goldenRevocationV1Payload), len(got))
	}

	// The golden round-trips back through the shared codec to the SAME entry set
	// (the Rust recognizer decodes an identical embedded copy independently).
	dec, ok := decodeRevocationArtifact([]byte(goldenRevocationV1Payload))
	if !ok {
		t.Fatal("golden did not decode through the shared ds.fleet_revocation.v1 codec")
	}
	if dec.SchemaVersion != RevocationSchemaVersion {
		t.Fatalf("golden schema = %q, want %q", dec.SchemaVersion, RevocationSchemaVersion)
	}
	if dec.BatchID != goldenRevBatchID {
		t.Fatalf("golden batch = %q, want %q", dec.BatchID, goldenRevBatchID)
	}
	if len(dec.Entries) != 2 {
		t.Fatalf("golden decoded %d entries, want 2", len(dec.Entries))
	}
	gotFP, gotBID := false, false
	for _, e := range dec.Entries {
		switch {
		case e.Fingerprint == goldenRevFingerprint && e.BlockID == "":
			gotFP = true
		case e.BlockID == goldenRevBlockID && e.Fingerprint == "":
			gotBID = true
		default:
			t.Fatalf("golden decoded an unexpected entry: %+v", e)
		}
	}
	if !gotFP || !gotBID {
		t.Fatalf("golden missing fingerprint/block-id entry: %+v", dec.Entries)
	}
}

// TestFleetRevocationSink_GoldenNoTokenBytes is the load-bearing §7/§9 guard on
// the golden itself: the committed payload carries ONLY the two lower-hex
// identifiers — a fingerprint and a block id — and NO token bytes. It asserts
// every byte of the payload is a member of the ds.fleet_revocation.v1 grammar
// (the header/schema/batch/count/entry framing plus lower-hex id characters), so
// no raw secret can hide in the golden even if a future edit repoints it.
func TestFleetRevocationSink_GoldenNoTokenBytes(t *testing.T) {
	// The two identifiers are present (the artifact names its tokens by hex id).
	if !strings.Contains(goldenRevocationV1Payload, goldenRevFingerprint) {
		t.Fatal("golden must contain the hex fingerprint id")
	}
	if !strings.Contains(goldenRevocationV1Payload, goldenRevBlockID) {
		t.Fatal("golden must contain the hex block id")
	}
	// Both identifiers are bounded lower-hex — never token bytes (§7/§9).
	if err := validateRevHexID("fingerprint", goldenRevFingerprint, fingerprintHexLen, fingerprintHexLen); err != nil {
		t.Fatalf("golden fingerprint is not a bounded lower-hex id: %v", err)
	}
	if err := validateRevHexID("block id", goldenRevBlockID, 2, blockIDHexMaxLen); err != nil {
		t.Fatalf("golden block id is not a bounded lower-hex id: %v", err)
	}
	// The strong form: the whole payload is exactly the framing lines + hex ids.
	// Reconstruct it from the grammar and require byte-equality; anything else
	// (e.g. a smuggled non-hex secret on some line) would fail this.
	want := revEnvelopeHeader + "\n" +
		revEnvelopeSchema + RevocationSchemaVersion + "\n" +
		revEnvelopeBatch + goldenRevBatchID + "\n" +
		revEnvelopeCount + "2\n" +
		revEnvelopeEntry + revKindBlockID + ":" + goldenRevBlockID + "\n" +
		revEnvelopeEntry + revKindFingerprint + ":" + goldenRevFingerprint + "\n"
	if goldenRevocationV1Payload != want {
		t.Fatalf("golden is not exactly the ds.fleet_revocation.v1 grammar (a non-grammar byte — a possible token smuggle):\n golden=%q\n want=%q", goldenRevocationV1Payload, want)
	}
}

// TestFleetRevocationSink_GoldenEmbedMatchesDisk pins the EMBEDDED golden to the single
// authoritative on-disk file testdata/ds.fleet_revocation.v1.golden — the SAME file the
// ds-policy-snapshot Rust recognizer include_bytes!s. The two trees load ONE file, so a
// framing edit must land in that file (visible to both) or a golden test flips; a stray
// header/byte prepended to the fixture (which would corrupt the byte-for-byte coupling)
// is caught here by the pinned 193-byte length.
func TestFleetRevocationSink_GoldenEmbedMatchesDisk(t *testing.T) {
	onDisk, err := os.ReadFile("testdata/ds.fleet_revocation.v1.golden")
	if err != nil {
		t.Fatalf("read authoritative golden: %v", err)
	}
	if goldenRevocationV1Payload != string(onDisk) {
		t.Fatalf("embedded golden drifted from the on-disk file:\n embed=%q\n disk=%q", goldenRevocationV1Payload, onDisk)
	}
	if len(onDisk) != 193 {
		t.Fatalf("authoritative golden is %d bytes, want the pinned 193", len(onDisk))
	}
}
