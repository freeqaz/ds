// SPDX-License-Identifier: Apache-2.0

package hostagent

// dnsfeed_carrier_test.go is the SYNTHETIC in-process proof of the host agent's
// CROSS-PROCESS PRODUCER half of the LIVE host-local `WatchPolicies(from_seq)` carrier
// (dnsfeed_carrier.go) against the on-the-wire frame contract the dataplane consumer
// (dataplane/services/ds-dnsgate/src/server.rs WatchPoliciesCarrierSource +
// serve_watch_policies_connection) reads. There is no live claude/cia/qemu/podman and
// no Rust here — the test drives the Go producer over a real UDS socket and a
// hand-decoded frame reader that mirrors the Rust consumer's read_watch_frame /
// WatchPoliciesFrame::decode_version, asserting the EXACT bytes-on-the-wire shape:
//
//   - the handshake is the 8-byte big-endian `from_seq` resume cursor;
//   - each version frame body is
//     seq (8B BE) || content_hash_len (4B BE) || content_hash || document_len (4B BE) || document;
//   - the bytes ARE the produce-once transported document + producer-pinned content_hash
//     (snap.GetContentHash()), transported verbatim — never re-serialized;
//   - the replay is FORWARD-ONLY (seq > from_seq), in ascending order, then EOF (§5.3 EOS);
//   - and WriteCommitted's SnapshotReason classification mirrors feedwriter.go
//     (ReasonNone / ReasonSchemaFailure / ReasonContentHashMismatch / forward-only dedup),
//     so a buggy upstream re-fan-out cannot serve a torn or backward version.
//
// snapAt is shared with feedwriter_test.go (same package).

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"path/filepath"
	"testing"
)

// readCarrierFrame reads ONE length-prefixed frame body off the connection — the Go-side
// mirror of the Rust consumer's read_watch_frame (4-byte BE length, then the body). A clean
// io.EOF before the length prefix is the producer's end-of-stream (§5.3).
func readCarrierFrame(t *testing.T, r io.Reader) ([]byte, error) {
	t.Helper()
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > watchFrameMaxBody {
		t.Fatalf("carrier frame length %d over cap %d", n, watchFrameMaxBody)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// decodeCarrierVersion decodes one version-frame body into (seq, content_hash, document) —
// the Go-side mirror of the Rust consumer's WatchPoliciesFrame::decode_version, so this test
// proves the producer's encodeWatchVersion is the exact inverse the dataplane consumer reads.
func decodeCarrierVersion(t *testing.T, body []byte) (uint64, []byte, []byte) {
	t.Helper()
	if len(body) < 8+4 {
		t.Fatalf("version frame too short: %d bytes", len(body))
	}
	seq := binary.BigEndian.Uint64(body[0:8])
	hashLen := binary.BigEndian.Uint32(body[8:12])
	off := 12
	if hashLen != sha256.Size {
		t.Fatalf("content_hash width %d is not the 32-byte SHA-256 width (torn frame)", hashLen)
	}
	if off+int(hashLen) > len(body) {
		t.Fatalf("content_hash field runs past the frame")
	}
	hash := body[off : off+int(hashLen)]
	off += int(hashLen)
	if off+4 > len(body) {
		t.Fatalf("document length field runs past the frame")
	}
	docLen := binary.BigEndian.Uint32(body[off : off+4])
	off += 4
	if off+int(docLen) != len(body) {
		t.Fatalf("document field width %d does not consume the frame exactly (trailing/short)", docLen)
	}
	return seq, hash, body[off : off+int(docLen)]
}

const carrierDoc = "schema_version: pol1/v0\nlayer: session\nposture: standard\n" +
	"dns:\n  boundary_zone: carrier.example.\n"

func TestWatchPoliciesCarrierWriteCommittedClassification(t *testing.T) {
	t.Run("ForwardOnlyBuffersAndAdvancesCursor", func(t *testing.T) {
		c := NewWatchPoliciesCarrier()
		if got := c.Cursor(); got != 0 {
			t.Fatalf("empty carrier cursor = %d, want 0", got)
		}
		reason, err := c.WriteCommitted(snapAt(5, carrierDoc))
		if err != nil || reason != ReasonNone {
			t.Fatalf("clean commit: reason=%v err=%v, want ReasonNone/nil", reason, err)
		}
		if got := c.Cursor(); got != 5 {
			t.Fatalf("cursor after seq 5 = %d, want 5", got)
		}
		reason, err = c.WriteCommitted(snapAt(6, carrierDoc))
		if err != nil || reason != ReasonNone {
			t.Fatalf("seq 6 commit: reason=%v err=%v, want ReasonNone/nil", reason, err)
		}
		if got := c.Cursor(); got != 6 {
			t.Fatalf("cursor after seq 6 = %d, want 6", got)
		}
	})

	t.Run("ForwardOnlyDropDedupIsReasonNoneWithError", func(t *testing.T) {
		c := NewWatchPoliciesCarrier()
		if _, err := c.WriteCommitted(snapAt(5, carrierDoc)); err != nil {
			t.Fatalf("seed seq 5: %v", err)
		}
		// A re-delivered seq 5 and an out-of-order seq 4 are benign forward-only dedups:
		// ReasonNone (not a schema/hash defect) with a non-nil error, buffer unchanged.
		for _, seq := range []uint64{5, 4} {
			reason, err := c.WriteCommitted(snapAt(seq, carrierDoc))
			if reason != ReasonNone {
				t.Fatalf("forward-only drop of seq %d reason = %v, want ReasonNone (benign dedup)", seq, reason)
			}
			if err == nil {
				t.Fatalf("forward-only drop of seq %d wanted a non-nil benign-dedup error", seq)
			}
		}
		if got := c.Cursor(); got != 5 {
			t.Fatalf("cursor unchanged after dedup drops = %d, want 5", got)
		}
	})

	t.Run("NoDocumentIsSchemaFailureNotBuffered", func(t *testing.T) {
		c := NewWatchPoliciesCarrier()
		reason, err := c.WriteCommitted(snapAt(7, "")) // empty document
		if reason != ReasonSchemaFailure || err == nil {
			t.Fatalf("empty-document commit: reason=%v err=%v, want ReasonSchemaFailure/non-nil", reason, err)
		}
		if got := c.Cursor(); got != 0 {
			t.Fatalf("schema-failure must NOT buffer: cursor = %d, want 0", got)
		}
	})

	t.Run("NilSnapshotIsSchemaFailure", func(t *testing.T) {
		c := NewWatchPoliciesCarrier()
		reason, err := c.WriteCommitted(nil)
		if reason != ReasonSchemaFailure || err == nil {
			t.Fatalf("nil snapshot: reason=%v err=%v, want ReasonSchemaFailure/non-nil", reason, err)
		}
	})

	t.Run("PresentButWrongContentHashIsTornCarrierNotBuffered", func(t *testing.T) {
		c := NewWatchPoliciesCarrier()
		// A PRESENT-but-WRONG producer-pinned content_hash (a torn carrier, D120): the
		// producer-side honesty guard mirrors feedwriter.go and refuses to BUFFER it, so the
		// consumer's verify-before-parse gate never sees a torn on-the-wire frame.
		good := snapAt(8, carrierDoc)
		good.ContentHash = make([]byte, sha256.Size) // all-zero != sha256(carrierDoc)
		reason, err := c.WriteCommitted(good)
		if reason != ReasonContentHashMismatch || err == nil {
			t.Fatalf("torn carrier: reason=%v err=%v, want ReasonContentHashMismatch/non-nil", reason, err)
		}
		if got := c.Cursor(); got != 0 {
			t.Fatalf("torn carrier must NOT buffer: cursor = %d, want 0", got)
		}
	})
}

func TestWatchPoliciesCarrierServesForwardOnlyStream(t *testing.T) {
	// The producer SERVES a real UDS: a dialing consumer sends the WatchPolicies(from_seq)
	// handshake, the producer replays the buffered versions with seq > from_seq in ascending
	// order as frames, then closes (EOF). The bytes are the produce-once document +
	// producer-pinned content_hash, transported verbatim. A hand-decoded reader mirroring the
	// Rust consumer's frame codec proves the cross-process wire shape — no live host agent.
	c := NewWatchPoliciesCarrier()
	for _, seq := range []uint64{1, 2, 3} {
		if _, err := c.WriteCommitted(snapAt(seq, carrierDoc)); err != nil {
			t.Fatalf("seed seq %d: %v", seq, err)
		}
	}

	dir := t.TempDir()
	sock := filepath.Join(dir, "watch.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("bind carrier UDS: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- c.Serve(ctx, listener) }()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial carrier UDS: %v", err)
	}
	defer conn.Close()

	// Handshake: from_seq=1 → the consumer must see seq 2 and 3 only (forward-only).
	var fromSeq [8]byte
	binary.BigEndian.PutUint64(fromSeq[:], 1)
	if err := writeWatchFrame(conn, fromSeq[:]); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	wantHash := sha256.Sum256([]byte(carrierDoc))
	for _, wantSeq := range []uint64{2, 3} {
		body, err := readCarrierFrame(t, conn)
		if err != nil {
			t.Fatalf("read version frame for seq %d: %v", wantSeq, err)
		}
		seq, hash, doc := decodeCarrierVersion(t, body)
		if seq != wantSeq {
			t.Fatalf("forward-only order: got seq %d, want %d", seq, wantSeq)
		}
		if string(doc) != carrierDoc {
			t.Fatalf("transported document for seq %d is not the produce-once bytes verbatim", seq)
		}
		if !bytesEqual(hash, wantHash[:]) {
			t.Fatalf("producer-pinned content_hash for seq %d is not transported verbatim", seq)
		}
	}
	// EOF: the producer closes after replaying its forward-only history (§5.3 end-of-stream).
	if _, err := readCarrierFrame(t, conn); err != io.EOF {
		t.Fatalf("after the replay the producer must close (EOF); got %v", err)
	}

	// Shutdown is clean (ctx-driven listener close), not a fault.
	cancel()
	if err := <-serveErr; err != nil && err != context.Canceled {
		t.Fatalf("Serve returned a non-shutdown error: %v", err)
	}
}

func TestWatchPoliciesCarrierSweeperBuffersBehindTheCommitBarrier(t *testing.T) {
	// The Sweeper seam (apply.go) buffers a version ONLY when invoked — the ApplyCoordinator
	// calls Sweep(ctx, snap) on the admitter-LAST commit, so a version reaches a dialing
	// consumer only behind the commit barrier. Sweep returns the swept seq; a nil snapshot is
	// a programming error; a buffering failure (a torn/backward version) HOLDS apply_seq.
	c := NewWatchPoliciesCarrier()
	gotSeq, err := c.Sweep(context.Background(), snapAt(9, carrierDoc))
	if err != nil || gotSeq != 9 {
		t.Fatalf("Sweep clean: seq=%d err=%v, want 9/nil", gotSeq, err)
	}
	if got := c.Cursor(); got != 9 {
		t.Fatalf("Sweep must buffer behind the barrier: cursor = %d, want 9", got)
	}
	if _, err := c.Sweep(context.Background(), nil); err == nil {
		t.Fatalf("Sweep on a nil snapshot must error")
	}
	// A backward/torn version that cannot buffer must surface the error so the coordinator
	// HOLDS apply_seq at the prior version (the resume cursor never names an unbuffered version).
	if _, err := c.Sweep(context.Background(), snapAt(9, carrierDoc)); err == nil {
		t.Fatalf("Sweep of a re-delivered seq must error so apply_seq holds")
	}
}

// ─── CROSS-LANGUAGE WatchPolicies carrier-frame conformance (Go ⇄ Rust) ───
//
// The on-the-wire WatchPolicies version-frame is a HAND-ROLLED cross-process contract with NO
// shared type (D40/D67): the Go producer (dnsfeed_carrier.go encodeWatchVersion) and the Rust
// consumer (server.rs WatchPoliciesFrame::encode_version / decode_version) each test only their
// OWN in-language mirror, so a frame-shape divergence (a byte-order flip, a field reorder, a
// content_hash-width change) surfaces ONLY at live integration.
//
// SINGLE-SOURCED THROUGH THE CONFORMANCE FIXTURE. The canonical tuple, the version-frame golden
// bytes, AND the 8-byte from_seq handshake are promoted into the checked-in conformance fixture
// assurance/conformance-adapter/revocationwire/carrierframe.go (CarrierGoldenSeq /
// CarrierGoldenDoc / CarrierGoldenContentHashHex / CarrierGoldenFrameHex / CarrierGoldenHandshakeHex),
// which RE-DERIVES every value from the canonical tuple by an independent encoder and pins it
// (revocationwire/carrierframe_test.go). The orchestrator module may import ONLY proto/gen/go
// cross-tree (CLAUDE.md), so this Go test pins a byte-IDENTICAL copy of those fixture constants;
// the Rust test (server.rs CARRIER_GOLDEN_FRAME_HEX) pins the same. Because all three re-derive
// the SAME bytes from the SAME canonical inputs, a frame-shape drift on any tree breaks that
// tree's recompute-and-pin assertion AND the shared fixture — the wire is single-sourced through
// the fixture, NOT two drifting per-side mirrors. Keep these constants byte-for-byte in lock-step
// with revocationwire.Carrier* (a one-tree drift fails the conformance suite).
//
// The tuple is fixed (a distinct-byte seq so an endianness flip is visible, a full 32-byte
// SHA-256 content_hash over the document, an ASCII document) and is NOT derived from a runtime
// hash call here: the golden hex below is the authoritative produce-once wire form, recomputed
// independently by the conformance fixture and the Rust side. NEVER-LOG-THE-SECRET holds — the
// fixture is a synthetic conformance string, not a real policy/secret (D73).
const (
	// carrierGoldenSeq is the fixed u64 seq of the cross-language fixture. The distinct bytes
	// (01 02 .. 08) make a byte-order divergence in the 8B-BE seq field visible. IDENTICAL to
	// revocationwire.CarrierGoldenSeq.
	carrierGoldenSeq = uint64(0x0102030405060708)
	// carrierGoldenDoc is the fixed produce-once transported document (the §5.1 identity tuple's
	// document leg). carrierGoldenContentHashHex is SHA-256 over exactly these bytes. IDENTICAL to
	// revocationwire.CarrierGoldenDoc.
	carrierGoldenDoc = "ds-watchpolicies-frame-conformance\n"
	// carrierGoldenContentHashHex is the full 32-byte SHA-256 content_hash over carrierGoldenDoc,
	// as 64 lowercase hex chars — the §5.1 content_hash leg. IDENTICAL to the Rust fixture and to
	// revocationwire.CarrierGoldenContentHashHex.
	carrierGoldenContentHashHex = "d52a55c4c38e4549e80cf020e14284f3db296de50461e4683e2988025e7f30b5"
	// carrierGoldenFrameHex is the canonical version-frame BODY bytes the carrier wire contract
	// serialises (carrierGoldenSeq, content_hash, carrierGoldenDoc) to, as hex:
	//   seq(8B BE) || content_hash_len=32(4B BE) || content_hash(32) || doc_len(4B BE) || document.
	// This is the byte-for-byte handshake-free version frame both languages agree on. IDENTICAL to
	// the Rust fixture (server.rs CARRIER_GOLDEN_FRAME_HEX) and revocationwire.CarrierGoldenFrameHex.
	carrierGoldenFrameHex = "010203040506070800000020" +
		"d52a55c4c38e4549e80cf020e14284f3db296de50461e4683e2988025e7f30b5" +
		"0000002364732d7761746368706f6c69636965732d6672616d652d636f6e666f726d616e63650a"
	// carrierGoldenHandshakeHex is the 8-byte big-endian from_seq handshake body a dialing consumer
	// sends to open a WatchPolicies(from_seq) stream (the resume cursor, D36) — exactly the 8 BE
	// bytes of carrierGoldenSeq. IDENTICAL to revocationwire.CarrierGoldenHandshakeHex.
	carrierGoldenHandshakeHex = "0102030405060708"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode fixture hex %q: %v", s, err)
	}
	return b
}

// TestWatchPoliciesCarrierFrameCrossLanguageGolden is the Go HALF of the cross-language frame-shape
// conformance: the Go producer's encodeWatchVersion of the canonical fixture tuple must equal the
// shared golden frame bytes, AND the Go-side decode of those golden bytes must round-trip back to
// the byte-equal tuple. The Rust half (server.rs) asserts the SAME golden against its own
// encode_version/decode_version — so a frame encoded by either side is decoded byte-equal by the
// other. The final sub-test confirms the golden CATCHES a deliberate seq / content_hash / document
// framing divergence (a mutated golden no longer decodes to the fixture tuple).
func TestWatchPoliciesCarrierFrameCrossLanguageGolden(t *testing.T) {
	wantHash := mustHex(t, carrierGoldenContentHashHex)
	wantFrame := mustHex(t, carrierGoldenFrameHex)
	wantDoc := []byte(carrierGoldenDoc)

	// Sanity: the fixture's content_hash IS SHA-256 over the document (the §5.1 identity tuple),
	// so the golden is the produce-once wire form, not an arbitrary blob.
	gotSum := sha256.Sum256(wantDoc)
	if !bytesEqual(gotSum[:], wantHash) {
		t.Fatalf("fixture content_hash is not SHA-256(document): the golden is inconsistent")
	}

	t.Run("GoEncodeProducesTheCrossLanguageGolden", func(t *testing.T) {
		// The PRODUCER half: encodeWatchVersion (dnsfeed_carrier.go, the exact bytes Serve writes)
		// of the fixture tuple must be the byte-for-byte golden the Rust consumer reads.
		got := encodeWatchVersion(carrierGoldenSeq, wantHash, wantDoc)
		if !bytesEqual(got, wantFrame) {
			t.Fatalf("Go encodeWatchVersion diverged from the cross-language golden:\n got %x\nwant %x",
				got, wantFrame)
		}
	})

	t.Run("GoHandshakeMatchesTheGolden", func(t *testing.T) {
		// The from_seq handshake leg (the 8B-BE resume cursor the consumer sends to open the
		// stream, D36) is single-sourced through the fixture too — the bytes the carrier's
		// TestWatchPoliciesCarrierServesForwardOnlyStream writes for a from_seq must be exactly the
		// golden the Rust producer (WatchPoliciesFrame::encode_handshake) emits.
		wantHandshake := mustHex(t, carrierGoldenHandshakeHex)
		var got [8]byte
		binary.BigEndian.PutUint64(got[:], carrierGoldenSeq)
		if !bytesEqual(got[:], wantHandshake) {
			t.Fatalf("Go from_seq handshake diverged from the golden:\n got %x\nwant %x", got[:], wantHandshake)
		}
	})

	t.Run("GoDecodeOfTheGoldenRoundTripsTheTuple", func(t *testing.T) {
		// The CONSUMER-mirror half: decoding the shared golden bytes (the form the Rust producer
		// emits) must yield the byte-equal (seq, content_hash, document) tuple — so a Rust-encoded
		// frame is read identically by the Go side.
		seq, hash, doc := decodeCarrierVersion(t, wantFrame)
		if seq != carrierGoldenSeq {
			t.Fatalf("decoded seq = %#x, want %#x", seq, carrierGoldenSeq)
		}
		if !bytesEqual(hash, wantHash) {
			t.Fatalf("decoded content_hash not byte-equal across the boundary:\n got %x\nwant %x", hash, wantHash)
		}
		if !bytesEqual(doc, wantDoc) {
			t.Fatalf("decoded document not byte-equal across the boundary:\n got %q\nwant %q", doc, wantDoc)
		}
	})

	t.Run("DivergenceIsCaught", func(t *testing.T) {
		// The deliberate-divergence proof (the exec-report deliverable): mutating ONE byte in each
		// of the three frame fields (seq, content_hash, document) makes the decoded tuple stop
		// matching the fixture — so a real frame-shape drift on either side can never pass silently.
		// seq leg: flip the low byte of the 8B-BE seq prefix.
		seqMut := append([]byte(nil), wantFrame...)
		seqMut[7] ^= 0x01
		if seq, _, _ := decodeCarrierVersion(t, seqMut); seq == carrierGoldenSeq {
			t.Fatalf("a mutated seq byte must change the decoded seq (divergence not caught)")
		}
		// content_hash leg: flip a byte inside the 32-byte hash (offset 8+4=12 .. 44).
		hashMut := append([]byte(nil), wantFrame...)
		hashMut[12] ^= 0x01
		if _, hash, _ := decodeCarrierVersion(t, hashMut); bytesEqual(hash, wantHash) {
			t.Fatalf("a mutated content_hash byte must change the decoded hash (divergence not caught)")
		}
		// document leg: flip a byte inside the document (the final field).
		docMut := append([]byte(nil), wantFrame...)
		docMut[len(docMut)-1] ^= 0x01
		if _, _, doc := decodeCarrierVersion(t, docMut); bytesEqual(doc, wantDoc) {
			t.Fatalf("a mutated document byte must change the decoded document (divergence not caught)")
		}
	})
}
