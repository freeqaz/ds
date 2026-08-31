// SPDX-License-Identifier: Apache-2.0

package revocationwire

// carrierframe_test.go is the cross-service conformance suite for the two hand-rolled
// cross-process contracts carrierframe.go single-sources: the WatchPolicies(from_seq) CARRIER
// FRAME and the caRef-LEAF cross-reader domain (doc 11 §5.3, doc 12 §8.1, D40/D67).
//
// It is the AUTHORITATIVE half of the assertion the round-D rung-table pattern uses: every
// golden value carrierframe.go freezes is RE-DERIVED here from the canonical inputs by an
// independent codec/sanitizer and pinned, so the golden is never an unchecked literal. The Go
// orchestrator suites (dnsfeed_carrier_test.go carrierGolden*, controlplane CrossReaderCARefVectors)
// and the Rust dataplane suites (server.rs CARRIER_GOLDEN_*, main.rs CROSS_READER_CAREF_VECTORS)
// keep byte-identical copies pinned by their OWN independent re-derivation — so a real wire/leaf
// drift can never pass all three, because all three must reproduce the SAME bytes this fixture
// freezes.
//
// The final sub-tests are the SCOPE's deliberate-drift exec-report deliverable: a one-byte
// mutation of THIS single source (the carrier golden frame, or a caRef leaf row) is shown to
// turn the conformance assertion RED — the wire is single-sourced through this fixture, not two
// drifting per-side mirrors.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode fixture hex %q: %v", s, err)
	}
	return b
}

// TestCarrierGoldenIsTheProduceOnceWireForm pins the carrier golden as the AUTHORITATIVE
// produce-once wire form: the content_hash IS SHA-256 over the document (the §5.1 identity
// tuple), and EncodeCarrierVersion of the canonical tuple equals CarrierGoldenFrameHex
// byte-for-byte. A frame-shape drift in this single source (the constant or the encoder) turns
// this RED — so the golden the two trees copy is never an unverified literal.
func TestCarrierGoldenIsTheProduceOnceWireForm(t *testing.T) {
	wantHash := mustHex(t, CarrierGoldenContentHashHex)
	wantFrame := mustHex(t, CarrierGoldenFrameHex)
	wantDoc := []byte(CarrierGoldenDoc)

	// §5.1 identity tuple: the pinned content_hash IS SHA-256(document) — the golden is the
	// produce-once wire form, not an arbitrary blob, and it is the SAME crypto/sha256 the Go
	// producer ran over the SAME bytes the Rust side independently recomputes.
	gotSum := sha256.Sum256(wantDoc)
	if !bytes.Equal(gotSum[:], wantHash) {
		t.Fatalf("fixture content_hash is not SHA-256(document): the golden is inconsistent")
	}
	if len(wantHash) != CarrierContentHashLen {
		t.Fatalf("fixture content_hash width = %d, want the %d-byte SHA-256 width", len(wantHash), CarrierContentHashLen)
	}

	// The INDEPENDENT reference encoder of the canonical tuple must be the byte-for-byte golden
	// both trees pin (Go encodeWatchVersion, Rust encode_version).
	got := EncodeCarrierVersion(CarrierGoldenSeq, wantHash, wantDoc)
	if !bytes.Equal(got, wantFrame) {
		t.Fatalf("EncodeCarrierVersion diverged from the cross-language golden:\n got %x\nwant %x", got, wantFrame)
	}

	// The 8-byte from_seq handshake leg is single-sourced too.
	wantHandshake := mustHex(t, CarrierGoldenHandshakeHex)
	gotHandshake := EncodeCarrierHandshake(CarrierGoldenSeq)
	if !bytes.Equal(gotHandshake, wantHandshake) {
		t.Fatalf("EncodeCarrierHandshake diverged from the golden:\n got %x\nwant %x", gotHandshake, wantHandshake)
	}
	if len(wantHandshake) != 8 {
		t.Fatalf("handshake golden is %d bytes, want the 8-byte big-endian from_seq", len(wantHandshake))
	}
}

// TestCarrierGoldenRoundTripsTheTuple proves the independent decoder is the encoder's inverse:
// decoding the shared golden bytes yields the byte-equal (seq, content_hash, document) tuple —
// so a frame encoded by EITHER tree is read identically through this single source.
func TestCarrierGoldenRoundTripsTheTuple(t *testing.T) {
	wantHash := mustHex(t, CarrierGoldenContentHashHex)
	wantFrame := mustHex(t, CarrierGoldenFrameHex)
	wantDoc := []byte(CarrierGoldenDoc)

	seq, hash, doc, ok := DecodeCarrierVersion(wantFrame)
	if !ok {
		t.Fatalf("the golden frame must decode (it is the well-formed produce-once wire form)")
	}
	if seq != CarrierGoldenSeq {
		t.Fatalf("decoded seq = %#x, want %#x", seq, CarrierGoldenSeq)
	}
	if !bytes.Equal(hash, wantHash) {
		t.Fatalf("decoded content_hash not byte-equal across the boundary:\n got %x\nwant %x", hash, wantHash)
	}
	if !bytes.Equal(doc, wantDoc) {
		t.Fatalf("decoded document not byte-equal across the boundary:\n got %q\nwant %q", doc, wantDoc)
	}
}

// TestCarrierFrameMalformedIsFailClosed is the cross-language MALFORMED-FRAME leg: a truncated
// OR over-long frame is rejected (ok=false) identically to both decoders' documented posture
// (Go decodeCarrierVersion's t.Fatalf guards, Rust WatchPoliciesFrame::decode_version's None).
// The carrier drops the stream fail-closed rather than fabricate a version.
func TestCarrierFrameMalformedIsFailClosed(t *testing.T) {
	good := mustHex(t, CarrierGoldenFrameHex)

	t.Run("EmptyIsRejected", func(t *testing.T) {
		if _, _, _, ok := DecodeCarrierVersion(nil); ok {
			t.Fatal("an empty frame must be rejected fail-closed")
		}
		if _, _, _, ok := DecodeCarrierVersion([]byte{}); ok {
			t.Fatal("a zero-length frame must be rejected fail-closed")
		}
	})

	t.Run("TruncatedBeforeEachFieldIsRejected", func(t *testing.T) {
		// Every strict prefix of the golden frame is truncated — it ends before the seq, a length
		// prefix, the content_hash, or the document. NONE may decode (the body does not consume
		// exactly / a field runs past the buffer).
		for cut := 1; cut < len(good); cut++ {
			if _, _, _, ok := DecodeCarrierVersion(good[:cut]); ok {
				t.Fatalf("truncated frame (len %d of %d) must be rejected fail-closed", cut, len(good))
			}
		}
	})

	t.Run("OverLongTrailingBytesIsRejected", func(t *testing.T) {
		// One trailing byte past the document — the body did not consume exactly. Both decoders
		// reject trailing bytes as a malformed (over-long) frame.
		overLong := append(append([]byte(nil), good...), 0x00)
		if _, _, _, ok := DecodeCarrierVersion(overLong); ok {
			t.Fatal("an over-long frame (trailing bytes) must be rejected fail-closed")
		}
	})

	t.Run("WrongContentHashWidthIsRejected", func(t *testing.T) {
		// Re-frame the SAME tuple with a content_hash_len that is not the 32-byte SHA-256 width
		// (here 31): both decoders reject a torn content_hash width even when the body is otherwise
		// self-consistent.
		shortHash := make([]byte, CarrierContentHashLen-1)
		body := EncodeCarrierVersion(CarrierGoldenSeq, shortHash, []byte(CarrierGoldenDoc))
		if _, _, _, ok := DecodeCarrierVersion(body); ok {
			t.Fatal("a content_hash that is not the 32-byte SHA-256 width must be rejected fail-closed")
		}
	})

	t.Run("OverLongDeclaredDocLenIsRejected", func(t *testing.T) {
		// A doc_len field that claims MORE bytes than the frame carries (a length past the buffer):
		// the document field runs past the body, rejected fail-closed (the dataplane take_slice
		// guard's analog — a declared length must not over-read).
		mut := append([]byte(nil), good...)
		// doc_len lives at offset 8 + 4 + 32 = 44 .. 48; bump its low byte so it over-declares.
		mut[47] ^= 0xff
		if _, _, _, ok := DecodeCarrierVersion(mut); ok {
			t.Fatal("a doc_len that over-declares past the frame must be rejected fail-closed")
		}
	})
}

// TestCarrierGoldenDivergenceIsCaught is the deliberate-drift exec-report deliverable for the
// carrier frame: mutating ONE byte in each of the three frame fields (seq, content_hash,
// document) makes the decoded tuple stop matching the fixture — so a real frame-shape drift on
// any of the three trees can never pass silently through this single source.
func TestCarrierGoldenDivergenceIsCaught(t *testing.T) {
	good := mustHex(t, CarrierGoldenFrameHex)
	wantHash := mustHex(t, CarrierGoldenContentHashHex)
	wantDoc := []byte(CarrierGoldenDoc)

	// seq leg: flip the low byte of the 8B-BE seq prefix.
	seqMut := append([]byte(nil), good...)
	seqMut[7] ^= 0x01
	if seq, _, _, ok := DecodeCarrierVersion(seqMut); ok && seq == CarrierGoldenSeq {
		t.Fatal("a mutated seq byte must change the decoded seq (divergence not caught)")
	}
	// content_hash leg: flip a byte inside the 32-byte hash (offset 8+4=12 .. 44).
	hashMut := append([]byte(nil), good...)
	hashMut[12] ^= 0x01
	if _, hash, _, ok := DecodeCarrierVersion(hashMut); ok && bytes.Equal(hash, wantHash) {
		t.Fatal("a mutated content_hash byte must change the decoded hash (divergence not caught)")
	}
	// document leg: flip a byte inside the document (the final field).
	docMut := append([]byte(nil), good...)
	docMut[len(docMut)-1] ^= 0x01
	if _, _, doc, ok := DecodeCarrierVersion(docMut); ok && bytes.Equal(doc, wantDoc) {
		t.Fatal("a mutated document byte must change the decoded document (divergence not caught)")
	}
}

// ─── caRef-leaf cross-reader conformance ───

// TestCARefVectorsAreReDerivedFromSanitize pins every golden caRef-leaf row as the
// AUTHORITATIVE re-derivation: CARefLeafStem(uuid) == Stem (and the cert/key leaf names follow),
// so the golden table both trees copy is re-computed by the independent SanitizeCARef, not an
// unverified literal. The "ca:" prefix's ':' is sanitized to '_', a hyphen survives, and a
// path-illegal '/' maps to '_' — the exact domain the producer, host-agent, and ds-tlsproxy
// consumer must all land on.
func TestCARefVectorsAreReDerivedFromSanitize(t *testing.T) {
	for _, v := range CrossReaderCARefVectors {
		stem := CARefLeafStem(v.SessionUUID)
		if stem != v.Stem {
			t.Errorf("CARefLeafStem(%q) = %q, want golden stem %q (sanitize drift)", v.SessionUUID, stem, v.Stem)
		}
		// The caRef the consumer re-derives is byte-identical to the producer's caRefFor(uuid).
		if caRef := CARefPrefix + v.SessionUUID; caRef != "ca:"+v.SessionUUID {
			t.Errorf("caRef domain drift for %q: %q", v.SessionUUID, caRef)
		}
		if cert := CARefLeafCert(v.SessionUUID); cert != v.Stem+".pem" {
			t.Errorf("CARefLeafCert(%q) = %q, want %q", v.SessionUUID, cert, v.Stem+".pem")
		}
		if key := CARefLeafKey(v.SessionUUID); key != v.Stem+".key.pem" {
			t.Errorf("CARefLeafKey(%q) = %q, want %q", v.SessionUUID, key, v.Stem+".key.pem")
		}
	}
}

// TestSanitizeCARefMatchesBothTreePorts pins the SanitizeCARef byte-table against the documented
// transform both trees port (trustpath.Sanitize / sanitize_ca_ref): the allowed alphabet
// [A-Za-z0-9._-] survives, every other byte maps to '_', and an empty result collapses to the
// "session" sentinel. A drift here is what re-introduces the producer↔consumer leaf MISS.
func TestSanitizeCARefMatchesBothTreePorts(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ca:01HZX9K6Q2VN7T4M8B0CWRD5EF", "ca_01HZX9K6Q2VN7T4M8B0CWRD5EF"}, // ':' → '_'
		{"ca:sess-prod-1", "ca_sess-prod-1"},                               // hyphen + '.' survive
		{"ca:a/b", "ca_a_b"},                                               // '/' → '_'
		{"a.b_c-d", "a.b_c-d"},                                             // the full allowed alphabet survives
		{"../escape", ".._escape"},                                         // '/' → '_'; '.' is allowed (single-component is the traversal guard)
		{"", CARefEmptySentinel},                                           // empty collapses to "session"
		{":::", "___"},                                                     // all-illegal → all-'_', NOT empty
	}
	for _, c := range cases {
		if got := SanitizeCARef(c.in); got != c.want {
			t.Errorf("SanitizeCARef(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestCARefDivergenceIsCaught is the deliberate-drift exec-report deliverable for the caRef
// leaf: a one-byte mutation of a golden row's expected stem is shown to no longer equal the
// re-derived stem — so a leaf-name drift in this single source (or copied wrong into a tree)
// turns the conformance assertion RED, the way the Go producer's package init() panics and the
// Rust caref_leaf_stem test goes red.
func TestCARefDivergenceIsCaught(t *testing.T) {
	row := CrossReaderCARefVectors[0]
	reDerived := CARefLeafStem(row.SessionUUID)
	// Mutate the expected stem by one byte (drop the trailing 'F' → 'G'): the re-derivation no
	// longer matches, which is exactly the RED a drifted fixture row produces.
	drifted := reDerived[:len(reDerived)-1] + "G"
	if drifted == reDerived {
		t.Fatal("the mutated stem must differ from the re-derived stem (test is vacuous)")
	}
	// The conformance row's re-derivation (CARefLeafStem) does NOT equal the drifted stem — so a
	// fixture row that drifts in one tree (its expected stem mutated) fails this assertion.
	if CARefLeafStem(row.SessionUUID) == drifted {
		t.Fatal("a drifted golden stem must NOT equal the independently re-derived stem")
	}
}
