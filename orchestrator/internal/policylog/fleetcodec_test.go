// SPDX-License-Identifier: Apache-2.0

package policylog

// Round-trip property tests for the SINGLE ds.fleet_digest.v1 envelope codec
// (encodeFleetEnvelope / decodeFleetEnvelope, fleetdigestsink.go). They drive the
// shared encode/decode pair DIRECTLY over raw entry bytes — the lowest common
// denominator both the producer (marshalFleetArtifact) and the POL-4 sweep's reader
// (parseFleetEnvelope) route through — so a framing change that breaks the inverse
// is caught here regardless of either caller. The cases cover the property surface
// the scope names: multi-entry, multiline-byte entries (the length-framed parse must
// not split on '\n'), and the empty-set REVOKE shape (entries=0 decodes ok, distinct
// from a parse failure). Synthetic byte fixtures only (D50) — no proto, no store.

import (
	"bytes"
	"testing"
)

// TestFleetEnvelopeCodec_RoundTrip is the property pin: for every fixture
// (multi-entry, entries carrying '\n' and ':' and 'e=' bytes, and the empty REVOKE
// set) decodeFleetEnvelope(encodeFleetEnvelope(...)) returns the SAME key id and the
// byte-identical entry frames in order. This is the single-source guarantee — the
// codec is its own inverse — so neither the writer nor the sweep can drift from it.
func TestFleetEnvelopeCodec_RoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		keyID   string
		batchID string
		entries [][]byte
	}{
		{
			name:    "multi-entry",
			keyID:   "key-a",
			batchID: "batch-1",
			entries: [][]byte{[]byte("alpha"), []byte("bravo"), []byte("charlie")},
		},
		{
			name:    "multiline-byte entries",
			keyID:   "key-nl",
			batchID: "b",
			// Entries that embed the framing's own delimiters: a newline (the parse must
			// read by hex length, never line boundary), a colon (the length/body
			// separator), and an "e=" prefix (an entry-frame marker) — none may be
			// mistaken for framing.
			entries: [][]byte{
				[]byte("line1\nline2\nline3"),
				[]byte("has:colon:and\nnewline"),
				[]byte("e=looks-like-a-frame\n"),
				{0x00, 0x0a, 0xff, 0x3a, 0x0a}, // NUL, '\n', 0xff, ':', '\n'
			},
		},
		{
			name:    "empty-set revoke",
			keyID:   "key-revoke",
			batchID: "b-rev",
			entries: nil, // the REVOKE shape: entries=0, no entry frames
		},
		{
			name:    "single empty-byte entry",
			keyID:   "key-empty-entry",
			batchID: "b",
			// A zero-LENGTH entry frame (e=0:\n) is distinct from the empty SET — it
			// carries one entry whose bytes are empty.
			entries: [][]byte{{}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := encodeFleetEnvelope(tc.keyID, tc.batchID, tc.entries)

			gotKey, gotEntries, ok := decodeFleetEnvelope(payload)
			if !ok {
				t.Fatalf("decodeFleetEnvelope failed to parse a payload the codec produced: %q", payload)
			}
			if gotKey != tc.keyID {
				t.Errorf("keyID = %q, want %q", gotKey, tc.keyID)
			}
			if len(gotEntries) != len(tc.entries) {
				t.Fatalf("entry count = %d, want %d (entries=%q)", len(gotEntries), len(tc.entries), gotEntries)
			}
			for i := range tc.entries {
				if !bytes.Equal(gotEntries[i], tc.entries[i]) {
					t.Errorf("entry[%d] = %q, want %q", i, gotEntries[i], tc.entries[i])
				}
			}

			// Encode is deterministic: the same inputs always yield byte-identical bytes
			// (the produce-once / content-id property, D73).
			if again := encodeFleetEnvelope(tc.keyID, tc.batchID, tc.entries); !bytes.Equal(again, payload) {
				t.Errorf("encode is not deterministic:\n a=%q\n b=%q", payload, again)
			}

			// Re-encoding the decoded frames reproduces the SAME bytes — full round-trip
			// stability across the codec boundary.
			if reencoded := encodeFleetEnvelope(gotKey, tc.batchID, gotEntries); !bytes.Equal(reencoded, payload) {
				t.Errorf("re-encode of decoded frames drifted:\n orig=%q\n re  =%q", payload, reencoded)
			}
		})
	}
}

// TestFleetEnvelopeCodec_DecodeReturnsCopies proves the decoder does NOT alias the
// caller's payload backing array: mutating the returned entry frames must not corrupt
// the source bytes (the sweep keeps these frames past the row's lifetime).
func TestFleetEnvelopeCodec_DecodeReturnsCopies(t *testing.T) {
	entry := []byte("mutable")
	payload := encodeFleetEnvelope("k", "b", [][]byte{entry})
	orig := append([]byte(nil), payload...)

	_, entries, ok := decodeFleetEnvelope(payload)
	if !ok || len(entries) != 1 {
		t.Fatalf("decode: ok=%v entries=%d", ok, len(entries))
	}
	for i := range entries[0] {
		entries[0][i] ^= 0xff // scribble over the returned frame
	}
	if !bytes.Equal(payload, orig) {
		t.Error("mutating a decoded entry frame corrupted the source payload — decode aliases its input")
	}
}

// TestFleetEnvelopeCodec_DecodeRejectsMalformed proves fail-closed decode: a
// non-envelope body, a truncated entry frame, and trailing garbage past the declared
// count all return ok=false (a malformed artifact advances no key's state). The
// empty-SET case stays ok (it is the revoke shape, asserted in TestFleetEnvelopeCodec_RoundTrip).
func TestFleetEnvelopeCodec_DecodeRejectsMalformed(t *testing.T) {
	good := encodeFleetEnvelope("k", "b", [][]byte{[]byte("x")})

	malformed := map[string][]byte{
		"not an envelope":             []byte("hello world\n"),
		"empty payload":               nil,
		"truncated entry body":        good[:len(good)-1], // drop the trailing entry byte+newline tail
		"trailing garbage past count": append(append([]byte(nil), good...), []byte("e=1:z\n")...),
		"bad header":                  []byte("ds.fleet_digest.v0\nkey=k\nbatch=b\nentries=0\n"),
	}
	for name, payload := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := decodeFleetEnvelope(payload); ok {
				t.Errorf("decodeFleetEnvelope accepted a malformed body (%q) — must fail closed", payload)
			}
		})
	}
}
