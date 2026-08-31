// SPDX-License-Identifier: Apache-2.0

package grantwire

import (
	"encoding/hex"
	"testing"
)

// TestGoldenGrantHexIsReDerived proves the pinned GoldenGrantHex is the AUTHORITATIVE
// produce-once wire form: the independent EncodeAllowGrant over the canonical inputs
// reproduces it byte-for-byte. A frame-shape drift in this single source turns the suite
// RED (and, because the Go producer test and the Rust decoder test pin the byte-identical
// hex, so does a drift on either tree).
func TestGoldenGrantHexIsReDerived(t *testing.T) {
	got := EncodeAllowGrant(
		GoldenSessionUUID, GoldenHostID, GoldenHostSessionIndex, GoldenTapName,
		GoldenSniDomain, GoldenExpiresAtUnixS,
	)
	if h := hex.EncodeToString(got); h != GoldenGrantHex {
		t.Fatalf("re-derived golden drifted:\n got  %s\n want %s", h, GoldenGrantHex)
	}
}

// TestGoldenGrantRoundTrips proves the independent encoder and decoder agree on the
// canonical grant — the byte-exact cross-language pin's Go-side self-consistency.
func TestGoldenGrantRoundTrips(t *testing.T) {
	body, err := hex.DecodeString(GoldenGrantHex)
	if err != nil {
		t.Fatalf("decode golden hex: %v", err)
	}
	uuid, hostID, idx, tap, sni, expires, ok := DecodeAllowGrant(body)
	if !ok {
		t.Fatal("DecodeAllowGrant rejected the golden frame")
	}
	if uuid != GoldenSessionUUID || hostID != GoldenHostID || idx != GoldenHostSessionIndex ||
		tap != GoldenTapName || sni != GoldenSniDomain || expires != GoldenExpiresAtUnixS {
		t.Fatalf("golden round-trip mismatch: got (%q,%q,%#x,%q,%q,%#x)",
			uuid, hostID, idx, tap, sni, expires)
	}
}

// TestExpiredGrantRoundTrips proves an already-expired grant (expires_at in the past)
// round-trips — the codec never judges TTL; the consumer's resolution-time check fails a
// past expiry closed, not the decoder.
func TestExpiredGrantRoundTrips(t *testing.T) {
	body := EncodeAllowGrant("sess-x", "host-y", 7, "dstap-7", "example.com", 1)
	_, _, _, _, sni, expires, ok := DecodeAllowGrant(body)
	if !ok {
		t.Fatal("DecodeAllowGrant rejected a well-formed (but expired) grant")
	}
	if sni != "example.com" || expires != 1 {
		t.Fatalf("round-trip mismatch: got sni=%q expires=%d, want example.com/1", sni, expires)
	}
}

// TestDecodeRejectsMalformed pins the fail-closed rejection set both decoders share:
// truncated fields and trailing bytes.
func TestDecodeRejectsMalformed(t *testing.T) {
	good := EncodeAllowGrant(GoldenSessionUUID, GoldenHostID, GoldenHostSessionIndex, GoldenTapName, GoldenSniDomain, 42)

	t.Run("truncated", func(t *testing.T) {
		if _, _, _, _, _, _, ok := DecodeAllowGrant(good[:len(good)-1]); ok {
			t.Fatal("a truncated frame decoded (want fail-closed)")
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		over := append(append([]byte{}, good...), 0xFF)
		if _, _, _, _, _, _, ok := DecodeAllowGrant(over); ok {
			t.Fatal("an over-long frame decoded (want fail-closed)")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, _, _, _, _, _, ok := DecodeAllowGrant(nil); ok {
			t.Fatal("an empty body decoded (want fail-closed)")
		}
	})
}
