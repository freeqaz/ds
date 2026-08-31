// SPDX-License-Identifier: Apache-2.0

package attendwire

import (
	"encoding/hex"
	"testing"
)

// TestGoldenFactHexIsReDerived proves the pinned GoldenFactHex is the AUTHORITATIVE
// produce-once wire form: the independent EncodeAttendednessFact over the canonical inputs
// reproduces it byte-for-byte. A frame-shape drift in this single source turns the suite RED
// (and, because the Go producer test and the Rust decoder test pin the byte-identical hex,
// so does a drift on either tree).
func TestGoldenFactHexIsReDerived(t *testing.T) {
	got := EncodeAttendednessFact(
		GoldenSessionUUID, GoldenHostID, GoldenHostSessionIndex, GoldenTapName,
		GoldenAttended, GoldenAttendedAtUnixS,
	)
	if h := hex.EncodeToString(got); h != GoldenFactHex {
		t.Fatalf("re-derived golden drifted:\n got  %s\n want %s", h, GoldenFactHex)
	}
}

// TestGoldenFactRoundTrips proves the independent encoder and decoder agree on the canonical
// fact — the byte-exact cross-language pin's Go-side self-consistency.
func TestGoldenFactRoundTrips(t *testing.T) {
	body, err := hex.DecodeString(GoldenFactHex)
	if err != nil {
		t.Fatalf("decode golden hex: %v", err)
	}
	uuid, hostID, idx, tap, attended, at, ok := DecodeAttendednessFact(body)
	if !ok {
		t.Fatal("DecodeAttendednessFact rejected the golden frame")
	}
	if uuid != GoldenSessionUUID || hostID != GoldenHostID || idx != GoldenHostSessionIndex ||
		tap != GoldenTapName || attended != GoldenAttended || at != GoldenAttendedAtUnixS {
		t.Fatalf("golden round-trip mismatch: got (%q,%q,%#x,%q,%v,%#x)",
			uuid, hostID, idx, tap, attended, at)
	}
}

// TestUnattendedFactRoundTrips proves an honest UNATTENDED fact (attended=0) round-trips —
// the fail-closed default the consumer records as UNATTENDED, never fabricated to attended.
func TestUnattendedFactRoundTrips(t *testing.T) {
	body := EncodeAttendednessFact("sess-x", "host-y", 7, "dstap-7", false, 12345)
	_, _, _, _, attended, at, ok := DecodeAttendednessFact(body)
	if !ok {
		t.Fatal("DecodeAttendednessFact rejected a well-formed unattended fact")
	}
	if attended {
		t.Fatal("attended=0 must decode to false (never fabricated true)")
	}
	if at != 12345 {
		t.Fatalf("attended_at = %d, want 12345", at)
	}
}

// TestDecodeRejectsMalformed pins the fail-closed rejection set both decoders share:
// truncated fields, an attended byte outside {0,1}, and trailing bytes.
func TestDecodeRejectsMalformed(t *testing.T) {
	good := EncodeAttendednessFact(GoldenSessionUUID, GoldenHostID, GoldenHostSessionIndex, GoldenTapName, true, 42)

	t.Run("truncated", func(t *testing.T) {
		if _, _, _, _, _, _, ok := DecodeAttendednessFact(good[:len(good)-1]); ok {
			t.Fatal("a truncated frame decoded (want fail-closed)")
		}
	})

	t.Run("trailing bytes", func(t *testing.T) {
		over := append(append([]byte{}, good...), 0xFF)
		if _, _, _, _, _, _, ok := DecodeAttendednessFact(over); ok {
			t.Fatal("an over-long frame decoded (want fail-closed)")
		}
	})

	t.Run("bad attended byte", func(t *testing.T) {
		// The attended byte sits right before the trailing 8-byte attended_at.
		bogus := append([]byte{}, good...)
		bogus[len(bogus)-9] = 2 // neither 0 nor 1
		if _, _, _, _, _, _, ok := DecodeAttendednessFact(bogus); ok {
			t.Fatal("an attended byte outside {0,1} decoded (want fail-closed — never a guessed verdict)")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if _, _, _, _, _, _, ok := DecodeAttendednessFact(nil); ok {
			t.Fatal("an empty body decoded (want fail-closed)")
		}
	})
}
