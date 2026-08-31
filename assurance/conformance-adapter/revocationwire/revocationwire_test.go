// SPDX-License-Identifier: Apache-2.0

package revocationwire

// revocationwire_test.go — the cross-service conformance suite for the D53
// revocation-delta RUNG↔WIRE-BYTE mapping (doc 12 §8.1). This is the Go HALF of
// the assertion: it pins the FROZEN wire bytes the host-agent revoked-set
// fan-out (the encoder) emits, byte-for-byte identical to the table the Rust
// ds-tlsproxy subscriber (`RevocationDeltaWire` / `ds_tlsproxy::Rung`) decodes.
// The Rust half pins the SAME values in
// `rung_wire_byte_round_trips_and_pins_the_d53_table`; together the two halves
// make a silent under-sever (a host-side `kill+snapshot` decoded as a no-op
// `allow+log` because the byte numbering drifted) a compile-or-test failure on
// whichever side moves.

import "testing"

// frozenWireBytes is the wire contract, written out as data (NOT derived from
// the Rung iota), so a reorder of the Rung constants is caught by this table
// disagreeing rather than silently renumbering the wire.
var frozenWireBytes = []struct {
	rung Rung
	name string
	b    byte
}{
	{AllowLog, "allow+log", 0},
	{BlockLog, "block+log", 1},
	{SuspendAsk, "suspend+ask", 2},
	{KillSnapshot, "kill+snapshot", 3},
}

// TestRungToWireByte_PinsTheFrozenD53Table asserts the encoder emits exactly the
// frozen bytes the Rust decoder reads — the single source of truth both services
// build against.
func TestRungToWireByte_PinsTheFrozenD53Table(t *testing.T) {
	for _, tc := range frozenWireBytes {
		got, ok := RungToWireByte(tc.rung)
		if !ok {
			t.Fatalf("RungToWireByte(%s): ok=false for a defined rung", tc.name)
		}
		if got != tc.b {
			t.Errorf("RungToWireByte(%s) = %d, want frozen wire byte %d", tc.name, got, tc.b)
		}
	}
}

// TestRungWireByte_RoundTrips proves the decoder is the encoder's inverse for
// every defined rung — the property the host-agent encoder and the proxy decoder
// must jointly preserve so a delivered rung is the rung the proxy enforces.
func TestRungWireByte_RoundTrips(t *testing.T) {
	for _, tc := range frozenWireBytes {
		b, ok := RungToWireByte(tc.rung)
		if !ok {
			t.Fatalf("RungToWireByte(%s): ok=false", tc.name)
		}
		back, ok := RungFromWireByte(b)
		if !ok {
			t.Fatalf("RungFromWireByte(%d): ok=false for a frozen byte", b)
		}
		if back != tc.rung {
			t.Errorf("round-trip %s: byte %d decoded to %v, want %s", tc.name, b, back, tc.name)
		}
	}
}

// TestRungFromWireByte_UnknownIsFailClosed pins the malformed-frame posture: an
// unknown rung byte decodes to ok=false (the subscriber drops the frame and
// severs NOTHING — it never guesses a rung), matching the Rust
// `rung_from_wire_byte` `None`-on-unknown return.
func TestRungFromWireByte_UnknownIsFailClosed(t *testing.T) {
	for _, b := range []byte{4, 5, 0x7f, 0xff} {
		if _, ok := RungFromWireByte(b); ok {
			t.Errorf("RungFromWireByte(%d): ok=true, want fail-closed (unknown byte)", b)
		}
	}
}

// TestSevers pins the D53 sever threshold (block-or-higher) the wire byte
// ultimately gates — mirrors the Rust `is_block_or_higher` predicate so the two
// services agree on which delivered rung tears down established flows.
func TestSevers(t *testing.T) {
	if AllowLog.Severs() {
		t.Error("allow+log must not sever")
	}
	for _, r := range []Rung{BlockLog, SuspendAsk, KillSnapshot} {
		if !r.Severs() {
			t.Errorf("rung %v must sever (block-or-higher)", r)
		}
	}
}
