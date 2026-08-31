// SPDX-License-Identifier: Apache-2.0

package revocationwire

// Rung is the D53 enforcement-action ladder, modelled here exactly as the Rust
// `ds_tlsproxy::Rung` enum is (doc 13 §2/§3 vocabulary; doc 12 §8). The ordinal
// values of THIS Go enum are deliberately NOT the wire bytes — the wire bytes
// are the explicit table in RungToWireByte below — so a reorder here cannot
// renumber the wire either. The ladder order (allow < block < suspend < kill)
// matches the Rust enum's declaration order purely for readability.
type Rung int

const (
	// AllowLog — `allow + log`: the flow is permitted; nothing severs.
	AllowLog Rung = iota
	// BlockLog — `block + log`: denied. The first rung that severs.
	BlockLog
	// SuspendAsk — `suspend + ask`: held for a human; severs (above block).
	SuspendAsk
	// KillSnapshot — `kill + snapshot`: terminal; severs (above block).
	KillSnapshot
)

// RungToWireByte maps a rung to its FROZEN revocation-delta wire byte — the
// single source of truth this fixture pins for the host-agent encoder. The
// values are written out explicitly (never `byte(r)`), so reordering the Rung
// constants above cannot silently renumber the wire. This MUST agree
// byte-for-byte with the Rust `ds_tlsproxy::Rung::rung_to_wire_byte`.
//
//	allow+log = 0 · block+log = 1 · suspend+ask = 2 · kill+snapshot = 3.
//
// The second return is false for a rung outside the defined ladder (an
// unreachable case for a well-formed Rung, surfaced rather than panicking so an
// encoder bug fails loud).
func RungToWireByte(r Rung) (byte, bool) {
	switch r {
	case AllowLog:
		return 0, true
	case BlockLog:
		return 1, true
	case SuspendAsk:
		return 2, true
	case KillSnapshot:
		return 3, true
	default:
		return 0, false
	}
}

// RungFromWireByte is the inverse of RungToWireByte: decode one revocation-delta
// wire byte back to a Rung. The second return is false for an UNKNOWN byte — a
// malformed frame the subscriber drops FAIL-CLOSED (it never guesses a rung,
// never silently severs nothing). This MUST agree byte-for-byte with the Rust
// `ds_tlsproxy::Rung::rung_from_wire_byte` (which returns `Option<Rung>` with
// the same `None`-on-unknown posture).
func RungFromWireByte(b byte) (Rung, bool) {
	switch b {
	case 0:
		return AllowLog, true
	case 1:
		return BlockLog, true
	case 2:
		return SuspendAsk, true
	case 3:
		return KillSnapshot, true
	default:
		// An unknown rung byte is a malformed frame — never silently severing.
		return 0, false
	}
}

// Severs reports whether a rung is block-or-higher — the D53 threshold at which
// a revocation delta tears down established flows (doc 12 §8). `allow+log` does
// not sever; block/suspend/kill do. Mirrors the Rust
// `ds_tlsproxy::Rung::is_block_or_higher`.
func (r Rung) Severs() bool {
	return r >= BlockLog
}
