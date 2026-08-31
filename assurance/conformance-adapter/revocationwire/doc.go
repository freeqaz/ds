// SPDX-License-Identifier: Apache-2.0

// Package revocationwire is the cross-service conformance fixture for the D53
// revocation-delta RUNG↔WIRE-BYTE mapping (doc 12 §8.1).
//
// The revocation-delta feed is host-LOCAL: the host-agent's revoked-set fan-out
// (a Go producer) ENCODES a rung to one wire byte, and the ds-tlsproxy
// subscriber (`RevocationDeltaWire`, Rust) DECODES that byte back to a
// `ds_tlsproxy::Rung`. The two services share no crate, so the byte table is
// duplicated by construction — the encoder's table and the decoder's table can
// drift, and a drift would silently UNDER-SEVER (a host-side `kill+snapshot`
// arriving as a no-op `allow+log` because the byte numbering disagreed).
//
// This fixture is the single artifact BOTH halves assert against:
//
//   - the Rust side single-sources the table on the `ds_tlsproxy::Rung` enum
//     (`rung_to_wire_byte` / `rung_from_wire_byte`) and pins the exact byte
//     values in `rung_wire_byte_round_trips_and_pins_the_d53_table`;
//   - this Go side pins the IDENTICAL byte values here, so the host-agent
//     encoder built against this table cannot drift from the proxy decoder.
//
// The bytes are FROZEN by the wire contract, NOT by enum/iota declaration
// order: they are written out explicitly (never derived from an iota or a
// `#[repr(u8)]` discriminant), so reordering the D53 ladder on either side can
// never renumber the wire. An unknown byte decodes fail-closed (`ok == false`),
// the same posture the Rust subscriber takes (drop the frame, sever nothing,
// never guess a rung).
//
// Stdlib-only, zero dependencies — the package mirrors the wire contract, it
// does not import the Rust crate (it can't) or any proto.
package revocationwire
