package policylog

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dream-serpent/dream-serpent/orchestrator/internal/store"
)

// POL-4 enforcement-clock tests (doc 16 §6.2; D68/D72): they drive the FULL
// sweep → composed-snapshot → flush path through the DefaultComposer, proving the
// landed SweepFleetDigests output is folded into the produce-once hashed host
// document so a fleet-digest revoke artifact removes the key's digests from the
// composed enforced set within one compose cycle.
//
// These tests live in a NEW file (this unit owns only compose.go + composer.go and
// the test files it adds); they reuse the synthetic fleet-digest fixtures from
// compose_test.go (fleetRow/fleetSweepEntry/entryHex) — real producer envelopes via
// marshalFleetArtifact, never hand-faked bodies (D50).

// TestComposeAt_FoldsFleetForbidden proves a FleetDigestKind row's forbidden digests
// reach the composed snapshot: ComposeAt carries the sweep's live forbidden set onto
// the snapshot AND folds it into the hashed document (the content_hash differs from a
// log with no fleet-digest row).
func TestComposeAt_FoldsFleetForbidden(t *testing.T) {
	e := fleetSweepEntry("key-a", 0x11)
	rows := []store.PolicyLogRow{
		{Seq: 1, Kind: store.PolicyKindAppend, Actor: "sys"},
		fleetRow(t, 2, "key-a", "batch-a", e),
	}
	ld := testLayerDecoder{rows: map[int64]layerSpec{
		1: {scope: LayerSystemBaseline, allow: []string{"github.com"}},
	}}
	c := NewDefaultComposer(ld, testGrantDecoder{})

	snap, err := c.ComposeAt(context.Background(), 2, rows, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("ComposeAt: %v", err)
	}

	// The forbidden digest rides the snapshot, tagged with its key id + content id.
	if len(snap.FleetForbidden) != 1 {
		t.Fatalf("FleetForbidden = %+v, want exactly one entry", snap.FleetForbidden)
	}
	if snap.FleetForbidden[0].KeyID != "key-a" || snap.FleetForbidden[0].EntryHex != entryHex(t, e) {
		t.Errorf("FleetForbidden[0] = %+v, want key-a/%s", snap.FleetForbidden[0], entryHex(t, e))
	}
	if len(snap.FleetRevoked) != 0 {
		t.Errorf("FleetRevoked = %v, want none", snap.FleetRevoked)
	}

	// The forbidden set is HASHED into the produce-once document: the same log
	// WITHOUT the fleet-digest row must produce a different content_hash, proving the
	// fleet material is enforced, not merely carried alongside.
	noFleet := []store.PolicyLogRow{rows[0]}
	bare, err := c.ComposeAt(context.Background(), 1, noFleet, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("ComposeAt(no-fleet): %v", err)
	}
	if snap.ContentHash == bare.ContentHash {
		t.Error("fleet-forbidden set did not change the content_hash — it is not folded into the enforced document")
	}
	if !strings.Contains(string(snap.Document), keyFleetForbidden) {
		t.Errorf("composed document does not carry the %q member", keyFleetForbidden)
	}
}

// TestComposeAt_RevokeRemovesFromEnforcedSet is the acceptance pin: a fleet-digest
// REVOKE artifact (an empty-entries artifact under the key id) removes that key's
// digests from the composed enforced set within ONE compose cycle. The composed
// document at the revoke seq hashes IDENTICALLY to the pre-fleet document (the
// enforced fleet set is empty again), and the snapshot records the revoked key.
func TestComposeAt_RevokeRemovesFromEnforcedSet(t *testing.T) {
	live := fleetSweepEntry("key-gone", 0x44)
	ld := testLayerDecoder{rows: map[int64]layerSpec{
		1: {scope: LayerSystemBaseline, allow: []string{"github.com"}},
	}}
	c := NewDefaultComposer(ld, testGrantDecoder{})
	now := time.Unix(1000, 0)

	baseRow := store.PolicyLogRow{Seq: 1, Kind: store.PolicyKindAppend, Actor: "sys"}

	// Cycle 1: the key's digest is published and enforced.
	pub := []store.PolicyLogRow{baseRow, fleetRow(t, 2, "key-gone", "b-pub", live)}
	enforced, err := c.ComposeAt(context.Background(), 2, pub, now)
	if err != nil {
		t.Fatalf("ComposeAt(publish): %v", err)
	}
	if len(enforced.FleetForbidden) != 1 {
		t.Fatalf("after publish FleetForbidden = %+v, want one", enforced.FleetForbidden)
	}

	// Cycle 2: a revoke artifact (empty entries) under the same key lands. Within this
	// single compose cycle the key's digest must leave the enforced set.
	revoked := append(append([]store.PolicyLogRow{}, pub...),
		fleetRow(t, 3, "key-gone", "b-revoke")) // empty entries == revoke
	after, err := c.ComposeAt(context.Background(), 3, revoked, now)
	if err != nil {
		t.Fatalf("ComposeAt(revoke): %v", err)
	}
	if len(after.FleetForbidden) != 0 {
		t.Errorf("after revoke FleetForbidden = %+v, want empty (key retired)", after.FleetForbidden)
	}
	assertStrings(t, "FleetRevoked", after.FleetRevoked, []string{"key-gone"})

	// The enforced document with the (now empty) fleet set hashes identically to the
	// pre-fleet document — the retired digest is gone from the enforced set, and the
	// fleet_forbidden member is omitted entirely (absent == omitted, §5.1).
	preFleet, err := c.ComposeAt(context.Background(), 1, []store.PolicyLogRow{baseRow}, now)
	if err != nil {
		t.Fatalf("ComposeAt(pre-fleet): %v", err)
	}
	if after.ContentHash != preFleet.ContentHash {
		t.Errorf("revoked snapshot content_hash %x != pre-fleet %x — retired digest still enforced",
			after.ContentHash, preFleet.ContentHash)
	}
	if strings.Contains(string(after.Document), keyFleetForbidden) {
		t.Errorf("revoked document still carries the %q member — empty fleet set must omit it", keyFleetForbidden)
	}
	// And the publish cycle (enforced) differs from the revoke cycle, proving the
	// enforcement clock advanced.
	if enforced.ContentHash == after.ContentHash {
		t.Error("publish and revoke produced the same content_hash — the revoke did not flush the digest")
	}
}

// TestComposeAt_FleetRowIsNotADenyLayer guards the wiring against double-counting: a
// FleetDigestKind row must be folded ONLY by the sweep, never (mis)decoded as a
// deny-overrides layer. With a layer decoder that would decode anything, the
// fleet-digest row's allow/deny sets must not appear in the composed shared policy.
func TestComposeAt_FleetRowIsNotADenyLayer(t *testing.T) {
	e := fleetSweepEntry("key-z", 0x99)
	rows := []store.PolicyLogRow{fleetRow(t, 1, "key-z", "b", e)}

	// A decoder that, if reached, would inject a bogus allow keyed off the row seq.
	greedy := LayerDecoderFunc(func(row store.PolicyLogRow) (Layer, string, bool) {
		return Layer{Scope: LayerSystemBaseline, Allow: []string{"BOGUS-from-fleet-row"}}, "", true
	})
	c := NewDefaultComposer(greedy, testGrantDecoder{})

	snap, err := c.ComposeAt(context.Background(), 1, rows, time.Unix(0, 0))
	if err != nil {
		t.Fatalf("ComposeAt: %v", err)
	}
	if strings.Contains(string(snap.Document), "BOGUS-from-fleet-row") {
		t.Error("fleet-digest row was decoded as a deny-overrides layer — it must be folded only by the sweep")
	}
	// The fleet forbidden digest IS present (the sweep folded it).
	if len(snap.FleetForbidden) != 1 || snap.FleetForbidden[0].KeyID != "key-z" {
		t.Errorf("FleetForbidden = %+v, want the swept key-z digest", snap.FleetForbidden)
	}
}
