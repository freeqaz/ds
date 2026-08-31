// SPDX-License-Identifier: Apache-2.0

// Full-rotation choreography tests (doc 16 §6.2/§6.3): FullRotation orders the
// SESSION leg (LiveRekey over DigestFeedService) THEN the FLEET leg
// (LiveRekeyFleet over the policy stream) as one redeploy motion and returns a
// combined RotationResult. These prove the DOCUMENTED ORDERING (session first,
// dropping the SHARED retiring key; fleet second, tolerating that drop and
// proving its own no-gap via the policy-log retire APPEND, not the shared drop)
// and the fail-closed guarantee (a fleet-leg failure leaves the old fleet key
// registered / shadowed; a session-leg failure never runs the fleet leg and
// leaves the old key live). It reuses the in-process fakes from keys_test.go
// (rekeyConsumer / dialConsumer) and rotation_test.go (fakePolicySink) — no live
// boundary (the wave rule). SYNTHETIC ONLY (D50).
package digest

import (
	"context"
	"testing"
)

// TestFullRotationOrdersSessionThenFleet is the core acceptance proof: one
// FullRotation call rolls BOTH cadences in order — the session leg re-pushes
// every session under the new key and drops the SHARED retiring key first, then
// the fleet leg re-registers + retires its OWN policy artifact and reports
// OldKeyRetired=true from the policy-log retire append (not the shared drop) —
// with no instant on either cadence unshadowed by both keys.
func TestFullRotationOrdersSessionThenFleet(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)
	sink := newFakePolicySink()
	m, err := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	sessions := liveSessions()
	fleet := fleetCreds()

	// Pre-state: both cadences registered under the OLD key.
	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	for _, s := range sessions {
		if _, err := PublishSession(context.Background(), client, oldProd, s.SessionUUID, s.Creds, "init-"+s.SessionUUID); err != nil {
			t.Fatalf("initial session publish: %v", err)
		}
	}
	if _, err := PublishFleetPolicy(context.Background(), sink, oldProd, fleet, "init-fleet"); err != nil {
		t.Fatalf("initial fleet registration: %v", err)
	}

	// Redeploy: advance the lifecycle, then a single full rotation.
	m.Rekey()
	newID := m.ActiveKeyID()
	if newID == oldID {
		t.Fatal("re-key did not change the active key id")
	}

	res, err := m.FullRotation(context.Background(), client, sink, oldID, sessions, fleet,
		batchIDFor, "rot-fleet-new", "rot-fleet-retire")
	if err != nil {
		t.Fatalf("FullRotation: %v", err)
	}
	if !res.Complete {
		t.Fatal("FullRotation reported not Complete on the happy path")
	}

	// SESSION leg: every session re-pushed under the new key, and it dropped the
	// SHARED retiring key (LiveRekey's RetireKey on success).
	if !res.Session.OldKeyRetired {
		t.Error("session leg did not retire the old (shared) key")
	}
	if res.Session.NewKeyID != newID {
		t.Errorf("session leg NewKeyID %q, want %q", res.Session.NewKeyID, newID)
	}
	if len(res.Session.Republished) != len(sessions) {
		t.Errorf("session leg re-pushed %d sessions, want %d", len(res.Session.Republished), len(sessions))
	}
	// The shared retiring key was dropped by the session leg FIRST (this is the
	// state the fleet leg must tolerate below).
	if containsStr(m.RetiringKeyIDs(), oldID) {
		t.Errorf("shared key %q still retiring after the session leg dropped it", oldID)
	}

	// FLEET leg: re-registered under the new key and retired its OWN policy
	// artifact — OldKeyRetired reflects the policy-log retire append, NOT the
	// shared-set drop the session leg already did.
	if !res.Fleet.OldKeyRetired {
		t.Error("fleet leg did not report OldKeyRetired (its policy-log retire append)")
	}
	if res.Fleet.NewKeyID != newID {
		t.Errorf("fleet leg NewKeyID %q, want %q", res.Fleet.NewKeyID, newID)
	}
	if !res.Fleet.NewArtifact.Committed {
		t.Error("fleet leg new-key artifact not committed")
	}

	// NONE STRANDED, EITHER CADENCE, under the new key. Fleet set matchable via
	// the policy sink's applied new-key entries; session set via the consumer's.
	newProd, _ := m.Producer()
	fleetMatcher, _ := MatcherFromProducer(newProd)
	fleetMatcher.Load(sink.applied[newID])
	for _, c := range fleet {
		if r := fleetMatcher.Match(c.Plaintext); !r.Matched {
			t.Errorf("after full rotation, fleet credential not matchable under new key: %q", c.Plaintext)
		}
	}
	sessMatcher, _ := MatcherFromProducer(newProd)
	sessMatcher.Load(consumer.byKeyID[newID])
	for _, s := range sessions {
		for _, c := range s.Creds {
			if r := sessMatcher.Match(c.Plaintext); !r.Matched {
				t.Errorf("after full rotation, session credential not matchable under new key: %q", c.Plaintext)
			}
		}
	}

	// FLEET cadence: the policy stream actively SWEEPS the old key (empty-entry
	// retire append), so nothing is left under the old key there.
	if _, ok := sink.applied[oldID]; ok {
		t.Errorf("fleet digests stranded under old key %q after full rotation", oldID)
	}
	// SESSION cadence: LiveRekey RETIRES the old key from the lifecycle (stops
	// SELECTING it) but does NOT flush the boundary's already-loaded old-key
	// entries — those stay live so a still-connected session is never unshadowed
	// mid-flip (the optional RetireOldKeyViaRevoke companion does the flush at
	// teardown). So old-key entries remaining loaded on the consumer is CORRECT,
	// not a strand; the lifecycle no longer lists the key as retiring, which is the
	// session-cadence proof.
	if containsStr(m.RetiringKeyIDs(), oldID) {
		t.Errorf("shared key %q still retiring after full rotation", oldID)
	}
}

// TestFullRotationFleetLegToleratesSessionLegSharedDrop pins the load-bearing
// ordering property: the fleet leg runs SECOND, over a shared key the session leg
// already dropped from the retiring set, and STILL succeeds — its no-gap proof is
// the policy-log retire append, never the shared-set bookkeeping.
func TestFullRotationFleetLegToleratesSessionLegSharedDrop(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)
	sink := newFakePolicySink()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)

	sessions := liveSessions()
	fleet := fleetCreds()
	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	for _, s := range sessions {
		if _, err := PublishSession(context.Background(), client, oldProd, s.SessionUUID, s.Creds, "init-"+s.SessionUUID); err != nil {
			t.Fatalf("initial session publish: %v", err)
		}
	}
	if _, err := PublishFleetPolicy(context.Background(), sink, oldProd, fleet, "init-fleet"); err != nil {
		t.Fatalf("initial fleet registration: %v", err)
	}
	m.Rekey()

	// Run the SESSION leg alone first (as FullRotation does), so it drops the
	// shared retiring key BEFORE the fleet leg sees it.
	if _, err := m.LiveRekey(context.Background(), client, oldID, sessions, batchIDFor); err != nil {
		t.Fatalf("session leg pre-drop: %v", err)
	}
	if containsStr(m.RetiringKeyIDs(), oldID) {
		t.Fatalf("shared key %q not dropped by the session leg", oldID)
	}

	// Now the fleet leg over the SAME (already-dropped) old key must still
	// re-register + retire its policy artifact and report OldKeyRetired=true.
	fres, err := m.LiveRekeyFleet(context.Background(), sink, oldID, fleet, "new", "retire")
	if err != nil {
		t.Fatalf("fleet leg over already-dropped shared key: %v (should tolerate the session-leg drop)", err)
	}
	if !fres.OldKeyRetired {
		t.Error("fleet leg over already-dropped shared key did not report OldKeyRetired (policy-log retire append)")
	}
	// The retire is proven on the POLICY LOG: an empty-entry append under oldID.
	sawRetireAppend := false
	for _, a := range sink.log {
		if a.keyID == oldID && a.entryCount == 0 && a.committed {
			sawRetireAppend = true
		}
	}
	if !sawRetireAppend {
		t.Error("fleet no-gap proof missing: no committed empty-entry retire append under the old key on the policy log")
	}
	// And the old fleet set was swept from the applied policy set (not stranded).
	if _, ok := sink.applied[oldID]; ok {
		t.Errorf("old fleet key %q still applied after fleet retire", oldID)
	}
}

// TestFullRotationSessionLegFailureDoesNotRunFleetLeg proves fail-closed
// ordering: a session-leg publish failure aborts the rotation BEFORE the fleet
// leg runs — the old key stays live on both cadences (no gap), and the policy
// stream is never touched.
func TestFullRotationSessionLegFailureDoesNotRunFleetLeg(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)
	sink := newFakePolicySink()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)

	sessions := liveSessions()
	fleet := fleetCreds()
	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	for _, s := range sessions {
		if _, err := PublishSession(context.Background(), client, oldProd, s.SessionUUID, s.Creds, "init-"+s.SessionUUID); err != nil {
			t.Fatalf("initial session publish: %v", err)
		}
	}
	if _, err := PublishFleetPolicy(context.Background(), sink, oldProd, fleet, "init-fleet"); err != nil {
		t.Fatalf("initial fleet registration: %v", err)
	}
	m.Rekey()

	// The NEXT DigestPublish (the first session re-push) fails uncommitted.
	consumer.failOnPublishN = consumer.publishCount + 1
	// Snapshot the policy log so we can prove the fleet leg never appended.
	fleetAppendsBefore := len(sink.log)

	res, err := m.FullRotation(context.Background(), client, sink, oldID, sessions, fleet,
		batchIDFor, "new", "retire")
	if err == nil {
		t.Fatal("session-leg failure: want error (fail-closed)")
	}
	if res.Complete {
		t.Fatal("FullRotation reported Complete despite a session-leg failure")
	}
	if res.Session.OldKeyRetired {
		t.Fatal("session-leg failure must NOT retire the shared old key (would strand sessions)")
	}
	// Shared key still live (retiring) — sessions still shadowed under it.
	if !containsStr(m.RetiringKeyIDs(), oldID) {
		t.Errorf("shared key %q dropped despite a session-leg failure", oldID)
	}
	// The fleet leg NEVER ran: no new policy-log append, and the fleet result is
	// the zero value (no OldKeyRetired, no new artifact).
	if len(sink.log) != fleetAppendsBefore {
		t.Errorf("fleet leg appended %d policy rows despite a session-leg failure (should be 0)", len(sink.log)-fleetAppendsBefore)
	}
	if res.Fleet.OldKeyRetired || res.Fleet.NewArtifact.Committed {
		t.Errorf("fleet leg ran despite the session-leg failure: %+v", res.Fleet)
	}
	if _, ok := sink.applied[oldID]; !ok {
		t.Error("old fleet digests dropped despite the session-leg failure (fleet leg must not have run)")
	}
}

// TestFullRotationFleetLegFailureLeavesOldFleetKeyLive proves the second
// fail-closed leg: the session cadence commits, but a fleet new-registration
// failure leaves the OLD fleet key's artifact registered (fleet still shadowed),
// Complete is false, and the caller can retry the fleet leg. Session state that
// already committed is surfaced so the caller knows not to re-run it.
func TestFullRotationFleetLegFailureLeavesOldFleetKeyLive(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)
	sink := newFakePolicySink()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)

	sessions := liveSessions()
	fleet := fleetCreds()
	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	for _, s := range sessions {
		if _, err := PublishSession(context.Background(), client, oldProd, s.SessionUUID, s.Creds, "init-"+s.SessionUUID); err != nil {
			t.Fatalf("initial session publish: %v", err)
		}
	}
	if _, err := PublishFleetPolicy(context.Background(), sink, oldProd, fleet, "init-fleet"); err != nil {
		t.Fatalf("initial fleet registration: %v", err)
	}
	m.Rekey()
	newID := m.ActiveKeyID()

	// The fleet leg's new-key registration (the NEXT policy append) fails
	// uncommitted — the session leg is unaffected (it uses DigestFeedService).
	sink.failOnAppendN = sink.appendCount + 1

	res, err := m.FullRotation(context.Background(), client, sink, oldID, sessions, fleet,
		batchIDFor, "new", "retire")
	if err == nil {
		t.Fatal("fleet-leg failure: want error (fail-closed)")
	}
	if res.Complete {
		t.Fatal("FullRotation reported Complete despite a fleet-leg failure")
	}
	// The SESSION cadence DID commit (its result is carried so the caller doesn't
	// re-run it): sessions re-pushed under the new key, shared key dropped.
	if !res.Session.OldKeyRetired {
		t.Error("session leg should have committed (retired the shared key) before the fleet leg failed")
	}
	if len(consumer.byKeyID[newID]) == 0 {
		t.Error("session digests not present under the new key after the session leg committed")
	}
	// The FLEET cadence is fail-closed: old fleet artifact still registered
	// (fleet shadowed), and the fleet result reports it was NOT retired.
	if res.Fleet.OldKeyRetired {
		t.Fatal("fleet-leg failure must NOT report the old fleet key retired")
	}
	if _, ok := sink.applied[oldID]; !ok {
		t.Error("old fleet key digests dropped on a failed fleet leg — stranded/gap risk")
	}
	// No retire append ran for the old fleet key (failure was before step 2).
	for _, a := range sink.log {
		if a.keyID == oldID && a.entryCount == 0 {
			t.Error("a fleet retire append ran despite the new-key registration failing — ordering violated")
		}
	}
}

// TestFullRotationEmptyFleetSetStillRollsSessions proves the fleet leg's empty-
// set no-op composes: a full rotation with sessions but NO fleet credentials
// rolls the session cadence and completes, with the fleet leg a clean no-op (it
// owns no fleet artifact to retire).
func TestFullRotationEmptyFleetSetStillRollsSessions(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)
	sink := newFakePolicySink()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)

	sessions := liveSessions()
	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	for _, s := range sessions {
		if _, err := PublishSession(context.Background(), client, oldProd, s.SessionUUID, s.Creds, "init-"+s.SessionUUID); err != nil {
			t.Fatalf("initial session publish: %v", err)
		}
	}
	m.Rekey()

	res, err := m.FullRotation(context.Background(), client, sink, oldID, sessions, nil,
		batchIDFor, "new", "retire")
	if err != nil {
		t.Fatalf("FullRotation with empty fleet set: %v", err)
	}
	if !res.Complete {
		t.Fatal("FullRotation with an empty fleet set should complete (session leg rolled, fleet leg a no-op)")
	}
	if !res.Session.OldKeyRetired {
		t.Error("session leg did not roll on a full rotation with an empty fleet set")
	}
	// Fleet leg was a clean no-op: no policy append, old key not reported retired
	// by the fleet leg (it owns no artifact to retire).
	if len(sink.log) != 0 {
		t.Errorf("empty fleet set appended %d policy rows, want 0", len(sink.log))
	}
	if res.Fleet.OldKeyRetired {
		t.Error("fleet leg reported OldKeyRetired on an empty fleet set (owns no artifact)")
	}
}

// TestFullRotationGuardsPreState pins that FullRotation surfaces each leg's
// pre-state guard (it does not swallow them): a non-advanced manager, a nil
// client, and an old key not in the retiring set each fail closed at the session
// leg before any policy append.
func TestFullRotationGuardsPreState(t *testing.T) {
	consumer := newRekeyConsumer()
	client := dialConsumer(t, consumer)
	sink := newFakePolicySink()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	sessions := liveSessions()
	fleet := fleetCreds()
	ctx := context.Background()

	// old key id == active (manager not advanced) — session leg rejects it.
	if res, err := m.FullRotation(ctx, client, sink, m.ActiveKeyID(), sessions, fleet, batchIDFor, "n", "o"); err == nil || res.Complete {
		t.Error("old==active key id: want fail-closed error, no completion")
	}
	// nil client — session leg rejects it, fleet leg never runs.
	m2, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	old := m2.ActiveKeyID()
	m2.Rekey()
	if res, err := m2.FullRotation(ctx, nil, sink, old, sessions, fleet, batchIDFor, "n", "o"); err == nil || res.Complete {
		t.Error("nil client: want fail-closed error, no completion")
	}
	if len(sink.log) != 0 {
		t.Error("a policy append ran despite the session-leg pre-state guard failing")
	}
	// old key not retiring (bad id) — session leg rejects it.
	m3, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	m3.Rekey()
	if res, err := m3.FullRotation(ctx, client, sink, "ds-dk-host-a-e9-g9", sessions, fleet, batchIDFor, "n", "o"); err == nil || res.Complete {
		t.Error("non-retiring old key: want fail-closed error, no completion")
	}
}
