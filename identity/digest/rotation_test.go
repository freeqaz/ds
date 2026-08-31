// SPDX-License-Identifier: Apache-2.0

// Fleet-scope re-key tests (doc 16 §6.2; D72 "two cadences, no third channel").
//
// LiveRekey (keys_test.go) covers the SESSION cadence over DigestFeedService.
// This file covers the SECOND cadence: a key rotation/re-key MUST also
// re-register the FLEET-scope forbidden-class digests under the new key as
// POLICY ARTIFACTS over the policy stream, gap-free — the new-key artifact
// applied BEFORE the old fleet key is retired, so the fleet digests are never
// stranded under a retired key (matchable nowhere). The policy_log surface is
// the orchestrator's; here it is an in-process fake PolicySink (no live boundary
// — the wave rule). SYNTHETIC ONLY (D50): ds-synth-* roots and plaintexts.
package digest

import (
	"context"
	"errors"
	"testing"
	"time"

	identityv1 "github.com/dream-serpent/dream-serpent/proto/gen/go/dreamserpent/identity/v1"
)

// fakePolicySink is the in-process stand-in for the orchestrator's policy_log
// append path (PolicyService.AppendPolicy → the one-per-host WatchPolicies
// fan-out). It accumulates the fleet-scope digest entries currently APPLIED
// under each key id, assigning a monotonic `policy_log`-style seq per append. A
// new-key registration adds entries; an empty-entry artifact (RevokeFleetPolicy)
// retires that key id's fleet digests via the policy revocation-sweep model.
//
// It records every append in order so a test can prove the new-key registration
// is applied BEFORE the old-key retire (the no-gap ordering). It can be told to
// fail the Nth append (uncommitted apply) to exercise the fail-closed leg.
type fakePolicySink struct {
	// applied is the entry set currently live under each key id (the boundary's
	// loaded fleet set per key, as composed from the policy_log).
	applied map[string][]*identityv1.DigestEntry
	// log is the ordered append journal: (keyID, entryCount, committed) per call.
	log []fakeAppend
	// seq is the monotonic policy_log bigserial the sink assigns.
	seq uint64
	// failOnAppendN, if >0, makes the Nth (1-based) append return an uncommitted
	// result (the policy-apply barrier did not confirm) — fail-closed.
	appendCount   int
	failOnAppendN int
	// errOnAppendN, if >0, makes the Nth append return a transport-style error.
	errOnAppendN int
}

type fakeAppend struct {
	keyID      string
	entryCount int
	committed  bool
	seq        uint64
}

func newFakePolicySink() *fakePolicySink {
	return &fakePolicySink{applied: map[string][]*identityv1.DigestEntry{}}
}

func (s *fakePolicySink) AppendFleetDigest(_ context.Context, art FleetPolicyArtifact) (FleetPolicyResult, error) {
	s.appendCount++
	if s.errOnAppendN > 0 && s.appendCount == s.errOnAppendN {
		return FleetPolicyResult{}, errors.New("synthetic policy-log transport error")
	}
	s.seq++
	committed := true
	if s.failOnAppendN > 0 && s.appendCount == s.failOnAppendN {
		committed = false // policy-apply barrier did not confirm ⇒ fail-closed
	}
	if committed {
		if len(art.Entries) == 0 {
			// Empty-entry artifact = retire this key id's fleet digests (the
			// revocation-sweep model).
			delete(s.applied, art.KeyID)
		} else {
			s.applied[art.KeyID] = append(s.applied[art.KeyID], art.Entries...)
		}
	}
	s.log = append(s.log, fakeAppend{keyID: art.KeyID, entryCount: len(art.Entries), committed: committed, seq: s.seq})
	return FleetPolicyResult{Seq: s.seq, Committed: committed, KeyID: art.KeyID, BatchID: art.BatchID}, nil
}

// fleetCreds is the synthetic live FLEET-scope (forbidden-class canary) set —
// the org-wide secrets every session is forbidden to egress (doc 06 (c) canary,
// D73). These ride the policy stream, never DigestFeedService.
func fleetCreds() []Credential {
	exp := time.Now().Add(24 * time.Hour)
	return []Credential{
		{Plaintext: []byte("ds-synth-fleet-canary-prod-signing-key"), CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_FLEET, Expiry: exp},
		{Plaintext: []byte("ds-synth-fleet-canary-root-pat"), CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_FLEET, Expiry: exp},
		{Plaintext: []byte("ds-synth-fleet-canary-db-master-pw"), CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_FLEET, Expiry: exp},
	}
}

// TestLiveRekeyFleetReRegistersUnderNewKeyBeforeRetiringOld is the core
// acceptance proof: a re-key re-registers EVERY fleet-scope digest under the new
// key over the policy stream, the new artifact is applied, and ONLY THEN is the
// old fleet key retired — with no instant at which the fleet is unshadowed by
// both keys, and none stranded.
func TestLiveRekeyFleetReRegistersUnderNewKeyBeforeRetiringOld(t *testing.T) {
	sink := newFakePolicySink()
	creds := fleetCreds()

	m, err := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	// Pre-state: the fleet set is registered under the OLD key as a policy
	// artifact (the original fleet registration over the policy stream).
	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	if _, err := PublishFleetPolicy(context.Background(), sink, oldProd, creds, "init-fleet"); err != nil {
		t.Fatalf("initial fleet registration: %v", err)
	}
	if _, ok := sink.applied[oldID]; !ok {
		t.Fatalf("old key %q has no applied fleet digests after initial registration", oldID)
	}
	wantDigests := len(creds) * len(AllVariants)
	if got := len(sink.applied[oldID]); got != wantDigests {
		t.Fatalf("initial fleet set has %d digests, want %d", got, wantDigests)
	}

	// Redeploy/rotation: advance the lifecycle, then fleet re-key.
	newE := m.Rekey()
	newID := newE.KeyID()
	if newID == oldID {
		t.Fatal("re-key did not change the active key id")
	}

	res, err := m.LiveRekeyFleet(context.Background(), sink, oldID, creds, "rekey-fleet-new", "rekey-fleet-retire")
	if err != nil {
		t.Fatalf("LiveRekeyFleet: %v", err)
	}
	if !res.OldKeyRetired {
		t.Fatal("LiveRekeyFleet reported old fleet key NOT retired on the happy path")
	}
	if res.NewKeyID != newID {
		t.Errorf("fleet re-key NewKeyID %q, want %q", res.NewKeyID, newID)
	}
	if !res.NewArtifact.Committed {
		t.Error("new-key fleet artifact not committed")
	}
	if res.NewArtifact.Seq == 0 {
		t.Error("new-key fleet artifact has no assigned policy_log seq")
	}

	// NONE STRANDED: every fleet credential, every variant, is matchable under the
	// NEW key (built from the sink's applied new-key set, mirroring the boundary
	// that consumed the policy artifact).
	newProd, _ := m.Producer()
	newMatcher, _ := MatcherFromProducer(newProd)
	newMatcher.Load(sink.applied[newID])
	for _, c := range creds {
		if r := newMatcher.Match(c.Plaintext); !r.Matched {
			t.Errorf("after fleet re-key, fleet credential not matchable under new key: %q", c.Plaintext)
		}
		if r := newMatcher.Match(c.Plaintext); r.Matched && r.Scope != identityv1.DigestScope_DIGEST_SCOPE_FLEET {
			t.Errorf("re-registered fleet digest carries scope %v, want FLEET", r.Scope)
		}
	}
	if got := len(sink.applied[newID]); got != wantDigests {
		t.Errorf("new fleet key applied %d digests, want %d (no fleet digest dropped)", got, wantDigests)
	}

	// The old fleet key's artifact was retired (swept), and the lifecycle no longer
	// lists it as retiring.
	if _, ok := sink.applied[oldID]; ok {
		t.Errorf("old fleet key %q still has applied digests after retire (stranded under retired key)", oldID)
	}
	if containsStr(m.RetiringKeyIDs(), oldID) {
		t.Errorf("old fleet key %q still retiring after a successful LiveRekeyFleet", oldID)
	}
}

// TestLiveRekeyFleetOrderingNewBeforeOldRetire proves the no-gap ordering
// DIRECTLY from the append journal: the new-key registration append precedes the
// old-key retire append, and at the instant the retire append runs the new-key
// set is already applied — so the fleet is shadowed by at least one key at every
// instant.
func TestLiveRekeyFleetOrderingNewBeforeOldRetire(t *testing.T) {
	sink := newFakePolicySink()
	creds := fleetCreds()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)

	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	if _, err := PublishFleetPolicy(context.Background(), sink, oldProd, creds, "init-fleet"); err != nil {
		t.Fatalf("initial fleet registration: %v", err)
	}
	initialAppends := len(sink.log) // 1 (the init registration)

	newE := m.Rekey()
	newID := newE.KeyID()
	if _, err := m.LiveRekeyFleet(context.Background(), sink, oldID, creds, "new", "retire"); err != nil {
		t.Fatalf("LiveRekeyFleet: %v", err)
	}

	// The re-key appended exactly two rows after the init: [new-key register],
	// then [old-key retire] — in that order.
	rekeyLog := sink.log[initialAppends:]
	if len(rekeyLog) != 2 {
		t.Fatalf("fleet re-key appended %d policy rows, want 2 (register-new then retire-old)", len(rekeyLog))
	}
	registerNew, retireOld := rekeyLog[0], rekeyLog[1]
	if registerNew.keyID != newID || registerNew.entryCount == 0 {
		t.Errorf("first re-key append is not the new-key registration: %+v (newID=%q)", registerNew, newID)
	}
	if retireOld.keyID != oldID || retireOld.entryCount != 0 {
		t.Errorf("second re-key append is not the old-key retire (empty entries): %+v (oldID=%q)", retireOld, oldID)
	}
	// Monotonic policy_log seq: register-new strictly precedes retire-old.
	if !(registerNew.seq < retireOld.seq) {
		t.Errorf("retire seq %d not strictly after register seq %d — ordering not gap-free", retireOld.seq, registerNew.seq)
	}
}

// TestLiveRekeyFleetFailClosed_NewRegistrationFailureLeavesOldLive proves a
// failed new-key registration does NOT retire the old fleet key — the fleet stays
// shadowed under the old fleet digests (no gap), and the caller can retry.
func TestLiveRekeyFleetFailClosed_NewRegistrationFailureLeavesOldLive(t *testing.T) {
	sink := newFakePolicySink()
	creds := fleetCreds()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)

	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	if _, err := PublishFleetPolicy(context.Background(), sink, oldProd, creds, "init-fleet"); err != nil {
		t.Fatalf("initial fleet registration: %v", err)
	}
	// The NEXT append (the new-key registration during re-key) fails uncommitted.
	sink.failOnAppendN = sink.appendCount + 1

	m.Rekey()
	res, err := m.LiveRekeyFleet(context.Background(), sink, oldID, creds, "new", "retire")
	if err == nil {
		t.Fatal("failed new-key registration: want error (fail-closed)")
	}
	if res.OldKeyRetired {
		t.Fatal("failed new-key registration must NOT retire the old fleet key (would strand the fleet)")
	}
	// The old fleet key's digests are STILL applied (the fleet is still shadowed),
	// and the lifecycle still lists it as retiring (the caller can retry).
	if _, ok := sink.applied[oldID]; !ok {
		t.Error("old fleet key digests dropped on a failed re-key — stranded/gap risk")
	}
	if !containsStr(m.RetiringKeyIDs(), oldID) {
		t.Errorf("old fleet key %q dropped from retiring on a failed re-key", oldID)
	}
	// And NO retire append ever ran (the failure was before step 2).
	for _, a := range sink.log {
		if a.keyID == oldID && a.entryCount == 0 {
			t.Error("a retire append ran despite the new-key registration failing — ordering violated")
		}
	}
}

// TestLiveRekeyFleetTransportErrorOnNewRegistrationFailsClosed mirrors the above
// for a sink transport error (not merely an uncommitted apply).
func TestLiveRekeyFleetTransportErrorOnNewRegistrationFailsClosed(t *testing.T) {
	sink := newFakePolicySink()
	creds := fleetCreds()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)

	oldID := m.ActiveKeyID()
	oldProd, _ := m.Producer()
	if _, err := PublishFleetPolicy(context.Background(), sink, oldProd, creds, "init-fleet"); err != nil {
		t.Fatalf("initial fleet registration: %v", err)
	}
	sink.errOnAppendN = sink.appendCount + 1 // the new-key registration errors

	m.Rekey()
	res, err := m.LiveRekeyFleet(context.Background(), sink, oldID, creds, "new", "retire")
	if err == nil {
		t.Fatal("sink transport error on new registration: want error (fail-closed)")
	}
	if res.OldKeyRetired {
		t.Fatal("transport error must NOT retire the old fleet key")
	}
	if !containsStr(m.RetiringKeyIDs(), oldID) {
		t.Errorf("old fleet key %q dropped from retiring on a transport error", oldID)
	}
}

// TestLiveRekeyFleetGuards covers the fail-closed construction/ordering guards.
func TestLiveRekeyFleetGuards(t *testing.T) {
	sink := newFakePolicySink()
	creds := fleetCreds()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	ctx := context.Background()

	// nil sink.
	if _, err := m.LiveRekeyFleet(ctx, nil, "x", creds, "n", "o"); err == nil {
		t.Error("nil sink: want error")
	}
	// old key id equals the active id (manager not advanced).
	if _, err := m.LiveRekeyFleet(ctx, sink, m.ActiveKeyID(), creds, "n", "o"); err == nil {
		t.Error("old==active key id: want error (advance the manager first)")
	}
	// old key not in the retiring set (never rotated).
	if _, err := m.LiveRekeyFleet(ctx, sink, "ds-dk-host-a-e9-g9", creds, "n", "o"); err == nil {
		t.Error("non-retiring old key: want error")
	}
	// empty old key id.
	old := m.ActiveKeyID()
	m.Rekey()
	if _, err := m.LiveRekeyFleet(ctx, sink, "", creds, "n", "o"); err == nil {
		t.Error("empty old key id: want error")
	}
	// A session-scope credential on the fleet path is fail-closed (no cadence
	// crossing — D72).
	badCreds := []Credential{
		{Plaintext: []byte("ds-synth-session-scoped-on-fleet-path"), CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION, Expiry: time.Now().Add(time.Hour)},
	}
	if _, err := m.LiveRekeyFleet(ctx, sink, old, badCreds, "n", "o"); err == nil {
		t.Error("session-scope cred on the fleet path: want error (D72 no cadence crossing)")
	}
	// And the bad-scope failure left the old key untouched (fail-closed).
	if !containsStr(m.RetiringKeyIDs(), old) {
		t.Errorf("old key %q dropped after a fail-closed bad-scope re-key", old)
	}
}

// TestLiveRekeyFleetEmptySetIsNoOp proves a re-key with NO fleet credentials is a
// clean no-op: nothing to re-register, so nothing stranded — and the old key is
// left to the session leg / caller (this leg never speculatively retires it).
func TestLiveRekeyFleetEmptySetIsNoOp(t *testing.T) {
	sink := newFakePolicySink()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)

	oldID := m.ActiveKeyID()
	m.Rekey()
	res, err := m.LiveRekeyFleet(context.Background(), sink, oldID, nil, "n", "o")
	if err != nil {
		t.Fatalf("empty fleet set: unexpected error %v", err)
	}
	if res.OldKeyRetired {
		t.Error("empty fleet re-key should not retire the old key (it owns no fleet artifact to retire)")
	}
	if len(sink.log) != 0 {
		t.Errorf("empty fleet re-key appended %d policy rows, want 0", len(sink.log))
	}
	// The old key is left in the retiring set for the session leg / caller.
	if !containsStr(m.RetiringKeyIDs(), oldID) {
		t.Errorf("old key %q dropped on an empty fleet re-key", oldID)
	}
}

// TestFleetAndSessionCadencesAreIndependent proves the two cadences never cross
// (D72): the fleet leg drives ONLY the policy sink, the session leg drives ONLY
// DigestFeedService, and a full rotation runs both without either touching the
// other's channel. It also pins that PublishFleetPolicy refuses to emit a
// session-scope entry onto the policy stream.
func TestFleetAndSessionCadencesAreIndependent(t *testing.T) {
	sink := newFakePolicySink()
	consumer := newRekeyConsumer() // the DigestFeedService fake from keys_test.go
	client := dialConsumer(t, consumer)
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)

	sessions := liveSessions()
	fleet := fleetCreds()

	// Initial registration on BOTH cadences under the old key.
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

	// Full rotation: re-key both cadences.
	m.Rekey()
	newID := m.ActiveKeyID()
	if _, err := m.LiveRekey(context.Background(), client, oldID, sessions, batchIDFor); err != nil {
		t.Fatalf("LiveRekey (session leg): %v", err)
	}
	if _, err := m.LiveRekeyFleet(context.Background(), sink, oldID, fleet, "new-fleet", "retire-fleet"); err != nil {
		t.Fatalf("LiveRekeyFleet (fleet leg): %v", err)
	}

	// The session leg never touched the policy sink: the sink holds ONLY fleet
	// scope entries, all under the new key id.
	for _, e := range sink.applied[newID] {
		if e.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_FLEET {
			t.Errorf("policy sink holds a non-FLEET entry (scope %v) — cadence crossed", e.GetScope())
		}
	}
	// The fleet leg never touched DigestFeedService: the consumer holds ONLY
	// session scope entries.
	for _, e := range consumer.byKeyID[newID] {
		if e.GetScope() != identityv1.DigestScope_DIGEST_SCOPE_SESSION {
			t.Errorf("DigestFeedService holds a non-SESSION entry (scope %v) — cadence crossed", e.GetScope())
		}
	}
	// Both cadences carry digests under the new key id; the fleet leg did not
	// strand its set under the old key.
	if len(sink.applied[newID]) == 0 {
		t.Error("no fleet digests under the new key after the fleet re-key")
	}
	if _, ok := sink.applied[oldID]; ok {
		t.Error("fleet digests stranded under the old key after the fleet re-key")
	}
	if len(consumer.byKeyID[newID]) == 0 {
		t.Error("no session digests under the new key after the session re-key")
	}
}

// TestPublishFleetPolicyFailClosed covers the fleet publish verb's guards
// independently of a re-key.
func TestPublishFleetPolicyFailClosed(t *testing.T) {
	sink := newFakePolicySink()
	m, _ := NewKeyManager(synthHostA, synthRoot, DefaultTruncationLenBytes)
	prod, _ := m.Producer()
	ctx := context.Background()

	// nil sink.
	if _, err := PublishFleetPolicy(ctx, nil, prod, fleetCreds(), "b"); err == nil {
		t.Error("nil sink: want error")
	}
	// nil producer.
	if _, err := PublishFleetPolicy(ctx, sink, nil, fleetCreds(), "b"); err == nil {
		t.Error("nil producer: want error")
	}
	// A session-scope cred on the fleet path is rejected (FleetBatchEntries guard).
	sessionScoped := []Credential{
		{Plaintext: []byte("ds-synth-session-on-fleet"), CredClass: Forbidden(), Scope: identityv1.DigestScope_DIGEST_SCOPE_SESSION, Expiry: time.Now().Add(time.Hour)},
	}
	if _, err := PublishFleetPolicy(ctx, sink, prod, sessionScoped, "b"); err == nil {
		t.Error("session-scope cred on fleet path: want error (D72)")
	}
	// An uncommitted policy apply fails closed.
	sink.failOnAppendN = sink.appendCount + 1
	if _, err := PublishFleetPolicy(ctx, sink, prod, fleetCreds(), "b"); err == nil {
		t.Error("uncommitted policy apply: want error (fail-closed)")
	}
}
